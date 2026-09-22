"""Adapter contracts and injectable local-system boundaries."""

from __future__ import annotations

import os
import secrets
import stat
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Protocol

from src.poc_models import Category

from ..command_runner import CommandRunner, MutationAuthorization
from ..models import (
    AuditEvidence,
    HealthCheck,
    RemediationAction,
    RemediationResult,
    RollbackResult,
    ValidationDecision,
)


class UnsafePathError(ValueError):
    """A fixed adapter target was replaced by an unsafe filesystem object."""


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    mode: int
    uid: int
    gid: int
    device: int
    inode: int
    size: int


class FileOperations(Protocol):
    def snapshot(self, path: Path) -> FileSnapshot: ...

    def read_text(self, path: Path, *, max_bytes: int) -> str: ...

    def make_private_directory(self, path: Path) -> None: ...

    def backup_file(
        self, source: Path, destination: Path, expected: FileSnapshot
    ) -> None: ...

    def set_metadata(
        self,
        path: Path,
        expected: FileSnapshot,
        *,
        uid: int,
        gid: int,
        mode: int,
    ) -> None: ...

    def atomic_write_text(
        self,
        path: Path,
        content: str,
        *,
        uid: int,
        gid: int,
        mode: int,
    ) -> None: ...

    def remove_file(self, path: Path) -> None: ...


class SystemFileOperations:
    """No-follow, descriptor-based operations used by fixed-path adapters."""

    @staticmethod
    def _safe_flags(base: int) -> int:
        return base | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    @staticmethod
    def _require_real_owned_directory(path: Path) -> None:
        lexical = path.absolute()
        if path.resolve(strict=True) != lexical:
            raise UnsafePathError(f"refusing directory reached through a link: {path}")
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise UnsafePathError(f"path is not a real directory: {path}")
        if metadata.st_uid != os.geteuid():
            raise UnsafePathError(f"directory is not owned by the effective user: {path}")

    def snapshot(self, path: Path) -> FileSnapshot:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise UnsafePathError(f"refusing symbolic link: {path}")
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsafePathError(f"refusing non-regular file: {path}")
        if metadata.st_nlink != 1:
            raise UnsafePathError(f"refusing file with unexpected hard links: {path}")
        return FileSnapshot(
            mode=stat.S_IMODE(metadata.st_mode),
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=metadata.st_size,
        )

    def _open_verified(self, path: Path, expected: FileSnapshot, flags: int) -> int:
        descriptor = os.open(path, self._safe_flags(flags))
        try:
            current = os.fstat(descriptor)
            if not stat.S_ISREG(current.st_mode):
                raise UnsafePathError(f"refusing non-regular file: {path}")
            if current.st_nlink != 1:
                raise UnsafePathError(f"refusing file with unexpected hard links: {path}")
            if (current.st_dev, current.st_ino) != (
                expected.device,
                expected.inode,
            ):
                raise UnsafePathError(f"file identity changed before mutation: {path}")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def read_text(self, path: Path, *, max_bytes: int) -> str:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        snapshot = self.snapshot(path)
        if snapshot.size > max_bytes:
            raise OSError(f"file exceeds the {max_bytes}-byte inspection limit")
        descriptor = self._open_verified(path, snapshot, os.O_RDONLY)
        try:
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > max_bytes:
                raise OSError(f"file exceeds the {max_bytes}-byte inspection limit")
            return data.decode("utf-8", errors="replace")
        finally:
            os.close(descriptor)

    def make_private_directory(self, path: Path) -> None:
        resolved_before_creation = path.resolve(strict=False)
        if resolved_before_creation != path.absolute():
            raise UnsafePathError(f"refusing backup path reached through a link: {path}")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._require_real_owned_directory(path)
        path.chmod(0o700)

    def backup_file(
        self, source: Path, destination: Path, expected: FileSnapshot
    ) -> None:
        source_fd = self._open_verified(source, expected, os.O_RDONLY)
        destination_fd: int | None = None
        try:
            destination_fd = os.open(
                destination,
                self._safe_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
                0o600,
            )
            while True:
                chunk = os.read(source_fd, 65536)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    view = view[written:]
            os.fsync(destination_fd)
            os.fchown(destination_fd, expected.uid, expected.gid)
            os.fchmod(destination_fd, expected.mode)
        except BaseException:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        finally:
            os.close(source_fd)
            if destination_fd is not None:
                os.close(destination_fd)

    def set_metadata(
        self,
        path: Path,
        expected: FileSnapshot,
        *,
        uid: int,
        gid: int,
        mode: int,
    ) -> None:
        if uid < 0 or gid < 0 or mode < 0 or mode > 0o7777:
            raise ValueError("invalid file metadata target")
        descriptor = self._open_verified(path, expected, os.O_RDONLY)
        try:
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def atomic_write_text(
        self,
        path: Path,
        content: str,
        *,
        uid: int,
        gid: int,
        mode: int,
    ) -> None:
        if uid < 0 or gid < 0 or mode < 0 or mode > 0o7777:
            raise ValueError("invalid file metadata target")
        self._require_real_owned_directory(path.parent)
        temporary = path.parent / f".{path.name}.sentra-{secrets.token_hex(8)}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                self._safe_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
                0o600,
            )
            data = content.encode("utf-8")
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def remove_file(self, path: Path) -> None:
        snapshot = self.snapshot(path)
        if snapshot:
            path.unlink()


@dataclass(slots=True)
class AdapterContext:
    """Injected local view; the CLI always uses root ``/``."""

    root: Path = field(default_factory=lambda: Path("/"))
    runner: CommandRunner = field(default_factory=CommandRunner)
    files: FileOperations = field(default_factory=SystemFileOperations)
    environment: Mapping[str, str] = field(default_factory=dict)
    clock: Callable[[], datetime] = field(
        default_factory=lambda: lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        self.root = Path(self.root)

    def resolve(self, logical_path: str) -> Path:
        path = PurePosixPath(logical_path)
        if not path.is_absolute() or ".." in path.parts or "\x00" in logical_path:
            raise UnsafePathError(f"unsafe target path: {logical_path!r}")
        return self.root.joinpath(*path.parts[1:])

    def backup_directory(self, control_id: str) -> Path:
        if control_id not in {"7.1.1", "5.1.20"}:
            raise ValueError("backup directory is not defined for this adapter")
        return self.resolve(f"/var/backups/sentra/{control_id}")


@dataclass(frozen=True, slots=True)
class AdapterOutcome:
    remediation: RemediationResult
    post_audit: list[AuditEvidence]
    health_checks: list[HealthCheck]
    rollback: RollbackResult
    decision: ValidationDecision
    explanation: str
    warnings: list[str]
    errors: list[str]


class ControlAdapter(ABC):
    control_id: str
    title: str
    category: Category
    mutation_supported: bool

    @abstractmethod
    def pre_audit(self, context: AdapterContext) -> list[AuditEvidence]:
        """Collect current state without changing it."""

    @abstractmethod
    def plan(self, pre_audit: list[AuditEvidence]) -> list[RemediationAction]:
        """Describe only the adapter's fixed, hand-authored actions."""

    @abstractmethod
    def execute(
        self,
        context: AdapterContext,
        pre_audit: list[AuditEvidence],
        authorization: MutationAuthorization,
    ) -> AdapterOutcome:
        """Perform the explicitly supported experiment or refuse safely."""


__all__ = [
    "AdapterContext",
    "AdapterOutcome",
    "ControlAdapter",
    "FileOperations",
    "FileSnapshot",
    "SystemFileOperations",
    "UnsafePathError",
]
