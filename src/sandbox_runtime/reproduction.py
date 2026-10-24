"""Reproduce the allowlisted 7.1.1 passwd metadata in the sandbox guest."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from typing import Literal, Protocol

from src.sandbox_protocol import PasswdSourceState, SandboxContextManifest


SANDBOX_PASSWD_TARGET_PATH = "/etc/passwd"
_CONTROL_ID: Literal["7.1.1"] = "7.1.1"
_MODE_PATTERN = re.compile(r"[0-7]{4}\Z")
_FIXED_ERROR_MESSAGE = "sandbox source-state reproduction failed"


class SandboxStateReproductionError(RuntimeError):
    """Fixed, non-sensitive failure for source-state reproduction."""


@dataclass(frozen=True, slots=True)
class SandboxPasswdReproductionResult:
    """Immutable metadata-only record of a successful source-state replay."""

    control_id: Literal["7.1.1"]
    target_path: Literal["/etc/passwd"]
    before_mode: str
    before_uid: int
    before_gid: int
    requested_mode: str
    requested_uid: int
    requested_gid: int
    after_mode: str
    after_uid: int
    after_gid: int
    reproduced: bool


@dataclass(frozen=True, slots=True)
class _MetadataSnapshot:
    mode: int
    uid: int
    gid: int


class _MetadataFilesystem(Protocol):
    """Narrow fd-only metadata operations; no content read/write methods."""

    def open(self, path: str, flags: int) -> int: ...

    def fstat(self, descriptor: int) -> os.stat_result: ...

    def fchown(self, descriptor: int, uid: int, gid: int) -> None: ...

    def fchmod(self, descriptor: int, mode: int) -> None: ...

    def close(self, descriptor: int) -> None: ...


_FILESYSTEM: _MetadataFilesystem = os


def _validated_source_values(
    manifest: SandboxContextManifest,
) -> tuple[str, int, int, int]:
    if type(manifest) is not SandboxContextManifest:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
    if manifest.control_id != _CONTROL_ID:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)

    source_state = manifest.source_state
    if type(source_state) is not PasswdSourceState:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)

    mode_text = source_state.passwd_file_mode
    uid = source_state.passwd_file_owner_uid
    gid = source_state.passwd_file_group_gid
    if type(mode_text) is not str or _MODE_PATTERN.fullmatch(mode_text) is None:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
    if type(uid) is not int or uid < 0 or type(gid) is not int or gid < 0:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)

    return mode_text, int(mode_text, 8), uid, gid


def _snapshot(filesystem: _MetadataFilesystem, descriptor: int) -> _MetadataSnapshot:
    metadata = filesystem.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
    return _MetadataSnapshot(
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def _restore_metadata(
    filesystem: _MetadataFilesystem,
    descriptor: int,
    before: _MetadataSnapshot,
) -> None:
    filesystem.fchown(descriptor, before.uid, before.gid)
    filesystem.fchmod(descriptor, before.mode)
    if _snapshot(filesystem, descriptor) != before:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)


def _reproduce_source_state(
    manifest: SandboxContextManifest,
    *,
    filesystem: _MetadataFilesystem,
) -> SandboxPasswdReproductionResult:
    mode_text, requested_mode, requested_uid, requested_gid = (
        _validated_source_values(manifest)
    )

    descriptor: int | None = None
    before: _MetadataSnapshot | None = None
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = filesystem.open(SANDBOX_PASSWD_TARGET_PATH, flags)
        before = _snapshot(filesystem, descriptor)

        try:
            filesystem.fchown(descriptor, requested_uid, requested_gid)
            filesystem.fchmod(descriptor, requested_mode)
            after = _snapshot(filesystem, descriptor)
            if after != _MetadataSnapshot(
                mode=requested_mode,
                uid=requested_uid,
                gid=requested_gid,
            ):
                raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
        except Exception:
            try:
                _restore_metadata(filesystem, descriptor, before)
            except Exception:
                pass
            raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE) from None

        return SandboxPasswdReproductionResult(
            control_id=_CONTROL_ID,
            target_path=SANDBOX_PASSWD_TARGET_PATH,
            before_mode=f"{before.mode:04o}",
            before_uid=before.uid,
            before_gid=before.gid,
            requested_mode=mode_text,
            requested_uid=requested_uid,
            requested_gid=requested_gid,
            after_mode=f"{after.mode:04o}",
            after_uid=after.uid,
            after_gid=after.gid,
            reproduced=True,
        )
    except SandboxStateReproductionError:
        raise
    except Exception:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE) from None
    finally:
        if descriptor is not None:
            try:
                filesystem.close(descriptor)
            except Exception:
                pass


def reproduce_passwd_source_state(
    manifest: SandboxContextManifest,
) -> SandboxPasswdReproductionResult:
    """Apply only validated 7.1.1 metadata to the fixed sandbox passwd file."""

    return _reproduce_source_state(
        manifest,
        filesystem=_FILESYSTEM,
    )
