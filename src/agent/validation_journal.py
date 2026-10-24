"""Crash-safe, credential-free journal for M6D mutation evidence.

M6A/M6B polling intentionally re-delivers dispatched jobs.  A read-only
profile can safely be collected again, but an M5 mutation must never be
repeated merely because an HTTPS response was lost.  This module records the
execution boundary before M5 runs and caches the resulting evidence before it
is submitted.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Iterator, Literal
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

from src.agent.state import AgentStateError
from src.controller.models import (
    ValidationJobRecord,
    ValidationResultPayload,
    ValidationResultRecord,
)


_MAX_JOURNAL_BYTES = 16 * 1024 * 1024


class ValidationJournalError(AgentStateError):
    """The protected local validation journal could not be trusted."""


class ValidationJournalInterruptedError(ValidationJournalError):
    """A prior validation stopped after its mutation boundary was armed."""


class ValidationJournalState(StrEnum):
    STARTED = "started"
    RESULT_READY = "result_ready"
    ACKNOWLEDGED = "acknowledged"


def _canonical_json(value: BaseModel) -> str:
    return json.dumps(
        value.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def validation_job_sha256(job: ValidationJobRecord) -> str:
    """Fingerprint every Controller-supplied field of one dispatched job."""

    return hashlib.sha256(_canonical_json(job).encode("utf-8")).hexdigest()


def validation_payload_sha256(payload: ValidationResultPayload) -> str:
    """Compute the canonical hash expected back from the Controller."""

    validated = ValidationResultPayload.model_validate(
        payload.model_dump(mode="python"),
        strict=True,
    )
    return hashlib.sha256(_canonical_json(validated).encode("utf-8")).hexdigest()


class ValidationJournalEntry(BaseModel):
    """One locally durable, UUID-addressed validation execution state."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
    )

    schema_version: Literal[1] = 1
    target_id: UUID
    agent_id: UUID
    validation_job_id: UUID
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: ValidationJournalState
    started_at: AwareDatetime
    result: ValidationResultPayload | None = None
    validation_result_id: UUID | None = None
    controller_result_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    @model_validator(mode="after")
    def validate_state(self) -> "ValidationJournalEntry":
        if self.state is ValidationJournalState.STARTED:
            if (
                self.result is not None
                or self.validation_result_id is not None
                or self.controller_result_sha256 is not None
            ):
                raise ValueError("a started journal entry cannot contain a result")
        elif self.state is ValidationJournalState.RESULT_READY:
            if self.result is None:
                raise ValueError("a result-ready journal entry requires evidence")
            if (
                self.validation_result_id is not None
                or self.controller_result_sha256 is not None
            ):
                raise ValueError(
                    "an unacknowledged journal entry cannot contain Controller metadata"
                )
        elif (
            self.result is None
            or self.validation_result_id is None
            or self.controller_result_sha256 is None
        ):
            raise ValueError(
                "an acknowledged journal entry requires evidence and Controller metadata"
            )

        if self.result is not None:
            if (
                self.result.target_id != self.target_id
                or self.result.validation_job_id != self.validation_job_id
            ):
                raise ValueError("journal evidence does not match its local identity")
        return self


class LockedValidationJournal:
    """One validation entry held under an exclusive process lock."""

    def __init__(
        self,
        store: "ValidationJournalStore",
        *,
        job: ValidationJobRecord,
        target_id: UUID,
        agent_id: UUID,
        entry: ValidationJournalEntry | None,
    ) -> None:
        self._store = store
        self.job = job
        self.target_id = target_id
        self.agent_id = agent_id
        self.request_sha256 = validation_job_sha256(job)
        self.entry = entry

    def mark_started(self) -> ValidationJournalEntry:
        if self.entry is not None:
            raise ValidationJournalError("validation job is already journaled")
        self.entry = ValidationJournalEntry(
            target_id=self.target_id,
            agent_id=self.agent_id,
            validation_job_id=self.job.validation_job_id,
            request_sha256=self.request_sha256,
            state=ValidationJournalState.STARTED,
            started_at=datetime.now(UTC),
        )
        self._store._write_entry(self.entry)
        return self.entry

    def cache_result(
        self,
        result: ValidationResultPayload,
    ) -> ValidationJournalEntry:
        if self.entry is None or self.entry.state is not ValidationJournalState.STARTED:
            raise ValidationJournalError(
                "validation result can be cached only after execution starts"
            )
        if (
            result.target_id != self.target_id
            or result.validation_job_id != self.job.validation_job_id
        ):
            raise ValidationJournalError("validation result does not match its job")
        self.entry = self.entry.model_copy(
            update={
                "state": ValidationJournalState.RESULT_READY,
                "result": result,
            }
        )
        # model_copy does not re-run model validation.
        self.entry = ValidationJournalEntry.model_validate(
            self.entry.model_dump(mode="python"),
            strict=True,
        )
        self._store._write_entry(self.entry)
        return self.entry

    def mark_acknowledged(
        self,
        record: ValidationResultRecord,
    ) -> ValidationJournalEntry:
        if self.entry is None or self.entry.result is None:
            raise ValidationJournalError("no cached validation result is available")
        if record.payload != self.entry.result:
            raise ValidationJournalError(
                "Controller acknowledgement changed validation evidence"
            )
        self.entry = self.entry.model_copy(
            update={
                "state": ValidationJournalState.ACKNOWLEDGED,
                "validation_result_id": record.validation_result_id,
                "controller_result_sha256": record.result_sha256,
            }
        )
        self.entry = ValidationJournalEntry.model_validate(
            self.entry.model_dump(mode="python"),
            strict=True,
        )
        self._store._write_entry(self.entry)
        return self.entry


class ValidationJournalStore:
    """Mode-0700 directory of mode-0600 UUID journal and lock files."""

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        supplied = Path(directory)
        if supplied.name in {"", ".", ".."}:
            raise ValidationJournalError("validation journal must name a directory")
        self.directory = Path(os.path.abspath(os.fspath(supplied)))

    @classmethod
    def for_agent_state(
        cls,
        state_path: str | os.PathLike[str],
    ) -> "ValidationJournalStore":
        state = Path(os.path.abspath(os.fspath(state_path)))
        return cls(state.with_name(f"{state.name}.validation-journal"))

    @staticmethod
    def _validate_trusted_ancestor(
        path: Path,
        item: os.stat_result,
    ) -> None:
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            raise ValidationJournalError(
                "validation journal parent must contain only real directories"
            )

        if stat.S_IMODE(item.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValidationJournalError(
                "validation journal parent must not be writable by group or others"
            )

        effective_uid = os.geteuid()

        if effective_uid == 0:
            if item.st_uid != 0:
                raise ValidationJournalError(
                    "privileged validation journal requires root-owned ancestors"
                )
        elif item.st_uid not in {0, effective_uid}:
            raise ValidationJournalError(
                "validation journal ancestors must be owned by root "
                "or the effective user"
            )

    def _ensure_directory(self) -> None:
        parent = self.directory.parent
        anchor = Path(parent.anchor)
        current = anchor
        relative_parts = parent.parts[1:] if parent.is_absolute() else parent.parts
        for part in relative_parts:
            current /= part
            try:
                item = os.lstat(current)
            except FileNotFoundError:
                try:
                    os.mkdir(current, mode=0o700)
                except FileExistsError:
                    pass
                item = os.lstat(current)
            self._validate_trusted_ancestor(current, item)

        try:
            directory_stat = os.lstat(self.directory)
        except FileNotFoundError:
            try:
                os.mkdir(self.directory, mode=0o700)
            except FileExistsError:
                pass
            directory_stat = os.lstat(self.directory)
        if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(
            directory_stat.st_mode
        ):
            raise ValidationJournalError(
                "validation journal must be a real directory"
            )
        if directory_stat.st_uid != os.geteuid():
            raise ValidationJournalError(
                "validation journal must be owned by the effective user"
            )
        if stat.S_IMODE(directory_stat.st_mode) != 0o700:
            raise ValidationJournalError(
                "validation journal directory permissions must be 0700"
            )

    @staticmethod
    def _validate_private_file(path: Path, item: os.stat_result) -> None:
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
            raise ValidationJournalError("validation journal entry is not a regular file")
        if item.st_uid != os.geteuid():
            raise ValidationJournalError(
                "validation journal entry must be owned by the effective user"
            )
        if stat.S_IMODE(item.st_mode) != 0o600:
            raise ValidationJournalError(
                "validation journal entry permissions must be 0600"
            )

    def _entry_path(self, validation_job_id: UUID) -> Path:
        return self.directory / f"{validation_job_id}.json"

    def _lock_path(self, validation_job_id: UUID) -> Path:
        return self.directory / f"{validation_job_id}.lock"

    def _open_lock(self, validation_job_id: UUID) -> int:
        path = self._lock_path(validation_job_id)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise ValidationJournalError(
                    "validation journal lock must not be a symlink"
                ) from None
            raise ValidationJournalError("validation journal lock could not open") from None
        try:
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            self._validate_private_file(path, opened)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            raise ValidationJournalError(
                "validation job is already active in another Agent process"
            ) from None
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _load_entry(
        self,
        validation_job_id: UUID,
    ) -> ValidationJournalEntry | None:
        path = self._entry_path(validation_job_id)
        try:
            expected = os.lstat(path)
        except FileNotFoundError:
            return None
        self._validate_private_file(path, expected)
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            self._validate_private_file(path, opened)
            if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
                raise ValidationJournalError(
                    "validation journal entry changed while opening"
                )
            raw = os.read(descriptor, _MAX_JOURNAL_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > _MAX_JOURNAL_BYTES:
            raise ValidationJournalError("validation journal entry exceeds size limit")
        try:
            return ValidationJournalEntry.model_validate_json(raw)
        except (ValidationError, ValueError, UnicodeError):
            raise ValidationJournalError("validation journal entry is invalid") from None

    def _write_entry(self, entry: ValidationJournalEntry) -> None:
        self._ensure_directory()
        rendered = (
            json.dumps(
                entry.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        if len(rendered) > _MAX_JOURNAL_BYTES:
            raise ValidationJournalError("validation journal entry exceeds size limit")

        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        directory_fd = os.open(self.directory, directory_flags)
        temporary_name = f".{entry.validation_job_id}.{uuid4().hex}.tmp"
        destination_name = f"{entry.validation_job_id}.json"
        descriptor: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_fd,
            )
            os.fchmod(descriptor, 0o600)
            view = memoryview(rendered)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("validation journal write made no progress")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(
                temporary_name,
                destination_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        except OSError:
            raise ValidationJournalError("validation journal could not be persisted") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.close(directory_fd)

    @contextmanager
    def acquire(
        self,
        job: ValidationJobRecord,
        *,
        target_id: UUID,
        agent_id: UUID,
    ) -> Iterator[LockedValidationJournal]:
        """Lock and validate the durable state for one UUID-addressed job."""

        if job.target_id != target_id:
            raise ValidationJournalError("validation job target does not match Agent")
        self._ensure_directory()
        lock_fd = self._open_lock(job.validation_job_id)
        try:
            entry = self._load_entry(job.validation_job_id)
            request_hash = validation_job_sha256(job)
            if entry is not None and (
                entry.target_id != target_id
                or entry.agent_id != agent_id
                or entry.validation_job_id != job.validation_job_id
                or entry.request_sha256 != request_hash
            ):
                raise ValidationJournalError(
                    "validation job conflicts with its durable local journal"
                )
            yield LockedValidationJournal(
                self,
                job=job,
                target_id=target_id,
                agent_id=agent_id,
                entry=entry,
            )
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


__all__ = [
    "LockedValidationJournal",
    "ValidationJournalEntry",
    "ValidationJournalError",
    "ValidationJournalInterruptedError",
    "ValidationJournalState",
    "ValidationJournalStore",
    "validation_job_sha256",
    "validation_payload_sha256",
]
