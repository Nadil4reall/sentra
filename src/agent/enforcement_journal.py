"""Private, atomic journal for read-only M7-B enforcement preflight."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Literal
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, model_validator,
)

from src.controller.enforcement import verify_enforcement_delivery
from src.controller.models import EnforcementJobDelivery
from src.sandbox_protocol.models import PasswdSourceState


_MAX_ENTRY_BYTES = 4096


class EnforcementJournalError(RuntimeError):
    """The local enforcement preflight journal cannot be trusted."""


class EnforcementPreflightOutcome(StrEnum):
    PREPARED = "PREPARED"
    BLOCKED_DRIFT = "BLOCKED_DRIFT"
    REJECTED = "REJECTED"


class EnforcementJournalEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal[1] = 1
    enforcement_job_id: UUID
    target_id: UUID
    agent_id: UUID
    control_id: Literal["7.1.1"]
    m6_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    delivery_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_source_state: PasswdSourceState
    observed_source_state: PasswdSourceState
    outcome: EnforcementPreflightOutcome
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def validate_outcome(self) -> "EnforcementJournalEntry":
        if (
            self.outcome is EnforcementPreflightOutcome.PREPARED
            and self.observed_source_state != self.expected_source_state
        ) or (
            self.outcome is EnforcementPreflightOutcome.BLOCKED_DRIFT
            and self.observed_source_state == self.expected_source_state
        ):
            raise ValueError("enforcement journal outcome contradicts observed state")
        return self


def _delivery_sha256(delivery: EnforcementJobDelivery) -> str:
    validated = EnforcementJobDelivery.model_validate(
        delivery.model_dump(mode="python"), strict=True,
    )
    canonical = json.dumps(
        validated.model_dump(mode="json"), sort_keys=True,
        ensure_ascii=False, allow_nan=False, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class EnforcementJournalStore:
    """A dedicated 0700 directory with 0600 UUID entries and locks."""

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        supplied = Path(directory)
        if supplied.name in {"", ".", ".."}:
            raise EnforcementJournalError("enforcement journal path is invalid")
        self.directory = Path(os.path.abspath(os.fspath(supplied)))

    @classmethod
    def for_agent_state(
        cls, state_path: str | os.PathLike[str],
    ) -> "EnforcementJournalStore":
        state = Path(os.path.abspath(os.fspath(state_path)))
        return cls(state.with_name(f"{state.name}.enforcement-journal"))

    @staticmethod
    def _private_file(item: os.stat_result) -> None:
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) != 0o600
            or item.st_nlink != 1
        ):
            raise EnforcementJournalError("enforcement journal file is untrusted")

    def _ensure_directory(self) -> None:
        current = Path(self.directory.anchor)
        for part in self.directory.parent.parts[1:]:
            current /= part
            try:
                item = os.lstat(current)
            except FileNotFoundError:
                raise EnforcementJournalError("enforcement journal ancestor is missing") from None
            if (
                not stat.S_ISDIR(item.st_mode)
                or stat.S_IMODE(item.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
                or item.st_uid not in ({0} if os.geteuid() == 0 else {0, os.geteuid()})
            ):
                raise EnforcementJournalError("enforcement journal ancestor is untrusted")
        try:
            os.mkdir(self.directory, mode=0o700)
        except FileExistsError:
            pass
        item = os.lstat(self.directory)
        if (
            not stat.S_ISDIR(item.st_mode)
            or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) != 0o700
        ):
            raise EnforcementJournalError("enforcement journal directory is untrusted")

    def _load(self, job_id: UUID) -> EnforcementJournalEntry | None:
        path = self.directory / f"{job_id}.json"
        try:
            expected = os.lstat(path)
        except FileNotFoundError:
            return None
        self._private_file(expected)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            self._private_file(opened)
            if (expected.st_dev, expected.st_ino) != (opened.st_dev, opened.st_ino):
                raise EnforcementJournalError("enforcement journal entry changed")
            if opened.st_size > _MAX_ENTRY_BYTES:
                raise EnforcementJournalError("enforcement journal entry is oversized")
            raw = os.read(descriptor, _MAX_ENTRY_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > _MAX_ENTRY_BYTES:
            raise EnforcementJournalError("enforcement journal entry is oversized")
        try:
            return EnforcementJournalEntry.model_validate_json(raw)
        except (ValidationError, ValueError, UnicodeError):
            raise EnforcementJournalError("enforcement journal entry is malformed") from None

    def _write(self, entry: EnforcementJournalEntry) -> None:
        rendered = (
            json.dumps(
                entry.model_dump(mode="json"), sort_keys=True,
                ensure_ascii=False, allow_nan=False, separators=(",", ":"),
            ) + "\n"
        ).encode("utf-8")
        if len(rendered) > _MAX_ENTRY_BYTES:
            raise EnforcementJournalError("enforcement journal entry is oversized")
        directory_fd = os.open(
            self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        temporary = f".{entry.enforcement_job_id}.{uuid4().hex}.tmp"
        descriptor = None
        try:
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=directory_fd,
            )
            self._private_file(os.fstat(descriptor))
            view = memoryview(rendered)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise EnforcementJournalError("enforcement journal write stalled")
                view = view[count:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(
                temporary, f"{entry.enforcement_job_id}.json",
                src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.close(directory_fd)

    def record(
        self,
        delivery: EnforcementJobDelivery,
        *,
        target_id: UUID,
        agent_id: UUID,
        observed: PasswdSourceState,
        outcome: EnforcementPreflightOutcome,
    ) -> EnforcementJournalEntry:
        try:
            verify_enforcement_delivery(
                delivery, target_id=target_id, agent_id=agent_id,
            )
        except (ValueError, TypeError):
            raise EnforcementJournalError("enforcement delivery is invalid") from None
        if outcome not in {
            EnforcementPreflightOutcome.PREPARED,
            EnforcementPreflightOutcome.BLOCKED_DRIFT,
        }:
            raise EnforcementJournalError("enforcement outcome is invalid")
        expected_outcome = (
            EnforcementPreflightOutcome.PREPARED
            if observed == delivery.expected_source_state
            else EnforcementPreflightOutcome.BLOCKED_DRIFT
        )
        if outcome is not expected_outcome:
            raise EnforcementJournalError("enforcement drift outcome is inconsistent")
        self._ensure_directory()
        lock_path = self.directory / f"{delivery.enforcement_job_id}.lock"
        lock_fd = os.open(
            lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600,
        )
        try:
            self._private_file(os.fstat(lock_fd))
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            existing = self._load(delivery.enforcement_job_id)
            digest = _delivery_sha256(delivery)
            if existing is not None:
                if (
                    existing.enforcement_job_id != delivery.enforcement_job_id
                    or existing.target_id != target_id
                    or existing.agent_id != agent_id
                    or existing.control_id != delivery.control_id
                    or existing.m6_evidence_sha256 != delivery.sandbox_evidence_sha256
                    or existing.delivery_sha256 != digest
                    or existing.expected_source_state != delivery.expected_source_state
                    or existing.observed_source_state != observed
                    or existing.outcome is not outcome
                ):
                    raise EnforcementJournalError("enforcement delivery conflicts with journal")
                return existing
            entry = EnforcementJournalEntry(
                enforcement_job_id=delivery.enforcement_job_id,
                target_id=target_id, agent_id=agent_id,
                control_id="7.1.1",
                m6_evidence_sha256=delivery.sandbox_evidence_sha256,
                delivery_sha256=digest,
                expected_source_state=delivery.expected_source_state,
                observed_source_state=observed,
                outcome=outcome,
                recorded_at=datetime.now(UTC),
            )
            self._write(entry)
            return entry
        except BlockingIOError:
            raise EnforcementJournalError("enforcement job is already active") from None
        finally:
            os.close(lock_fd)


__all__ = [
    "EnforcementJournalEntry", "EnforcementJournalError",
    "EnforcementJournalStore", "EnforcementPreflightOutcome",
]
