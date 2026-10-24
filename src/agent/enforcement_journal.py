"""Private, atomic journal for one fixed M7 enforcement transaction."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from contextlib import contextmanager
from collections.abc import Iterator
from typing import Literal
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, model_validator,
)

from src.controller.enforcement import verify_enforcement_delivery
from src.controller.models import EnforcementJobDelivery, EnforcementResultRecord
from src.sandbox_protocol.models import PasswdSourceState


_MAX_ENTRY_BYTES = 8192


class EnforcementJournalError(RuntimeError):
    """The local enforcement preflight journal cannot be trusted."""


class EnforcementPreflightOutcome(StrEnum):
    PREPARED = "PREPARED"
    BLOCKED_DRIFT = "BLOCKED_DRIFT"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


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
    updated_at: AwareDatetime | None = None
    pre_execution_observed_state: PasswdSourceState | None = None
    original_rollback_state: PasswdSourceState | None = None
    post_execution_observed_state: PasswdSourceState | None = None
    rollback_observed_state: PasswdSourceState | None = None
    mutation_attempted: bool = False
    mutation_changed: bool = False
    verification_succeeded: bool | None = None
    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None
    execution_started_at: AwareDatetime | None = None
    execution_finished_at: AwareDatetime | None = None
    controller_result_id: UUID | None = None
    controller_result_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$",
    )
    acknowledged_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> "EnforcementJournalEntry":
        acknowledgements = (
            self.controller_result_id, self.controller_result_sha256,
            self.acknowledged_at,
        )
        if any(value is None for value in acknowledgements) != all(
            value is None for value in acknowledgements
        ):
            raise ValueError("enforcement acknowledgement is incomplete")
        if self.acknowledged_at is not None and self.outcome.value not in {
            "SUCCEEDED", "BLOCKED_DRIFT", "FAILED", "ROLLED_BACK", "ROLLBACK_FAILED",
        }:
            raise ValueError("nonterminal enforcement cannot be acknowledged")
        if self.acknowledged_at is not None and self.acknowledged_at < (
            self.execution_finished_at or self.updated_at or self.recorded_at
        ):
            raise ValueError("enforcement acknowledgement precedes terminal evidence")
        if self.outcome is EnforcementPreflightOutcome.PREPARED and (
            self.observed_source_state != self.expected_source_state
            or self.mutation_attempted
            or self.original_rollback_state is not None
        ):
            raise ValueError("enforcement journal outcome contradicts observed state")
        if self.outcome is EnforcementPreflightOutcome.BLOCKED_DRIFT and (
            (self.pre_execution_observed_state or self.observed_source_state)
            == self.expected_source_state
            or self.mutation_changed
        ):
            raise ValueError("enforcement drift journal is inconsistent")
        if self.outcome is EnforcementPreflightOutcome.EXECUTING and (
            self.original_rollback_state != self.expected_source_state
            or self.pre_execution_observed_state != self.expected_source_state
            or not self.mutation_attempted
            or self.execution_started_at is None
        ):
            raise ValueError("executing journal lacks original metadata")
        if self.outcome is EnforcementPreflightOutcome.SUCCEEDED and (
            self.original_rollback_state != self.expected_source_state
            or self.post_execution_observed_state is None
            or self.verification_succeeded is not True
            or self.execution_finished_at is None
        ):
            raise ValueError("success journal lacks verified metadata")
        if self.outcome is EnforcementPreflightOutcome.FAILED and (
            self.mutation_attempted
            or self.verification_succeeded is not False
            or self.execution_finished_at is None
        ):
            raise ValueError("pre-mutation failure journal is inconsistent")
        if self.outcome in {
            EnforcementPreflightOutcome.ROLLED_BACK,
            EnforcementPreflightOutcome.ROLLBACK_FAILED,
        } and (
            not self.mutation_attempted
            or not self.rollback_attempted
            or self.rollback_succeeded is not (
                self.outcome is EnforcementPreflightOutcome.ROLLED_BACK
            )
            or self.original_rollback_state is None
            or self.execution_finished_at is None
        ):
            raise ValueError("rollback journal is inconsistent")
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

    @contextmanager
    def acquire(
        self, delivery: EnforcementJobDelivery, *, target_id: UUID, agent_id: UUID,
    ) -> Iterator["LockedEnforcementJournal"]:
        try:
            verify_enforcement_delivery(
                delivery, target_id=target_id, agent_id=agent_id,
            )
        except (ValueError, TypeError):
            raise EnforcementJournalError("enforcement delivery is invalid") from None
        self._ensure_directory()
        lock_path = self.directory / f"{delivery.enforcement_job_id}.lock"
        lock_fd = os.open(
            lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600,
        )
        try:
            self._private_file(os.fstat(lock_fd))
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            existing = self._load(delivery.enforcement_job_id)
            if existing is not None and (
                existing.enforcement_job_id != delivery.enforcement_job_id
                or existing.target_id != target_id
                or existing.agent_id != agent_id
                or existing.control_id != delivery.control_id
                or existing.m6_evidence_sha256 != delivery.sandbox_evidence_sha256
                or existing.delivery_sha256 != _delivery_sha256(delivery)
                or existing.expected_source_state != delivery.expected_source_state
            ):
                raise EnforcementJournalError("enforcement delivery conflicts with journal")
            yield LockedEnforcementJournal(self, delivery, target_id, agent_id, existing)
        except BlockingIOError:
            raise EnforcementJournalError("enforcement job is already active") from None
        finally:
            os.close(lock_fd)

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
        with self.acquire(delivery, target_id=target_id, agent_id=agent_id) as locked:
            return locked.prepare(observed, outcome)

    def pending_results(
        self, *, target_id: UUID, agent_id: UUID,
    ) -> list[EnforcementJournalEntry]:
        """Find only protected, terminal, unacknowledged entries for retry."""

        self._ensure_directory()
        pending: list[EnforcementJournalEntry] = []
        for name in sorted(os.listdir(self.directory)):
            if not name.endswith(".json"):
                continue
            raw_id = name[:-5]
            try:
                job_id = UUID(raw_id)
            except ValueError:
                raise EnforcementJournalError("enforcement journal filename is invalid") from None
            if raw_id != str(job_id):
                raise EnforcementJournalError("enforcement journal filename is noncanonical")
            entry = self._load(job_id)
            if entry is None or entry.enforcement_job_id != job_id:
                raise EnforcementJournalError("enforcement journal filename conflicts")
            if entry.target_id != target_id or entry.agent_id != agent_id:
                raise EnforcementJournalError("enforcement journal identity conflicts")
            if entry.acknowledged_at is None and entry.outcome.value in {
                "SUCCEEDED", "BLOCKED_DRIFT", "FAILED", "ROLLED_BACK", "ROLLBACK_FAILED",
            }:
                pending.append(entry)
        return pending

    def acknowledge_result(
        self, entry: EnforcementJournalEntry, record: EnforcementResultRecord,
    ) -> EnforcementJournalEntry:
        """Durably bind the Controller response to the exact terminal payload."""

        from src.agent.enforcement_result import payload_from_trusted_journal
        from src.controller.enforcement import canonical_enforcement_payload_json

        self._ensure_directory()
        lock_fd = os.open(
            self.directory / f"{entry.enforcement_job_id}.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600,
        )
        try:
            self._private_file(os.fstat(lock_fd))
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = self._load(entry.enforcement_job_id)
            if current is None:
                raise EnforcementJournalError("enforcement journal disappeared")
            expected_payload = payload_from_trusted_journal(
                current, target_id=current.target_id, agent_id=current.agent_id,
            )
            expected_sha = hashlib.sha256(
                canonical_enforcement_payload_json(expected_payload).encode("utf-8")
            ).hexdigest()
            if (
                record.enforcement_job_id != current.enforcement_job_id
                or record.target_id != current.target_id
                or record.agent_id != current.agent_id
                or record.payload != expected_payload
                or record.result_sha256 != expected_sha
                or current.model_dump(
                    exclude={"controller_result_id", "controller_result_sha256", "acknowledged_at"}
                ) != entry.model_dump(
                    exclude={"controller_result_id", "controller_result_sha256", "acknowledged_at"}
                )
            ):
                raise EnforcementJournalError("Controller enforcement acknowledgement conflicts")
            if current.acknowledged_at is not None:
                if (
                    current.controller_result_id != record.enforcement_result_id
                    or current.controller_result_sha256 != record.result_sha256
                ):
                    raise EnforcementJournalError("Controller enforcement acknowledgement changed")
                return current
            values = current.model_dump(mode="python")
            values.update(
                controller_result_id=record.enforcement_result_id,
                controller_result_sha256=record.result_sha256,
                acknowledged_at=datetime.now(UTC),
            )
            updated = EnforcementJournalEntry.model_validate(values, strict=True)
            self._write(updated)
            return updated
        except BlockingIOError:
            raise EnforcementJournalError("enforcement job is already active") from None
        finally:
            os.close(lock_fd)


class LockedEnforcementJournal:
    """Holds the per-job lock across drift recheck, mutation, and final write."""

    def __init__(
        self, store: EnforcementJournalStore, delivery: EnforcementJobDelivery,
        target_id: UUID, agent_id: UUID, entry: EnforcementJournalEntry | None,
    ) -> None:
        self._store = store
        self._delivery = delivery
        self._target_id = target_id
        self._agent_id = agent_id
        self.entry = entry

    def prepare(
        self, observed: PasswdSourceState, outcome: EnforcementPreflightOutcome,
    ) -> EnforcementJournalEntry:
        expected_outcome = (
            EnforcementPreflightOutcome.PREPARED
            if observed == self._delivery.expected_source_state
            else EnforcementPreflightOutcome.BLOCKED_DRIFT
        )
        if outcome is not expected_outcome:
            raise EnforcementJournalError("enforcement drift outcome is inconsistent")
        if self.entry is not None:
            if self.entry.observed_source_state != observed or self.entry.outcome is not outcome:
                raise EnforcementJournalError("enforcement delivery conflicts with journal")
            return self.entry
        entry = EnforcementJournalEntry(
            enforcement_job_id=self._delivery.enforcement_job_id,
            target_id=self._target_id, agent_id=self._agent_id,
            control_id="7.1.1",
            m6_evidence_sha256=self._delivery.sandbox_evidence_sha256,
            delivery_sha256=_delivery_sha256(self._delivery),
            expected_source_state=self._delivery.expected_source_state,
            observed_source_state=observed,
            outcome=outcome,
            recorded_at=datetime.now(UTC),
        )
        self._store._write(entry)
        self.entry = entry
        return entry

    def transition(
        self, outcome: EnforcementPreflightOutcome, **changes: object,
    ) -> EnforcementJournalEntry:
        entry = self.entry
        if entry is None:
            raise EnforcementJournalError("enforcement journal is not prepared")
        allowed = {
            EnforcementPreflightOutcome.PREPARED: {
                EnforcementPreflightOutcome.BLOCKED_DRIFT,
                EnforcementPreflightOutcome.EXECUTING,
                EnforcementPreflightOutcome.SUCCEEDED,
                EnforcementPreflightOutcome.FAILED,
            },
            EnforcementPreflightOutcome.EXECUTING: {
                EnforcementPreflightOutcome.BLOCKED_DRIFT,
                EnforcementPreflightOutcome.EXECUTING,
                EnforcementPreflightOutcome.SUCCEEDED,
                EnforcementPreflightOutcome.ROLLED_BACK,
                EnforcementPreflightOutcome.ROLLBACK_FAILED,
            },
        }
        if outcome not in allowed.get(entry.outcome, set()):
            raise EnforcementJournalError("enforcement journal transition is invalid")
        mutable_fields = {
            "pre_execution_observed_state", "original_rollback_state",
            "post_execution_observed_state", "rollback_observed_state",
            "mutation_attempted", "mutation_changed", "verification_succeeded",
            "rollback_attempted", "rollback_succeeded",
            "execution_started_at", "execution_finished_at",
        }
        if not changes.keys() <= mutable_fields:
            raise EnforcementJournalError("enforcement journal lineage cannot change")
        values = entry.model_dump(mode="python")
        values.update(changes)
        values["outcome"] = outcome
        values["updated_at"] = datetime.now(UTC)
        try:
            updated = EnforcementJournalEntry.model_validate(values, strict=True)
        except ValidationError:
            raise EnforcementJournalError("enforcement journal transition is malformed") from None
        self._store._write(updated)
        self.entry = updated
        return updated


__all__ = [
    "EnforcementJournalEntry", "EnforcementJournalError",
    "EnforcementJournalStore", "EnforcementPreflightOutcome", "LockedEnforcementJournal",
]
