"""Fixed, metadata-only Agent execution of approved control 7.1.1."""

from __future__ import annotations

from datetime import UTC, datetime
import os
import stat
from typing import Protocol

from src.agent.enforcement import PASSWD_PATH
from src.agent.enforcement_journal import (
    EnforcementJournalEntry, EnforcementPreflightOutcome as State,
    LockedEnforcementJournal,
)
from src.controller.models import EnforcementJobDelivery
from src.sandbox_protocol.models import PasswdSourceState


class EnforcementExecutionError(RuntimeError):
    """The fixed target cannot be safely enforced or verified."""


class EnforcementExecutionInterruptedError(EnforcementExecutionError):
    """An interrupted change requires an explicit, inspected recovery choice."""


class _MetadataFilesystem(Protocol):
    """Only descriptor metadata operations; no content-access method."""

    def lstat(self, path: str) -> os.stat_result: ...
    def open(self, path: str, flags: int) -> int: ...
    def fstat(self, descriptor: int) -> os.stat_result: ...
    def fchown(self, descriptor: int, uid: int, gid: int) -> None: ...
    def fchmod(self, descriptor: int, mode: int) -> None: ...
    def fsync(self, descriptor: int) -> None: ...
    def close(self, descriptor: int) -> None: ...


_FILESYSTEM: _MetadataFilesystem = os


def _state(metadata: os.stat_result) -> PasswdSourceState:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise EnforcementExecutionError("fixed passwd target is not a unique regular file")
    return PasswdSourceState(
        passwd_file_mode=f"{stat.S_IMODE(metadata.st_mode):04o}",
        passwd_file_owner_uid=metadata.st_uid,
        passwd_file_group_gid=metadata.st_gid,
    )


def _opened_state(filesystem: _MetadataFilesystem, descriptor: int) -> PasswdSourceState:
    path_item = filesystem.lstat(PASSWD_PATH)
    opened = filesystem.fstat(descriptor)
    if (
        not stat.S_ISREG(path_item.st_mode)
        or path_item.st_nlink != 1
        or (path_item.st_dev, path_item.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise EnforcementExecutionError("fixed passwd object changed during execution")
    return _state(opened)


def _open_fixed(filesystem: _MetadataFilesystem) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise EnforcementExecutionError("safe fixed-path open is unavailable")
    before = filesystem.lstat(PASSWD_PATH)
    _state(before)
    descriptor = filesystem.open(
        PASSWD_PATH, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened = filesystem.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise EnforcementExecutionError("fixed passwd object changed while opening")
        _opened_state(filesystem, descriptor)
        return descriptor
    except BaseException:
        filesystem.close(descriptor)
        raise


def _desired(original: PasswdSourceState) -> PasswdSourceState:
    # Exact fixed M5 PasswdPermissionsAdapter rule: current mode masked by 0644.
    return PasswdSourceState(
        passwd_file_mode=f"{int(original.passwd_file_mode, 8) & 0o644:04o}",
        passwd_file_owner_uid=0,
        passwd_file_group_gid=0,
    )


def _healthy(state: PasswdSourceState, desired: PasswdSourceState) -> bool:
    mode = int(state.passwd_file_mode, 8)
    # M5's narrow readability-mode check is mirrored without reading contents.
    return (
        state == desired
        and state.passwd_file_owner_uid == 0
        and state.passwd_file_group_gid == 0
        and mode & ~0o644 == 0
        and bool(mode & stat.S_IRUSR)
    )


def _restore(
    filesystem: _MetadataFilesystem, descriptor: int,
    original: PasswdSourceState,
) -> bool:
    try:
        filesystem.fchown(
            descriptor, original.passwd_file_owner_uid,
            original.passwd_file_group_gid,
        )
        filesystem.fchmod(descriptor, int(original.passwd_file_mode, 8))
        filesystem.fsync(descriptor)
        return _opened_state(filesystem, descriptor) == original
    except Exception:
        return False


def _execute(
    delivery: EnforcementJobDelivery,
    journal: LockedEnforcementJournal,
    *,
    filesystem: _MetadataFilesystem,
    retry_interrupted: bool,
) -> EnforcementJournalEntry:
    if filesystem is os and os.geteuid() != 0:
        raise EnforcementExecutionError("fixed passwd enforcement requires root Agent identity")
    entry = journal.entry
    if entry is None:
        raise EnforcementExecutionError("enforcement journal is not PREPARED")
    if entry.outcome is State.SUCCEEDED:
        return entry
    if entry.outcome in {
        State.BLOCKED_DRIFT, State.FAILED, State.ROLLED_BACK,
        State.ROLLBACK_FAILED, State.REJECTED,
    }:
        return entry  # terminal: never repeat a mutation automatically
    if entry.outcome not in {State.PREPARED, State.EXECUTING}:
        raise EnforcementExecutionError("enforcement journal state is invalid")
    if (
        entry.enforcement_job_id != delivery.enforcement_job_id
        or entry.target_id != delivery.target_id
        or entry.agent_id != delivery.assigned_agent_id
        or entry.control_id != "7.1.1"
        or entry.m6_evidence_sha256 != delivery.sandbox_evidence_sha256
        or entry.expected_source_state != delivery.expected_source_state
    ):
        raise EnforcementExecutionError("enforcement journal lineage is invalid")

    descriptor: int | None = None
    try:
        try:
            descriptor = _open_fixed(filesystem)
        except (OSError, EnforcementExecutionError):
            if entry.outcome is State.PREPARED:
                journal.transition(
                    State.FAILED,
                    verification_succeeded=False,
                    execution_finished_at=datetime.now(UTC),
                )
            raise EnforcementExecutionError("fixed passwd metadata is unavailable") from None
        observed = _opened_state(filesystem, descriptor)
        expected = delivery.expected_source_state
        desired = _desired(expected)

        if entry.outcome is State.EXECUTING:
            if entry.original_rollback_state != expected:
                raise EnforcementExecutionInterruptedError("interrupted original state is invalid")
            if _healthy(observed, desired):
                return journal.transition(
                    State.SUCCEEDED,
                    post_execution_observed_state=observed,
                    verification_succeeded=True,
                    mutation_changed=True,
                    execution_finished_at=datetime.now(UTC),
                )
            if observed != expected:
                raise EnforcementExecutionInterruptedError(
                    "interrupted target metadata is ambiguous; manual recovery required"
                )
            if not retry_interrupted:
                raise EnforcementExecutionInterruptedError(
                    "interrupted original state requires explicit retry authorization"
                )
        elif observed != expected:
            return journal.transition(
                State.BLOCKED_DRIFT,
                pre_execution_observed_state=observed,
            )

        if not int(desired.passwd_file_mode, 8) & stat.S_IRUSR:
            if entry.outcome is State.EXECUTING:
                raise EnforcementExecutionInterruptedError(
                    "interrupted target metadata cannot pass readability verification"
                )
            return journal.transition(
                State.FAILED,
                pre_execution_observed_state=observed,
                original_rollback_state=observed,
                post_execution_observed_state=observed,
                verification_succeeded=False,
                execution_finished_at=datetime.now(UTC),
            )

        if _healthy(observed, desired):
            return journal.transition(
                State.SUCCEEDED,
                pre_execution_observed_state=observed,
                original_rollback_state=observed,
                post_execution_observed_state=observed,
                mutation_attempted=False,
                mutation_changed=False,
                verification_succeeded=True,
                execution_finished_at=datetime.now(UTC),
            )

        if entry.outcome is State.PREPARED:
            journal.transition(
                State.EXECUTING,
                pre_execution_observed_state=observed,
                original_rollback_state=observed,
                mutation_attempted=True,
                execution_started_at=datetime.now(UTC),
            )
        # This is the second, execution-time drift gate, on the same descriptor
        # immediately before the first metadata-changing syscall.
        fresh = _opened_state(filesystem, descriptor)
        if fresh != expected:
            return journal.transition(
                State.BLOCKED_DRIFT,
                pre_execution_observed_state=fresh,
                mutation_attempted=False,
            )

        try:
            if (fresh.passwd_file_owner_uid, fresh.passwd_file_group_gid) != (0, 0):
                filesystem.fchown(descriptor, 0, 0)
            if fresh.passwd_file_mode != desired.passwd_file_mode:
                filesystem.fchmod(descriptor, int(desired.passwd_file_mode, 8))
            filesystem.fsync(descriptor)
            post = _opened_state(filesystem, descriptor)
            if not _healthy(post, desired):
                raise EnforcementExecutionError("fixed passwd post-verification failed")
            return journal.transition(
                State.SUCCEEDED,
                post_execution_observed_state=post,
                mutation_changed=True,
                verification_succeeded=True,
                execution_finished_at=datetime.now(UTC),
            )
        except Exception:
            try:
                post = _opened_state(filesystem, descriptor)
            except Exception:
                post = None
            restored = _restore(filesystem, descriptor, expected)
            try:
                rollback_state = _opened_state(filesystem, descriptor)
            except Exception:
                rollback_state = None
            return journal.transition(
                State.ROLLED_BACK if restored else State.ROLLBACK_FAILED,
                post_execution_observed_state=post,
                rollback_observed_state=rollback_state,
                mutation_changed=post != expected if post is not None else True,
                verification_succeeded=False,
                rollback_attempted=True,
                rollback_succeeded=restored,
                execution_finished_at=datetime.now(UTC),
            )
    except OSError:
        raise EnforcementExecutionError("fixed passwd metadata is unavailable") from None
    finally:
        if descriptor is not None:
            filesystem.close(descriptor)


def execute_prepared_enforcement(
    delivery: EnforcementJobDelivery,
    journal: LockedEnforcementJournal,
    *,
    retry_interrupted: bool = False,
) -> EnforcementJournalEntry:
    """Execute only the already-locked fixed 7.1.1 transaction."""

    return _execute(
        delivery, journal, filesystem=_FILESYSTEM,
        retry_interrupted=retry_interrupted,
    )


__all__ = [
    "EnforcementExecutionError", "EnforcementExecutionInterruptedError",
    "execute_prepared_enforcement",
]
