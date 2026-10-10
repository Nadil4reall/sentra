"""M7-C fixed passwd enforcement tests: all target metadata I/O is fake."""

from __future__ import annotations

from datetime import UTC, datetime
import inspect
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from uuid import uuid4

from pydantic import ValidationError
import pytest

import src.agent.enforcement as preflight
import src.agent.enforcement_execute as execute
from src.agent.enforcement_journal import (
    EnforcementJournalError, EnforcementJournalStore,
    EnforcementPreflightOutcome as State,
)
from src.agent.runtime import AgentRuntime
from src.controller.models import EnforcementJobDelivery

from test_m6_agent_runtime import _Profiler, _Transport, _protocol
from test_m7_enforcement_delivery import _delivery, _state


class FakePasswdFilesystem:
    def __init__(self, state=None) -> None:
        self.state = state or _state()
        self.calls: list[str] = []
        self.lstat_count = 0
        self.drift_on_lstat: int | None = None
        self.drift_to = None
        self.symlink = False
        self.nonregular = False
        self.fail_chown_once = False
        self.fail_chmod_once = False
        self.fail_chmod_always = False
        self.ignore_chmod = False
        self.closed = False

    def _stat(self, *, path: bool = False):
        kind = stat.S_IFLNK if path and self.symlink else (
            stat.S_IFDIR if self.nonregular else stat.S_IFREG
        )
        return SimpleNamespace(
            st_mode=kind | int(self.state.passwd_file_mode, 8),
            st_uid=self.state.passwd_file_owner_uid,
            st_gid=self.state.passwd_file_group_gid,
            st_nlink=1, st_dev=1, st_ino=7,
        )

    def lstat(self, path):
        assert path == "/etc/passwd"
        self.calls.append("lstat")
        self.lstat_count += 1
        if self.drift_on_lstat == self.lstat_count:
            self.state = self.drift_to
        return self._stat(path=True)

    def open(self, path, flags):
        assert path == "/etc/passwd"
        assert flags & os.O_NOFOLLOW
        assert flags & os.O_RDONLY == os.O_RDONLY
        self.calls.append("open")
        return 19

    def fstat(self, descriptor):
        assert descriptor == 19
        self.calls.append("fstat")
        return self._stat()

    def fchown(self, descriptor, uid, gid):
        assert descriptor == 19
        self.calls.append("fchown")
        if self.fail_chown_once:
            self.fail_chown_once = False
            raise OSError("simulated chown failure")
        self.state = _state(self.state.passwd_file_mode, uid, gid)

    def fchmod(self, descriptor, mode):
        assert descriptor == 19
        self.calls.append("fchmod")
        if self.fail_chmod_always or self.fail_chmod_once:
            self.fail_chmod_once = False
            raise OSError("simulated chmod failure")
        if not self.ignore_chmod:
            self.state = _state(f"{mode:04o}", self.state.passwd_file_owner_uid,
                                self.state.passwd_file_group_gid)

    def fsync(self, descriptor):
        assert descriptor == 19
        self.calls.append("fsync")

    def close(self, descriptor):
        assert descriptor == 19
        self.calls.append("close")
        self.closed = True


def _prepared(tmp_path: Path, *, expected=None):
    case, delivery = _delivery(tmp_path)
    if expected is not None:
        # A synthetic approved source state allows exercising the 0664->0644
        # primitive without modifying the Controller's original test database.
        delivery = EnforcementJobDelivery.model_validate({
            **delivery.model_dump(mode="python"),
            "expected_source_state": expected,
        }, strict=True)
    journal = EnforcementJournalStore.for_agent_state(tmp_path / "agent-state.json")
    journal.record(
        delivery, target_id=case.enrollment.target_id,
        agent_id=case.enrollment.agent_id,
        observed=delivery.expected_source_state,
        outcome=State.PREPARED,
    )
    return case, delivery, journal


def _run(case, delivery, journal, filesystem, *, retry=False):
    with journal.acquire(
        delivery, target_id=case.enrollment.target_id,
        agent_id=case.enrollment.agent_id,
    ) as locked:
        return execute._execute(
            delivery, locked, filesystem=filesystem, retry_interrupted=retry,
        )


def test_prepared_exact_0664_source_executes_fixed_metadata_only(tmp_path):
    case, delivery, journal = _prepared(tmp_path, expected=_state("0664"))
    files = FakePasswdFilesystem(_state("0664"))
    result = _run(case, delivery, journal, files)
    assert result.outcome is State.SUCCEEDED
    assert result.original_rollback_state == _state("0664")
    assert result.post_execution_observed_state == _state()
    assert result.mutation_attempted and result.mutation_changed
    assert result.verification_succeeded is True
    assert files.state == _state()
    assert files.calls.count("fchmod") == 1
    assert files.calls.count("fchown") == 0


def test_already_compliant_does_not_mutate_but_verifies(tmp_path):
    case, delivery, journal = _prepared(tmp_path)
    files = FakePasswdFilesystem()
    result = _run(case, delivery, journal, files)
    assert result.outcome is State.SUCCEEDED
    assert result.mutation_attempted is False and result.mutation_changed is False
    assert result.verification_succeeded is True
    assert not {"fchmod", "fchown"}.intersection(files.calls)
    again = _run(case, delivery, journal, FakePasswdFilesystem(_state("0664")))
    assert again == result  # terminal redelivery never reopens or changes target


@pytest.mark.parametrize("drift", [_state("0664"), _state(uid=1), _state(gid=1)])
def test_execution_time_drift_blocks_with_zero_mutation(tmp_path, drift):
    case, delivery, journal = _prepared(tmp_path)
    files = FakePasswdFilesystem(drift)
    result = _run(case, delivery, journal, files)
    assert result.outcome is State.BLOCKED_DRIFT
    assert result.pre_execution_observed_state == drift
    assert result.mutation_attempted is False
    assert not {"fchmod", "fchown"}.intersection(files.calls)


def test_second_drift_check_occurs_after_executing_journal_before_syscall(tmp_path):
    case, delivery, journal = _prepared(tmp_path, expected=_state("0664"))
    files = FakePasswdFilesystem(_state("0664"))
    # _open_fixed performs two lstat calls, then initial _opened_state is third.
    # The next is the post-journal recheck immediately before mutation.
    files.drift_on_lstat = 4
    files.drift_to = _state(uid=1)
    result = _run(case, delivery, journal, files)
    assert result.outcome is State.BLOCKED_DRIFT
    assert not {"fchmod", "fchown"}.intersection(files.calls)


@pytest.mark.parametrize("unsafe", ["symlink", "nonregular"])
def test_unsafe_fixed_target_is_rejected_before_mutation(tmp_path, unsafe):
    case, delivery, journal = _prepared(tmp_path)
    files = FakePasswdFilesystem()
    setattr(files, unsafe, True)
    with pytest.raises(execute.EnforcementExecutionError):
        _run(case, delivery, journal, files)
    assert not {"fchmod", "fchown"}.intersection(files.calls)
    with journal.acquire(delivery, target_id=case.enrollment.target_id,
                         agent_id=case.enrollment.agent_id) as locked:
        assert locked.entry.outcome is State.FAILED


def test_unreadable_approved_mode_fails_without_mutation(tmp_path):
    case, delivery, journal = _prepared(tmp_path, expected=_state("0000"))
    files = FakePasswdFilesystem(_state("0000"))
    result = _run(case, delivery, journal, files)
    assert result.outcome is State.FAILED
    assert result.verification_succeeded is False
    assert not {"fchmod", "fchown"}.intersection(files.calls)


@pytest.mark.parametrize("failure", ["fail_chown_once", "fail_chmod_once", "ignore_chmod"])
def test_partial_failure_or_post_mismatch_rolls_back(tmp_path, failure):
    original = _state("0664", 1, 1)
    case, delivery, journal = _prepared(tmp_path, expected=original)
    files = FakePasswdFilesystem(original)
    setattr(files, failure, True)
    result = _run(case, delivery, journal, files)
    assert result.outcome is State.ROLLED_BACK
    assert result.rollback_attempted and result.rollback_succeeded is True
    assert result.verification_succeeded is False
    assert files.state == original


def test_rollback_failure_is_terminal_and_not_retried(tmp_path):
    original = _state("0664", 1, 1)
    case, delivery, journal = _prepared(tmp_path, expected=original)
    files = FakePasswdFilesystem(original)
    files.fail_chmod_always = True
    result = _run(case, delivery, journal, files)
    assert result.outcome is State.ROLLBACK_FAILED
    assert result.rollback_attempted and result.rollback_succeeded is False
    assert _run(case, delivery, journal, FakePasswdFilesystem()) == result


def _arm_executing(case, delivery, journal):
    with journal.acquire(delivery, target_id=case.enrollment.target_id,
                         agent_id=case.enrollment.agent_id) as locked:
        locked.transition(
            State.EXECUTING,
            pre_execution_observed_state=delivery.expected_source_state,
            original_rollback_state=delivery.expected_source_state,
            mutation_attempted=True,
            execution_started_at=datetime.now(UTC),
        )


def test_executing_recovery_final_state_safely_finalizes(tmp_path):
    case, delivery, journal = _prepared(tmp_path, expected=_state("0664"))
    _arm_executing(case, delivery, journal)
    files = FakePasswdFilesystem(_state())
    result = _run(case, delivery, journal, files)
    assert result.outcome is State.SUCCEEDED
    assert result.post_execution_observed_state == _state()
    assert not {"fchmod", "fchown"}.intersection(files.calls)


def test_executing_recovery_original_requires_explicit_retry(tmp_path):
    case, delivery, journal = _prepared(tmp_path, expected=_state("0664"))
    _arm_executing(case, delivery, journal)
    files = FakePasswdFilesystem(_state("0664"))
    with pytest.raises(execute.EnforcementExecutionInterruptedError):
        _run(case, delivery, journal, files)
    assert not {"fchmod", "fchown"}.intersection(files.calls)
    assert _run(case, delivery, journal, files, retry=True).outcome is State.SUCCEEDED


def test_executing_recovery_ambiguous_state_fails_closed(tmp_path):
    case, delivery, journal = _prepared(tmp_path, expected=_state("0664"))
    _arm_executing(case, delivery, journal)
    files = FakePasswdFilesystem(_state("0600"))
    with pytest.raises(execute.EnforcementExecutionInterruptedError):
        _run(case, delivery, journal, files, retry=True)
    assert not {"fchmod", "fchown"}.intersection(files.calls)


@pytest.mark.parametrize("change", [
    {"sandbox_evidence_sha256": "0" * 64},
    {"target_id": uuid4()},
    {"administrator_enforcement_approval_acknowledged": False},
])
def test_wrong_lineage_hash_or_approval_never_opens_target(tmp_path, change):
    case, delivery, journal = _prepared(tmp_path)
    files = FakePasswdFilesystem()
    with pytest.raises((EnforcementJournalError, ValidationError)):
        with journal.acquire(
            delivery.model_copy(update=change),
            target_id=case.enrollment.target_id,
            agent_id=case.enrollment.agent_id,
        ) as locked:
            execute._execute(delivery, locked, filesystem=files,
                             retry_interrupted=False)
    assert files.calls == []


def test_missing_or_nonprepared_journal_never_mutates(tmp_path):
    case, delivery = _delivery(tmp_path)
    journal = EnforcementJournalStore.for_agent_state(tmp_path / "state.json")
    files = FakePasswdFilesystem()
    with journal.acquire(delivery, target_id=case.enrollment.target_id,
                         agent_id=case.enrollment.agent_id) as locked:
        with pytest.raises(execute.EnforcementExecutionError):
            execute._execute(delivery, locked, filesystem=files,
                             retry_interrupted=False)
        locked.prepare(_state("0664"), State.BLOCKED_DRIFT)
        assert execute._execute(delivery, locked, filesystem=files,
                                retry_interrupted=False).outcome is State.BLOCKED_DRIFT
    assert files.calls == []


def test_runtime_integrates_preflight_execution_and_stops_locally(tmp_path, monkeypatch):
    case, delivery = _delivery(tmp_path)
    files = FakePasswdFilesystem()
    monkeypatch.setattr(preflight, "collect_local_passwd_source_state", lambda: _state())
    monkeypatch.setattr(execute, "_FILESYSTEM", files)
    state_path = tmp_path / "agent-state.json"
    protocol = _protocol(state_path)
    protocol.accept_enrollment(case.enrollment)
    transport = _Transport(case.enrollment, jobs=[delivery])
    runtime = AgentRuntime(
        protocol=protocol, transport=transport, profiler=_Profiler(),
        enforcement_journal=EnforcementJournalStore.for_agent_state(state_path),
    )
    assert runtime.run_once().jobs_polled == 1
    assert runtime.run_once().jobs_polled == 1
    assert files.calls.count("open") == 1
    assert not hasattr(transport, "submit_enforcement_result")


def test_strict_delivery_rejects_generic_operation_fields(tmp_path):
    _, delivery = _delivery(tmp_path)
    for field in ("command", "argv", "script", "path", "mode", "uid", "gid", "adapter"):
        values = delivery.model_dump(mode="python")
        values[field] = "untrusted"
        with pytest.raises(ValidationError):
            EnforcementJobDelivery.model_validate(values, strict=True)


def test_execution_source_is_fixed_path_metadata_only():
    source = inspect.getsource(execute)
    assert execute.PASSWD_PATH == "/etc/passwd"
    assert "filesystem.open(" in source and "PASSWD_PATH, os.O_RDONLY" in source
    assert "filesystem.fchown(" in source and "filesystem.fchmod(" in source
    for forbidden in (
        "subprocess", "os.system", "shell=True", "os.read(", "read_text(",
        "Popen(", "socket.", "ssh ",
    ):
        assert forbidden not in source
    assert "path:" not in str(inspect.signature(execute.execute_prepared_enforcement))
