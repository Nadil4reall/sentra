"""M7-B Controller delivery and read-only Agent preflight tests."""

from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import sqlite3
import stat
from uuid import uuid4

from pydantic import ValidationError
import pytest

import src.agent.enforcement as preflight
from src.agent.enforcement_journal import (
    EnforcementJournalError,
    EnforcementJournalStore,
    EnforcementPreflightOutcome,
)
from src.agent.runtime import AgentRuntime, AgentRuntimeError
from src.controller.enforcement import verify_enforcement_delivery
from src.controller.models import (
    EnforcementJobDelivery, EnforcementJobRecord, JobCreateRequest,
    JobPollRequest, JobPollResponse, JobStatus, JobType,
)
from src.controller.service import ControllerConflictError
from src.controller.storage import (
    ControllerStorageSecurityError, SQLiteControllerRepository,
    StorageConflictError,
    _CREATE_ENFORCEMENT_JOBS_M7A_SQL,
)
from src.sandbox_protocol.models import PasswdSourceState
from src.sandbox_validator.models import ValidationDecision

from test_m6_agent_runtime import _Profiler, _Transport, _protocol
from test_m6_validation import _auth, _enroll
from test_m7_enforcement import _admin, _case, _request


def _delivery(tmp_path: Path) -> tuple[object, EnforcementJobDelivery]:
    case = _case(tmp_path)
    case.service.create_enforcement_job(_admin(), _request(case))
    jobs = case.service.poll_jobs(JobPollRequest(auth=_auth(case.enrollment))).jobs
    assert len(jobs) == 1
    assert isinstance(jobs[0], EnforcementJobDelivery)
    return case, jobs[0]


def _state(mode: str = "0644", uid: int = 0, gid: int = 0) -> PasswdSourceState:
    return PasswdSourceState(
        passwd_file_mode=mode,
        passwd_file_owner_uid=uid,
        passwd_file_group_gid=gid,
    )


def test_controller_dispatches_exact_evidence_and_replays_only_to_owner(
    tmp_path: Path,
) -> None:
    case, delivery = _delivery(tmp_path)
    assert delivery.status is JobStatus.DISPATCHED
    assert delivery.assigned_agent_id == case.enrollment.agent_id
    assert delivery.expected_source_state == _state()
    payload, digest = case.repository.get_sandbox_validation_evidence(
        sandbox_session_id=case.session_id
    )
    assert delivery.m6_evidence == payload
    assert delivery.sandbox_evidence_sha256 == digest
    assert verify_enforcement_delivery(
        delivery, target_id=case.enrollment.target_id,
        agent_id=case.enrollment.agent_id,
    ) == digest
    wire = JobPollResponse(jobs=[delivery]).model_dump_json()
    assert JobPollResponse.model_validate_json(wire).jobs == [delivery]
    repeated = case.service.poll_jobs(JobPollRequest(auth=_auth(case.enrollment))).jobs
    assert repeated == [delivery]
    assert repeated[0].dispatched_at == delivery.dispatched_at
    foreign = _enroll(case.service, "foreign-m7-target")
    assert case.service.poll_jobs(JobPollRequest(auth=_auth(foreign))).jobs == []


def test_controller_rejects_tampered_evidence_before_delivery(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case.service.create_enforcement_job(_admin(), _request(case))
    with sqlite3.connect(case.database) as connection:
        connection.execute(
            "UPDATE sandbox_validation_executions SET payload_json = ?",
            ('{"tampered":true}',),
        )
    with pytest.raises(ControllerConflictError):
        case.service.poll_jobs(JobPollRequest(auth=_auth(case.enrollment)))
    with sqlite3.connect(case.database) as connection:
        assert connection.execute(
            "SELECT status FROM enforcement_jobs"
        ).fetchone()[0] == "pending"


def test_enforcement_poll_respects_remaining_capacity(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case.service.create_enforcement_job(_admin(), _request(case))
    capacity = case.service._settings.max_jobs_per_poll
    for _ in range(capacity):
        case.service.create_job(
            _admin(), JobCreateRequest(target_id=case.enrollment.target_id)
        )
    jobs = case.service.poll_jobs(JobPollRequest(auth=_auth(case.enrollment))).jobs
    assert len(jobs) == capacity
    assert all(job.job_type is JobType.PROFILE_TARGET for job in jobs)
    with sqlite3.connect(case.database) as connection:
        assert connection.execute(
            "SELECT status FROM enforcement_jobs"
        ).fetchone()[0] == "pending"


def test_repository_cannot_insert_pre_dispatched_enforcement_job(tmp_path: Path) -> None:
    case, delivery = _delivery(tmp_path)
    stored_fields = delivery.model_dump(
        mode="python",
        exclude={"evidence_sandbox_session_id", "m6_evidence", "expected_source_state"},
    )
    pre_dispatched = EnforcementJobRecord.model_validate(stored_fields, strict=True)
    with pytest.raises(StorageConflictError):
        case.repository.create_enforcement_job(pre_dispatched)


@pytest.mark.parametrize("observed,outcome", [
    (_state(), EnforcementPreflightOutcome.PREPARED),
    (_state(mode="0664"), EnforcementPreflightOutcome.BLOCKED_DRIFT),
    (_state(uid=1000), EnforcementPreflightOutcome.BLOCKED_DRIFT),
    (_state(gid=1000), EnforcementPreflightOutcome.BLOCKED_DRIFT),
])
def test_agent_preflight_journals_exact_state_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    observed: PasswdSourceState, outcome: EnforcementPreflightOutcome,
) -> None:
    case, delivery = _delivery(tmp_path)
    monkeypatch.setattr(preflight, "collect_local_passwd_source_state", lambda: observed)
    # Keep this M7-B preflight test at its read-only boundary; M7-C execution
    # is exercised separately with an injected metadata-only filesystem.
    monkeypatch.setattr(
        "src.agent.runtime.enforcement_execute.execute_prepared_enforcement",
        lambda *_args, **_kwargs: None,
    )
    state_path = tmp_path / "agent-state.json"
    protocol = _protocol(state_path)
    protocol.accept_enrollment(case.enrollment)
    transport = _Transport(case.enrollment, jobs=[delivery])
    profiler = _Profiler()

    class ForbiddenValidator:
        def validate(self, *args, **kwargs):
            raise AssertionError("M5 must never be invoked by M7-B")

    runtime = AgentRuntime(
        protocol=protocol, transport=transport, profiler=profiler,
        control_validator=ForbiddenValidator(),
        enforcement_journal=EnforcementJournalStore.for_agent_state(state_path),
    )
    result = runtime.run_once()
    assert result.jobs_polled == 1
    assert result.validation_results_submitted == 0
    assert profiler.calls == 0
    journal_path = EnforcementJournalStore.for_agent_state(state_path).directory
    entry = json.loads((journal_path / f"{delivery.enforcement_job_id}.json").read_text())
    assert entry["outcome"] == outcome.value
    assert entry["expected_source_state"] == _state().model_dump()
    assert entry["observed_source_state"] == observed.model_dump()
    assert runtime.run_once().jobs_polled == 1  # identical delivery is idempotent


@pytest.mark.parametrize("change", [
    {"sandbox_evidence_sha256": "0" * 64},
    {"target_id": uuid4()},
    {"profile_id": uuid4()},
    {"sandbox_session_id": uuid4()},
    {"administrator_enforcement_approval_acknowledged": False},
])
def test_agent_rejects_wrong_hash_lineage_or_approval(
    tmp_path: Path, change: dict[str, object],
) -> None:
    case, delivery = _delivery(tmp_path)
    altered = delivery.model_copy(update=change)
    with pytest.raises((ValueError, ValidationError)):
        verify_enforcement_delivery(
            altered, target_id=case.enrollment.target_id,
            agent_id=case.enrollment.agent_id,
        )


def test_agent_rejects_unvalidated_result_and_wrong_execution_mode(tmp_path: Path) -> None:
    case, delivery = _delivery(tmp_path)
    control = delivery.m6_evidence.report.control_results[0]
    invalid_control = control.model_copy(update={"result": ValidationDecision.FAILED})
    invalid_report = delivery.m6_evidence.report.model_copy(
        update={"control_results": [invalid_control]}
    )
    invalid_payload = delivery.m6_evidence.model_copy(update={"report": invalid_report})
    for payload in (
        invalid_payload,
        delivery.m6_evidence.model_copy(update={"execution_mode": "PLAN"}),
    ):
        with pytest.raises((ValueError, ValidationError)):
            verify_enforcement_delivery(
                delivery.model_copy(update={"m6_evidence": payload}),
                target_id=case.enrollment.target_id,
                agent_id=case.enrollment.agent_id,
            )


def test_runtime_rejects_bad_hash_before_local_metadata_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    case, delivery = _delivery(tmp_path)
    monkeypatch.setattr(
        preflight, "collect_local_passwd_source_state",
        lambda: (_ for _ in ()).throw(AssertionError("local read must not happen")),
    )
    with pytest.raises(AgentRuntimeError):
        AgentRuntime._preflight_jobs(
            [delivery.model_copy(update={"sandbox_evidence_sha256": "0" * 64})],
            target_id=case.enrollment.target_id,
            agent_id=case.enrollment.agent_id,
        )


def test_delivery_rejects_generic_fields(tmp_path: Path) -> None:
    _, delivery = _delivery(tmp_path)
    for field in ("command", "path", "argv", "shell", "script", "payload", "adapter"):
        values = delivery.model_dump(mode="python")
        values[field] = "forbidden"
        with pytest.raises(ValidationError):
            EnforcementJobDelivery.model_validate(values, strict=True)
    for changed in (
        {"control_id": "5.1.20"},
        {"administrator_enforcement_approval_acknowledged": False},
    ):
        values = delivery.model_dump(mode="python")
        values.update(changed)
        with pytest.raises(ValidationError):
            EnforcementJobDelivery.model_validate(values, strict=True)
    values = delivery.model_dump(mode="python")
    values.pop("administrator_enforcement_approval_acknowledged")
    with pytest.raises(ValidationError):
        EnforcementJobDelivery.model_validate(values, strict=True)


def test_changed_duplicate_and_malformed_journal_fail_closed(tmp_path: Path) -> None:
    case, delivery = _delivery(tmp_path)
    store = EnforcementJournalStore.for_agent_state(tmp_path / "state.json")
    params = dict(target_id=case.enrollment.target_id, agent_id=case.enrollment.agent_id)
    store.record(delivery, observed=_state(),
                 outcome=EnforcementPreflightOutcome.PREPARED, **params)
    with pytest.raises(EnforcementJournalError):
        store.record(delivery, observed=_state(uid=1),
                     outcome=EnforcementPreflightOutcome.BLOCKED_DRIFT, **params)
    with pytest.raises(EnforcementJournalError):
        store.record(delivery.model_copy(update={"sandbox_evidence_sha256": "0" * 64}),
                     observed=_state(), outcome=EnforcementPreflightOutcome.PREPARED,
                     **params)
    entry = store.directory / f"{delivery.enforcement_job_id}.json"
    lock = store.directory / f"{delivery.enforcement_job_id}.lock"
    assert stat.S_IMODE(os.lstat(store.directory).st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(entry).st_mode) == 0o600
    assert stat.S_IMODE(os.lstat(lock).st_mode) == 0o600
    entry.write_text("{bad-json", encoding="utf-8")
    with pytest.raises(EnforcementJournalError):
        store.record(delivery, observed=_state(),
                     outcome=EnforcementPreflightOutcome.PREPARED, **params)


@pytest.mark.parametrize("unsafe", ["writable", "symlink"])
def test_enforcement_journal_rejects_untrusted_ancestor(
    tmp_path: Path, unsafe: str,
) -> None:
    case, delivery = _delivery(tmp_path)
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    parent = tmp_path / "unsafe"
    if unsafe == "writable":
        parent.mkdir(mode=0o700)
        os.chmod(parent, 0o777)
    else:
        parent.symlink_to(trusted, target_is_directory=True)
    store = EnforcementJournalStore(parent / "journal")
    with pytest.raises(EnforcementJournalError):
        store.record(
            delivery, target_id=case.enrollment.target_id,
            agent_id=case.enrollment.agent_id,
            observed=_state(), outcome=EnforcementPreflightOutcome.PREPARED,
        )


def test_exact_m7a_schema_migrates_and_tamper_still_fails_closed(tmp_path: Path) -> None:
    case = _case(tmp_path)
    job = case.service.create_enforcement_job(_admin(), _request(case))

    from test_m9_controller_storage import _downgrade_m9_to_pre_m9

    _downgrade_m9_to_pre_m9(case.database)

    with sqlite3.connect(case.database) as connection:
        connection.execute("ALTER TABLE enforcement_jobs RENAME TO m7b_temporary")
        connection.execute(_CREATE_ENFORCEMENT_JOBS_M7A_SQL)
        connection.execute(
            """INSERT INTO enforcement_jobs SELECT
               enforcement_job_id, request_id, target_id, profile_id,
               compatibility_report_id, sandbox_session_id, control_id,
               job_type, administrator_enforcement_approval_acknowledged,
               sandbox_evidence_sha256, status, created_at, dispatched_at,
               completed_at FROM m7b_temporary"""
        )
        connection.execute("DROP TABLE m7b_temporary")
    reopened = SQLiteControllerRepository(case.database)
    assert reopened.create_enforcement_job(job).enforcement_job_id == job.enforcement_job_id
    with sqlite3.connect(case.database) as connection:
        connection.execute("UPDATE enforcement_jobs SET request_id = ?",
                           ("{" + str(job.request_id) + "}",))
    with pytest.raises(ControllerStorageSecurityError):
        SQLiteControllerRepository(case.database)


def test_fixed_passwd_reader_uses_nofollow_and_never_reads_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []
    real_open = os.open
    real_fstat = os.fstat
    real_close = os.close

    def fake_open(path: str, flags: int) -> int:
        calls.append((path, flags))
        return 99

    class FakeStat:
        st_mode = stat.S_IFREG | 0o644
        st_uid = 0
        st_gid = 0

    monkeypatch.setattr(preflight.os, "open", fake_open)
    monkeypatch.setattr(preflight.os, "fstat", lambda fd: FakeStat())
    monkeypatch.setattr(preflight.os, "close", lambda fd: None)
    try:
        assert preflight.collect_local_passwd_source_state() == _state()
    finally:
        monkeypatch.setattr(preflight.os, "open", real_open)
        monkeypatch.setattr(preflight.os, "fstat", real_fstat)
        monkeypatch.setattr(preflight.os, "close", real_close)
    assert len(calls) == 1
    assert calls[0][0] == "/etc/passwd"
    assert calls[0][1] & os.O_NOFOLLOW
    assert not calls[0][1] & (os.O_WRONLY | os.O_RDWR)


def test_m7b_path_has_no_mutation_or_generic_execution_source() -> None:
    source = inspect.getsource(preflight) + inspect.getsource(EnforcementJournalStore)
    for forbidden in (
        "chmod", "chown", "fchmod", "fchown", "subprocess", "os.system",
        "SandboxValidator", "LocalSandboxControlValidator", "shell=True",
    ):
        assert forbidden not in source
    assert preflight.PASSWD_PATH == "/etc/passwd"
