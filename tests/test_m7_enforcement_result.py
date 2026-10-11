"""M7-D immutable result, retry, reprofile, and verification tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
import hashlib
import inspect
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from pydantic import ValidationError
import pytest

import src.agent.enforcement as preflight
import src.agent.enforcement_execute as execution
from src.agent.enforcement_journal import (
    EnforcementJournalError, EnforcementJournalStore,
    EnforcementPreflightOutcome as JournalState,
)
from src.agent.enforcement_result import (
    payload_from_trusted_journal, payload_from_verified_delivery,
)
from src.agent.runtime import AgentRuntime
from src.agent.transport import AgentTransportError
from src.controller.api import ControllerAPI
from src.controller.enforcement import canonical_enforcement_payload_json
from src.controller.models import (
    AdminAuth, EnforcementOutcome, EnforcementResultPayload,
    EnforcementResultSubmissionRequest, JobPollRequest, JobStatus,
    PostEnforcementVerificationOutcome, ProfileSubmissionRequest,
)
from src.controller.service import (
    AuthorizationError, ControllerConflictError, ControllerNotFoundError,
)
from src.controller.storage import (
    ControllerStorageSecurityError, SQLiteControllerRepository,
    _CREATE_ENFORCEMENT_JOBS_SQL,
)
from src.controller.transport import ControllerHTTPSApplication
from src.target_profiler.models import TargetProfile

from test_m6_agent_runtime import _Profiler, _Transport, _protocol
from test_m6_validation import _admin, _auth, _enroll
from test_m7_enforcement_delivery import _delivery, _state
from test_m7_enforcement_execution import FakePasswdFilesystem


def _terminal(tmp_path: Path, *, outcome: JournalState = JournalState.SUCCEEDED):
    case, delivery = _delivery(tmp_path)
    journal = EnforcementJournalStore.for_agent_state(tmp_path / "agent-state.json")
    observed = _state() if outcome is not JournalState.BLOCKED_DRIFT else _state("0664")
    journal.record(
        delivery, target_id=case.enrollment.target_id,
        agent_id=case.enrollment.agent_id, observed=observed,
        outcome=JournalState.PREPARED if outcome is not JournalState.BLOCKED_DRIFT
        else JournalState.BLOCKED_DRIFT,
    )
    if outcome in {JournalState.SUCCEEDED, JournalState.FAILED}:
        with journal.acquire(
            delivery, target_id=case.enrollment.target_id,
            agent_id=case.enrollment.agent_id,
        ) as locked:
            filesystem = FakePasswdFilesystem()
            filesystem.symlink = outcome is JournalState.FAILED
            if outcome is JournalState.FAILED:
                with pytest.raises(execution.EnforcementExecutionError):
                    execution._execute(
                        delivery, locked, filesystem=filesystem,
                        retry_interrupted=False,
                    )
                entry = locked.entry
            else:
                entry = execution._execute(
                delivery, locked, filesystem=filesystem,
                retry_interrupted=False,
            )
    else:
        entry = journal.pending_results(
            target_id=case.enrollment.target_id,
            agent_id=case.enrollment.agent_id,
        )[0]
    payload = payload_from_verified_delivery(
        delivery, entry, target_id=case.enrollment.target_id,
        agent_id=case.enrollment.agent_id,
    )
    case.service._clock = lambda: datetime.now(UTC) + timedelta(seconds=20)
    request = EnforcementResultSubmissionRequest(
        auth=_auth(case.enrollment), payload=payload,
    )
    return case, delivery, journal, entry, request


def _fresh_profile(case, *, mode="0644", uid=0, gid=0) -> TargetProfile:
    original = case.repository.get_stored_profile(case.profile_id).profile
    values = original.model_dump(mode="python")
    values["collected_at"] = datetime.now(UTC) + timedelta(seconds=21)
    values["facts"]["passwd_file_mode"]["value"] = mode
    values["facts"]["passwd_file_owner_uid"]["value"] = uid
    values["facts"]["passwd_file_group_gid"]["value"] = gid
    return TargetProfile.model_validate(values)


def _complete_reprofile(case, result, *, mode="0644", uid=0, gid=0):
    jobs = case.service.poll_jobs(JobPollRequest(auth=_auth(case.enrollment))).jobs
    matching = [job for job in jobs if job.job_id == result.post_enforcement_profile_job_id]
    assert len(matching) == 1
    case.service._clock = lambda: datetime.now(UTC) + timedelta(seconds=40)
    stored = case.service.submit_profile(ProfileSubmissionRequest(
        auth=_auth(case.enrollment), job_id=matching[0].job_id,
        profile=_fresh_profile(case, mode=mode, uid=uid, gid=gid),
    ))
    verification = case.repository.get_post_enforcement_verification(
        result.enforcement_result_id,
    )
    assert verification is not None and verification.profile_id == stored.profile_id
    return verification


def test_strict_terminal_models_and_canonical_hash(tmp_path):
    case, delivery, journal, entry, request = _terminal(tmp_path)
    payload = request.payload
    assert payload.outcome is EnforcementOutcome.SUCCEEDED
    canonical = canonical_enforcement_payload_json(payload)
    assert canonical == json.dumps(payload.model_dump(mode="json"), sort_keys=True,
                                   ensure_ascii=False, allow_nan=False,
                                   separators=(",", ":"))
    assert payload_from_trusted_journal(
        entry, target_id=case.enrollment.target_id,
        agent_id=case.enrollment.agent_id,
    ) == payload
    blocked_case, _, _, _, blocked_request = _terminal(
        tmp_path / "blocked", outcome=JournalState.BLOCKED_DRIFT,
    )
    assert blocked_request.payload.outcome is EnforcementOutcome.BLOCKED_DRIFT
    assert blocked_request.payload.pre_execution_observed_state == _state("0664")
    assert blocked_case.enrollment.target_id != case.enrollment.target_id


@pytest.mark.parametrize("outcome,rollback_succeeded", [
    (EnforcementOutcome.FAILED, None),
    (EnforcementOutcome.ROLLED_BACK, True),
    (EnforcementOutcome.ROLLBACK_FAILED, False),
])
def test_valid_non_success_terminal_shapes(outcome, rollback_succeeded):
    now = datetime.now(UTC)
    original = _state("0664", 1, 1)
    rollback = outcome in {
        EnforcementOutcome.ROLLED_BACK, EnforcementOutcome.ROLLBACK_FAILED,
    }
    payload = EnforcementResultPayload(
        enforcement_job_id=uuid4(), target_id=uuid4(), agent_id=uuid4(),
        control_id="7.1.1", m6_evidence_sha256="a" * 64,
        outcome=outcome, expected_source_state=original,
        pre_execution_observed_state=original if rollback else None,
        original_rollback_state=original if rollback else None,
        post_execution_observed_state=None,
        mutation_attempted=rollback, mutation_changed=rollback,
        verification_succeeded=False, rollback_attempted=rollback,
        rollback_succeeded=rollback_succeeded,
        execution_started_at=now if rollback else None,
        execution_completed_at=now,
    )
    assert payload.outcome is outcome


@pytest.mark.parametrize("field,value", [
    ("outcome", "PREPARED"), ("outcome", "EXECUTING"),
    ("verification_succeeded", False), ("rollback_attempted", True),
    ("mutation_changed", True), ("post_execution_observed_state", None),
    ("command", "id"), ("path", "/tmp/other"), ("argv", ["id"]),
])
def test_impossible_or_generic_result_fields_rejected(tmp_path, field, value):
    _, _, _, _, request = _terminal(tmp_path)
    values = request.payload.model_dump(mode="python")
    values[field] = value
    with pytest.raises(ValidationError):
        EnforcementResultPayload.model_validate(values, strict=True)


def test_agent_builder_rejects_changed_delivery_or_journal(tmp_path):
    case, delivery, _, entry, _ = _terminal(tmp_path)
    for changed in (
        {"target_id": uuid4()}, {"m6_evidence_sha256": "0" * 64},
        {"expected_source_state": _state("0664")},
        {"control_id": "5.1.20"},
    ):
        with pytest.raises((ValueError, ValidationError)):
            payload_from_verified_delivery(
                delivery, entry.model_copy(update=changed),
                target_id=case.enrollment.target_id,
                agent_id=case.enrollment.agent_id,
            )
    with pytest.raises(ValueError):
        payload_from_trusted_journal(
            entry.model_copy(update={"outcome": JournalState.EXECUTING}),
            target_id=case.enrollment.target_id,
            agent_id=case.enrollment.agent_id,
        )


def test_malformed_private_journal_never_generates_trusted_submission(tmp_path):
    case, delivery, journal, _, _ = _terminal(tmp_path)
    path = journal.directory / f"{delivery.enforcement_job_id}.json"
    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(EnforcementJournalError):
        journal.pending_results(
            target_id=case.enrollment.target_id,
            agent_id=case.enrollment.agent_id,
        )


def test_controller_result_completion_hash_replay_and_one_reprofile(tmp_path):
    case, delivery, journal, entry, request = _terminal(tmp_path)
    result = case.service.submit_enforcement_result(request)
    assert result.enforcement_job_id == delivery.enforcement_job_id
    assert result.result_sha256 == hashlib.sha256(
        canonical_enforcement_payload_json(request.payload).encode("utf-8")
    ).hexdigest()
    assert case.repository.get_enforcement_job(delivery.enforcement_job_id).status is JobStatus.COMPLETED
    assert case.repository.get_enforcement_result_for_job(delivery.enforcement_job_id) == result
    assert case.service.submit_enforcement_result(request) == result
    with sqlite3.connect(case.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM enforcement_results").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM jobs WHERE job_id = ?",
            (str(result.post_enforcement_profile_job_id),),
        ).fetchone()[0] == 1
    acknowledged = journal.acknowledge_result(entry, result)
    assert acknowledged.controller_result_id == result.enforcement_result_id
    assert acknowledged.controller_result_sha256 == result.result_sha256
    assert journal.pending_results(
        target_id=case.enrollment.target_id,
        agent_id=case.enrollment.agent_id,
    ) == []


@pytest.mark.parametrize("change", [
    {"enforcement_job_id": uuid4()}, {"target_id": uuid4()},
    {"m6_evidence_sha256": "0" * 64},
    {"expected_source_state": _state("0664")},
])
def test_controller_rejects_wrong_job_target_hash_or_source(tmp_path, change):
    case, _, _, _, request = _terminal(tmp_path)
    bad = request.payload.model_copy(update=change)
    with pytest.raises((AuthorizationError, ControllerNotFoundError,
                        ControllerConflictError, ValidationError)):
        case.service.submit_enforcement_result(
            request.model_copy(update={"payload": bad})
        )
    with sqlite3.connect(case.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM enforcement_results").fetchone()[0] == 0


def test_foreign_agent_and_changed_replay_rejected(tmp_path):
    case, _, _, _, request = _terminal(tmp_path)
    foreign = _enroll(case.service, "foreign-m7d")
    with pytest.raises(AuthorizationError):
        case.service.submit_enforcement_result(
            request.model_copy(update={"auth": _auth(foreign)})
        )
    first = case.service.submit_enforcement_result(request)
    changed = request.payload.model_copy(update={"execution_completed_at":
        request.payload.execution_completed_at + timedelta(seconds=1)})
    with pytest.raises(ControllerConflictError):
        case.service.submit_enforcement_result(
            request.model_copy(update={"payload": changed})
        )
    assert case.repository.get_enforcement_result_for_job(first.enforcement_job_id) == first


def test_tampered_stored_payload_or_hash_fails_closed(tmp_path):
    case, delivery, _, _, request = _terminal(tmp_path)
    case.service.submit_enforcement_result(request)
    with sqlite3.connect(case.database) as connection:
        connection.execute("UPDATE enforcement_results SET result_sha256 = ?", ("0" * 64,))
    with pytest.raises(ControllerConflictError):
        case.service.submit_enforcement_result(request)
    with pytest.raises(ControllerStorageSecurityError):
        SQLiteControllerRepository(case.database)


def test_exact_m7c_schema_migrates_dispatched_job_without_result(tmp_path):
    case, delivery = _delivery(tmp_path)
    with sqlite3.connect(case.database) as connection:
        connection.execute("DROP TABLE post_enforcement_verifications")
        connection.execute("DROP TABLE enforcement_results")
        connection.execute("ALTER TABLE enforcement_jobs RENAME TO enforcement_m7d_old")
        connection.execute(_CREATE_ENFORCEMENT_JOBS_SQL)
        connection.execute(
            "INSERT INTO enforcement_jobs SELECT * FROM enforcement_m7d_old"
        )
        connection.execute("DROP TABLE enforcement_m7d_old")
    reopened = SQLiteControllerRepository(case.database)
    stored = reopened.get_enforcement_job(delivery.enforcement_job_id)
    assert stored is not None and stored.status is JobStatus.DISPATCHED
    with sqlite3.connect(case.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM enforcement_results").fetchone()[0] == 0


@pytest.mark.parametrize("mode,uid,gid,expected", [
    ("0644", 0, 0, PostEnforcementVerificationOutcome.VERIFIED),
    ("0664", 0, 0, PostEnforcementVerificationOutcome.DRIFT_DETECTED),
    ("0644", 1, 0, PostEnforcementVerificationOutcome.DRIFT_DETECTED),
    ("0644", 0, 1, PostEnforcementVerificationOutcome.DRIFT_DETECTED),
])
def test_fresh_m3_verifies_only_matching_success(
    tmp_path, mode, uid, gid, expected,
):
    case, _, _, _, request = _terminal(tmp_path)
    result = case.service.submit_enforcement_result(request)
    verification = _complete_reprofile(case, result, mode=mode, uid=uid, gid=gid)
    assert verification.outcome is expected
    assert verification.target_id == result.target_id
    assert verification.profile_job_id == result.post_enforcement_profile_job_id
    assert verification.profile_sha256 == case.repository.get_profile(
        verification.profile_id,
    ).profile_sha256


def test_non_success_result_reprofiles_without_success_claim(tmp_path):
    case, _, _, _, request = _terminal(
        tmp_path, outcome=JournalState.BLOCKED_DRIFT,
    )
    result = case.service.submit_enforcement_result(request)
    verification = _complete_reprofile(case, result, mode="0644", uid=0, gid=0)
    assert verification.outcome is PostEnforcementVerificationOutcome.OBSERVED_FAILURE_STATE
    assert verification.observed_source_state == _state()


def test_failed_pre_mutation_result_is_stored_and_reprofiled(tmp_path):
    case, _, _, _, request = _terminal(tmp_path, outcome=JournalState.FAILED)
    assert request.payload.outcome is EnforcementOutcome.FAILED
    assert request.payload.mutation_attempted is False
    result = case.service.submit_enforcement_result(request)
    verification = _complete_reprofile(case, result)
    assert verification.outcome is PostEnforcementVerificationOutcome.OBSERVED_FAILURE_STATE


def test_foreign_target_never_receives_post_enforcement_profile_job(tmp_path):
    case, _, _, _, request = _terminal(tmp_path)
    result = case.service.submit_enforcement_result(request)
    foreign = _enroll(case.service, "foreign-m7d-reprofile")
    assert case.service.poll_jobs(JobPollRequest(auth=_auth(foreign))).jobs == []
    assert case.repository.get_job(result.post_enforcement_profile_job_id).job.target_id \
        == case.enrollment.target_id


def test_missing_post_verification_after_completed_profile_fails_startup(tmp_path):
    case, _, _, _, request = _terminal(tmp_path)
    result = case.service.submit_enforcement_result(request)
    _complete_reprofile(case, result)
    with sqlite3.connect(case.database) as connection:
        connection.execute(
            "DELETE FROM post_enforcement_verifications WHERE enforcement_result_id = ?",
            (str(result.enforcement_result_id),),
        )
    with pytest.raises(ControllerStorageSecurityError):
        SQLiteControllerRepository(case.database)


def test_transport_agent_only_and_admin_audit_routes(tmp_path):
    case, _, _, _, request = _terminal(tmp_path)
    app = ControllerHTTPSApplication(ControllerAPI(case.service))
    route = f"/api/v1/agents/{case.enrollment.agent_id}/enforcement-results"
    body = request.model_dump(mode="json")
    body["auth"]["agent_credential"] = (
        request.auth.agent_credential.get_secret_value()
    )
    encoded = json.dumps(body).encode("utf-8")
    wrong = app.dispatch("POST", f"/api/v1/agents/{uuid4()}/enforcement-results", encoded)
    assert wrong.status is HTTPStatus.UNAUTHORIZED
    response = app.dispatch("POST", route, encoded)
    assert response.status is HTTPStatus.OK
    result_id = json.loads(response.body)["enforcement_result_id"]
    job_id = str(request.payload.enforcement_job_id)
    admin_route = f"/api/v1/admin/enforcement-jobs/{job_id}/result"
    assert app.dispatch("GET", admin_route, b"").status is HTTPStatus.UNAUTHORIZED
    retrieved = app.dispatch(
        "GET", admin_route, b"", {
            "Authorization": "Bearer " + _admin().admin_credential.get_secret_value(),
        },
    )
    assert retrieved.status is HTTPStatus.OK
    assert json.loads(retrieved.body)["enforcement_result_id"] == result_id


def test_lost_ack_retry_uses_journal_and_never_mutates_twice(tmp_path, monkeypatch):
    case, delivery = _delivery(tmp_path)
    case.service._clock = lambda: datetime.now(UTC) + timedelta(seconds=20)
    files = FakePasswdFilesystem()
    monkeypatch.setattr(preflight, "collect_local_passwd_source_state", lambda: _state())
    monkeypatch.setattr(execution, "_FILESYSTEM", files)
    state_path = tmp_path / "agent-state.json"
    protocol = _protocol(state_path)
    protocol.accept_enrollment(case.enrollment)

    class LostResponseTransport(_Transport):
        lost = False

        def submit_enforcement_result(self, request):
            stored = case.service.submit_enforcement_result(request)
            if not self.lost:
                self.lost = True
                raise AgentTransportError("simulated response loss")
            return stored

    transport = LostResponseTransport(case.enrollment, jobs=[delivery])
    journal = EnforcementJournalStore.for_agent_state(state_path)
    runtime = AgentRuntime(
        protocol=protocol, transport=transport, profiler=_Profiler(),
        enforcement_journal=journal,
        enforcement_result_submission_enabled=True,
    )
    with pytest.raises(AgentTransportError):
        runtime.run_once()
    assert len(journal.pending_results(
        target_id=case.enrollment.target_id,
        agent_id=case.enrollment.agent_id,
    )) == 1
    assert runtime.run_once().jobs_polled == 1
    assert files.calls.count("open") == 1
    assert journal.pending_results(
        target_id=case.enrollment.target_id,
        agent_id=case.enrollment.agent_id,
    ) == []
    with sqlite3.connect(case.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM enforcement_results").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM jobs WHERE job_type = 'PROFILE_TARGET'",
        ).fetchone()[0] == 2


def test_m7d_evidence_modules_have_no_generic_execution_surface():
    import src.agent.enforcement_result as agent_result
    import src.controller.enforcement as controller_enforcement

    source = inspect.getsource(agent_result) + inspect.getsource(controller_enforcement)
    for forbidden in (
        "subprocess", "os.system", "shell=True", "Popen(", "eval(",
        "exec(", "socket.", "paramiko", "ssh ",
    ):
        assert forbidden not in source
