"""Controller-only M7-A authorization tests; no target or VM I/O."""

from __future__ import annotations

from pathlib import Path
import sqlite3
from types import SimpleNamespace
from uuid import uuid4

from pydantic import ValidationError
import pytest

from src.controller.models import (
    AdminAuth,
    EnforcementJobCreateRequest,
    EnforcementJobRecord,
    JobPollRequest,
    JobPollResponse,
    JobStatus,
    JobType,
    SandboxSessionStatus,
    ValidationResultPayload,
)
from src.controller.sandbox_context import derive_sandbox_context
from src.controller.validation import compatibility_reference_from_record
from src.sandbox_protocol.models import IpForwardingSourceState

from src.controller.service import (
    AuthenticationError,
    AuthorizationError,
    ControllerConflictError,
    ControllerNotFoundError,
)
from src.controller.storage import (
    ControllerStorageSecurityError,
    SQLiteControllerRepository,
    StorageConflictError,
)
from src.sandbox_validator.models import ActionStatus, HealthStatus, ValidationDecision

from test_m6_sandbox_lifecycle import (
    _controller as _m9_controller,
    _stored_profile_and_report as _m9_stored_profile_and_report,
)

from test_m6_validation import (
    _admin,
    _auth,
    _sandbox_sqlite_fixture,
    _validation_payload,
)


def _request(case: SimpleNamespace, **changes: object) -> EnforcementJobCreateRequest:
    values = {
        "request_id": uuid4(),
        "target_id": case.enrollment.target_id,
        "profile_id": case.profile_id,
        "compatibility_report_id": case.report_id,
        "sandbox_session_id": case.session_id,
        "control_id": "7.1.1",
        "administrator_enforcement_approval_acknowledged": True,
    }
    values.update(changes)
    return EnforcementJobCreateRequest.model_validate(values, strict=True)


def _make_validated(payload: ValidationResultPayload) -> ValidationResultPayload:
    """Convert an inert M6 failure fixture into schema-valid success evidence."""

    values = payload.model_dump(mode="python")
    report = values["report"]
    control = report["control_results"][0]
    control["result"] = ValidationDecision.VALIDATED
    control["remediation"]["succeeded"] = True
    control["remediation"]["reason"] = "Inert fixture metadata was corrected."
    control["remediation"]["actions"][0]["status"] = ActionStatus.APPLIED
    control["remediation"]["actions"][0]["error"] = None
    control["post_audit"][0]["value"] = "0644"
    control["health_checks"][0]["status"] = HealthStatus.PASSED
    control["health_checks"][0]["explanation"] = "Inert fixture check passed."
    control["rollback"] = {
        "supported": True,
        "attempted": False,
        "succeeded": None,
        "actions": [],
        "explanation": "No rollback was necessary.",
    }
    control["errors"] = []
    control["explanation"] = "Inert fixture validation succeeded."
    report["summary"]["validated"] = 1
    report["summary"]["failed"] = 0
    report["summary"]["rollbacks_attempted"] = 0
    return ValidationResultPayload.model_validate(values, strict=True)


def _case(tmp_path: Path, *, validated: bool = True) -> SimpleNamespace:
    database, repository, service, enrollment, ready, pending = (
        _sandbox_sqlite_fixture(tmp_path)
    )
    dispatched, _ = service.dispatch_sandbox_validation_job(
        _admin(),
        sandbox_session_id=ready.sandbox_session_id,
        validation_job_id=pending.validation_job_id,
    )
    payload, _ = _validation_payload(dispatched, tmp_path / "inert-m5-root")
    if validated:
        payload = _make_validated(payload)
    service.complete_sandbox_validation_job(
        _admin(), sandbox_session_id=ready.sandbox_session_id,
        validation_job_id=dispatched.validation_job_id, payload=payload,
    )
    closed = service.close_session(ready.sandbox_session_id)
    assert closed.status is SandboxSessionStatus.CLOSED
    return SimpleNamespace(
        database=database, repository=repository, service=service,
        enrollment=enrollment, profile_id=closed.source_profile_id,
        report_id=closed.source_compatibility_report_id,
        session_id=closed.sandbox_session_id, payload=payload,
    )


def test_closed_validated_evidence_creates_pending_controller_job(tmp_path: Path) -> None:
    case = _case(tmp_path)
    request = _request(case)

    job = case.service.create_enforcement_job(_admin(), request)
    evidence = case.repository.get_sandbox_validation_evidence(
        sandbox_session_id=case.session_id
    )

    assert evidence is not None
    assert job.sandbox_evidence_sha256 == evidence[1]
    assert job.job_type is JobType.ENFORCE_CONTROL
    assert job.status is JobStatus.PENDING
    assert job.dispatched_at is None and job.completed_at is None
    assert job.administrator_enforcement_approval_acknowledged is True
    assert (job.target_id, job.profile_id, job.compatibility_report_id,
            job.sandbox_session_id) == (
        request.target_id, request.profile_id, request.compatibility_report_id,
        request.sandbox_session_id,
    )
    delivered = case.service.poll_jobs(
        JobPollRequest(auth=_auth(case.enrollment))
    ).jobs
    assert len(delivered) == 1
    assert delivered[0].enforcement_job_id == job.enforcement_job_id
    assert delivered[0].status is JobStatus.DISPATCHED
    assert JobPollResponse.model_validate(
        {"jobs": [delivered[0].model_dump(mode="python")]}, strict=True
    ).jobs == delivered
    assert (
        SQLiteControllerRepository(case.database)
        .create_enforcement_job(job).enforcement_job_id
        == job.enforcement_job_id
    )


def test_identical_request_replay_is_idempotent_and_changed_replay_conflicts(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    request = _request(case)
    first = case.service.create_enforcement_job(_admin(), request)
    assert case.service.create_enforcement_job(_admin(), request) == first
    changed = first.model_copy(update={"target_id": uuid4()})
    with pytest.raises(StorageConflictError):
        case.repository.create_enforcement_job(changed)
    with sqlite3.connect(case.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0] == 1


@pytest.mark.parametrize("field", ["target_id", "profile_id", "compatibility_report_id"])
def test_cross_lineage_request_rejected(tmp_path: Path, field: str) -> None:
    case = _case(tmp_path)
    with pytest.raises((AuthorizationError, ControllerNotFoundError, ControllerConflictError)):
        case.service.create_enforcement_job(_admin(), _request(case, **{field: uuid4()}))


def test_wrong_session_rejected(tmp_path: Path) -> None:
    case = _case(tmp_path)
    with pytest.raises(ControllerNotFoundError):
        case.service.create_enforcement_job(
            _admin(), _request(case, sandbox_session_id=uuid4())
        )


def test_enforcement_creation_requires_administrator_authentication(tmp_path: Path) -> None:
    case = _case(tmp_path)
    with pytest.raises(AuthenticationError):
        case.service.create_enforcement_job(
            AdminAuth(admin_credential="not-the-administrator-credential"),
            _request(case),
        )
    with sqlite3.connect(case.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0] == 0


@pytest.mark.parametrize("status", ["READY", "VALIDATING", "FAILED", "QUARANTINED"])
def test_non_closed_sandbox_status_rejected(tmp_path: Path, status: str) -> None:
    database, repository, service, enrollment, ready, pending = (
        _sandbox_sqlite_fixture(tmp_path)
    )
    if status in {"VALIDATING", "QUARANTINED"}:
        service.dispatch_sandbox_validation_job(
            _admin(), sandbox_session_id=ready.sandbox_session_id,
            validation_job_id=pending.validation_job_id,
        )
    if status == "FAILED":
        service.mark_failed(ready.sandbox_session_id, failure_reason="fixture")
    elif status == "QUARANTINED":
        service.mark_quarantined(
            ready.sandbox_session_id, quarantine_reason="fixture"
        )
    session = repository.get_sandbox_session_by_id(ready.sandbox_session_id)
    assert session is not None and session.status.value == status
    case = SimpleNamespace(
        database=database, repository=repository, service=service,
        enrollment=enrollment, profile_id=ready.source_profile_id,
        report_id=ready.source_compatibility_report_id,
        session_id=ready.sandbox_session_id,
    )
    with pytest.raises(ControllerConflictError):
        case.service.create_enforcement_job(_admin(), _request(case))


def test_closed_session_without_evidence_rejected(tmp_path: Path) -> None:
    case = _case(tmp_path)
    with sqlite3.connect(case.database) as connection:
        connection.execute(
            "DELETE FROM sandbox_validation_executions WHERE sandbox_session_id = ?",
            (str(case.session_id),),
        )
    with pytest.raises(ControllerConflictError):
        case.service.create_enforcement_job(_admin(), _request(case))


def test_tampered_evidence_rejected(tmp_path: Path) -> None:
    case = _case(tmp_path)
    with sqlite3.connect(case.database) as connection:
        connection.execute(
            "UPDATE sandbox_validation_executions SET payload_json = ? "
            "WHERE sandbox_session_id = ?",
            ('{"tampered":true}', str(case.session_id)),
        )
    with pytest.raises(ControllerConflictError):
        case.service.create_enforcement_job(_admin(), _request(case))


def test_non_validated_result_rejected(tmp_path: Path) -> None:
    case = _case(tmp_path, validated=False)
    with pytest.raises(ControllerConflictError):
        case.service.create_enforcement_job(_admin(), _request(case))


def test_wrong_control_rejected_by_strict_request_model(tmp_path: Path) -> None:
    case = _case(tmp_path)
    values = _request(case).model_dump(mode="python")
    values["control_id"] = "5.1.20"
    with pytest.raises(ValidationError):
        EnforcementJobCreateRequest.model_validate(values, strict=True)


@pytest.mark.parametrize("approval", [None, False])
def test_missing_or_false_new_enforcement_approval_rejected(
    tmp_path: Path, approval: object,
) -> None:
    case = _case(tmp_path)
    values = _request(case).model_dump(mode="python")
    if approval is None:
        values.pop("administrator_enforcement_approval_acknowledged")
    else:
        values["administrator_enforcement_approval_acknowledged"] = approval
    with pytest.raises(ValidationError):
        EnforcementJobCreateRequest.model_validate(values, strict=True)


@pytest.mark.parametrize("field", [
    "command", "argv", "shell", "script", "path", "mode", "uid", "gid",
    "adapter", "payload", "service",
])
def test_generic_execution_and_file_fields_rejected(tmp_path: Path, field: str) -> None:
    case = _case(tmp_path)
    values = _request(case).model_dump(mode="python")
    values[field] = "forbidden"
    with pytest.raises(ValidationError):
        EnforcementJobCreateRequest.model_validate(values, strict=True)


@pytest.mark.parametrize("tamper", ["request_id", "sandbox_evidence_sha256"])
def test_database_tampering_fails_closed_at_startup(tmp_path: Path, tamper: str) -> None:
    case = _case(tmp_path)
    case.service.create_enforcement_job(_admin(), _request(case))
    with sqlite3.connect(case.database) as connection:
        if tamper == "request_id":
            row = connection.execute("SELECT request_id FROM enforcement_jobs").fetchone()
            connection.execute("UPDATE enforcement_jobs SET request_id = ?",
                               ("{" + row[0] + "}",))
        else:
            connection.execute("UPDATE enforcement_jobs SET sandbox_evidence_sha256 = ?",
                               ("0" * 64,))
    with pytest.raises(ControllerStorageSecurityError):
        SQLiteControllerRepository(case.database)


def test_enforcement_table_schema_tampering_fails_closed(tmp_path: Path) -> None:
    case = _case(tmp_path)
    with sqlite3.connect(case.database) as connection:
        connection.execute("DROP TABLE enforcement_jobs")
        connection.execute("CREATE TABLE enforcement_jobs (request_id TEXT)")
    with pytest.raises(ControllerStorageSecurityError):
        SQLiteControllerRepository(case.database)


def test_record_is_pending_only_and_agent_union_excludes_enforcement() -> None:
    assert set(EnforcementJobCreateRequest.model_fields) == {
        "request_id", "target_id", "profile_id", "compatibility_report_id",
        "sandbox_session_id", "control_id",
        "administrator_enforcement_approval_acknowledged",
    }
    assert "command" not in EnforcementJobRecord.model_fields



def test_3_3_1_approved_state_is_derived_from_stored_m3_m4(
    tmp_path: Path,
) -> None:
    """M7 must derive 3.3.1 state from trusted stored M3/M4 lineage."""

    _database, repository, service = _m9_controller(tmp_path)
    enrollment, profile, report = _m9_stored_profile_and_report(service)

    stored_profile = repository.get_stored_profile(profile.profile_id)
    assert stored_profile is not None

    reference = compatibility_reference_from_record(report, "3.3.1")
    expected = derive_sandbox_context(
        "3.3.1",
        stored_profile.profile,
        reference,
    ).source_state

    assert type(expected) is IpForwardingSourceState

    job = EnforcementJobRecord(
        enforcement_job_id=uuid4(),
        request_id=uuid4(),
        target_id=enrollment.target_id,
        profile_id=profile.profile_id,
        compatibility_report_id=report.compatibility_report_id,
        sandbox_session_id=uuid4(),
        control_id="3.3.1",
        administrator_enforcement_approval_acknowledged=True,
        sandbox_evidence_sha256="0" * 64,
        created_at=profile.received_at,
    )

    with repository._connection() as connection:
        observed = repository._approved_enforcement_state(connection, job)

    assert type(observed) is IpForwardingSourceState
    assert observed == expected


def test_7_1_1_sandbox_evidence_cannot_be_relabelled_as_3_3_1(
    tmp_path: Path,
) -> None:
    """Cross-control M6 evidence must fail closed at M7 authorization."""

    case = _case(tmp_path)

    with pytest.raises(ControllerConflictError):
        case.service.create_enforcement_job(
            _admin(),
            _request(case, control_id="3.3.1"),
        )
