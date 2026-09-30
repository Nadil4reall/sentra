"""M6E-A Controller-side sandbox lifecycle and lineage tests.

These tests exercise only Controller models, SQLite state, and the HTTPS
application dispatcher.  They do not provision a VM, invoke M5, mutate a
target, or expose a generic execution/status endpoint.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import UUID, uuid4

from pydantic import SecretStr, ValidationError
import pytest
import yaml

from src.compatibility_engine.models import CompatibilityDecision
from src.controller.api import ControllerAPI, ENDPOINTS
from src.controller.models import (
    AdminAuth,
    AgentAuth,
    CompatibilityAnalysisRequest,
    EnrollmentRequest,
    JobCreateRequest,
    JobPollRequest,
    JobType,
    ObservedTargetMetadata,
    ProfileSubmissionRequest,
    SandboxProviderType,
    SandboxSessionCreateRequest,
    SandboxSessionRecord,
    SandboxSessionStatus,
    ValidationJobCreateRequest,
)
from src.controller.service import (
    AuthenticationError,
    AuthorizationError,
    ControllerConflictError,
    ControllerNotFoundError,
    ControllerService,
    ControllerSettings,
)
from src.controller.storage import (
    ControllerStorageSecurityError,
    SQLiteControllerRepository,
    StorageConflictError,
)
from src.controller.transport import ControllerHTTPSApplication
from src.target_profiler.models import TargetProfile


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "data" / "profiles" / "target-profile.yaml"
NOW = datetime(2026, 9, 29, 8, 30, tzinfo=UTC)
BOOTSTRAP = SecretStr("m6e-bootstrap-fixture")
ADMIN = SecretStr("m6e-admin-fixture")


def _profile() -> TargetProfile:
    return TargetProfile.model_validate(
        yaml.safe_load(PROFILE_PATH.read_text(encoding="utf-8"))
    )


def _controller(
    tmp_path: Path,
    *,
    clock=None,
) -> tuple[Path, SQLiteControllerRepository, ControllerService]:
    database = tmp_path / "controller.sqlite3"
    repository = SQLiteControllerRepository(database)
    service = ControllerService(
        repository,
        ControllerSettings(
            bootstrap_credential=BOOTSTRAP,
            admin_credential=ADMIN,
        ),
        clock=clock or (lambda: NOW),
    )
    return database, repository, service


def _admin() -> AdminAuth:
    return AdminAuth(admin_credential=ADMIN)


def _enroll(service: ControllerService, hostname: str):
    return service.enroll(
        EnrollmentRequest(
            bootstrap_credential=BOOTSTRAP,
            installation_id=uuid4(),
            agent_version="m6e-a-test",
            observed_metadata=ObservedTargetMetadata(
                hostname=hostname,
                os="Ubuntu",
                os_version="24.04",
                kernel="6.8.0-m6e-test",
                architecture="x86_64",
            ),
        )
    )


def _auth(enrollment) -> AgentAuth:
    return AgentAuth(
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
        agent_credential=enrollment.agent_credential,
    )


def _stored_profile_and_report(
    service: ControllerService,
    *,
    hostname: str = "m6e-source-target",
):
    enrollment = _enroll(service, hostname)
    profile_job = service.create_job(
        _admin(),
        JobCreateRequest(
            target_id=enrollment.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )
    jobs = service.poll_jobs(JobPollRequest(auth=_auth(enrollment))).jobs
    assert [item.job_id for item in jobs] == [profile_job.job_id]
    stored_profile = service.submit_profile(
        ProfileSubmissionRequest(
            auth=_auth(enrollment),
            job_id=profile_job.job_id,
            profile=_profile(),
            profiler_version="m3-m6e-test",
            sentra_version="m6e-a-test",
        )
    )
    report = service.run_compatibility_analysis(
        _admin(),
        CompatibilityAnalysisRequest(
            target_id=enrollment.target_id,
            profile_id=stored_profile.profile_id,
        ),
    )
    return enrollment, stored_profile, report


def _session_request(*, request_id: UUID | None = None):
    return SandboxSessionCreateRequest(
        request_id=request_id or uuid4(),
        control_id="7.1.1",
        administrator_sandbox_authorization_acknowledged=True,
    )


def _create_session(
    service: ControllerService,
    enrollment,
    stored_profile,
    report,
    *,
    request_id: UUID | None = None,
) -> SandboxSessionRecord:
    return service.create_sandbox_session(
        _admin(),
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
        compatibility_report_id=report.compatibility_report_id,
        request=_session_request(request_id=request_id),
    )


def _session_path(enrollment, stored_profile, report) -> str:
    return (
        f"/api/v1/admin/targets/{enrollment.target_id}/profiles/"
        f"{stored_profile.profile_id}/compatibility-reports/"
        f"{report.compatibility_report_id}/sandbox-sessions"
    )


def _validation_request(enrollment, stored_profile, report):
    """Create one pre-M6E M6D row for migration-preservation coverage."""

    selected = next(
        item for item in report.report.control_results if item.control_id == "7.1.1"
    )
    uncertain = selected.result in {
        CompatibilityDecision.WARNING,
        CompatibilityDecision.REVIEW_REQUIRED,
        CompatibilityDecision.INSUFFICIENT_EVIDENCE,
    }
    return ValidationJobCreateRequest(
        request_id=uuid4(),
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
        compatibility_report_id=report.compatibility_report_id,
        control_id="7.1.1",
        administrator_approval_acknowledged=True,
        compatibility_risk_acknowledged=uncertain,
        compatibility_override_reason=(
            "M6E migration fixture reviewed the unavailable compatibility evidence."
            if selected.result is CompatibilityDecision.INSUFFICIENT_EVIDENCE
            else None
        ),
    )


@pytest.mark.parametrize(
    "forbidden_field, value",
    [
        ("command", "id"),
        ("shell", True),
        ("argv", ["id"]),
        ("script", "echo unsafe"),
        ("path", "/etc/passwd"),
        ("target", "/etc/passwd"),
        ("service", "ssh"),
        ("service_action", "restart"),
        ("adapter", "arbitrary"),
        ("provider_type", "local_nested_vm"),
        ("provider_payload", {"memory": "16G"}),
        ("vm_args", ["--host-device"]),
        ("host_mounts", ["/"]),
        ("raw_cis_remediation", "chmod 0644 /etc/passwd"),
        ("sandbox_instance_id", "caller-controlled-instance"),
        ("status", "READY"),
        ("created_at", NOW.isoformat()),
    ],
)
def test_creation_model_rejects_execution_provider_and_controller_fields(
    forbidden_field: str,
    value: object,
) -> None:
    document = {
        "request_id": uuid4(),
        "control_id": "7.1.1",
        "administrator_sandbox_authorization_acknowledged": True,
        forbidden_field: value,
    }

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SandboxSessionCreateRequest.model_validate(document)


def test_creation_model_rejects_other_controls_and_missing_authorization() -> None:
    with pytest.raises(ValidationError):
        SandboxSessionCreateRequest(
            request_id=uuid4(),
            control_id="5.1.20",  # type: ignore[arg-type]
            administrator_sandbox_authorization_acknowledged=True,
        )
    with pytest.raises(ValidationError):
        SandboxSessionCreateRequest(
            request_id=uuid4(),
            control_id="7.1.1",
            administrator_sandbox_authorization_acknowledged=False,  # type: ignore[arg-type]
        )


def test_valid_creation_seals_lineage_m4_reference_and_canonical_hash(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, report = _stored_profile_and_report(service)

    session = _create_session(service, enrollment, stored_profile, report)

    assert session.source_target_id == enrollment.target_id
    assert session.source_profile_id == stored_profile.profile_id
    assert session.source_compatibility_report_id == report.compatibility_report_id
    assert session.control_id == "7.1.1"
    assert session.provider_type is SandboxProviderType.LOCAL_NESTED_VM
    assert session.status is SandboxSessionStatus.REQUESTED
    assert session.sandbox_instance_id is None
    assert session.created_at == NOW
    assert session.provisioning_started_at is None
    assert session.compatibility_reference.control_id == "7.1.1"
    assert session.compatibility_reference.result in set(CompatibilityDecision)
    assert session.compatibility_reference.provisional is True
    assert session.compatibility_reference.metadata_review_status.value == "needs_review"
    assert session.compatibility_reference.result.value != "safe"
    assert session.compatibility_reference.report_source.endswith(
        str(report.compatibility_report_id)
    )
    canonical = json.dumps(
        session.compatibility_reference.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert session.compatibility_reference_sha256 == hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()

    with sqlite3.connect(database) as connection:
        stored = connection.execute(
            "SELECT provider_type, status, sandbox_instance_id, "
            "compatibility_reference_json, compatibility_reference_sha256 "
            "FROM sandbox_sessions WHERE sandbox_session_id = ?",
            (str(session.sandbox_session_id),),
        ).fetchone()
    assert stored == (
        SandboxProviderType.LOCAL_NESTED_VM.value,
        SandboxSessionStatus.REQUESTED.value,
        None,
        canonical,
        session.compatibility_reference_sha256,
    )


def test_request_id_identical_replay_is_idempotent_and_changed_replay_conflicts(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, report = _stored_profile_and_report(service)
    request_id = uuid4()

    first = _create_session(
        service,
        enrollment,
        stored_profile,
        report,
        request_id=request_id,
    )
    replay = _create_session(
        service,
        enrollment,
        stored_profile,
        report,
        request_id=request_id,
    )
    assert replay == first

    progressed = service.mark_provisioning(first.sandbox_session_id)
    replay_after_progress = _create_session(
        service,
        enrollment,
        stored_profile,
        report,
        request_id=request_id,
    )
    assert replay_after_progress == progressed

    other_enrollment, other_profile, other_report = _stored_profile_and_report(
        service,
        hostname="m6e-other-target",
    )
    with pytest.raises(ControllerConflictError):
        _create_session(
            service,
            other_enrollment,
            other_profile,
            other_report,
            request_id=request_id,
        )

    with sqlite3.connect(database) as connection:
        count = connection.execute("SELECT COUNT(*) FROM sandbox_sessions").fetchone()[0]
    assert count == 1


@pytest.mark.parametrize(
    "stored_request_id",
    [
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
        "{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}",
    ],
)
def test_noncanonical_persisted_request_id_fails_closed_without_duplicate(
    tmp_path: Path,
    stored_request_id: str,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, report = _stored_profile_and_report(service)
    request_id = UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    session = _create_session(
        service,
        enrollment,
        stored_profile,
        report,
        request_id=request_id,
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE sandbox_sessions SET request_id = ? WHERE sandbox_session_id = ?",
            (stored_request_id, str(session.sandbox_session_id)),
        )

    with pytest.raises(ControllerConflictError):
        _create_session(
            service,
            enrollment,
            stored_profile,
            report,
            request_id=request_id,
        )
    with sqlite3.connect(database) as connection:
        count = connection.execute("SELECT COUNT(*) FROM sandbox_sessions").fetchone()[0]
    assert count == 1


def test_cross_target_profile_report_lineage_is_rejected(tmp_path: Path) -> None:
    _, _, service = _controller(tmp_path)
    first, first_profile, first_report = _stored_profile_and_report(
        service,
        hostname="m6e-first",
    )
    second, second_profile, second_report = _stored_profile_and_report(
        service,
        hostname="m6e-second",
    )

    mismatches = [
        (second.target_id, first_profile.profile_id, first_report.compatibility_report_id),
        (first.target_id, second_profile.profile_id, second_report.compatibility_report_id),
        (first.target_id, first_profile.profile_id, second_report.compatibility_report_id),
        (uuid4(), first_profile.profile_id, first_report.compatibility_report_id),
        (first.target_id, uuid4(), first_report.compatibility_report_id),
        (first.target_id, first_profile.profile_id, uuid4()),
    ]
    for target_id, profile_id, report_id in mismatches:
        with pytest.raises(
            (AuthorizationError, ControllerConflictError, ControllerNotFoundError)
        ):
            service.create_sandbox_session(
                _admin(),
                target_id=target_id,
                profile_id=profile_id,
                compatibility_report_id=report_id,
                request=_session_request(),
            )


def test_admin_http_create_list_get_and_lineage_isolation(tmp_path: Path) -> None:
    _, _, service = _controller(tmp_path)
    enrollment, stored_profile, report = _stored_profile_and_report(service)
    application = ControllerHTTPSApplication(ControllerAPI(service))
    path = _session_path(enrollment, stored_profile, report)
    body = _session_request().model_dump_json().encode("utf-8")
    admin_header = {"Authorization": f"Bearer {ADMIN.get_secret_value()}"}
    agent_header = {
        "Authorization": f"Bearer {enrollment.agent_credential.get_secret_value()}"
    }

    assert application.dispatch("POST", path, body).status is HTTPStatus.UNAUTHORIZED
    assert application.dispatch("POST", path, body, agent_header).status is (
        HTTPStatus.UNAUTHORIZED
    )
    created = application.dispatch("POST", path, body, admin_header)
    assert created.status is HTTPStatus.CREATED
    document = json.loads(created.body)
    session_id = UUID(document["sandbox_session_id"])

    assert application.dispatch("GET", path).status is HTTPStatus.UNAUTHORIZED
    listed = application.dispatch("GET", path, headers=admin_header)
    fetched = application.dispatch(
        "GET",
        f"{path}/{session_id}",
        headers=admin_header,
    )
    assert listed.status is HTTPStatus.OK
    assert json.loads(listed.body) == [document]
    assert fetched.status is HTTPStatus.OK
    assert json.loads(fetched.body) == document

    wrong_target_path = path.replace(str(enrollment.target_id), str(uuid4()), 1)
    assert application.dispatch(
        "GET", wrong_target_path, headers=admin_header
    ).status is HTTPStatus.FORBIDDEN
    assert application.dispatch(
        "GET", f"{wrong_target_path}/{session_id}", headers=admin_header
    ).status is HTTPStatus.FORBIDDEN

    other, other_profile, other_report = _stored_profile_and_report(
        service,
        hostname="m6e-http-isolated-target",
    )
    other_path = _session_path(other, other_profile, other_report)
    isolated_list = application.dispatch("GET", other_path, headers=admin_header)
    isolated_get = application.dispatch(
        "GET",
        f"{other_path}/{session_id}",
        headers=admin_header,
    )
    assert isolated_list.status is HTTPStatus.OK
    assert json.loads(isolated_list.body) == []
    assert isolated_get.status is HTTPStatus.NOT_FOUND

    # M6E-A intentionally exposes no lifecycle mutation endpoint.
    assert application.dispatch(
        "POST", f"{path}/{session_id}/status", b"{}", admin_header
    ).status is HTTPStatus.NOT_FOUND
    assert all("set" not in endpoint.operation for endpoint in ENDPOINTS)


def test_malformed_stored_session_evidence_fails_closed(tmp_path: Path) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, stored_profile, report)

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE sandbox_sessions SET compatibility_reference_json = ? "
            "WHERE sandbox_session_id = ?",
            ("{}", str(session.sandbox_session_id)),
        )

    with pytest.raises(ControllerConflictError):
        service.get_sandbox_session(
            _admin(),
            target_id=enrollment.target_id,
            profile_id=stored_profile.profile_id,
            compatibility_report_id=report.compatibility_report_id,
            sandbox_session_id=session.sandbox_session_id,
        )


def test_malformed_stored_lifecycle_state_fails_closed(tmp_path: Path) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, stored_profile, report)

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE sandbox_sessions SET created_at = ? "
            "WHERE sandbox_session_id = ?",
            ("not-a-controller-timestamp", str(session.sandbox_session_id)),
        )

    with pytest.raises(ControllerConflictError):
        service.get_sandbox_session(
            _admin(),
            target_id=enrollment.target_id,
            profile_id=stored_profile.profile_id,
            compatibility_report_id=report.compatibility_report_id,
            sandbox_session_id=session.sandbox_session_id,
        )


def _session_at_status(
    service: ControllerService,
    enrollment,
    stored_profile,
    report,
    status: SandboxSessionStatus,
) -> SandboxSessionRecord:
    session = _create_session(service, enrollment, stored_profile, report)
    if status is SandboxSessionStatus.REQUESTED:
        return session
    session = service.mark_provisioning(session.sandbox_session_id)
    if status is SandboxSessionStatus.PROVISIONING:
        return session
    if status is SandboxSessionStatus.FAILED:
        return service.mark_failed(
            session.sandbox_session_id,
            failure_reason="synthetic provisioning failure",
        )
    session = service.mark_ready(
        session.sandbox_session_id,
        sandbox_instance_id=f"nested-vm-{session.sandbox_session_id}",
    )
    if status is SandboxSessionStatus.READY:
        return session
    session = service.mark_validating(session.sandbox_session_id)
    if status is SandboxSessionStatus.VALIDATING:
        return session
    if status is SandboxSessionStatus.QUARANTINED:
        return service.mark_quarantined(
            session.sandbox_session_id,
            quarantine_reason="synthetic containment boundary",
        )
    session = service.mark_completed(session.sandbox_session_id)
    if status is SandboxSessionStatus.COMPLETED:
        return session
    assert status is SandboxSessionStatus.CLOSED
    return service.close_session(session.sandbox_session_id)


def test_every_allowed_lifecycle_transition_preserves_controller_timestamps(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, report = _stored_profile_and_report(service)

    successful = _create_session(service, enrollment, stored_profile, report)
    successful = service.mark_provisioning(successful.sandbox_session_id)
    assert successful.status is SandboxSessionStatus.PROVISIONING
    assert successful.provisioning_started_at == NOW
    successful = service.mark_ready(
        successful.sandbox_session_id,
        sandbox_instance_id="provider-generated-success",
    )
    assert successful.status is SandboxSessionStatus.READY
    assert successful.ready_at == NOW
    successful = service.mark_validating(successful.sandbox_session_id)
    assert successful.status is SandboxSessionStatus.VALIDATING
    assert successful.validation_started_at == NOW
    successful = service.mark_completed(successful.sandbox_session_id)
    assert successful.status is SandboxSessionStatus.COMPLETED
    assert successful.completed_at == NOW
    successful = service.close_session(successful.sandbox_session_id)
    assert successful.status is SandboxSessionStatus.CLOSED
    assert successful.closed_at == NOW
    assert successful.failure_reason is None
    assert successful.quarantine_reason is None

    # The permitted failure transition is independently exercised from every
    # possible prior state, and each terminal failure can be closed.
    for source in (
        SandboxSessionStatus.PROVISIONING,
        SandboxSessionStatus.READY,
        SandboxSessionStatus.VALIDATING,
    ):
        candidate = _session_at_status(
            service,
            enrollment,
            stored_profile,
            report,
            source,
        )
        failed = service.mark_failed(
            candidate.sandbox_session_id,
            failure_reason=f"synthetic failure from {source.value}",
        )
        assert failed.status is SandboxSessionStatus.FAILED
        assert failed.completed_at == NOW
        assert failed.failure_reason == f"synthetic failure from {source.value}"
        closed = service.close_session(failed.sandbox_session_id)
        assert closed.status is SandboxSessionStatus.CLOSED
        assert closed.closed_at == NOW
        assert closed.failure_reason == failed.failure_reason

    validating = _session_at_status(
        service,
        enrollment,
        stored_profile,
        report,
        SandboxSessionStatus.VALIDATING,
    )
    quarantined = service.mark_quarantined(
        validating.sandbox_session_id,
        quarantine_reason="provider must retain isolated evidence",
    )
    assert quarantined.status is SandboxSessionStatus.QUARANTINED
    assert quarantined.completed_at == NOW
    assert quarantined.quarantine_reason == "provider must retain isolated evidence"
    closed_quarantine = service.close_session(quarantined.sandbox_session_id)
    assert closed_quarantine.status is SandboxSessionStatus.CLOSED
    assert closed_quarantine.closed_at == NOW
    assert closed_quarantine.quarantine_reason == quarantined.quarantine_reason

    with sqlite3.connect(database) as connection:
        statuses = {
            row[0]
            for row in connection.execute("SELECT status FROM sandbox_sessions")
        }
    assert statuses == {SandboxSessionStatus.CLOSED.value}


def test_each_lifecycle_timestamp_comes_from_an_advancing_controller_clock(
    tmp_path: Path,
) -> None:
    tick = 0

    def advancing_clock() -> datetime:
        nonlocal tick
        value = NOW + timedelta(seconds=tick)
        tick += 1
        return value

    _, _, service = _controller(tmp_path, clock=advancing_clock)
    enrollment, stored_profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, stored_profile, report)
    session = service.mark_provisioning(session.sandbox_session_id)
    session = service.mark_ready(
        session.sandbox_session_id,
        sandbox_instance_id="advancing-clock-instance",
    )
    session = service.mark_validating(session.sandbox_session_id)
    session = service.mark_completed(session.sandbox_session_id)
    session = service.close_session(session.sandbox_session_id)

    timestamps = [
        session.created_at,
        session.provisioning_started_at,
        session.ready_at,
        session.validation_started_at,
        session.completed_at,
        session.closed_at,
    ]
    assert all(value is not None for value in timestamps)
    assert timestamps == sorted(timestamps)
    assert len(set(timestamps)) == len(timestamps)


def test_every_illegal_transition_fails_closed_and_closed_is_terminal(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    enrollment, stored_profile, report = _stored_profile_and_report(service)
    allowed_targets = {
        SandboxSessionStatus.REQUESTED: {SandboxSessionStatus.PROVISIONING},
        SandboxSessionStatus.PROVISIONING: {
            SandboxSessionStatus.READY,
            SandboxSessionStatus.FAILED,
        },
        SandboxSessionStatus.READY: {
            SandboxSessionStatus.VALIDATING,
            SandboxSessionStatus.FAILED,
        },
        SandboxSessionStatus.VALIDATING: {
            SandboxSessionStatus.COMPLETED,
            SandboxSessionStatus.FAILED,
            SandboxSessionStatus.QUARANTINED,
        },
        SandboxSessionStatus.COMPLETED: {SandboxSessionStatus.CLOSED},
        SandboxSessionStatus.FAILED: {SandboxSessionStatus.CLOSED},
        SandboxSessionStatus.QUARANTINED: {SandboxSessionStatus.CLOSED},
        SandboxSessionStatus.CLOSED: set(),
    }

    for source_status in SandboxSessionStatus:
        session = _session_at_status(
            service,
            enrollment,
            stored_profile,
            report,
            source_status,
        )
        operations = {
            SandboxSessionStatus.PROVISIONING: lambda: service.mark_provisioning(
                session.sandbox_session_id
            ),
            SandboxSessionStatus.READY: lambda: service.mark_ready(
                session.sandbox_session_id,
                sandbox_instance_id=f"illegal-{session.sandbox_session_id}",
            ),
            SandboxSessionStatus.VALIDATING: lambda: service.mark_validating(
                session.sandbox_session_id
            ),
            SandboxSessionStatus.COMPLETED: lambda: service.mark_completed(
                session.sandbox_session_id
            ),
            SandboxSessionStatus.FAILED: lambda: service.mark_failed(
                session.sandbox_session_id,
                failure_reason="illegal transition fixture",
            ),
            SandboxSessionStatus.QUARANTINED: lambda: service.mark_quarantined(
                session.sandbox_session_id,
                quarantine_reason="illegal transition fixture",
            ),
            SandboxSessionStatus.CLOSED: lambda: service.close_session(
                session.sandbox_session_id
            ),
        }
        for target_status, operation in operations.items():
            if target_status in allowed_targets[source_status]:
                continue
            with pytest.raises((ControllerConflictError, ValidationError)):
                operation()
            unchanged = service.get_sandbox_session(
                _admin(),
                target_id=enrollment.target_id,
                profile_id=stored_profile.profile_id,
                compatibility_report_id=report.compatibility_report_id,
                sandbox_session_id=session.sandbox_session_id,
            )
            assert unchanged.status is source_status


def test_repository_transition_cannot_rewrite_recorded_lifecycle_fields(
    tmp_path: Path,
) -> None:
    _, repository, service = _controller(tmp_path)
    enrollment, stored_profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, stored_profile, report)
    service.mark_provisioning(session.sandbox_session_id)
    ready = service.mark_ready(
        session.sandbox_session_id,
        sandbox_instance_id="provider-owned-instance",
    )

    forged_values = ready.model_dump(mode="python")
    forged_values.update(
        status=SandboxSessionStatus.VALIDATING,
        sandbox_instance_id="replacement-instance",
        validation_started_at=NOW,
    )
    forged = SandboxSessionRecord.model_validate(forged_values)
    with pytest.raises(
        StorageConflictError,
        match="changed previously recorded state",
    ):
        repository.mark_validating(forged)

    unchanged = repository.get_sandbox_session_by_id(session.sandbox_session_id)
    assert unchanged == ready


def test_populated_m6d_database_migrates_without_rewriting_existing_evidence(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, report = _stored_profile_and_report(service)
    validation_job = service.create_validation_job(
        _admin(),
        _validation_request(enrollment, stored_profile, report),
    )
    original = (
        stored_profile.profile_sha256,
        report.report_sha256,
        validation_job.validation_job_id,
    )

    # This reconstructs the exact pre-M6E table set while leaving populated M6D
    # identity, profile, compatibility, and validation evidence in place.
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE sandbox_sessions")

    migrated = SQLiteControllerRepository(database)
    migrated_profile = migrated.get_profile(stored_profile.profile_id)
    migrated_report = migrated.get_compatibility_report(
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
        compatibility_report_id=report.compatibility_report_id,
    )
    migrated_job = migrated.get_validation_job(validation_job.validation_job_id)
    assert migrated_profile is not None
    assert migrated_report is not None
    assert migrated_job is not None
    assert (
        migrated_profile.profile_sha256,
        migrated_report.report_sha256,
        migrated_job.job.validation_job_id,
    ) == original
    assert migrated.list_sandbox_sessions(
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
        compatibility_report_id=report.compatibility_report_id,
    ) == []
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_partial_or_false_current_sandbox_schema_fails_closed(tmp_path: Path) -> None:
    database, _, _ = _controller(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE sandbox_sessions")
        connection.execute(
            "CREATE TABLE sandbox_sessions ("
            "sandbox_session_id TEXT, request_id TEXT, status TEXT)"
        )

    with pytest.raises(ControllerStorageSecurityError):
        SQLiteControllerRepository(database)
