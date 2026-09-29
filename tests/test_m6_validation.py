"""M6D constrained sandbox-validation orchestration and lineage tests.

No test in this module uses the live M5 adapter registry, the developer host's
``/etc`` tree, or a real subprocess.  The one Agent-side M5 integration test
injects an inert adapter and a temporary root while retaining the real M5
validator, models, authorization gates, and report construction.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
from http import HTTPStatus
import json
from pathlib import Path
import sqlite3
import stat
from uuid import UUID, uuid4

from pydantic import SecretStr, ValidationError
import pytest
import yaml

from src.agent.protocol import AgentProtocol
from src.agent.runtime import AgentRuntime
from src.agent.state import AgentStateStore
from src.agent.validation import LocalSandboxControlValidator
from src.agent.validation_journal import (
    ValidationJournalError,
    ValidationJournalInterruptedError,
    ValidationJournalState,
    ValidationJournalStore,
    validation_payload_sha256,
)
from src.compatibility_engine.models import CompatibilityDecision
from src.controller.api import ControllerAPI
from src.controller.models import (
    AdminAuth,
    AgentAuth,
    EnrollmentRequest,
    EnrollmentResponse,
    HeartbeatResponse,
    JobCreateRequest,
    JobPollRequest,
    JobPollResponse,
    JobStatus,
    JobType,
    ObservedTargetMetadata,
    ProfileSubmissionRequest,
    ValidationJobCreateRequest,
    ValidationJobRecord,
    ValidationResultPayload,
    ValidationResultRecord,
    ValidationResultSubmissionRequest,
)
from src.controller.service import (
    AuthenticationError,
    AuthorizationError,
    ControllerConflictError,
    ControllerService,
    ControllerSettings,
)
from src.controller.storage import (
    ControllerStorageSecurityError,
    SQLiteControllerRepository,
    StorageConflictError,
)
from src.controller.validation import canonical_validation_payload_json
from src.controller.transport import ControllerHTTPSApplication
from src.poc_models import Category
from src.sandbox_validator.adapters.base import AdapterContext, AdapterOutcome
from src.sandbox_validator.models import (
    ActionStatus,
    AuditEvidence,
    EvidenceStatus,
    HealthCheck,
    HealthStatus,
    RemediationAction,
    RemediationResult,
    RollbackResult,
    SandboxIdentity,
    ValidationDecision,
)
from src.sandbox_validator.validator import SandboxValidator
from src.target_profiler.models import TargetProfile


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "data" / "profiles" / "target-profile.yaml"
NOW = datetime(2026, 9, 26, 8, 30, tzinfo=UTC)
BOOTSTRAP = SecretStr("m6d-bootstrap-fixture")
ADMIN = SecretStr("m6d-admin-fixture")
AGENT_CREDENTIAL = SecretStr("m6d-agent-fixture")


def _metadata(hostname: str) -> ObservedTargetMetadata:
    return ObservedTargetMetadata(
        hostname=hostname,
        os="Ubuntu",
        os_version="24.04",
        kernel="6.8.0-m6d-test",
        architecture="x86_64",
    )


def _profile() -> TargetProfile:
    return TargetProfile.model_validate(
        yaml.safe_load(PROFILE_PATH.read_text(encoding="utf-8"))
    )


def _controller(
    tmp_path: Path,
) -> tuple[Path, SQLiteControllerRepository, ControllerService]:
    database = tmp_path / "controller.sqlite3"
    repository = SQLiteControllerRepository(database)
    service = ControllerService(
        repository,
        ControllerSettings(
            bootstrap_credential=BOOTSTRAP,
            admin_credential=ADMIN,
        ),
        clock=lambda: NOW,
    )
    return database, repository, service


def _admin() -> AdminAuth:
    return AdminAuth(admin_credential=ADMIN)


def _enroll(service: ControllerService, hostname: str):
    return service.enroll(
        EnrollmentRequest(
            bootstrap_credential=BOOTSTRAP,
            installation_id=uuid4(),
            agent_version="m6d-test",
            observed_metadata=_metadata(hostname),
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
    hostname: str = "m6d-target",
):
    enrollment = _enroll(service, hostname)
    profile_job = service.create_job(
        _admin(),
        JobCreateRequest(
            target_id=enrollment.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )
    polled = service.poll_jobs(JobPollRequest(auth=_auth(enrollment))).jobs
    assert [item.job_id for item in polled] == [profile_job.job_id]
    profile = _profile()
    stored_profile = service.submit_profile(
        ProfileSubmissionRequest(
            auth=_auth(enrollment),
            job_id=profile_job.job_id,
            profile=profile,
            profiler_version="m3-m6d-test",
            sentra_version="m6d-test",
        )
    )
    from src.controller.models import CompatibilityAnalysisRequest

    compatibility = service.run_compatibility_analysis(
        _admin(),
        CompatibilityAnalysisRequest(
            target_id=enrollment.target_id,
            profile_id=stored_profile.profile_id,
        ),
    )
    return enrollment, stored_profile, compatibility


def _job_request(
    enrollment,
    stored_profile,
    compatibility,
    *,
    request_id: UUID | None = None,
) -> ValidationJobCreateRequest:
    selected = next(
        item
        for item in compatibility.report.control_results
        if item.control_id == "7.1.1"
    )
    uncertain = selected.result in {
        CompatibilityDecision.WARNING,
        CompatibilityDecision.REVIEW_REQUIRED,
        CompatibilityDecision.INSUFFICIENT_EVIDENCE,
    }
    return ValidationJobCreateRequest(
        request_id=request_id or uuid4(),
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
        compatibility_report_id=compatibility.compatibility_report_id,
        control_id="7.1.1",
        administrator_approval_acknowledged=True,
        compatibility_risk_acknowledged=uncertain,
        compatibility_override_reason=(
            "Fixture administrator reviewed the missing compatibility evidence."
            if selected.result is CompatibilityDecision.INSUFFICIENT_EVIDENCE
            else None
        ),
    )


def _create_and_poll_validation_job(
    service: ControllerService,
    enrollment,
    stored_profile,
    compatibility,
    *,
    request_id: UUID | None = None,
) -> tuple[ValidationJobCreateRequest, ValidationJobRecord]:
    request = _job_request(
        enrollment,
        stored_profile,
        compatibility,
        request_id=request_id,
    )
    pending = service.create_validation_job(_admin(), request)
    jobs = service.poll_jobs(JobPollRequest(auth=_auth(enrollment))).jobs
    matching = [
        item
        for item in jobs
        if isinstance(item, ValidationJobRecord)
        and item.validation_job_id == pending.validation_job_id
    ]
    assert len(matching) == 1
    assert matching[0].status is JobStatus.DISPATCHED
    return request, matching[0]


def _sandbox_identity() -> SandboxIdentity:
    return SandboxIdentity(
        hostname="m6d-inert-sandbox",
        os="Ubuntu",
        version="24.04",
        kernel="6.8.0-m6d-test",
        architecture="x86_64",
        architecture_supported=True,
        effective_uid=0,
        privileged=True,
        supported=True,
    )


class _NoCommandRunner:
    def run_read(self, *_args: object, **_kwargs: object) -> None:
        raise AssertionError("M6D fixture attempted a real read command")

    def run_mutation(self, *_args: object, **_kwargs: object) -> None:
        raise AssertionError("M6D fixture attempted a real mutation command")


class _RollbackEvidenceAdapter:
    """Inert adapter producing real M5 rollback and health-check structures."""

    control_id = "7.1.1"
    title = "Ensure permissions on /etc/passwd are configured"
    category = Category.FILE_PERMISSIONS
    mutation_supported = True

    def __init__(self) -> None:
        self.execute_calls = 0

    @staticmethod
    def pre_audit(_context: AdapterContext) -> list[AuditEvidence]:
        return [
            AuditEvidence(
                name="passwd_file_mode",
                status=EvidenceStatus.COLLECTED,
                value="0664",
                source="fixture:m6d-pre-audit",
            )
        ]

    @staticmethod
    def plan(_pre_audit: list[AuditEvidence]) -> list[RemediationAction]:
        return [
            RemediationAction(
                action_id="apply-passwd-metadata",
                description="Exercise the M5 result boundary without host I/O.",
                mutating=True,
                target="/etc/passwd",
                planned_effect="Produce deterministic rollback evidence.",
                status=ActionStatus.PLANNED,
            )
        ]

    def execute(self, context, pre_audit, authorization) -> AdapterOutcome:
        del context, pre_audit
        assert authorization.control_id == self.control_id
        self.execute_calls += 1
        return AdapterOutcome(
            remediation=RemediationResult(
                supported=True,
                attempted=True,
                changed=True,
                succeeded=False,
                actions=[
                    RemediationAction(
                        action_id="apply-passwd-metadata",
                        description="Exercise the M5 result boundary without host I/O.",
                        mutating=True,
                        target="/etc/passwd",
                        planned_effect="Produce deterministic rollback evidence.",
                        status=ActionStatus.FAILED,
                        error="fixture_post_state_failure",
                    )
                ],
                backups=[],
                reason="The inert candidate intentionally failed verification.",
            ),
            post_audit=[
                AuditEvidence(
                    name="passwd_file_mode",
                    status=EvidenceStatus.COLLECTED,
                    value="0600",
                    source="fixture:m6d-post-audit",
                )
            ],
            health_checks=[
                HealthCheck(
                    check_id="passwd-record-sanity",
                    description="Exercise required M5 health evidence.",
                    required=True,
                    status=HealthStatus.FAILED,
                    explanation="The inert fixture requested rollback.",
                )
            ],
            rollback=RollbackResult(
                supported=True,
                attempted=True,
                succeeded=True,
                actions=[
                    RemediationAction(
                        action_id="restore-passwd-metadata",
                        description="Record an inert successful rollback.",
                        mutating=True,
                        target="/etc/passwd",
                        planned_effect="Restore the fixture pre-state.",
                        status=ActionStatus.APPLIED,
                    )
                ],
                explanation="The inert fixture rollback completed.",
            ),
            decision=ValidationDecision.FAILED,
            explanation="The inert fixture failed and preserved rollback evidence.",
            warnings=[],
            errors=["fixture required post-state failed"],
        )


def _validation_payload(
    job: ValidationJobRecord,
    tmp_path: Path,
) -> tuple[ValidationResultPayload, _RollbackEvidenceAdapter]:
    adapter = _RollbackEvidenceAdapter()
    validator = SandboxValidator(
        context=AdapterContext(
            root=tmp_path,
            runner=_NoCommandRunner(),  # type: ignore[arg-type]
            environment={},
            clock=lambda: NOW,
        ),
        identity_provider=_sandbox_identity,
        adapters={adapter.control_id: adapter},
    )
    payload = LocalSandboxControlValidator(validator=validator).validate(
        job,
        sandbox_operator_acknowledged=True,
    )
    return payload, adapter


def test_validation_job_creation_is_idempotent_and_preserves_m4_lineage(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    request_id = uuid4()
    request = _job_request(
        enrollment,
        stored_profile,
        compatibility,
        request_id=request_id,
    )

    first = service.create_validation_job(_admin(), request)
    repeated = service.create_validation_job(_admin(), request)

    assert repeated == first
    assert first.request_id == request_id
    assert first.target_id == enrollment.target_id
    assert first.profile_id == stored_profile.profile_id
    assert first.compatibility_report_id == compatibility.compatibility_report_id
    assert first.control_id == "7.1.1"
    assert first.job_type is JobType.VALIDATE_CONTROL
    assert first.compatibility_reference.report_sha256 == compatibility.report_sha256
    assert first.compatibility_reference.report_source.endswith(
        str(compatibility.compatibility_report_id)
    )
    assert first.compatibility_reference.profile_source.endswith(
        str(stored_profile.profile_id)
    )


@pytest.mark.parametrize("control_id", ["5.1.20", "4.2.3", "9.9.9"])
def test_validation_job_model_rejects_every_non_allowlisted_control(
    control_id: str,
) -> None:
    with pytest.raises(ValidationError):
        ValidationJobCreateRequest.model_validate(
            {
                "request_id": str(uuid4()),
                "target_id": str(uuid4()),
                "profile_id": str(uuid4()),
                "compatibility_report_id": str(uuid4()),
                "control_id": control_id,
                "validation_mode": "sandbox",
                "execution_mode": "execute",
                "administrator_approval_acknowledged": True,
            }
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("command", "id"),
        ("shell", "sh -c whoami"),
        ("argv", ["/usr/bin/id"]),
        ("script", "echo unsafe"),
        ("path", "/etc/shadow"),
        ("service", "ssh.service"),
        ("adapter", "arbitrary.module.Adapter"),
    ],
)
def test_validation_job_has_no_generic_execution_or_file_action_fields(
    field: str,
    value: object,
) -> None:
    document = {
        "request_id": uuid4(),
        "target_id": uuid4(),
        "profile_id": uuid4(),
        "compatibility_report_id": uuid4(),
        "control_id": "7.1.1",
        "administrator_approval_acknowledged": True,
        field: value,
    }
    with pytest.raises(ValidationError):
        ValidationJobCreateRequest.model_validate(document)

    forbidden = {"command", "shell", "argv", "script", "path", "service", "adapter"}
    assert forbidden.isdisjoint(ValidationJobRecord.model_fields)


def test_cross_target_lineage_and_admin_authentication_are_rejected(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    first, stored_profile, compatibility = _stored_profile_and_report(
        service,
        hostname="first-target",
    )
    second = _enroll(service, "second-target")
    request = _job_request(first, stored_profile, compatibility)

    with pytest.raises(AuthenticationError):
        service.create_validation_job(
            AdminAuth(admin_credential=SecretStr("wrong-admin")),
            request,
        )

    crossed = request.model_copy(update={"target_id": second.target_id})
    with pytest.raises(AuthorizationError, match="does not belong"):
        service.create_validation_job(_admin(), crossed)


def test_target_b_cannot_poll_or_submit_target_a_validation(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    first, stored_profile, compatibility = _stored_profile_and_report(
        service,
        hostname="first-target",
    )
    second = _enroll(service, "second-target")
    pending = service.create_validation_job(
        _admin(),
        _job_request(first, stored_profile, compatibility),
    )

    foreign_poll = service.poll_jobs(JobPollRequest(auth=_auth(second)))
    assert all(
        not isinstance(item, ValidationJobRecord)
        or item.validation_job_id != pending.validation_job_id
        for item in foreign_poll.jobs
    )

    own_poll = service.poll_jobs(JobPollRequest(auth=_auth(first)))
    job = next(
        item
        for item in own_poll.jobs
        if isinstance(item, ValidationJobRecord)
        and item.validation_job_id == pending.validation_job_id
    )
    payload, _ = _validation_payload(job, tmp_path / "inert-root")
    with pytest.raises(AuthorizationError, match="not assigned"):
        service.submit_validation_result(
            ValidationResultSubmissionRequest(
                auth=_auth(second),
                payload=payload,
            )
        )


def test_local_m5_result_is_strict_and_preserves_health_and_rollback_evidence(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    _, job = _create_and_poll_validation_job(
        service,
        enrollment,
        stored_profile,
        compatibility,
    )

    payload, adapter = _validation_payload(job, tmp_path / "inert-root")
    result = payload.report.control_results[0]

    assert adapter.execute_calls == 1
    assert result.result is ValidationDecision.FAILED
    assert result.remediation.attempted is True
    assert result.remediation.succeeded is False
    assert result.health_checks[0].status is HealthStatus.FAILED
    assert result.rollback.attempted is True
    assert result.rollback.succeeded is True
    assert result.m4_input == job.compatibility_reference
    assert result.m3_profile_source == job.compatibility_reference.profile_source
    assert result.precheck.sandbox_operator_acknowledged is True
    assert result.precheck.administrator_approval_acknowledged is True

    malformed = payload.model_dump(mode="python")
    malformed["command"] = "id"
    with pytest.raises(ValidationError):
        ValidationResultPayload.model_validate(malformed)


def test_result_hash_persistence_retrieval_and_idempotent_replay(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    _, job = _create_and_poll_validation_job(
        service,
        enrollment,
        stored_profile,
        compatibility,
    )
    payload, _ = _validation_payload(job, tmp_path / "inert-root")
    request = ValidationResultSubmissionRequest(
        auth=_auth(enrollment),
        payload=payload,
    )

    first = service.submit_validation_result(request)
    repeated = service.submit_validation_result(request)
    canonical = canonical_validation_payload_json(payload)
    expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    assert repeated == first
    assert first.result_sha256 == expected_hash
    assert service.list_validation_results(
        _admin(),
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
        compatibility_report_id=compatibility.compatibility_report_id,
    ) == [first]
    assert service.get_validation_result(
        _admin(),
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
        compatibility_report_id=compatibility.compatibility_report_id,
        validation_result_id=first.validation_result_id,
    ) == first

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT target_id, profile_id, compatibility_report_id, "
            "validation_job_id, control_id, validation_mode, execution_mode, "
            "result_sha256, payload_json FROM validation_results "
            "WHERE validation_result_id = ?",
            (str(first.validation_result_id),),
        ).fetchone()
    assert row == (
        str(enrollment.target_id),
        str(stored_profile.profile_id),
        str(compatibility.compatibility_report_id),
        str(job.validation_job_id),
        "7.1.1",
        "sandbox",
        "execute",
        expected_hash,
        canonical,
    )

    changed_report = payload.report.model_copy(deep=True)
    changed_report.control_results[0].warnings.append("different replay evidence")
    changed_payload = ValidationResultPayload.model_validate(
        {
            **payload.model_dump(mode="python"),
            "report": changed_report,
        }
    )
    with pytest.raises(ControllerConflictError, match="conflicts"):
        service.submit_validation_result(
            ValidationResultSubmissionRequest(
                auth=_auth(enrollment),
                payload=changed_payload,
            )
        )


def test_result_lineage_mismatch_is_rejected_before_storage(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    _, job = _create_and_poll_validation_job(
        service,
        enrollment,
        stored_profile,
        compatibility,
    )
    payload, _ = _validation_payload(job, tmp_path / "inert-root")
    mismatched = ValidationResultPayload.model_validate(
        {
            **payload.model_dump(mode="python"),
            # Keep the payload internally self-consistent so this exercises
            # the Controller's binding to the authorized job, rather than the
            # payload model's nested profile-source validation.
            "target_id": uuid4(),
        }
    )

    with pytest.raises(ControllerConflictError, match="authorized job"):
        service.submit_validation_result(
            ValidationResultSubmissionRequest(
                auth=_auth(enrollment),
                payload=mismatched,
            )
        )


def test_validation_result_cannot_predate_controller_dispatch(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    _, job = _create_and_poll_validation_job(
        service,
        enrollment,
        stored_profile,
        compatibility,
    )
    payload, _ = _validation_payload(job, tmp_path / "inert-root")
    changed_report = payload.report.model_copy(deep=True)
    changed_report.control_results[0].started_at = NOW - timedelta(seconds=1)
    predating = ValidationResultPayload.model_validate(
        {
            **payload.model_dump(mode="python"),
            "report": changed_report,
        }
    )

    with pytest.raises(ControllerConflictError, match="authorized job"):
        service.submit_validation_result(
            ValidationResultSubmissionRequest(
                auth=_auth(enrollment),
                payload=predating,
            )
        )


def test_validation_storage_revalidates_payload_hash_and_fails_closed(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    _, job = _create_and_poll_validation_job(
        service,
        enrollment,
        stored_profile,
        compatibility,
    )
    payload, _ = _validation_payload(job, tmp_path / "inert-root")
    stored = service.submit_validation_result(
        ValidationResultSubmissionRequest(
            auth=_auth(enrollment),
            payload=payload,
        )
    )

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE validation_results SET result_sha256 = ? "
            "WHERE validation_result_id = ?",
            ("0" * 64, str(stored.validation_result_id)),
        )

    with pytest.raises(ControllerConflictError, match="could not be validated"):
        service.get_validation_result(
            _admin(),
            target_id=enrollment.target_id,
            profile_id=stored_profile.profile_id,
            compatibility_report_id=compatibility.compatibility_report_id,
            validation_result_id=stored.validation_result_id,
        )


def test_submission_maps_tampered_stored_job_to_controlled_conflict(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    _, job = _create_and_poll_validation_job(
        service,
        enrollment,
        stored_profile,
        compatibility,
    )
    payload, _ = _validation_payload(job, tmp_path / "inert-root")
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE validation_jobs SET compatibility_reference_json = ? "
            "WHERE validation_job_id = ?",
            ("{}", str(job.validation_job_id)),
        )

    with pytest.raises(
        ControllerConflictError,
        match="stored validation job could not be validated",
    ):
        service.submit_validation_result(
            ValidationResultSubmissionRequest(
                auth=_auth(enrollment),
                payload=payload,
            )
        )


def test_validation_sqlite_schema_is_exact_and_partial_schema_is_rejected(
    tmp_path: Path,
) -> None:
    database, _, _ = _controller(tmp_path)
    with sqlite3.connect(database) as connection:
        job_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(validation_jobs)")
        }
        result_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(validation_results)")
        }
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(validation_results)"
        ).fetchall()

    assert {
        "validation_job_id",
        "request_id",
        "target_id",
        "profile_id",
        "compatibility_report_id",
        "assigned_agent_id",
        "compatibility_reference_json",
        "status",
    }.issubset(job_columns)
    assert {
        "validation_result_id",
        "validation_job_id",
        "target_id",
        "profile_id",
        "compatibility_report_id",
        "agent_id",
        "result_sha256",
        "payload_json",
    }.issubset(result_columns)
    assert foreign_keys

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TABLE validation_results")
    with pytest.raises(
        ControllerStorageSecurityError,
        match="validation schema is incomplete|validation schema.*not recognized",
    ):
        SQLiteControllerRepository(database)


def test_populated_m6c_database_adds_empty_m6d_tables_without_rewriting_evidence(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    original_hash = compatibility.report_sha256
    original_payload = compatibility.report

    # Removing both new tables recreates the exact M6C starting condition while
    # retaining populated M6A-M6C identity and evidence tables.
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TABLE validation_results")
        connection.execute("DROP TABLE validation_jobs")

    migrated = SQLiteControllerRepository(database)
    restored = migrated.get_compatibility_report(
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
        compatibility_report_id=compatibility.compatibility_report_id,
    )
    assert restored is not None
    assert restored.report_sha256 == original_hash
    assert restored.report == original_payload
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM validation_jobs"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM validation_results"
        ).fetchone()[0] == 0
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_validation_storage_rejects_existing_broken_foreign_key_lineage(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    pending = service.create_validation_job(
        _admin(),
        _job_request(enrollment, stored_profile, compatibility),
    )

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            "UPDATE validation_jobs SET profile_id = ? "
            "WHERE validation_job_id = ?",
            (str(uuid4()), str(pending.validation_job_id)),
        )

    with pytest.raises(
        ControllerStorageSecurityError,
        match="broken lineage",
    ):
        SQLiteControllerRepository(database)


def test_validation_journal_is_private_and_rejects_changed_job_replay(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    _, job = _create_and_poll_validation_job(
        service,
        enrollment,
        stored_profile,
        compatibility,
    )
    payload, _ = _validation_payload(job, tmp_path / "inert-root")
    store = ValidationJournalStore.for_agent_state(tmp_path / "agent" / "state.json")

    with store.acquire(
        job,
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
    ) as locked:
        assert locked.entry is None
        assert locked.mark_started().state is ValidationJournalState.STARTED
        cached = locked.cache_result(payload)
        assert cached.state is ValidationJournalState.RESULT_READY

    entry_path = store.directory / f"{job.validation_job_id}.json"
    lock_path = store.directory / f"{job.validation_job_id}.lock"
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(entry_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600

    with store.acquire(
        job,
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
    ) as locked:
        assert locked.entry is not None
        assert locked.entry.state is ValidationJournalState.RESULT_READY
        assert locked.entry.result == payload

    changed_job = ValidationJobRecord.model_validate(
        {
            **job.model_dump(mode="python"),
            "request_id": uuid4(),
        }
    )
    with pytest.raises(ValidationJournalError, match="conflicts"):
        with store.acquire(
            changed_job,
            target_id=enrollment.target_id,
            agent_id=enrollment.agent_id,
        ):
            pass


class _NoProfileCollector:
    def collect(self) -> TargetProfile:
        raise AssertionError("validation job invoked the M3 profiler")


class _CountingValidator:
    def __init__(self, payload: ValidationResultPayload) -> None:
        self.payload = payload
        self.calls = 0

    def validate(self, job, *, sandbox_operator_acknowledged: bool):
        assert job.validation_job_id == self.payload.validation_job_id
        assert sandbox_operator_acknowledged is True
        self.calls += 1
        return self.payload


class _ValidationRuntimeTransport:
    def __init__(
        self,
        enrollment: EnrollmentResponse,
        job: ValidationJobRecord,
        *,
        fail_submission: bool,
    ) -> None:
        self.enrollment = enrollment
        self.job = job
        self.fail_submission = fail_submission
        self.validation_requests: list[ValidationResultSubmissionRequest] = []

    def enroll(self, _request):
        raise AssertionError("already-enrolled fixture attempted enrollment")

    def heartbeat(self, _request) -> HeartbeatResponse:
        return HeartbeatResponse(accepted=True, last_seen=NOW)

    def poll_jobs(self, _request) -> JobPollResponse:
        return JobPollResponse(jobs=[self.job])

    def submit_profile(self, _request):
        raise AssertionError("validation fixture attempted profile submission")

    def submit_validation_result(
        self,
        request: ValidationResultSubmissionRequest,
    ) -> ValidationResultRecord:
        self.validation_requests.append(request)
        if self.fail_submission:
            raise RuntimeError("synthetic HTTPS submission failure")
        return ValidationResultRecord(
            validation_result_id=uuid4(),
            agent_id=request.auth.agent_id,
            created_at=self.job.created_at,
            dispatched_at=self.job.dispatched_at,
            completed_at=NOW,
            result_sha256=validation_payload_sha256(request.payload),
            payload=request.payload,
        )


def _protocol(path: Path, enrollment: EnrollmentResponse) -> AgentProtocol:
    AgentStateStore(path).save_enrollment(enrollment)
    return AgentProtocol(
        AgentStateStore(path),
        observed_metadata=_metadata("m6d-runtime-target"),
        agent_version="m6d-test",
    )


def test_runtime_retries_cached_result_without_repeating_local_validation(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    enrolled, stored_profile, compatibility = _stored_profile_and_report(service)
    _, job = _create_and_poll_validation_job(
        service,
        enrolled,
        stored_profile,
        compatibility,
    )
    payload, _ = _validation_payload(job, tmp_path / "inert-root")
    enrollment = EnrollmentResponse(
        target_id=enrolled.target_id,
        agent_id=enrolled.agent_id,
        agent_credential=AGENT_CREDENTIAL,
        polling_interval_seconds=30,
    )
    state_path = tmp_path / "runtime" / "state.json"
    protocol = _protocol(state_path, enrollment)
    journal = ValidationJournalStore.for_agent_state(state_path)
    validator = _CountingValidator(payload)
    failing_transport = _ValidationRuntimeTransport(
        enrollment,
        job,
        fail_submission=True,
    )

    with pytest.raises(RuntimeError, match="synthetic HTTPS"):
        AgentRuntime(
            protocol=protocol,
            transport=failing_transport,
            profiler=_NoProfileCollector(),
            control_validator=validator,
            validation_journal=journal,
            sandbox_validation_acknowledged=True,
        ).run_once()
    assert validator.calls == 1

    succeeding_transport = _ValidationRuntimeTransport(
        enrollment,
        job,
        fail_submission=False,
    )
    result = AgentRuntime(
        protocol=AgentProtocol(
            AgentStateStore(state_path),
            observed_metadata=_metadata("m6d-runtime-target"),
            agent_version="m6d-test",
        ),
        transport=succeeding_transport,
        profiler=_NoProfileCollector(),
        control_validator=validator,
        validation_journal=journal,
        sandbox_validation_acknowledged=True,
    ).run_once()

    assert validator.calls == 1
    assert result.jobs_polled == 1
    assert result.profiles_submitted == 0
    assert result.validation_results_submitted == 1
    assert succeeding_transport.validation_requests[0].payload == payload
    with journal.acquire(
        job,
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
    ) as locked:
        assert locked.entry is not None
        assert locked.entry.state is ValidationJournalState.ACKNOWLEDGED


def test_runtime_default_local_sandbox_gate_returns_not_tested_without_mutation(
    tmp_path: Path,
) -> None:
    """The Agent's independent local acknowledgement remains default-deny."""

    _, _, service = _controller(tmp_path)
    enrolled, stored_profile, compatibility = _stored_profile_and_report(service)
    _, job = _create_and_poll_validation_job(
        service,
        enrolled,
        stored_profile,
        compatibility,
    )
    enrollment = EnrollmentResponse(
        target_id=enrolled.target_id,
        agent_id=enrolled.agent_id,
        agent_credential=AGENT_CREDENTIAL,
        polling_interval_seconds=30,
    )
    state_path = tmp_path / "default-deny-runtime" / "state.json"
    adapter = _RollbackEvidenceAdapter()
    validator = SandboxValidator(
        context=AdapterContext(
            root=tmp_path / "inert-default-deny-root",
            runner=_NoCommandRunner(),  # type: ignore[arg-type]
            environment={},
            clock=lambda: NOW,
        ),
        identity_provider=_sandbox_identity,
        adapters={adapter.control_id: adapter},
    )
    transport = _ValidationRuntimeTransport(
        enrollment,
        job,
        fail_submission=False,
    )

    # Deliberately omit sandbox_validation_acknowledged.  Its production
    # default is False and Controller approval must not override this gate.
    result = AgentRuntime(
        protocol=_protocol(state_path, enrollment),
        transport=transport,
        profiler=_NoProfileCollector(),
        control_validator=LocalSandboxControlValidator(validator=validator),
        validation_journal=ValidationJournalStore.for_agent_state(state_path),
    ).run_once()

    assert adapter.execute_calls == 0
    assert result.validation_results_submitted == 1
    submitted = transport.validation_requests[0].payload.report.control_results[0]
    assert submitted.result is ValidationDecision.NOT_TESTED
    assert submitted.precheck.sandbox_operator_acknowledged is False
    assert submitted.precheck.administrator_approval_acknowledged is True
    assert submitted.remediation.attempted is False
    assert submitted.remediation.changed is False


def test_runtime_persisted_started_journal_fails_closed_without_revalidation(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    enrolled, stored_profile, compatibility = _stored_profile_and_report(service)
    _, job = _create_and_poll_validation_job(
        service,
        enrolled,
        stored_profile,
        compatibility,
    )
    payload, _ = _validation_payload(job, tmp_path / "inert-root")
    enrollment = EnrollmentResponse(
        target_id=enrolled.target_id,
        agent_id=enrolled.agent_id,
        agent_credential=AGENT_CREDENTIAL,
        polling_interval_seconds=30,
    )
    state_path = tmp_path / "interrupted-runtime" / "state.json"
    protocol = _protocol(state_path, enrollment)
    journal = ValidationJournalStore.for_agent_state(state_path)
    with journal.acquire(
        job,
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
    ) as locked:
        locked.mark_started()

    validator = _CountingValidator(payload)
    transport = _ValidationRuntimeTransport(
        enrollment,
        job,
        fail_submission=False,
    )
    with pytest.raises(
        ValidationJournalInterruptedError,
        match="previous validation stopped",
    ):
        AgentRuntime(
            protocol=protocol,
            transport=transport,
            profiler=_NoProfileCollector(),
            control_validator=validator,
            validation_journal=journal,
            sandbox_validation_acknowledged=True,
        ).run_once()

    assert validator.calls == 0
    assert transport.validation_requests == []
    with journal.acquire(
        job,
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
    ) as locked:
        assert locked.entry is not None
        assert locked.entry.state is ValidationJournalState.STARTED


def test_validation_http_routes_enforce_admin_agent_and_lineage_bindings(
    tmp_path: Path,
) -> None:
    """Exercise M6D auth and path binding at the actual JSON API boundary."""

    _, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    application = ControllerHTTPSApplication(ControllerAPI(service))
    request = _job_request(enrollment, stored_profile, compatibility)
    job_path = (
        f"/api/v1/admin/targets/{enrollment.target_id}/profiles/"
        f"{stored_profile.profile_id}/compatibility-reports/"
        f"{compatibility.compatibility_report_id}/validation-jobs"
    )
    request_body = request.model_dump_json().encode("utf-8")
    agent_bearer = enrollment.agent_credential.get_secret_value()

    assert application.dispatch("POST", job_path, request_body).status is (
        HTTPStatus.UNAUTHORIZED
    )
    assert application.dispatch(
        "POST",
        job_path,
        request_body,
        {"Authorization": f"Bearer {agent_bearer}"},
    ).status is HTTPStatus.UNAUTHORIZED
    wrong_target_path = job_path.replace(str(enrollment.target_id), str(uuid4()), 1)
    assert application.dispatch(
        "POST",
        wrong_target_path,
        request_body,
        {"Authorization": f"Bearer {ADMIN.get_secret_value()}"},
    ).status is HTTPStatus.UNAUTHORIZED

    created = application.dispatch(
        "POST",
        job_path,
        request_body,
        {"Authorization": f"Bearer {ADMIN.get_secret_value()}"},
    )
    assert created.status is HTTPStatus.CREATED
    created_job_id = UUID(json.loads(created.body)["validation_job_id"])
    polled = service.poll_jobs(JobPollRequest(auth=_auth(enrollment))).jobs
    job = next(
        item
        for item in polled
        if isinstance(item, ValidationJobRecord)
        and item.validation_job_id == created_job_id
    )
    payload, _ = _validation_payload(job, tmp_path / "transport-inert-root")
    submission = ValidationResultSubmissionRequest(
        auth=_auth(enrollment),
        payload=payload,
    )
    submission_document = submission.model_dump(mode="json")
    submission_document["auth"]["agent_credential"] = agent_bearer
    submission_body = json.dumps(submission_document).encode("utf-8")
    result_path = f"/api/v1/agents/{enrollment.agent_id}/validation-results"

    wrong_agent_path = result_path.replace(str(enrollment.agent_id), str(uuid4()), 1)
    assert application.dispatch(
        "POST",
        wrong_agent_path,
        submission_body,
    ).status is HTTPStatus.UNAUTHORIZED
    bad_auth_document = json.loads(submission_body)
    bad_auth_document["auth"]["agent_credential"] = "wrong-agent-credential"
    assert application.dispatch(
        "POST",
        result_path,
        json.dumps(bad_auth_document).encode("utf-8"),
    ).status is HTTPStatus.UNAUTHORIZED

    submitted = application.dispatch("POST", result_path, submission_body)
    assert submitted.status is HTTPStatus.OK
    submitted_document = json.loads(submitted.body)
    result_id = UUID(submitted_document["validation_result_id"])

    result_collection_path = (
        f"/api/v1/admin/targets/{enrollment.target_id}/profiles/"
        f"{stored_profile.profile_id}/compatibility-reports/"
        f"{compatibility.compatibility_report_id}/validation-results"
    )
    assert application.dispatch("GET", result_collection_path).status is (
        HTTPStatus.UNAUTHORIZED
    )
    assert application.dispatch(
        "GET",
        result_collection_path,
        headers={"Authorization": f"Bearer {agent_bearer}"},
    ).status is HTTPStatus.UNAUTHORIZED
    cross_target_collection = result_collection_path.replace(
        str(enrollment.target_id),
        str(uuid4()),
        1,
    )
    assert application.dispatch(
        "GET",
        cross_target_collection,
        headers={"Authorization": f"Bearer {ADMIN.get_secret_value()}"},
    ).status is HTTPStatus.FORBIDDEN

    listed = application.dispatch(
        "GET",
        result_collection_path,
        headers={"Authorization": f"Bearer {ADMIN.get_secret_value()}"},
    )
    retrieved = application.dispatch(
        "GET",
        f"{result_collection_path}/{result_id}",
        headers={"Authorization": f"Bearer {ADMIN.get_secret_value()}"},
    )
    assert listed.status is HTTPStatus.OK
    assert [item["validation_result_id"] for item in json.loads(listed.body)] == [
        str(result_id)
    ]
    assert retrieved.status is HTTPStatus.OK
    assert json.loads(retrieved.body) == submitted_document


def test_service_dispatches_at_most_one_validation_job_per_agent_cycle(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    pending = [
        service.create_validation_job(
            _admin(),
            _job_request(enrollment, stored_profile, compatibility),
        )
        for _ in range(3)
    ]

    first_poll = service.poll_jobs(JobPollRequest(auth=_auth(enrollment))).jobs
    validation_jobs = [
        item for item in first_poll if isinstance(item, ValidationJobRecord)
    ]

    assert len(validation_jobs) == 1
    assert validation_jobs[0].validation_job_id == min(
        (item.validation_job_id for item in pending),
        key=str,
    )

    # Until that job is completed, another cycle receives the same dispatched
    # job rather than arming a second mutating sandbox experiment.
    repeated_poll = service.poll_jobs(JobPollRequest(auth=_auth(enrollment))).jobs
    repeated_validation_jobs = [
        item for item in repeated_poll if isinstance(item, ValidationJobRecord)
    ]
    assert [item.validation_job_id for item in repeated_validation_jobs] == [
        validation_jobs[0].validation_job_id
    ]
    assert repeated_validation_jobs[0].dispatched_at == validation_jobs[0].dispatched_at


def test_repository_validation_poll_is_ordered_bounded_and_preserves_dispatch_time(
    tmp_path: Path,
) -> None:
    _, repository, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    pending = [
        service.create_validation_job(
            _admin(),
            _job_request(enrollment, stored_profile, compatibility),
        )
        for _ in range(3)
    ]
    expected_ids = sorted(
        (item.validation_job_id for item in pending),
        key=str,
    )

    dispatched = repository.poll_validation_jobs(
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
        dispatched_at=NOW,
        limit=2,
    )

    assert [item.validation_job_id for item in dispatched] == expected_ids[:2]
    assert all(item.status is JobStatus.DISPATCHED for item in dispatched)
    assert all(item.dispatched_at == NOW for item in dispatched)

    replayed = repository.poll_validation_jobs(
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
        dispatched_at=NOW + timedelta(hours=1),
        limit=2,
    )
    assert [item.validation_job_id for item in replayed] == expected_ids[:2]
    assert all(item.dispatched_at == NOW for item in replayed)

    with sqlite3.connect(repository.path) as connection:
        rows = connection.execute(
            "SELECT validation_job_id, status, assigned_agent_id, dispatched_at "
            "FROM validation_jobs ORDER BY created_at, validation_job_id"
        ).fetchall()
    assert [UUID(row[0]) for row in rows] == expected_ids
    assert [row[1] for row in rows] == [
        JobStatus.DISPATCHED.value,
        JobStatus.DISPATCHED.value,
        JobStatus.PENDING.value,
    ]
    assert rows[2][2:] == (None, None)


def test_repository_validation_poll_is_strictly_target_and_agent_isolated(
    tmp_path: Path,
) -> None:
    _, repository, service = _controller(tmp_path)
    first, stored_profile, compatibility = _stored_profile_and_report(
        service,
        hostname="validation-owner",
    )
    second = _enroll(service, "different-target")
    owned = service.create_validation_job(
        _admin(),
        _job_request(first, stored_profile, compatibility),
    )

    assert repository.poll_validation_jobs(
        target_id=second.target_id,
        agent_id=second.agent_id,
        dispatched_at=NOW,
        limit=10,
    ) == []

    with sqlite3.connect(repository.path) as connection:
        untouched = connection.execute(
            "SELECT status, assigned_agent_id, dispatched_at "
            "FROM validation_jobs WHERE validation_job_id = ?",
            (str(owned.validation_job_id),),
        ).fetchone()
    assert untouched == (JobStatus.PENDING.value, None, None)

    own_poll = repository.poll_validation_jobs(
        target_id=first.target_id,
        agent_id=first.agent_id,
        dispatched_at=NOW,
        limit=10,
    )
    assert [item.validation_job_id for item in own_poll] == [
        owned.validation_job_id
    ]


def test_malformed_validation_record_aborts_poll_without_dispatching_siblings(
    tmp_path: Path,
) -> None:
    _, repository, service = _controller(tmp_path)
    enrollment, stored_profile, compatibility = _stored_profile_and_report(service)
    pending = [
        service.create_validation_job(
            _admin(),
            _job_request(enrollment, stored_profile, compatibility),
        )
        for _ in range(2)
    ]
    ordered_ids = sorted(
        (item.validation_job_id for item in pending),
        key=str,
    )

    with sqlite3.connect(repository.path) as connection:
        connection.execute(
            "UPDATE validation_jobs SET compatibility_reference_json = ? "
            "WHERE validation_job_id = ?",
            ("{}", str(ordered_ids[1])),
        )

    with pytest.raises(StorageConflictError, match="compatibility reference"):
        repository.poll_validation_jobs(
            target_id=enrollment.target_id,
            agent_id=enrollment.agent_id,
            dispatched_at=NOW,
            limit=2,
        )

    with sqlite3.connect(repository.path) as connection:
        rows = connection.execute(
            "SELECT validation_job_id, status, assigned_agent_id, dispatched_at "
            "FROM validation_jobs ORDER BY created_at, validation_job_id"
        ).fetchall()
    assert [UUID(row[0]) for row in rows] == ordered_ids
    assert all(
        row[1:] == (JobStatus.PENDING.value, None, None)
        for row in rows
    )



# M6D_SECURITY_HARDENING_REGRESSIONS


def test_validation_journal_trusted_ancestor_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import stat
    from types import SimpleNamespace

    import src.agent.validation_journal as validation_journal_module

    safe_user = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700,
        st_uid=1000,
    )

    monkeypatch.setattr(
        validation_journal_module.os,
        "geteuid",
        lambda: 1000,
    )

    ValidationJournalStore._validate_trusted_ancestor(
        Path("/safe-user"),
        safe_user,
    )

    safe_root = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o755,
        st_uid=0,
    )

    monkeypatch.setattr(
        validation_journal_module.os,
        "geteuid",
        lambda: 0,
    )

    ValidationJournalStore._validate_trusted_ancestor(
        Path("/var/lib"),
        safe_root,
    )


def test_validation_journal_root_rejects_user_owned_ancestor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import stat
    from types import SimpleNamespace

    import src.agent.validation_journal as validation_journal_module

    user_owned = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700,
        st_uid=1000,
    )

    monkeypatch.setattr(
        validation_journal_module.os,
        "geteuid",
        lambda: 0,
    )

    with pytest.raises(
        ValidationJournalError,
        match="root-owned ancestors",
    ):
        ValidationJournalStore._validate_trusted_ancestor(
            Path("/home/user"),
            user_owned,
        )


def test_validation_journal_rejects_writable_and_symlink_ancestors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import stat
    from types import SimpleNamespace

    import src.agent.validation_journal as validation_journal_module

    monkeypatch.setattr(
        validation_journal_module.os,
        "geteuid",
        lambda: 1000,
    )

    writable = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o777,
        st_uid=1000,
    )

    with pytest.raises(
        ValidationJournalError,
        match="writable by group or others",
    ):
        ValidationJournalStore._validate_trusted_ancestor(
            Path("/unsafe"),
            writable,
        )

    symlink = SimpleNamespace(
        st_mode=stat.S_IFLNK | 0o777,
        st_uid=1000,
    )

    with pytest.raises(
        ValidationJournalError,
        match="real directories",
    ):
        ValidationJournalStore._validate_trusted_ancestor(
            Path("/linked"),
            symlink,
        )


def test_validation_journal_rechecks_parent_security_between_cycles(
    tmp_path: Path,
) -> None:
    import os

    if os.geteuid() == 0:
        pytest.skip("normal-user replay test")

    parent = tmp_path / "agent-state"
    parent.mkdir(mode=0o700)

    store = ValidationJournalStore.for_agent_state(
        parent / "state.json"
    )

    store._ensure_directory()

    parent.chmod(0o777)

    try:
        with pytest.raises(
            ValidationJournalError,
            match="writable by group or others",
        ):
            store._ensure_directory()
    finally:
        parent.chmod(0o700)


@pytest.mark.parametrize(
    "stored_request_id",
    [
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
        "{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}",
    ],
)
def test_validation_job_create_rejects_noncanonical_stored_request_id(
    tmp_path: Path,
    stored_request_id: str,
) -> None:
    import sqlite3
    from uuid import UUID

    database, _, service = _controller(tmp_path)

    enrollment, stored_profile, compatibility = (
        _stored_profile_and_report(service)
    )

    request_id = UUID(
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    )

    request = _job_request(
        enrollment,
        stored_profile,
        compatibility,
        request_id=request_id,
    )

    first = service.create_validation_job(
        _admin(),
        request,
    )

    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            UPDATE validation_jobs
            SET request_id = ?
            WHERE validation_job_id = ?
            """,
            (
                stored_request_id,
                str(first.validation_job_id),
            ),
        )

    with pytest.raises(
        ControllerConflictError,
        match="validation job conflicts with Controller state",
    ):
        service.create_validation_job(
            _admin(),
            request,
        )

    with sqlite3.connect(database) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM validation_jobs"
        ).fetchone()[0]

    assert count == 1


def test_validation_job_changed_authorization_replay_conflicts(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)

    enrollment, stored_profile, compatibility = (
        _stored_profile_and_report(service)
    )

    request_id = uuid4()

    request = _job_request(
        enrollment,
        stored_profile,
        compatibility,
        request_id=request_id,
    )

    service.create_validation_job(
        _admin(),
        request,
    )

    changed = request.model_dump(mode="python")
    changed["compatibility_override_reason"] = (
        "changed replay authorization"
    )

    changed_request = (
        ValidationJobCreateRequest.model_validate(changed)
    )

    with pytest.raises(
        ControllerConflictError,
        match="validation job conflicts with Controller state",
    ):
        service.create_validation_job(
            _admin(),
            changed_request,
        )

    with sqlite3.connect(database) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM validation_jobs"
        ).fetchone()[0]

    assert count == 1
