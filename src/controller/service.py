"""Authenticated SENTRA Controller operations.

The service remains transport-independent and exposes no target-side shell, SSH,
generic command, or production-target deployment capability.  M6D authorization is
limited to a fixed existing M5 sandbox-validation adapter.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Callable
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
)

from src.compatibility_engine.models import CompatibilityReport
from src.controller.compatibility import (
    CompatibilityAnalyzer,
    ExistingM4CompatibilityAnalyzer,
)
from src.controller.models import (
    AdminAuth,
    AgentAuth,
    CompatibilityAnalysisRequest,
    CompatibilityReportRecord,
    EnrollmentRequest,
    EnrollmentResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    JobCreateRequest,
    JobPollRequest,
    JobPollResponse,
    JobRecord,
    JobStatus,
    JobType,
    MetadataChangeRecord,
    ProfileRecord,
    ProfileSubmissionRequest,
    SandboxProviderType,
    SandboxSessionCreateRequest,
    SandboxSessionRecord,
    SandboxSessionStatus,
    TargetRecord,
    ValidationJobCreateRequest,
    ValidationJobRecord,
    ValidationResultRecord,
    ValidationResultSubmissionRequest,
)
from src.controller.security import (
    CredentialHash,
    generate_credential,
    hash_credential,
    verify_credential,
)
from src.controller.storage import (
    ControllerRepository,
    StorageConflictError,
    StorageNotFoundError,
)
from src.controller.validation import (
    canonical_validation_payload_json,
    compatibility_reference_from_record,
    require_payload_matches_job,
)


CURRENT_BENCHMARK_IDENTITY = (
    "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0"
)
CURRENT_BENCHMARK_VERSION = "v1.0.0"


class ControllerError(RuntimeError):
    """Base class for safe controller failures."""


class AuthenticationError(ControllerError):
    """A supplied bootstrap, agent, or administrator credential was invalid."""


class AuthorizationError(ControllerError):
    """An authenticated identity is not bound to the requested object."""


class ControllerNotFoundError(ControllerError):
    """A requested target, job, or profile was not found."""


class ControllerConflictError(ControllerError):
    """A request conflicts with immutable identity or evidence lineage."""


class ControllerSettings(BaseModel):
    """Secrets and bounded polling settings supplied by the operator."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
    )

    bootstrap_credential: SecretStr
    admin_credential: SecretStr
    polling_interval_seconds: int = Field(default=30, ge=5, le=3600)
    max_jobs_per_poll: int = Field(default=10, ge=1, le=100)

    @field_validator("bootstrap_credential", "admin_credential")
    @classmethod
    def reject_blank_credentials(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("controller credentials must not be blank")
        return value


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_profile_json(request: ProfileSubmissionRequest) -> str:
    """Canonicalize only the validated M3 profile payload for authoritative hashing."""

    return json.dumps(
        request.profile.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_compatibility_report_json(report: CompatibilityReport) -> str:
    """Canonicalize the validated M4 payload used for storage and hashing."""

    return json.dumps(
        report.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_sandbox_reference_json(reference: BaseModel) -> str:
    """Canonicalize the validated M4 reference sealed into an M6E-A session."""

    return json.dumps(
        reference.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


class ControllerService:
    """Controller-issued identity, job, and evidence-lineage operations."""

    def __init__(
        self,
        repository: ControllerRepository,
        settings: ControllerSettings,
        *,
        clock: Callable[[], datetime] = _utcnow,
        id_factory: Callable[[], UUID] = uuid4,
        credential_factory: Callable[[], SecretStr] = generate_credential,
        compatibility_analyzer: CompatibilityAnalyzer | None = None,
    ) -> None:
        self._repository = repository
        self._settings = settings
        self._clock = clock
        self._id_factory = id_factory
        self._credential_factory = credential_factory
        self._compatibility_analyzer = (
            ExistingM4CompatibilityAnalyzer()
            if compatibility_analyzer is None
            else compatibility_analyzer
        )
        self._bootstrap_hash = hash_credential(settings.bootstrap_credential)
        self._admin_hash = hash_credential(settings.admin_credential)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.utcoffset() is None:
            raise ControllerConflictError(
                "controller clock must return a timezone-aware datetime"
            )
        return value

    def _new_id(self) -> UUID:
        value = self._id_factory()
        if not isinstance(value, UUID):
            raise ControllerConflictError("controller ID generator returned an invalid ID")
        return value

    @staticmethod
    def _storage_hash(value: CredentialHash) -> str:
        return value.to_storage()

    def _authenticate_agent(self, auth: AgentAuth):
        stored = self._repository.get_agent(auth.agent_id)
        if stored is None:
            raise AuthenticationError("invalid agent identity or credential")
        if stored.target_id != auth.target_id:
            raise AuthenticationError("invalid agent identity or credential")
        verifier = CredentialHash.from_storage(stored.credential_hash)
        if not verify_credential(auth.agent_credential, verifier):
            raise AuthenticationError("invalid agent identity or credential")
        return stored

    def _authenticate_admin(self, auth: AdminAuth) -> None:
        if not verify_credential(auth.admin_credential, self._admin_hash):
            raise AuthenticationError("invalid administrator credential")

    def enroll(self, request: EnrollmentRequest) -> EnrollmentResponse:
        """Exchange a bootstrap credential for controller-issued identities."""

        if not verify_credential(request.bootstrap_credential, self._bootstrap_hash):
            raise AuthenticationError("invalid enrollment credential")
        target_id = self._new_id()
        agent_id = self._new_id()
        agent_credential = self._credential_factory()
        created_at = self._now()
        response = EnrollmentResponse(
            target_id=target_id,
            agent_id=agent_id,
            agent_credential=agent_credential,
            polling_interval_seconds=self._settings.polling_interval_seconds,
        )
        try:
            self._repository.enroll(
                target_id=target_id,
                agent_id=agent_id,
                installation_id=request.installation_id,
                credential_hash=self._storage_hash(
                    hash_credential(agent_credential)
                ),
                agent_version=request.agent_version,
                metadata=request.observed_metadata,
                created_at=created_at,
            )
        except StorageConflictError as error:
            raise ControllerConflictError(
                "installation identity is already enrolled"
            ) from error
        return response

    def heartbeat(self, request: HeartbeatRequest) -> HeartbeatResponse:
        """Authenticate one agent-target binding and update its observed state."""

        self._authenticate_agent(request.auth)
        received_at = self._now()
        response = HeartbeatResponse(accepted=True, last_seen=received_at)
        try:
            self._repository.record_heartbeat(
                target_id=request.auth.target_id,
                agent_id=request.auth.agent_id,
                seen_at=received_at,
                agent_version=request.agent_version,
                metadata=request.observed_metadata,
                change_id=self._new_id(),
            )
        except StorageNotFoundError as error:
            raise AuthenticationError("invalid agent identity or credential") from error
        except StorageConflictError as error:
            raise ControllerConflictError("heartbeat conflicts with controller state") from error
        return response

    def list_targets(self, auth: AdminAuth) -> list[TargetRecord]:
        self._authenticate_admin(auth)
        return self._repository.list_targets()

    def list_metadata_changes(
        self, auth: AdminAuth, target_id: UUID
    ) -> list[MetadataChangeRecord]:
        self._authenticate_admin(auth)
        if self._repository.get_target(target_id) is None:
            raise ControllerNotFoundError("target does not exist")
        return self._repository.list_metadata_changes(target_id)

    def create_job(self, auth: AdminAuth, request: JobCreateRequest) -> JobRecord:
        """Create the sole M6A operational job type for a registered target."""

        self._authenticate_admin(auth)
        if request.job_type is not JobType.PROFILE_TARGET:
            raise ControllerConflictError("unsupported job type")
        if self._repository.get_target(request.target_id) is None:
            raise ControllerNotFoundError("target does not exist")
        job = JobRecord(
            job_id=self._new_id(),
            target_id=request.target_id,
            job_type=JobType.PROFILE_TARGET,
            status=JobStatus.PENDING,
            created_at=self._now(),
            dispatched_at=None,
            completed_at=None,
        )
        try:
            return self._repository.create_job(job)
        except StorageConflictError as error:
            raise ControllerConflictError("job could not be created") from error

    def poll_jobs(self, request: JobPollRequest) -> JobPollResponse:
        self._authenticate_agent(request.auth)
        try:
            dispatched_at = self._now()
            profile_jobs = self._repository.poll_jobs(
                target_id=request.auth.target_id,
                agent_id=request.auth.agent_id,
                dispatched_at=dispatched_at,
                limit=self._settings.max_jobs_per_poll,
            )
            remaining = self._settings.max_jobs_per_poll - len(profile_jobs)
            validation_jobs = (
                self._repository.poll_validation_jobs(
                    target_id=request.auth.target_id,
                    agent_id=request.auth.agent_id,
                    dispatched_at=dispatched_at,
                    # A single Agent cycle may arm at most one mutating M5
                    # experiment.  PROFILE_TARGET work can still consume the
                    # rest of the configured poll capacity.
                    limit=min(remaining, 1),
                )
                if remaining > 0
                else []
            )
        except StorageNotFoundError as error:
            raise AuthenticationError("invalid agent identity or credential") from error
        except StorageConflictError as error:
            raise ControllerConflictError("job dispatch conflicts with controller state") from error
        return JobPollResponse(jobs=[*profile_jobs, *validation_jobs])

    def submit_profile(self, request: ProfileSubmissionRequest) -> ProfileRecord:
        """Validate and store an M3 profile with a controller-computed hash."""

        self._authenticate_agent(request.auth)
        stored_job = self._repository.get_job(request.job_id)
        if stored_job is None:
            raise ControllerNotFoundError("profile job does not exist")
        if (
            stored_job.job.target_id != request.auth.target_id
            or stored_job.assigned_agent_id != request.auth.agent_id
            or stored_job.job.job_type is not JobType.PROFILE_TARGET
        ):
            raise AuthorizationError("profile job is not assigned to this agent")
        if stored_job.job.status is not JobStatus.DISPATCHED:
            raise ControllerConflictError("profile job is not awaiting a result")

        payload_json = _canonical_profile_json(request)
        profile_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        record = ProfileRecord(
            profile_id=self._new_id(),
            target_id=request.auth.target_id,
            agent_id=request.auth.agent_id,
            job_id=request.job_id,
            collected_at=request.profile.collected_at,
            received_at=self._now(),
            profile_sha256=profile_hash,
            profiler_version=request.profiler_version,
            sentra_version=request.sentra_version,
        )
        try:
            return self._repository.store_profile(record, payload_json)
        except StorageNotFoundError as error:
            raise ControllerNotFoundError("profile job does not exist") from error
        except StorageConflictError as error:
            raise ControllerConflictError(
                "profile lineage conflicts with the dispatched job"
            ) from error

    def run_compatibility_analysis(
        self,
        auth: AdminAuth,
        request: CompatibilityAnalysisRequest,
    ) -> CompatibilityReportRecord:
        """Run existing M4 logic for one validated, Controller-stored profile."""

        self._authenticate_admin(auth)
        try:
            stored_profile = self._repository.get_stored_profile(request.profile_id)
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored profile evidence could not be validated"
            ) from error
        if stored_profile is None:
            raise ControllerNotFoundError("profile does not exist")
        if stored_profile.record.target_id != request.target_id:
            raise AuthorizationError("profile does not belong to the target")

        generated_at = self._now()
        if generated_at < stored_profile.record.received_at:
            raise ControllerConflictError(
                "compatibility analysis time precedes stored profile receipt"
            )
        try:
            analysis = self._compatibility_analyzer.analyze(
                profile=stored_profile.profile,
                profile_id=request.profile_id,
                generated_at=generated_at,
            )
            report = CompatibilityReport.model_validate(
                analysis.report.model_dump(mode="json")
            )
        except (OSError, ValueError) as error:
            raise ControllerConflictError(
                "stored profile is not eligible for compatibility analysis"
            ) from error

        expected_source = f"controller-stored-profile:{request.profile_id}"
        if (
            analysis.benchmark_identity != CURRENT_BENCHMARK_IDENTITY
            or analysis.benchmark_version != CURRENT_BENCHMARK_VERSION
            or report.generated_at != generated_at
            or report.profile_source != expected_source
            or report.profile_collected_at != stored_profile.record.collected_at
            or report.target != stored_profile.profile.target
        ):
            raise ControllerConflictError(
                "compatibility analysis metadata conflicts with profile lineage"
            )

        payload_json = _canonical_compatibility_report_json(report)
        report_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        record = CompatibilityReportRecord(
            compatibility_report_id=self._new_id(),
            target_id=request.target_id,
            profile_id=request.profile_id,
            benchmark_identity=analysis.benchmark_identity,
            benchmark_version=analysis.benchmark_version,
            generated_at=generated_at,
            report_version=report.report_version,
            report_sha256=report_sha256,
            report=report,
        )
        try:
            return self._repository.store_compatibility_report(
                record,
                payload_json,
            )
        except StorageNotFoundError as error:
            raise ControllerNotFoundError("profile does not exist") from error
        except StorageConflictError as error:
            raise ControllerConflictError(
                "compatibility report lineage could not be stored"
            ) from error

    def list_compatibility_reports(
        self,
        auth: AdminAuth,
        *,
        target_id: UUID,
        profile_id: UUID,
    ) -> list[CompatibilityReportRecord]:
        """List immutable M6C reports for one target-owned profile."""

        self._authenticate_admin(auth)
        self._require_profile_target(target_id=target_id, profile_id=profile_id)
        try:
            return self._repository.list_compatibility_reports(
                target_id=target_id,
                profile_id=profile_id,
            )
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored compatibility report could not be validated"
            ) from error

    def get_compatibility_report(
        self,
        auth: AdminAuth,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
    ) -> CompatibilityReportRecord:
        """Retrieve one immutable M6C report through its full lineage."""

        self._authenticate_admin(auth)
        self._require_profile_target(target_id=target_id, profile_id=profile_id)
        try:
            report = self._repository.get_compatibility_report(
                target_id=target_id,
                profile_id=profile_id,
                compatibility_report_id=compatibility_report_id,
            )
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored compatibility report could not be validated"
            ) from error
        if report is None:
            raise ControllerNotFoundError("compatibility report does not exist")
        return report

    def create_sandbox_session(
        self,
        auth: AdminAuth,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        request: SandboxSessionCreateRequest,
    ) -> SandboxSessionRecord:
        """Record one inert, administrator-authorized M6E-A lifecycle.

        This operation does not create a VM or dispatch validation.  The M4
        control reference is derived from Controller-stored evidence rather
        than accepted from the caller.
        """

        self._authenticate_admin(auth)
        report = self._require_compatibility_lineage(
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
        )
        try:
            reference = compatibility_reference_from_record(
                report,
                request.control_id,
            )
        except ValueError as error:
            raise ControllerConflictError(
                "compatibility report does not authorize this control"
            ) from error
        reference_json = _canonical_sandbox_reference_json(reference)
        session = SandboxSessionRecord(
            sandbox_session_id=self._new_id(),
            request_id=request.request_id,
            source_target_id=target_id,
            source_profile_id=profile_id,
            source_compatibility_report_id=compatibility_report_id,
            control_id=request.control_id,
            provider_type=SandboxProviderType.LOCAL_NESTED_VM,
            status=SandboxSessionStatus.REQUESTED,
            sandbox_instance_id=None,
            administrator_sandbox_authorization_acknowledged=(
                request.administrator_sandbox_authorization_acknowledged
            ),
            compatibility_reference=reference,
            compatibility_reference_sha256=hashlib.sha256(
                reference_json.encode("utf-8")
            ).hexdigest(),
            created_at=self._now(),
        )
        try:
            return self._repository.create_sandbox_session(session)
        except StorageNotFoundError as error:
            raise ControllerNotFoundError(
                "sandbox session lineage does not exist"
            ) from error
        except StorageConflictError as error:
            raise ControllerConflictError(
                "sandbox session conflicts with Controller state"
            ) from error

    def list_sandbox_sessions(
        self,
        auth: AdminAuth,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
    ) -> list[SandboxSessionRecord]:
        """List sessions only through their complete M3/M4 source lineage."""

        self._authenticate_admin(auth)
        self._require_compatibility_lineage(
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
        )
        try:
            return self._repository.list_sandbox_sessions(
                target_id=target_id,
                profile_id=profile_id,
                compatibility_report_id=compatibility_report_id,
            )
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored sandbox session could not be validated"
            ) from error

    def get_sandbox_session(
        self,
        auth: AdminAuth,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord:
        """Retrieve one session only through its complete source lineage."""

        self._authenticate_admin(auth)
        self._require_compatibility_lineage(
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
        )
        try:
            session = self._repository.get_sandbox_session(
                target_id=target_id,
                profile_id=profile_id,
                compatibility_report_id=compatibility_report_id,
                sandbox_session_id=sandbox_session_id,
            )
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored sandbox session could not be validated"
            ) from error
        if session is None:
            raise ControllerNotFoundError("sandbox session does not exist")
        return session

    def _get_internal_sandbox_session(
        self,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord:
        try:
            session = self._repository.get_sandbox_session_by_id(
                sandbox_session_id
            )
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored sandbox session could not be validated"
            ) from error
        if session is None:
            raise ControllerNotFoundError("sandbox session does not exist")
        return session

    @staticmethod
    def _updated_sandbox_session(
        session: SandboxSessionRecord,
        **changes: object,
    ) -> SandboxSessionRecord:
        values = session.model_dump(mode="python")
        values.update(changes)
        try:
            return SandboxSessionRecord.model_validate(values)
        except ValidationError as error:
            raise ControllerConflictError(
                "sandbox lifecycle transition is not allowed"
            ) from error

    def _store_sandbox_transition(
        self,
        *,
        updated: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        try:
            transitions = {
                SandboxSessionStatus.PROVISIONING: (
                    self._repository.mark_provisioning
                ),
                SandboxSessionStatus.READY: self._repository.mark_ready,
                SandboxSessionStatus.VALIDATING: (
                    self._repository.mark_validating
                ),
                SandboxSessionStatus.COMPLETED: (
                    self._repository.mark_completed
                ),
                SandboxSessionStatus.FAILED: self._repository.mark_failed,
                SandboxSessionStatus.QUARANTINED: (
                    self._repository.mark_quarantined
                ),
                SandboxSessionStatus.CLOSED: self._repository.close_session,
            }
            transition = transitions.get(updated.status)
            if transition is None:
                raise StorageConflictError(
                    "sandbox lifecycle transition is not allowed"
                )
            return transition(updated)
        except StorageNotFoundError as error:
            raise ControllerNotFoundError(
                "sandbox session does not exist"
            ) from error
        except StorageConflictError as error:
            raise ControllerConflictError(
                "sandbox lifecycle transition conflicts with Controller state"
            ) from error

    def mark_provisioning(
        self,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord:
        """Internal provider boundary: REQUESTED -> PROVISIONING."""

        previous = self._get_internal_sandbox_session(sandbox_session_id)
        updated = self._updated_sandbox_session(
            previous,
            status=SandboxSessionStatus.PROVISIONING,
            provisioning_started_at=self._now(),
        )
        return self._store_sandbox_transition(updated=updated)

    def mark_ready(
        self,
        sandbox_session_id: UUID,
        *,
        sandbox_instance_id: str,
    ) -> SandboxSessionRecord:
        """Internal provider boundary: PROVISIONING -> READY."""

        previous = self._get_internal_sandbox_session(sandbox_session_id)
        updated = self._updated_sandbox_session(
            previous,
            status=SandboxSessionStatus.READY,
            sandbox_instance_id=sandbox_instance_id,
            ready_at=self._now(),
        )
        return self._store_sandbox_transition(updated=updated)

    def mark_validating(
        self,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord:
        """Internal orchestrator boundary: READY -> VALIDATING."""

        previous = self._get_internal_sandbox_session(sandbox_session_id)
        updated = self._updated_sandbox_session(
            previous,
            status=SandboxSessionStatus.VALIDATING,
            validation_started_at=self._now(),
        )
        return self._store_sandbox_transition(updated=updated)

    def mark_completed(
        self,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord:
        """Internal orchestrator boundary: VALIDATING -> COMPLETED."""

        previous = self._get_internal_sandbox_session(sandbox_session_id)
        updated = self._updated_sandbox_session(
            previous,
            status=SandboxSessionStatus.COMPLETED,
            completed_at=self._now(),
        )
        return self._store_sandbox_transition(updated=updated)

    def mark_failed(
        self,
        sandbox_session_id: UUID,
        *,
        failure_reason: str,
    ) -> SandboxSessionRecord:
        """Internal failure boundary from provisioning, ready, or validating."""

        previous = self._get_internal_sandbox_session(sandbox_session_id)
        updated = self._updated_sandbox_session(
            previous,
            status=SandboxSessionStatus.FAILED,
            completed_at=self._now(),
            failure_reason=failure_reason,
        )
        return self._store_sandbox_transition(updated=updated)

    def mark_provisioning_failed(
        self,
        sandbox_session_id: UUID,
        *,
        failure_reason: str,
    ) -> SandboxSessionRecord:
        """M6E-B race-safe failure from PROVISIONING only."""

        previous = self._get_internal_sandbox_session(sandbox_session_id)
        updated = self._updated_sandbox_session(
            previous,
            status=SandboxSessionStatus.FAILED,
            completed_at=self._now(),
            failure_reason=failure_reason,
        )
        try:
            return self._repository.mark_provisioning_failed(updated)
        except StorageNotFoundError as error:
            raise ControllerNotFoundError(
                "sandbox session does not exist"
            ) from error
        except StorageConflictError as error:
            raise ControllerConflictError(
                "sandbox provisioning failure conflicts with Controller state"
            ) from error

    def mark_quarantined(
        self,
        sandbox_session_id: UUID,
        *,
        quarantine_reason: str,
    ) -> SandboxSessionRecord:
        """Internal isolation boundary: VALIDATING -> QUARANTINED."""

        previous = self._get_internal_sandbox_session(sandbox_session_id)
        updated = self._updated_sandbox_session(
            previous,
            status=SandboxSessionStatus.QUARANTINED,
            completed_at=self._now(),
            quarantine_reason=quarantine_reason,
        )
        return self._store_sandbox_transition(updated=updated)

    def close_session(
        self,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord:
        """Internal cleanup boundary for a terminal, non-closed session."""

        previous = self._get_internal_sandbox_session(sandbox_session_id)
        updated = self._updated_sandbox_session(
            previous,
            status=SandboxSessionStatus.CLOSED,
            closed_at=self._now(),
        )
        return self._store_sandbox_transition(updated=updated)

    def create_validation_job(
        self,
        auth: AdminAuth,
        request: ValidationJobCreateRequest,
    ) -> ValidationJobRecord:
        """Authorize one fixed 7.1.1 M5 experiment for one stored M6C report."""

        self._authenticate_admin(auth)
        self._require_profile_target(
            target_id=request.target_id,
            profile_id=request.profile_id,
        )
        try:
            report = self._repository.get_compatibility_report(
                target_id=request.target_id,
                profile_id=request.profile_id,
                compatibility_report_id=request.compatibility_report_id,
            )
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored compatibility report could not be validated"
            ) from error
        if report is None:
            raise ControllerNotFoundError("compatibility report does not exist")
        try:
            reference = compatibility_reference_from_record(
                report,
                request.control_id,
            )
            job = ValidationJobRecord(
                validation_job_id=self._new_id(),
                request_id=request.request_id,
                target_id=request.target_id,
                profile_id=request.profile_id,
                compatibility_report_id=request.compatibility_report_id,
                control_id=request.control_id,
                validation_mode=request.validation_mode,
                execution_mode=request.execution_mode,
                administrator_approval_acknowledged=(
                    request.administrator_approval_acknowledged
                ),
                compatibility_risk_acknowledged=(
                    request.compatibility_risk_acknowledged
                ),
                compatibility_override_reason=(
                    request.compatibility_override_reason
                ),
                compatibility_reference=reference,
                status=JobStatus.PENDING,
                created_at=self._now(),
            )
        except ValueError as error:
            raise ControllerConflictError(
                "compatibility evidence does not authorize the requested validation"
            ) from error
        try:
            return self._repository.create_validation_job(job)
        except StorageNotFoundError as error:
            raise ControllerNotFoundError(
                "validation job lineage does not exist"
            ) from error
        except StorageConflictError as error:
            raise ControllerConflictError(
                "validation job conflicts with Controller state"
            ) from error

    def submit_validation_result(
        self,
        request: ValidationResultSubmissionRequest,
    ) -> ValidationResultRecord:
        """Validate, hash, and persist one fixed-adapter M5 result."""

        self._authenticate_agent(request.auth)
        try:
            stored_job = self._repository.get_validation_job(
                request.payload.validation_job_id
            )
        except (StorageConflictError, StorageNotFoundError) as error:
            raise ControllerConflictError(
                "stored validation job could not be validated"
            ) from error
        if stored_job is None:
            raise ControllerNotFoundError("validation job does not exist")
        job = stored_job.job
        if (
            job.target_id != request.auth.target_id
            or stored_job.assigned_agent_id != request.auth.agent_id
        ):
            raise AuthorizationError(
                "validation job is not assigned to this agent"
            )
        if job.status not in {JobStatus.DISPATCHED, JobStatus.COMPLETED}:
            raise ControllerConflictError(
                "validation job is not awaiting or retaining a result"
            )
        try:
            require_payload_matches_job(request.payload, job)
            payload_json = canonical_validation_payload_json(request.payload)
        except ValueError as error:
            raise ControllerConflictError(
                "validation evidence conflicts with the authorized job"
            ) from error
        if job.dispatched_at is None:
            raise ControllerConflictError("validation job has no dispatch time")
        completed_at = self._now()
        if (
            request.payload.report.generated_at < job.dispatched_at
            or completed_at < request.payload.report.generated_at
        ):
            raise ControllerConflictError(
                "validation evidence timeline conflicts with job dispatch"
            )
        result_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        record = ValidationResultRecord(
            validation_result_id=self._new_id(),
            agent_id=request.auth.agent_id,
            created_at=job.created_at,
            dispatched_at=job.dispatched_at,
            completed_at=completed_at,
            result_sha256=result_sha256,
            payload=request.payload,
        )
        try:
            return self._repository.store_validation_result(record, payload_json)
        except StorageNotFoundError as error:
            raise ControllerNotFoundError("validation job does not exist") from error
        except StorageConflictError as error:
            raise ControllerConflictError(
                "validation result conflicts with Controller state"
            ) from error

    def list_validation_results(
        self,
        auth: AdminAuth,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
    ) -> list[ValidationResultRecord]:
        self._authenticate_admin(auth)
        self._require_compatibility_lineage(
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
        )
        try:
            return self._repository.list_validation_results(
                target_id=target_id,
                profile_id=profile_id,
                compatibility_report_id=compatibility_report_id,
            )
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored validation result could not be validated"
            ) from error

    def get_validation_result(
        self,
        auth: AdminAuth,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        validation_result_id: UUID,
    ) -> ValidationResultRecord:
        self._authenticate_admin(auth)
        self._require_compatibility_lineage(
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
        )
        try:
            result = self._repository.get_validation_result(
                target_id=target_id,
                profile_id=profile_id,
                compatibility_report_id=compatibility_report_id,
                validation_result_id=validation_result_id,
            )
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored validation result could not be validated"
            ) from error
        if result is None:
            raise ControllerNotFoundError("validation result does not exist")
        return result

    def _require_compatibility_lineage(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
    ) -> CompatibilityReportRecord:
        self._require_profile_target(target_id=target_id, profile_id=profile_id)
        try:
            report = self._repository.get_compatibility_report(
                target_id=target_id,
                profile_id=profile_id,
                compatibility_report_id=compatibility_report_id,
            )
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored compatibility report could not be validated"
            ) from error
        if report is None:
            raise ControllerNotFoundError("compatibility report does not exist")
        return report

    def _require_profile_target(self, *, target_id: UUID, profile_id: UUID) -> None:
        try:
            profile = self._repository.get_profile(profile_id)
        except StorageConflictError as error:
            raise ControllerConflictError(
                "stored profile evidence could not be validated"
            ) from error
        if profile is None:
            raise ControllerNotFoundError("profile does not exist")
        if profile.target_id != target_id:
            raise AuthorizationError("profile does not belong to the target")
