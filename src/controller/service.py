"""Authenticated M6A controller operations.

This service is transport-independent.  A later HTTPS adapter can expose the same
operations without giving the controller a target-side shell or SSH capability.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Callable
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from src.controller.models import (
    AdminAuth,
    AgentAuth,
    CompatibilityLineageRecord,
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
    TargetRecord,
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


CURRENT_BENCHMARK_IDENTITY = "CIS Ubuntu Linux 24.04 LTS Benchmark"
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
    ) -> None:
        self._repository = repository
        self._settings = settings
        self._clock = clock
        self._id_factory = id_factory
        self._credential_factory = credential_factory
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
            jobs = self._repository.poll_jobs(
                target_id=request.auth.target_id,
                agent_id=request.auth.agent_id,
                dispatched_at=self._now(),
                limit=self._settings.max_jobs_per_poll,
            )
        except StorageNotFoundError as error:
            raise AuthenticationError("invalid agent identity or credential") from error
        except StorageConflictError as error:
            raise ControllerConflictError("job dispatch conflicts with controller state") from error
        return JobPollResponse(jobs=jobs)

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

    def record_compatibility_lineage(
        self,
        auth: AdminAuth,
        *,
        target_id: UUID,
        profile_id: UUID,
        generated_at: datetime,
        report_sha256: str,
        benchmark_identity: str = CURRENT_BENCHMARK_IDENTITY,
        benchmark_version: str = CURRENT_BENCHMARK_VERSION,
    ) -> CompatibilityLineageRecord:
        """Future M4 integration boundary; it does not run the M4 engine."""

        self._authenticate_admin(auth)
        profile = self._repository.get_profile(profile_id)
        if profile is None:
            raise ControllerNotFoundError("profile does not exist")
        if profile.target_id != target_id:
            raise AuthorizationError("profile does not belong to the target")
        record = CompatibilityLineageRecord(
            compatibility_report_id=self._new_id(),
            target_id=target_id,
            profile_id=profile_id,
            benchmark_identity=benchmark_identity,
            benchmark_version=benchmark_version,
            generated_at=generated_at,
            report_sha256=report_sha256,
        )
        try:
            return self._repository.store_compatibility_lineage(record)
        except (StorageNotFoundError, StorageConflictError) as error:
            raise ControllerConflictError(
                "compatibility lineage could not be stored"
            ) from error
