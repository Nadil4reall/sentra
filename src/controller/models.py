"""Strict protocol and lineage models for the SENTRA M6 controller.

Observed host details are deliberately kept separate from controller-issued
``target_id`` and ``agent_id`` values.  In particular, neither a hostname nor
the optional hashed machine-identity evidence is an authoritative SENTRA
identity.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, TypeAlias
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from src.compatibility_engine.models import CompatibilityReport
from src.sandbox_validator.models import (
    CompatibilityReference,
    ExecutionMode,
    ValidationReport,
)
from src.target_profiler.models import TargetProfile


def _reject_blank_string(value: str) -> str:
    if not value.strip():
        raise ValueError("value must not be blank")
    return value


def _reject_blank_secret(value: SecretStr) -> SecretStr:
    if not value.get_secret_value().strip():
        raise ValueError("credential must not be blank")
    return value


NonEmptyString = Annotated[
    str,
    Field(min_length=1),
    AfterValidator(_reject_blank_string),
]
NonEmptySecret = Annotated[SecretStr, AfterValidator(_reject_blank_secret)]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class StrictControllerModel(BaseModel):
    """Base for protocol models with coercion and undocumented fields disabled."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        hide_input_in_errors=True,
    )


class ObservedTargetMetadata(StrictControllerModel):
    """Non-authoritative host attributes observed by an agent.

    ``machine_identity_hash`` may be supplied as correlation evidence, but it
    must never replace the opaque controller-issued target identity.  Raw
    machine IDs are not part of this protocol.
    """

    hostname: NonEmptyString
    os: NonEmptyString
    os_version: NonEmptyString
    kernel: NonEmptyString
    architecture: NonEmptyString
    machine_identity_hash: Sha256Hex | None = Field(
        default=None,
        description=(
            "Optional non-authoritative SHA-256 evidence; never a target ID"
        ),
    )

class JobType(StrEnum):
    """Closed SENTRA operational job vocabulary."""

    PROFILE_TARGET = "PROFILE_TARGET"
    VALIDATE_CONTROL = "VALIDATE_CONTROL"


class JobStatus(StrEnum):
    PENDING = "pending"
    DISPATCHED = "dispatched"
    COMPLETED = "completed"


class TargetStatus(StrEnum):
    ENROLLED = "enrolled"
    ONLINE = "online"


class ValidationMode(StrEnum):
    """M6D can orchestrate validation only inside an acknowledged sandbox."""

    SANDBOX = "sandbox"


class EnrollmentRequest(StrictControllerModel):
    bootstrap_credential: NonEmptySecret
    installation_id: UUID
    agent_version: NonEmptyString
    observed_metadata: ObservedTargetMetadata


class EnrollmentResponse(StrictControllerModel):
    target_id: UUID
    agent_id: UUID
    agent_credential: NonEmptySecret
    polling_interval_seconds: int = Field(ge=1, le=86_400)


class AgentAuth(StrictControllerModel):
    target_id: UUID
    agent_id: UUID
    agent_credential: NonEmptySecret


class AdminAuth(StrictControllerModel):
    admin_credential: NonEmptySecret


class HeartbeatRequest(StrictControllerModel):
    auth: AgentAuth
    sent_at: AwareDatetime
    agent_version: NonEmptyString
    observed_metadata: ObservedTargetMetadata


class HeartbeatResponse(StrictControllerModel):
    accepted: bool
    last_seen: AwareDatetime


class JobCreateRequest(StrictControllerModel):
    target_id: UUID
    job_type: Literal[JobType.PROFILE_TARGET] = JobType.PROFILE_TARGET


class JobRecord(StrictControllerModel):
    job_id: UUID
    target_id: UUID
    job_type: Literal[JobType.PROFILE_TARGET] = JobType.PROFILE_TARGET
    status: JobStatus
    created_at: AwareDatetime
    dispatched_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "JobRecord":
        if self.status is JobStatus.PENDING:
            if self.dispatched_at is not None or self.completed_at is not None:
                raise ValueError("a pending job cannot have dispatch/completion times")
        elif self.status is JobStatus.DISPATCHED:
            if self.dispatched_at is None or self.completed_at is not None:
                raise ValueError(
                    "a dispatched job requires dispatched_at and no completed_at"
                )
        elif self.dispatched_at is None or self.completed_at is None:
            raise ValueError(
                "a completed job requires dispatched_at and completed_at"
            )

        if self.dispatched_at is not None and self.dispatched_at < self.created_at:
            raise ValueError("dispatched_at cannot precede created_at")
        if (
            self.completed_at is not None
            and self.dispatched_at is not None
            and self.completed_at < self.dispatched_at
        ):
            raise ValueError("completed_at cannot precede dispatched_at")
        return self


class ValidationJobCreateRequest(StrictControllerModel):
    """Explicit administrator request for the sole initial M6D experiment.

    The request deliberately has no generic payload, path, command, argv,
    service, file target, or adapter selector.  ``request_id`` is supplied by
    the administrator so a lost HTTP response cannot create a second mutation
    job when the same request is retried.
    """

    request_id: UUID
    target_id: UUID
    profile_id: UUID
    compatibility_report_id: UUID
    control_id: Literal["7.1.1"]
    validation_mode: Literal[ValidationMode.SANDBOX] = ValidationMode.SANDBOX
    execution_mode: Literal[ExecutionMode.EXECUTE] = ExecutionMode.EXECUTE
    administrator_approval_acknowledged: Literal[True]
    compatibility_risk_acknowledged: bool = False
    compatibility_override_reason: NonEmptyString | None = None


class ValidationJobRecord(StrictControllerModel):
    """A Controller-derived, allowlisted M6D job delivered to one Agent."""

    validation_job_id: UUID
    request_id: UUID
    target_id: UUID
    profile_id: UUID
    compatibility_report_id: UUID
    job_type: Literal[JobType.VALIDATE_CONTROL] = JobType.VALIDATE_CONTROL
    control_id: Literal["7.1.1"]
    validation_mode: Literal[ValidationMode.SANDBOX] = ValidationMode.SANDBOX
    execution_mode: Literal[ExecutionMode.EXECUTE] = ExecutionMode.EXECUTE
    administrator_approval_acknowledged: Literal[True]
    compatibility_risk_acknowledged: bool = False
    compatibility_override_reason: NonEmptyString | None = None
    compatibility_reference: CompatibilityReference
    status: JobStatus
    created_at: AwareDatetime
    dispatched_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_job(self) -> "ValidationJobRecord":
        _validate_job_lifecycle(
            status=self.status,
            created_at=self.created_at,
            dispatched_at=self.dispatched_at,
            completed_at=self.completed_at,
        )
        reference = self.compatibility_reference
        if reference.control_id != self.control_id:
            raise ValueError("validation job control does not match M4 evidence")
        if reference.report_source != (
            "controller-stored-compatibility-report:"
            f"{self.compatibility_report_id}"
        ):
            raise ValueError("validation job report source does not match lineage")
        if reference.profile_source != f"controller-stored-profile:{self.profile_id}":
            raise ValueError("validation job profile source does not match lineage")
        uncertain = {
            "warning",
            "review_required",
            "insufficient_evidence",
        }
        if (
            reference.result.value in uncertain
            and not self.compatibility_risk_acknowledged
        ):
            raise ValueError(
                "uncertain compatibility evidence requires risk acknowledgement"
            )
        if (
            reference.result.value == "insufficient_evidence"
            and self.compatibility_override_reason is None
        ):
            raise ValueError(
                "insufficient evidence requires a recorded override reason"
            )
        return self


def _validate_job_lifecycle(
    *,
    status: JobStatus,
    created_at: AwareDatetime,
    dispatched_at: AwareDatetime | None,
    completed_at: AwareDatetime | None,
) -> None:
    if status is JobStatus.PENDING:
        if dispatched_at is not None or completed_at is not None:
            raise ValueError("a pending job cannot have dispatch/completion times")
    elif status is JobStatus.DISPATCHED:
        if dispatched_at is None or completed_at is not None:
            raise ValueError(
                "a dispatched job requires dispatched_at and no completed_at"
            )
    elif dispatched_at is None or completed_at is None:
        raise ValueError("a completed job requires dispatched_at and completed_at")
    if dispatched_at is not None and dispatched_at < created_at:
        raise ValueError("dispatched_at cannot precede created_at")
    if (
        completed_at is not None
        and dispatched_at is not None
        and completed_at < dispatched_at
    ):
        raise ValueError("completed_at cannot precede dispatched_at")


class JobPollRequest(StrictControllerModel):
    auth: AgentAuth


AgentJobRecord: TypeAlias = Annotated[
    JobRecord | ValidationJobRecord,
    Field(discriminator="job_type"),
]


class JobPollResponse(StrictControllerModel):
    jobs: list[AgentJobRecord]

    @field_validator("jobs")
    @classmethod
    def reject_duplicate_jobs(
        cls, jobs: list[AgentJobRecord]
    ) -> list[AgentJobRecord]:
        job_ids = [
            job.job_id
            if isinstance(job, JobRecord)
            else job.validation_job_id
            for job in jobs
        ]
        if len(job_ids) != len(set(job_ids)):
            raise ValueError("jobs must have unique Controller job IDs")
        return jobs


class ProfileSubmissionRequest(StrictControllerModel):
    auth: AgentAuth
    job_id: UUID
    profile: TargetProfile
    profiler_version: NonEmptyString | None = None
    sentra_version: NonEmptyString | None = None


class ProfileRecord(StrictControllerModel):
    profile_id: UUID
    target_id: UUID
    agent_id: UUID
    job_id: UUID
    collected_at: AwareDatetime
    received_at: AwareDatetime
    profile_sha256: Sha256Hex
    profiler_version: NonEmptyString | None = None
    sentra_version: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_timeline(self) -> "ProfileRecord":
        if self.received_at < self.collected_at:
            raise ValueError("received_at cannot precede collected_at")
        return self


class CompatibilityAnalysisRequest(StrictControllerModel):
    """Administrator request to analyze one Controller-stored profile."""

    target_id: UUID
    profile_id: UUID


class CompatibilityReportRecord(StrictControllerModel):
    """Immutable M6C report payload and its Controller-owned lineage."""

    compatibility_report_id: UUID
    target_id: UUID
    profile_id: UUID
    benchmark_identity: Literal[
        "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0"
    ]
    benchmark_version: Literal["v1.0.0"]
    generated_at: AwareDatetime
    report_version: Literal["1"]
    report_sha256: Sha256Hex
    report: CompatibilityReport

    @model_validator(mode="after")
    def validate_report_metadata(self) -> "CompatibilityReportRecord":
        if self.generated_at != self.report.generated_at:
            raise ValueError(
                "generated_at must match the validated compatibility report"
            )
        if self.report_version != self.report.report_version:
            raise ValueError(
                "report_version must match the validated compatibility report"
            )
        return self


class ValidationResultPayload(StrictControllerModel):
    """Canonical Agent-produced evidence bound to one M6D job."""

    target_id: UUID
    profile_id: UUID
    compatibility_report_id: UUID
    validation_job_id: UUID
    control_id: Literal["7.1.1"]
    validation_mode: Literal[ValidationMode.SANDBOX] = ValidationMode.SANDBOX
    execution_mode: Literal[ExecutionMode.EXECUTE] = ExecutionMode.EXECUTE
    report: ValidationReport

    @model_validator(mode="after")
    def validate_m5_payload(self) -> "ValidationResultPayload":
        report = self.report
        if report.mode is not self.execution_mode:
            raise ValueError("M5 report execution mode does not match the job")
        if len(report.control_results) != 1:
            raise ValueError("an M6D result must contain exactly one control")
        control = report.control_results[0]
        if control.control_id != self.control_id:
            raise ValueError("M5 result control does not match the job")
        reference = control.m4_input
        if reference is None:
            raise ValueError("M6D result must retain its M4 compatibility input")
        if reference.report_source != (
            "controller-stored-compatibility-report:"
            f"{self.compatibility_report_id}"
        ):
            raise ValueError("M5 result report source does not match lineage")
        if reference.profile_source != f"controller-stored-profile:{self.profile_id}":
            raise ValueError("M5 result profile source does not match lineage")
        return self


class ValidationResultSubmissionRequest(StrictControllerModel):
    auth: AgentAuth
    payload: ValidationResultPayload


class ValidationResultRecord(StrictControllerModel):
    """Controller-owned M6D result identifier, timestamps, hash, and payload."""

    validation_result_id: UUID
    agent_id: UUID
    created_at: AwareDatetime
    dispatched_at: AwareDatetime
    completed_at: AwareDatetime
    result_sha256: Sha256Hex
    payload: ValidationResultPayload

    @model_validator(mode="after")
    def validate_timeline(self) -> "ValidationResultRecord":
        _validate_job_lifecycle(
            status=JobStatus.COMPLETED,
            created_at=self.created_at,
            dispatched_at=self.dispatched_at,
            completed_at=self.completed_at,
        )
        return self


class TargetRecord(StrictControllerModel):
    target_id: UUID
    agent_id: UUID
    installation_id: UUID
    status: TargetStatus
    created_at: AwareDatetime
    last_seen: AwareDatetime | None = None
    agent_version: NonEmptyString
    observed_metadata: ObservedTargetMetadata

    @model_validator(mode="after")
    def validate_last_seen(self) -> "TargetRecord":
        if self.last_seen is not None and self.last_seen < self.created_at:
            raise ValueError("last_seen cannot precede created_at")
        if self.status is TargetStatus.ONLINE and self.last_seen is None:
            raise ValueError("an online target requires last_seen")
        return self


class MetadataChangeRecord(StrictControllerModel):
    change_id: UUID
    target_id: UUID
    agent_id: UUID
    observed_at: AwareDatetime
    previous_metadata: ObservedTargetMetadata
    current_metadata: ObservedTargetMetadata

    @model_validator(mode="after")
    def validate_change(self) -> "MetadataChangeRecord":
        if self.previous_metadata == self.current_metadata:
            raise ValueError("a metadata-change record must contain a change")
        return self


__all__ = [
    "AdminAuth",
    "AgentJobRecord",
    "AgentAuth",
    "CompatibilityAnalysisRequest",
    "CompatibilityReportRecord",
    "EnrollmentRequest",
    "EnrollmentResponse",
    "HeartbeatRequest",
    "HeartbeatResponse",
    "JobCreateRequest",
    "JobPollRequest",
    "JobPollResponse",
    "JobRecord",
    "JobStatus",
    "JobType",
    "MetadataChangeRecord",
    "ObservedTargetMetadata",
    "ProfileRecord",
    "ProfileSubmissionRequest",
    "StrictControllerModel",
    "TargetRecord",
    "TargetStatus",
    "ValidationJobCreateRequest",
    "ValidationJobRecord",
    "ValidationMode",
    "ValidationResultPayload",
    "ValidationResultRecord",
    "ValidationResultSubmissionRequest",
]
