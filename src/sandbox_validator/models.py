"""Strict, traceable schemas for Milestone 5 sandbox experiments."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from src.compatibility_engine.models import CompatibilityDecision
from src.poc_models import Category, DerivationStatus
from src.target_profiler.models import TargetInfo


class StrictSandboxModel(BaseModel):
    """Reject fields that are not part of the M5 report contract."""

    model_config = ConfigDict(extra="forbid")


class ExecutionMode(StrEnum):
    PLAN = "plan"
    EXECUTE = "execute"


class ValidationDecision(StrEnum):
    """Empirical sandbox outcomes; these are not CIS compliance verdicts."""

    VALIDATED = "validated"
    WARNING = "warning"
    FAILED = "failed"
    NOT_TESTED = "not_tested"


class EvidenceStatus(StrEnum):
    COLLECTED = "collected"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class ActionStatus(StrEnum):
    PLANNED = "planned"
    APPLIED = "applied"
    SKIPPED = "skipped"
    FAILED = "failed"


class HealthStatus(StrEnum):
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class EventStage(StrEnum):
    PRECHECK = "sandbox_precheck"
    PRE_AUDIT = "pre_audit"
    REMEDIATION_STARTED = "remediation_started"
    REMEDIATION_ACTION = "remediation_action"
    POST_AUDIT = "post_audit"
    HEALTH_CHECK = "health_check"
    ROLLBACK = "rollback_attempt"
    FINAL = "final_result"


class SandboxIdentity(StrictSandboxModel):
    """Observed local identity without claiming that a VM is disposable."""

    hostname: str = Field(min_length=1)
    os: str = Field(min_length=1)
    version: str
    kernel: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    architecture_supported: bool
    effective_uid: int = Field(ge=0)
    privileged: bool
    supported: bool
    reason: str | None = None

    @model_validator(mode="after")
    def validate_identity(self) -> "SandboxIdentity":
        if self.privileged != (self.effective_uid == 0):
            raise ValueError("privileged must reflect effective_uid")
        if self.supported:
            if (
                self.os.casefold() != "ubuntu"
                or self.version != "24.04"
                or not self.architecture_supported
            ):
                raise ValueError(
                    "only Ubuntu 24.04 on a supported architecture can be supported"
                )
            if self.reason is not None:
                raise ValueError("a supported identity must not include a reason")
        elif not self.reason or not self.reason.strip():
            raise ValueError("an unsupported identity must include a reason")
        return self


class CompatibilityReference(StrictSandboxModel):
    """The selected M4 result, recorded as input rather than permission."""

    control_id: str = Field(pattern=r"^\d+(?:\.\d+){2,}$")
    report_source: str = Field(min_length=1)
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_version: str = Field(min_length=1)
    report_generated_at: datetime
    profile_source: str = Field(min_length=1)
    profile_collected_at: datetime
    profile_target: TargetInfo
    result: CompatibilityDecision
    provisional: bool
    metadata_review_status: DerivationStatus
    explanation: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_timestamps(self) -> "CompatibilityReference":
        if (
            self.report_generated_at.utcoffset() is None
            or self.profile_collected_at.utcoffset() is None
        ):
            raise ValueError("M4 reference timestamps must include a timezone")
        return self


class SandboxPrecheck(StrictSandboxModel):
    """Mutation gate and the evidence behind it."""

    control_id: str = Field(pattern=r"^\d+(?:\.\d+){2,}$")
    control_title: str = Field(min_length=1)
    identity: SandboxIdentity
    mutation_requested: bool
    sandbox_operator_acknowledged: bool
    administrator_approval_acknowledged: bool
    compatibility_risk_acknowledged: bool
    ssh_recovery_access_acknowledged: bool = False
    ssh_non_root_admin_sudo_access_verified: bool = False
    ssh_lockout_risk_acknowledged: bool = False
    snapshot_expectation: str = Field(min_length=1)
    compatibility_override_reason: str | None = None
    compatibility: CompatibilityReference | None = None
    can_mutate: bool
    blockers: list[str]
    warnings: list[str]

    @model_validator(mode="after")
    def validate_gate(self) -> "SandboxPrecheck":
        expected = self.mutation_requested and not self.blockers
        if self.can_mutate != expected:
            raise ValueError("can_mutate must reflect the mutation request and blockers")
        if self.compatibility is not None:
            if self.compatibility.control_id != self.control_id:
                raise ValueError("compatibility input must match the selected control")
        if self.can_mutate and not (
            self.sandbox_operator_acknowledged
            and self.administrator_approval_acknowledged
            and self.identity.supported
            and self.identity.privileged
        ):
            raise ValueError(
                "mutation authorization requires acknowledgement, approval, a "
                "supported identity, and elevated privilege"
            )
        if self.can_mutate and self.control_id == "5.1.20" and not (
            self.ssh_recovery_access_acknowledged
            and self.ssh_non_root_admin_sudo_access_verified
            and self.ssh_lockout_risk_acknowledged
        ):
            raise ValueError(
                "SSH mutation authorization requires recovery access, tested non-root "
                "administrator sudo access, and lockout-risk acknowledgement"
            )
        if self.can_mutate and self.compatibility is None:
            raise ValueError("mutation authorization requires an explicit M4 result")
        if (
            self.can_mutate
            and self.compatibility is not None
            and self.compatibility.result
            in {
                CompatibilityDecision.WARNING,
                CompatibilityDecision.REVIEW_REQUIRED,
                CompatibilityDecision.INSUFFICIENT_EVIDENCE,
            }
            and not self.compatibility_risk_acknowledged
        ):
            raise ValueError("the selected M4 state requires risk acknowledgement")
        if (
            self.can_mutate
            and self.compatibility is not None
            and self.compatibility.result
            is CompatibilityDecision.INSUFFICIENT_EVIDENCE
            and not self.compatibility_override_reason
        ):
            raise ValueError("insufficient evidence requires an override reason")
        if self.compatibility_override_reason is not None:
            if not self.compatibility_override_reason.strip():
                raise ValueError("compatibility override reason must not be blank")
        return self


class AuditEvidence(StrictSandboxModel):
    """One pre- or post-remediation observation with uncertainty preserved."""

    name: str = Field(pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
    status: EvidenceStatus
    value: JsonValue | None = None
    source: str = Field(min_length=1)
    reason: str | None = None

    @model_validator(mode="after")
    def validate_state(self) -> "AuditEvidence":
        if self.status is EvidenceStatus.COLLECTED:
            if self.value is None:
                raise ValueError("collected evidence must have a non-null value")
            if self.reason is not None:
                raise ValueError("collected evidence must not include a reason")
        else:
            if self.value is not None:
                raise ValueError("non-collected evidence must have a null value")
            if not self.reason or not self.reason.strip():
                raise ValueError("non-collected evidence must include a reason")
        return self


class RemediationAction(StrictSandboxModel):
    """One hand-authored action; it never contains executable CIS prose."""

    action_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    description: str = Field(min_length=1)
    mutating: bool
    target: str | None = None
    planned_effect: str = Field(min_length=1)
    status: ActionStatus
    error: str | None = None

    @model_validator(mode="after")
    def validate_status(self) -> "RemediationAction":
        if self.status is ActionStatus.FAILED:
            if not self.error or not self.error.strip():
                raise ValueError("failed actions must include an error")
        elif self.error is not None:
            raise ValueError("only failed actions may include an error")
        return self


class BackupInformation(StrictSandboxModel):
    target: str = Field(min_length=1)
    original_existed: bool
    created: bool
    path: str | None = None
    metadata_preserved: bool
    reason: str | None = None

    @model_validator(mode="after")
    def validate_backup(self) -> "BackupInformation":
        if self.created and not self.path:
            raise ValueError("a created backup must record its path")
        if not self.created and not self.reason:
            raise ValueError("a missing backup must record why it was not created")
        return self


class RemediationResult(StrictSandboxModel):
    supported: bool
    attempted: bool
    changed: bool
    succeeded: bool | None
    actions: list[RemediationAction]
    backups: list[BackupInformation]
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_result(self) -> "RemediationResult":
        if not self.attempted:
            if self.changed:
                raise ValueError("an unattempted remediation cannot report changes")
            if self.succeeded is not None:
                raise ValueError("an unattempted remediation has no success outcome")
        elif self.succeeded is None:
            raise ValueError("an attempted remediation must report success or failure")
        if not self.supported and self.attempted:
            raise ValueError("an unsupported remediation cannot be attempted")
        return self


class HealthCheck(StrictSandboxModel):
    check_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    description: str = Field(min_length=1)
    required: bool
    status: HealthStatus
    explanation: str = Field(min_length=1)


class RollbackResult(StrictSandboxModel):
    supported: bool
    attempted: bool
    succeeded: bool | None
    actions: list[RemediationAction]
    explanation: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_rollback(self) -> "RollbackResult":
        if not self.attempted and self.succeeded is not None:
            raise ValueError("an unattempted rollback has no success outcome")
        if self.attempted and self.succeeded is None:
            raise ValueError("an attempted rollback must report success or failure")
        if not self.supported and self.attempted:
            raise ValueError("an unsupported rollback cannot be attempted")
        return self


class AuditEvent(StrictSandboxModel):
    timestamp: datetime
    stage: EventStage
    outcome: str = Field(min_length=1)
    description: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_timestamp(self) -> "AuditEvent":
        if self.timestamp.utcoffset() is None:
            raise ValueError("event timestamps must include a timezone")
        return self


class ControlValidationResult(StrictSandboxModel):
    control_id: str = Field(pattern=r"^\d+(?:\.\d+){2,}$")
    control_title: str = Field(min_length=1)
    category: Category | None
    started_at: datetime
    completed_at: datetime
    m2_metadata_source: str | None
    m3_profile_source: str | None
    m4_input: CompatibilityReference | None
    sandbox: SandboxIdentity
    precheck: SandboxPrecheck
    pre_audit: list[AuditEvidence]
    remediation: RemediationResult
    post_audit: list[AuditEvidence]
    health_checks: list[HealthCheck]
    rollback: RollbackResult
    events: list[AuditEvent]
    result: ValidationDecision
    explanation: str = Field(min_length=1)
    errors: list[str]
    warnings: list[str]

    @model_validator(mode="after")
    def validate_control_result(self) -> "ControlValidationResult":
        if self.started_at.utcoffset() is None or self.completed_at.utcoffset() is None:
            raise ValueError("control timestamps must include a timezone")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        if self.sandbox != self.precheck.identity:
            raise ValueError("result sandbox must match the precheck identity")
        if self.m4_input != self.precheck.compatibility:
            raise ValueError("result M4 input must match the precheck reference")
        if self.result in {ValidationDecision.VALIDATED, ValidationDecision.WARNING}:
            if not self.remediation.attempted or self.remediation.succeeded is not True:
                raise ValueError("validated/warning requires successful remediation")
            if not self.post_audit:
                raise ValueError("validated/warning requires post-audit evidence")
        if self.result is ValidationDecision.NOT_TESTED and self.remediation.attempted:
            raise ValueError("not_tested cannot include an attempted remediation")
        if self.result is ValidationDecision.FAILED:
            if not self.remediation.attempted or self.remediation.succeeded is not False:
                raise ValueError("failed requires an attempted, unsuccessful remediation")
        if self.result in {ValidationDecision.VALIDATED, ValidationDecision.WARNING}:
            if any(
                check.required and check.status is not HealthStatus.PASSED
                for check in self.health_checks
            ):
                raise ValueError(
                    "validated/warning requires every required health check to pass"
                )
        return self


class ValidationSummary(StrictSandboxModel):
    controls_evaluated: int = Field(ge=0)
    validated: int = Field(ge=0)
    warning: int = Field(ge=0)
    failed: int = Field(ge=0)
    not_tested: int = Field(ge=0)
    remediations_attempted: int = Field(ge=0)
    rollbacks_attempted: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_counts(self) -> "ValidationSummary":
        terminal = self.validated + self.warning + self.failed + self.not_tested
        if terminal != self.controls_evaluated:
            raise ValueError("M5 result counts must add up to controls_evaluated")
        if self.remediations_attempted > self.controls_evaluated:
            raise ValueError("remediation count cannot exceed controls evaluated")
        if self.rollbacks_attempted > self.remediations_attempted:
            raise ValueError("rollback count cannot exceed remediations attempted")
        return self


class ValidationReport(StrictSandboxModel):
    report_version: Literal["1"] = "1"
    generated_at: datetime
    mode: ExecutionMode
    control_results: list[ControlValidationResult] = Field(min_length=1)
    summary: ValidationSummary

    @model_validator(mode="after")
    def validate_report(self) -> "ValidationReport":
        if self.generated_at.utcoffset() is None:
            raise ValueError("generated_at must include a timezone")
        if self.summary.controls_evaluated != len(self.control_results):
            raise ValueError("summary count must match control_results")
        ids = [item.control_id for item in self.control_results]
        if len(ids) != len(set(ids)):
            raise ValueError("control IDs must be unique within an M5 report")
        expected = {
            "validated": sum(
                item.result is ValidationDecision.VALIDATED
                for item in self.control_results
            ),
            "warning": sum(
                item.result is ValidationDecision.WARNING
                for item in self.control_results
            ),
            "failed": sum(
                item.result is ValidationDecision.FAILED
                for item in self.control_results
            ),
            "not_tested": sum(
                item.result is ValidationDecision.NOT_TESTED
                for item in self.control_results
            ),
            "remediations_attempted": sum(
                item.remediation.attempted for item in self.control_results
            ),
            "rollbacks_attempted": sum(
                item.rollback.attempted for item in self.control_results
            ),
        }
        if any(getattr(self.summary, name) != value for name, value in expected.items()):
            raise ValueError("summary counts must match control results")
        if self.mode is ExecutionMode.PLAN and any(
            item.remediation.attempted for item in self.control_results
        ):
            raise ValueError("plan reports cannot contain attempted remediation")
        return self
