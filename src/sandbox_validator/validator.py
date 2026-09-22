"""Fail-stop orchestration for one local M5 sandbox experiment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .adapters import adapter_registry
from .adapters.base import AdapterContext, ControlAdapter
from .command_runner import MutationAction, MutationAuthorization
from .loaders import ValidationInputs
from .models import (
    ActionStatus,
    AuditEvent,
    AuditEvidence,
    ControlValidationResult,
    EvidenceStatus,
    EventStage,
    ExecutionMode,
    RemediationResult,
    RollbackResult,
    SandboxIdentity,
    ValidationDecision,
    ValidationReport,
)
from .precheck import build_precheck, inspect_sandbox_identity
from .report import build_summary


@dataclass(frozen=True, slots=True)
class ValidationRequest:
    control_id: str
    mode: ExecutionMode = ExecutionMode.PLAN
    sandbox_operator_acknowledged: bool = False
    administrator_approval_acknowledged: bool = False
    compatibility_risk_acknowledged: bool = False
    compatibility_override_reason: str | None = None
    ssh_recovery_access_acknowledged: bool = False
    ssh_non_root_admin_sudo_access_verified: bool = False
    ssh_lockout_risk_acknowledged: bool = False


IdentityProvider = Callable[[], SandboxIdentity]


class SandboxValidator:
    def __init__(
        self,
        *,
        context: AdapterContext | None = None,
        identity_provider: IdentityProvider | None = None,
        adapters: dict[str, ControlAdapter] | None = None,
    ) -> None:
        self.context = context or AdapterContext()
        self.identity_provider = identity_provider or (
            lambda: inspect_sandbox_identity(self.context.root)
        )
        self.adapters = adapters or adapter_registry()

    def _event(self, stage: EventStage, outcome: str, description: str) -> AuditEvent:
        return AuditEvent(
            timestamp=self.context.clock(),
            stage=stage,
            outcome=outcome,
            description=description,
        )

    def validate(
        self, inputs: ValidationInputs, request: ValidationRequest
    ) -> ValidationReport:
        if inputs.control_id != request.control_id:
            raise ValueError("validation request and loaded inputs select different controls")

        started_at = self.context.clock()
        adapter = self.adapters.get(request.control_id)
        identity = self.identity_provider()
        mutation_requested = request.mode is ExecutionMode.EXECUTE
        precheck = build_precheck(
            control_id=request.control_id,
            control_title=inputs.control_title,
            identity=identity,
            mutation_requested=mutation_requested,
            mutation_supported=bool(adapter and adapter.mutation_supported),
            sandbox_operator_acknowledged=request.sandbox_operator_acknowledged,
            administrator_approval_acknowledged=(
                request.administrator_approval_acknowledged
            ),
            compatibility_risk_acknowledged=(
                request.compatibility_risk_acknowledged
            ),
            compatibility_override_reason=request.compatibility_override_reason,
            compatibility=inputs.compatibility,
            ssh_recovery_access_acknowledged=(
                request.ssh_recovery_access_acknowledged
            ),
            ssh_non_root_admin_sudo_access_verified=(
                request.ssh_non_root_admin_sudo_access_verified
            ),
            ssh_lockout_risk_acknowledged=request.ssh_lockout_risk_acknowledged,
        )
        events = [
            self._event(
                EventStage.PRECHECK,
                "authorized" if precheck.can_mutate else "read_only_or_refused",
                "Sandbox identity and explicit mutation gates were evaluated.",
            )
        ]

        if adapter is None:
            pre_audit: list[AuditEvidence] = []
        else:
            try:
                pre_audit = adapter.pre_audit(self.context)
            except Exception as exc:  # defensive boundary around injected adapters
                pre_audit = [
                    AuditEvidence(
                        name="adapter_audit_error",
                        status=EvidenceStatus.ERROR,
                        value=None,
                        source="adapter:pre_audit",
                        reason=f"pre-audit failed: {type(exc).__name__}",
                    )
                ]
        events.append(
            self._event(
                EventStage.PRE_AUDIT,
                "completed" if pre_audit else "not_available",
                "Fresh local pre-remediation evidence was collected where supported.",
            )
        )

        if adapter is None or not precheck.can_mutate:
            planned_actions = adapter.plan(pre_audit) if adapter is not None else []
            supported = bool(adapter and adapter.mutation_supported)
            reason = (
                "No hand-authored M5 adapter exists for this control."
                if adapter is None
                else "The candidate was planned/audited but mutation was not authorized."
            )
            remediation = RemediationResult(
                supported=supported,
                attempted=False,
                changed=False,
                succeeded=None,
                actions=planned_actions,
                backups=[],
                reason=reason,
            )
            rollback = RollbackResult(
                supported=supported,
                attempted=False,
                succeeded=None,
                actions=[],
                explanation="No target mutation occurred, so rollback was not attempted.",
            )
            post_audit: list[AuditEvidence] = []
            health_checks = []
            decision = ValidationDecision.NOT_TESTED
            explanation = reason
            errors = list(precheck.blockers)
            warnings = list(precheck.warnings)
        else:
            allowed_actions = (
                frozenset({MutationAction.SSH_SERVICE_RELOAD})
                if request.control_id == "5.1.20"
                else frozenset()
            )
            authorization = MutationAuthorization(
                control_id=request.control_id,
                allowed_actions=allowed_actions,
            )
            events.append(
                self._event(
                    EventStage.REMEDIATION_STARTED,
                    "started",
                    "The selected fixed adapter began its controlled candidate action.",
                )
            )
            try:
                outcome = adapter.execute(self.context, pre_audit, authorization)
            except Exception as exc:  # fail closed; never continue blindly
                planned = adapter.plan(pre_audit)
                remediation = RemediationResult(
                    supported=adapter.mutation_supported,
                    attempted=True,
                    changed=False,
                    succeeded=False,
                    actions=[
                        item.model_copy(
                            update={
                                "status": (
                                    ActionStatus.FAILED
                                    if index == 0
                                    else ActionStatus.SKIPPED
                                ),
                                "error": (
                                    type(exc).__name__ if index == 0 else None
                                ),
                            }
                        )
                        for index, item in enumerate(planned)
                    ],
                    backups=[],
                    reason="The adapter stopped after an unexpected controlled failure.",
                )
                post_audit = []
                health_checks = []
                rollback = RollbackResult(
                    supported=adapter.mutation_supported,
                    attempted=False,
                    succeeded=None,
                    actions=[],
                    explanation=(
                        "Rollback status is unknown because the adapter boundary failed; "
                        "manual sandbox inspection is required."
                    ),
                )
                decision = ValidationDecision.FAILED
                explanation = "The fail-stop adapter boundary captured an unexpected failure."
                errors = [type(exc).__name__]
                warnings = list(precheck.warnings)
            else:
                remediation = outcome.remediation
                post_audit = outcome.post_audit
                health_checks = outcome.health_checks
                rollback = outcome.rollback
                decision = outcome.decision
                explanation = outcome.explanation
                errors = list(outcome.errors)
                warnings = [*precheck.warnings, *outcome.warnings]

        for action in remediation.actions:
            events.append(
                self._event(
                    EventStage.REMEDIATION_ACTION,
                    action.status.value,
                    f"Adapter action {action.action_id} was recorded.",
                )
            )
        if post_audit:
            events.append(
                self._event(
                    EventStage.POST_AUDIT,
                    "completed",
                    "Fresh post-remediation evidence was collected.",
                )
            )
        for check in health_checks:
            events.append(
                self._event(
                    EventStage.HEALTH_CHECK,
                    check.status.value,
                    f"Health check {check.check_id} was recorded.",
                )
            )
        if rollback.attempted:
            events.append(
                self._event(
                    EventStage.ROLLBACK,
                    "succeeded" if rollback.succeeded else "failed",
                    rollback.explanation,
                )
            )
        events.append(
            self._event(
                EventStage.FINAL,
                decision.value,
                "The M5 sandbox result was finalized; it is not a CIS compliance verdict.",
            )
        )

        completed_at = self.context.clock()
        result = ControlValidationResult(
            control_id=request.control_id,
            control_title=inputs.control_title,
            category=(inputs.enrichment.sentra.category if inputs.enrichment else None),
            started_at=started_at,
            completed_at=completed_at,
            m2_metadata_source=(
                inputs.enrichment_path.as_posix()
                if inputs.enrichment_path is not None
                else None
            ),
            m3_profile_source=inputs.m3_profile_source,
            m4_input=inputs.compatibility,
            sandbox=identity,
            precheck=precheck,
            pre_audit=pre_audit,
            remediation=remediation,
            post_audit=post_audit,
            health_checks=health_checks,
            rollback=rollback,
            events=events,
            result=decision,
            explanation=explanation,
            errors=errors,
            warnings=warnings,
        )
        results = [result]
        return ValidationReport(
            generated_at=completed_at,
            mode=request.mode,
            control_results=results,
            summary=build_summary(results),
        )


__all__ = ["SandboxValidator", "ValidationRequest"]
