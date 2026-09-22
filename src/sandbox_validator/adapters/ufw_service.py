"""Audit-and-plan-only adapter for high-risk UFW control 4.2.3."""

from __future__ import annotations

from src.poc_models import Category

from ..audit import audit_ufw
from ..models import (
    ActionStatus,
    RemediationAction,
    RemediationResult,
    RollbackResult,
    ValidationDecision,
)
from .base import AdapterContext, AdapterOutcome, ControlAdapter


class UfwServiceAdapter(ControlAdapter):
    control_id = "4.2.3"
    title = "Ensure ufw service is enabled"
    category = Category.FIREWALL
    mutation_supported = False

    def pre_audit(self, context: AdapterContext):
        return audit_ufw(context)

    def plan(self, pre_audit):
        return [
            RemediationAction(
                action_id="review-ufw-remote-access-safety",
                description="Review session context, TCP/22 evidence, and alternate ports.",
                mutating=False,
                target="ufw.service",
                planned_effect="Require explicit future safety design before firewall mutation.",
                status=ActionStatus.PLANNED,
            ),
            RemediationAction(
                action_id="defer-ufw-mutation",
                description="Do not enable, reconfigure, or add rules in M5 initial scope.",
                mutating=False,
                target="ufw.service",
                planned_effect="Preserve remote-access safety and current firewall state.",
                status=ActionStatus.PLANNED,
            ),
        ]

    def execute(self, context, pre_audit, authorization):
        actions = [
            item.model_copy(update={"status": ActionStatus.APPLIED})
            for item in self.plan(pre_audit)
        ]
        return AdapterOutcome(
            remediation=RemediationResult(
                supported=False,
                attempted=False,
                changed=False,
                succeeded=None,
                actions=actions,
                backups=[],
                reason=(
                    "Automatic UFW mutation is intentionally outside the initial M5 "
                    "adapter because remote-access safety cannot be established."
                ),
            ),
            post_audit=[],
            health_checks=[],
            rollback=RollbackResult(
                supported=False,
                attempted=False,
                succeeded=None,
                actions=[],
                explanation="No UFW mutation exists, so no rollback is claimed.",
            ),
            decision=ValidationDecision.NOT_TESTED,
            explanation=(
                "UFW was audited, but the candidate was not applied; session absence, "
                "TCP/22, and alternate-port context are not sufficient for safe automation."
            ),
            warnings=["firewall and remote-access context requires administrator review"],
            errors=[],
        )
