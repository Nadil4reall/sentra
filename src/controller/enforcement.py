"""Shared, read-only verification of one fixed M7 enforcement delivery."""

from __future__ import annotations

import hashlib
from uuid import UUID

from src.controller.models import EnforcementJobDelivery, JobStatus, JobType
from src.controller.validation import canonical_validation_payload_json
from src.sandbox_validator.models import ExecutionMode, ValidationDecision


def verify_enforcement_delivery(
    delivery: EnforcementJobDelivery, *, target_id: UUID, agent_id: UUID,
) -> str:
    """Recompute the approved M6 hash and bind every delivered lineage field.

    This deliberately has no file or mutation capability. The hash covers the
    existing canonical M6 payload, not a second representation of its evidence.
    """

    if type(delivery) is not EnforcementJobDelivery:
        raise ValueError("enforcement delivery type is invalid")
    delivery = EnforcementJobDelivery.model_validate(
        delivery.model_dump(mode="python"), strict=True,
    )
    evidence = delivery.m6_evidence
    control = evidence.report.control_results[0]
    if (
        delivery.target_id != target_id
        or delivery.assigned_agent_id != agent_id
        or delivery.job_type is not JobType.ENFORCE_CONTROL
        or delivery.status is not JobStatus.DISPATCHED
        or delivery.control_id != "7.1.1"
        or delivery.evidence_sandbox_session_id != delivery.sandbox_session_id
        or delivery.administrator_enforcement_approval_acknowledged is not True
        or evidence.target_id != delivery.target_id
        or evidence.profile_id != delivery.profile_id
        or evidence.compatibility_report_id != delivery.compatibility_report_id
        or evidence.control_id != delivery.control_id
        or evidence.execution_mode is not ExecutionMode.EXECUTE
        or evidence.report.mode is not ExecutionMode.EXECUTE
        or len(evidence.report.control_results) != 1
        or control.control_id != "7.1.1"
        or control.result is not ValidationDecision.VALIDATED
        or control.m4_input is None
        or control.m4_input.report_source != (
            "controller-stored-compatibility-report:"
            f"{delivery.compatibility_report_id}"
        )
        or control.m4_input.profile_source != (
            f"controller-stored-profile:{delivery.profile_id}"
        )
        or control.m3_profile_source != (
            f"controller-stored-profile:{delivery.profile_id}"
        )
    ):
        raise ValueError("enforcement delivery lineage or M6 result is invalid")
    # Strict source-state schema is revalidated above with the full delivery.
    canonical = canonical_validation_payload_json(evidence)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if digest != delivery.sandbox_evidence_sha256:
        raise ValueError("enforcement M6 evidence hash does not match")
    return digest


__all__ = ["verify_enforcement_delivery"]
