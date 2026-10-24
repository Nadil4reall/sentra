"""Shared, read-only verification of one fixed M7 enforcement delivery."""

from __future__ import annotations

import hashlib
import json
from uuid import UUID

from src.controller.models import (
    EnforcementJobDelivery, EnforcementOutcome, EnforcementResultPayload,
    JobStatus, JobType, PostEnforcementVerificationOutcome,
)
from src.sandbox_protocol.models import PasswdSourceState
from src.controller.validation import canonical_validation_payload_json
from src.sandbox_validator.models import ExecutionMode, ValidationDecision
from src.target_profiler.models import FactStatus, TargetProfile


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


def canonical_enforcement_payload_json(payload: EnforcementResultPayload) -> str:
    """Strictly revalidate and serialize exactly the accepted terminal evidence."""

    if type(payload) is not EnforcementResultPayload:
        raise ValueError("enforcement evidence type is invalid")
    validated = EnforcementResultPayload.model_validate(
        payload.model_dump(mode="python"), strict=True,
    )
    return json.dumps(
        validated.model_dump(mode="json"), sort_keys=True,
        ensure_ascii=False, allow_nan=False, separators=(",", ":"),
    )


def observed_passwd_state(profile: TargetProfile) -> PasswdSourceState | None:
    """Use only three collected 7.1.1 M3 facts; retain absence as uncertainty."""

    values: dict[str, object] = {}
    for name in (
        "passwd_file_mode", "passwd_file_owner_uid", "passwd_file_group_gid",
    ):
        fact = profile.facts.get(name)
        if (
            fact is None or fact.status is not FactStatus.COLLECTED
            or "7.1.1" not in fact.requested_by
        ):
            return None
        values[name] = fact.value
    return PasswdSourceState.model_validate(values, strict=True)


def post_enforcement_outcome(
    payload: EnforcementResultPayload,
    observed: PasswdSourceState | None,
) -> PostEnforcementVerificationOutcome:
    if payload.outcome is not EnforcementOutcome.SUCCEEDED or observed is None:
        return PostEnforcementVerificationOutcome.OBSERVED_FAILURE_STATE
    expected_mode = int(payload.expected_source_state.passwd_file_mode, 8) & 0o644
    if (
        observed == payload.post_execution_observed_state
        and observed.passwd_file_owner_uid == 0
        and observed.passwd_file_group_gid == 0
        and int(observed.passwd_file_mode, 8) == expected_mode
    ):
        return PostEnforcementVerificationOutcome.VERIFIED
    return PostEnforcementVerificationOutcome.DRIFT_DETECTED


__all__ = [
    "canonical_enforcement_payload_json", "observed_passwd_state",
    "post_enforcement_outcome", "verify_enforcement_delivery",
]
