"""Construct fixed M7 terminal evidence only from the protected local journal."""

from __future__ import annotations

from uuid import UUID

from src.agent.enforcement_journal import (
    EnforcementJournalEntry, EnforcementPreflightOutcome as JournalState,
)
from src.controller.enforcement import verify_enforcement_delivery
from src.controller.models import (
    EnforcementJobDelivery, EnforcementOutcome, EnforcementResultPayload,
)


_TERMINAL = frozenset(item.value for item in EnforcementOutcome)


def payload_from_trusted_journal(
    entry: EnforcementJournalEntry, *, target_id: UUID, agent_id: UUID,
) -> EnforcementResultPayload:
    """Revalidate one protected entry; it carries no target file contents."""

    if type(entry) is not EnforcementJournalEntry:
        raise ValueError("enforcement journal entry type is invalid")
    entry = EnforcementJournalEntry.model_validate(
        entry.model_dump(mode="python"), strict=True,
    )
    if (
        entry.target_id != target_id
        or entry.agent_id != agent_id
        or entry.control_id != "7.1.1"
        or entry.outcome.value not in _TERMINAL
    ):
        raise ValueError("enforcement journal is not trusted terminal evidence")
    pre = entry.pre_execution_observed_state
    if entry.outcome is JournalState.BLOCKED_DRIFT and pre is None:
        pre = entry.observed_source_state
    completed = entry.execution_finished_at or entry.updated_at or entry.recorded_at
    return EnforcementResultPayload(
        enforcement_job_id=entry.enforcement_job_id,
        target_id=entry.target_id,
        agent_id=entry.agent_id,
        control_id="7.1.1",
        m6_evidence_sha256=entry.m6_evidence_sha256,
        outcome=EnforcementOutcome(entry.outcome.value),
        expected_source_state=entry.expected_source_state,
        pre_execution_observed_state=pre,
        original_rollback_state=entry.original_rollback_state,
        post_execution_observed_state=entry.post_execution_observed_state,
        mutation_attempted=entry.mutation_attempted,
        mutation_changed=entry.mutation_changed,
        verification_succeeded=entry.verification_succeeded is True,
        rollback_attempted=entry.rollback_attempted,
        rollback_succeeded=entry.rollback_succeeded,
        execution_started_at=entry.execution_started_at,
        execution_completed_at=completed,
    )


def payload_from_verified_delivery(
    delivery: EnforcementJobDelivery,
    entry: EnforcementJournalEntry,
    *, target_id: UUID, agent_id: UUID,
) -> EnforcementResultPayload:
    """Bind the persisted terminal evidence to this exact verified delivery."""

    verify_enforcement_delivery(delivery, target_id=target_id, agent_id=agent_id)
    if (
        entry.enforcement_job_id != delivery.enforcement_job_id
        or entry.target_id != delivery.target_id
        or entry.agent_id != delivery.assigned_agent_id
        or entry.control_id != delivery.control_id
        or entry.m6_evidence_sha256 != delivery.sandbox_evidence_sha256
        or entry.expected_source_state != delivery.expected_source_state
    ):
        raise ValueError("enforcement journal conflicts with the verified delivery")
    return payload_from_trusted_journal(entry, target_id=target_id, agent_id=agent_id)


__all__ = ["payload_from_trusted_journal", "payload_from_verified_delivery"]
