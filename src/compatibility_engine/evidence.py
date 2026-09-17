"""Resolve immutable evidence records from a supplied Milestone 3 profile."""

from __future__ import annotations

from collections.abc import Iterable

from src.target_profiler.models import TargetProfile

from .models import EvidenceRecord


def resolve_evidence(
    profile: TargetProfile, fact_name: str, control_id: str
) -> EvidenceRecord:
    """Copy one exact profile fact and verify its requester relationship."""

    try:
        result = profile.facts[fact_name]
    except KeyError as exc:
        raise ValueError(f"Profile is missing required fact {fact_name!r}") from exc

    if control_id not in result.requested_by:
        raise ValueError(
            f"Fact {fact_name!r} does not identify control {control_id} as a requester"
        )

    return EvidenceRecord(
        fact=result.name,
        status=result.status,
        value=result.value,
        requested_by=list(result.requested_by),
        reason=result.reason,
    )


def resolve_control_evidence(
    profile: TargetProfile,
    control_id: str,
    fact_names: Iterable[str],
) -> tuple[EvidenceRecord, ...]:
    """Resolve a control's evidence in enrichment order."""

    return tuple(
        resolve_evidence(profile, fact_name, control_id)
        for fact_name in fact_names
    )
