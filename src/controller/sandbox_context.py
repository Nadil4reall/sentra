"""Derive minimal, target-sourced metadata for a representative sandbox run."""

from __future__ import annotations

from src.sandbox_validator.models import CompatibilityReference
from src.sandbox_protocol.models import (
    SANDBOX_CONTEXT_CONTROL_ID,
    SANDBOX_CONTEXT_VERSION,
    PasswdSourceState,
    SandboxContextManifest,
)
from src.target_profiler.models import FactStatus, TargetProfile


__all__ = [
    "SANDBOX_CONTEXT_CONTROL_ID",
    "PasswdSourceState",
    "SandboxContextManifest",
    "derive_sandbox_context",
]


def derive_sandbox_context(
    control_id: str,
    target_profile: TargetProfile,
    compatibility: CompatibilityReference,
) -> SandboxContextManifest:
    """Derive only the three validated 7.1.1 facts from a stored M3 profile.

    This function checks M3/M4 lineage and fact provenance. It deliberately does
    not interpret M4 risk or decide whether existing M5 approval gates are met.
    """

    if control_id != SANDBOX_CONTEXT_CONTROL_ID:
        raise ValueError("sandbox context derivation supports only control 7.1.1")
    if not isinstance(target_profile, TargetProfile):
        raise ValueError("target_profile must be a validated TargetProfile")
    if not isinstance(compatibility, CompatibilityReference):
        raise ValueError("compatibility must be a validated CompatibilityReference")
    if compatibility.control_id != control_id:
        raise ValueError("compatibility control does not match sandbox context control")
    if target_profile.collected_at != compatibility.profile_collected_at:
        raise ValueError("M3 profile and M4 compatibility timestamps do not match")
    if target_profile.target != compatibility.profile_target:
        raise ValueError("M3 profile and M4 compatibility targets do not match")

    values: dict[str, object] = {}
    for fact_name in (
        "passwd_file_mode",
        "passwd_file_owner_uid",
        "passwd_file_group_gid",
    ):
        fact = target_profile.facts.get(fact_name)
        if fact is None:
            raise ValueError(f"required 7.1.1 fact is missing: {fact_name}")
        if fact.status is not FactStatus.COLLECTED or fact.value is None:
            raise ValueError(f"required 7.1.1 fact is not collected: {fact_name}")
        if control_id not in fact.requested_by:
            raise ValueError(
                f"required 7.1.1 fact has incorrect provenance: {fact_name}"
            )
        values[fact_name] = fact.value

    return SandboxContextManifest(
        context_version=SANDBOX_CONTEXT_VERSION,
        control_id=SANDBOX_CONTEXT_CONTROL_ID,
        source_state=PasswdSourceState(**values),
    )
