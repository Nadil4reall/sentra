"""Derive minimal, target-sourced metadata for a representative sandbox run."""

from __future__ import annotations

from src.sandbox_validator.models import CompatibilityReference
from src.sandbox_protocol.models import (
    SANDBOX_CONTEXT_CONTROL_ID,
    SANDBOX_CONTEXT_SUPPORTED_CONTROL_IDS,
    SANDBOX_CONTEXT_VERSION,
    IpForwardingSourceState,
    PasswdSourceState,
    SandboxContextManifest,
)
from src.target_profiler.models import FactStatus, TargetProfile


__all__ = [
    "SANDBOX_CONTEXT_CONTROL_ID",
    "PasswdSourceState",
    "IpForwardingSourceState",
    "SandboxContextManifest",
    "derive_sandbox_context",
]


def derive_sandbox_context(
    control_id: str,
    target_profile: TargetProfile,
    compatibility: CompatibilityReference,
) -> SandboxContextManifest:
    """Derive only the allowlisted source facts for a selected sandbox control.

    This function checks M3/M4 lineage and fact provenance. It deliberately does
    not interpret M4 risk or decide whether existing M5 approval gates are met.
    """

    if control_id not in SANDBOX_CONTEXT_SUPPORTED_CONTROL_IDS:
        raise ValueError("sandbox context derivation does not support this control")
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

    def collected_fact(fact_name: str) -> object:
        fact = target_profile.facts.get(fact_name)
        if fact is None:
            raise ValueError(f"required sandbox fact is missing: {fact_name}")
        if fact.status is not FactStatus.COLLECTED or fact.value is None:
            raise ValueError(f"required sandbox fact is not collected: {fact_name}")
        if control_id not in fact.requested_by:
            raise ValueError(
                f"required sandbox fact has incorrect provenance: {fact_name}"
            )
        return fact.value

    if control_id == SANDBOX_CONTEXT_CONTROL_ID:
        source_state = PasswdSourceState(
            passwd_file_mode=collected_fact("passwd_file_mode"),
            passwd_file_owner_uid=collected_fact("passwd_file_owner_uid"),
            passwd_file_group_gid=collected_fact("passwd_file_group_gid"),
        )
    else:
        ipv6_state = collected_fact("ipv6_enabled")
        source_state = IpForwardingSourceState(
            ipv4_forwarding_status=collected_fact("ipv4_forwarding_status"),
            ipv6_enabled=ipv6_state,
            ipv6_forwarding_status=(
                collected_fact("ipv6_forwarding_status")
                if ipv6_state is True else None
            ),
        )

    return SandboxContextManifest(
        context_version=SANDBOX_CONTEXT_VERSION,
        control_id=control_id,
        source_state=source_state,
    )
