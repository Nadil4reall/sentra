"""Focused tests for the auditable Milestone 4 compatibility rules."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from src.compatibility_engine.models import (
    CompatibilityDecision,
    EvidenceRecord,
    TriggeredRule,
)
from src.compatibility_engine.rules import (
    evaluate_control_rules,
    list_rule_descriptions,
)
from src.target_profiler.models import FactStatus


def collected(fact: str, value: Any, control_id: str) -> EvidenceRecord:
    """Build one schema-valid collected fact for direct rule evaluation."""

    return EvidenceRecord(
        fact=fact,
        status=FactStatus.COLLECTED,
        value=value,
        requested_by=[control_id],
    )


def unresolved(
    fact: str,
    status: FactStatus,
    control_id: str,
    reason: str = "fixture evidence is intentionally unresolved",
) -> EvidenceRecord:
    """Build one schema-valid non-collected fact without inventing a value."""

    return EvidenceRecord(
        fact=fact,
        status=status,
        value=None,
        requested_by=[control_id],
        reason=reason,
    )


def decisions(findings: tuple[TriggeredRule, ...]) -> list[CompatibilityDecision]:
    return [finding.result for finding in findings]


def rule_ids(findings: tuple[TriggeredRule, ...]) -> list[str]:
    return [finding.rule_id for finding in findings]


def ip_evidence(
    *,
    router: EvidenceRecord | None = None,
    csp: EvidenceRecord | None = None,
    ipv4: EvidenceRecord | None = None,
    ipv6_is_enabled: bool = False,
    ipv6_forwarding: EvidenceRecord | None = None,
    sources: list[str] | None = None,
) -> dict[str, EvidenceRecord]:
    control_id = "3.3.1"
    return {
        "router_role": router or collected("router_role", False, control_id),
        "csp_hosted": csp or collected("csp_hosted", False, control_id),
        "ipv4_forwarding_status": ipv4
        or collected("ipv4_forwarding_status", 0, control_id),
        "ipv6_enabled": collected("ipv6_enabled", ipv6_is_enabled, control_id),
        "ipv6_forwarding_status": ipv6_forwarding
        or collected("ipv6_forwarding_status", 0, control_id),
        "sysctl_parameter_sources": collected(
            "sysctl_parameter_sources", sources or [], control_id
        ),
    }


def ufw_service_evidence(
    *,
    remote: EvidenceRecord | None = None,
    ssh: EvidenceRecord | None = None,
    port_22: EvidenceRecord | None = None,
    service_active: EvidenceRecord | None = None,
) -> dict[str, EvidenceRecord]:
    control_id = "4.2.3"
    return {
        "ufw_service_mask_status": collected(
            "ufw_service_mask_status", "not_masked", control_id
        ),
        "ufw_service_enabled": collected(
            "ufw_service_enabled", "enabled", control_id
        ),
        "ufw_service_active": service_active
        or collected("ufw_service_active", "active", control_id),
        "ufw_status": collected("ufw_status", "active", control_id),
        "remote_network_session_active": remote
        or collected("remote_network_session_active", False, control_id),
        "ssh_session_active": ssh
        or collected("ssh_session_active", False, control_id),
        "ufw_ssh_port_22_rule_present": port_22
        or collected("ufw_ssh_port_22_rule_present", True, control_id),
    }


def ssh_root_evidence(
    *,
    match: EvidenceRecord | None = None,
    includes: EvidenceRecord | None = None,
    administrator: EvidenceRecord | None = None,
    escalation: EvidenceRecord | None = None,
    effective: EvidenceRecord | None = None,
) -> dict[str, EvidenceRecord]:
    control_id = "5.1.20"
    return {
        "sshd_permit_root_login_effective": effective
        or collected(
            "sshd_permit_root_login_effective", "prohibit-password", control_id
        ),
        "sshd_match_directives_present": match
        or collected("sshd_match_directives_present", False, control_id),
        "sshd_include_locations_enabled": includes
        or collected("sshd_include_locations_enabled", [], control_id),
        "individual_administrator_account_available": administrator
        or collected(
            "individual_administrator_account_available", True, control_id
        ),
        "root_escalation_path_available": escalation
        or collected("root_escalation_path_available", True, control_id),
    }


def ssh_empty_password_evidence(
    *,
    match: bool = False,
    includes: list[str] | None = None,
) -> dict[str, EvidenceRecord]:
    control_id = "5.1.19"
    return {
        "sshd_permit_empty_passwords_effective": collected(
            "sshd_permit_empty_passwords_effective", "no", control_id
        ),
        "sshd_match_directives_present": collected(
            "sshd_match_directives_present", match, control_id
        ),
        "sshd_include_locations_enabled": collected(
            "sshd_include_locations_enabled", includes or [], control_id
        ),
    }


def test_overlayfs_container_workload_warns_with_exact_evidence() -> None:
    evidence = {
        "container_applications_in_use": collected(
            "container_applications_in_use", ["docker", "podman"], "1.1.1.6"
        )
    }

    findings = evaluate_control_rules("1.1.1.6", evidence)

    assert rule_ids(findings) == ["overlayfs-container-workload"]
    assert decisions(findings) == [CompatibilityDecision.WARNING]
    assert findings[0].evidence_facts == ["container_applications_in_use"]
    assert "docker, podman" in findings[0].explanation


def test_overlayfs_empty_container_list_does_not_trigger_warning() -> None:
    evidence = {
        "container_applications_in_use": collected(
            "container_applications_in_use", [], "1.1.1.6"
        )
    }

    assert evaluate_control_rules("1.1.1.6", evidence) == ()


@pytest.mark.parametrize("status", [FactStatus.UNAVAILABLE, FactStatus.ERROR])
def test_overlayfs_missing_technical_evidence_is_insufficient(
    status: FactStatus,
) -> None:
    evidence = {
        "container_applications_in_use": unresolved(
            "container_applications_in_use", status, "1.1.1.6"
        )
    }

    findings = evaluate_control_rules("1.1.1.6", evidence)

    assert decisions(findings) == [CompatibilityDecision.INSUFFICIENT_EVIDENCE]
    assert "container_applications_in_use" in findings[0].explanation


def test_overlayfs_absent_fact_is_rejected_instead_of_inventing_evidence() -> None:
    with pytest.raises(ValueError, match="Rule evidence is missing"):
        evaluate_control_rules("1.1.1.6", {})


def test_ip_forwarding_zero_is_not_proof_of_a_conflict_or_safety() -> None:
    evidence = ip_evidence(
        ipv4=collected("ipv4_forwarding_status", 0, "3.3.1"),
        ipv6_is_enabled=False,
        ipv6_forwarding=unresolved(
            "ipv6_forwarding_status", FactStatus.UNAVAILABLE, "3.3.1"
        ),
    )

    assert evaluate_control_rules("3.3.1", evidence) == ()


def test_ip_forwarding_unsupported_router_context_requires_review() -> None:
    evidence = ip_evidence(
        router=unresolved("router_role", FactStatus.UNSUPPORTED, "3.3.1")
    )

    findings = evaluate_control_rules("3.3.1", evidence)

    assert rule_ids(findings) == ["ip-forwarding-deployment-role"]
    assert decisions(findings) == [CompatibilityDecision.REVIEW_REQUIRED]
    assert "router_role" in findings[0].explanation


def test_ip_forwarding_router_role_true_warns_even_if_csp_is_unknown() -> None:
    evidence = ip_evidence(
        router=collected("router_role", True, "3.3.1"),
        csp=unresolved("csp_hosted", FactStatus.UNSUPPORTED, "3.3.1"),
    )

    findings = evaluate_control_rules("3.3.1", evidence)

    assert decisions(findings) == [CompatibilityDecision.WARNING]
    assert "router-role" in findings[0].explanation


def test_ip_forwarding_multiple_sysctl_sources_require_review() -> None:
    findings = evaluate_control_rules(
        "3.3.1",
        ip_evidence(sources=["/etc/sysctl.d/10-a.conf", "/etc/sysctl.conf"]),
    )

    assert rule_ids(findings) == ["ip-forwarding-source-precedence-review"]
    assert decisions(findings) == [CompatibilityDecision.REVIEW_REQUIRED]
    assert "assignments and precedence" in findings[0].explanation


def test_ufw_remote_session_triggers_documented_connection_warning() -> None:
    control_id = "4.2.3"
    findings = evaluate_control_rules(
        control_id,
        ufw_service_evidence(
            remote=collected("remote_network_session_active", True, control_id)
        ),
    )

    assert rule_ids(findings) == ["ufw-live-remote-session"]
    assert decisions(findings) == [CompatibilityDecision.WARNING]


def test_ufw_ssh_session_without_port_22_rule_triggers_both_warnings() -> None:
    control_id = "4.2.3"
    findings = evaluate_control_rules(
        control_id,
        ufw_service_evidence(
            ssh=collected("ssh_session_active", True, control_id),
            port_22=collected("ufw_ssh_port_22_rule_present", False, control_id),
        ),
    )

    assert rule_ids(findings) == [
        "ufw-live-remote-session",
        "ufw-ssh-22-safeguard",
    ]
    assert decisions(findings) == [
        CompatibilityDecision.WARNING,
        CompatibilityDecision.WARNING,
    ]
    assert "does not establish which port" in findings[1].explanation


def test_ufw_port_22_rule_does_not_erase_live_session_warning() -> None:
    control_id = "4.2.3"
    findings = evaluate_control_rules(
        control_id,
        ufw_service_evidence(
            ssh=collected("ssh_session_active", True, control_id),
            port_22=collected("ufw_ssh_port_22_rule_present", True, control_id),
        ),
    )

    assert rule_ids(findings) == ["ufw-live-remote-session"]
    assert decisions(findings) == [CompatibilityDecision.WARNING]


def test_ufw_absent_port_22_rule_without_known_session_does_not_warn() -> None:
    control_id = "4.2.3"
    findings = evaluate_control_rules(
        control_id,
        ufw_service_evidence(
            port_22=collected("ufw_ssh_port_22_rule_present", False, control_id)
        ),
    )

    assert findings == ()


def test_ufw_unknown_session_and_absent_port_22_rule_require_review() -> None:
    control_id = "4.2.3"
    findings = evaluate_control_rules(
        control_id,
        ufw_service_evidence(
            remote=unresolved(
                "remote_network_session_active", FactStatus.UNSUPPORTED, control_id
            ),
            ssh=unresolved("ssh_session_active", FactStatus.UNSUPPORTED, control_id),
            port_22=collected("ufw_ssh_port_22_rule_present", False, control_id),
        ),
    )

    assert decisions(findings) == [
        CompatibilityDecision.REVIEW_REQUIRED,
        CompatibilityDecision.REVIEW_REQUIRED,
    ]
    assert "active SSH port must not be assumed" in findings[1].explanation


def test_ufw_live_ssh_warning_survives_missing_port_evidence() -> None:
    control_id = "4.2.3"
    findings = evaluate_control_rules(
        control_id,
        ufw_service_evidence(
            ssh=collected("ssh_session_active", True, control_id),
            port_22=unresolved(
                "ufw_ssh_port_22_rule_present", FactStatus.UNAVAILABLE, control_id
            ),
        ),
    )

    assert decisions(findings) == [
        CompatibilityDecision.WARNING,
        CompatibilityDecision.INSUFFICIENT_EVIDENCE,
    ]


def test_ufw_missing_service_state_is_insufficient_evidence() -> None:
    control_id = "4.2.3"
    findings = evaluate_control_rules(
        control_id,
        ufw_service_evidence(
            service_active=unresolved(
                "ufw_service_active", FactStatus.ERROR, control_id
            )
        ),
    )

    assert rule_ids(findings) == ["ufw-service-state-evidence"]
    assert decisions(findings) == [CompatibilityDecision.INSUFFICIENT_EVIDENCE]


def test_ssh_root_unsupported_administrator_context_requires_review() -> None:
    control_id = "5.1.20"
    findings = evaluate_control_rules(
        control_id,
        ssh_root_evidence(
            administrator=unresolved(
                "individual_administrator_account_available",
                FactStatus.UNSUPPORTED,
                control_id,
            ),
            escalation=unresolved(
                "root_escalation_path_available", FactStatus.UNSUPPORTED, control_id
            ),
        ),
    )

    assert rule_ids(findings) == ["ssh-root-login-administrator-path"]
    assert decisions(findings) == [CompatibilityDecision.REVIEW_REQUIRED]


@pytest.mark.parametrize(
    "fact_name",
    [
        "individual_administrator_account_available",
        "root_escalation_path_available",
    ],
)
def test_ssh_root_collected_false_administrator_path_warns(fact_name: str) -> None:
    control_id = "5.1.20"
    kwargs = {
        "administrator": collected(
            "individual_administrator_account_available", True, control_id
        ),
        "escalation": collected("root_escalation_path_available", True, control_id),
    }
    argument = "administrator" if fact_name.startswith("individual") else "escalation"
    kwargs[argument] = collected(fact_name, False, control_id)

    findings = evaluate_control_rules(control_id, ssh_root_evidence(**kwargs))

    assert decisions(findings) == [CompatibilityDecision.WARNING]
    assert fact_name in findings[0].explanation


def test_ssh_root_match_and_include_complexity_each_require_review() -> None:
    control_id = "5.1.20"
    findings = evaluate_control_rules(
        control_id,
        ssh_root_evidence(
            match=collected("sshd_match_directives_present", True, control_id),
            includes=collected(
                "sshd_include_locations_enabled",
                ["/etc/ssh/sshd_config.d/*.conf"],
                control_id,
            ),
        ),
    )

    assert rule_ids(findings) == [
        "ssh-root-login-match-context",
        "ssh-root-login-include-precedence",
    ]
    assert decisions(findings) == [
        CompatibilityDecision.REVIEW_REQUIRED,
        CompatibilityDecision.REVIEW_REQUIRED,
    ]


def test_ssh_empty_password_match_and_include_complexity_require_review() -> None:
    findings = evaluate_control_rules(
        "5.1.19",
        ssh_empty_password_evidence(
            match=True, includes=["/etc/ssh/sshd_config.d/*.conf"]
        ),
    )

    assert rule_ids(findings) == [
        "ssh-empty-passwords-match-context",
        "ssh-empty-passwords-include-precedence",
    ]
    assert all(
        finding.result is CompatibilityDecision.REVIEW_REQUIRED
        for finding in findings
    )


@pytest.mark.parametrize(
    ("fact", "expected"),
    [
        (collected("cramfs_filesystem_required", False, "1.1.1.1"), None),
        (
            collected("cramfs_filesystem_required", True, "1.1.1.1"),
            CompatibilityDecision.WARNING,
        ),
        (
            unresolved(
                "cramfs_filesystem_required", FactStatus.UNSUPPORTED, "1.1.1.1"
            ),
            CompatibilityDecision.REVIEW_REQUIRED,
        ),
        (
            unresolved(
                "cramfs_filesystem_required", FactStatus.UNAVAILABLE, "1.1.1.1"
            ),
            CompatibilityDecision.INSUFFICIENT_EVIDENCE,
        ),
    ],
)
def test_cramfs_workload_rule_preserves_true_false_and_uncertainty(
    fact: EvidenceRecord, expected: CompatibilityDecision | None
) -> None:
    findings = evaluate_control_rules("1.1.1.1", {fact.fact: fact})

    assert decisions(findings) == ([] if expected is None else [expected])


def firewall_install_evidence(
    *, iptables: bool, utilities: list[str]
) -> Mapping[str, EvidenceRecord]:
    control_id = "4.2.1"
    return {
        "ufw_installed": collected("ufw_installed", True, control_id),
        "iptables_installed": collected(
            "iptables_installed", iptables, control_id
        ),
        "installed_firewall_utilities": collected(
            "installed_firewall_utilities", utilities, control_id
        ),
    }


def test_ufw_iptables_is_a_prerequisite_not_an_other_firewall_conflict() -> None:
    evidence = firewall_install_evidence(
        iptables=True, utilities=["ufw", "iptables"]
    )

    assert evaluate_control_rules("4.2.1", evidence) == ()


def test_ufw_missing_iptables_prerequisite_warns() -> None:
    findings = evaluate_control_rules(
        "4.2.1", firewall_install_evidence(iptables=False, utilities=["ufw"])
    )

    assert rule_ids(findings) == ["ufw-iptables-prerequisite"]
    assert decisions(findings) == [CompatibilityDecision.WARNING]


def test_ufw_other_installed_firewall_utility_warns() -> None:
    findings = evaluate_control_rules(
        "4.2.1",
        firewall_install_evidence(
            iptables=True, utilities=["ufw", "iptables", "nftables"]
        ),
    )

    assert rule_ids(findings) == ["ufw-other-firewall-utility"]
    assert decisions(findings) == [CompatibilityDecision.WARNING]
    assert "nftables" in findings[0].explanation


def auditd_evidence(
    missing_status: FactStatus | None = None,
) -> dict[str, EvidenceRecord]:
    control_id = "6.2.1.2"
    evidence = {
        "auditd_service_present": collected(
            "auditd_service_present", False, control_id
        ),
        "auditd_service_mask_status": collected(
            "auditd_service_mask_status", "masked", control_id
        ),
        "auditd_service_enabled": collected(
            "auditd_service_enabled", "disabled", control_id
        ),
        "auditd_service_active": collected(
            "auditd_service_active", "inactive", control_id
        ),
    }
    if missing_status is not None:
        evidence["auditd_service_active"] = unresolved(
            "auditd_service_active", missing_status, control_id
        )
    return evidence


def shadow_evidence(
    missing_status: FactStatus | None = None,
) -> dict[str, EvidenceRecord]:
    control_id = "7.1.5"
    evidence = {
        "shadow_file_mode": collected("shadow_file_mode", "0640", control_id),
        "shadow_file_owner_uid": collected(
            "shadow_file_owner_uid", 0, control_id
        ),
        "shadow_file_group_gid": collected(
            "shadow_file_group_gid", 42, control_id
        ),
        "shadow_group_gid": collected("shadow_group_gid", 42, control_id),
    }
    if missing_status is not None:
        evidence["shadow_group_gid"] = unresolved(
            "shadow_group_gid", missing_status, control_id
        )
    return evidence


@pytest.mark.parametrize(
    ("control_id", "evidence"),
    [
        ("6.2.1.2", auditd_evidence()),
        ("7.1.5", shadow_evidence()),
    ],
)
def test_controls_without_conflict_rules_do_not_become_compliance_checks(
    control_id: str, evidence: Mapping[str, EvidenceRecord]
) -> None:
    assert evaluate_control_rules(control_id, evidence) == ()


@pytest.mark.parametrize(
    ("control_id", "evidence"),
    [
        ("6.2.1.2", auditd_evidence(FactStatus.UNAVAILABLE)),
        ("7.1.5", shadow_evidence(FactStatus.ERROR)),
    ],
)
def test_auditd_and_shadow_missing_evidence_is_insufficient(
    control_id: str, evidence: Mapping[str, EvidenceRecord]
) -> None:
    findings = evaluate_control_rules(control_id, evidence)

    assert decisions(findings) == [CompatibilityDecision.INSUFFICIENT_EVIDENCE]


def passwd_evidence(
    mode: EvidenceRecord | None = None,
) -> dict[str, EvidenceRecord]:
    control_id = "7.1.1"
    return {
        "passwd_file_mode": mode
        or collected("passwd_file_mode", "0644", control_id),
        "passwd_file_owner_uid": collected("passwd_file_owner_uid", 0, control_id),
        "passwd_file_group_gid": collected("passwd_file_group_gid", 0, control_id),
    }


def test_passwd_readability_is_contextual_review_not_permission_pass_fail() -> None:
    findings = evaluate_control_rules("7.1.1", passwd_evidence())

    assert rule_ids(findings) == ["passwd-readability-preservation-review"]
    assert decisions(findings) == [CompatibilityDecision.REVIEW_REQUIRED]
    assert "not converted into PASS/FAIL" in findings[0].explanation


def test_passwd_missing_mode_is_insufficient_before_contextual_review() -> None:
    mode = unresolved("passwd_file_mode", FactStatus.UNAVAILABLE, "7.1.1")

    findings = evaluate_control_rules("7.1.1", passwd_evidence(mode))

    assert decisions(findings) == [CompatibilityDecision.INSUFFICIENT_EVIDENCE]


def test_rule_evaluation_is_deterministic_and_does_not_mutate_evidence() -> None:
    control_id = "4.2.3"
    evidence = ufw_service_evidence(
        ssh=collected("ssh_session_active", True, control_id),
        port_22=collected("ufw_ssh_port_22_rule_present", False, control_id),
    )
    before = {
        name: item.model_dump(mode="json") for name, item in evidence.items()
    }

    first = evaluate_control_rules(control_id, evidence)
    second = evaluate_control_rules(control_id, evidence)

    assert first == second
    assert {
        name: item.model_dump(mode="json") for name, item in evidence.items()
    } == before


def test_rule_catalog_has_stable_unique_ids_and_traceable_source_basis() -> None:
    descriptions = list_rule_descriptions()
    rule_ids_in_order = [item.rule_id for item in descriptions]

    assert len(rule_ids_in_order) == len(set(rule_ids_in_order))
    assert [item.control_id for item in descriptions] == [
        "1.1.1.1",
        "1.1.1.6",
        "3.3.1",
        "3.3.1",
        "4.2.1",
        "4.2.1",
        "4.2.3",
        "4.2.3",
        "4.2.3",
        "5.1.19",
        "5.1.19",
        "5.1.19",
        "5.1.20",
        "5.1.20",
        "5.1.20",
        "5.1.20",
        "6.2.1.2",
        "7.1.1",
        "7.1.5",
    ]
    assert all(item.source_basis for item in descriptions)
    assert all(item.evidence_facts for item in descriptions)
    assert all(
        basis.startswith(
            ("possible_conflicts:", "prerequisites:", "evidence.notes:", "required_target_facts:")
        )
        for item in descriptions
        for basis in item.source_basis
    )


def test_unknown_control_has_no_implicit_fallback_rule() -> None:
    with pytest.raises(ValueError, match="No Milestone 4 rule set registered"):
        evaluate_control_rules("9.9.9", {})
