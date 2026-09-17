"""Explicit, deterministic compatibility rules for the ten PoC controls.

The rule set is intentionally ordinary Python.  It contains no expression
language, dynamic evaluation, command execution, or CIS Audit/Remediation text.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from src.target_profiler.models import FactStatus

from .models import (
    CompatibilityDecision,
    EvidenceRecord,
    RuleDescription,
    TriggeredRule,
)


RuleEvaluator = Callable[[Mapping[str, EvidenceRecord]], TriggeredRule | None]


@dataclass(frozen=True)
class DeterministicRule:
    """One catalog entry paired with its fixed Python evaluator."""

    description: RuleDescription
    evaluator: RuleEvaluator


def _description(
    rule_id: str,
    control_id: str,
    purpose: str,
    source_basis: Sequence[str],
    evidence_facts: Sequence[str],
) -> RuleDescription:
    return RuleDescription(
        rule_id=rule_id,
        control_id=control_id,
        purpose=purpose,
        source_basis=list(source_basis),
        evidence_facts=list(evidence_facts),
    )


def _finding(
    rule: RuleDescription,
    result: CompatibilityDecision,
    explanation: str,
) -> TriggeredRule:
    return TriggeredRule(
        rule_id=rule.rule_id,
        result=result,
        explanation=explanation,
        source_basis=list(rule.source_basis),
        evidence_facts=list(rule.evidence_facts),
    )


def _records(
    evidence: Mapping[str, EvidenceRecord], names: Sequence[str]
) -> list[EvidenceRecord]:
    missing = [name for name in names if name not in evidence]
    if missing:
        raise ValueError(
            f"Rule evidence is missing from the control result: {missing}"
        )
    return [evidence[name] for name in names]


def _technical_gap(
    rule: RuleDescription, records: Sequence[EvidenceRecord]
) -> TriggeredRule | None:
    incomplete = [item for item in records if item.status is not FactStatus.COLLECTED]
    if not incomplete:
        return None
    states = ", ".join(f"{item.fact}={item.status.value}" for item in incomplete)
    return _finding(
        rule,
        CompatibilityDecision.INSUFFICIENT_EVIDENCE,
        f"Rule-required technical evidence is incomplete: {states}.",
    )


def _invalid_type(
    rule: RuleDescription, fact_name: str, expected: str
) -> TriggeredRule:
    return _finding(
        rule,
        CompatibilityDecision.INSUFFICIENT_EVIDENCE,
        f"Collected evidence {fact_name} did not have the expected {expected} value.",
    )


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_int(value: Any) -> bool:
    return type(value) is int


_CRAMFS = _description(
    "cramfs-required-workload",
    "1.1.1.1",
    "Preserve a workload that requires the cramfs filesystem.",
    ["possible_conflicts: The target requires the cramfs filesystem type."],
    ["cramfs_filesystem_required"],
)


def _cramfs_required(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    item = _records(evidence, _CRAMFS.evidence_facts)[0]
    if item.status is FactStatus.UNSUPPORTED:
        return _finding(
            _CRAMFS,
            CompatibilityDecision.REVIEW_REQUIRED,
            "Whether the target workload requires cramfs needs workload-owner or "
            "administrator context.",
        )

    gap = _technical_gap(_CRAMFS, [item])
    if gap:
        return gap
    if type(item.value) is not bool:
        return _invalid_type(_CRAMFS, item.fact, "boolean")
    if item.value:
        return _finding(
            _CRAMFS,
            CompatibilityDecision.WARNING,
            "Collected evidence says this target requires cramfs, matching the "
            "documented workload conflict.",
        )
    return None


_OVERLAYFS = _description(
    "overlayfs-container-workload",
    "1.1.1.6",
    "Identify the documented OverlayFS concern for active container applications.",
    [
        "possible_conflicts: Detected container applications may be severely "
        "disrupted by disabling overlayfs.",
        "evidence.notes: CIS Impact names Docker, Kubernetes, Podman, LXC, and "
        "other container applications.",
    ],
    ["container_applications_in_use"],
)


def _overlayfs_container_workload(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    item = _records(evidence, _OVERLAYFS.evidence_facts)[0]
    gap = _technical_gap(_OVERLAYFS, [item])
    if gap:
        return gap
    if not _is_string_list(item.value):
        return _invalid_type(_OVERLAYFS, item.fact, "list of strings")
    if item.value:
        applications = ", ".join(item.value)
        return _finding(
            _OVERLAYFS,
            CompatibilityDecision.WARNING,
            f"Container workload evidence ({applications}) matches the documented "
            "OverlayFS compatibility concern.",
        )
    return None


_IP_ROLE = _description(
    "ip-forwarding-deployment-role",
    "3.3.1",
    "Review router and cloud deployment roles before changing forwarding.",
    [
        "possible_conflicts: Systems configured as routers require IP forwarding.",
        "possible_conflicts: Many Cloud Service Provider hosted systems require IP "
        "forwarding.",
    ],
    ["router_role", "csp_hosted"],
)


def _ip_forwarding_role(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    items = _records(evidence, _IP_ROLE.evidence_facts)
    collected_true: list[str] = []
    unsupported: list[str] = []
    incomplete: list[str] = []
    for item in items:
        if item.status is FactStatus.COLLECTED:
            if type(item.value) is not bool:
                return _invalid_type(_IP_ROLE, item.fact, "boolean")
            if item.value:
                collected_true.append(item.fact)
        elif item.status is FactStatus.UNSUPPORTED:
            unsupported.append(item.fact)
        else:
            incomplete.append(item.fact)

    if "router_role" in collected_true:
        return _finding(
            _IP_ROLE,
            CompatibilityDecision.WARNING,
            "Collected router-role evidence matches the documented requirement for "
            "IP forwarding.",
        )
    if incomplete:
        return _finding(
            _IP_ROLE,
            CompatibilityDecision.INSUFFICIENT_EVIDENCE,
            "Deployment-role evidence is unavailable or erroneous: "
            + ", ".join(incomplete)
            + ".",
        )
    if "csp_hosted" in collected_true:
        return _finding(
            _IP_ROLE,
            CompatibilityDecision.REVIEW_REQUIRED,
            "The target is CSP-hosted; the enrichment says many such systems require "
            "forwarding, so target-specific review is required.",
        )
    if unsupported:
        return _finding(
            _IP_ROLE,
            CompatibilityDecision.REVIEW_REQUIRED,
            "Router or cloud deployment role requires administrator context: "
            + ", ".join(unsupported)
            + ".",
        )
    return None


_IP_SOURCES = _description(
    "ip-forwarding-source-precedence-review",
    "3.3.1",
    "Preserve forwarding-state and sysctl-source uncertainty.",
    [
        "possible_conflicts: Later sysctl assignments can override an earlier setting.",
        "evidence.notes: The IPv6 parameter applies only when IPv6 is enabled.",
    ],
    [
        "ipv4_forwarding_status",
        "ipv6_enabled",
        "ipv6_forwarding_status",
        "sysctl_parameter_sources",
    ],
)


def _ip_forwarding_sources(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    ipv4, ipv6_enabled, ipv6_forwarding, sources = _records(
        evidence, _IP_SOURCES.evidence_facts
    )
    required = [ipv4, ipv6_enabled, sources]
    gap = _technical_gap(_IP_SOURCES, required)
    if gap:
        return gap
    if not _is_int(ipv4.value):
        return _invalid_type(_IP_SOURCES, ipv4.fact, "integer")
    if type(ipv6_enabled.value) is not bool:
        return _invalid_type(_IP_SOURCES, ipv6_enabled.fact, "boolean")
    if not _is_string_list(sources.value):
        return _invalid_type(_IP_SOURCES, sources.fact, "list of strings")
    if ipv6_enabled.value:
        gap = _technical_gap(_IP_SOURCES, [ipv6_forwarding])
        if gap:
            return gap
        if not _is_int(ipv6_forwarding.value):
            return _invalid_type(_IP_SOURCES, ipv6_forwarding.fact, "integer")
    if len(sources.value) > 1:
        return _finding(
            _IP_SOURCES,
            CompatibilityDecision.REVIEW_REQUIRED,
            "Multiple sysctl source files are present; their assignments and "
            "precedence require review. Current forwarding values alone are not a "
            "safety conclusion.",
        )
    return None


_UFW_IPTABLES = _description(
    "ufw-iptables-prerequisite",
    "4.2.1",
    "Check the explicit iptables package prerequisite for UFW.",
    ["prerequisites: UFW depends on the iptables package."],
    ["ufw_installed", "iptables_installed"],
)


def _ufw_iptables_prerequisite(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    items = _records(evidence, _UFW_IPTABLES.evidence_facts)
    gap = _technical_gap(_UFW_IPTABLES, items)
    if gap:
        return gap
    if any(type(item.value) is not bool for item in items):
        invalid = next(item for item in items if type(item.value) is not bool)
        return _invalid_type(_UFW_IPTABLES, invalid.fact, "boolean")
    if items[1].value is False:
        return _finding(
            _UFW_IPTABLES,
            CompatibilityDecision.WARNING,
            "The explicit iptables package prerequisite is not present on the target.",
        )
    return None


_UFW_OTHER = _description(
    "ufw-other-firewall-utility",
    "4.2.1",
    "Identify another installed firewall utility without treating iptables as a "
    "conflict.",
    [
        "possible_conflicts: Another firewall utility is already installed or "
        "configured.",
        "evidence.notes: CIS states that only one firewall utility should be "
        "installed and configured.",
    ],
    ["installed_firewall_utilities"],
)


def _ufw_other_firewall(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    item = _records(evidence, _UFW_OTHER.evidence_facts)[0]
    gap = _technical_gap(_UFW_OTHER, [item])
    if gap:
        return gap
    if not _is_string_list(item.value):
        return _invalid_type(_UFW_OTHER, item.fact, "list of strings")
    other = sorted(set(item.value) - {"ufw", "iptables"})
    if other:
        return _finding(
            _UFW_OTHER,
            CompatibilityDecision.WARNING,
            "Another firewall utility is installed: " + ", ".join(other) + ".",
        )
    return None


_UFW_SERVICE = _description(
    "ufw-service-state-evidence",
    "4.2.3",
    "Require the UFW state evidence named by the enrichment.",
    [
        "required_target_facts: UFW mask, enabled, active, and firewall status.",
        "evidence.notes: CIS explicitly audits and changes these UFW states.",
    ],
    [
        "ufw_service_mask_status",
        "ufw_service_enabled",
        "ufw_service_active",
        "ufw_status",
    ],
)


def _ufw_service_evidence(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    items = _records(evidence, _UFW_SERVICE.evidence_facts)
    gap = _technical_gap(_UFW_SERVICE, items)
    if gap:
        return gap
    invalid = next((item for item in items if not isinstance(item.value, str)), None)
    if invalid:
        return _invalid_type(_UFW_SERVICE, invalid.fact, "string")
    return None


_UFW_SESSION = _description(
    "ufw-live-remote-session",
    "4.2.3",
    "Identify the documented connection-loss risk during remote administration.",
    [
        "possible_conflicts: Enabling or starting UFW may drop existing connections, "
        "including SSH.",
        "possible_conflicts: Network firewall changes can lock an administrator out.",
    ],
    ["remote_network_session_active", "ssh_session_active"],
)


def _ufw_live_session(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    items = _records(evidence, _UFW_SESSION.evidence_facts)
    true_facts: list[str] = []
    unsupported: list[str] = []
    incomplete: list[str] = []
    for item in items:
        if item.status is FactStatus.COLLECTED:
            if type(item.value) is not bool:
                return _invalid_type(_UFW_SESSION, item.fact, "boolean")
            if item.value:
                true_facts.append(item.fact)
        elif item.status is FactStatus.UNSUPPORTED:
            unsupported.append(item.fact)
        else:
            incomplete.append(item.fact)

    if true_facts:
        return _finding(
            _UFW_SESSION,
            CompatibilityDecision.WARNING,
            "An active remote-management context matches the documented UFW "
            "connection-loss and lockout concern: "
            + ", ".join(true_facts)
            + ".",
        )
    if incomplete:
        return _finding(
            _UFW_SESSION,
            CompatibilityDecision.INSUFFICIENT_EVIDENCE,
            "Remote-session evidence is unavailable or erroneous: "
            + ", ".join(incomplete)
            + ".",
        )
    if unsupported:
        return _finding(
            _UFW_SESSION,
            CompatibilityDecision.REVIEW_REQUIRED,
            "Absence of a remote management session could not be established: "
            + ", ".join(unsupported)
            + ".",
        )
    return None


_UFW_SSH_22 = _description(
    "ufw-ssh-22-safeguard",
    "4.2.3",
    "Check only the documented TCP/22 safeguard when an SSH session is known.",
    [
        "prerequisites: When preserving SSH on TCP port 22, add an allow rule before "
        "enabling UFW.",
        "evidence.notes: Alternate SSH ports require manual review.",
    ],
    ["ssh_session_active", "ufw_ssh_port_22_rule_present"],
)


def _ufw_ssh_22_safeguard(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    session, port_rule = _records(evidence, _UFW_SSH_22.evidence_facts)
    if session.status is FactStatus.UNSUPPORTED:
        if (
            port_rule.status is FactStatus.COLLECTED
            and port_rule.value is False
        ):
            return _finding(
                _UFW_SSH_22,
                CompatibilityDecision.REVIEW_REQUIRED,
                "The documented TCP/22 safeguard was not found and SSH session "
                "context is unknown; the active SSH port must not be assumed.",
            )
        return None

    gap = _technical_gap(_UFW_SSH_22, [session])
    if gap:
        return gap
    if type(session.value) is not bool:
        return _invalid_type(_UFW_SSH_22, session.fact, "boolean")
    if not session.value:
        return None

    gap = _technical_gap(_UFW_SSH_22, [port_rule])
    if gap:
        return gap
    if type(port_rule.value) is not bool:
        return _invalid_type(_UFW_SSH_22, port_rule.fact, "boolean")
    if port_rule.value is False:
        return _finding(
            _UFW_SSH_22,
            CompatibilityDecision.WARNING,
            "An SSH session is active and the documented TCP/22 allow-rule safeguard "
            "was not found; this does not establish which port the session uses.",
        )
    return None


_SSH_EMPTY_EFFECTIVE = _description(
    "ssh-empty-passwords-effective-evidence",
    "5.1.19",
    "Require the effective setting used alongside configuration-context checks.",
    ["required_target_facts: sshd_permit_empty_passwords_effective."],
    ["sshd_permit_empty_passwords_effective"],
)


def _string_evidence_rule(
    rule: RuleDescription, evidence: Mapping[str, EvidenceRecord]
) -> TriggeredRule | None:
    item = _records(evidence, rule.evidence_facts)[0]
    gap = _technical_gap(rule, [item])
    if gap:
        return gap
    if not isinstance(item.value, str):
        return _invalid_type(rule, item.fact, "string")
    return None


_SSH_EMPTY_MATCH = _description(
    "ssh-empty-passwords-match-context",
    "5.1.19",
    "Require review when Match directives can change connection-specific behavior.",
    [
        "possible_conflicts: Match directives can change the effective "
        "PermitEmptyPasswords value for specific connections."
    ],
    ["sshd_match_directives_present"],
)


def _boolean_review_rule(
    rule: RuleDescription,
    evidence: Mapping[str, EvidenceRecord],
    explanation: str,
) -> TriggeredRule | None:
    item = _records(evidence, rule.evidence_facts)[0]
    gap = _technical_gap(rule, [item])
    if gap:
        return gap
    if type(item.value) is not bool:
        return _invalid_type(rule, item.fact, "boolean")
    if item.value:
        return _finding(
            rule,
            CompatibilityDecision.REVIEW_REQUIRED,
            explanation,
        )
    return None


_SSH_EMPTY_INCLUDE = _description(
    "ssh-empty-passwords-include-precedence",
    "5.1.19",
    "Require review when Include ordering can affect the effective configuration.",
    [
        "possible_conflicts: Include ordering and first-occurrence precedence can "
        "change the effective setting."
    ],
    ["sshd_include_locations_enabled"],
)


def _include_review_rule(
    rule: RuleDescription,
    evidence: Mapping[str, EvidenceRecord],
    explanation: str,
) -> TriggeredRule | None:
    item = _records(evidence, rule.evidence_facts)[0]
    gap = _technical_gap(rule, [item])
    if gap:
        return gap
    if not _is_string_list(item.value):
        return _invalid_type(rule, item.fact, "list of strings")
    if item.value:
        return _finding(
            rule,
            CompatibilityDecision.REVIEW_REQUIRED,
            explanation,
        )
    return None


_SSH_ROOT_EFFECTIVE = _description(
    "ssh-root-login-effective-evidence",
    "5.1.20",
    "Require the effective setting used alongside access-path and context checks.",
    ["required_target_facts: sshd_permit_root_login_effective."],
    ["sshd_permit_root_login_effective"],
)


_SSH_ROOT_MATCH = _description(
    "ssh-root-login-match-context",
    "5.1.20",
    "Require review when Match directives can change connection-specific behavior.",
    [
        "possible_conflicts: Match directives can change the effective PermitRootLogin "
        "value for specific connections."
    ],
    ["sshd_match_directives_present"],
)


_SSH_ROOT_INCLUDE = _description(
    "ssh-root-login-include-precedence",
    "5.1.20",
    "Require review when Include ordering can affect the effective configuration.",
    [
        "possible_conflicts: Include ordering and first-occurrence precedence can "
        "change the effective setting."
    ],
    ["sshd_include_locations_enabled"],
)


_SSH_ROOT_PATH = _description(
    "ssh-root-login-administrator-path",
    "5.1.20",
    "Preserve individual-administrator and root-escalation access context.",
    [
        "evidence.notes: The rationale describes individual administrator "
        "authentication followed by root escalation; availability requires review."
    ],
    [
        "individual_administrator_account_available",
        "root_escalation_path_available",
    ],
)


def _ssh_root_admin_path(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    items = _records(evidence, _SSH_ROOT_PATH.evidence_facts)
    false_facts: list[str] = []
    unsupported: list[str] = []
    incomplete: list[str] = []
    for item in items:
        if item.status is FactStatus.COLLECTED:
            if type(item.value) is not bool:
                return _invalid_type(_SSH_ROOT_PATH, item.fact, "boolean")
            if item.value is False:
                false_facts.append(item.fact)
        elif item.status is FactStatus.UNSUPPORTED:
            unsupported.append(item.fact)
        else:
            incomplete.append(item.fact)

    if false_facts:
        return _finding(
            _SSH_ROOT_PATH,
            CompatibilityDecision.WARNING,
            "Collected evidence shows part of the documented administrator-to-root "
            "access path is absent: "
            + ", ".join(false_facts)
            + ".",
        )
    if incomplete:
        return _finding(
            _SSH_ROOT_PATH,
            CompatibilityDecision.INSUFFICIENT_EVIDENCE,
            "Administrator access-path evidence is unavailable or erroneous: "
            + ", ".join(incomplete)
            + ".",
        )
    if unsupported:
        return _finding(
            _SSH_ROOT_PATH,
            CompatibilityDecision.REVIEW_REQUIRED,
            "Administrator fallback and escalation context requires administrator "
            "review: "
            + ", ".join(unsupported)
            + ".",
        )
    return None


_AUDITD_EVIDENCE = _description(
    "auditd-required-evidence",
    "6.2.1.2",
    "Require the service evidence named by an enrichment with no explicit conflict "
    "rule.",
    [
        "required_target_facts: auditd service presence, mask, enabled, and active "
        "state."
    ],
    [
        "auditd_service_present",
        "auditd_service_mask_status",
        "auditd_service_enabled",
        "auditd_service_active",
    ],
)


def _auditd_evidence(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    items = _records(evidence, _AUDITD_EVIDENCE.evidence_facts)
    gap = _technical_gap(_AUDITD_EVIDENCE, items)
    if gap:
        return gap
    present, mask_status, enabled, active = items
    if type(present.value) is not bool:
        return _invalid_type(_AUDITD_EVIDENCE, present.fact, "boolean")
    invalid = next(
        (
            item
            for item in (mask_status, enabled, active)
            if not isinstance(item.value, str)
        ),
        None,
    )
    if invalid:
        return _invalid_type(_AUDITD_EVIDENCE, invalid.fact, "string")
    return None


_PASSWD_READABILITY = _description(
    "passwd-readability-preservation-review",
    "7.1.1",
    "Require contextual review because the enrichment does not define which "
    "consumers must retain read access.",
    [
        "possible_conflicts: /etc/passwd must remain readable for system utilities "
        "to operate."
    ],
    ["passwd_file_mode", "passwd_file_owner_uid", "passwd_file_group_gid"],
)


def _passwd_readability(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    items = _records(evidence, _PASSWD_READABILITY.evidence_facts)
    gap = _technical_gap(_PASSWD_READABILITY, items)
    if gap:
        return gap
    mode, owner, group = items
    if not isinstance(mode.value, str):
        return _invalid_type(_PASSWD_READABILITY, mode.fact, "octal mode string")
    if not _is_int(owner.value):
        return _invalid_type(_PASSWD_READABILITY, owner.fact, "integer")
    if not _is_int(group.value):
        return _invalid_type(_PASSWD_READABILITY, group.fact, "integer")
    return _finding(
        _PASSWD_READABILITY,
        CompatibilityDecision.REVIEW_REQUIRED,
        "The enrichment requires /etc/passwd readability to be preserved but does "
        "not define the consuming identities or a compatibility threshold; "
        "permission values are therefore not converted into PASS/FAIL.",
    )


_SHADOW_EVIDENCE = _description(
    "shadow-required-evidence",
    "7.1.5",
    "Require the file and target shadow-group evidence named by an enrichment with "
    "no explicit conflict rule.",
    [
        "required_target_facts: shadow file mode/owner/group and target shadow-group "
        "GID."
    ],
    [
        "shadow_file_mode",
        "shadow_file_owner_uid",
        "shadow_file_group_gid",
        "shadow_group_gid",
    ],
)


def _shadow_evidence(
    evidence: Mapping[str, EvidenceRecord],
) -> TriggeredRule | None:
    items = _records(evidence, _SHADOW_EVIDENCE.evidence_facts)
    gap = _technical_gap(_SHADOW_EVIDENCE, items)
    if gap:
        return gap
    mode, owner, group, shadow_group = items
    if not isinstance(mode.value, str):
        return _invalid_type(_SHADOW_EVIDENCE, mode.fact, "octal mode string")
    invalid = next(
        (
            item
            for item in (owner, group, shadow_group)
            if not _is_int(item.value)
        ),
        None,
    )
    if invalid:
        return _invalid_type(_SHADOW_EVIDENCE, invalid.fact, "integer")
    return None


def _rule(
    description: RuleDescription, evaluator: RuleEvaluator
) -> DeterministicRule:
    return DeterministicRule(description=description, evaluator=evaluator)


RULES_BY_CONTROL: dict[str, tuple[DeterministicRule, ...]] = {
    "1.1.1.1": (_rule(_CRAMFS, _cramfs_required),),
    "1.1.1.6": (_rule(_OVERLAYFS, _overlayfs_container_workload),),
    "3.3.1": (
        _rule(_IP_ROLE, _ip_forwarding_role),
        _rule(_IP_SOURCES, _ip_forwarding_sources),
    ),
    "4.2.1": (
        _rule(_UFW_IPTABLES, _ufw_iptables_prerequisite),
        _rule(_UFW_OTHER, _ufw_other_firewall),
    ),
    "4.2.3": (
        _rule(_UFW_SERVICE, _ufw_service_evidence),
        _rule(_UFW_SESSION, _ufw_live_session),
        _rule(_UFW_SSH_22, _ufw_ssh_22_safeguard),
    ),
    "5.1.19": (
        _rule(
            _SSH_EMPTY_EFFECTIVE,
            lambda evidence: _string_evidence_rule(_SSH_EMPTY_EFFECTIVE, evidence),
        ),
        _rule(
            _SSH_EMPTY_MATCH,
            lambda evidence: _boolean_review_rule(
                _SSH_EMPTY_MATCH,
                evidence,
                "Match directives are present and may change PermitEmptyPasswords "
                "for specific connections.",
            ),
        ),
        _rule(
            _SSH_EMPTY_INCLUDE,
            lambda evidence: _include_review_rule(
                _SSH_EMPTY_INCLUDE,
                evidence,
                "Enabled Include locations require ordering and edit-location review.",
            ),
        ),
    ),
    "5.1.20": (
        _rule(
            _SSH_ROOT_EFFECTIVE,
            lambda evidence: _string_evidence_rule(_SSH_ROOT_EFFECTIVE, evidence),
        ),
        _rule(
            _SSH_ROOT_MATCH,
            lambda evidence: _boolean_review_rule(
                _SSH_ROOT_MATCH,
                evidence,
                "Match directives are present and may change PermitRootLogin for "
                "specific connections.",
            ),
        ),
        _rule(
            _SSH_ROOT_INCLUDE,
            lambda evidence: _include_review_rule(
                _SSH_ROOT_INCLUDE,
                evidence,
                "Enabled Include locations require ordering and edit-location review.",
            ),
        ),
        _rule(_SSH_ROOT_PATH, _ssh_root_admin_path),
    ),
    "6.2.1.2": (_rule(_AUDITD_EVIDENCE, _auditd_evidence),),
    "7.1.1": (_rule(_PASSWD_READABILITY, _passwd_readability),),
    "7.1.5": (_rule(_SHADOW_EVIDENCE, _shadow_evidence),),
}


def list_rule_descriptions() -> tuple[RuleDescription, ...]:
    """Return all rule metadata in manifest/control order."""

    return tuple(
        rule.description
        for control_rules in RULES_BY_CONTROL.values()
        for rule in control_rules
    )


def evaluate_control_rules(
    control_id: str, evidence: Mapping[str, EvidenceRecord]
) -> tuple[TriggeredRule, ...]:
    """Evaluate only the static rules registered for one selected control."""

    try:
        rules = RULES_BY_CONTROL[control_id]
    except KeyError as exc:
        raise ValueError(
            f"No Milestone 4 rule set registered for {control_id}"
        ) from exc
    findings = [
        finding
        for rule in rules
        if (finding := rule.evaluator(evidence))
    ]
    return tuple(findings)


__all__ = ["RULES_BY_CONTROL", "evaluate_control_rules", "list_rule_descriptions"]
