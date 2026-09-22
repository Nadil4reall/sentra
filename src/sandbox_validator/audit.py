"""Fresh, normalized M5 audits that never emit secrets or raw configuration."""

from __future__ import annotations

import re
import shlex
from typing import Any

from .adapters.base import AdapterContext, UnsafePathError
from .command_runner import CommandResult, ReadAction
from .models import AuditEvidence, EvidenceStatus


_SSH_SESSION_KEYS = ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")
_MAX_PASSWD_BYTES = 4 * 1024 * 1024
_MAX_SSH_CONFIG_BYTES = 1024 * 1024


def _collected(name: str, value: Any, source: str) -> AuditEvidence:
    return AuditEvidence(
        name=name,
        status=EvidenceStatus.COLLECTED,
        value=value,
        source=source,
    )


def _missing(
    name: str, status: EvidenceStatus, reason: str, source: str
) -> AuditEvidence:
    return AuditEvidence(
        name=name,
        status=status,
        value=None,
        source=source,
        reason=reason,
    )


def _exception_status(exc: BaseException) -> EvidenceStatus:
    if isinstance(exc, (FileNotFoundError, PermissionError)):
        return EvidenceStatus.UNAVAILABLE
    return EvidenceStatus.ERROR


def _command_failure(
    name: str, result: CommandResult, purpose: str
) -> AuditEvidence:
    status = (
        EvidenceStatus.UNAVAILABLE
        if result.error_kind in {"permission_denied", "not_found"}
        else EvidenceStatus.ERROR
    )
    reason = result.reason or f"unable to {purpose}"
    return _missing(name, status, reason, f"command:{result.action}")


def audit_passwd(context: AdapterContext) -> list[AuditEvidence]:
    """Capture metadata for the one fixed 7.1.1 target."""

    logical_path = "/etc/passwd"
    path = context.resolve(logical_path)
    names = ("passwd_file_mode", "passwd_file_owner_uid", "passwd_file_group_gid")
    try:
        snapshot = context.files.snapshot(path)
    except (OSError, UnsafePathError) as exc:
        status = _exception_status(exc)
        reason = f"unable to inspect {logical_path}: {type(exc).__name__}"
        return [_missing(name, status, reason, "python:lstat") for name in names]
    return [
        _collected("passwd_file_mode", format(snapshot.mode, "04o"), "python:lstat"),
        _collected("passwd_file_owner_uid", snapshot.uid, "python:lstat"),
        _collected("passwd_file_group_gid", snapshot.gid, "python:lstat"),
    ]


def _parse_sshd_settings(result: CommandResult) -> dict[str, str] | None:
    if not result.succeeded:
        return None
    settings: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.strip().partition(" ")
        if separator and key:
            settings[key.casefold()] = value.strip()
    return settings


def _ssh_command_audit(context: AdapterContext) -> list[AuditEvidence]:
    evidence: list[AuditEvidence] = []

    package = context.runner.run_read(ReadAction.SSH_PACKAGE_STATUS)
    if package.succeeded:
        installed = "install ok installed" in package.stdout.casefold()
        evidence.append(
            _collected("ssh_installed", installed, "command:ssh_package_status")
        )
    elif package.error_kind == "nonzero_exit":
        evidence.append(
            _collected("ssh_installed", False, "command:ssh_package_status")
        )
    else:
        evidence.append(_command_failure("ssh_installed", package, "query package"))

    service = context.runner.run_read(ReadAction.SSH_SERVICE_ACTIVE)
    service_state = service.stdout.strip().splitlines()[0] if service.stdout.strip() else ""
    if service_state and service.error_kind in {None, "nonzero_exit"}:
        evidence.append(
            _collected(
                "ssh_service_status", service_state, "command:ssh_service_active"
            )
        )
    else:
        evidence.append(
            _command_failure("ssh_service_status", service, "read SSH service state")
        )

    reload_capability = context.runner.run_read(ReadAction.SSH_SERVICE_CAN_RELOAD)
    reload_lines = [
        line.strip()
        for line in reload_capability.stdout.splitlines()
        if line.strip()
    ]
    reload_state = reload_lines[0].casefold() if len(reload_lines) == 1 else ""
    if reload_capability.succeeded and reload_state in {"yes", "no"}:
        evidence.append(
            _collected(
                "ssh_service_reload_supported",
                reload_state == "yes",
                "command:ssh_service_can_reload",
            )
        )
    elif reload_capability.succeeded:
        evidence.append(
            _missing(
                "ssh_service_reload_supported",
                EvidenceStatus.ERROR,
                "systemctl returned an unrecognized SSH reload capability",
                "command:ssh_service_can_reload",
            )
        )
    else:
        evidence.append(
            _command_failure(
                "ssh_service_reload_supported",
                reload_capability,
                "read SSH reload capability",
            )
        )

    syntax = context.runner.run_read(ReadAction.SSHD_SYNTAX)
    if syntax.returncode is not None and syntax.error_kind in {None, "nonzero_exit"}:
        evidence.append(
            _collected("sshd_config_syntax_valid", syntax.succeeded, "command:sshd_syntax")
        )
    else:
        evidence.append(
            _command_failure("sshd_config_syntax_valid", syntax, "validate SSH syntax")
        )

    effective = context.runner.run_read(ReadAction.SSHD_EFFECTIVE)
    settings = _parse_sshd_settings(effective)
    if settings is None:
        evidence.append(
            _command_failure(
                "sshd_permit_root_login_effective",
                effective,
                "read effective SSH configuration",
            )
        )
    elif "permitrootlogin" not in settings:
        evidence.append(
            _missing(
                "sshd_permit_root_login_effective",
                EvidenceStatus.UNAVAILABLE,
                "sshd -T did not report PermitRootLogin",
                "command:sshd_effective",
            )
        )
    else:
        evidence.append(
            _collected(
                "sshd_permit_root_login_effective",
                settings["permitrootlogin"],
                "command:sshd_effective",
            )
        )
    return evidence


def _tokens(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError:
        return []


def _scan_ssh_configuration(context: AdapterContext) -> list[AuditEvidence]:
    main_logical = "/etc/ssh/sshd_config"
    main = context.resolve(main_logical)
    include_pattern = "/etc/ssh/sshd_config.d/*.conf"
    includes: list[str] = []
    match_present = False
    global_permit_before_include = False
    exact_include_seen = False
    nested_include_present = False
    scanned_files: list[str] = []

    try:
        main_text = context.files.read_text(main, max_bytes=_MAX_SSH_CONFIG_BYTES)
        scanned_files.append(main_logical)
        in_match = False
        for raw_line in main_text.splitlines():
            tokens = _tokens(raw_line)
            if not tokens:
                continue
            directive = tokens[0].casefold()
            if directive == "match":
                match_present = True
                in_match = True
            elif directive == "include":
                for location in tokens[1:]:
                    if location not in includes:
                        includes.append(location)
                    if not in_match and location == include_pattern:
                        exact_include_seen = True
            elif (
                directive == "permitrootlogin"
                and not in_match
                and not exact_include_seen
            ):
                global_permit_before_include = True

        dropin_directory = context.resolve("/etc/ssh/sshd_config.d")
        if dropin_directory.exists():
            for candidate in sorted(dropin_directory.glob("*.conf")):
                relative = "/" + candidate.relative_to(context.root).as_posix()
                try:
                    text = context.files.read_text(
                        candidate, max_bytes=_MAX_SSH_CONFIG_BYTES
                    )
                except FileNotFoundError:
                    continue
                scanned_files.append(relative)
                for nested_tokens in (_tokens(line) for line in text.splitlines()):
                    if not nested_tokens:
                        continue
                    nested_directive = nested_tokens[0].casefold()
                    if nested_directive == "match":
                        match_present = True
                    elif nested_directive == "include":
                        nested_include_present = True
    except (OSError, UnsafePathError, ValueError) as exc:
        status = _exception_status(exc)
        reason = f"unable to scan SSH configuration: {type(exc).__name__}"
        return [
            _missing("sshd_include_locations_enabled", status, reason, "python:ssh_scan"),
            _missing("sshd_match_directives_present", status, reason, "python:ssh_scan"),
            _missing("sshd_include_precedence_supported", status, reason, "python:ssh_scan"),
            _missing("sshd_configuration_files_scanned", status, reason, "python:ssh_scan"),
        ]

    return [
        _collected("sshd_include_locations_enabled", includes, "python:ssh_scan"),
        _collected("sshd_match_directives_present", match_present, "python:ssh_scan"),
        _collected(
            "sshd_include_precedence_supported",
            (
                exact_include_seen
                and not global_permit_before_include
                and not nested_include_present
                and all(location == include_pattern for location in includes)
            ),
            "python:ssh_scan",
        ),
        _collected(
            "sshd_configuration_files_scanned", scanned_files, "python:ssh_scan"
        ),
    ]


def _remote_session_evidence(context: AdapterContext) -> AuditEvidence:
    if any(bool(context.environment.get(key)) for key in _SSH_SESSION_KEYS):
        return _collected(
            "remote_session_context", True, "process_environment:ssh_markers"
        )
    return _missing(
        "remote_session_context",
        EvidenceStatus.UNSUPPORTED,
        "no SSH marker was detected; absence cannot be proven after privilege escalation",
        "process_environment:ssh_markers",
    )


def audit_ssh(context: AdapterContext) -> list[AuditEvidence]:
    return [
        *_ssh_command_audit(context),
        *_scan_ssh_configuration(context),
        _remote_session_evidence(context),
    ]


def _systemd_state(
    name: str, result: CommandResult, purpose: str
) -> AuditEvidence:
    state = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    if state and result.error_kind in {None, "nonzero_exit"}:
        return _collected(name, state, f"command:{result.action}")
    return _command_failure(name, result, purpose)


def _ufw_tcp_22_rule(result: CommandResult) -> AuditEvidence:
    if not result.succeeded:
        return _command_failure(
            "ufw_ssh_port_22_rule_present", result, "read configured UFW rules"
        )
    ambiguous = False
    for raw_line in result.stdout.splitlines():
        try:
            tokens = [token.casefold() for token in shlex.split(raw_line)]
        except ValueError:
            ambiguous = True
            continue
        if tokens[:1] == ["ufw"]:
            tokens = tokens[1:]
        if not tokens or tokens[0] != "allow" or "out" in tokens:
            continue
        if "22/tcp" in tokens or tokens[1:2] == ["22"]:
            return _collected(
                "ufw_ssh_port_22_rule_present", True, "command:ufw_added_rules"
            )
        if "22" in tokens:
            if "udp" in tokens and "tcp" not in tokens:
                continue
            ambiguous = True
        if "openssh" in tokens:
            ambiguous = True
    if ambiguous:
        return _missing(
            "ufw_ssh_port_22_rule_present",
            EvidenceStatus.UNAVAILABLE,
            "a possible SSH rule could not be confirmed as inbound TCP/22",
            "command:ufw_added_rules",
        )
    return _collected(
        "ufw_ssh_port_22_rule_present", False, "command:ufw_added_rules"
    )


def audit_ufw(context: AdapterContext) -> list[AuditEvidence]:
    enabled = context.runner.run_read(ReadAction.UFW_SERVICE_ENABLED)
    active = context.runner.run_read(ReadAction.UFW_SERVICE_ACTIVE)
    status_result = context.runner.run_read(ReadAction.UFW_STATUS)
    rules = context.runner.run_read(ReadAction.UFW_ADDED_RULES)

    enabled_evidence = _systemd_state(
        "ufw_service_enabled", enabled, "read UFW enablement state"
    )
    if enabled_evidence.status is EvidenceStatus.COLLECTED:
        enabled_value = str(enabled_evidence.value)
        mask = _collected(
            "ufw_service_mask_status",
            "masked" if enabled_value.startswith("masked") else "not_masked",
            "derived:ufw_service_enabled",
        )
    else:
        mask = _missing(
            "ufw_service_mask_status",
            enabled_evidence.status,
            enabled_evidence.reason or "UFW mask state is unavailable",
            "derived:ufw_service_enabled",
        )

    if status_result.succeeded:
        match = re.search(
            r"(?im)^Status:\s*(active|inactive)\s*$", status_result.stdout
        )
        if match:
            ufw_status = _collected(
                "ufw_status", match.group(1).casefold(), "command:ufw_status"
            )
        else:
            ufw_status = _missing(
                "ufw_status",
                EvidenceStatus.ERROR,
                "UFW returned an unrecognized status response",
                "command:ufw_status",
            )
    else:
        ufw_status = _command_failure("ufw_status", status_result, "read UFW status")

    return [
        mask,
        enabled_evidence,
        _systemd_state("ufw_service_active", active, "read UFW active state"),
        ufw_status,
        _remote_session_evidence(context),
        _ufw_tcp_22_rule(rules),
        _missing(
            "alternate_ssh_port_context",
            EvidenceStatus.UNSUPPORTED,
            "alternate SSH ports require administrator context",
            "administrator_context",
        ),
    ]


def evidence_by_name(evidence: list[AuditEvidence]) -> dict[str, AuditEvidence]:
    return {item.name: item for item in evidence}


__all__ = [
    "audit_passwd",
    "audit_ssh",
    "audit_ufw",
    "evidence_by_name",
]
