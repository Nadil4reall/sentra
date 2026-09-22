"""Narrow post-change health checks for supported M5 adapters."""

from __future__ import annotations

from .adapters.base import AdapterContext, UnsafePathError
from .audit import evidence_by_name
from .models import AuditEvidence, EvidenceStatus, HealthCheck, HealthStatus


def check_passwd_health(context: AdapterContext) -> list[HealthCheck]:
    """Check readability and minimal account-record structure without reporting data."""

    path = context.resolve("/etc/passwd")
    try:
        text = context.files.read_text(path, max_bytes=4 * 1024 * 1024)
    except (OSError, UnsafePathError, ValueError) as exc:
        explanation = f"/etc/passwd could not be read safely: {type(exc).__name__}"
        return [
            HealthCheck(
                check_id="passwd-readable",
                description="The account database remains readable.",
                required=True,
                status=HealthStatus.FAILED,
                explanation=explanation,
            ),
            HealthCheck(
                check_id="passwd-record-sanity",
                description="Account records retain a minimally valid structure.",
                required=True,
                status=HealthStatus.UNAVAILABLE,
                explanation="Record structure was not inspected because reading failed.",
            ),
        ]

    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    structurally_valid = bool(lines) and all(len(line.split(":")) == 7 for line in lines)
    root_records = [
        fields
        for fields in (line.split(":") for line in lines)
        if len(fields) == 7 and fields[0] == "root"
    ]
    root_valid = len(root_records) == 1 and root_records[0][2:4] == ["0", "0"]
    return [
        HealthCheck(
            check_id="passwd-readable",
            description="The account database remains readable.",
            required=True,
            status=HealthStatus.PASSED,
            explanation="The fixed account database path was read successfully.",
        ),
        HealthCheck(
            check_id="passwd-record-sanity",
            description="Account records retain a minimally valid structure.",
            required=True,
            status=(
                HealthStatus.PASSED
                if structurally_valid and root_valid
                else HealthStatus.FAILED
            ),
            explanation=(
                "Record field counts and the root account identity passed a narrow check; "
                "no account contents were recorded."
                if structurally_valid and root_valid
                else "The account database failed a narrow structural/root-record check; "
                "no account contents were recorded."
            ),
        ),
    ]


def check_passwd_readability_mode(post_audit: list[AuditEvidence]) -> HealthCheck:
    """Retain a non-fatal concern if ordinary users may no longer read passwd."""

    mode = evidence_by_name(post_audit).get("passwd_file_mode")
    if mode is None or mode.status is not EvidenceStatus.COLLECTED:
        return HealthCheck(
            check_id="passwd-unprivileged-readability",
            description="The account database remains readable to ordinary utilities.",
            required=False,
            status=HealthStatus.UNAVAILABLE,
            explanation="File-mode evidence was unavailable for the readability check.",
        )
    parsed = int(str(mode.value), 8)
    readable = bool(parsed & 0o004)
    return HealthCheck(
        check_id="passwd-unprivileged-readability",
        description="The account database remains readable to ordinary utilities.",
        required=False,
        status=HealthStatus.PASSED if readable else HealthStatus.WARNING,
        explanation=(
            "The other-read bit remains set."
            if readable
            else "The mode is restrictive enough for the control but ordinary-user "
            "readability requires administrator review."
        ),
    )


def check_ssh_health(post_audit: list[AuditEvidence]) -> list[HealthCheck]:
    by_name = evidence_by_name(post_audit)
    syntax = by_name.get("sshd_config_syntax_valid")
    service = by_name.get("ssh_service_status")
    remote = by_name.get("remote_session_context")

    syntax_passed = (
        syntax is not None
        and syntax.status is EvidenceStatus.COLLECTED
        and syntax.value is True
    )
    service_active = (
        service is not None
        and service.status is EvidenceStatus.COLLECTED
        and str(service.value).casefold() == "active"
    )
    remote_explanation = (
        "A current SSH session marker is present; service state alone does not prove "
        "future remote access."
        if remote is not None
        and remote.status is EvidenceStatus.COLLECTED
        and remote.value is True
        else "Remote-session absence could not be proven; service state alone does not "
        "prove future remote access."
    )
    return [
        HealthCheck(
            check_id="sshd-config-syntax",
            description="The SSH daemon configuration remains syntactically valid.",
            required=True,
            status=HealthStatus.PASSED if syntax_passed else HealthStatus.FAILED,
            explanation=(
                "The fixed sshd syntax test succeeded."
                if syntax_passed
                else "The fixed sshd syntax test did not succeed."
            ),
        ),
        HealthCheck(
            check_id="ssh-service-active",
            description="The SSH service remains active after the candidate change.",
            required=True,
            status=HealthStatus.PASSED if service_active else HealthStatus.FAILED,
            explanation=(
                "The SSH service reports active."
                if service_active
                else "The SSH service did not report active."
            ),
        ),
        HealthCheck(
            check_id="ssh-remote-access-continuity",
            description="Future administrator remote access remains available.",
            required=False,
            status=HealthStatus.WARNING,
            explanation=remote_explanation,
        ),
    ]


__all__ = [
    "check_passwd_health",
    "check_passwd_readability_mode",
    "check_ssh_health",
]
