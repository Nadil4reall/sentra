"""Local sandbox identity collection and fail-closed mutation policy."""

from __future__ import annotations

import os
import platform
import socket
from pathlib import Path

from src.compatibility_engine.models import CompatibilityDecision

from .models import CompatibilityReference, SandboxIdentity, SandboxPrecheck


_SUPPORTED_ARCHITECTURES = frozenset({"x86_64", "aarch64", "arm64"})
_SNAPSHOT_EXPECTATION = (
    "Create and retain a VM snapshot externally before execution; SENTRA M5 does "
    "not create, verify, or restore VM snapshots."
)


def _parse_os_release(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def inspect_sandbox_identity(
    root: Path = Path("/"),
    *,
    hostname: str | None = None,
    kernel: str | None = None,
    architecture: str | None = None,
    system_name: str | None = None,
    effective_uid: int | None = None,
) -> SandboxIdentity:
    """Describe the local host without claiming it is a disposable sandbox."""

    values = _parse_os_release(Path(root) / "etc" / "os-release")
    os_name = values.get("NAME") or values.get("ID") or "unknown"
    if values.get("ID", "").casefold() == "ubuntu":
        os_name = "Ubuntu"
    version = values.get("VERSION_ID", "")
    selected_architecture = architecture or platform.machine() or "unknown"
    arch_supported = selected_architecture.casefold() in _SUPPORTED_ARCHITECTURES
    selected_system = system_name or platform.system()

    reason: str | None = None
    if selected_system.casefold() != "linux":
        reason = "unsupported_operating_system"
    elif os_name.casefold() != "ubuntu":
        reason = "unsupported_linux_distribution"
    elif version != "24.04":
        reason = "unsupported_ubuntu_version"
    elif not arch_supported:
        reason = "unsupported_architecture"
    supported = reason is None
    uid = os.geteuid() if effective_uid is None else effective_uid
    return SandboxIdentity(
        hostname=hostname or socket.gethostname(),
        os=os_name,
        version=version,
        kernel=kernel or platform.release(),
        architecture=selected_architecture,
        architecture_supported=arch_supported,
        effective_uid=uid,
        privileged=uid == 0,
        supported=supported,
        reason=reason,
    )


def build_precheck(
    *,
    control_id: str,
    control_title: str,
    identity: SandboxIdentity,
    mutation_requested: bool,
    mutation_supported: bool,
    sandbox_operator_acknowledged: bool,
    administrator_approval_acknowledged: bool,
    compatibility_risk_acknowledged: bool,
    compatibility_override_reason: str | None,
    compatibility: CompatibilityReference | None,
    ssh_recovery_access_acknowledged: bool = False,
    ssh_non_root_admin_sudo_access_verified: bool = False,
    ssh_lockout_risk_acknowledged: bool = False,
) -> SandboxPrecheck:
    blockers: list[str] = []
    warnings: list[str] = [_SNAPSHOT_EXPECTATION]

    if mutation_requested:
        if not mutation_supported:
            blockers.append("the selected adapter does not support mutation")
        if not sandbox_operator_acknowledged:
            blockers.append("explicit sandbox operator acknowledgement is missing")
        if not administrator_approval_acknowledged:
            blockers.append("explicit administrator approval is missing")
        if not identity.supported:
            blockers.append("the local host is not supported Ubuntu 24.04 sandbox evidence")
        if not identity.privileged:
            blockers.append("effective UID 0 is required for mutation")
        if control_id == "5.1.20":
            if not ssh_recovery_access_acknowledged:
                blockers.append(
                    "SSH execution requires acknowledged console or snapshot recovery access"
                )
            if not ssh_non_root_admin_sudo_access_verified:
                blockers.append(
                    "SSH execution requires tested non-root administrator sudo access"
                )
            if not ssh_lockout_risk_acknowledged:
                blockers.append(
                    "SSH execution requires explicit lockout-risk acknowledgement"
                )
        if compatibility is None:
            blockers.append("an explicit M4 compatibility result is required for mutation")
        elif compatibility.result in {
            CompatibilityDecision.WARNING,
            CompatibilityDecision.REVIEW_REQUIRED,
        }:
            if not compatibility_risk_acknowledged:
                blockers.append(
                    "the M4 warning/review_required result needs separate risk acknowledgement"
                )
        elif compatibility.result is CompatibilityDecision.INSUFFICIENT_EVIDENCE:
            if not compatibility_risk_acknowledged:
                blockers.append(
                    "the M4 insufficient_evidence result needs separate risk acknowledgement"
                )
            if (
                compatibility_override_reason is None
                or not compatibility_override_reason.strip()
            ):
                blockers.append(
                    "insufficient_evidence requires a recorded research override reason"
                )

    if compatibility is not None and compatibility.provisional:
        warnings.append("the supplied M4 result is provisional")
    if compatibility is None:
        warnings.append("no M4 report was supplied; planning remains read-only")

    return SandboxPrecheck(
        control_id=control_id,
        control_title=control_title,
        identity=identity,
        mutation_requested=mutation_requested,
        sandbox_operator_acknowledged=sandbox_operator_acknowledged,
        administrator_approval_acknowledged=administrator_approval_acknowledged,
        compatibility_risk_acknowledged=compatibility_risk_acknowledged,
        ssh_recovery_access_acknowledged=ssh_recovery_access_acknowledged,
        ssh_non_root_admin_sudo_access_verified=(
            ssh_non_root_admin_sudo_access_verified
        ),
        ssh_lockout_risk_acknowledged=ssh_lockout_risk_acknowledged,
        snapshot_expectation=_SNAPSHOT_EXPECTATION,
        compatibility_override_reason=compatibility_override_reason,
        compatibility=compatibility,
        can_mutate=mutation_requested and not blockers,
        blockers=blockers,
        warnings=warnings,
    )


__all__ = ["build_precheck", "inspect_sandbox_identity"]
