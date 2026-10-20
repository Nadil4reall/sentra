"""Read-only, fixed-path M7 target-enforcement preflight."""

from __future__ import annotations

import os
import stat
from uuid import UUID

from src.controller.enforcement import verify_enforcement_delivery
from src.controller.models import EnforcementJobDelivery
from src.sandbox_protocol.models import (
    IpForwardingSourceState,
    PasswdSourceState,
)


PASSWD_PATH = "/etc/passwd"

IPV4_FORWARDING_PATH = "/proc/sys/net/ipv4/ip_forward"
IPV6_MODULE_DISABLE_PATH = "/sys/module/ipv6/parameters/disable"
IPV6_ALL_DISABLE_PATH = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
IPV6_DEFAULT_DISABLE_PATH = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
IPV6_FORWARDING_PATH = "/proc/sys/net/ipv6/conf/all/forwarding"

_FIXED_INTEGER_PATHS = frozenset(
    {
        IPV4_FORWARDING_PATH,
        IPV6_MODULE_DISABLE_PATH,
        IPV6_ALL_DISABLE_PATH,
        IPV6_DEFAULT_DISABLE_PATH,
        IPV6_FORWARDING_PATH,
    }
)

EnforcementSourceState = PasswdSourceState | IpForwardingSourceState


class EnforcementPreflightError(RuntimeError):
    """A delivered enforcement job cannot safely proceed to execution."""


def collect_local_passwd_source_state() -> PasswdSourceState:
    """Read only fixed /etc/passwd metadata; never read its contents."""

    if not hasattr(os, "O_NOFOLLOW"):
        raise EnforcementPreflightError(
            "safe fixed-path metadata open is unavailable"
        )

    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    try:
        descriptor = os.open(PASSWD_PATH, flags)
        try:
            item = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise EnforcementPreflightError(
            "fixed passwd metadata is unavailable"
        ) from None

    if not stat.S_ISREG(item.st_mode):
        raise EnforcementPreflightError(
            "fixed passwd target is not a regular file"
        )

    return PasswdSourceState(
        passwd_file_mode=format(stat.S_IMODE(item.st_mode), "04o"),
        passwd_file_owner_uid=item.st_uid,
        passwd_file_group_gid=item.st_gid,
    )


def _read_fixed_integer(path: str) -> int:
    """Read one allowlisted kernel boolean from a fixed proc/sysfs path."""

    if path not in _FIXED_INTEGER_PATHS:
        raise EnforcementPreflightError(
            "kernel observation path is not allowlisted"
        )

    if not hasattr(os, "O_NOFOLLOW"):
        raise EnforcementPreflightError(
            "safe fixed-path kernel observation is unavailable"
        )

    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        item = os.fstat(descriptor)

        if not stat.S_ISREG(item.st_mode):
            raise EnforcementPreflightError(
                "fixed kernel observation is not a regular file"
            )

        raw = os.read(descriptor, 65)
    except EnforcementPreflightError:
        raise
    except OSError:
        raise EnforcementPreflightError(
            "fixed kernel observation is unavailable"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    if len(raw) > 64:
        raise EnforcementPreflightError(
            "fixed kernel observation is oversized"
        )

    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise EnforcementPreflightError(
            "fixed kernel observation is malformed"
        ) from None

    if value not in {"0", "1"}:
        raise EnforcementPreflightError(
            "fixed kernel observation is not boolean"
        )

    return int(value)


def collect_local_ip_forwarding_source_state() -> IpForwardingSourceState:
    """Read only the fixed kernel state required by CIS control 3.3.1."""

    ipv4_forwarding = _read_fixed_integer(IPV4_FORWARDING_PATH)

    module_disable = _read_fixed_integer(IPV6_MODULE_DISABLE_PATH)

    if module_disable == 1:
        ipv6_enabled = False
    else:
        all_disable = _read_fixed_integer(IPV6_ALL_DISABLE_PATH)
        default_disable = _read_fixed_integer(IPV6_DEFAULT_DISABLE_PATH)
        ipv6_enabled = not (
            all_disable == 1 and default_disable == 1
        )

    ipv6_forwarding = (
        _read_fixed_integer(IPV6_FORWARDING_PATH)
        if ipv6_enabled
        else None
    )

    return IpForwardingSourceState(
        ipv4_forwarding_status=ipv4_forwarding,
        ipv6_enabled=ipv6_enabled,
        ipv6_forwarding_status=ipv6_forwarding,
    )


def verify_and_observe(
    delivery: EnforcementJobDelivery,
    *,
    target_id: UUID,
    agent_id: UUID,
) -> tuple[EnforcementSourceState, str]:
    """Verify trusted delivery before performing fixed read-only observations."""

    try:
        verify_enforcement_delivery(
            delivery,
            target_id=target_id,
            agent_id=agent_id,
        )
    except (ValueError, TypeError):
        raise EnforcementPreflightError(
            "enforcement delivery is invalid"
        ) from None

    if delivery.control_id == "7.1.1":
        observed: EnforcementSourceState = (
            collect_local_passwd_source_state()
        )
    elif delivery.control_id == "3.3.1":
        observed = collect_local_ip_forwarding_source_state()
    else:
        raise EnforcementPreflightError(
            "enforcement control is not supported"
        )

    outcome = (
        "PREPARED"
        if observed == delivery.expected_source_state
        else "BLOCKED_DRIFT"
    )

    return observed, outcome


__all__ = [
    "EnforcementPreflightError",
    "collect_local_passwd_source_state",
    "collect_local_ip_forwarding_source_state",
    "verify_and_observe",
]
