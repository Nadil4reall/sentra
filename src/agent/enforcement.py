"""Read-only, fixed-path 7.1.1 target-enforcement preflight."""

from __future__ import annotations

import os
import stat
from uuid import UUID

from src.controller.enforcement import verify_enforcement_delivery
from src.controller.models import EnforcementJobDelivery
from src.sandbox_protocol.models import PasswdSourceState


PASSWD_PATH = "/etc/passwd"


class EnforcementPreflightError(RuntimeError):
    """A delivered enforcement job cannot safely proceed to future execution."""


def collect_local_passwd_source_state() -> PasswdSourceState:
    """Read only fixed /etc/passwd metadata; never read its contents."""

    if not hasattr(os, "O_NOFOLLOW"):
        raise EnforcementPreflightError("safe fixed-path metadata open is unavailable")
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
        raise EnforcementPreflightError("fixed passwd metadata is unavailable") from None
    if not stat.S_ISREG(item.st_mode):
        raise EnforcementPreflightError("fixed passwd target is not a regular file")
    return PasswdSourceState(
        passwd_file_mode=format(stat.S_IMODE(item.st_mode), "04o"),
        passwd_file_owner_uid=item.st_uid,
        passwd_file_group_gid=item.st_gid,
    )


def verify_and_observe(
    delivery: EnforcementJobDelivery, *, target_id: UUID, agent_id: UUID,
) -> tuple[PasswdSourceState, str]:
    """Verify approval/evidence before touching even the read-only target path."""

    try:
        verify_enforcement_delivery(delivery, target_id=target_id, agent_id=agent_id)
    except (ValueError, TypeError):
        raise EnforcementPreflightError("enforcement delivery is invalid") from None
    observed = collect_local_passwd_source_state()
    outcome = (
        "PREPARED" if observed == delivery.expected_source_state
        else "BLOCKED_DRIFT"
    )
    return observed, outcome


__all__ = [
    "EnforcementPreflightError",
    "collect_local_passwd_source_state",
    "verify_and_observe",
]
