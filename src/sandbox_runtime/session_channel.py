"""Open the one fixed virtio port and run one full M5 session."""

from __future__ import annotations

import os
from typing import BinaryIO

from src.sandbox_m5_protocol.models import SandboxM5SessionResult
from src.sandbox_m5_session import run_sandbox_m5_session

from .receiver import SENTRA_VALIDATION_DEVICE_PATH, SandboxReceiverIOError


def open_fixed_validation_channel_and_run_session(
    *,
    sandbox_operator_acknowledged: bool,
) -> SandboxM5SessionResult:
    """Open only the fixed virtio device and process exactly one session."""

    if type(sandbox_operator_acknowledged) is not bool:
        raise SandboxReceiverIOError("invalid local sandbox operator setting")
    flags = os.O_RDWR | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(SENTRA_VALIDATION_DEVICE_PATH, flags)
    except OSError:
        raise SandboxReceiverIOError("could not open fixed validation channel") from None

    try:
        stream: BinaryIO = os.fdopen(descriptor, "r+b", buffering=0)
    except (OSError, ValueError):
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise SandboxReceiverIOError("could not open fixed validation channel") from None

    with stream:
        return run_sandbox_m5_session(
            stream,
            sandbox_operator_acknowledged=sandbox_operator_acknowledged,
        )
