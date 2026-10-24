"""Opt-in one-context source-state reproduction orchestration."""

from __future__ import annotations

from src.sandbox_runtime.receiver import open_fixed_validation_channel_and_receive
from src.sandbox_runtime.reproduction import (
    SandboxPasswdReproductionResult,
    SandboxStateReproductionError,
    reproduce_passwd_source_state,
)


def receive_and_reproduce_source_state() -> SandboxPasswdReproductionResult:
    """Receive one validated context and reproduce its allowlisted metadata."""

    received = open_fixed_validation_channel_and_receive()
    if (
        received.manifest is None
        or received.acknowledgement.status != "accepted"
    ):
        raise SandboxStateReproductionError(
            "sandbox source-state reproduction failed"
        )
    return reproduce_passwd_source_state(received.manifest)
