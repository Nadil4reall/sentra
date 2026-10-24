"""Compatibility re-exports for the shared sandbox-context protocol."""

from src.sandbox_protocol.models import (
    SENTRA_VALIDATION_CHANNEL_NAME,
    SandboxContextAcknowledgement,
    SandboxContextRejectionCode,
)
from src.sandbox_protocol.transport import (
    MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES,
    SandboxTransportError,
    decode_sandbox_acknowledgement_frame,
    decode_sandbox_context_frame,
    encode_sandbox_acknowledgement_frame,
    encode_sandbox_context_frame,
)

__all__ = [
    "MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES",
    "SENTRA_VALIDATION_CHANNEL_NAME",
    "SandboxContextAcknowledgement",
    "SandboxContextRejectionCode",
    "SandboxTransportError",
    "decode_sandbox_acknowledgement_frame",
    "decode_sandbox_context_frame",
    "encode_sandbox_acknowledgement_frame",
    "encode_sandbox_context_frame",
]
