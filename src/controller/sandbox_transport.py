"""Strict codec for the fixed SENTRA sandbox-context protocol.

This module defines a wire boundary only. It does not open a channel, perform
guest I/O, execute an adapter, or apply the received target metadata.
"""

from __future__ import annotations

import json
import struct
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from .sandbox_context import SandboxContextManifest


SENTRA_VALIDATION_CHANNEL_NAME = "org.sentra.validation.0"

_FRAME_HEADER_BYTES = 4
_MAX_PAYLOAD_BYTES = 4096


class SandboxTransportError(ValueError):
    """A non-sensitive protocol/framing validation error."""


class SandboxTransportModel(BaseModel):
    """Immutable protocol model with no undocumented fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class SandboxContextRejectionCode(StrEnum):
    """Allowlisted, non-sensitive acknowledgement rejection reasons."""

    INVALID_FRAME = "invalid_frame"
    INVALID_CONTEXT = "invalid_context"
    UNSUPPORTED_CONTEXT = "unsupported_context"


class SandboxContextAcknowledgement(SandboxTransportModel):
    """Fixed accepted/rejected response; it never carries the manifest back."""

    protocol_version: Literal["1"]
    status: Literal["accepted", "rejected"]
    reason_code: Literal[
        "invalid_frame", "invalid_context", "unsupported_context"
    ] | None = None

    @model_validator(mode="after")
    def validate_status_fields(self) -> "SandboxContextAcknowledgement":
        reason_was_supplied = "reason_code" in self.model_fields_set
        if self.status == "accepted":
            if self.reason_code is not None or reason_was_supplied:
                raise ValueError("accepted acknowledgement cannot include a reason")
        elif self.reason_code is None:
            raise ValueError("rejected acknowledgement requires a reason code")
        return self


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON constant: {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _canonical_json_bytes(model: BaseModel) -> bytes:
    try:
        text = json.dumps(
            model.model_dump(mode="json", exclude_none=True),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        raise SandboxTransportError("protocol model cannot be serialized") from None
    return text.encode("utf-8")


def _encode_frame(model: BaseModel) -> bytes:
    payload = _canonical_json_bytes(model)
    if not payload:
        raise SandboxTransportError("empty payload is not permitted")
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise SandboxTransportError("payload exceeds the protocol size limit")
    return struct.pack("!I", len(payload)) + payload


def _extract_frame_payload(frame: bytes) -> bytes:
    if not isinstance(frame, bytes):
        raise SandboxTransportError("frame must be bytes")
    if len(frame) < _FRAME_HEADER_BYTES:
        raise SandboxTransportError("truncated frame header")

    payload_size = struct.unpack("!I", frame[:_FRAME_HEADER_BYTES])[0]
    if payload_size == 0:
        raise SandboxTransportError("zero-length frame is not permitted")
    if payload_size > _MAX_PAYLOAD_BYTES:
        raise SandboxTransportError("frame exceeds the protocol size limit")

    expected_size = _FRAME_HEADER_BYTES + payload_size
    if len(frame) < expected_size:
        raise SandboxTransportError("truncated frame payload")
    if len(frame) > expected_size:
        raise SandboxTransportError("trailing bytes after framed message")
    return frame[_FRAME_HEADER_BYTES:expected_size]


def _decode_json_object(frame: bytes) -> tuple[dict[str, object], bytes]:
    payload = _extract_frame_payload(frame)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise SandboxTransportError("payload is not valid UTF-8") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ValueError):
        raise SandboxTransportError("payload is not valid JSON") from None
    if type(value) is not dict:
        raise SandboxTransportError("payload JSON must be an object")
    return value, payload


def encode_sandbox_context_frame(manifest: SandboxContextManifest) -> bytes:
    """Serialize exactly one validated context manifest into a length frame."""

    if not isinstance(manifest, SandboxContextManifest):
        raise TypeError("manifest must be a SandboxContextManifest")
    try:
        validated = SandboxContextManifest.model_validate(
            manifest.model_dump(mode="python"), strict=True
        )
    except ValidationError:
        raise SandboxTransportError(
            "manifest does not match the supported schema"
        ) from None
    return _encode_frame(validated)


def decode_sandbox_context_frame(frame: bytes) -> SandboxContextManifest:
    """Decode one canonical frame using the existing manifest schema authority."""

    raw, payload = _decode_json_object(frame)
    try:
        manifest = SandboxContextManifest.model_validate(raw, strict=True)
    except ValidationError:
        raise SandboxTransportError(
            "context does not match the supported schema"
        ) from None
    if _canonical_json_bytes(manifest) != payload:
        raise SandboxTransportError("context JSON is not in canonical form")
    return manifest


def encode_sandbox_acknowledgement_frame(
    acknowledgement: SandboxContextAcknowledgement,
) -> bytes:
    """Serialize the fixed acknowledgement model into the same bounded frame."""

    if not isinstance(acknowledgement, SandboxContextAcknowledgement):
        raise TypeError("acknowledgement must use the fixed protocol model")
    try:
        validated = SandboxContextAcknowledgement.model_validate(
            acknowledgement.model_dump(mode="python", exclude_unset=True),
            strict=True,
        )
    except ValidationError:
        raise SandboxTransportError(
            "acknowledgement does not match the protocol"
        ) from None
    return _encode_frame(validated)


def decode_sandbox_acknowledgement_frame(
    frame: bytes,
) -> SandboxContextAcknowledgement:
    """Decode one canonical fixed acknowledgement, without accepting envelopes."""

    raw, payload = _decode_json_object(frame)
    try:
        acknowledgement = SandboxContextAcknowledgement.model_validate(
            raw, strict=True
        )
    except ValidationError:
        raise SandboxTransportError(
            "acknowledgement does not match the protocol"
        ) from None
    if _canonical_json_bytes(acknowledgement) != payload:
        raise SandboxTransportError("acknowledgement JSON is not canonical")
    return acknowledgement
