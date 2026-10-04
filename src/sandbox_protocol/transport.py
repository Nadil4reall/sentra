"""Canonical bounded framing for the shared sandbox-context protocol."""

from __future__ import annotations

import json
import struct

from pydantic import BaseModel, ValidationError

from .models import SandboxContextAcknowledgement, SandboxContextManifest


MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES = 4096
_FRAME_HEADER_BYTES = 4


class SandboxTransportError(ValueError):
    """A non-sensitive protocol/framing validation error."""


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
    if len(payload) > MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES:
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
    if payload_size > MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES:
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


def _validate_model(
    model_type: type[SandboxContextManifest] | type[SandboxContextAcknowledgement],
    value: dict[str, object],
    message: str,
) -> SandboxContextManifest | SandboxContextAcknowledgement:
    try:
        return model_type.model_validate(value, strict=True)
    except ValidationError:
        raise SandboxTransportError(message) from None


def encode_sandbox_context_frame(manifest: SandboxContextManifest) -> bytes:
    """Serialize exactly one validated context manifest into a length frame."""

    if not isinstance(manifest, SandboxContextManifest):
        raise TypeError("manifest must be a SandboxContextManifest")
    validated = _validate_model(
        SandboxContextManifest,
        manifest.model_dump(mode="python"),
        "manifest does not match the supported schema",
    )
    assert isinstance(validated, SandboxContextManifest)
    return _encode_frame(validated)


def decode_sandbox_context_frame(frame: bytes) -> SandboxContextManifest:
    """Decode one canonical frame using the manifest schema authority."""

    raw, payload = _decode_json_object(frame)
    manifest = _validate_model(
        SandboxContextManifest,
        raw,
        "context does not match the supported schema",
    )
    assert isinstance(manifest, SandboxContextManifest)
    if _canonical_json_bytes(manifest) != payload:
        raise SandboxTransportError("context JSON is not in canonical form")
    return manifest


def encode_sandbox_acknowledgement_frame(
    acknowledgement: SandboxContextAcknowledgement,
) -> bytes:
    """Serialize the fixed acknowledgement model into the same bounded frame."""

    if not isinstance(acknowledgement, SandboxContextAcknowledgement):
        raise TypeError("acknowledgement must use the fixed protocol model")
    validated = _validate_model(
        SandboxContextAcknowledgement,
        acknowledgement.model_dump(mode="python", exclude_unset=True),
        "acknowledgement does not match the protocol",
    )
    assert isinstance(validated, SandboxContextAcknowledgement)
    return _encode_frame(validated)


def decode_sandbox_acknowledgement_frame(
    frame: bytes,
) -> SandboxContextAcknowledgement:
    """Decode one canonical fixed acknowledgement, without accepting envelopes."""

    raw, payload = _decode_json_object(frame)
    acknowledgement = _validate_model(
        SandboxContextAcknowledgement,
        raw,
        "acknowledgement does not match the protocol",
    )
    assert isinstance(acknowledgement, SandboxContextAcknowledgement)
    if _canonical_json_bytes(acknowledgement) != payload:
        raise SandboxTransportError("acknowledgement JSON is not canonical")
    return acknowledgement
