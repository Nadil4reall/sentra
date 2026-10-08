"""Canonical bounded framing for the separate post-ACK M5 protocol."""

from __future__ import annotations

import json
import struct
from typing import BinaryIO

from pydantic import BaseModel, ValidationError

from .models import SandboxM5ControllerAuthorization, SandboxM5SessionResult


MAX_SANDBOX_M5_PAYLOAD_BYTES = 65536
_FRAME_HEADER_BYTES = 4


class SandboxM5TransportError(ValueError):
    """A fixed, non-sensitive M5 framing or schema error."""


def _reject_constant(value: str) -> None:
    raise ValueError("non-JSON constant")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _canonical_json_bytes(model: BaseModel) -> bytes:
    try:
        value = json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return value.encode("utf-8")
    except (TypeError, ValueError):
        raise SandboxM5TransportError("M5 protocol model is invalid") from None


def _encode(model: BaseModel, expected_type: type[BaseModel]) -> bytes:
    if type(model) is not expected_type:
        raise TypeError("unexpected M5 protocol model")
    try:
        validated = expected_type.model_validate_json(
            model.model_dump_json(), strict=True
        )
    except (ValidationError, ValueError, TypeError):
        raise SandboxM5TransportError("M5 protocol model is invalid") from None
    payload = _canonical_json_bytes(validated)
    if not payload or len(payload) > MAX_SANDBOX_M5_PAYLOAD_BYTES:
        raise SandboxM5TransportError("M5 payload exceeds the protocol size limit")
    return struct.pack("!I", len(payload)) + payload


def _extract_payload(frame: bytes) -> bytes:
    if type(frame) is not bytes or len(frame) < _FRAME_HEADER_BYTES:
        raise SandboxM5TransportError("M5 frame header is truncated")
    payload_size = struct.unpack("!I", frame[:_FRAME_HEADER_BYTES])[0]
    if payload_size == 0:
        raise SandboxM5TransportError("zero-size M5 frames are not permitted")
    if payload_size > MAX_SANDBOX_M5_PAYLOAD_BYTES:
        raise SandboxM5TransportError("M5 frame exceeds the protocol size limit")
    expected_size = _FRAME_HEADER_BYTES + payload_size
    if len(frame) < expected_size:
        raise SandboxM5TransportError("M5 frame payload is truncated")
    if len(frame) > expected_size:
        raise SandboxM5TransportError("trailing bytes after M5 frame")
    return frame[_FRAME_HEADER_BYTES:expected_size]


def _decode(frame: bytes, model_type: type[BaseModel]) -> BaseModel:
    payload = _extract_payload(frame)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise SandboxM5TransportError("M5 frame is not valid UTF-8") from None
    try:
        raw = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ValueError):
        raise SandboxM5TransportError("M5 frame is not valid JSON") from None
    if type(raw) is not dict:
        raise SandboxM5TransportError("M5 frame JSON must be an object")
    try:
        model = model_type.model_validate_json(payload, strict=True)
    except (ValidationError, ValueError, TypeError):
        raise SandboxM5TransportError("M5 frame does not match its schema") from None
    if _canonical_json_bytes(model) != payload:
        raise SandboxM5TransportError("M5 frame JSON is not canonical")
    return model


def encode_sandbox_m5_authorization_frame(
    authorization: SandboxM5ControllerAuthorization,
) -> bytes:
    return _encode(authorization, SandboxM5ControllerAuthorization)


def decode_sandbox_m5_authorization_frame(
    frame: bytes,
) -> SandboxM5ControllerAuthorization:
    model = _decode(frame, SandboxM5ControllerAuthorization)
    assert isinstance(model, SandboxM5ControllerAuthorization)
    return model


def encode_sandbox_m5_result_frame(result: SandboxM5SessionResult) -> bytes:
    return _encode(result, SandboxM5SessionResult)


def decode_sandbox_m5_result_frame(frame: bytes) -> SandboxM5SessionResult:
    model = _decode(frame, SandboxM5SessionResult)
    assert isinstance(model, SandboxM5SessionResult)
    return model


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        remaining = size - len(result)
        try:
            chunk = stream.read(remaining)
        except Exception:
            raise SandboxM5TransportError("M5 stream read failed") from None
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            raise SandboxM5TransportError("M5 stream frame is truncated")
        result.extend(chunk)
    return bytes(result)


def read_sandbox_m5_authorization(stream: BinaryIO) -> SandboxM5ControllerAuthorization:
    header = _read_exact(stream, _FRAME_HEADER_BYTES)
    payload_size = struct.unpack("!I", header)[0]
    if payload_size == 0 or payload_size > MAX_SANDBOX_M5_PAYLOAD_BYTES:
        raise SandboxM5TransportError("M5 frame length is invalid")
    return decode_sandbox_m5_authorization_frame(
        header + _read_exact(stream, payload_size)
    )


def read_sandbox_m5_result(stream: BinaryIO) -> SandboxM5SessionResult:
    header = _read_exact(stream, _FRAME_HEADER_BYTES)
    payload_size = struct.unpack("!I", header)[0]
    if payload_size == 0 or payload_size > MAX_SANDBOX_M5_PAYLOAD_BYTES:
        raise SandboxM5TransportError("M5 frame length is invalid")
    return decode_sandbox_m5_result_frame(header + _read_exact(stream, payload_size))


def _write_all(stream: BinaryIO, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            count = stream.write(data[offset:])
        except Exception:
            raise SandboxM5TransportError("M5 stream write failed") from None
        remaining = len(data) - offset
        if type(count) is not int or count <= 0 or count > remaining:
            raise SandboxM5TransportError("M5 stream write failed")
        offset += count


def write_sandbox_m5_authorization(
    stream: BinaryIO,
    authorization: SandboxM5ControllerAuthorization,
) -> None:
    _write_all(stream, encode_sandbox_m5_authorization_frame(authorization))


def write_sandbox_m5_result(
    stream: BinaryIO,
    result: SandboxM5SessionResult,
) -> None:
    _write_all(stream, encode_sandbox_m5_result_frame(result))
