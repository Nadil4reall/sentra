"""Receive one fixed sandbox-context message without executing or applying it."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import BinaryIO

from src.sandbox_protocol import (
    MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES,
    SANDBOX_PROTOCOL_VERSION,
    SENTRA_VALIDATION_CHANNEL_NAME,
    SandboxContextAcknowledgement,
    SandboxContextManifest,
    SandboxContextRejectionCode,
    SandboxTransportError,
    decode_sandbox_context_frame,
    encode_sandbox_acknowledgement_frame,
)


SENTRA_VALIDATION_DEVICE_PATH = (
    f"/dev/virtio-ports/{SENTRA_VALIDATION_CHANNEL_NAME}"
)
_FRAME_HEADER_BYTES = 4
_FIRST_FRAME_STARTUP_TIMEOUT_SECONDS = 30.0
_FIRST_FRAME_RETRY_INTERVAL_SECONDS = 0.05
_monotonic = time.monotonic
_sleep = time.sleep


class SandboxReceiverIOError(OSError):
    """Fixed, non-sensitive guest-channel I/O failure."""


class _IncompleteFrame(Exception):
    pass


@dataclass(frozen=True, slots=True)
class SandboxContextReceiveResult:
    """One receive attempt and its fixed protocol response."""

    manifest: SandboxContextManifest | None
    acknowledgement: SandboxContextAcknowledgement


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    """Read at most the validated requested size, allowing partial reads."""

    chunks = bytearray()
    while len(chunks) < size:
        remaining = size - len(chunks)
        try:
            chunk = stream.read(remaining)
        except Exception:
            raise SandboxReceiverIOError("failed to read validation channel") from None
        if chunk == b"":
            raise _IncompleteFrame
        if not isinstance(chunk, bytes) or len(chunk) > remaining:
            raise SandboxReceiverIOError("invalid validation channel read result")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_first_frame_header(stream: BinaryIO) -> bytes:
    """Wait briefly for the first byte, then read the header strictly.

    Empty reads are retried only while no header byte has arrived. Once the
    header starts, EOF is an incomplete frame and follows the normal rejection
    path. The deadline and retry delay are fixed module constants.
    """

    deadline = _monotonic() + _FIRST_FRAME_STARTUP_TIMEOUT_SECONDS
    chunks = bytearray()
    while len(chunks) < _FRAME_HEADER_BYTES:
        if not chunks and _monotonic() >= deadline:
            raise SandboxReceiverIOError("timed out waiting for validation context")

        remaining = _FRAME_HEADER_BYTES - len(chunks)
        try:
            chunk = stream.read(remaining)
        except Exception:
            raise SandboxReceiverIOError("failed to read validation channel") from None

        if chunk == b"":
            if chunks:
                raise _IncompleteFrame
            time_remaining = deadline - _monotonic()
            if time_remaining <= 0:
                raise SandboxReceiverIOError(
                    "timed out waiting for validation context"
                )
            _sleep(min(_FIRST_FRAME_RETRY_INTERVAL_SECONDS, time_remaining))
            continue
        if not isinstance(chunk, bytes) or len(chunk) > remaining:
            raise SandboxReceiverIOError("invalid validation channel read result")
        chunks.extend(chunk)

    return bytes(chunks)


def _write_all(stream: BinaryIO, data: bytes) -> None:
    """Complete a possibly partial write or fail closed."""

    offset = 0
    while offset < len(data):
        try:
            written = stream.write(data[offset:])
        except Exception:
            raise SandboxReceiverIOError(
                "failed to write validation acknowledgement"
            ) from None
        remaining = len(data) - offset
        if type(written) is not int or written <= 0 or written > remaining:
            raise SandboxReceiverIOError("invalid validation channel write result")
        offset += written


def _send_rejection(
    stream: BinaryIO,
    reason_code: SandboxContextRejectionCode,
) -> SandboxContextReceiveResult:
    acknowledgement = SandboxContextAcknowledgement(
        protocol_version=SANDBOX_PROTOCOL_VERSION,
        status="rejected",
        reason_code=reason_code,
    )
    _write_all(stream, encode_sandbox_acknowledgement_frame(acknowledgement))
    return SandboxContextReceiveResult(manifest=None, acknowledgement=acknowledgement)


def receive_one_context(stream: BinaryIO) -> SandboxContextReceiveResult:
    """Read one bounded frame, acknowledge it, and never inspect a second one.

    Any bytes after the declared payload remain unread. The character-device
    stream boundary does not probe for trailing data because another byte may
    begin a subsequent message and a blocking probe could hang indefinitely.
    """

    try:
        header = _read_first_frame_header(stream)
    except _IncompleteFrame:
        return _send_rejection(stream, SandboxContextRejectionCode.INVALID_FRAME)

    payload_size = int.from_bytes(header, byteorder="big", signed=False)
    if payload_size == 0 or payload_size > MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES:
        return _send_rejection(stream, SandboxContextRejectionCode.INVALID_FRAME)

    try:
        payload = _read_exact(stream, payload_size)
    except _IncompleteFrame:
        return _send_rejection(stream, SandboxContextRejectionCode.INVALID_FRAME)

    try:
        manifest = decode_sandbox_context_frame(header + payload)
    except SandboxTransportError:
        return _send_rejection(stream, SandboxContextRejectionCode.INVALID_CONTEXT)

    acknowledgement = SandboxContextAcknowledgement(
        protocol_version=SANDBOX_PROTOCOL_VERSION,
        status="accepted",
    )
    _write_all(stream, encode_sandbox_acknowledgement_frame(acknowledgement))
    return SandboxContextReceiveResult(
        manifest=manifest,
        acknowledgement=acknowledgement,
    )


def open_fixed_validation_channel_and_receive() -> SandboxContextReceiveResult:
    """Open the single fixed virtio port once and process one context frame."""

    flags = os.O_RDWR | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(SENTRA_VALIDATION_DEVICE_PATH, flags)
    except OSError:
        raise SandboxReceiverIOError(
            "could not open fixed validation channel"
        ) from None

    try:
        stream = os.fdopen(descriptor, "r+b", buffering=0)
    except (OSError, ValueError):
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise SandboxReceiverIOError(
            "could not open fixed validation channel"
        ) from None

    with stream:
        return receive_one_context(stream)
