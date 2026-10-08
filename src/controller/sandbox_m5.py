"""Controller-side authorization and stream transaction for one M5 session."""

from __future__ import annotations

from typing import BinaryIO

from pydantic import ValidationError

from src.controller.models import (
    JobStatus,
    ValidationJobRecord,
    ValidationResultPayload,
)
from src.controller.validation import require_payload_matches_job
from src.sandbox_protocol import (
    MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES,
    SandboxContextAcknowledgement,
    SandboxContextManifest,
    SandboxTransportError,
    decode_sandbox_acknowledgement_frame,
    decode_sandbox_context_frame,
    encode_sandbox_context_frame,
)
from src.sandbox_m5_protocol.context import sandbox_context_sha256
from src.sandbox_m5_protocol.models import (
    SandboxM5ControllerAuthorization,
    SandboxM5SessionResult,
)
from src.sandbox_m5_protocol.transport import (
    SandboxM5TransportError,
    read_sandbox_m5_result,
    write_sandbox_m5_authorization,
)


class SandboxM5ControllerError(RuntimeError):
    """Fixed, non-sensitive error for a failed Controller-side transaction."""


def build_sandbox_m5_authorization(
    job: ValidationJobRecord,
    manifest: SandboxContextManifest,
) -> SandboxM5ControllerAuthorization:
    """Derive the fixed guest authorization from one Controller job record."""

    if type(job) is not ValidationJobRecord or type(manifest) is not SandboxContextManifest:
        raise SandboxM5ControllerError("M5 authorization job was rejected")
    try:
        validated_job = ValidationJobRecord.model_validate_json(
            job.model_dump_json(), strict=True
        )
    except (ValidationError, ValueError, TypeError):
        raise SandboxM5ControllerError("M5 authorization job was rejected") from None
    if (
        validated_job.control_id != "7.1.1"
        or validated_job.status is not JobStatus.DISPATCHED
        or validated_job.dispatched_at is None
    ):
        raise SandboxM5ControllerError("M5 authorization job was rejected")
    try:
        validated_manifest = decode_sandbox_context_frame(
            encode_sandbox_context_frame(manifest)
        )
        context_sha256 = sandbox_context_sha256(validated_manifest)
    except (SandboxTransportError, TypeError, ValueError):
        raise SandboxM5ControllerError("M5 authorization context was rejected") from None
    if validated_manifest.control_id != validated_job.control_id:
        raise SandboxM5ControllerError("M5 authorization context was rejected")
    try:
        return SandboxM5ControllerAuthorization(
            validation_job_id=validated_job.validation_job_id,
            profile_id=validated_job.profile_id,
            compatibility_report_id=validated_job.compatibility_report_id,
            context_sha256=context_sha256,
            control_id="7.1.1",
            administrator_approval_acknowledged=(
                validated_job.administrator_approval_acknowledged
            ),
            compatibility_risk_acknowledged=(
                validated_job.compatibility_risk_acknowledged
            ),
            compatibility_override_reason=(
                validated_job.compatibility_override_reason
            ),
            compatibility_reference=validated_job.compatibility_reference,
        )
    except (ValidationError, ValueError, TypeError):
        raise SandboxM5ControllerError("M5 authorization job was rejected") from None


def sandbox_m5_result_to_validation_payload(
    job: ValidationJobRecord,
    result: SandboxM5SessionResult,
    manifest: SandboxContextManifest,
) -> ValidationResultPayload:
    """Validate result lineage and produce the existing strict M6D payload."""

    if (
        type(job) is not ValidationJobRecord
        or type(result) is not SandboxM5SessionResult
        or type(manifest) is not SandboxContextManifest
    ):
        raise SandboxM5ControllerError("M5 session result was rejected")
    try:
        validated_job = ValidationJobRecord.model_validate_json(
            job.model_dump_json(), strict=True
        )
        validated_result = SandboxM5SessionResult.model_validate_json(
            result.model_dump_json(), strict=True
        )
    except (ValidationError, ValueError, TypeError):
        raise SandboxM5ControllerError("M5 session result was rejected") from None
    try:
        expected_context_sha256 = sandbox_context_sha256(
            decode_sandbox_context_frame(encode_sandbox_context_frame(manifest))
        )
    except (SandboxTransportError, TypeError, ValueError):
        raise SandboxM5ControllerError("M5 session context was rejected") from None
    if (
        validated_result.validation_job_id != validated_job.validation_job_id
        or validated_result.profile_id != validated_job.profile_id
        or validated_result.compatibility_report_id
        != validated_job.compatibility_report_id
        or validated_result.control_id != validated_job.control_id
        or validated_result.context_sha256 != expected_context_sha256
    ):
        raise SandboxM5ControllerError("M5 session lineage was rejected")
    try:
        payload = ValidationResultPayload.model_validate(
            {
                "target_id": validated_job.target_id,
                "profile_id": validated_result.profile_id,
                "compatibility_report_id": (
                    validated_result.compatibility_report_id
                ),
                "validation_job_id": validated_result.validation_job_id,
                "control_id": validated_result.control_id,
                "report": validated_result.report,
            },
            strict=True,
        )
        require_payload_matches_job(payload, validated_job)
    except (ValidationError, ValueError, TypeError):
        raise SandboxM5ControllerError("M5 session result was rejected") from None
    return payload


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        remaining = size - len(result)
        try:
            chunk = stream.read(remaining)
        except Exception:
            raise SandboxM5ControllerError("Controller stream read failed") from None
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            raise SandboxM5ControllerError("Controller stream frame was truncated")
        result.extend(chunk)
    return bytes(result)


def _read_acknowledgement(stream: BinaryIO) -> SandboxContextAcknowledgement:
    header = _read_exact(stream, 4)
    payload_size = int.from_bytes(header, byteorder="big", signed=False)
    if payload_size == 0 or payload_size > MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES:
        raise SandboxM5ControllerError("context acknowledgement length was rejected")
    try:
        return decode_sandbox_acknowledgement_frame(
            header + _read_exact(stream, payload_size)
        )
    except SandboxTransportError:
        raise SandboxM5ControllerError("context acknowledgement was rejected") from None


def _write_all(stream: BinaryIO, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            count = stream.write(data[offset:])
        except Exception:
            raise SandboxM5ControllerError("Controller stream write failed") from None
        remaining = len(data) - offset
        if type(count) is not int or count <= 0 or count > remaining:
            raise SandboxM5ControllerError("Controller stream write failed")
        offset += count


def run_sandbox_m5_controller_transaction(
    stream: BinaryIO,
    *,
    manifest: SandboxContextManifest,
    job: ValidationJobRecord,
) -> ValidationResultPayload:
    """Exchange context, ACK, fixed authorization, and one bounded result."""

    authorization = build_sandbox_m5_authorization(job, manifest)
    try:
        context_frame = encode_sandbox_context_frame(manifest)
    except (SandboxTransportError, TypeError, ValueError):
        raise SandboxM5ControllerError("sandbox context was rejected") from None
    _write_all(stream, context_frame)
    acknowledgement = _read_acknowledgement(stream)
    if acknowledgement.status != "accepted":
        raise SandboxM5ControllerError("sandbox context was rejected by guest")
    try:
        write_sandbox_m5_authorization(stream, authorization)
        result = read_sandbox_m5_result(stream)
    except SandboxM5TransportError:
        raise SandboxM5ControllerError("M5 session transport was rejected") from None
    return sandbox_m5_result_to_validation_payload(job, result, manifest)
