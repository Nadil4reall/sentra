"""Controller-side authorization and stream transaction for one M5 session."""

from __future__ import annotations

import logging
from typing import BinaryIO

from pydantic import ValidationError

from src.controller.models import (
    AdminAuth,
    JobStatus,
    SandboxSessionRecord,
    SandboxSessionStatus,
    ValidationJobCreateRequest,
    ValidationJobRecord,
    ValidationResultPayload,
)
from src.controller.service import ControllerService
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


_LOG = logging.getLogger(__name__)


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
        except Exception as error:
            _LOG.warning(
                "sandbox controller stage=ack_read_failed exception_type=%s",
                type(error).__name__,
            )
            raise SandboxM5ControllerError("Controller stream read failed") from None
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            raise SandboxM5ControllerError("Controller stream frame was truncated")
        result.extend(chunk)
    return bytes(result)


def _read_acknowledgement(stream: BinaryIO) -> SandboxContextAcknowledgement:
    _LOG.warning("sandbox controller stage=ack_header_read_started")
    header = _read_exact(stream, 4)
    _LOG.warning("sandbox controller stage=ack_header_complete")
    payload_size = int.from_bytes(header, byteorder="big", signed=False)
    if payload_size == 0 or payload_size > MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES:
        raise SandboxM5ControllerError("context acknowledgement length was rejected")
    try:
        payload = _read_exact(stream, payload_size)
        _LOG.warning("sandbox controller stage=ack_payload_complete")
        return decode_sandbox_acknowledgement_frame(header + payload)
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
    _LOG.warning("sandbox controller stage=context_write_started")
    _write_all(stream, context_frame)
    _LOG.warning("sandbox controller stage=context_write_complete")
    acknowledgement = _read_acknowledgement(stream)
    if acknowledgement.status != "accepted":
        raise SandboxM5ControllerError("sandbox context was rejected by guest")
    _LOG.warning("sandbox controller stage=ack_accepted")
    try:
        write_sandbox_m5_authorization(stream, authorization)
        result = read_sandbox_m5_result(stream)
    except SandboxM5TransportError:
        raise SandboxM5ControllerError("M5 session transport was rejected") from None
    return sandbox_m5_result_to_validation_payload(job, result, manifest)

def run_controller_owned_sandbox_validation(
    service: ControllerService,
    provider: object,
    auth: AdminAuth,
    *,
    session: SandboxSessionRecord,
    request: ValidationJobCreateRequest,
    manifest: SandboxContextManifest,
) -> tuple[ValidationResultPayload, SandboxSessionRecord]:
    """Run one fixed M5 job through the Controller-owned disposable sandbox."""

    if (
        type(session) is not SandboxSessionRecord
        or type(request) is not ValidationJobCreateRequest
        or type(manifest) is not SandboxContextManifest
    ):
        raise SandboxM5ControllerError(
            "sandbox validation execution input was rejected"
        )

    current = service.get_sandbox_session(
        auth,
        target_id=session.source_target_id,
        profile_id=session.source_profile_id,
        compatibility_report_id=session.source_compatibility_report_id,
        sandbox_session_id=session.sandbox_session_id,
    )

    if current.status is not SandboxSessionStatus.READY:
        raise SandboxM5ControllerError(
            "sandbox is not ready for validation"
        )

    if (
        request.target_id != current.source_target_id
        or request.profile_id != current.source_profile_id
        or request.compatibility_report_id
        != current.source_compatibility_report_id
        or request.control_id != current.control_id
        or manifest.control_id != current.control_id
    ):
        raise SandboxM5ControllerError(
            "sandbox validation lineage was rejected"
        )

    opener = getattr(provider, "open_validation_channel", None)
    if not callable(opener):
        raise SandboxM5ControllerError(
            "sandbox validation channel is unavailable"
        )

    # The authoritative DISPATCHED job is persisted and bound to this VM,
    # in the same transaction as the READY -> VALIDATING transition.
    try:
        dispatched_job, validating = service.create_and_dispatch_sandbox_validation_job(
            auth,
            sandbox_session_id=current.sandbox_session_id,
            request=request,
        )
    except Exception:
        raise SandboxM5ControllerError(
            "sandbox validation dispatch was rejected"
        ) from None
    if (
        validating.status is not SandboxSessionStatus.VALIDATING
        or dispatched_job.status is not JobStatus.DISPATCHED
        or dispatched_job.request_id != request.request_id
        or dispatched_job.target_id != current.source_target_id
        or dispatched_job.profile_id != current.source_profile_id
        or dispatched_job.compatibility_report_id
        != current.source_compatibility_report_id
        or dispatched_job.compatibility_reference
        != current.compatibility_reference
        or dispatched_job.dispatched_at != validating.validation_started_at
    ):
        raise SandboxM5ControllerError(
            "sandbox validation dispatch was not confirmed"
        )

    try:
        channel = opener(current.sandbox_session_id)
        if channel is None:
            raise SandboxM5ControllerError(
                "sandbox validation channel is unavailable"
            )

        with channel as stream:
            payload = run_sandbox_m5_controller_transaction(
                stream,
                manifest=manifest,
                job=dispatched_job,
            )
    except Exception as error:
        try:
            service.mark_failed(
                current.sandbox_session_id,
                failure_reason="sandbox validation failed",
            )
        except Exception:
            pass

        if isinstance(error, SandboxM5ControllerError):
            raise

        raise SandboxM5ControllerError(
            "sandbox validation execution failed"
        ) from None

    try:
        completed = service.complete_sandbox_validation_job(
            auth,
            sandbox_session_id=current.sandbox_session_id,
            validation_job_id=dispatched_job.validation_job_id,
            payload=payload,
        )
    except Exception:
        try:
            service.mark_failed(
                current.sandbox_session_id,
                failure_reason="sandbox validation completion failed",
            )
        except Exception:
            pass
        raise SandboxM5ControllerError(
            "sandbox validation completion failed"
        ) from None

    return payload, completed
