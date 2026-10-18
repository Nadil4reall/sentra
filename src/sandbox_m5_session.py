"""Opt-in one-shot guest session for context reproduction and M5 validation."""

from __future__ import annotations

from typing import BinaryIO

from src.sandbox_m5_validation import (
    SandboxM5ValidationInput,
    run_m5_validation_after_reproduction,
)
from src.sandbox_m5_protocol.models import SandboxM5SessionResult
from src.sandbox_m5_protocol.context import sandbox_context_sha256
from src.sandbox_m5_protocol.transport import (
    SandboxM5TransportError,
    read_sandbox_m5_authorization,
    write_sandbox_m5_result,
)
from src.sandbox_runtime.receiver import receive_one_context
from src.sandbox_runtime.reproduction import (
    SandboxIpForwardingReproductionResult,
    SandboxPasswdReproductionResult,
    SandboxStateReproductionError,
    reproduce_ip_forwarding_source_state,
    reproduce_passwd_source_state,
)
from src.sandbox_validator.models import ExecutionMode, ValidationReport


class SandboxM5SessionError(RuntimeError):
    """Fixed, non-sensitive error for an incomplete one-shot M5 session."""


def run_sandbox_m5_session(
    stream: BinaryIO,
    *,
    sandbox_operator_acknowledged: bool,
) -> SandboxM5SessionResult:
    """Receive one context and authorization, then run the selected fixed M5 path."""

    if type(sandbox_operator_acknowledged) is not bool:
        raise SandboxM5SessionError("sandbox M5 session was rejected")

    try:
        received = receive_one_context(stream)
    except Exception:
        raise SandboxM5SessionError("sandbox M5 session was rejected") from None
    if (
        received.manifest is None
        or received.acknowledgement.status != "accepted"
    ):
        raise SandboxM5SessionError("sandbox M5 context was rejected")

    try:
        authorization = read_sandbox_m5_authorization(stream)
    except SandboxM5TransportError:
        raise SandboxM5SessionError("sandbox M5 authorization was rejected") from None
    if authorization.control_id != received.manifest.control_id:
        raise SandboxM5SessionError("sandbox M5 authorization was rejected")
    try:
        context_sha256 = sandbox_context_sha256(received.manifest)
    except (TypeError, ValueError):
        raise SandboxM5SessionError("sandbox M5 context was rejected") from None
    if context_sha256 != authorization.context_sha256:
        raise SandboxM5SessionError("sandbox M5 context lineage was rejected")

    try:
        if authorization.control_id == "7.1.1":
            reproduction = reproduce_passwd_source_state(received.manifest)
            expected_result_type = SandboxPasswdReproductionResult
        elif authorization.control_id == "3.3.1":
            reproduction = reproduce_ip_forwarding_source_state(received.manifest)
            expected_result_type = SandboxIpForwardingReproductionResult
        else:
            raise SandboxM5SessionError("sandbox M5 control was rejected")
        if type(reproduction) is not expected_result_type:
            raise SandboxStateReproductionError("sandbox source-state reproduction failed")
        m5_authorization = SandboxM5ValidationInput(
            control_id=authorization.control_id,
            administrator_approval_acknowledged=(
                authorization.administrator_approval_acknowledged
            ),
            sandbox_operator_acknowledged=sandbox_operator_acknowledged,
            compatibility_risk_acknowledged=(
                authorization.compatibility_risk_acknowledged
            ),
            compatibility_override_reason=(
                authorization.compatibility_override_reason
            ),
            compatibility_reference=authorization.compatibility_reference,
        )
        report = run_m5_validation_after_reproduction(
            reproduction,
            m5_authorization,
        )
        if type(report) is not ValidationReport:
            raise SandboxM5SessionError("sandbox M5 report was rejected")
        if report.mode is not ExecutionMode.EXECUTE or len(report.control_results) != 1:
            raise SandboxM5SessionError("sandbox M5 report was rejected")
        control = report.control_results[0]
        precheck = control.precheck
        if (
            control.control_id != authorization.control_id
            or control.m4_input != authorization.compatibility_reference
            or control.m3_profile_source
            != authorization.compatibility_reference.profile_source
            or precheck.administrator_approval_acknowledged
            is not authorization.administrator_approval_acknowledged
            or precheck.compatibility_risk_acknowledged
            is not authorization.compatibility_risk_acknowledged
            or precheck.compatibility_override_reason
            != authorization.compatibility_override_reason
            or precheck.sandbox_operator_acknowledged
            is not sandbox_operator_acknowledged
        ):
            raise SandboxM5SessionError("sandbox M5 report lineage was rejected")
        result = SandboxM5SessionResult(
            validation_job_id=authorization.validation_job_id,
            profile_id=authorization.profile_id,
            compatibility_report_id=authorization.compatibility_report_id,
            context_sha256=authorization.context_sha256,
            control_id=authorization.control_id,
            reproduction=reproduction,
            report=report,
        )
        write_sandbox_m5_result(stream, result)
    except SandboxM5SessionError:
        raise
    except (SandboxStateReproductionError, SandboxM5TransportError):
        raise SandboxM5SessionError("sandbox M5 session failed") from None
    except Exception:
        raise SandboxM5SessionError("sandbox M5 session failed") from None
    return result
