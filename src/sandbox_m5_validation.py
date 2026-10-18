"""Explicit opt-in bridge from validated sandbox reproduction to M5.

This module is kept outside ``sandbox_runtime`` so the fixed guest receiver and
boot runtime do not import or invoke the M5 validator.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr, model_validator

from src.sandbox_validator.adapters.base import AdapterContext
from src.sandbox_validator.loaders import ValidationInputs, load_validation_inputs
from src.sandbox_validator.models import (
    CompatibilityReference,
    ExecutionMode,
    ValidationReport,
)
from src.sandbox_validator.validator import SandboxValidator, ValidationRequest
from src.sandbox_runtime.reproduction import (
    SANDBOX_PASSWD_TARGET_PATH,
    SandboxIpForwardingReproductionResult,
    SandboxPasswdReproductionResult,
)


_SUPPORTED_CONTROL_IDS = frozenset({"7.1.1", "3.3.1"})
_MODE_PATTERN = re.compile(r"[0-7]{4}\Z")
_FIXED_ERROR_MESSAGE = "sandbox M5 validation input was rejected"


class SandboxM5ValidationInput(BaseModel):
    """Only explicit execution approvals and a strict M4 reference are accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    control_id: Literal["7.1.1", "3.3.1"]
    administrator_approval_acknowledged: StrictBool
    sandbox_operator_acknowledged: StrictBool
    compatibility_risk_acknowledged: StrictBool
    compatibility_override_reason: StrictStr | None
    compatibility_reference: CompatibilityReference

    @model_validator(mode="after")
    def validate_compatibility_control(self) -> "SandboxM5ValidationInput":
        if self.compatibility_reference.control_id != self.control_id:
            raise ValueError("M4 compatibility reference must match selected control")
        return self


class SandboxM5ValidationError(RuntimeError):
    """Fixed, non-sensitive error for invalid reproduction/authorization input."""


def _validate_reproduction(
    result: SandboxPasswdReproductionResult | SandboxIpForwardingReproductionResult,
) -> str:
    if type(result) is SandboxPasswdReproductionResult:
        if (
            result.control_id != "7.1.1"
            or result.target_path != SANDBOX_PASSWD_TARGET_PATH
            or result.reproduced is not True
            or type(result.requested_mode) is not str
            or _MODE_PATTERN.fullmatch(result.requested_mode) is None
            or result.after_mode != result.requested_mode
            or type(result.requested_uid) is not int
            or result.requested_uid < 0
            or type(result.requested_gid) is not int
            or result.requested_gid < 0
            or type(result.after_uid) is not int
            or result.after_uid != result.requested_uid
            or type(result.after_gid) is not int
            or result.after_gid != result.requested_gid
        ):
            raise SandboxM5ValidationError(_FIXED_ERROR_MESSAGE)
        return "7.1.1"
    if type(result) is SandboxIpForwardingReproductionResult:
        if (
            result.control_id != "3.3.1"
            or result.reproduced is not True
            or type(result.before_ipv4) is not int
            or result.before_ipv4 not in {0, 1}
            or type(result.requested_ipv4) is not int
            or result.requested_ipv4 not in {0, 1}
            or result.after_ipv4 != result.requested_ipv4
            or type(result.ipv6_enabled) is not bool
            or (
                result.ipv6_enabled
                and (
                    type(result.before_ipv6) is not int
                    or result.before_ipv6 not in {0, 1}
                    or type(result.requested_ipv6) is not int
                    or result.requested_ipv6 not in {0, 1}
                    or result.after_ipv6 != result.requested_ipv6
                )
            )
            or (
                not result.ipv6_enabled
                and (
                    result.before_ipv6 is not None
                    or result.requested_ipv6 is not None
                    or result.after_ipv6 is not None
                )
            )
        ):
            raise SandboxM5ValidationError(_FIXED_ERROR_MESSAGE)
        return "3.3.1"
    raise SandboxM5ValidationError(_FIXED_ERROR_MESSAGE)


def _validate_authorization(
    authorization: SandboxM5ValidationInput,
) -> SandboxM5ValidationInput:
    if type(authorization) is not SandboxM5ValidationInput:
        raise SandboxM5ValidationError(_FIXED_ERROR_MESSAGE)
    try:
        return SandboxM5ValidationInput.model_validate(authorization.model_dump())
    except Exception:
        raise SandboxM5ValidationError(_FIXED_ERROR_MESSAGE) from None


def run_m5_validation_after_reproduction(
    reproduction: SandboxPasswdReproductionResult | SandboxIpForwardingReproductionResult,
    authorization: SandboxM5ValidationInput,
) -> ValidationReport:
    """Run one allowlisted M5 adapter only after successful reproduction.

    The guest appliance entrypoint intentionally does not call this function in
    this integration slice. Its production context is always the guest root.
    """

    reproduced_control_id = _validate_reproduction(reproduction)
    validated_authorization = _validate_authorization(authorization)
    if (
        reproduced_control_id != validated_authorization.control_id
        or reproduced_control_id not in _SUPPORTED_CONTROL_IDS
    ):
        raise SandboxM5ValidationError(_FIXED_ERROR_MESSAGE)

    loaded_inputs = load_validation_inputs(reproduced_control_id)
    if (
        type(loaded_inputs) is not ValidationInputs
        or loaded_inputs.control_id != reproduced_control_id
    ):
        raise SandboxM5ValidationError(_FIXED_ERROR_MESSAGE)

    compatibility = validated_authorization.compatibility_reference
    m5_inputs = replace(
        loaded_inputs,
        m3_profile_source=compatibility.profile_source,
        compatibility=compatibility,
    )
    request = ValidationRequest(
        control_id=reproduced_control_id,
        mode=ExecutionMode.EXECUTE,
        sandbox_operator_acknowledged=(
            validated_authorization.sandbox_operator_acknowledged
        ),
        administrator_approval_acknowledged=(
            validated_authorization.administrator_approval_acknowledged
        ),
        compatibility_risk_acknowledged=(
            validated_authorization.compatibility_risk_acknowledged
        ),
        compatibility_override_reason=(
            validated_authorization.compatibility_override_reason
        ),
    )
    validator = SandboxValidator(context=AdapterContext(root=Path("/")))
    return validator.validate(m5_inputs, request)
