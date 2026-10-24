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
    SandboxPasswdReproductionResult,
)


_CONTROL_ID: Literal["7.1.1"] = "7.1.1"
_MODE_PATTERN = re.compile(r"[0-7]{4}\Z")
_FIXED_ERROR_MESSAGE = "sandbox M5 validation input was rejected"


class SandboxM5ValidationInput(BaseModel):
    """Only explicit execution approvals and a strict M4 reference are accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    control_id: Literal["7.1.1"]
    administrator_approval_acknowledged: StrictBool
    sandbox_operator_acknowledged: StrictBool
    compatibility_risk_acknowledged: StrictBool
    compatibility_override_reason: StrictStr | None
    compatibility_reference: CompatibilityReference

    @model_validator(mode="after")
    def validate_compatibility_control(self) -> "SandboxM5ValidationInput":
        if self.compatibility_reference.control_id != self.control_id:
            raise ValueError("M4 compatibility reference must match control 7.1.1")
        return self


class SandboxM5ValidationError(RuntimeError):
    """Fixed, non-sensitive error for invalid reproduction/authorization input."""


def _validate_reproduction(
    result: SandboxPasswdReproductionResult,
) -> None:
    if type(result) is not SandboxPasswdReproductionResult:
        raise SandboxM5ValidationError(_FIXED_ERROR_MESSAGE)
    if (
        result.control_id != _CONTROL_ID
        or result.target_path != SANDBOX_PASSWD_TARGET_PATH
        or result.reproduced is not True
    ):
        raise SandboxM5ValidationError(_FIXED_ERROR_MESSAGE)
    if (
        type(result.requested_mode) is not str
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
    reproduction: SandboxPasswdReproductionResult,
    authorization: SandboxM5ValidationInput,
) -> ValidationReport:
    """Run fixed 7.1.1 M5 library logic only after successful reproduction.

    The guest appliance entrypoint intentionally does not call this function in
    this integration slice. Its production context is always the guest root.
    """

    _validate_reproduction(reproduction)
    validated_authorization = _validate_authorization(authorization)

    loaded_inputs = load_validation_inputs("7.1.1")
    if (
        type(loaded_inputs) is not ValidationInputs
        or loaded_inputs.control_id != _CONTROL_ID
    ):
        raise SandboxM5ValidationError(_FIXED_ERROR_MESSAGE)

    compatibility = validated_authorization.compatibility_reference
    m5_inputs = replace(
        loaded_inputs,
        m3_profile_source=compatibility.profile_source,
        compatibility=compatibility,
    )
    request = ValidationRequest(
        control_id="7.1.1",
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
