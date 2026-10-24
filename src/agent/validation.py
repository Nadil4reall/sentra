"""Narrow Agent adapter to the existing M5 sandbox validator.

The Controller may select only the initial M6D control.  It cannot supply a
filesystem root, path, command, argv, service action, or adapter implementation.
The local sandbox acknowledgement remains an Agent-operator decision separate
from the Controller administrator approval recorded in the job.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Protocol, runtime_checkable

from src.controller.models import (
    ValidationJobRecord,
    ValidationResultPayload,
)
from src.sandbox_validator.loaders import (
    ValidationInputs,
    load_validation_inputs,
)
from src.sandbox_validator.validator import SandboxValidator, ValidationRequest


M6D_AGENT_CONTROL_ID = "7.1.1"


@runtime_checkable
class ControlValidationAdapter(Protocol):
    """Execute one fixed, structured M5 sandbox-validation request."""

    def validate(
        self,
        job: ValidationJobRecord,
        *,
        sandbox_operator_acknowledged: bool,
    ) -> ValidationResultPayload: ...


class LocalSandboxControlValidator:
    """Map the sole initial M6D control to unchanged in-process M5 logic."""

    def __init__(self, *, validator: SandboxValidator | None = None) -> None:
        # SandboxValidator's production default is AdapterContext(root=Path("/")).
        # No Controller field can replace that context or its fixed adapter registry.
        self._validator = validator or SandboxValidator()

    @staticmethod
    def _inputs(job: ValidationJobRecord) -> ValidationInputs:
        if job.control_id != M6D_AGENT_CONTROL_ID:
            raise ValueError("validation control is not enabled on this Agent")
        local = load_validation_inputs(M6D_AGENT_CONTROL_ID)
        return replace(
            local,
            m3_profile_source=job.compatibility_reference.profile_source,
            compatibility=job.compatibility_reference,
        )

    def validate(
        self,
        job: ValidationJobRecord,
        *,
        sandbox_operator_acknowledged: bool,
    ) -> ValidationResultPayload:
        if job.control_id != M6D_AGENT_CONTROL_ID:
            raise ValueError("validation control is not enabled on this Agent")

        report = self._validator.validate(
            self._inputs(job),
            ValidationRequest(
                control_id=M6D_AGENT_CONTROL_ID,
                mode=job.execution_mode,
                sandbox_operator_acknowledged=sandbox_operator_acknowledged,
                administrator_approval_acknowledged=(
                    job.administrator_approval_acknowledged
                ),
                compatibility_risk_acknowledged=(
                    job.compatibility_risk_acknowledged
                ),
                compatibility_override_reason=(
                    job.compatibility_override_reason
                ),
            ),
        )
        payload = ValidationResultPayload(
            target_id=job.target_id,
            profile_id=job.profile_id,
            compatibility_report_id=job.compatibility_report_id,
            validation_job_id=job.validation_job_id,
            control_id=job.control_id,
            validation_mode=job.validation_mode,
            execution_mode=job.execution_mode,
            report=report,
        )
        # Make the strict wire model the final boundary before journaling.
        return ValidationResultPayload.model_validate(
            payload.model_dump(mode="python"),
            strict=True,
        )


__all__ = [
    "ControlValidationAdapter",
    "LocalSandboxControlValidator",
    "M6D_AGENT_CONTROL_ID",
]
