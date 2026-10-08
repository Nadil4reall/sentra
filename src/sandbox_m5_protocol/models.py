"""Strict wire models for the post-context-ACK M5 sandbox session."""

from __future__ import annotations

import re
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, model_validator

from src.sandbox_runtime.reproduction import SandboxPasswdReproductionResult
from src.sandbox_validator.models import CompatibilityReference, ExecutionMode, ValidationReport


_MODE_PATTERN = re.compile(r"[0-7]{4}\Z")


class _StrictM5ProtocolModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SandboxM5ControllerAuthorization(_StrictM5ProtocolModel):
    """Controller authorization for one fixed 7.1.1 sandbox experiment.

    The sandbox-operator acknowledgement is intentionally local to the guest
    session and is never present in this Controller-supplied model.
    """

    protocol_version: Literal["1"] = "1"
    validation_job_id: UUID
    profile_id: UUID
    compatibility_report_id: UUID
    context_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    control_id: Literal["7.1.1"] = "7.1.1"
    administrator_approval_acknowledged: StrictBool
    compatibility_risk_acknowledged: StrictBool
    compatibility_override_reason: StrictStr | None
    compatibility_reference: CompatibilityReference

    @model_validator(mode="after")
    def validate_lineage(self) -> "SandboxM5ControllerAuthorization":
        reference = self.compatibility_reference
        if reference.control_id != self.control_id:
            raise ValueError("M4 reference control does not match authorization")
        if reference.profile_source != f"controller-stored-profile:{self.profile_id}":
            raise ValueError("M4 profile source does not match authorization lineage")
        if reference.report_source != (
            "controller-stored-compatibility-report:"
            f"{self.compatibility_report_id}"
        ):
            raise ValueError("M4 report source does not match authorization lineage")
        return self


class SandboxM5SessionResult(_StrictM5ProtocolModel):
    """Bounded guest result with fixed job, M4, and reproduction lineage."""

    protocol_version: Literal["1"] = "1"
    validation_job_id: UUID
    profile_id: UUID
    compatibility_report_id: UUID
    context_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    control_id: Literal["7.1.1"] = "7.1.1"
    reproduction: SandboxPasswdReproductionResult
    report: ValidationReport

    @model_validator(mode="after")
    def validate_session_result(self) -> "SandboxM5SessionResult":
        reproduction = self.reproduction
        if (
            type(reproduction) is not SandboxPasswdReproductionResult
            or reproduction.control_id != "7.1.1"
            or reproduction.target_path != "/etc/passwd"
            or reproduction.reproduced is not True
            or type(reproduction.requested_mode) is not str
            or _MODE_PATTERN.fullmatch(reproduction.requested_mode) is None
            or reproduction.after_mode != reproduction.requested_mode
            or type(reproduction.requested_uid) is not int
            or reproduction.requested_uid < 0
            or type(reproduction.requested_gid) is not int
            or reproduction.requested_gid < 0
            or type(reproduction.after_uid) is not int
            or reproduction.after_uid != reproduction.requested_uid
            or type(reproduction.after_gid) is not int
            or reproduction.after_gid != reproduction.requested_gid
            or type(reproduction.before_mode) is not str
            or _MODE_PATTERN.fullmatch(reproduction.before_mode) is None
            or type(reproduction.before_uid) is not int
            or reproduction.before_uid < 0
            or type(reproduction.before_gid) is not int
            or reproduction.before_gid < 0
        ):
            raise ValueError("result reproduction evidence is invalid")

        try:
            report = ValidationReport.model_validate_json(
                self.report.model_dump_json(), strict=True
            )
        except Exception:
            raise ValueError("result report is invalid") from None
        if report != self.report:
            raise ValueError("result report changed during validation")
        if report.mode is not ExecutionMode.EXECUTE or len(report.control_results) != 1:
            raise ValueError("result must contain one executed control")

        control = report.control_results[0]
        reference = control.m4_input
        if (
            control.control_id != self.control_id
            or reference is None
            or reference.control_id != self.control_id
            or reference.profile_source
            != f"controller-stored-profile:{self.profile_id}"
            or reference.report_source
            != (
                "controller-stored-compatibility-report:"
                f"{self.compatibility_report_id}"
            )
            or control.m3_profile_source != reference.profile_source
        ):
            raise ValueError("result M4 lineage does not match its envelope")
        return self
