"""Guest-safe shared schema for SENTRA sandbox context exchange."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)


SANDBOX_CONTEXT_CONTROL_ID = "7.1.1"
SANDBOX_CONTEXT_VERSION = "1"
SANDBOX_PROTOCOL_VERSION = "1"
SENTRA_VALIDATION_CHANNEL_NAME = "org.sentra.validation.0"


class _StrictSandboxProtocolModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PasswdSourceState(_StrictSandboxProtocolModel):
    """The allowlisted M3 metadata needed to model control 7.1.1."""

    passwd_file_mode: StrictStr = Field(pattern=r"^[0-7]{4}$")
    passwd_file_owner_uid: StrictInt = Field(ge=0)
    passwd_file_group_gid: StrictInt = Field(ge=0)


class SandboxContextManifest(_StrictSandboxProtocolModel):
    """Versioned guest-bound context containing no general target profile data."""

    context_version: Literal["1"]
    control_id: Literal["7.1.1"]
    source_state: PasswdSourceState


class SandboxContextRejectionCode(StrEnum):
    """Allowlisted, non-sensitive acknowledgement rejection reasons."""

    INVALID_FRAME = "invalid_frame"
    INVALID_CONTEXT = "invalid_context"
    UNSUPPORTED_CONTEXT = "unsupported_context"


class SandboxContextAcknowledgement(_StrictSandboxProtocolModel):
    """Fixed accepted/rejected response; it never carries the manifest back."""

    protocol_version: Literal["1"]
    status: Literal["accepted", "rejected"]
    reason_code: StrictStr | None = None

    @field_validator("reason_code")
    @classmethod
    def validate_reason_code(
        cls,
        value: str | None,
    ) -> str | None:
        allowed_codes = {code.value for code in SandboxContextRejectionCode}
        if value is not None and value not in allowed_codes:
            raise ValueError("acknowledgement reason code is not allowlisted")
        return value

    @model_validator(mode="after")
    def validate_status_fields(self) -> "SandboxContextAcknowledgement":
        reason_was_supplied = "reason_code" in self.model_fields_set
        if self.status == "accepted":
            if self.reason_code is not None or reason_was_supplied:
                raise ValueError("accepted acknowledgement cannot include a reason")
        elif self.reason_code is None:
            raise ValueError("rejected acknowledgement requires a reason code")
        return self
