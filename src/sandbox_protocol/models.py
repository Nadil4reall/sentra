"""Guest-safe shared schema for SENTRA sandbox context exchange."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)


SANDBOX_CONTEXT_CONTROL_ID = "7.1.1"
SANDBOX_CONTEXT_SUPPORTED_CONTROL_IDS = frozenset({"7.1.1", "3.3.1"})
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


class IpForwardingSourceState(_StrictSandboxProtocolModel):
    """Only collected forwarding facts needed for the 3.3.1 sandbox state."""

    ipv4_forwarding_status: StrictInt = Field(ge=0, le=1)
    ipv6_enabled: StrictBool
    ipv6_forwarding_status: StrictInt | None = Field(default=None, ge=0, le=1)

    @model_validator(mode="after")
    def validate_ipv6_condition(self) -> "IpForwardingSourceState":
        if self.ipv6_enabled != (self.ipv6_forwarding_status is not None):
            raise ValueError("IPv6 forwarding status must match IPv6 applicability")
        return self


class SandboxContextManifest(_StrictSandboxProtocolModel):
    """Versioned guest-bound context containing no general target profile data."""

    context_version: Literal["1"]
    control_id: Literal["7.1.1", "3.3.1"]
    source_state: PasswdSourceState | IpForwardingSourceState

    @model_validator(mode="after")
    def validate_control_state_pair(self) -> "SandboxContextManifest":
        expected = (
            PasswdSourceState
            if self.control_id == "7.1.1"
            else IpForwardingSourceState
        )
        if type(self.source_state) is not expected:
            raise ValueError("sandbox context state does not match its control")
        return self


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
