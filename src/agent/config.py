"""Future transport-security contract for real Agent-to-Controller testing.

M6A does not implement network transport.  This strict configuration makes the later
boundary explicit: an Agent transport must use HTTPS and verify the Controller against
an operator-supplied CA bundle.  There is intentionally no plaintext or
skip-verification mode.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, HttpUrl, model_validator


class AgentTransportConfig(BaseModel):
    """TLS-only configuration contract for a future network adapter."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
    )

    controller_url: HttpUrl
    controller_ca_path: Path
    tls_required: Literal[True] = True
    verify_controller_certificate: Literal[True] = True

    @model_validator(mode="after")
    def validate_tls_boundary(self) -> "AgentTransportConfig":
        if self.controller_url.scheme != "https":
            raise ValueError("Controller transport must use HTTPS")
        if self.controller_url.username is not None or self.controller_url.password is not None:
            raise ValueError("Controller URL must not contain credentials")
        if str(self.controller_ca_path) in {"", "."}:
            raise ValueError("Controller CA path must identify a configured bundle")
        return self


__all__ = ["AgentTransportConfig"]
