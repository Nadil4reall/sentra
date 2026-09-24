"""Strict configuration for the outbound Agent-to-Controller transport."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class AgentTransportConfig(BaseModel):
    """TLS-only configuration for the real M6B HTTPS client.

    The two literal fields intentionally make insecure variants unrepresentable.
    There is no runtime switch that disables certificate verification.
    """

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
    request_timeout_seconds: float = Field(default=30.0, gt=0, le=300)

    @model_validator(mode="after")
    def validate_tls_boundary(self) -> "AgentTransportConfig":
        if self.controller_url.scheme != "https":
            raise ValueError("Controller transport must use HTTPS")
        if self.controller_url.username is not None or self.controller_url.password is not None:
            raise ValueError("Controller URL must not contain credentials")
        if self.controller_url.query is not None or self.controller_url.fragment is not None:
            raise ValueError("Controller URL must not contain a query or fragment")
        if self.controller_url.path.rstrip("/") not in {"", "/api/v1"}:
            raise ValueError(
                "Controller URL path must be empty or the versioned /api/v1 prefix"
            )
        if str(self.controller_ca_path) in {"", "."}:
            raise ValueError("Controller CA path must identify a configured bundle")
        return self


class AgentRuntimeConfig(BaseModel):
    """Non-secret configuration for one Agent execution cycle."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
    )

    transport: AgentTransportConfig
    state_path: Path
    agent_version: str = Field(min_length=1)
    profiler_version: str | None = Field(default=None, min_length=1)
    sentra_version: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_runtime_paths_and_versions(self) -> "AgentRuntimeConfig":
        if self.state_path.name in {"", ".", ".."}:
            raise ValueError("Agent state path must name a file")
        for name, value in (
            ("agent_version", self.agent_version),
            ("profiler_version", self.profiler_version),
            ("sentra_version", self.sentra_version),
        ):
            if value is not None and not value.strip():
                raise ValueError(f"{name} must not be blank")
        return self


__all__ = ["AgentRuntimeConfig", "AgentTransportConfig"]
