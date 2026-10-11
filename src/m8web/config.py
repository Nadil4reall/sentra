"""Configuration boundary for the SENTRA M8 web application."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class M8WebConfigurationError(ValueError):
    """Raised when the M8 web runtime configuration is unsafe or invalid."""


@dataclass(frozen=True, slots=True)
class M8WebSettings:
    """Immutable configuration for one M8 web process."""

    database: Path

    def __post_init__(self) -> None:
        database = Path(self.database).expanduser()

        if not database.is_absolute():
            raise M8WebConfigurationError(
                "M8 database path must be absolute"
            )

        if database.is_symlink():
            raise M8WebConfigurationError(
                "M8 database path must not be a symbolic link"
            )

        if not database.exists():
            raise M8WebConfigurationError(
                "M8 database does not exist"
            )

        if not database.is_file():
            raise M8WebConfigurationError(
                "M8 database path must reference a regular file"
            )

        object.__setattr__(self, "database", database)


__all__ = [
    "M8WebConfigurationError",
    "M8WebSettings",
]
