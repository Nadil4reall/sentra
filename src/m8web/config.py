"""Configuration boundary for the SENTRA M8 web application."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import stat


class M8WebConfigurationError(ValueError):
    """Raised when the M8 web runtime configuration is unsafe or invalid."""


@dataclass(frozen=True, slots=True)
class M8WebSettings:
    """Immutable configuration for one M8 web process."""

    database: Path
    secret_key_file: Path | None = None
    secure_cookie: bool = True
    secret_key: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.secure_cookie) is not bool:
            raise M8WebConfigurationError("secure cookie setting must be boolean")
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
        if self.secret_key_file is None:
            # Tests and embedded one-process use get a fresh, nonpersistent key.
            # The CLI requires an explicit protected file for stable sessions.
            object.__setattr__(self, "secret_key", os.urandom(32))
            return
        secret_path = Path(self.secret_key_file).expanduser()
        if not secret_path.is_absolute():
            raise M8WebConfigurationError("secret key file path must be absolute")
        current = Path(secret_path.anchor)
        for part in secret_path.parent.parts[1:]:
            current /= part
            try:
                item = os.lstat(current)
            except OSError as error:
                raise M8WebConfigurationError("secret key parent is unavailable") from error
            if not stat.S_ISDIR(item.st_mode) or stat.S_IMODE(item.st_mode) & 0o022:
                raise M8WebConfigurationError("secret key parent is unsafe")
        try:
            item = os.lstat(secret_path)
        except OSError as error:
            raise M8WebConfigurationError("secret key file is unavailable") from error
        if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid()
                or stat.S_IMODE(item.st_mode) != 0o600 or item.st_nlink != 1):
            raise M8WebConfigurationError("secret key file must be owned, regular mode 0600")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(secret_path, flags)
        except OSError as error:
            raise M8WebConfigurationError("secret key file cannot be opened") from error
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (item.st_dev, item.st_ino):
                raise M8WebConfigurationError("secret key file changed during open")
            secret = os.read(descriptor, 257)
        finally:
            os.close(descriptor)
        if not 32 <= len(secret) <= 256:
            raise M8WebConfigurationError("secret key must contain 32–256 bytes")
        object.__setattr__(self, "secret_key_file", secret_path)
        object.__setattr__(self, "secret_key", secret)


__all__ = [
    "M8WebConfigurationError",
    "M8WebSettings",
]
