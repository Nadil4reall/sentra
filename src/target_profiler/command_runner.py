"""Strict, read-only subprocess boundary for target fact collection.

Only the small set of commands required by Milestone 3 collectors is accepted.
Callers cannot supply shell command strings, arbitrary service names, or command
arguments outside the patterns below.  CIS audit and remediation content is data
and must never be passed through this module.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal


CommandErrorKind = Literal[
    "permission_denied",
    "not_found",
    "timeout",
    "nonzero_exit",
    "execution_error",
]


class CommandNotAllowedError(ValueError):
    """Raised before execution when argv is outside the read-only allowlist."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Captured result from an allowed command.

    ``returncode`` is ``None`` when the process could not produce an exit code.
    Non-zero stdout and stderr are deliberately preserved because inspection
    commands such as ``systemctl is-active`` use non-zero codes for valid states.
    """

    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    error_kind: CommandErrorKind | None = None
    reason: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and self.error_kind is None

    @property
    def permission_denied(self) -> bool:
        return self.error_kind == "permission_denied"


_SYSTEMCTL_UNITS = frozenset(
    {
        "ufw",
        "ufw.service",
        "ssh",
        "ssh.service",
        "sshd",
        "sshd.service",
        "auditd",
        "auditd.service",
    }
)
_SYSTEMCTL_STATE_QUERIES = frozenset({"is-active", "is-enabled"})
_MODULES = frozenset({"cramfs", "overlay"})
_UFW_QUERIES = frozenset(
    {
        ("ufw", "show", "added"),
        ("ufw", "status"),
        ("ufw", "status", "numbered"),
        ("ufw", "status", "verbose"),
    }
)
_MODPROBE_QUERIES = frozenset(
    {
        ("modprobe", "--showconfig"),
        *(('modprobe', '-n', '-v', module) for module in _MODULES),
        *(('modprobe', '-n', '--show-depends', module) for module in _MODULES),
    }
)

# Do not inherit SSH, locale, Python, or user-controlled program environment.
# Every allowlisted executable on Ubuntu 24.04 is in one of these system paths.
_READ_ONLY_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "SYSTEMD_COLORS": "0",
    "SYSTEMD_PAGER": "",
}

_PERMISSION_MARKERS = (
    "permission denied",
    "operation not permitted",
    "access denied",
    "must be root",
    "need to be root",
    "needs to be root",
    "requires root",
    "not authorized",
    "authentication is required",
)


def _normalize_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Return validated immutable argv without accepting command strings."""

    if isinstance(argv, (str, bytes)):
        raise CommandNotAllowedError(
            "commands must be passed as a sequence of argument strings"
        )

    try:
        normalized = tuple(argv)
    except TypeError as exc:
        raise CommandNotAllowedError("command argv must be a sequence") from exc

    if not normalized:
        raise CommandNotAllowedError("command argv must not be empty")
    if any(
        not isinstance(argument, str)
        or not argument
        or "\x00" in argument
        for argument in normalized
    ):
        raise CommandNotAllowedError(
            "every command argument must be a non-empty string without NUL bytes"
        )
    return normalized


def _matches_allowlist(argv: tuple[str, ...]) -> bool:
    if argv in _UFW_QUERIES or argv in _MODPROBE_QUERIES:
        return True
    if argv == ("sshd", "-T"):
        return True
    if (
        len(argv) == 3
        and argv[0] == "systemctl"
        and argv[1] in _SYSTEMCTL_STATE_QUERIES
        and argv[2] in _SYSTEMCTL_UNITS
    ):
        return True
    return (
        len(argv) == 5
        and argv[:4] == (
            "systemctl",
            "show",
            "--property=LoadState",
            "--value",
        )
        and argv[4] in _SYSTEMCTL_UNITS
    )


def validate_read_only_command(argv: Sequence[str]) -> tuple[str, ...]:
    """Validate argv against the complete Milestone 3 command allowlist."""

    normalized = _normalize_argv(argv)
    if not _matches_allowlist(normalized):
        executable = normalized[0]
        raise CommandNotAllowedError(
            f"command is not an allowed read-only inspection: {executable!r}"
        )
    return normalized


def _as_text(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def _looks_like_permission_failure(stdout: str, stderr: str) -> bool:
    message = f"{stdout}\n{stderr}".casefold()
    return any(marker in message for marker in _PERMISSION_MARKERS)


class CommandRunner:
    """Execute only explicitly allowed, local, read-only inspection commands."""

    def __init__(self, *, timeout_seconds: float = 10.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self.timeout_seconds = timeout_seconds

    def run(self, argv: Sequence[str]) -> CommandResult:
        """Run validated argv with ``shell=False`` and capture all outcomes."""

        command = validate_read_only_command(argv)
        try:
            completed = subprocess.run(
                command,
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
                env=dict(_READ_ONLY_ENVIRONMENT),
            )
        except FileNotFoundError:
            return CommandResult(
                argv=command,
                returncode=None,
                stdout="",
                stderr="",
                error_kind="not_found",
                reason="command_not_found",
            )
        except PermissionError:
            return CommandResult(
                argv=command,
                returncode=None,
                stdout="",
                stderr="",
                error_kind="permission_denied",
                reason="permission_denied",
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                argv=command,
                returncode=None,
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr),
                error_kind="timeout",
                reason="command_timed_out",
            )
        except (OSError, subprocess.SubprocessError):
            return CommandResult(
                argv=command,
                returncode=None,
                stdout="",
                stderr="",
                error_kind="execution_error",
                reason="command_execution_failed",
            )

        stdout = completed.stdout
        stderr = completed.stderr
        if completed.returncode == 0:
            error_kind: CommandErrorKind | None = None
            reason = None
        elif _looks_like_permission_failure(stdout, stderr):
            error_kind = "permission_denied"
            reason = "permission_denied"
        else:
            error_kind = "nonzero_exit"
            reason = "command_returned_nonzero"

        return CommandResult(
            argv=command,
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            error_kind=error_kind,
            reason=reason,
        )


__all__ = [
    "CommandErrorKind",
    "CommandNotAllowedError",
    "CommandResult",
    "CommandRunner",
    "validate_read_only_command",
]
