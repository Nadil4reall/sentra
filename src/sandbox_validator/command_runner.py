"""Closed command boundary for Milestone 5 sandbox validation.

Callers select a named, hand-authored action.  There is intentionally no API that
accepts a command string or arbitrary argv from YAML, CIS content, or a CLI option.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal


class ReadAction(StrEnum):
    SSH_PACKAGE_STATUS = "ssh_package_status"
    SSH_SERVICE_ACTIVE = "ssh_service_active"
    SSH_SERVICE_CAN_RELOAD = "ssh_service_can_reload"
    SSHD_SYNTAX = "sshd_syntax"
    SSHD_EFFECTIVE = "sshd_effective"
    UFW_SERVICE_ENABLED = "ufw_service_enabled"
    UFW_SERVICE_ACTIVE = "ufw_service_active"
    UFW_STATUS = "ufw_status"
    UFW_ADDED_RULES = "ufw_added_rules"


class MutationAction(StrEnum):
    """The complete subprocess mutation allowlist for the initial M5 release."""

    SSH_SERVICE_RELOAD = "ssh_service_reload"


CommandKind = Literal["read", "mutation"]
CommandErrorKind = Literal[
    "permission_denied",
    "not_found",
    "timeout",
    "nonzero_exit",
    "execution_error",
]


_READ_COMMANDS: dict[ReadAction, tuple[str, ...]] = {
    ReadAction.SSH_PACKAGE_STATUS: (
        "/usr/bin/dpkg-query",
        "-W",
        "-f=${Status}",
        "openssh-server",
    ),
    ReadAction.SSH_SERVICE_ACTIVE: (
        "/usr/bin/systemctl",
        "is-active",
        "ssh.service",
    ),
    ReadAction.SSH_SERVICE_CAN_RELOAD: (
        "/usr/bin/systemctl",
        "show",
        "--property=CanReload",
        "--value",
        "ssh.service",
    ),
    ReadAction.SSHD_SYNTAX: ("/usr/sbin/sshd", "-t"),
    ReadAction.SSHD_EFFECTIVE: ("/usr/sbin/sshd", "-T"),
    ReadAction.UFW_SERVICE_ENABLED: (
        "/usr/bin/systemctl",
        "is-enabled",
        "ufw.service",
    ),
    ReadAction.UFW_SERVICE_ACTIVE: (
        "/usr/bin/systemctl",
        "is-active",
        "ufw.service",
    ),
    ReadAction.UFW_STATUS: ("/usr/sbin/ufw", "status"),
    ReadAction.UFW_ADDED_RULES: ("/usr/sbin/ufw", "show", "added"),
}

_MUTATION_COMMANDS: dict[MutationAction, tuple[str, ...]] = {
    MutationAction.SSH_SERVICE_RELOAD: (
        "/usr/bin/systemctl",
        "reload",
        "ssh.service",
    )
}

_FIXED_ENVIRONMENT = {
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


@dataclass(frozen=True, slots=True)
class MutationAuthorization:
    """Narrow permit issued only after the validator's mutation precheck."""

    control_id: str
    allowed_actions: frozenset[MutationAction]

    def allows(self, action: MutationAction) -> bool:
        return action in self.allowed_actions


@dataclass(frozen=True, slots=True)
class CommandResult:
    action: str
    kind: CommandKind
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    error_kind: CommandErrorKind | None = None
    reason: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and self.error_kind is None


class CommandNotAllowedError(ValueError):
    """Raised before execution for an unknown or unauthorized named action."""


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
    """Run only named M5 actions with fixed argv, environment, and timeout."""

    def __init__(self, *, timeout_seconds: float = 10.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self.timeout_seconds = timeout_seconds

    def run_read(self, action: ReadAction) -> CommandResult:
        if not isinstance(action, ReadAction):
            raise CommandNotAllowedError("read action must be a ReadAction value")
        return self._run(action.value, "read", _READ_COMMANDS[action])

    def run_mutation(
        self,
        action: MutationAction,
        authorization: MutationAuthorization,
    ) -> CommandResult:
        if not isinstance(action, MutationAction):
            raise CommandNotAllowedError(
                "mutation action must be a MutationAction value"
            )
        if not isinstance(authorization, MutationAuthorization):
            raise CommandNotAllowedError("mutation authorization is required")
        expected_control = {
            MutationAction.SSH_SERVICE_RELOAD: "5.1.20",
        }[action]
        if authorization.control_id != expected_control:
            raise CommandNotAllowedError(
                f"mutation action {action.value!r} is restricted to control "
                f"{expected_control}"
            )
        if not authorization.allows(action):
            raise CommandNotAllowedError(
                f"mutation action {action.value!r} was not authorized"
            )
        return self._run(action.value, "mutation", _MUTATION_COMMANDS[action])

    def _run(
        self,
        action: str,
        kind: CommandKind,
        command: tuple[str, ...],
    ) -> CommandResult:
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
                env=dict(_FIXED_ENVIRONMENT),
            )
        except FileNotFoundError:
            return CommandResult(
                action, kind, command, None, "", "", "not_found", "command_not_found"
            )
        except PermissionError:
            return CommandResult(
                action,
                kind,
                command,
                None,
                "",
                "",
                "permission_denied",
                "permission_denied",
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                action,
                kind,
                command,
                None,
                _as_text(exc.stdout),
                _as_text(exc.stderr),
                "timeout",
                "command_timed_out",
            )
        except (OSError, subprocess.SubprocessError):
            return CommandResult(
                action,
                kind,
                command,
                None,
                "",
                "",
                "execution_error",
                "command_execution_failed",
            )

        if completed.returncode == 0:
            error_kind: CommandErrorKind | None = None
            reason = None
        elif _looks_like_permission_failure(completed.stdout, completed.stderr):
            error_kind = "permission_denied"
            reason = "permission_denied"
        else:
            error_kind = "nonzero_exit"
            reason = "command_returned_nonzero"
        return CommandResult(
            action=action,
            kind=kind,
            argv=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            error_kind=error_kind,
            reason=reason,
        )


__all__ = [
    "CommandNotAllowedError",
    "CommandResult",
    "CommandRunner",
    "MutationAction",
    "MutationAuthorization",
    "ReadAction",
]
