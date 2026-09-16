from __future__ import annotations

import subprocess

import pytest

from src.target_profiler.command_runner import (
    CommandNotAllowedError,
    CommandRunner,
    validate_read_only_command,
)


@pytest.mark.parametrize(
    "argv",
    [
        ("systemctl", "is-active", "ssh.service"),
        ("systemctl", "is-enabled", "auditd"),
        (
            "systemctl",
            "show",
            "--property=LoadState",
            "--value",
            "ufw.service",
        ),
        ("ufw", "show", "added"),
        ("ufw", "status"),
        ("ufw", "status", "verbose"),
        ("sshd", "-T"),
        ("modprobe", "--showconfig"),
        ("modprobe", "-n", "-v", "cramfs"),
        ("modprobe", "-n", "--show-depends", "overlay"),
    ],
)
def test_documented_read_only_commands_are_allowed(argv: tuple[str, ...]) -> None:
    assert validate_read_only_command(argv) == argv


@pytest.mark.parametrize(
    "argv",
    [
        ("apt", "install", "ufw"),
        ("apt", "update"),
        ("systemctl", "start", "ssh.service"),
        ("systemctl", "restart", "auditd.service"),
        ("systemctl", "disable", "ufw.service"),
        ("service", "ssh", "restart"),
        ("chmod", "0600", "/etc/passwd"),
        ("chown", "root:root", "/etc/passwd"),
        ("modprobe", "-r", "cramfs"),
        ("rmmod", "overlay"),
        ("sysctl", "-w", "net.ipv4.ip_forward=0"),
        ("ufw", "enable"),
        ("ufw", "disable"),
        ("ufw", "delete", "allow", "22/tcp"),
        ("iptables", "-F"),
        ("nft", "flush", "ruleset"),
        ("sed", "-i", "s/a/b/", "/etc/ssh/sshd_config"),
        ("reboot",),
        ("shutdown", "-h", "now"),
    ],
)
def test_modifying_commands_are_rejected_before_execution(
    monkeypatch: pytest.MonkeyPatch, argv: tuple[str, ...]
) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a rejected command reached subprocess.run")

    monkeypatch.setattr(subprocess, "run", fail_if_called)

    with pytest.raises(CommandNotAllowedError):
        CommandRunner().run(argv)


def test_command_strings_and_cis_content_cannot_be_executed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("CIS text reached subprocess.run")

    monkeypatch.setattr(subprocess, "run", fail_if_called)
    cis_remediation = "systemctl disable --now cramfs && modprobe -r cramfs"

    with pytest.raises(CommandNotAllowedError):
        CommandRunner().run(cis_remediation)


def test_allowed_command_uses_no_shell_and_a_fixed_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, "active\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = CommandRunner(timeout_seconds=3).run(
        ("systemctl", "is-active", "ssh.service")
    )

    assert result.succeeded is True
    assert result.stdout == "active\n"
    assert captured["shell"] is False
    assert captured["check"] is False
    assert captured["stdin"] == subprocess.DEVNULL
    assert captured["timeout"] == 3
    assert captured["env"] == {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "SYSTEMD_COLORS": "0",
        "SYSTEMD_PAGER": "",
    }


def test_permission_failure_is_structured_and_never_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        argv: tuple[str, ...], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            argv,
            1,
            "",
            "ERROR: You need to be root to run this script\n",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = CommandRunner().run(("ufw", "status"))

    assert result.returncode == 1
    assert result.permission_denied is True
    assert result.error_kind == "permission_denied"
    assert result.reason == "permission_denied"
    assert result.stdout == ""
    assert not isinstance(result.stdout, bool)


def test_nonzero_command_output_is_preserved_for_state_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        argv: tuple[str, ...], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 3, "inactive\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = CommandRunner().run(("systemctl", "is-active", "ssh.service"))

    assert result.succeeded is False
    assert result.returncode == 3
    assert result.stdout == "inactive\n"
    assert result.error_kind == "nonzero_exit"
    assert result.reason == "command_returned_nonzero"


def test_process_launch_errors_are_captured(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", missing)
    result = CommandRunner().run(("sshd", "-T"))

    assert result.returncode is None
    assert result.error_kind == "not_found"
    assert result.reason == "command_not_found"


def test_timeout_output_is_captured(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(
            cmd=("sshd", "-T"), timeout=1, output=b"partial\n", stderr=b"late\n"
        )

    monkeypatch.setattr(subprocess, "run", timeout)
    result = CommandRunner(timeout_seconds=1).run(("sshd", "-T"))

    assert result.returncode is None
    assert result.stdout == "partial\n"
    assert result.stderr == "late\n"
    assert result.error_kind == "timeout"
    assert result.reason == "command_timed_out"


def test_invalid_timeout_is_rejected() -> None:
    with pytest.raises(ValueError):
        CommandRunner(timeout_seconds=0)
