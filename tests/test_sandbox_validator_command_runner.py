from __future__ import annotations

import subprocess
from typing import Any

import pytest

from src.sandbox_validator.command_runner import (
    CommandNotAllowedError,
    CommandRunner,
    MutationAction,
    MutationAuthorization,
    ReadAction,
)


FIXED_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "SYSTEMD_COLORS": "0",
    "SYSTEMD_PAGER": "",
}


@pytest.mark.parametrize(
    ("action", "expected_argv"),
    [
        (
            ReadAction.SSH_PACKAGE_STATUS,
            ("/usr/bin/dpkg-query", "-W", "-f=${Status}", "openssh-server"),
        ),
        (
            ReadAction.SSH_SERVICE_ACTIVE,
            ("/usr/bin/systemctl", "is-active", "ssh.service"),
        ),
        (
            ReadAction.SSH_SERVICE_CAN_RELOAD,
            (
                "/usr/bin/systemctl",
                "show",
                "--property=CanReload",
                "--value",
                "ssh.service",
            ),
        ),
        (ReadAction.SSHD_SYNTAX, ("/usr/sbin/sshd", "-t")),
        (ReadAction.SSHD_EFFECTIVE, ("/usr/sbin/sshd", "-T")),
        (
            ReadAction.UFW_SERVICE_ENABLED,
            ("/usr/bin/systemctl", "is-enabled", "ufw.service"),
        ),
        (
            ReadAction.UFW_SERVICE_ACTIVE,
            ("/usr/bin/systemctl", "is-active", "ufw.service"),
        ),
        (ReadAction.UFW_STATUS, ("/usr/sbin/ufw", "status")),
        (ReadAction.UFW_ADDED_RULES, ("/usr/sbin/ufw", "show", "added")),
    ],
)
def test_each_named_read_action_maps_to_fixed_argv(
    monkeypatch: pytest.MonkeyPatch,
    action: ReadAction,
    expected_argv: tuple[str, ...],
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(
        argv: tuple[str, ...], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, "observed\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = CommandRunner(timeout_seconds=2.5).run_read(action)

    assert result.succeeded is True
    assert result.kind == "read"
    assert result.action == action.value
    assert result.argv == expected_argv
    assert captured == {
        "argv": expected_argv,
        "shell": False,
        "stdin": subprocess.DEVNULL,
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": 2.5,
        "check": False,
        "env": FIXED_ENVIRONMENT,
    }


def test_mutation_action_uses_separate_allowlist_and_fixed_process_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(
        argv: tuple[str, ...], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    action = MutationAction.SSH_SERVICE_RELOAD
    authorization = MutationAuthorization(
        control_id="5.1.20",
        allowed_actions=frozenset({action}),
    )

    result = CommandRunner(timeout_seconds=4).run_mutation(action, authorization)

    assert result.succeeded is True
    assert result.kind == "mutation"
    assert result.action == "ssh_service_reload"
    assert result.argv == ("/usr/bin/systemctl", "reload", "ssh.service")
    assert captured["shell"] is False
    assert captured["timeout"] == 4
    assert captured["env"] == FIXED_ENVIRONMENT


def test_raw_commands_and_cis_text_are_rejected_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("untrusted command content reached subprocess.run")

    monkeypatch.setattr(subprocess, "run", fail_if_called)
    runner = CommandRunner()
    raw_values: list[object] = [
        "systemctl reload ssh.service",
        "sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
        "systemctl reload ssh.service && ufw enable",
        ("/usr/bin/systemctl", "reload", "ssh.service"),
        ["/usr/sbin/ufw", "enable"],
    ]

    for raw_value in raw_values:
        with pytest.raises(CommandNotAllowedError, match="ReadAction"):
            runner.run_read(raw_value)  # type: ignore[arg-type]

    assert not hasattr(runner, "run")


def test_named_action_values_are_not_accepted_as_untyped_user_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("an untyped action reached subprocess.run")

    monkeypatch.setattr(subprocess, "run", fail_if_called)

    with pytest.raises(CommandNotAllowedError, match="ReadAction"):
        CommandRunner().run_read("sshd_syntax")  # type: ignore[arg-type]
    with pytest.raises(CommandNotAllowedError, match="MutationAction"):
        CommandRunner().run_mutation(  # type: ignore[arg-type]
            "ssh_service_reload",
            MutationAuthorization(
                control_id="5.1.20",
                allowed_actions=frozenset({MutationAction.SSH_SERVICE_RELOAD}),
            ),
        )


def test_mutation_requires_explicit_named_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("an unauthorized mutation reached subprocess.run")

    monkeypatch.setattr(subprocess, "run", fail_if_called)
    action = MutationAction.SSH_SERVICE_RELOAD

    with pytest.raises(CommandNotAllowedError, match="was not authorized"):
        CommandRunner().run_mutation(
            action,
            MutationAuthorization(control_id="5.1.20", allowed_actions=frozenset()),
        )
    with pytest.raises(CommandNotAllowedError, match="authorization is required"):
        CommandRunner().run_mutation(action, None)  # type: ignore[arg-type]


def test_cross_control_authorization_cannot_reuse_mutation_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("cross-control authorization reached subprocess.run")

    monkeypatch.setattr(subprocess, "run", fail_if_called)
    action = MutationAction.SSH_SERVICE_RELOAD
    authorization = MutationAuthorization(
        control_id="7.1.1",
        allowed_actions=frozenset({action}),
    )

    with pytest.raises(CommandNotAllowedError, match="restricted to control 5.1.20"):
        CommandRunner().run_mutation(action, authorization)


def test_permission_and_nonzero_failures_remain_structured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = iter(
        [
            subprocess.CompletedProcess(
                ("/usr/sbin/ufw", "status"),
                1,
                "",
                "ERROR: You need to be root to run this script\n",
            ),
            subprocess.CompletedProcess(
                ("/usr/bin/systemctl", "is-active", "ssh.service"),
                3,
                "inactive\n",
                "",
            ),
        ]
    )

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return next(responses)

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = CommandRunner()

    permission = runner.run_read(ReadAction.UFW_STATUS)
    assert permission.succeeded is False
    assert permission.error_kind == "permission_denied"
    assert permission.reason == "permission_denied"

    inactive = runner.run_read(ReadAction.SSH_SERVICE_ACTIVE)
    assert inactive.succeeded is False
    assert inactive.returncode == 3
    assert inactive.stdout == "inactive\n"
    assert inactive.error_kind == "nonzero_exit"
    assert inactive.reason == "command_returned_nonzero"


def test_timeout_is_bounded_and_preserves_partial_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def timeout(
        argv: tuple[str, ...], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured.update(kwargs)
        raise subprocess.TimeoutExpired(
            cmd=argv,
            timeout=kwargs["timeout"],
            output=b"partial stdout\n",
            stderr=b"partial stderr\n",
        )

    monkeypatch.setattr(subprocess, "run", timeout)
    result = CommandRunner(timeout_seconds=0.5).run_read(ReadAction.SSHD_EFFECTIVE)

    assert captured["timeout"] == 0.5
    assert result.returncode is None
    assert result.stdout == "partial stdout\n"
    assert result.stderr == "partial stderr\n"
    assert result.error_kind == "timeout"
    assert result.reason == "command_timed_out"


def test_invalid_timeout_is_rejected_before_any_execution() -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        CommandRunner(timeout_seconds=0)
    with pytest.raises(ValueError, match="greater than zero"):
        CommandRunner(timeout_seconds=-1)
