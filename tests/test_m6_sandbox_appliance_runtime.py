from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any

import pytest

from src.sandbox_m5_protocol.models import SandboxM5ControllerAuthorization
from src.sandbox_runtime import __main__ as entrypoint
from src.sandbox_runtime import config as config_module
from src.sandbox_runtime import session_channel
from src.sandbox_runtime.receiver import SENTRA_VALIDATION_DEVICE_PATH


_ROOT = Path(__file__).resolve().parents[1]
_SERVICE_PATH = _ROOT / "deploy/sandbox/sentra-sandbox-receiver.service"
_CONFIG_TEMPLATE_PATH = _ROOT / "deploy/sandbox/sandbox-runtime.conf"


class _AcceptedSession:
    pass


class _FakeStream:
    def __init__(self) -> None:
        self.entered = False
        self.exited = False

    def __enter__(self) -> "_FakeStream":
        self.entered = True
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.exited = True


def test_entrypoint_rejects_arguments_without_opening_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert inspect.signature(entrypoint.main).parameters == {}
    monkeypatch.setattr(entrypoint.sys, "argv", ["sentra-sandbox", "/tmp/manifest"])
    monkeypatch.setattr(
        entrypoint,
        "open_fixed_validation_channel_and_run_session",
        lambda **_kwargs: pytest.fail("arguments must be rejected before opening"),
    )

    assert entrypoint.main() == entrypoint.EXIT_CONTEXT_REJECTED


def test_entrypoint_runs_exactly_one_full_session_with_local_true_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, bool]] = []
    monkeypatch.setattr(entrypoint.sys, "argv", ["sentra-sandbox"])
    monkeypatch.setenv(config_module.SANDBOX_OPERATOR_ACK_ENVIRONMENT_KEY, "true")
    monkeypatch.setattr(entrypoint, "SandboxM5SessionResult", _AcceptedSession)
    monkeypatch.setattr(
        entrypoint,
        "open_fixed_validation_channel_and_run_session",
        lambda **kwargs: calls.append(kwargs) or _AcceptedSession(),
    )

    assert entrypoint.main() == entrypoint.EXIT_ACCEPTED
    assert calls == [{"sandbox_operator_acknowledged": True}]


def test_entrypoint_missing_local_setting_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, bool]] = []
    monkeypatch.setattr(entrypoint.sys, "argv", ["sentra-sandbox"])
    monkeypatch.delenv(config_module.SANDBOX_OPERATOR_ACK_ENVIRONMENT_KEY, raising=False)
    monkeypatch.setattr(entrypoint, "SandboxM5SessionResult", _AcceptedSession)
    monkeypatch.setattr(
        entrypoint,
        "open_fixed_validation_channel_and_run_session",
        lambda **kwargs: calls.append(kwargs) or _AcceptedSession(),
    )

    assert entrypoint.main() == entrypoint.EXIT_ACCEPTED
    assert calls == [{"sandbox_operator_acknowledged": False}]


@pytest.mark.parametrize("value", ["TRUE", "True", "1", "yes", "false", "", " true"])
def test_invalid_local_operator_setting_is_false(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv(config_module.SANDBOX_OPERATOR_ACK_ENVIRONMENT_KEY, value)

    assert config_module.local_sandbox_operator_acknowledged() is False


def test_exact_local_true_operator_setting_is_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(config_module.SANDBOX_OPERATOR_ACK_ENVIRONMENT_KEY, "true")

    assert config_module.local_sandbox_operator_acknowledged() is True


def test_controller_authorization_has_no_operator_acknowledgement_field() -> None:
    assert "sandbox_operator_acknowledged" not in (
        SandboxM5ControllerAuthorization.model_fields
    )


def test_fixed_channel_opener_accepts_only_local_ack_and_opens_fixed_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = inspect.signature(
        session_channel.open_fixed_validation_channel_and_run_session
    )
    assert list(signature.parameters) == ["sandbox_operator_acknowledged"]
    assert signature.parameters["sandbox_operator_acknowledged"].default is inspect.Parameter.empty
    assert signature.parameters["sandbox_operator_acknowledged"].kind is inspect.Parameter.KEYWORD_ONLY

    opened: list[tuple[str, int]] = []
    fdopen_calls: list[tuple[int, str, int]] = []
    session_calls: list[tuple[_FakeStream, dict[str, bool]]] = []
    stream = _FakeStream()

    def fake_open(path: str, flags: int) -> int:
        opened.append((path, flags))
        return 41

    def fake_fdopen(fd: int, mode: str, *, buffering: int) -> _FakeStream:
        fdopen_calls.append((fd, mode, buffering))
        return stream

    def fake_run_session(
        received_stream: _FakeStream,
        *,
        sandbox_operator_acknowledged: bool,
    ) -> _AcceptedSession:
        session_calls.append(
            (received_stream, {"sandbox_operator_acknowledged": sandbox_operator_acknowledged})
        )
        return _AcceptedSession()

    monkeypatch.setattr(session_channel.os, "open", fake_open)
    monkeypatch.setattr(session_channel.os, "fdopen", fake_fdopen)
    monkeypatch.setattr(session_channel, "run_sandbox_m5_session", fake_run_session)

    result = session_channel.open_fixed_validation_channel_and_run_session(
        sandbox_operator_acknowledged=False
    )

    expected_flags = session_channel.os.O_RDWR
    expected_flags |= getattr(session_channel.os, "O_NOCTTY", 0)
    expected_flags |= getattr(session_channel.os, "O_CLOEXEC", 0)
    assert opened == [(SENTRA_VALIDATION_DEVICE_PATH, expected_flags)]
    assert opened[0][0] == "/dev/virtio-ports/org.sentra.validation.0"
    assert fdopen_calls == [(41, "r+b", 0)]
    assert session_calls == [(stream, {"sandbox_operator_acknowledged": False})]
    assert stream.entered and stream.exited
    assert isinstance(result, _AcceptedSession)


def test_entrypoint_fails_closed_without_printing_exception_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(entrypoint.sys, "argv", ["sentra-sandbox"])

    def fail_with_sensitive_detail(**_kwargs: Any) -> None:
        raise RuntimeError("manifest=/secret/path passwd contents are private")

    monkeypatch.setattr(
        entrypoint,
        "open_fixed_validation_channel_and_run_session",
        fail_with_sensitive_detail,
    )

    assert entrypoint.main() == entrypoint.EXIT_SESSION_FAILURE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_entrypoint_requires_a_session_result_before_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(entrypoint.sys, "argv", ["sentra-sandbox"])
    monkeypatch.setattr(
        entrypoint,
        "open_fixed_validation_channel_and_run_session",
        lambda **_kwargs: object(),
    )

    assert entrypoint.main() == entrypoint.EXIT_SESSION_FAILURE


def _unit_settings() -> dict[str, list[str]]:
    settings: dict[str, list[str]] = {}
    for raw_line in _SERVICE_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("[") or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        settings.setdefault(key, []).append(value)
    return settings


def test_v3_systemd_unit_is_fixed_one_shot_and_hardened() -> None:
    text = _SERVICE_PATH.read_text(encoding="utf-8")
    settings = _unit_settings()

    assert settings["Type"] == ["oneshot"]
    assert settings["ExecStart"] == ["/opt/sentra/venv/bin/python -m src.sandbox_runtime"]
    assert settings["WorkingDirectory"] == ["/opt/sentra"]
    assert settings["Environment"] == ["PYTHONPATH=/opt/sentra"]
    assert settings["EnvironmentFile"] == ["-/etc/sentra/sandbox-runtime.conf"]
    assert settings["Requires"] == [
        "dev-virtio\\x2dports-org.sentra.validation.0.device"
    ]
    assert settings["After"] == [
        "dev-virtio\\x2dports-org.sentra.validation.0.device"
    ]
    assert settings["ReadWritePaths"] == [
        "/etc/passwd /var/backups/sentra/7.1.1"
    ]
    assert settings["CapabilityBoundingSet"] == [
        "CAP_CHOWN CAP_FOWNER CAP_DAC_READ_SEARCH"
    ]
    assert settings["AmbientCapabilities"] == [""]
    assert settings["Restart"] == ["no"]
    assert "Restart=always" not in text
    assert settings["PrivateDevices"] == ["no"]

    for setting in (
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_UNIX",
        "UMask=0077",
    ):
        assert setting in text

    assert "CAP_SYS_ADMIN" not in text
    assert "CAP_SYS_PTRACE" not in text
    assert "CAP_NET_ADMIN" not in text
    assert "CAP_NET_RAW" not in text


def test_local_runtime_config_template_contains_only_non_secret_ack() -> None:
    assert _CONFIG_TEMPLATE_PATH.read_text(encoding="utf-8").splitlines() == [
        "SENTRA_SANDBOX_OPERATOR_ACKNOWLEDGED=true"
    ]


def test_boot_runtime_has_no_generic_execution_or_network_surface() -> None:
    runtime_paths = [
        _ROOT / "src/sandbox_runtime/__main__.py",
        _ROOT / "src/sandbox_runtime/config.py",
        _ROOT / "src/sandbox_runtime/session_channel.py",
    ]
    sources = [path.read_text(encoding="utf-8") for path in runtime_paths]
    forbidden_tokens = (
        "subprocess",
        "os.system",
        "shell=True",
        "paramiko",
        "socket.",
        "listen(",
        "bind(",
        "QEMU guest agent",
        "AgentRuntime",
        "enroll(",
        "heartbeat(",
        "poll_jobs(",
        "argparse",
        "--control",
        "--path",
        "--command",
    )
    combined = "\n".join(sources)
    for token in forbidden_tokens:
        assert token not in combined

    trees = [ast.parse(source) for source in sources]
    assert not any(
        isinstance(node, (ast.For, ast.While))
        for tree in trees
        for node in ast.walk(tree)
    )
    service = _SERVICE_PATH.read_text(encoding="utf-8")
    assert "ssh" not in service.lower()
    assert "sh -c" not in service.lower()
    assert "ExecStart=/bin/sh" not in service
    assert "ExecStartPre=" not in service
