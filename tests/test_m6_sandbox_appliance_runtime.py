from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.sandbox_protocol import PasswdSourceState, SandboxContextManifest
from src.sandbox_runtime import __main__ as appliance_runtime
from src.sandbox_runtime.receiver import SandboxReceiverIOError


_REPO_ROOT = Path(__file__).resolve().parents[1]
_ENTRYPOINT_PATH = _REPO_ROOT / "src" / "sandbox_runtime" / "__main__.py"
_SERVICE_PATH = _REPO_ROOT / "deploy" / "sandbox" / "sentra-sandbox-receiver.service"
_DEVICE_UNIT = r"dev-virtio\x2dports-org.sentra.validation.0.device"


def _accepted_result() -> SimpleNamespace:
    return SimpleNamespace(
        manifest=SandboxContextManifest(
            context_version="1",
            control_id="7.1.1",
            source_state=PasswdSourceState(
                passwd_file_mode="0666",
                passwd_file_owner_uid=0,
                passwd_file_group_gid=0,
            ),
        ),
        acknowledgement=SimpleNamespace(status="accepted"),
    )


def _rejected_result() -> SimpleNamespace:
    return SimpleNamespace(
        manifest=None,
        acknowledgement=SimpleNamespace(status="rejected"),
    )


def test_entrypoint_has_no_parameters_and_rejects_cli_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def receiver() -> SimpleNamespace:
        nonlocal called
        called = True
        return _accepted_result()

    monkeypatch.setattr(
        appliance_runtime, "open_fixed_validation_channel_and_receive", receiver
    )
    monkeypatch.setattr(appliance_runtime.sys, "argv", ["sentra-runtime", "/tmp/other"])

    assert not inspect.signature(appliance_runtime.main).parameters
    assert appliance_runtime.main() == appliance_runtime.EXIT_CONTEXT_REJECTED
    assert called is False


def test_entrypoint_returns_zero_for_an_accepted_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def receiver() -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return _accepted_result()

    monkeypatch.setattr(
        appliance_runtime, "open_fixed_validation_channel_and_receive", receiver
    )
    monkeypatch.setattr(appliance_runtime.sys, "argv", ["sentra-runtime"])

    assert appliance_runtime.main() == 0
    assert calls == 1


def test_entrypoint_does_not_print_an_accepted_manifest(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        appliance_runtime,
        "open_fixed_validation_channel_and_receive",
        _accepted_result,
    )
    monkeypatch.setattr(appliance_runtime.sys, "argv", ["sentra-runtime"])

    assert appliance_runtime.main() == appliance_runtime.EXIT_ACCEPTED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_entrypoint_returns_fixed_nonzero_for_rejected_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        appliance_runtime,
        "open_fixed_validation_channel_and_receive",
        _rejected_result,
    )
    monkeypatch.setattr(appliance_runtime.sys, "argv", ["sentra-runtime"])

    assert appliance_runtime.main() == appliance_runtime.EXIT_CONTEXT_REJECTED


def test_entrypoint_returns_fixed_nonzero_for_receiver_io_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def receiver() -> None:
        raise SandboxReceiverIOError("private receiver diagnostic sentinel")

    monkeypatch.setattr(
        appliance_runtime, "open_fixed_validation_channel_and_receive", receiver
    )
    monkeypatch.setattr(appliance_runtime.sys, "argv", ["sentra-runtime"])

    assert appliance_runtime.main() == appliance_runtime.EXIT_RECEIVER_FAILURE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert "private receiver diagnostic sentinel" not in captured.out + captured.err


def test_entrypoint_does_not_print_manifest_or_unexpected_exception(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def receiver() -> None:
        raise RuntimeError("secret manifest and diagnostic sentinel")

    monkeypatch.setattr(
        appliance_runtime, "open_fixed_validation_channel_and_receive", receiver
    )
    monkeypatch.setattr(appliance_runtime.sys, "argv", ["sentra-runtime"])

    assert appliance_runtime.main() == appliance_runtime.EXIT_RECEIVER_FAILURE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert "secret manifest and diagnostic sentinel" not in captured.out + captured.err


def test_entrypoint_calls_only_the_fixed_receiver_api() -> None:
    tree = ast.parse(_ENTRYPOINT_PATH.read_text(encoding="utf-8"))
    imported_from_receiver = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "receiver"
        for alias in node.names
    }
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert imported_from_receiver == {"open_fixed_validation_channel_and_receive"}
    assert called_names == {
        "len",
        "open_fixed_validation_channel_and_receive",
        "SystemExit",
        "main",
    }


def test_entrypoint_has_no_shell_network_m5_or_passwd_mutation_surface() -> None:
    source = _ENTRYPOINT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )

    assert not imported.intersection({"argparse", "subprocess", "socket", "paramiko"})
    assert "sandbox_validator" not in source
    assert "/etc/passwd" not in source
    assert "eval(" not in source
    assert "exec(" not in source
    assert "os.system" not in source
    assert "shell=True" not in source


def test_systemd_service_is_fixed_oneshot_with_exact_device_dependency() -> None:
    service = _SERVICE_PATH.read_text(encoding="utf-8")
    lines = [line.strip() for line in service.splitlines() if line.strip()]

    assert "Type=oneshot" in lines
    assert "WorkingDirectory=/opt/sentra" in lines
    assert "Environment=PYTHONPATH=/opt/sentra" in lines
    assert "ExecStart=/opt/sentra/venv/bin/python -m src.sandbox_runtime" in lines
    assert sum(line.startswith("ExecStart=") for line in lines) == 1
    assert f"Requires={_DEVICE_UNIT}" in lines
    assert f"After={_DEVICE_UNIT}" in lines
    assert "Restart=no" in lines
    assert "Restart=always" not in lines
    assert "PrivateDevices=no" in lines
    assert "ProtectSystem=strict" in lines
    assert "NoNewPrivileges=yes" in lines
    assert "CapabilityBoundingSet=" in lines
    assert "AmbientCapabilities=" in lines


def test_systemd_service_has_no_shell_network_or_m5_execution_surface() -> None:
    service = _SERVICE_PATH.read_text(encoding="utf-8")
    lowered = service.lower()

    assert "/bin/sh" not in service
    assert "bash" not in lowered
    assert "ssh" not in lowered
    assert "socket" not in lowered
    assert "subprocess" not in lowered
    assert "sandbox_validator" not in lowered
    assert "/etc/passwd" not in service
    assert "virsh" not in lowered
    assert "qemu-img" not in lowered
    assert "ExecStart=/opt/sentra/venv/bin/python -m src.sandbox_runtime " not in service
