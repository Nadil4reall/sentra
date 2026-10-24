from __future__ import annotations

import ast
import inspect
import os
import stat
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from src.sandbox_protocol import PasswdSourceState, SandboxContextManifest
from src.sandbox_runtime import orchestrator, reproduction
from src.sandbox_runtime.reproduction import (
    SANDBOX_PASSWD_TARGET_PATH,
    SandboxPasswdReproductionResult,
    SandboxStateReproductionError,
    reproduce_passwd_source_state,
)


_REPO_ROOT = Path(__file__).resolve().parents[1]
_RUNTIME_DIR = _REPO_ROOT / "src" / "sandbox_runtime"


def _manifest(
    *, mode: str = "0644", uid: int = 0, gid: int = 0
) -> SandboxContextManifest:
    return SandboxContextManifest(
        context_version="1",
        control_id="7.1.1",
        source_state=PasswdSourceState(
            passwd_file_mode=mode,
            passwd_file_owner_uid=uid,
            passwd_file_group_gid=gid,
        ),
    )


def _constructed_manifest(
    *, control_id: str = "7.1.1", mode: Any = "0644"
) -> SandboxContextManifest:
    state = PasswdSourceState.model_construct(
        passwd_file_mode=mode,
        passwd_file_owner_uid=0,
        passwd_file_group_gid=0,
    )
    return SandboxContextManifest.model_construct(
        context_version="1",
        control_id=control_id,
        source_state=state,
    )


class FakeMetadataFilesystem:
    """Redirect the fixed target to a temp file and emulate metadata safely."""

    def __init__(
        self,
        temp_file: Path,
        *,
        mode: int = 0o600,
        uid: int = 1001,
        gid: int = 1002,
        fail_chmod_calls: set[int] | None = None,
        ignore_chmod_calls: set[int] | None = None,
    ) -> None:
        self.temp_file = temp_file
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.fail_chmod_calls = fail_chmod_calls or set()
        self.ignore_chmod_calls = ignore_chmod_calls or set()
        self.paths: list[str] = []
        self.flags: list[int] = []
        self.fstat_snapshots: list[tuple[int, int, int]] = []
        self.chown_calls: list[tuple[int, int]] = []
        self.chmod_calls: list[int] = []
        self._descriptor: int | None = None

    def open(self, path: str, flags: int) -> int:
        self.paths.append(path)
        self.flags.append(flags)
        self._descriptor = os.open(self.temp_file, flags)
        return self._descriptor

    def fstat(self, descriptor: int) -> os.stat_result:
        assert descriptor == self._descriptor
        self.fstat_snapshots.append((self.mode, self.uid, self.gid))
        return SimpleNamespace(
            st_mode=stat.S_IFREG | self.mode,
            st_uid=self.uid,
            st_gid=self.gid,
        )  # type: ignore[return-value]

    def fchown(self, descriptor: int, uid: int, gid: int) -> None:
        assert descriptor == self._descriptor
        self.chown_calls.append((uid, gid))
        self.uid = uid
        self.gid = gid

    def fchmod(self, descriptor: int, mode: int) -> None:
        assert descriptor == self._descriptor
        self.chmod_calls.append(mode)
        if len(self.chmod_calls) in self.fail_chmod_calls:
            raise OSError("private filesystem diagnostic")
        if len(self.chmod_calls) not in self.ignore_chmod_calls:
            self.mode = mode

    def close(self, descriptor: int) -> None:
        assert descriptor == self._descriptor
        os.close(descriptor)

    def snapshot(self) -> tuple[int, int, int]:
        return self.mode, self.uid, self.gid


@pytest.fixture
def metadata_fs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeMetadataFilesystem:
    target = tmp_path / "sandbox-passwd"
    target.write_bytes(b"sandbox-only passwd database\n")
    fake = FakeMetadataFilesystem(target)
    monkeypatch.setattr(reproduction, "_FILESYSTEM", fake)
    return fake


@pytest.mark.parametrize(
    ("mode", "expected_mode"),
    [("0644", 0o644), ("0664", 0o664)],
)
def test_valid_source_metadata_is_reproduced_without_changing_content(
    mode: str,
    expected_mode: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "sandbox-passwd"
    original_content = b"sandbox-only passwd database\n"
    target.write_bytes(original_content)
    fake = FakeMetadataFilesystem(target)
    monkeypatch.setattr(reproduction, "_FILESYSTEM", fake)

    result = reproduce_passwd_source_state(_manifest(mode=mode))

    assert result == SandboxPasswdReproductionResult(
        control_id="7.1.1",
        target_path="/etc/passwd",
        before_mode="0600",
        before_uid=1001,
        before_gid=1002,
        requested_mode=mode,
        requested_uid=0,
        requested_gid=0,
        after_mode=mode,
        after_uid=0,
        after_gid=0,
        reproduced=True,
    )
    assert fake.paths == [SANDBOX_PASSWD_TARGET_PATH]
    assert fake.snapshot() == (expected_mode, 0, 0)
    assert fake.fstat_snapshots[0] == (0o600, 1001, 1002)
    assert target.read_bytes() == original_content


def test_metadata_application_uses_fixed_path_and_no_caller_path_argument(
    metadata_fs: FakeMetadataFilesystem,
) -> None:
    assert list(inspect.signature(reproduce_passwd_source_state).parameters) == [
        "manifest"
    ]
    private_parameters = inspect.signature(
        reproduction._reproduce_source_state
    ).parameters
    assert list(private_parameters) == ["manifest", "filesystem"]
    assert "target_path" not in private_parameters

    with pytest.raises(TypeError):
        reproduce_passwd_source_state(_manifest(), "/tmp/other")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        reproduction._reproduce_source_state(
            _manifest(), target_path="/tmp/other", filesystem=metadata_fs
        )  # type: ignore[call-arg]

    reproduce_passwd_source_state(_manifest())

    assert metadata_fs.paths == ["/etc/passwd"]
    assert metadata_fs.flags[0] & os.O_NOFOLLOW


def test_unsupported_control_is_rejected_before_filesystem_access(
    metadata_fs: FakeMetadataFilesystem,
) -> None:
    with pytest.raises(SandboxStateReproductionError, match="^sandbox source-state"):
        reproduce_passwd_source_state(_constructed_manifest(control_id="5.1.20"))

    assert metadata_fs.paths == []
    assert metadata_fs.chown_calls == []
    assert metadata_fs.chmod_calls == []


@pytest.mark.parametrize("mode", ["644", "0o644", "0788", 0o644, "0644;id"])
def test_malformed_mode_is_rejected_before_metadata_mutation(
    mode: Any,
    metadata_fs: FakeMetadataFilesystem,
) -> None:
    with pytest.raises(SandboxStateReproductionError):
        reproduce_passwd_source_state(_constructed_manifest(mode=mode))

    assert metadata_fs.paths == []
    assert metadata_fs.chown_calls == []
    assert metadata_fs.chmod_calls == []


def test_application_failure_rolls_back_and_verifies_original_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "sandbox-passwd"
    target.write_bytes(b"unchanged\n")
    fake = FakeMetadataFilesystem(target, fail_chmod_calls={1})
    monkeypatch.setattr(reproduction, "_FILESYSTEM", fake)

    with pytest.raises(SandboxStateReproductionError) as error:
        reproduce_passwd_source_state(_manifest())

    assert str(error.value) == "sandbox source-state reproduction failed"
    assert fake.snapshot() == (0o600, 1001, 1002)
    assert fake.chown_calls == [(0, 0), (1001, 1002)]
    assert fake.chmod_calls == [0o644, 0o600]
    assert fake.fstat_snapshots[-1] == (0o600, 1001, 1002)
    assert target.read_bytes() == b"unchanged\n"


def test_verification_failure_rolls_back_and_verifies_original_metadata(
    metadata_fs: FakeMetadataFilesystem,
) -> None:
    metadata_fs.ignore_chmod_calls.add(1)

    with pytest.raises(SandboxStateReproductionError):
        reproduce_passwd_source_state(_manifest())

    assert metadata_fs.snapshot() == (0o600, 1001, 1002)
    assert metadata_fs.chown_calls == [(0, 0), (1001, 1002)]
    assert metadata_fs.chmod_calls == [0o644, 0o600]
    assert metadata_fs.fstat_snapshots[-1] == (0o600, 1001, 1002)


def test_rollback_failure_raises_without_claiming_reproduction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "sandbox-passwd"
    target.write_bytes(b"unchanged\n")
    fake = FakeMetadataFilesystem(target, fail_chmod_calls={1, 2})
    monkeypatch.setattr(reproduction, "_FILESYSTEM", fake)

    with pytest.raises(SandboxStateReproductionError) as error:
        reproduce_passwd_source_state(_manifest())

    assert not hasattr(error.value, "reproduced")
    assert str(error.value) == "sandbox source-state reproduction failed"
    assert target.read_bytes() == b"unchanged\n"


def test_result_is_immutable_and_contains_only_metadata_fields(
    metadata_fs: FakeMetadataFilesystem,
) -> None:
    result = reproduce_passwd_source_state(_manifest())

    assert [field.name for field in fields(result)] == [
        "control_id",
        "target_path",
        "before_mode",
        "before_uid",
        "before_gid",
        "requested_mode",
        "requested_uid",
        "requested_gid",
        "after_mode",
        "after_uid",
        "after_gid",
        "reproduced",
    ]
    assert "sandbox-only passwd database" not in repr(result)
    with pytest.raises((AttributeError, TypeError)):
        result.reproduced = False  # type: ignore[misc]


def test_orchestrator_receives_then_reproduces_without_changing_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    expected = object()
    calls: list[object] = []
    monkeypatch.setattr(
        orchestrator,
        "open_fixed_validation_channel_and_receive",
        lambda: SimpleNamespace(
            manifest=manifest,
            acknowledgement=SimpleNamespace(status="accepted"),
        ),
    )

    def reproduce(received_manifest: SandboxContextManifest) -> object:
        calls.append(received_manifest)
        return expected

    monkeypatch.setattr(orchestrator, "reproduce_passwd_source_state", reproduce)

    assert orchestrator.receive_and_reproduce_source_state() is expected
    assert calls == [manifest]


def test_orchestrator_does_not_reproduce_rejected_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        orchestrator,
        "open_fixed_validation_channel_and_receive",
        lambda: SimpleNamespace(
            manifest=None,
            acknowledgement=SimpleNamespace(status="rejected"),
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "reproduce_passwd_source_state",
        lambda _manifest: pytest.fail("rejected context must not be reproduced"),
    )

    with pytest.raises(SandboxStateReproductionError):
        orchestrator.receive_and_reproduce_source_state()


def test_reproduction_runtime_has_no_m5_or_generic_execution_surface() -> None:
    production_files = [
        _RUNTIME_DIR / "reproduction.py",
        _RUNTIME_DIR / "orchestrator.py",
    ]
    source = "\n".join(path.read_text(encoding="utf-8") for path in production_files)
    imported: set[str] = set()
    called: set[str] = set()
    for path in production_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    called.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    called.add(node.func.attr)

    assert not imported.intersection(
        {"argparse", "subprocess", "socket", "paramiko", "sandbox_validator"}
    )
    assert not called.intersection({"system", "eval", "exec", "read", "read_text"})
    assert "sandbox_validator" not in source
    assert "ssh" not in source.lower()
    assert "M5" not in source
    assert "os.system" not in source
    assert "shell=True" not in source
    assert SANDBOX_PASSWD_TARGET_PATH == "/etc/passwd"


def test_existing_entrypoint_is_not_wired_to_mutate_passwd_yet() -> None:
    entrypoint = (_RUNTIME_DIR / "__main__.py").read_text(encoding="utf-8")
    assert "reproduce_passwd_source_state" not in entrypoint
    assert "receive_and_reproduce_source_state" not in entrypoint
    assert "sandbox_runtime.reproduction" not in entrypoint
    assert "sandbox_runtime.orchestrator" not in entrypoint
