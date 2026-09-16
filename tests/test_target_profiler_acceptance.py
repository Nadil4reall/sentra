"""Additional Milestone 3 acceptance-boundary regression tests."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

import pytest

from src.target_profiler.collectors import CollectionContext, collect_fact
from src.target_profiler.command_runner import CommandResult
from src.target_profiler.models import FactStatus, RequiredFact
from src.target_profiler.profiler import inspect_local_target


class RuntimeMaskedRunner:
    """Return the legitimate non-zero systemd state used for runtime masks."""

    def run(self, argv: Sequence[str]) -> CommandResult:
        command = tuple(argv)
        assert command == ("systemctl", "is-enabled", "auditd.service")
        return CommandResult(
            argv=command,
            returncode=1,
            stdout="masked-runtime\n",
            stderr="",
            error_kind="nonzero_exit",
            reason="command_returned_nonzero",
        )


def test_only_ubuntu_24_04_is_a_supported_target(tmp_path: Path) -> None:
    os_release = tmp_path / "etc" / "os-release"
    os_release.parent.mkdir(parents=True)
    os_release.write_text(
        'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\n',
        encoding="utf-8",
    )

    target = inspect_local_target(
        tmp_path,
        system_name="Linux",
        hostname="older-ubuntu-fixture",
        kernel_release="fixture-kernel",
        architecture="x86_64",
        platform_version="fixture-version",
    )

    assert target.os == "Ubuntu"
    assert target.os_version == "22.04"
    assert target.supported is False
    assert target.reason == "unsupported_ubuntu_version"


def test_filesystem_permission_denial_is_unavailable_not_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    passwd_path = tmp_path / "etc" / "passwd"
    passwd_path.parent.mkdir(parents=True)
    passwd_path.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
    original_stat = Path.stat

    def permission_denied(path: Path, *args: object, **kwargs: object):
        if path == passwd_path:
            raise PermissionError("fixture permission denial")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", permission_denied)
    result = collect_fact(
        RequiredFact(name="passwd_file_mode", requested_by=["7.1.1"]),
        CollectionContext(root=tmp_path),
    )

    assert result.status is FactStatus.UNAVAILABLE
    assert result.value is None
    assert "permission denied" in (result.reason or "")


def test_runtime_systemd_mask_is_still_reported_as_masked() -> None:
    result = collect_fact(
        RequiredFact(name="auditd_service_mask_status", requested_by=["6.2.1.2"]),
        CollectionContext(runner=RuntimeMaskedRunner()),  # type: ignore[arg-type]
    )

    assert result.status is FactStatus.COLLECTED
    assert result.value == "masked"
