"""Integration and safety tests for SENTRA Milestone 3."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Sequence

import pytest
import yaml

from src.target_profiler import cli
from src.target_profiler.command_runner import (
    CommandNotAllowedError,
    CommandResult,
    validate_read_only_command,
)
from src.target_profiler.fact_loader import load_required_facts
from src.target_profiler.models import FactStatus
from src.target_profiler.profiler import (
    collect_local_profile,
    inspect_local_target,
    profile_to_yaml,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "data" / "poc" / "poc_controls.yaml"
EXPECTED_CONTROL_IDS = {
    "1.1.1.1",
    "1.1.1.6",
    "3.3.1",
    "4.2.1",
    "4.2.3",
    "5.1.19",
    "5.1.20",
    "6.2.1.2",
    "7.1.1",
    "7.1.5",
}


class UnavailableRunner:
    """Fake boundary that never starts a process."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str]) -> CommandResult:
        command = tuple(argv)
        self.calls.append(command)
        return CommandResult(
            argv=command,
            returncode=None,
            stdout="",
            stderr="",
            error_kind="not_found",
            reason="command_not_found",
        )


class ForbiddenRunner:
    def run(self, argv: Sequence[str]) -> CommandResult:
        raise AssertionError(f"unsupported host invoked a collector command: {tuple(argv)}")


def _write_fake_ubuntu_identity(root: Path) -> None:
    path = root / "etc" / "os-release"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n',
        encoding="utf-8",
    )


def test_all_ten_enrichments_contribute_to_discovered_facts() -> None:
    facts = load_required_facts(MANIFEST_PATH)
    requester_ids = {
        control_id for fact in facts for control_id in fact.requested_by
    }

    assert len(facts) == 47
    assert requester_ids == EXPECTED_CONTROL_IDS


def test_list_required_facts_does_not_profile_host(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail_if_profiled(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("--list-required-facts attempted host profiling")

    monkeypatch.setattr(cli, "collect_local_profile", fail_if_profiled)

    assert cli.main(["--list-required-facts"]) == 0
    document = yaml.safe_load(capsys.readouterr().out)
    facts = document["required_target_facts"]
    assert len(facts) == 47
    assert facts["ssh_service_status"]["requested_by"] == ["5.1.19", "5.1.20"]


def test_macos_identity_is_not_replaced_by_fake_ubuntu_data(tmp_path: Path) -> None:
    _write_fake_ubuntu_identity(tmp_path)

    target = inspect_local_target(
        tmp_path,
        system_name="Darwin",
        hostname="developer-machine",
        kernel_release="Darwin-test",
        architecture="arm64",
        platform_version="test-version",
    )

    assert target.os == "macOS"
    assert target.os != "Ubuntu"
    assert target.supported is False
    assert target.reason == "unsupported_operating_system"


def test_unsupported_host_skips_all_ubuntu_fact_collectors(tmp_path: Path) -> None:
    target = inspect_local_target(
        tmp_path,
        system_name="Darwin",
        hostname="developer-machine",
        kernel_release="Darwin-test",
        architecture="arm64",
        platform_version="test-version",
    )

    profile = collect_local_profile(
        MANIFEST_PATH,
        filesystem_root=tmp_path,
        runner=ForbiddenRunner(),  # type: ignore[arg-type]
        target=target,
        collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert profile.target.os == "macOS"
    assert profile.collection_summary.requested == 47
    assert profile.collection_summary.unsupported == 47
    assert all(result.value is None for result in profile.facts.values())


def test_fake_supported_target_builds_valid_yaml_profile(tmp_path: Path) -> None:
    _write_fake_ubuntu_identity(tmp_path)
    target = inspect_local_target(
        tmp_path,
        system_name="Linux",
        hostname="sentra-fixture",
        kernel_release="6.8.0-fixture",
        architecture="x86_64",
        platform_version="fixture",
    )
    runner = UnavailableRunner()

    profile = collect_local_profile(
        MANIFEST_PATH,
        filesystem_root=tmp_path,
        runner=runner,  # type: ignore[arg-type]
        environment={},
        target=target,
        collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    rendered = profile_to_yaml(profile)
    loaded = yaml.safe_load(rendered)

    assert target.supported is True
    assert loaded["profile_version"] == "1"
    assert loaded["target"]["os"] == "Ubuntu"
    assert loaded["target"]["os_version"] == "24.04"
    assert len(loaded["facts"]) == 47
    assert loaded["collection_summary"]["requested"] == 47
    assert loaded["facts"]["router_role"] == {
        "name": "router_role",
        "status": "unsupported",
        "value": None,
        "requested_by": ["3.3.1"],
        "reason": "router role requires administrator or deployment context",
    }


def test_cis_command_text_in_enrichment_metadata_remains_inert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    poc_root = tmp_path / "data" / "poc"
    enrichment_root = poc_root / "enriched"
    enrichment_root.mkdir(parents=True)
    manifest_text = MANIFEST_PATH.read_text(encoding="utf-8")
    (poc_root / "poc_controls.yaml").write_text(manifest_text, encoding="utf-8")

    for source in (MANIFEST_PATH.parent / "enriched").glob("*.yaml"):
        content = source.read_text(encoding="utf-8")
        content += '\nAudit: "systemctl start example.service"\n'
        content += 'Remediation: "chmod 000 /etc/passwd"\n'
        (enrichment_root / source.name).write_text(content, encoding="utf-8")

    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("CIS command text was executed")

    monkeypatch.setattr(os, "system", fail_if_called)
    monkeypatch.setattr(subprocess, "run", fail_if_called)
    facts = load_required_facts(poc_root / "poc_controls.yaml")

    assert len(facts) == 47


def test_no_remote_execution_or_address_argument_exists() -> None:
    parser = cli.build_parser()
    option_strings = {
        option
        for action in parser._actions
        for option in action.option_strings
    }

    assert not any("address" in option or option.endswith("-ip") for option in option_strings)
    assert "--host" not in option_strings
    with pytest.raises(CommandNotAllowedError):
        validate_read_only_command(("ssh", "some-host", "uname"))


def test_milestone_3_sources_contain_no_ipv4_literal() -> None:
    ipv4_literal = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
    paths = [
        *sorted((ROOT / "src" / "target_profiler").glob("*.py")),
        ROOT / "README.md",
    ]

    for path in paths:
        assert ipv4_literal.search(path.read_text(encoding="utf-8")) is None, path


def test_cli_writes_yaml_when_output_is_requested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = inspect_local_target(
        tmp_path,
        system_name="Darwin",
        hostname="developer-machine",
        kernel_release="Darwin-test",
        architecture="arm64",
        platform_version="test-version",
    )
    profile = collect_local_profile(
        MANIFEST_PATH,
        filesystem_root=tmp_path,
        target=target,
        collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    monkeypatch.setattr(cli, "collect_local_profile", lambda *_args, **_kwargs: profile)
    output = tmp_path / "profiles" / "profile.yaml"

    assert cli.main(["--output", str(output), "--format", "yaml"]) == 0
    loaded = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert loaded["target"]["os"] == "macOS"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(output.parent.glob(f".{output.name}.*.tmp")) == []
    assert all(
        fact["status"] == FactStatus.UNSUPPORTED.value
        for fact in loaded["facts"].values()
    )
