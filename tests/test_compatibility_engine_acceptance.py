"""Milestone 4 end-to-end, safety, and repository-boundary acceptance tests.

All target profiles in this module are synthetic fixtures.  These tests do not
claim that the compatibility engine has been run against the recorded real
Ubuntu target.
"""

from __future__ import annotations

import ast
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import stat
import subprocess
from typing import Any

import pytest
import yaml

from src.compatibility_engine import cli
from src.compatibility_engine.engine import evaluate_compatibility
from src.compatibility_engine.loaders import load_compatibility_inputs
from src.compatibility_engine.models import (
    CompatibilityDecision,
    CompatibilityReport,
)
from src.compatibility_engine.report import report_to_yaml
from src.target_profiler import cli as target_profiler_cli
from src.target_profiler import profiler as target_profiler
from src.target_profiler.command_runner import CommandRunner
from src.target_profiler.fact_loader import load_required_facts
from src.target_profiler.models import (
    FactResult,
    FactStatus,
    TargetInfo,
    TargetProfile,
    build_collection_summary,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "data" / "poc" / "poc_controls.yaml"
M4_SOURCE_DIRECTORY = ROOT / "src" / "compatibility_engine"
COMPATIBILITY_OUTPUT_DIRECTORY = ROOT / "data" / "compatibility"
EXPECTED_CONTROL_IDS = (
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
)


# A complete, deliberately uncomplicated evidence set.  These values mean only
# that no current deterministic compatibility rule is triggered; they are not a
# CIS compliance fixture and do not express a global safety conclusion.
BASE_FACT_VALUES: dict[str, Any] = {
    "cramfs_filesystem_required": False,
    "cramfs_module_available_in_installed_kernels": False,
    "cramfs_module_precompiled_into_kernel": False,
    "cramfs_module_loaded": False,
    "cramfs_module_loadable": False,
    "cramfs_module_denylisted": True,
    "overlayfs_module_available_in_installed_kernels": True,
    "overlayfs_module_precompiled_into_kernel": True,
    "overlayfs_module_loaded": True,
    "overlayfs_module_loadable": True,
    "overlayfs_module_denylisted": False,
    "container_applications_in_use": [],
    "ipv4_forwarding_status": 0,
    "ipv6_enabled": True,
    "ipv6_forwarding_status": 0,
    "router_role": False,
    "csp_hosted": False,
    "sysctl_parameter_sources": ["/etc/sysctl.conf"],
    "ufw_installed": True,
    "iptables_installed": True,
    "installed_firewall_utilities": ["ufw", "iptables"],
    "ufw_service_mask_status": "not_masked",
    "ufw_service_enabled": "enabled",
    "ufw_service_active": "active",
    "ufw_status": "active",
    "remote_network_session_active": False,
    "ssh_session_active": False,
    "ufw_ssh_port_22_rule_present": True,
    "ssh_installed": True,
    "ssh_service_status": "active",
    "sshd_permit_empty_passwords_effective": "no",
    "sshd_match_directives_present": False,
    "sshd_include_locations_enabled": [],
    "sshd_permit_root_login_effective": "prohibit-password",
    "individual_administrator_account_available": True,
    "root_escalation_path_available": True,
    "auditd_service_present": True,
    "auditd_service_mask_status": "not_masked",
    "auditd_service_enabled": "enabled",
    "auditd_service_active": "active",
    "passwd_file_mode": "0644",
    "passwd_file_owner_uid": 0,
    "passwd_file_group_gid": 0,
    "shadow_file_mode": "0640",
    "shadow_file_owner_uid": 0,
    "shadow_file_group_gid": 42,
    "shadow_group_gid": 42,
}


FactOverride = tuple[FactStatus, Any | None, str | None]


def _synthetic_profile(
    *,
    overrides: dict[str, FactOverride] | None = None,
    target: TargetInfo | None = None,
) -> TargetProfile:
    required_facts = load_required_facts(MANIFEST_PATH)
    required_names = {item.name for item in required_facts}
    assert set(BASE_FACT_VALUES) == required_names

    selected_overrides = overrides or {}
    assert set(selected_overrides) <= required_names
    facts: dict[str, FactResult] = {}
    for required in required_facts:
        status, value, reason = selected_overrides.get(
            required.name,
            (FactStatus.COLLECTED, BASE_FACT_VALUES[required.name], None),
        )
        facts[required.name] = FactResult(
            name=required.name,
            status=status,
            value=value,
            requested_by=list(required.requested_by),
            reason=reason,
        )

    selected_target = target or TargetInfo(
        hostname="sentra-synthetic-fixture",
        os="Ubuntu",
        os_version="24.04",
        kernel="6.8.0-synthetic",
        architecture="x86_64",
        supported=True,
    )
    return TargetProfile(
        collected_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        target=selected_target,
        facts=facts,
        collection_summary=build_collection_summary(facts),
    )


def _write_profile(path: Path, profile: TargetProfile) -> None:
    path.write_text(
        yaml.safe_dump(
            profile.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )


def _mixed_profile() -> TargetProfile:
    return _synthetic_profile(
        overrides={
            "cramfs_filesystem_required": (
                FactStatus.UNSUPPORTED,
                None,
                "filesystem requirements require workload-owner context",
            ),
            "container_applications_in_use": (
                FactStatus.COLLECTED,
                ["docker"],
                None,
            ),
            "router_role": (
                FactStatus.UNSUPPORTED,
                None,
                "router role requires administrator or deployment context",
            ),
            "remote_network_session_active": (
                FactStatus.COLLECTED,
                True,
                None,
            ),
            "ssh_session_active": (FactStatus.COLLECTED, True, None),
            "ufw_ssh_port_22_rule_present": (
                FactStatus.COLLECTED,
                False,
                None,
            ),
            "sshd_match_directives_present": (
                FactStatus.COLLECTED,
                True,
                None,
            ),
            "individual_administrator_account_available": (
                FactStatus.UNSUPPORTED,
                None,
                "administrator account suitability requires identity context",
            ),
            "root_escalation_path_available": (
                FactStatus.UNSUPPORTED,
                None,
                "root escalation availability requires authorization context",
            ),
            "auditd_service_active": (
                FactStatus.UNAVAILABLE,
                None,
                "permission denied while reading auditd state",
            ),
        }
    )


def _input_bytes() -> dict[Path, bytes]:
    paths = [
        MANIFEST_PATH,
        *sorted((MANIFEST_PATH.parent / "enriched").glob("*.yaml")),
    ]
    return {path: path.read_bytes() for path in paths}


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
    return None


def test_synthetic_mixed_profile_produces_traceable_provisional_report(
    tmp_path: Path,
) -> None:
    profile_path = tmp_path / "synthetic-mixed-profile.yaml"
    _write_profile(profile_path, _mixed_profile())

    inputs = load_compatibility_inputs(profile_path, MANIFEST_PATH)
    report = evaluate_compatibility(
        inputs,
        generated_at=datetime(2026, 2, 3, 4, 5, 6, tzinfo=timezone.utc),
    )
    # The serialized representation must itself satisfy the public report schema.
    CompatibilityReport.model_validate(report.model_dump(mode="json"))

    assert tuple(item.control_id for item in report.control_results) == EXPECTED_CONTROL_IDS
    decisions = {item.control_id: item.result for item in report.control_results}
    assert decisions == {
        "1.1.1.1": CompatibilityDecision.REVIEW_REQUIRED,
        "1.1.1.6": CompatibilityDecision.WARNING,
        "3.3.1": CompatibilityDecision.REVIEW_REQUIRED,
        "4.2.1": CompatibilityDecision.NO_KNOWN_CONFLICT,
        "4.2.3": CompatibilityDecision.WARNING,
        "5.1.19": CompatibilityDecision.REVIEW_REQUIRED,
        "5.1.20": CompatibilityDecision.REVIEW_REQUIRED,
        "6.2.1.2": CompatibilityDecision.INSUFFICIENT_EVIDENCE,
        # The enrichment defines a readability concern but no consumer/threshold,
        # so M4 must preserve the ambiguity instead of inventing a mode verdict.
        "7.1.1": CompatibilityDecision.REVIEW_REQUIRED,
        "7.1.5": CompatibilityDecision.NO_KNOWN_CONFLICT,
    }
    assert report.overall_summary.model_dump() == {
        "controls_evaluated": 10,
        "no_known_conflict": 2,
        "warning": 2,
        "review_required": 5,
        "insufficient_evidence": 1,
        "provisional": 10,
    }

    for result in report.control_results:
        assert result.provisional is True
        assert result.metadata_review_status.value == "needs_review"
        assert result.evidence_used
        assert result.explanation.strip()
        if result.result is not CompatibilityDecision.NO_KNOWN_CONFLICT:
            assert result.triggered_rules
        evidence_names = {item.fact for item in result.evidence_used}
        for finding in result.triggered_rules:
            assert set(finding.evidence_facts) <= evidence_names
            assert finding.source_basis
            assert finding.explanation.strip()

    overlay = next(
        item for item in report.control_results if item.control_id == "1.1.1.6"
    )
    assert any(
        rule.rule_id == "overlayfs-container-workload"
        for rule in overlay.triggered_rules
    )
    container_evidence = next(
        item
        for item in overlay.evidence_used
        if item.fact == "container_applications_in_use"
    )
    assert container_evidence.status is FactStatus.COLLECTED
    assert container_evidence.value == ["docker"]
    assert report.profile_source == profile_path.as_posix()


def test_report_yaml_has_no_global_safe_or_compliance_verdict(tmp_path: Path) -> None:
    profile_path = tmp_path / "synthetic-profile.yaml"
    _write_profile(profile_path, _synthetic_profile())
    report = evaluate_compatibility(
        load_compatibility_inputs(profile_path, MANIFEST_PATH),
        generated_at=datetime(2026, 2, 3, tzinfo=timezone.utc),
    )

    document = yaml.safe_load(report_to_yaml(report))
    assert CompatibilityReport.model_validate(document)
    forbidden_keys = {
        "safe",
        "system_safe",
        "compliant",
        "compliance_verdict",
        "global_verdict",
    }
    assert forbidden_keys.isdisjoint(document)
    assert "result" not in document
    allowed_results = {decision.value for decision in CompatibilityDecision}
    assert {
        item["result"] for item in document["control_results"]
    } <= allowed_results
    assert not (
        {"safe", "pass", "fail", "compatible"}
        & {item["result"] for item in document["control_results"]}
    )


def test_cli_writes_only_requested_report_and_preserves_all_inputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile_path = tmp_path / "synthetic-profile.yaml"
    _write_profile(profile_path, _mixed_profile())
    profile_before = profile_path.read_bytes()
    metadata_before = _input_bytes()
    output_path = tmp_path / "reports" / "compatibility.yaml"
    files_before = {
        path.relative_to(tmp_path)
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    assert cli.main(
        [
            "--profile",
            str(profile_path),
            "--manifest",
            str(MANIFEST_PATH),
            "--output",
            str(output_path),
        ]
    ) == 0

    assert capsys.readouterr().out == ""
    assert output_path.is_file()
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600
    files_after = {
        path.relative_to(tmp_path)
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert files_after - files_before == {output_path.relative_to(tmp_path)}
    assert not list(output_path.parent.glob(f".{output_path.name}.*.tmp"))
    assert profile_path.read_bytes() == profile_before
    assert {path: path.read_bytes() for path in metadata_before} == metadata_before

    document = yaml.safe_load(output_path.read_text(encoding="utf-8"))
    parsed = CompatibilityReport.model_validate(document)
    assert parsed.overall_summary.controls_evaluated == 10
    assert parsed.overall_summary.provisional == 10


def test_list_rules_needs_no_profile_and_never_evaluates_target(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("--list-rules attempted to load or evaluate a target")

    monkeypatch.setattr(cli, "load_compatibility_inputs", fail)
    monkeypatch.setattr(cli, "evaluate_compatibility", fail)

    assert cli.main(["--list-rules"]) == 0
    first = capsys.readouterr().out
    assert cli.main(["--list-rules"]) == 0
    second = capsys.readouterr().out
    assert first == second

    document = yaml.safe_load(first)
    rules = document["rules"]
    assert rules
    assert len({item["rule_id"] for item in rules}) == len(rules)
    assert {item["control_id"] for item in rules} == set(EXPECTED_CONTROL_IDS)
    assert "overlayfs-container-workload" in {
        item["rule_id"] for item in rules
    }
    assert all(item["source_basis"] for item in rules)
    assert all(item["evidence_facts"] for item in rules)


def test_unsupported_profile_is_refused_without_writing_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    unsupported_target = TargetInfo(
        hostname="unsupported-synthetic-fixture",
        os="macOS",
        os_version="15.0",
        kernel="Darwin-synthetic",
        architecture="arm64",
        supported=False,
        reason="unsupported_operating_system",
    )
    profile_path = tmp_path / "unsupported-profile.yaml"
    _write_profile(
        profile_path,
        _synthetic_profile(target=unsupported_target),
    )
    output_path = tmp_path / "must-not-exist.yaml"

    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "--profile",
                str(profile_path),
                "--manifest",
                str(MANIFEST_PATH),
                "--output",
                str(output_path),
            ]
        )

    assert raised.value.code == 2
    assert "supported Ubuntu 24.04" in capsys.readouterr().err
    assert not output_path.exists()


def test_evaluation_invokes_no_process_network_or_target_profiler_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile_path = tmp_path / "synthetic-profile.yaml"
    _write_profile(profile_path, _mixed_profile())

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Milestone 4 crossed a forbidden execution boundary")

    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(subprocess, "call", fail)
    monkeypatch.setattr(subprocess, "check_call", fail)
    monkeypatch.setattr(subprocess, "check_output", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(target_profiler, "collect_local_profile", fail)
    monkeypatch.setattr(target_profiler_cli, "main", fail)
    monkeypatch.setattr(CommandRunner, "run", fail)

    assert cli.main(
        [
            "--profile",
            str(profile_path),
            "--manifest",
            str(MANIFEST_PATH),
        ]
    ) == 0
    document = yaml.safe_load(capsys.readouterr().out)
    assert document["overall_summary"]["controls_evaluated"] == 10


def test_m4_source_has_no_dynamic_process_network_or_profiler_execution() -> None:
    forbidden_imports = {
        "subprocess",
        "socket",
        "paramiko",
        "asyncssh",
        "fabric",
        "src.target_profiler.cli",
        "src.target_profiler.collectors",
        "src.target_profiler.command_runner",
        "src.target_profiler.profiler",
    }
    forbidden_calls = {
        "eval",
        "exec",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "os.spawnv",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "socket.socket",
        "socket.create_connection",
        "collect_local_profile",
    }

    for path in sorted(M4_SOURCE_DIRECTORY.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported: set[str] = set()
        calls: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Call):
                name = _dotted_name(node.func)
                if name:
                    calls.add(name)

        assert not any(
            imported_name == forbidden
            or imported_name.startswith(f"{forbidden}.")
            for imported_name in imported
            for forbidden in forbidden_imports
        ), path
        assert forbidden_calls.isdisjoint(calls), (path, forbidden_calls & calls)


def test_generated_compatibility_reports_are_ignored_but_gitkeep_is_preserved() -> None:
    ignore_text = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()

    assert "data/compatibility/*" in ignore_text
    assert "!data/compatibility/.gitkeep" in ignore_text
    assert (COMPATIBILITY_OUTPUT_DIRECTORY / ".gitkeep").is_file()

