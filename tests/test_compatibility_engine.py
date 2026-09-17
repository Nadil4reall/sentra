"""Core model, loader, evidence, report, and CLI tests for Milestone 4."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import shutil
import stat

import pytest
import yaml
from pydantic import ValidationError

from src.compatibility_engine import cli
from src.compatibility_engine.engine import evaluate_compatibility
from src.compatibility_engine.evidence import resolve_evidence
from src.compatibility_engine.loaders import load_compatibility_inputs
from src.compatibility_engine.models import (
    CompatibilityDecision,
    CompatibilityReport,
    CompatibilitySummary,
    ControlCompatibilityResult,
    EvidenceRecord,
)
from src.compatibility_engine.report import report_to_yaml
from src.poc_models import Category, DerivationStatus
from src.target_profiler.fact_loader import load_required_facts
from src.target_profiler.models import (
    FactResult,
    FactStatus,
    TargetInfo,
    TargetProfile,
    build_collection_summary,
)
from src.target_profiler.profiler import profile_to_yaml


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "data" / "poc" / "poc_controls.yaml"
FIXED_COLLECTED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
FIXED_GENERATED_AT = datetime(2026, 1, 2, 4, 5, 6, tzinfo=timezone.utc)


@pytest.fixture
def complete_profile() -> TargetProfile:
    """Build the full current 47-fact M3 contract without probing a host."""

    facts = {
        required.name: FactResult(
            name=required.name,
            status=FactStatus.UNSUPPORTED,
            value=None,
            requested_by=list(required.requested_by),
            reason="synthetic fixture requires contextual review",
        )
        for required in load_required_facts(MANIFEST_PATH)
    }
    return TargetProfile(
        collected_at=FIXED_COLLECTED_AT,
        target=TargetInfo(
            hostname="sentra-m4-fixture",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-fixture",
            architecture="x86_64",
            supported=True,
        ),
        facts=facts,
        collection_summary=build_collection_summary(facts),
    )


@pytest.fixture
def profile_path(tmp_path: Path, complete_profile: TargetProfile) -> Path:
    path = tmp_path / "profiles" / "target-profile.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(profile_to_yaml(complete_profile), encoding="utf-8")
    return path


def _copy_m2_inputs(tmp_path: Path) -> Path:
    destination = tmp_path / "poc"
    destination.mkdir()
    shutil.copy2(MANIFEST_PATH, destination / MANIFEST_PATH.name)
    shutil.copytree(MANIFEST_PATH.parent / "enriched", destination / "enriched")
    return destination / MANIFEST_PATH.name


def _replace_fact(
    profile: TargetProfile,
    name: str,
    *,
    status: FactStatus,
    value: object = None,
    reason: str | None = None,
) -> TargetProfile:
    updated = profile.model_copy(deep=True)
    original = updated.facts[name]
    updated.facts[name] = FactResult(
        name=name,
        status=status,
        value=value,
        requested_by=list(original.requested_by),
        reason=reason,
    )
    updated.collection_summary = build_collection_summary(updated.facts)
    return TargetProfile.model_validate(updated.model_dump())


def test_decision_values_are_compatibility_states_not_pass_fail() -> None:
    assert {item.value for item in CompatibilityDecision} == {
        "no_known_conflict",
        "warning",
        "review_required",
        "insufficient_evidence",
    }


def test_evidence_model_preserves_false_and_rejects_false_for_unavailable() -> None:
    collected = EvidenceRecord(
        fact="example_fact",
        status=FactStatus.COLLECTED,
        value=False,
        requested_by=["1.1.1.1"],
    )
    assert collected.value is False
    assert collected.reason is None

    with pytest.raises(ValidationError):
        EvidenceRecord(
            fact="example_fact",
            status=FactStatus.UNAVAILABLE,
            value=False,
            requested_by=["1.1.1.1"],
            reason="permission denied",
        )


def test_summary_model_rejects_inconsistent_terminal_counts() -> None:
    with pytest.raises(ValidationError):
        CompatibilitySummary(
            controls_evaluated=2,
            no_known_conflict=1,
            warning=0,
            review_required=0,
            insufficient_evidence=0,
            provisional=2,
        )


def test_control_result_provisional_flag_must_match_metadata_status() -> None:
    evidence = EvidenceRecord(
        fact="example_fact",
        status=FactStatus.COLLECTED,
        value=True,
        requested_by=["1.1.1.1"],
    )
    with pytest.raises(ValidationError):
        ControlCompatibilityResult(
            control_id="1.1.1.1",
            category=Category.KERNEL,
            result=CompatibilityDecision.NO_KNOWN_CONFLICT,
            provisional=False,
            metadata_review_status=DerivationStatus.NEEDS_REVIEW,
            evidence_used=[evidence],
            triggered_rules=[],
            missing_or_contextual_evidence=[],
            explanation="Fixture explanation.",
        )


def test_full_m3_profile_round_trips_through_its_schema(
    profile_path: Path,
) -> None:
    raw = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile = TargetProfile.model_validate(raw)

    assert profile.profile_version == "1"
    assert profile.collected_at == FIXED_COLLECTED_AT
    assert profile.target.supported is True
    assert len(profile.facts) == 47
    assert profile.collection_summary.requested == 47


def test_loader_reads_all_m2_enrichments_and_matches_m3_relationships(
    profile_path: Path,
) -> None:
    inputs = load_compatibility_inputs(profile_path, MANIFEST_PATH)

    assert inputs.profile_source == profile_path.as_posix()
    assert inputs.manifest.poc.total_controls == 10
    assert len(inputs.enrichments) == 10
    assert [item.control_id for item in inputs.enrichments] == [
        item.id for item in inputs.manifest.poc.controls
    ]
    assert all(
        enrichment.sentra.category == selected.category
        for enrichment, selected in zip(
            inputs.enrichments, inputs.manifest.poc.controls, strict=True
        )
    )
    assert len(inputs.profile.facts) == 47
    assert inputs.profile.facts["ssh_service_status"].requested_by == [
        "5.1.19",
        "5.1.20",
    ]


def test_loader_does_not_require_cis_source_control_files(
    tmp_path: Path, profile_path: Path
) -> None:
    copied_manifest = _copy_m2_inputs(tmp_path)

    inputs = load_compatibility_inputs(profile_path, copied_manifest)

    assert len(inputs.enrichments) == 10
    assert not (copied_manifest.parents[1] / "controls").exists()


def test_loader_rejects_manifest_enrichment_id_mismatch(
    tmp_path: Path, profile_path: Path
) -> None:
    copied_manifest = _copy_m2_inputs(tmp_path)
    enrichment_path = copied_manifest.parent / "enriched" / "1_1_1_1.yaml"
    document = yaml.safe_load(enrichment_path.read_text(encoding="utf-8"))
    document["control_id"] = "9.9.9"
    enrichment_path.write_text(
        yaml.safe_dump(document, sort_keys=False), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="Manifest/enrichment ID mismatch"):
        load_compatibility_inputs(profile_path, copied_manifest)


def test_loader_rejects_missing_profile_fact(
    tmp_path: Path, complete_profile: TargetProfile
) -> None:
    raw = complete_profile.model_dump(mode="json")
    raw["facts"].pop("container_applications_in_use")
    raw["collection_summary"]["requested"] -= 1
    raw["collection_summary"]["unsupported"] -= 1
    path = tmp_path / "missing-fact.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="Profile facts do not match"):
        load_compatibility_inputs(path, MANIFEST_PATH)


def test_loader_rejects_requested_by_relationship_mismatch(
    tmp_path: Path, complete_profile: TargetProfile
) -> None:
    raw = complete_profile.model_dump(mode="json")
    raw["facts"]["ssh_service_status"]["requested_by"] = ["5.1.19"]
    path = tmp_path / "wrong-requester.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="requested_by mismatch"):
        load_compatibility_inputs(path, MANIFEST_PATH)


def test_loader_refuses_unsupported_target_profile(
    tmp_path: Path, complete_profile: TargetProfile
) -> None:
    raw = complete_profile.model_dump(mode="json")
    raw["target"].update(
        {
            "os": "Ubuntu",
            "os_version": "22.04",
            "supported": False,
            "reason": "unsupported_ubuntu_version",
        }
    )
    path = tmp_path / "unsupported-profile.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="supported Ubuntu 24.04"):
        load_compatibility_inputs(path, MANIFEST_PATH)


def test_evidence_resolution_preserves_collected_false_and_shared_requesters(
    complete_profile: TargetProfile,
) -> None:
    profile = _replace_fact(
        complete_profile,
        "ssh_installed",
        status=FactStatus.COLLECTED,
        value=False,
    )

    evidence = resolve_evidence(profile, "ssh_installed", "5.1.20")

    assert evidence.fact == "ssh_installed"
    assert evidence.status is FactStatus.COLLECTED
    assert evidence.value is False
    assert evidence.requested_by == ["5.1.19", "5.1.20"]
    assert evidence.reason is None


def test_evidence_resolution_preserves_unavailable_reason_without_false(
    complete_profile: TargetProfile,
) -> None:
    profile = _replace_fact(
        complete_profile,
        "ufw_ssh_port_22_rule_present",
        status=FactStatus.UNAVAILABLE,
        reason="permission denied while reading configured UFW rules",
    )

    evidence = resolve_evidence(
        profile, "ufw_ssh_port_22_rule_present", "4.2.3"
    )

    assert evidence.status is FactStatus.UNAVAILABLE
    assert evidence.value is None
    assert evidence.reason == "permission denied while reading configured UFW rules"


def test_evidence_resolution_returns_a_copy_and_checks_requester(
    complete_profile: TargetProfile,
) -> None:
    evidence = resolve_evidence(complete_profile, "ssh_installed", "5.1.19")
    evidence.requested_by.append("9.9.9")

    assert complete_profile.facts["ssh_installed"].requested_by == [
        "5.1.19",
        "5.1.20",
    ]
    with pytest.raises(ValueError, match="does not identify control"):
        resolve_evidence(complete_profile, "ssh_installed", "4.2.3")


def test_evidence_resolution_rejects_absent_fact(
    complete_profile: TargetProfile,
) -> None:
    with pytest.raises(ValueError, match="missing required fact"):
        resolve_evidence(complete_profile, "not_in_profile", "1.1.1.1")


def test_evaluation_builds_complete_provisional_report(
    profile_path: Path,
) -> None:
    inputs = load_compatibility_inputs(profile_path, MANIFEST_PATH)

    report = evaluate_compatibility(inputs, generated_at=FIXED_GENERATED_AT)

    assert report.report_version == "1"
    assert report.generated_at == FIXED_GENERATED_AT
    assert report.profile_collected_at == FIXED_COLLECTED_AT
    assert len(report.control_results) == 10
    assert report.overall_summary.controls_evaluated == 10
    assert report.overall_summary.provisional == 10
    assert sum(
        (
            report.overall_summary.no_known_conflict,
            report.overall_summary.warning,
            report.overall_summary.review_required,
            report.overall_summary.insufficient_evidence,
        )
    ) == 10
    assert all(result.evidence_used for result in report.control_results)
    assert all(result.explanation for result in report.control_results)


def test_report_yaml_is_safe_deterministic_and_schema_valid(
    profile_path: Path,
) -> None:
    inputs = load_compatibility_inputs(profile_path, MANIFEST_PATH)
    report = evaluate_compatibility(inputs, generated_at=FIXED_GENERATED_AT)

    first = report_to_yaml(report)
    second = report_to_yaml(report)
    loaded = yaml.safe_load(first)
    validated = CompatibilityReport.model_validate(loaded)

    assert first == second
    assert "!!python" not in first
    assert loaded["report_version"] == "1"
    assert loaded["generated_at"] == "2026-01-02T04:05:06Z"
    assert validated.overall_summary.controls_evaluated == 10


def test_cli_lists_rules_without_loading_a_profile(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail_if_loaded(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("--list-rules attempted to load a target profile")

    monkeypatch.setattr(cli, "load_compatibility_inputs", fail_if_loaded)

    assert cli.main(["--list-rules"]) == 0
    document = yaml.safe_load(capsys.readouterr().out)

    assert document["rules"]
    assert any(
        item["rule_id"] == "overlayfs-container-workload"
        and item["control_id"] == "1.1.1.6"
        for item in document["rules"]
    )


def test_cli_evaluates_explicit_profile_to_stdout(
    profile_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(
        ["--profile", str(profile_path), "--manifest", str(MANIFEST_PATH)]
    ) == 0
    document = yaml.safe_load(capsys.readouterr().out)
    report = CompatibilityReport.model_validate(document)

    assert report.profile_source == profile_path.as_posix()
    assert report.overall_summary.controls_evaluated == 10


def test_cli_writes_private_yaml_report_only_when_output_is_requested(
    tmp_path: Path,
    profile_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "compatibility" / "report.yaml"

    assert cli.main(
        [
            "--profile",
            str(profile_path),
            "--manifest",
            str(MANIFEST_PATH),
            "--output",
            str(output),
        ]
    ) == 0

    assert capsys.readouterr().out == ""
    report = CompatibilityReport.model_validate(
        yaml.safe_load(output.read_text(encoding="utf-8"))
    )
    assert report.overall_summary.controls_evaluated == 10
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(output.parent.glob(f".{output.name}.*.tmp")) == []
