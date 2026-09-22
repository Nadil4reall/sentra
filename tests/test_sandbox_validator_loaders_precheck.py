"""M5 input-lineage and local precheck boundary tests."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import shutil

import pytest
import yaml

from src.compatibility_engine.models import (
    CompatibilityDecision,
    CompatibilityReport,
    CompatibilitySummary,
    ControlCompatibilityResult,
    EvidenceRecord,
    TriggeredRule,
)
from src.compatibility_engine.report import report_to_yaml as m4_report_to_yaml
from src.poc_models import Category, DerivationStatus
from src.sandbox_validator import cli
from src.sandbox_validator.loaders import load_validation_inputs
from src.sandbox_validator.models import (
    AuditEvidence,
    EvidenceStatus,
    SandboxIdentity,
)
from src.sandbox_validator.precheck import build_precheck, inspect_sandbox_identity
from src.target_profiler.models import FactStatus, TargetInfo


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data" / "poc" / "poc_controls.yaml"
NOW = datetime(2026, 9, 20, 8, 30, tzinfo=timezone.utc)


def _copy_minimal_m2(tmp_path: Path) -> Path:
    destination = tmp_path / "poc"
    (destination / "enriched").mkdir(parents=True)
    shutil.copy2(MANIFEST, destination / MANIFEST.name)
    shutil.copy2(
        MANIFEST.parent / "enriched" / "7_1_1.yaml",
        destination / "enriched" / "7_1_1.yaml",
    )
    return destination / MANIFEST.name


def _m4_report() -> CompatibilityReport:
    target = TargetInfo(
        hostname="profiled-target",
        os="Ubuntu",
        os_version="24.04",
        kernel="6.8.0-fixture",
        architecture="aarch64",
        supported=True,
    )
    evidence = EvidenceRecord(
        fact="passwd_file_mode",
        status=FactStatus.COLLECTED,
        value="0644",
        requested_by=["7.1.1"],
    )
    finding = TriggeredRule(
        rule_id="passwd-readability-preservation-review",
        result=CompatibilityDecision.REVIEW_REQUIRED,
        explanation="Readability preservation requires sandbox validation.",
        source_basis=["possible_conflicts: preserve /etc/passwd readability"],
        evidence_facts=["passwd_file_mode"],
    )
    result = ControlCompatibilityResult(
        control_id="7.1.1",
        category=Category.FILE_PERMISSIONS,
        result=CompatibilityDecision.REVIEW_REQUIRED,
        provisional=True,
        metadata_review_status=DerivationStatus.NEEDS_REVIEW,
        evidence_used=[evidence],
        triggered_rules=[finding],
        missing_or_contextual_evidence=[evidence],
        explanation="Synthetic provisional M4 review result.",
    )
    return CompatibilityReport(
        generated_at=NOW,
        profile_source="data/profiles/sandbox-profile.yaml",
        profile_collected_at=NOW,
        target=target,
        control_results=[result],
        overall_summary=CompatibilitySummary(
            controls_evaluated=1,
            no_known_conflict=0,
            warning=0,
            review_required=1,
            insufficient_evidence=0,
            provisional=1,
        ),
    )


def _identity(*, uid: int = 0, supported: bool = True) -> SandboxIdentity:
    return SandboxIdentity(
        hostname="sandbox",
        os="Ubuntu" if supported else "Other Linux",
        version="24.04" if supported else "1",
        kernel="fixture",
        architecture="aarch64",
        architecture_supported=True,
        effective_uid=uid,
        privileged=uid == 0,
        supported=supported,
        reason=None if supported else "unsupported_linux_distribution",
    )


def test_loader_uses_m2_metadata_and_m4_report_without_cis_source_files(
    tmp_path: Path,
) -> None:
    manifest = _copy_minimal_m2(tmp_path)
    report_path = tmp_path / "m4.yaml"
    rendered = m4_report_to_yaml(_m4_report())
    report_path.write_text(rendered, encoding="utf-8")

    inputs = load_validation_inputs(
        "7.1.1", compatibility_report=report_path, manifest_path=manifest
    )

    assert inputs.enrichment is not None
    assert inputs.enrichment.sentra.category is Category.FILE_PERMISSIONS
    assert inputs.control_title == "Ensure permissions on /etc/passwd are configured"
    assert inputs.compatibility is not None
    assert inputs.compatibility.control_id == "7.1.1"
    assert inputs.compatibility.result is CompatibilityDecision.REVIEW_REQUIRED
    assert inputs.compatibility.provisional is True
    assert inputs.compatibility.report_sha256 == hashlib.sha256(
        report_path.read_bytes()
    ).hexdigest()
    assert not (tmp_path / "controls").exists()


def test_loader_rejects_m4_report_without_selected_control(tmp_path: Path) -> None:
    manifest = _copy_minimal_m2(tmp_path)
    raw = _m4_report().model_dump(mode="json")
    raw["control_results"][0]["control_id"] = "7.1.5"
    raw["control_results"][0]["evidence_used"][0]["requested_by"] = ["7.1.5"]
    raw["control_results"][0]["missing_or_contextual_evidence"][0][
        "requested_by"
    ] = ["7.1.5"]
    report_path = tmp_path / "wrong-control.yaml"
    report_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="no result for control 7.1.1"):
        load_validation_inputs(
            "7.1.1", compatibility_report=report_path, manifest_path=manifest
        )


@pytest.mark.parametrize(
    ("sandbox_ack", "admin_ack", "identity", "compatibility_present", "fragment"),
    [
        (False, True, _identity(), True, "sandbox operator acknowledgement"),
        (True, False, _identity(), True, "administrator approval"),
        (True, True, _identity(uid=1000), True, "effective UID 0"),
        (True, True, _identity(supported=False), True, "not supported Ubuntu 24.04"),
        (True, True, _identity(), False, "explicit M4 compatibility result"),
    ],
)
def test_precheck_fails_closed_for_each_required_execution_gate(
    sandbox_ack: bool,
    admin_ack: bool,
    identity: SandboxIdentity,
    compatibility_present: bool,
    fragment: str,
) -> None:
    compatibility = None
    if compatibility_present:
        report = _m4_report()
        result = report.control_results[0]
        from src.sandbox_validator.models import CompatibilityReference

        compatibility = CompatibilityReference(
            control_id="7.1.1",
            report_source="fixture-m4.yaml",
            report_sha256="a" * 64,
            report_version="1",
            report_generated_at=report.generated_at,
            profile_source=report.profile_source,
            profile_collected_at=report.profile_collected_at,
            profile_target=report.target,
            result=result.result,
            provisional=result.provisional,
            metadata_review_status=result.metadata_review_status,
            explanation=result.explanation,
        )

    precheck = build_precheck(
        control_id="7.1.1",
        control_title="Ensure permissions on /etc/passwd are configured",
        identity=identity,
        mutation_requested=True,
        mutation_supported=True,
        sandbox_operator_acknowledged=sandbox_ack,
        administrator_approval_acknowledged=admin_ack,
        compatibility_risk_acknowledged=True,
        compatibility_override_reason=None,
        compatibility=compatibility,
    )

    assert precheck.can_mutate is False
    assert any(fragment in blocker for blocker in precheck.blockers)
    assert not hasattr(precheck, "sandbox_verified")


def test_identity_records_architecture_and_rejects_wrong_ubuntu_version(
    tmp_path: Path,
) -> None:
    os_release = tmp_path / "etc" / "os-release"
    os_release.parent.mkdir(parents=True)
    os_release.write_text(
        'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\n', encoding="utf-8"
    )

    identity = inspect_sandbox_identity(
        tmp_path,
        hostname="fixture",
        kernel="fixture-kernel",
        architecture="aarch64",
        system_name="Linux",
        effective_uid=0,
    )

    assert identity.architecture == "aarch64"
    assert identity.architecture_supported is True
    assert identity.supported is False
    assert identity.reason == "unsupported_ubuntu_version"


def test_unavailable_evidence_survives_safe_yaml_round_trip() -> None:
    evidence = AuditEvidence(
        name="ufw_status",
        status=EvidenceStatus.UNAVAILABLE,
        value=None,
        source="command:ufw_status",
        reason="permission_denied",
    )
    rendered = yaml.safe_dump(evidence.model_dump(mode="json"), sort_keys=False)

    parsed = AuditEvidence.model_validate(yaml.safe_load(rendered))

    assert parsed.status is EvidenceStatus.UNAVAILABLE
    assert parsed.value is None
    assert parsed.reason == "permission_denied"


def test_cli_rejects_output_equal_to_m4_input_before_loading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report_directory = tmp_path / "data" / "sandbox"
    report_directory.mkdir(parents=True)
    monkeypatch.setattr(cli, "REPORT_OUTPUT_DIRECTORY", report_directory)
    report_path = report_directory / "compatibility.yaml"
    report_path.write_text("sentinel\n", encoding="utf-8")

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("protected-output rejection reached input loading")

    monkeypatch.setattr(cli, "load_validation_inputs", fail)
    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "--control",
                "7.1.1",
                "--plan",
                "--compatibility-report",
                str(report_path),
                "--output",
                str(report_path),
                "--overwrite",
            ]
        )

    assert raised.value.code == 2
    assert "must not overwrite" in capsys.readouterr().err
    assert report_path.read_text(encoding="utf-8") == "sentinel\n"
