from __future__ import annotations

import copy
import hashlib
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from src import poc_summary
from src.poc_models import (
    Category,
    DerivationStatus,
    EnrichmentDocument,
    enrichment_filename,
    validate_poc_dataset,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "data" / "poc" / "poc_controls.yaml"
EXPECTED_IDS = (
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
SOURCE_SHA256 = {
    "1.1.1.1": "d58fe0fb45f0eb39a1018f0526fd053605f4e2a73e3ba7a1721c59d8b32a83c5",
    "1.1.1.6": "c65e89df80e515636a23ec40b561512b905c8056bcd8da3fd1e7ef01ff0e1c6e",
    "3.3.1": "8e9c46fb200b731544bc128ce3b7444c21c75271b6a58b192618a966b2614868",
    "4.2.1": "fb00b8b9e7cddbe8f93c0e75e9afa1206faa00c11e64ffa5b1e4ec1d68613be1",
    "4.2.3": "c7851d022620273d39e1948a6587681990c395b6557c9aaeb281e29acf0f8c91",
    "5.1.19": "fe3c06f0fb8eae5e5a1f89970977d95b669caa51eb1da4f8f4926c36f1b6cb14",
    "5.1.20": "caf4e79dfa84d6d4cb2de0670a59bed6d15f8f0493591bb651729ad428f4001a",
    "6.2.1.2": "01f07dcd2f1aeb33a7ce511f58a576c148ccb4991b2ca244269ed998a8838323",
    "7.1.1": "ede5a41ea95e41893befeaffb07cb01ff76067123f5f31533c07b1f86c98eea9",
    "7.1.5": "071d807d57ca70c3bc1e2d1d01b70d3993eea29ded98ac26ab741f11978140b6",
}


@pytest.fixture(scope="module")
def dataset():
    return validate_poc_dataset(MANIFEST_PATH)


def load_enrichment_mapping(control_id: str) -> dict:
    path = MANIFEST_PATH.parent / "enriched" / enrichment_filename(control_id)
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def source_path(control_id: str) -> Path:
    return ROOT / "data" / "controls" / enrichment_filename(control_id)


def test_exactly_ten_poc_controls_are_selected(dataset) -> None:
    assert dataset.manifest.poc.total_controls == 10
    assert tuple(control.id for control in dataset.manifest.poc.controls) == EXPECTED_IDS


def test_every_selected_control_exists_in_cis_source_data(dataset) -> None:
    for control in dataset.manifest.poc.controls:
        assert source_path(control.id).is_file()


def test_every_selected_control_has_an_enrichment_file(dataset) -> None:
    enrichment_directory = MANIFEST_PATH.parent / "enriched"
    expected = {enrichment_filename(control_id) for control_id in EXPECTED_IDS}
    actual = {path.name for path in enrichment_directory.glob("*.yaml")}
    assert actual == expected


def test_manifest_source_and_enrichment_ids_match(dataset) -> None:
    for manifest_entry, enrichment in zip(
        dataset.manifest.poc.controls, dataset.enrichments, strict=True
    ):
        assert manifest_entry.id == enrichment.control_id
        source = yaml.safe_load(source_path(manifest_entry.id).read_text(encoding="utf-8"))
        assert source["control"]["id"] == enrichment.control_id


def test_categories_are_from_the_allowed_values(dataset) -> None:
    allowed = {category.value for category in Category}
    assert {item.sentra.category.value for item in dataset.enrichments} <= allowed

    invalid = copy.deepcopy(load_enrichment_mapping("5.1.20"))
    invalid["sentra"]["category"] = "remote_access"
    with pytest.raises(ValidationError):
        EnrichmentDocument.model_validate(invalid)


def test_derivation_status_has_only_allowed_values(dataset) -> None:
    allowed = {status.value for status in DerivationStatus}
    assert {
        item.sentra.evidence.derivation_status.value for item in dataset.enrichments
    } <= allowed

    invalid = copy.deepcopy(load_enrichment_mapping("5.1.20"))
    invalid["sentra"]["evidence"]["derivation_status"] = "verified"
    with pytest.raises(ValidationError):
        EnrichmentDocument.model_validate(invalid)


def test_no_enrichment_is_automatically_marked_reviewed(dataset) -> None:
    assert all(
        item.sentra.evidence.derivation_status == DerivationStatus.NEEDS_REVIEW
        for item in dataset.enrichments
    )


def test_required_safety_gates_are_enabled(dataset) -> None:
    for enrichment in dataset.enrichments:
        assert enrichment.sentra.sandbox.required is True
        assert enrichment.sentra.validation.pre_audit_required is True
        assert enrichment.sentra.validation.post_audit_required is True
        assert enrichment.sentra.deployment.administrator_approval_required is True
        assert "Requires manual enrichment review" in enrichment.sentra.evidence.notes


def test_original_cis_yaml_files_remain_byte_for_byte_unchanged(dataset) -> None:
    for entry in dataset.manifest.poc.controls:
        digest = hashlib.sha256(source_path(entry.id).read_bytes()).hexdigest()
        assert digest == SOURCE_SHA256[entry.id]


def test_summary_never_invokes_process_execution(monkeypatch, capsys) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("The read-only PoC summary attempted process execution")

    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(subprocess, "call", fail)
    monkeypatch.setattr(subprocess, "check_call", fail)
    monkeypatch.setattr(subprocess, "check_output", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)

    assert poc_summary.main(["--manifest", str(MANIFEST_PATH)]) == 0
    output = capsys.readouterr().out
    assert output.startswith("SENTRA PoC Control Set\n")
    assert "Selected controls: 10" in output
    assert "Kernel:             2" in output
    assert "Network:            1" in output
    assert "Firewall:           2" in output
    assert "SSH:                2" in output
    assert "Auditing:           1" in output
    assert "File Permissions:   2" in output
    assert "Needs review: 10" in output
    assert output.rstrip().endswith("Controls executed: 0")


def test_overlayfs_compatibility_risk_is_represented_but_not_executed(dataset) -> None:
    overlayfs = next(item for item in dataset.enrichments if item.control_id == "1.1.1.6")
    assert "container_applications_in_use" in overlayfs.sentra.required_target_facts
    assert any(
        "compatibility warning" in conflict
        and "severely disrupt containerization" in conflict
        for conflict in overlayfs.sentra.possible_conflicts
    )
    assert overlayfs.sentra.evidence.derivation_status == DerivationStatus.NEEDS_REVIEW


def test_enrichment_requires_all_explicit_list_fields() -> None:
    invalid = copy.deepcopy(load_enrichment_mapping("5.1.20"))
    del invalid["sentra"]["affected_packages"]
    with pytest.raises(ValidationError):
        EnrichmentDocument.model_validate(invalid)


def test_expected_category_distribution(dataset) -> None:
    counts = {
        category: sum(item.sentra.category == category for item in dataset.enrichments)
        for category in Category
    }
    assert counts == {
        Category.KERNEL: 2,
        Category.NETWORK: 1,
        Category.FIREWALL: 2,
        Category.SSH: 2,
        Category.AUDITING: 1,
        Category.FILE_PERMISSIONS: 2,
    }
