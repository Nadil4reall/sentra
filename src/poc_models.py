"""Milestone 2 models and read-only cross-file validation.

The utilities in this module parse metadata only. They never import, evaluate, or
execute Audit or Remediation content from the CIS-derived control files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, TypeVar

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


CONTROL_ID_RE = re.compile(r"^\d+(?:\.\d+){2,}$")
EXPECTED_POC_CONTROL_COUNT = 10


class StrictPocModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Category(StrEnum):
    KERNEL = "kernel"
    NETWORK = "network"
    FIREWALL = "firewall"
    SSH = "ssh"
    AUDITING = "auditing"
    FILE_PERMISSIONS = "file_permissions"


class DerivationStatus(StrEnum):
    NEEDS_REVIEW = "needs_review"
    REVIEWED = "reviewed"


class SandboxMetadata(StrictPocModel):
    required: bool
    service_health_checks: list[str]


class ValidationMetadata(StrictPocModel):
    pre_audit_required: bool
    post_audit_required: bool
    service_check_required: bool


class DeploymentMetadata(StrictPocModel):
    administrator_approval_required: bool


class EvidenceMetadata(StrictPocModel):
    source_control: str = Field(min_length=1)
    derivation_status: DerivationStatus
    notes: list[str]


class SentraMetadata(StrictPocModel):
    category: Category
    affected_services: list[str]
    affected_files: list[str]
    affected_packages: list[str]
    required_target_facts: list[str]
    prerequisites: list[str]
    possible_conflicts: list[str]
    sandbox: SandboxMetadata
    validation: ValidationMetadata
    deployment: DeploymentMetadata
    evidence: EvidenceMetadata

    @model_validator(mode="after")
    def validate_internal_references(self) -> "SentraMetadata":
        unknown_health_checks = set(self.sandbox.service_health_checks) - set(
            self.affected_services
        )
        if unknown_health_checks:
            raise ValueError(
                "service health checks must also appear in affected_services: "
                f"{sorted(unknown_health_checks)}"
            )
        return self


class EnrichmentDocument(StrictPocModel):
    control_id: str = Field(pattern=r"^\d+(?:\.\d+){2,}$")
    sentra: SentraMetadata


class PocBenchmark(StrictPocModel):
    name: Literal["CIS Ubuntu Linux 24.04 LTS Benchmark"]
    version: Literal["1.0.0"]


class PocManifestControl(StrictPocModel):
    id: str = Field(pattern=r"^\d+(?:\.\d+){2,}$")
    category: Category


class PocSelection(StrictPocModel):
    total_controls: int = Field(ge=1)
    controls: list[PocManifestControl]

    @model_validator(mode="after")
    def validate_count_and_unique_ids(self) -> "PocSelection":
        if self.total_controls != len(self.controls):
            raise ValueError("poc.total_controls must match the controls list length")
        ids = [control.id for control in self.controls]
        if len(ids) != len(set(ids)):
            raise ValueError("PoC control IDs must be unique")
        return self


class PocManifest(StrictPocModel):
    benchmark: PocBenchmark
    poc: PocSelection


@dataclass(frozen=True)
class PocDataset:
    manifest_path: Path
    manifest: PocManifest
    enrichments: tuple[EnrichmentDocument, ...]


ModelType = TypeVar("ModelType", bound=BaseModel)


def load_yaml_model(path: Path, model: type[ModelType]) -> ModelType:
    """Safely load a YAML mapping into a strict Pydantic model."""

    with path.open("r", encoding="utf-8") as stream:
        raw: Any = yaml.safe_load(stream)
    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping in {path}")
    return model.model_validate(raw)


def enrichment_filename(control_id: str) -> str:
    if not CONTROL_ID_RE.fullmatch(control_id):
        raise ValueError(f"Invalid control ID: {control_id}")
    return control_id.replace(".", "_") + ".yaml"


def validate_poc_dataset(manifest_path: str | Path) -> PocDataset:
    """Validate manifest, sources, enrichments, IDs, categories, and evidence paths."""

    path = Path(manifest_path).resolve()
    manifest = load_yaml_model(path, PocManifest)
    if manifest.poc.total_controls != EXPECTED_POC_CONTROL_COUNT:
        raise ValueError(
            f"Milestone 2 requires exactly {EXPECTED_POC_CONTROL_COUNT} controls; "
            f"found {manifest.poc.total_controls}"
        )

    repository_root = path.parents[2]
    source_directory = (repository_root / "data" / "controls").resolve()
    enrichments: list[EnrichmentDocument] = []
    for entry in manifest.poc.controls:
        source_path = source_directory / enrichment_filename(entry.id)
        if not source_path.is_file():
            raise FileNotFoundError(f"Missing CIS source control: {source_path}")

        # Read only the source identity. Audit and Remediation values remain inert data.
        with source_path.open("r", encoding="utf-8") as stream:
            source_data = yaml.safe_load(stream)
        source_id = source_data.get("control", {}).get("id") if isinstance(source_data, dict) else None
        if source_id != entry.id:
            raise ValueError(
                f"Manifest/source ID mismatch for {entry.id}: source contains {source_id!r}"
            )

        enrichment_path = path.parent / "enriched" / enrichment_filename(entry.id)
        if not enrichment_path.is_file():
            raise FileNotFoundError(f"Missing enrichment file: {enrichment_path}")
        enrichment = load_yaml_model(enrichment_path, EnrichmentDocument)
        if enrichment.control_id != entry.id:
            raise ValueError(
                f"Manifest/enrichment ID mismatch: {entry.id} != {enrichment.control_id}"
            )
        if enrichment.sentra.category != entry.category:
            raise ValueError(f"Category mismatch for control {entry.id}")

        evidence_path = (repository_root / enrichment.sentra.evidence.source_control).resolve()
        if evidence_path != source_path:
            raise ValueError(f"Evidence source mismatch for control {entry.id}")
        enrichments.append(enrichment)

    return PocDataset(path, manifest, tuple(enrichments))
