"""Load inert M2/M3/M4 inputs without reading or executing CIS command text."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from src.compatibility_engine.loaders import DEFAULT_MANIFEST_PATH
from src.compatibility_engine.models import CompatibilityReport
from src.poc_models import (
    EnrichmentDocument,
    PocManifest,
    enrichment_filename,
    load_yaml_model,
)
from src.target_profiler.models import TargetProfile

from .models import CompatibilityReference


_CONTROL_ID = re.compile(r"^\d+(?:\.\d+){2,}$")
_ADAPTER_TITLES = {
    "3.3.1": "Ensure ip forwarding is disabled",
    "7.1.1": "Ensure permissions on /etc/passwd are configured",
    "5.1.20": "Ensure sshd PermitRootLogin is disabled",
    "4.2.3": "Ensure ufw service is enabled",
}


@dataclass(frozen=True, slots=True)
class ValidationInputs:
    control_id: str
    control_title: str
    manifest_path: Path
    enrichment_path: Path | None
    enrichment: EnrichmentDocument | None
    m3_profile_path: Path | None
    m3_profile_source: str | None
    m3_profile: TargetProfile | None
    m4_report_path: Path | None
    compatibility: CompatibilityReference | None


def _load_mapping(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        raw: Any = yaml.safe_load(stream)
    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping in {path}")
    return raw


def _load_selected_metadata(
    control_id: str, manifest_path: Path
) -> tuple[Path | None, EnrichmentDocument | None]:
    manifest = load_yaml_model(manifest_path, PocManifest)
    selected = next(
        (item for item in manifest.poc.controls if item.id == control_id), None
    )
    if selected is None:
        return None, None
    path = manifest_path.parent / "enriched" / enrichment_filename(control_id)
    enrichment = load_yaml_model(path, EnrichmentDocument)
    if enrichment.control_id != control_id:
        raise ValueError("M2 enrichment does not match the selected control")
    if enrichment.sentra.category != selected.category:
        raise ValueError("M2 manifest and enrichment categories do not match")
    return path, enrichment


def _load_m4_reference(path: Path, control_id: str) -> CompatibilityReference:
    raw_bytes = path.read_bytes()
    raw: Any = yaml.safe_load(raw_bytes)
    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping in {path}")
    report = CompatibilityReport.model_validate(raw)
    selected = next(
        (item for item in report.control_results if item.control_id == control_id),
        None,
    )
    if selected is None:
        raise ValueError(f"M4 report has no result for control {control_id}")
    return CompatibilityReference(
        control_id=control_id,
        report_source=path.as_posix(),
        report_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        report_version=report.report_version,
        report_generated_at=report.generated_at,
        profile_source=report.profile_source,
        profile_collected_at=report.profile_collected_at,
        profile_target=report.target,
        result=selected.result,
        provisional=selected.provisional,
        metadata_review_status=selected.metadata_review_status,
        explanation=selected.explanation,
    )


def load_validation_inputs(
    control_id: str,
    *,
    compatibility_report: str | Path | None = None,
    target_profile: str | Path | None = None,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> ValidationInputs:
    """Load only structured milestone inputs; CIS source records remain untouched."""

    if _CONTROL_ID.fullmatch(control_id) is None:
        raise ValueError(f"Invalid control ID: {control_id}")
    manifest = Path(manifest_path).resolve()
    enrichment_path, enrichment = _load_selected_metadata(control_id, manifest)

    profile_path: Path | None = None
    profile_source: str | None = None
    profile: TargetProfile | None = None
    if target_profile is not None:
        profile_source = Path(target_profile).as_posix()
        profile_path = Path(target_profile).resolve()
        profile = TargetProfile.model_validate(_load_mapping(profile_path))

    report_path: Path | None = None
    compatibility: CompatibilityReference | None = None
    if compatibility_report is not None:
        report_path = Path(compatibility_report).resolve()
        compatibility = _load_m4_reference(report_path, control_id)
        if profile is not None:
            if profile.collected_at != compatibility.profile_collected_at:
                raise ValueError("M3 profile and M4 report collection timestamps differ")
            if profile.target != compatibility.profile_target:
                raise ValueError("M3 profile and M4 report targets differ")

    return ValidationInputs(
        control_id=control_id,
        control_title=_ADAPTER_TITLES.get(
            control_id, f"Unsupported M5 control {control_id}"
        ),
        manifest_path=manifest,
        enrichment_path=enrichment_path,
        enrichment=enrichment,
        m3_profile_path=profile_path,
        m3_profile_source=profile_source,
        m3_profile=profile,
        m4_report_path=report_path,
        compatibility=compatibility,
    )


__all__ = ["ValidationInputs", "load_validation_inputs"]
