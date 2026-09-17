"""Read and cross-validate Milestone 2 metadata and Milestone 3 profiles."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from src.poc_models import (
    EXPECTED_POC_CONTROL_COUNT,
    EnrichmentDocument,
    PocManifest,
    enrichment_filename,
    load_yaml_model,
)
from src.target_profiler.models import TargetProfile


DEFAULT_MANIFEST_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "poc" / "poc_controls.yaml"
)


@dataclass(frozen=True)
class CompatibilityInputs:
    """Validated structured inputs for one compatibility evaluation."""

    manifest_path: Path
    profile_path: Path
    profile_source: str
    manifest: PocManifest
    enrichments: tuple[EnrichmentDocument, ...]
    profile: TargetProfile


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        raw: Any = yaml.safe_load(stream)
    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping in {path}")
    return raw


def _load_m2_inputs(
    manifest_path: Path,
) -> tuple[PocManifest, tuple[EnrichmentDocument, ...]]:
    """Load only the PoC manifest and enrichments, never CIS command content."""

    manifest = load_yaml_model(manifest_path, PocManifest)
    if manifest.poc.total_controls != EXPECTED_POC_CONTROL_COUNT:
        raise ValueError(
            f"Milestone 4 expects {EXPECTED_POC_CONTROL_COUNT} selected controls; "
            f"found {manifest.poc.total_controls}"
        )

    enrichments: list[EnrichmentDocument] = []
    for selected in manifest.poc.controls:
        path = (
            manifest_path.parent
            / "enriched"
            / enrichment_filename(selected.id)
        )
        if not path.is_file():
            raise FileNotFoundError(f"Missing enrichment file: {path}")
        enrichment = load_yaml_model(path, EnrichmentDocument)
        if enrichment.control_id != selected.id:
            raise ValueError(
                "Manifest/enrichment ID mismatch: "
                f"{selected.id} != {enrichment.control_id}"
            )
        if enrichment.sentra.category != selected.category:
            raise ValueError(f"Category mismatch for control {selected.id}")
        facts = enrichment.sentra.required_target_facts
        if not facts:
            raise ValueError(f"Control {selected.id} has no required target facts")
        if len(facts) != len(set(facts)):
            raise ValueError(
                f"Control {selected.id} contains duplicate required target facts"
            )
        enrichments.append(enrichment)
    return manifest, tuple(enrichments)


def _validate_profile_relationships(
    enrichments: tuple[EnrichmentDocument, ...], profile: TargetProfile
) -> None:
    expected_requesters: dict[str, list[str]] = {}
    for enrichment in enrichments:
        for fact_name in enrichment.sentra.required_target_facts:
            requesters = expected_requesters.setdefault(fact_name, [])
            requesters.append(enrichment.control_id)

    expected_names = set(expected_requesters)
    actual_names = set(profile.facts)
    missing = sorted(expected_names - actual_names)
    unexpected = sorted(actual_names - expected_names)
    if missing or unexpected:
        raise ValueError(
            "Profile facts do not match the current PoC enrichments; "
            f"missing={missing}, unexpected={unexpected}"
        )

    for fact_name, expected in expected_requesters.items():
        actual = profile.facts[fact_name].requested_by
        if actual != expected:
            raise ValueError(
                f"Profile requested_by mismatch for {fact_name}: "
                f"expected {expected}, found {actual}"
            )


def load_compatibility_inputs(
    profile_path: str | Path,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> CompatibilityInputs:
    """Load supplied structured data without profiling or changing the target."""

    raw_profile_path = Path(profile_path)
    resolved_profile_path = raw_profile_path.resolve()
    resolved_manifest_path = Path(manifest_path).resolve()
    manifest, enrichments = _load_m2_inputs(resolved_manifest_path)
    profile = TargetProfile.model_validate(
        _load_yaml_mapping(resolved_profile_path)
    )

    if not profile.target.supported:
        raise ValueError(
            "Milestone 4 requires a supported Ubuntu 24.04 target profile"
        )

    _validate_profile_relationships(enrichments, profile)

    return CompatibilityInputs(
        manifest_path=resolved_manifest_path,
        profile_path=resolved_profile_path,
        profile_source=raw_profile_path.as_posix(),
        manifest=manifest,
        enrichments=enrichments,
        profile=profile,
    )
