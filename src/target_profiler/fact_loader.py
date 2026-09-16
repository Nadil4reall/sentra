"""Load target facts requested by the Milestone 2 enrichment dataset.

Only manifest and enrichment metadata are parsed. CIS Audit and Remediation
fields are neither loaded nor executed by this module.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from src.poc_models import enrichment_filename
from src.target_profiler.models import RequiredFact


EXPECTED_ENRICHMENT_COUNT = 10
DEFAULT_MANIFEST_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "poc" / "poc_controls.yaml"
)


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        raw: Any = yaml.safe_load(stream)
    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping in {path}")
    return raw


def _manifest_control_ids(manifest_path: Path) -> tuple[str, ...]:
    manifest = _load_yaml_mapping(manifest_path)
    poc = manifest.get("poc")
    if not isinstance(poc, dict):
        raise ValueError(f"Missing poc mapping in {manifest_path}")
    controls = poc.get("controls")
    if not isinstance(controls, list):
        raise ValueError(f"Missing poc.controls list in {manifest_path}")

    control_ids: list[str] = []
    for index, item in enumerate(controls):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError(f"Invalid poc.controls[{index}] in {manifest_path}")
        control_ids.append(item["id"])

    declared_count = poc.get("total_controls")
    if declared_count != len(control_ids):
        raise ValueError("poc.total_controls must match the controls list length")
    if len(control_ids) != EXPECTED_ENRICHMENT_COUNT:
        raise ValueError(
            f"Milestone 3 expects {EXPECTED_ENRICHMENT_COUNT} enrichments; "
            f"found {len(control_ids)}"
        )
    if len(control_ids) != len(set(control_ids)):
        raise ValueError("PoC control IDs must be unique")
    return tuple(control_ids)


def _enrichment_fact_names(path: Path, expected_control_id: str) -> tuple[str, ...]:
    enrichment = _load_yaml_mapping(path)
    if enrichment.get("control_id") != expected_control_id:
        raise ValueError(
            f"Manifest/enrichment ID mismatch for {expected_control_id}: "
            f"found {enrichment.get('control_id')!r}"
        )

    sentra = enrichment.get("sentra")
    if not isinstance(sentra, dict):
        raise ValueError(f"Missing sentra mapping in {path}")
    raw_facts = sentra.get("required_target_facts")
    if not isinstance(raw_facts, list):
        raise ValueError(f"Missing sentra.required_target_facts list in {path}")

    facts: list[str] = []
    for index, fact_name in enumerate(raw_facts):
        if not isinstance(fact_name, str) or not fact_name.strip():
            raise ValueError(
                f"Invalid sentra.required_target_facts[{index}] in {path}"
            )
        if fact_name != fact_name.strip():
            raise ValueError(f"Fact names may not have surrounding whitespace in {path}")
        facts.append(fact_name)
    return tuple(facts)


def load_required_facts(
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> tuple[RequiredFact, ...]:
    """Return deduplicated facts in first-seen order with control provenance.

    Manifest order determines enrichment traversal, fact order follows each
    enrichment's ``required_target_facts`` list, and repeated facts retain the
    ordered IDs of every requesting control.
    """

    path = Path(manifest_path).resolve()
    control_ids = _manifest_control_ids(path)
    enrichment_directory = path.parent / "enriched"

    requesters_by_fact: dict[str, list[str]] = {}
    for control_id in control_ids:
        enrichment_path = enrichment_directory / enrichment_filename(control_id)
        if not enrichment_path.is_file():
            raise FileNotFoundError(f"Missing enrichment file: {enrichment_path}")
        for fact_name in _enrichment_fact_names(enrichment_path, control_id):
            requesters = requesters_by_fact.setdefault(fact_name, [])
            if control_id not in requesters:
                requesters.append(control_id)

    return tuple(
        RequiredFact(name=name, requested_by=requesters)
        for name, requesters in requesters_by_fact.items()
    )
