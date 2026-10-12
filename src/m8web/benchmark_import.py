"""Bounded, text-based identity gate for the one supported research benchmark.

This is a scope check, not a claim that an uploaded PDF is publisher-signed.
M1 remains the converter; no CIS command text is executed or persisted here.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

import pymupdf

from src.cli import convert
from src.models import ControlDocument
from src.poc_models import load_yaml_model, validate_poc_dataset
from src.yaml_writer import control_filename


MAX_BENCHMARK_PDF_BYTES = 32 * 1024 * 1024
_MANIFEST = Path(__file__).resolve().parents[2] / "data/poc/poc_controls.yaml"


@dataclass(frozen=True, slots=True)
class BenchmarkIdentity:
    supported: bool
    source_sha256: str
    reason: str


class BenchmarkImportError(ValueError):
    """Upload or conversion did not satisfy the supported research scope."""


def validate_supported_benchmark_pdf(content: bytes) -> BenchmarkIdentity:
    if not isinstance(content, bytes) or len(content) > MAX_BENCHMARK_PDF_BYTES:
        raise BenchmarkImportError("PDF upload size is invalid")
    if len(content) < 1024 or not content.startswith(b"%PDF-"):
        raise BenchmarkImportError("input is not a readable PDF")
    digest = hashlib.sha256(content).hexdigest()
    try:
        with pymupdf.open(stream=content, filetype="pdf") as document:
            if document.needs_pass or not 20 <= document.page_count <= 1500:
                raise BenchmarkImportError("PDF structure is unsupported")
            cover = document[0].get_text("text")[:8192]
            technology = " ".join(
                document[index].get_text("text")[:16384]
                for index in range(10, min(18, document.page_count))
            )
    except BenchmarkImportError:
        raise
    except (RuntimeError, ValueError, OSError) as error:
        raise BenchmarkImportError("input is not a readable PDF") from error
    normalized_cover = " ".join(cover.split()).lower()
    normalized_technology = " ".join(technology.split()).lower()
    supported = (
        "cis ubuntu linux 24.04 lts benchmark" in normalized_cover
        and "v1.0.0" in normalized_cover
        and "08-26-2024" in normalized_cover
        and "target technology details" in normalized_technology
        and "ubuntu linux 24.04 lts systems" in normalized_technology
    )
    return BenchmarkIdentity(
        supported=supported,
        source_sha256=digest,
        reason="supported_text_identity" if supported else "unsupported_text_identity",
    )


def convert_supported_benchmark(content: bytes) -> tuple[BenchmarkIdentity, list[dict]]:
    """Run M1 only after identity validation; return only selected PoC metadata."""
    identity = validate_supported_benchmark_pdf(content)
    if not identity.supported:
        raise BenchmarkImportError("PDF is outside the supported benchmark scope")
    dataset = validate_poc_dataset(_MANIFEST)
    with TemporaryDirectory(prefix="sentra-benchmark-") as temporary:
        root = Path(temporary)
        pdf = root / "source.pdf"  # Never derived from the uploaded filename.
        pdf.write_bytes(content)
        catalog = convert(pdf, root / "converted", None)
        if (catalog.benchmark.name != dataset.manifest.benchmark.name
                or catalog.benchmark.version != dataset.manifest.benchmark.version):
            raise BenchmarkImportError("M1 output identity does not match M2")
        entries = {entry.id: entry for entry in catalog.controls if entry.generated}
        controls: list[dict] = []
        for enrichment in dataset.enrichments:
            entry = entries.get(enrichment.control_id)
            if entry is None:
                raise BenchmarkImportError("M1 did not extract a selected control")
            document = load_yaml_model(
                root / "converted" / "controls" / control_filename(entry.id),
                ControlDocument,
            )
            if (document.control.id != entry.id
                    or document.benchmark != catalog.benchmark):
                raise BenchmarkImportError("M1 selected-control lineage is invalid")
            capability = {
                "7.1.1": "full",
                "5.1.20": "conditional",
                "4.2.3": "audit_plan_only",
            }.get(entry.id, "not_supported")
            controls.append({
                "control_id": entry.id,
                "title": document.control.title,
                "description": document.control.description or "",
                "profile_level": ", ".join(document.control.profile_applicability),
                "assessment_type": document.control.assessment_status,
                "required_facts": enrichment.sentra.required_target_facts,
                "adapter_capability": capability,
                "review_state": enrichment.sentra.evidence.derivation_status.value,
                "metadata": {
                    "source_sha256": identity.source_sha256,
                    "source_pages": document.source.model_dump(mode="json"),
                    "sentra_category": enrichment.sentra.category.value,
                },
            })
    return identity, controls
