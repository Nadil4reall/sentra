"""Validated output models for the Milestone 1 control catalog."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Base model that rejects accidental, undocumented output fields."""

    model_config = ConfigDict(extra="forbid")


class BenchmarkMetadata(StrictModel):
    name: str
    version: str
    release_date: str
    platform: str


class CISControlMapping(StrictModel):
    version: str
    control_id: str
    title: str
    description: str | None = None
    implementation_groups: list[str] = Field(default_factory=list)


class MitreAttackMappings(StrictModel):
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)


class ControlData(StrictModel):
    id: str
    title: str
    assessment_status: Literal["Automated", "Manual"]
    profile_applicability: list[str] = Field(default_factory=list)
    description: str | None = None
    rationale: str | None = None
    impact: str | None = None
    audit: str | None = None
    remediation: str | None = None
    default_value: str | None = None
    references: list[str] = Field(default_factory=list)
    additional_information: str | None = None
    cis_controls: list[CISControlMapping] = Field(default_factory=list)
    mitre_attack: MitreAttackMappings = Field(default_factory=MitreAttackMappings)


class SourceLocation(StrictModel):
    pdf_page_start: int
    pdf_page_end: int
    benchmark_page_start: int | None = None
    benchmark_page_end: int | None = None


class Verification(StrictModel):
    status: Literal["unverified"] = "unverified"
    code_integrity: Literal["needs_review"] = "needs_review"


class ControlDocument(StrictModel):
    benchmark: BenchmarkMetadata
    control: ControlData
    source: SourceLocation
    verification: Verification = Field(default_factory=Verification)
    raw_source_text: str


class CatalogEntry(StrictModel):
    id: str
    title: str
    assessment_status: Literal["Automated", "Manual"]
    source: SourceLocation
    generated: bool
    output_file: str | None = None


class Catalog(StrictModel):
    benchmark: BenchmarkMetadata
    source_pdf: str
    detected_recommendations: int
    generated_recommendations: int
    controls: list[CatalogEntry] = Field(default_factory=list)


def benchmark_metadata() -> BenchmarkMetadata:
    """Return the fixed metadata for the official Milestone 1 benchmark."""

    return BenchmarkMetadata(
        name="CIS Ubuntu Linux 24.04 LTS Benchmark",
        version="1.0.0",
        release_date="2024-08-26",
        platform="Ubuntu Linux 24.04 LTS",
    )

