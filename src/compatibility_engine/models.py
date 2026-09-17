"""Strict schemas for Milestone 4 compatibility analysis and reports."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from src.poc_models import Category, DerivationStatus
from src.target_profiler.models import FactStatus, TargetInfo


class StrictCompatibilityModel(BaseModel):
    """Reject undocumented fields at the Milestone 4 data boundary."""

    model_config = ConfigDict(extra="forbid")


class CompatibilityDecision(StrEnum):
    """Compatibility/readiness states; deliberately not compliance verdicts."""

    NO_KNOWN_CONFLICT = "no_known_conflict"
    WARNING = "warning"
    REVIEW_REQUIRED = "review_required"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class EvidenceRecord(StrictCompatibilityModel):
    """One target fact as used by a compatibility decision."""

    fact: str = Field(pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
    status: FactStatus
    value: JsonValue | None = None
    requested_by: list[str] = Field(min_length=1)
    reason: str | None = None

    @model_validator(mode="after")
    def validate_state(self) -> "EvidenceRecord":
        if self.status is FactStatus.COLLECTED:
            if self.value is None:
                raise ValueError("collected evidence must have a non-null value")
            if self.reason is not None:
                raise ValueError("collected evidence must not include a reason")
        else:
            if self.value is not None:
                raise ValueError("non-collected evidence must retain a null value")
            if not self.reason or not self.reason.strip():
                raise ValueError("non-collected evidence must retain its reason")
        if len(self.requested_by) != len(set(self.requested_by)):
            raise ValueError("evidence requested_by values must be unique")
        return self


class TriggeredRule(StrictCompatibilityModel):
    """An auditable rule finding attached to a control decision."""

    rule_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    result: CompatibilityDecision
    explanation: str = Field(min_length=1)
    source_basis: list[str] = Field(min_length=1)
    evidence_facts: list[str] = Field(min_length=1)


class RuleDescription(StrictCompatibilityModel):
    """Stable public description of one deterministic rule."""

    rule_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    control_id: str = Field(pattern=r"^\d+(?:\.\d+){2,}$")
    purpose: str = Field(min_length=1)
    source_basis: list[str] = Field(min_length=1)
    evidence_facts: list[str] = Field(min_length=1)


class ControlCompatibilityResult(StrictCompatibilityModel):
    """Traceable compatibility result for one selected PoC control."""

    control_id: str = Field(pattern=r"^\d+(?:\.\d+){2,}$")
    category: Category
    result: CompatibilityDecision
    provisional: bool
    metadata_review_status: DerivationStatus
    evidence_used: list[EvidenceRecord] = Field(min_length=1)
    triggered_rules: list[TriggeredRule]
    missing_or_contextual_evidence: list[EvidenceRecord]
    explanation: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_provisional_and_evidence(self) -> "ControlCompatibilityResult":
        expected_provisional = (
            self.metadata_review_status is DerivationStatus.NEEDS_REVIEW
        )
        if self.provisional != expected_provisional:
            raise ValueError(
                "provisional must reflect the enrichment derivation status"
            )

        evidence_names = [item.fact for item in self.evidence_used]
        if len(evidence_names) != len(set(evidence_names)):
            raise ValueError("evidence_used fact names must be unique")
        if any(
            item.fact not in set(evidence_names)
            for item in self.missing_or_contextual_evidence
        ):
            raise ValueError(
                "missing_or_contextual_evidence must be drawn from evidence_used"
            )

        if (
            self.result is not CompatibilityDecision.NO_KNOWN_CONFLICT
            and not self.triggered_rules
        ):
            raise ValueError("non-default decisions require a triggered rule")
        return self


class CompatibilitySummary(StrictCompatibilityModel):
    """Counts of terminal control decisions and provisional results."""

    controls_evaluated: int = Field(ge=0)
    no_known_conflict: int = Field(ge=0)
    warning: int = Field(ge=0)
    review_required: int = Field(ge=0)
    insufficient_evidence: int = Field(ge=0)
    provisional: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_counts(self) -> "CompatibilitySummary":
        terminal_total = (
            self.no_known_conflict
            + self.warning
            + self.review_required
            + self.insufficient_evidence
        )
        if terminal_total != self.controls_evaluated:
            raise ValueError("decision counts must add up to controls_evaluated")
        if self.provisional > self.controls_evaluated:
            raise ValueError("provisional cannot exceed controls_evaluated")
        return self


class CompatibilityReport(StrictCompatibilityModel):
    """Complete structured output for one supplied target profile."""

    report_version: Literal["1"] = "1"
    generated_at: datetime
    profile_source: str = Field(min_length=1)
    profile_collected_at: datetime
    target: TargetInfo
    control_results: list[ControlCompatibilityResult] = Field(min_length=1)
    overall_summary: CompatibilitySummary

    @model_validator(mode="after")
    def validate_report(self) -> "CompatibilityReport":
        if self.generated_at.utcoffset() is None:
            raise ValueError("generated_at must include a timezone")
        if self.profile_collected_at.utcoffset() is None:
            raise ValueError("profile_collected_at must include a timezone")
        control_ids = [item.control_id for item in self.control_results]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("control result IDs must be unique")
        if self.overall_summary.controls_evaluated != len(self.control_results):
            raise ValueError("summary count must match control_results")
        return self
