"""Coordinate deterministic, data-only compatibility evaluation."""

from __future__ import annotations

from datetime import datetime, timezone

from src.poc_models import DerivationStatus, EnrichmentDocument

from .evidence import resolve_control_evidence
from .loaders import CompatibilityInputs
from .models import (
    CompatibilityDecision,
    CompatibilityReport,
    ControlCompatibilityResult,
    EvidenceRecord,
    TriggeredRule,
)
from .report import build_summary
from .rules import evaluate_control_rules


_DECISION_PRIORITY = {
    CompatibilityDecision.NO_KNOWN_CONFLICT: 0,
    CompatibilityDecision.REVIEW_REQUIRED: 1,
    CompatibilityDecision.INSUFFICIENT_EVIDENCE: 2,
    CompatibilityDecision.WARNING: 3,
}


def _decision(findings: tuple[TriggeredRule, ...]) -> CompatibilityDecision:
    if not findings:
        return CompatibilityDecision.NO_KNOWN_CONFLICT
    return max(
        (item.result for item in findings), key=_DECISION_PRIORITY.__getitem__
    )


def _contextual_evidence(
    evidence: tuple[EvidenceRecord, ...],
    findings: tuple[TriggeredRule, ...],
) -> list[EvidenceRecord]:
    contextual_names = {
        fact_name
        for finding in findings
        if finding.result
        in {
            CompatibilityDecision.REVIEW_REQUIRED,
            CompatibilityDecision.INSUFFICIENT_EVIDENCE,
        }
        for fact_name in finding.evidence_facts
    }
    return [
        item
        for item in evidence
        if item.status.value != "collected" or item.fact in contextual_names
    ]


def _explanation(
    result: CompatibilityDecision,
    findings: tuple[TriggeredRule, ...],
    provisional: bool,
) -> str:
    if findings:
        rationale = " ".join(item.explanation for item in findings)
    else:
        rationale = (
            "Available evidence did not trigger a compatibility concern defined "
            "by the current Milestone 2 enrichment. This is not a safety or CIS "
            "compliance verdict."
        )
    if provisional:
        rationale += (
            " The result is provisional because the enrichment remains "
            "needs_review."
        )
    if result is CompatibilityDecision.NO_KNOWN_CONFLICT:
        rationale += (
            " no_known_conflict means only that the current rules found no concern."
        )
    return rationale


def evaluate_control(
    enrichment: EnrichmentDocument, inputs: CompatibilityInputs
) -> ControlCompatibilityResult:
    """Evaluate one enrichment against the already supplied target profile."""

    resolved = resolve_control_evidence(
        inputs.profile,
        enrichment.control_id,
        enrichment.sentra.required_target_facts,
    )
    by_name = {item.fact: item for item in resolved}
    findings = evaluate_control_rules(enrichment.control_id, by_name)
    result = _decision(findings)
    metadata_status = enrichment.sentra.evidence.derivation_status
    provisional = metadata_status is DerivationStatus.NEEDS_REVIEW
    return ControlCompatibilityResult(
        control_id=enrichment.control_id,
        category=enrichment.sentra.category,
        result=result,
        provisional=provisional,
        metadata_review_status=metadata_status,
        evidence_used=list(resolved),
        triggered_rules=list(findings),
        missing_or_contextual_evidence=_contextual_evidence(resolved, findings),
        explanation=_explanation(result, findings, provisional),
    )


def evaluate_compatibility(
    inputs: CompatibilityInputs, *, generated_at: datetime | None = None
) -> CompatibilityReport:
    """Evaluate all selected controls without executing target-side operations."""

    results = [
        evaluate_control(enrichment, inputs)
        for enrichment in inputs.enrichments
    ]
    return CompatibilityReport(
        generated_at=generated_at or datetime.now(timezone.utc),
        profile_source=inputs.profile_source,
        profile_collected_at=inputs.profile.collected_at,
        target=inputs.profile.target,
        control_results=results,
        overall_summary=build_summary(results),
    )
