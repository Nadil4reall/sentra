"""Build and safely serialize deterministic Milestone 4 reports."""

from __future__ import annotations

import yaml

from .models import (
    CompatibilityDecision,
    CompatibilityReport,
    CompatibilitySummary,
    ControlCompatibilityResult,
)


def build_summary(
    results: list[ControlCompatibilityResult],
) -> CompatibilitySummary:
    """Count every terminal decision and provisional result."""

    return CompatibilitySummary(
        controls_evaluated=len(results),
        no_known_conflict=sum(
            item.result is CompatibilityDecision.NO_KNOWN_CONFLICT
            for item in results
        ),
        warning=sum(
            item.result is CompatibilityDecision.WARNING for item in results
        ),
        review_required=sum(
            item.result is CompatibilityDecision.REVIEW_REQUIRED
            for item in results
        ),
        insufficient_evidence=sum(
            item.result is CompatibilityDecision.INSUFFICIENT_EVIDENCE
            for item in results
        ),
        provisional=sum(item.provisional for item in results),
    )


def report_to_yaml(report: CompatibilityReport) -> str:
    """Serialize a validated report without Python-specific YAML tags."""

    return yaml.safe_dump(
        report.model_dump(mode="json"),
        sort_keys=False,
        allow_unicode=True,
    )
