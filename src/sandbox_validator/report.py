"""Build and serialize validated Milestone 5 reports."""

from __future__ import annotations

import yaml

from .models import (
    ControlValidationResult,
    ValidationDecision,
    ValidationReport,
    ValidationSummary,
)


def build_summary(results: list[ControlValidationResult]) -> ValidationSummary:
    return ValidationSummary(
        controls_evaluated=len(results),
        validated=sum(item.result is ValidationDecision.VALIDATED for item in results),
        warning=sum(item.result is ValidationDecision.WARNING for item in results),
        failed=sum(item.result is ValidationDecision.FAILED for item in results),
        not_tested=sum(
            item.result is ValidationDecision.NOT_TESTED for item in results
        ),
        remediations_attempted=sum(item.remediation.attempted for item in results),
        rollbacks_attempted=sum(item.rollback.attempted for item in results),
    )


def report_to_yaml(report: ValidationReport) -> str:
    return yaml.safe_dump(
        report.model_dump(mode="json"),
        sort_keys=False,
        allow_unicode=True,
    )


__all__ = ["build_summary", "report_to_yaml"]
