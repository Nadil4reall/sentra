"""Narrow M6D adapters between stored M4 evidence and unchanged M5 models."""

from __future__ import annotations

import json

from src.controller.models import (
    CompatibilityReportRecord,
    ValidationJobRecord,
    ValidationResultPayload,
)
from src.sandbox_validator.models import CompatibilityReference


M6D_SUPPORTED_CONTROL_IDS = frozenset({"7.1.1"})


def compatibility_reference_from_record(
    record: CompatibilityReportRecord,
    control_id: str,
) -> CompatibilityReference:
    """Derive the exact inert M5 reference from one validated M6C record."""

    if control_id not in M6D_SUPPORTED_CONTROL_IDS:
        raise ValueError("control is not enabled for M6D validation")
    selected = next(
        (
            item
            for item in record.report.control_results
            if item.control_id == control_id
        ),
        None,
    )
    if selected is None:
        raise ValueError("compatibility report does not contain the selected control")
    return CompatibilityReference(
        control_id=control_id,
        report_source=(
            "controller-stored-compatibility-report:"
            f"{record.compatibility_report_id}"
        ),
        report_sha256=record.report_sha256,
        report_version=record.report_version,
        report_generated_at=record.generated_at,
        profile_source=record.report.profile_source,
        profile_collected_at=record.report.profile_collected_at,
        profile_target=record.report.target,
        result=selected.result,
        provisional=selected.provisional,
        metadata_review_status=selected.metadata_review_status,
        explanation=selected.explanation,
    )


def canonical_validation_payload_json(payload: ValidationResultPayload) -> str:
    """Strictly round-trip and canonically serialize an M6D evidence payload."""

    validated = ValidationResultPayload.model_validate(
        payload.model_dump(mode="python"),
        strict=True,
    )
    canonical = json.dumps(
        validated.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    reparsed = ValidationResultPayload.model_validate_json(canonical)
    if reparsed != validated:
        raise ValueError("validation evidence changed during canonicalization")
    return canonical


def require_payload_matches_job(
    payload: ValidationResultPayload,
    job: ValidationJobRecord,
) -> None:
    """Bind submitted M5 evidence to every immutable M6D job field."""

    if (
        payload.target_id != job.target_id
        or payload.profile_id != job.profile_id
        or payload.compatibility_report_id != job.compatibility_report_id
        or payload.validation_job_id != job.validation_job_id
        or payload.control_id != job.control_id
        or payload.validation_mode is not job.validation_mode
        or payload.execution_mode is not job.execution_mode
    ):
        raise ValueError("validation evidence lineage does not match its job")

    report = payload.report
    control = report.control_results[0]
    if (
        job.dispatched_at is None
        or control.started_at < job.dispatched_at
    ):
        raise ValueError(
            "validation evidence predates Controller dispatch authorization"
        )
    if control.m4_input != job.compatibility_reference:
        raise ValueError("validation evidence changed its M4 compatibility input")
    if control.m3_profile_source != job.compatibility_reference.profile_source:
        raise ValueError("validation evidence changed its M3 profile source")
    precheck = control.precheck
    if (
        precheck.administrator_approval_acknowledged
        is not job.administrator_approval_acknowledged
        or precheck.compatibility_risk_acknowledged
        is not job.compatibility_risk_acknowledged
        or precheck.compatibility_override_reason
        != job.compatibility_override_reason
    ):
        raise ValueError("validation evidence changed its authorization gates")
    if report.generated_at != control.completed_at:
        raise ValueError("M5 report generation time must match control completion")


__all__ = [
    "M6D_SUPPORTED_CONTROL_IDS",
    "canonical_validation_payload_json",
    "compatibility_reference_from_record",
    "require_payload_matches_job",
]
