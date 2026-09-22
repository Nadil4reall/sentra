from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from src.compatibility_engine.models import CompatibilityDecision
from src.poc_models import Category, DerivationStatus
from src.sandbox_validator.models import (
    ActionStatus,
    AuditEvidence,
    BackupInformation,
    CompatibilityReference,
    ControlValidationResult,
    EvidenceStatus,
    HealthCheck,
    HealthStatus,
    RemediationAction,
    RemediationResult,
    RollbackResult,
    SandboxIdentity,
    SandboxPrecheck,
    ValidationDecision,
    ValidationReport,
    ValidationSummary,
)
from src.target_profiler.models import TargetInfo


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)


def _identity(*, privileged: bool = True) -> SandboxIdentity:
    return SandboxIdentity(
        hostname="sentra-sandbox",
        os="Ubuntu",
        version="24.04",
        kernel="6.8.0-79-generic",
        architecture="x86_64",
        architecture_supported=True,
        effective_uid=0 if privileged else 1000,
        privileged=privileged,
        supported=True,
    )


def _compatibility(
    *,
    control_id: str = "7.1.1",
    decision: CompatibilityDecision = CompatibilityDecision.NO_KNOWN_CONFLICT,
) -> CompatibilityReference:
    return CompatibilityReference(
        control_id=control_id,
        report_source="data/compatibility/sandbox-input.yaml",
        report_sha256="a" * 64,
        report_version="1",
        report_generated_at=NOW,
        profile_source="data/profiles/sandbox.yaml",
        profile_collected_at=NOW - timedelta(minutes=5),
        profile_target=TargetInfo(
            hostname="profiled-target",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-79-generic",
            architecture="x86_64",
            supported=True,
        ),
        result=decision,
        provisional=True,
        metadata_review_status=DerivationStatus.NEEDS_REVIEW,
        explanation="The M4 result is an input, not mutation authorization.",
    )


def _precheck(
    *,
    identity: SandboxIdentity | None = None,
    compatibility: CompatibilityReference | None = None,
) -> SandboxPrecheck:
    selected_identity = identity or _identity()
    selected_compatibility = compatibility or _compatibility()
    return SandboxPrecheck(
        control_id="7.1.1",
        control_title="Ensure permissions on /etc/passwd are configured",
        identity=selected_identity,
        mutation_requested=True,
        sandbox_operator_acknowledged=True,
        administrator_approval_acknowledged=True,
        compatibility_risk_acknowledged=False,
        snapshot_expectation="A manual VM snapshot exists before execution.",
        compatibility=selected_compatibility,
        can_mutate=True,
        blockers=[],
        warnings=[],
    )


def _collected_evidence() -> AuditEvidence:
    return AuditEvidence(
        name="passwd_mode",
        status=EvidenceStatus.COLLECTED,
        value="0644",
        source="python:os.stat:/etc/passwd",
    )


def _successful_remediation() -> RemediationResult:
    return RemediationResult(
        supported=True,
        attempted=True,
        changed=True,
        succeeded=True,
        actions=[
            RemediationAction(
                action_id="set-passwd-mode",
                description="Set the fixed /etc/passwd target mode.",
                mutating=True,
                target="/etc/passwd",
                planned_effect="Set mode to the adapter-owned target state.",
                status=ActionStatus.APPLIED,
            )
        ],
        backups=[
            BackupInformation(
                target="/etc/passwd",
                original_existed=True,
                created=True,
                path="/var/backups/sentra/passwd.metadata.json",
                metadata_preserved=True,
            )
        ],
        reason="The fixed adapter action completed.",
    )


def _unattempted_remediation() -> RemediationResult:
    return RemediationResult(
        supported=True,
        attempted=False,
        changed=False,
        succeeded=None,
        actions=[],
        backups=[],
        reason="Mutation was not authorized.",
    )


def _health(
    *,
    required: bool = True,
    status: HealthStatus = HealthStatus.PASSED,
) -> HealthCheck:
    return HealthCheck(
        check_id="passwd-readable",
        description="Confirm the account database remains readable.",
        required=required,
        status=status,
        explanation="The simulated health observation was recorded.",
    )


def _control_result(
    *,
    decision: ValidationDecision = ValidationDecision.VALIDATED,
    remediation: RemediationResult | None = None,
    post_audit: list[AuditEvidence] | None = None,
    health_checks: list[HealthCheck] | None = None,
) -> ControlValidationResult:
    identity = _identity()
    compatibility = _compatibility()
    return ControlValidationResult(
        control_id="7.1.1",
        control_title="Ensure permissions on /etc/passwd are configured",
        category=Category.FILE_PERMISSIONS,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        m2_metadata_source="data/poc/enriched/7_1_1.yaml",
        m3_profile_source="data/profiles/sandbox.yaml",
        m4_input=compatibility,
        sandbox=identity,
        precheck=_precheck(identity=identity, compatibility=compatibility),
        pre_audit=[_collected_evidence()],
        remediation=remediation or _successful_remediation(),
        post_audit=(post_audit if post_audit is not None else [_collected_evidence()]),
        health_checks=(health_checks if health_checks is not None else [_health()]),
        rollback=RollbackResult(
            supported=True,
            attempted=False,
            succeeded=None,
            actions=[],
            explanation="Rollback was not needed.",
        ),
        events=[],
        result=decision,
        explanation="This is an empirical sandbox result, not a CIS verdict.",
        errors=[],
        warnings=(
            ["A non-fatal concern remains."]
            if decision is ValidationDecision.WARNING
            else []
        ),
    )


def _summary_for(result: ControlValidationResult) -> ValidationSummary:
    return ValidationSummary(
        controls_evaluated=1,
        validated=int(result.result is ValidationDecision.VALIDATED),
        warning=int(result.result is ValidationDecision.WARNING),
        failed=int(result.result is ValidationDecision.FAILED),
        not_tested=int(result.result is ValidationDecision.NOT_TESTED),
        remediations_attempted=int(result.remediation.attempted),
        rollbacks_attempted=int(result.rollback.attempted),
    )


@pytest.mark.parametrize("value", [False, 0, "", [], {}])
def test_collected_evidence_preserves_falsy_non_null_values(value: object) -> None:
    evidence = AuditEvidence(
        name="observed_value",
        status=EvidenceStatus.COLLECTED,
        value=value,  # type: ignore[arg-type]
        source="test:controlled-observation",
    )

    assert evidence.value == value
    assert evidence.reason is None


@pytest.mark.parametrize(
    "status",
    [EvidenceStatus.UNAVAILABLE, EvidenceStatus.UNSUPPORTED, EvidenceStatus.ERROR],
)
def test_uncertain_evidence_requires_null_value_and_reason(
    status: EvidenceStatus,
) -> None:
    evidence = AuditEvidence(
        name="ssh_effective_config",
        status=status,
        value=None,
        source="action:sshd_effective",
        reason="The observation could not be established.",
    )

    assert evidence.status is status
    assert evidence.value is None
    assert evidence.reason == "The observation could not be established."

    with pytest.raises(ValidationError, match="null value"):
        AuditEvidence(
            name="ssh_effective_config",
            status=status,
            value=False,
            source="action:sshd_effective",
            reason="The observation could not be established.",
        )
    with pytest.raises(ValidationError, match="include a reason"):
        AuditEvidence(
            name="ssh_effective_config",
            status=status,
            value=None,
            source="action:sshd_effective",
        )


def test_collected_evidence_rejects_missing_value_or_failure_reason() -> None:
    with pytest.raises(ValidationError, match="non-null value"):
        AuditEvidence(
            name="passwd_mode",
            status=EvidenceStatus.COLLECTED,
            value=None,
            source="python:os.stat:/etc/passwd",
        )
    with pytest.raises(ValidationError, match="must not include a reason"):
        AuditEvidence(
            name="passwd_mode",
            status=EvidenceStatus.COLLECTED,
            value="0644",
            source="python:os.stat:/etc/passwd",
            reason="This would contradict a collected observation.",
        )


def test_models_reject_undocumented_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AuditEvidence(
            name="passwd_mode",
            status=EvidenceStatus.COLLECTED,
            value="0644",
            source="python:os.stat:/etc/passwd",
            compliance_pass=True,
        )


@pytest.mark.parametrize("decision", [ValidationDecision.VALIDATED, ValidationDecision.WARNING])
def test_success_decisions_require_attempted_successful_remediation(
    decision: ValidationDecision,
) -> None:
    with pytest.raises(ValidationError, match="requires successful remediation"):
        _control_result(decision=decision, remediation=_unattempted_remediation())


@pytest.mark.parametrize("decision", [ValidationDecision.VALIDATED, ValidationDecision.WARNING])
def test_success_decisions_require_post_audit_evidence(
    decision: ValidationDecision,
) -> None:
    with pytest.raises(ValidationError, match="requires post-audit evidence"):
        _control_result(decision=decision, post_audit=[])


@pytest.mark.parametrize(
    ("decision", "status"),
    [
        (decision, status)
        for decision in (ValidationDecision.VALIDATED, ValidationDecision.WARNING)
        for status in (
            HealthStatus.WARNING,
            HealthStatus.FAILED,
            HealthStatus.UNAVAILABLE,
        )
    ],
)
def test_validated_requires_every_required_health_check_to_pass(
    decision: ValidationDecision,
    status: HealthStatus,
) -> None:
    with pytest.raises(ValidationError, match="required health check"):
        _control_result(decision=decision, health_checks=[_health(status=status)])


def test_non_required_health_concern_can_produce_warning() -> None:
    result = _control_result(
        decision=ValidationDecision.WARNING,
        health_checks=[_health(required=False, status=HealthStatus.WARNING)],
    )

    assert result.result is ValidationDecision.WARNING
    assert result.remediation.succeeded is True
    assert result.post_audit
    assert result.warnings


def test_remediation_and_rollback_outcomes_are_not_ambiguous() -> None:
    with pytest.raises(ValidationError, match="unattempted remediation"):
        RemediationResult(
            supported=True,
            attempted=False,
            changed=True,
            succeeded=None,
            actions=[],
            backups=[],
            reason="Contradictory state.",
        )
    with pytest.raises(ValidationError, match="must report success or failure"):
        RemediationResult(
            supported=True,
            attempted=True,
            changed=False,
            succeeded=None,
            actions=[],
            backups=[],
            reason="Ambiguous state.",
        )
    with pytest.raises(ValidationError, match="unsupported remediation"):
        RemediationResult(
            supported=False,
            attempted=True,
            changed=False,
            succeeded=False,
            actions=[],
            backups=[],
            reason="Unsupported actions must not start.",
        )
    with pytest.raises(ValidationError, match="unattempted rollback"):
        RollbackResult(
            supported=True,
            attempted=False,
            succeeded=True,
            actions=[],
            explanation="Contradictory rollback state.",
        )


def test_failed_actions_and_missing_backups_require_reasons() -> None:
    with pytest.raises(ValidationError, match="failed actions must include an error"):
        RemediationAction(
            action_id="set-passwd-mode",
            description="Attempt a fixed action.",
            mutating=True,
            target="/etc/passwd",
            planned_effect="Set the fixed target mode.",
            status=ActionStatus.FAILED,
        )
    with pytest.raises(ValidationError, match="missing backup"):
        BackupInformation(
            target="/etc/passwd",
            original_existed=True,
            created=False,
            metadata_preserved=False,
        )


def test_precheck_mutation_gate_requires_exact_matching_evidence() -> None:
    compatibility = _compatibility(control_id="5.1.20")

    with pytest.raises(ValidationError, match="match the selected control"):
        _precheck(compatibility=compatibility)

    precheck = _precheck()
    with pytest.raises(ValidationError, match="can_mutate must reflect"):
        SandboxPrecheck.model_validate(
            {
                **precheck.model_dump(mode="python"),
                "blockers": ["mutation is blocked"],
            }
        )


def test_precheck_requires_risk_acknowledgement_for_uncertain_m4_input() -> None:
    compatibility = _compatibility(decision=CompatibilityDecision.REVIEW_REQUIRED)

    with pytest.raises(ValidationError, match="requires risk acknowledgement"):
        _precheck(compatibility=compatibility)


def test_result_rejects_mismatched_sandbox_and_m4_traceability() -> None:
    result = _control_result()
    other_identity = _identity(privileged=False)

    with pytest.raises(ValidationError, match="sandbox must match"):
        ControlValidationResult.model_validate(
            {
                **result.model_dump(mode="python"),
                "sandbox": other_identity,
            }
        )

    with pytest.raises(ValidationError, match="M4 input must match"):
        ControlValidationResult.model_validate(
            {
                **result.model_dump(mode="python"),
                "m4_input": _compatibility(control_id="5.1.20"),
            }
        )


def test_result_timestamps_are_ordered_and_timezone_aware() -> None:
    result = _control_result()

    with pytest.raises(ValidationError, match="cannot precede"):
        ControlValidationResult.model_validate(
            {
                **result.model_dump(mode="python"),
                "completed_at": NOW - timedelta(seconds=1),
            }
        )
    with pytest.raises(ValidationError, match="must include a timezone"):
        ControlValidationResult.model_validate(
            {
                **result.model_dump(mode="python"),
                "completed_at": NOW.replace(tzinfo=None),
            }
        )


def test_summary_requires_complete_terminal_counts_and_bounded_attempts() -> None:
    with pytest.raises(ValidationError, match="must add up"):
        ValidationSummary(
            controls_evaluated=2,
            validated=1,
            warning=0,
            failed=0,
            not_tested=0,
            remediations_attempted=1,
            rollbacks_attempted=0,
        )
    with pytest.raises(ValidationError, match="remediation count"):
        ValidationSummary(
            controls_evaluated=1,
            validated=1,
            warning=0,
            failed=0,
            not_tested=0,
            remediations_attempted=2,
            rollbacks_attempted=0,
        )
    with pytest.raises(ValidationError, match="rollback count"):
        ValidationSummary(
            controls_evaluated=1,
            validated=1,
            warning=0,
            failed=0,
            not_tested=0,
            remediations_attempted=0,
            rollbacks_attempted=1,
        )


def test_not_tested_and_failed_have_distinct_execution_semantics() -> None:
    with pytest.raises(ValidationError, match="not_tested cannot include"):
        _control_result(decision=ValidationDecision.NOT_TESTED)

    with pytest.raises(ValidationError, match="attempted, unsuccessful remediation"):
        _control_result(
            decision=ValidationDecision.FAILED,
            remediation=_unattempted_remediation(),
            post_audit=[],
            health_checks=[],
        )


def test_report_rejects_summary_length_mismatch_and_duplicate_controls() -> None:
    result = _control_result()

    with pytest.raises(ValidationError, match="summary count"):
        ValidationReport(
            generated_at=NOW,
            mode="execute",
            control_results=[result],
            summary=ValidationSummary(
                controls_evaluated=0,
                validated=0,
                warning=0,
                failed=0,
                not_tested=0,
                remediations_attempted=0,
                rollbacks_attempted=0,
            ),
        )

    with pytest.raises(ValidationError, match="control IDs must be unique"):
        ValidationReport(
            generated_at=NOW,
            mode="execute",
            control_results=[result, result],
            summary=ValidationSummary(
                controls_evaluated=2,
                validated=2,
                warning=0,
                failed=0,
                not_tested=0,
                remediations_attempted=2,
                rollbacks_attempted=0,
            ),
        )


def test_report_summary_must_match_results_not_only_total_length() -> None:
    result = _control_result(decision=ValidationDecision.WARNING)

    with pytest.raises(ValidationError, match="summary counts must match"):
        ValidationReport(
            generated_at=NOW,
            mode="execute",
            control_results=[result],
            summary=ValidationSummary(
                controls_evaluated=1,
                validated=1,
                warning=0,
                failed=0,
                not_tested=0,
                remediations_attempted=1,
                rollbacks_attempted=0,
            ),
        )


def test_plan_report_cannot_claim_attempted_remediation() -> None:
    result = _control_result()

    with pytest.raises(ValidationError, match="plan reports cannot contain"):
        ValidationReport(
            generated_at=NOW,
            mode="plan",
            control_results=[result],
            summary=_summary_for(result),
        )


def test_valid_report_preserves_empirical_result_and_summary() -> None:
    result = _control_result(decision=ValidationDecision.WARNING)
    report = ValidationReport(
        generated_at=NOW,
        mode="execute",
        control_results=[result],
        summary=_summary_for(result),
    )

    dumped = report.model_dump(mode="json")
    assert dumped["control_results"][0]["result"] == "warning"
    assert dumped["control_results"][0]["m4_input"]["result"] == "no_known_conflict"
    assert dumped["summary"] == {
        "controls_evaluated": 1,
        "validated": 0,
        "warning": 1,
        "failed": 0,
        "not_tested": 0,
        "remediations_attempted": 1,
        "rollbacks_attempted": 0,
    }
