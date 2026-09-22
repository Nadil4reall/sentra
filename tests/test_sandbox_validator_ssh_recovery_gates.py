"""Focused execute-only recovery gates for the conditional SSH experiment."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.compatibility_engine.models import CompatibilityDecision
from src.poc_models import DerivationStatus
from src.sandbox_validator.adapters.ssh_root_login import SshRootLoginAdapter
from src.sandbox_validator.command_runner import MutationAction, MutationAuthorization
from src.sandbox_validator.loaders import ValidationInputs
from src.sandbox_validator.models import (
    AuditEvidence,
    CompatibilityReference,
    EvidenceStatus,
    ExecutionMode,
    SandboxIdentity,
    ValidationDecision,
)
from src.sandbox_validator.precheck import build_precheck
from src.sandbox_validator.validator import SandboxValidator, ValidationRequest
from src.target_profiler.models import TargetInfo


NOW = datetime(2026, 9, 22, tzinfo=timezone.utc)


def _identity() -> SandboxIdentity:
    return SandboxIdentity(
        hostname="sentra-sandbox",
        os="Ubuntu",
        version="24.04",
        kernel="6.8.0-test",
        architecture="x86_64",
        architecture_supported=True,
        effective_uid=0,
        privileged=True,
        supported=True,
    )


def _compatibility(control_id: str) -> CompatibilityReference:
    return CompatibilityReference(
        control_id=control_id,
        report_source="fixtures/compatibility.yaml",
        report_sha256="a" * 64,
        report_version="1",
        report_generated_at=NOW,
        profile_source="fixtures/profile.yaml",
        profile_collected_at=NOW,
        profile_target=TargetInfo(
            hostname="target",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-test",
            architecture="x86_64",
            supported=True,
            reason=None,
        ),
        result=CompatibilityDecision.NO_KNOWN_CONFLICT,
        provisional=False,
        metadata_review_status=DerivationStatus.REVIEWED,
        explanation="No defined compatibility concern was triggered.",
    )


def _precheck(
    *,
    control_id: str = "5.1.20",
    mutation_requested: bool = True,
    ssh_recovery_access_acknowledged: bool = True,
    ssh_non_root_admin_sudo_access_verified: bool = True,
    ssh_lockout_risk_acknowledged: bool = True,
):
    return build_precheck(
        control_id=control_id,
        control_title="test control",
        identity=_identity(),
        mutation_requested=mutation_requested,
        mutation_supported=True,
        sandbox_operator_acknowledged=True,
        administrator_approval_acknowledged=True,
        compatibility_risk_acknowledged=False,
        compatibility_override_reason=None,
        compatibility=_compatibility(control_id),
        ssh_recovery_access_acknowledged=ssh_recovery_access_acknowledged,
        ssh_non_root_admin_sudo_access_verified=(
            ssh_non_root_admin_sudo_access_verified
        ),
        ssh_lockout_risk_acknowledged=ssh_lockout_risk_acknowledged,
    )


@pytest.mark.parametrize(
    ("missing", "blocker"),
    [
        ("ssh_recovery_access_acknowledged", "console or snapshot recovery access"),
        (
            "ssh_non_root_admin_sudo_access_verified",
            "tested non-root administrator sudo access",
        ),
        ("ssh_lockout_risk_acknowledged", "lockout-risk acknowledgement"),
    ],
)
def test_ssh_execute_requires_each_recovery_gate(missing: str, blocker: str) -> None:
    acknowledgements = {
        "ssh_recovery_access_acknowledged": True,
        "ssh_non_root_admin_sudo_access_verified": True,
        "ssh_lockout_risk_acknowledged": True,
    }
    acknowledgements[missing] = False

    precheck = _precheck(**acknowledgements)

    assert precheck.can_mutate is False
    assert any(blocker in item for item in precheck.blockers)


def test_all_ssh_recovery_gates_are_recorded_and_authorize_precheck() -> None:
    precheck = _precheck()

    assert precheck.can_mutate is True
    assert precheck.ssh_recovery_access_acknowledged is True
    assert precheck.ssh_non_root_admin_sudo_access_verified is True
    assert precheck.ssh_lockout_risk_acknowledged is True


def test_ssh_recovery_gates_do_not_block_plan_or_other_control() -> None:
    plan = _precheck(
        mutation_requested=False,
        ssh_recovery_access_acknowledged=False,
        ssh_non_root_admin_sudo_access_verified=False,
        ssh_lockout_risk_acknowledged=False,
    )
    passwd_execute = _precheck(
        control_id="7.1.1",
        ssh_recovery_access_acknowledged=False,
        ssh_non_root_admin_sudo_access_verified=False,
        ssh_lockout_risk_acknowledged=False,
    )

    assert plan.blockers == []
    assert plan.can_mutate is False
    assert passwd_execute.can_mutate is True


def _collected(name: str, value: object) -> AuditEvidence:
    return AuditEvidence(
        name=name,
        status=EvidenceStatus.COLLECTED,
        value=value,
        source="fixture:ssh-pre-audit",
    )


def _safe_ssh_pre_audit() -> list[AuditEvidence]:
    return [
        _collected("ssh_installed", True),
        _collected("ssh_service_status", "active"),
        _collected("ssh_service_reload_supported", True),
        _collected("sshd_config_syntax_valid", True),
        _collected("sshd_match_directives_present", False),
        _collected("sshd_include_precedence_supported", True),
        _collected("remote_session_context", True),
    ]


def test_ssh_adapter_refuses_before_mutation_when_remote_session_is_not_collected() -> None:
    evidence = _safe_ssh_pre_audit()
    evidence[-1] = AuditEvidence(
        name="remote_session_context",
        status=EvidenceStatus.UNSUPPORTED,
        value=None,
        source="process_environment:ssh_markers",
        reason="absence cannot be proven after privilege escalation",
    )
    authorization = MutationAuthorization(
        control_id="5.1.20",
        allowed_actions=frozenset({MutationAction.SSH_SERVICE_RELOAD}),
    )

    outcome = SshRootLoginAdapter().execute(None, evidence, authorization)

    assert outcome.decision is ValidationDecision.NOT_TESTED
    assert outcome.remediation.attempted is False
    assert any("remote_session_context" in item for item in outcome.errors)


class _NeverExecuteSshAdapter:
    mutation_supported = True

    def __init__(self) -> None:
        self.execute_calls = 0

    def pre_audit(self, _context):
        return _safe_ssh_pre_audit()

    def plan(self, _pre_audit):
        return []

    def execute(self, _context, _pre_audit, _authorization):
        self.execute_calls += 1
        raise AssertionError("missing SSH recovery gates must prevent adapter execution")


def test_validation_request_recovery_fields_reach_precheck_and_block_execute() -> None:
    adapter = _NeverExecuteSshAdapter()
    inputs = ValidationInputs(
        control_id="5.1.20",
        control_title="Ensure sshd PermitRootLogin is disabled",
        manifest_path=Path("fixtures/manifest.yaml"),
        enrichment_path=None,
        enrichment=None,
        m3_profile_path=None,
        m3_profile_source=None,
        m3_profile=None,
        m4_report_path=Path("fixtures/compatibility.yaml"),
        compatibility=_compatibility("5.1.20"),
    )
    validator = SandboxValidator(
        identity_provider=_identity,
        adapters={"5.1.20": adapter},
    )

    report = validator.validate(
        inputs,
        ValidationRequest(
            control_id="5.1.20",
            mode=ExecutionMode.EXECUTE,
            sandbox_operator_acknowledged=True,
            administrator_approval_acknowledged=True,
        ),
    )

    result = report.control_results[0]
    assert result.result is ValidationDecision.NOT_TESTED
    assert result.precheck.can_mutate is False
    assert len(result.precheck.blockers) == 3
    assert adapter.execute_calls == 0
