"""Milestone 5 acceptance, CLI, traceability, and safety-boundary tests.

Every execution path in this module uses an injected identity and adapter.  The
tests never inspect or mutate the developer host and never run a real command.
"""

from __future__ import annotations

import ast
from datetime import datetime, timezone
from pathlib import Path
import stat
import subprocess

import pytest
import yaml

from src.compatibility_engine.models import CompatibilityDecision
from src.poc_models import Category, DerivationStatus
from src.sandbox_validator import cli
from src.sandbox_validator.adapters.base import (
    AdapterContext,
    AdapterOutcome,
    ControlAdapter,
)
from src.sandbox_validator.command_runner import (
    CommandNotAllowedError,
    CommandRunner,
    MutationAuthorization,
)
from src.sandbox_validator.loaders import ValidationInputs
from src.sandbox_validator.models import (
    ActionStatus,
    AuditEvidence,
    CompatibilityReference,
    EvidenceStatus,
    ExecutionMode,
    HealthCheck,
    HealthStatus,
    RemediationAction,
    RemediationResult,
    RollbackResult,
    SandboxIdentity,
    ValidationDecision,
    ValidationReport,
)
from src.sandbox_validator.report import report_to_yaml
from src.sandbox_validator.validator import SandboxValidator, ValidationRequest
from src.target_profiler.models import TargetInfo


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "data" / "poc" / "poc_controls.yaml"
M5_SOURCE_DIRECTORY = ROOT / "src" / "sandbox_validator"
NOW = datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)


class NoCommandRunner:
    """Tripwire proving that acceptance fixtures never cross into subprocesses."""

    def run_read(self, *_args: object, **_kwargs: object) -> None:
        raise AssertionError("acceptance test attempted a real read command")

    def run_mutation(self, *_args: object, **_kwargs: object) -> None:
        raise AssertionError("acceptance test attempted a real mutation command")


class RecordingAdapter(ControlAdapter):
    """A deterministic in-memory adapter used to observe orchestration gates."""

    control_id = "7.1.1"
    title = "Ensure permissions on /etc/passwd are configured"
    category = Category.FILE_PERMISSIONS
    mutation_supported = True

    def __init__(self) -> None:
        self.pre_audit_calls = 0
        self.execute_calls = 0

    @staticmethod
    def _evidence(source: str) -> AuditEvidence:
        return AuditEvidence(
            name="fixture_state",
            status=EvidenceStatus.COLLECTED,
            value="expected",
            source=source,
        )

    def pre_audit(self, context: AdapterContext) -> list[AuditEvidence]:
        self.pre_audit_calls += 1
        return [self._evidence("fixture:pre_audit")]

    def plan(self, pre_audit: list[AuditEvidence]) -> list[RemediationAction]:
        return [
            RemediationAction(
                action_id="apply-fixture-candidate",
                description="Apply the inert acceptance-test candidate.",
                mutating=True,
                target="fixture-only",
                planned_effect="Exercise the M5 authorization boundary without host I/O.",
                status=ActionStatus.PLANNED,
            )
        ]

    def execute(
        self,
        context: AdapterContext,
        pre_audit: list[AuditEvidence],
        authorization: MutationAuthorization,
    ) -> AdapterOutcome:
        assert authorization.control_id == self.control_id
        self.execute_calls += 1
        actions = [
            action.model_copy(update={"status": ActionStatus.APPLIED})
            for action in self.plan(pre_audit)
        ]
        return AdapterOutcome(
            remediation=RemediationResult(
                supported=True,
                attempted=True,
                changed=True,
                succeeded=True,
                actions=actions,
                backups=[],
                reason="The inert fixture candidate completed.",
            ),
            post_audit=[self._evidence("fixture:post_audit")],
            health_checks=[
                HealthCheck(
                    check_id="fixture-health",
                    description="Confirm the inert fixture post-state.",
                    required=True,
                    status=HealthStatus.PASSED,
                    explanation="The in-memory post-state matched.",
                )
            ],
            rollback=RollbackResult(
                supported=True,
                attempted=False,
                succeeded=None,
                actions=[],
                explanation="Rollback was not required for the inert fixture.",
            ),
            decision=ValidationDecision.VALIDATED,
            explanation="The injected acceptance adapter validated its inert candidate.",
            warnings=[],
            errors=[],
        )


class RecordingSshAdapter(RecordingAdapter):
    """Inert SSH-shaped adapter used only to observe CLI authorization gates."""

    control_id = "5.1.20"
    title = "Ensure sshd PermitRootLogin is disabled"
    category = Category.SSH


def _identity() -> SandboxIdentity:
    return SandboxIdentity(
        hostname="sentra-sandbox-fixture",
        os="Ubuntu",
        version="24.04",
        kernel="6.8.0-fixture",
        architecture="x86_64",
        architecture_supported=True,
        effective_uid=0,
        privileged=True,
        supported=True,
    )


def _compatibility(
    decision: CompatibilityDecision = CompatibilityDecision.NO_KNOWN_CONFLICT,
    *,
    control_id: str = "7.1.1",
) -> CompatibilityReference:
    return CompatibilityReference(
        control_id=control_id,
        report_source="fixtures/m4-compatibility.yaml",
        report_sha256="a" * 64,
        report_version="1",
        report_generated_at=NOW,
        profile_source="fixtures/m3-profile.yaml",
        profile_collected_at=NOW,
        profile_target=TargetInfo(
            hostname="sentra-target-fixture",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-target-fixture",
            architecture="x86_64",
            supported=True,
        ),
        result=decision,
        provisional=True,
        metadata_review_status=DerivationStatus.NEEDS_REVIEW,
        explanation=f"Synthetic M4 {decision.value} input for an M5 acceptance test.",
    )


def _inputs(
    compatibility: CompatibilityReference | None,
    *,
    control_id: str = "7.1.1",
) -> ValidationInputs:
    return ValidationInputs(
        control_id=control_id,
        control_title=(
            "Ensure permissions on /etc/passwd are configured"
            if control_id == "7.1.1"
            else f"Unsupported M5 control {control_id}"
        ),
        manifest_path=MANIFEST_PATH,
        enrichment_path=None,
        enrichment=None,
        m3_profile_path=None,
        m3_profile_source=(
            compatibility.profile_source if compatibility is not None else None
        ),
        m3_profile=None,
        m4_report_path=None,
        compatibility=compatibility,
    )


def _context(tmp_path: Path) -> AdapterContext:
    return AdapterContext(
        root=tmp_path,
        runner=NoCommandRunner(),  # type: ignore[arg-type]
        environment={},
        clock=lambda: NOW,
    )


def _validator(
    tmp_path: Path, adapter: RecordingAdapter
) -> SandboxValidator:
    return SandboxValidator(
        context=_context(tmp_path),
        identity_provider=_identity,
        adapters={adapter.control_id: adapter},
    )


def _authorized_request(
    *,
    mode: ExecutionMode = ExecutionMode.EXECUTE,
    sandbox_ack: bool = True,
    compatibility_ack: bool = False,
    override_reason: str | None = None,
) -> ValidationRequest:
    return ValidationRequest(
        control_id="7.1.1",
        mode=mode,
        sandbox_operator_acknowledged=sandbox_ack,
        administrator_approval_acknowledged=True,
        compatibility_risk_acknowledged=compatibility_ack,
        compatibility_override_reason=override_reason,
    )


def _install_cli_fakes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    adapter: RecordingAdapter,
    inputs: ValidationInputs,
) -> None:
    context = _context(tmp_path)
    report_directory = tmp_path / "data" / "sandbox"
    report_directory.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(cli, "REPORT_OUTPUT_DIRECTORY", report_directory)
    monkeypatch.setattr(
        cli,
        "load_validation_inputs",
        lambda *_args, **_kwargs: inputs,
    )
    monkeypatch.setattr(cli, "AdapterContext", lambda **_kwargs: context)
    monkeypatch.setattr(
        cli,
        "SandboxValidator",
        lambda *, context: SandboxValidator(
            context=context,
            identity_provider=_identity,
            adapters={adapter.control_id: adapter},
        ),
    )


def test_cli_without_execute_is_read_only_even_when_all_acknowledgements_exist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    adapter = RecordingAdapter()
    _install_cli_fakes(monkeypatch, tmp_path, adapter, _inputs(_compatibility()))

    assert cli.main(
        [
            "--control",
            "7.1.1",
            "--plan",
            "--sandbox-ack",
            "--administrator-approval",
        ]
    ) == 0

    report = ValidationReport.model_validate(yaml.safe_load(capsys.readouterr().out))
    result = report.control_results[0]
    assert report.mode is ExecutionMode.PLAN
    assert result.precheck.mutation_requested is False
    assert result.precheck.can_mutate is False
    assert result.result is ValidationDecision.NOT_TESTED
    assert result.remediation.attempted is False
    assert adapter.pre_audit_calls == 1
    assert adapter.execute_calls == 0


def test_cli_execute_without_sandbox_ack_never_calls_adapter_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = RecordingAdapter()
    _install_cli_fakes(monkeypatch, tmp_path, adapter, _inputs(_compatibility()))
    output = tmp_path / "data" / "sandbox" / "blocked.yaml"

    assert cli.main(
        [
            "--control",
            "7.1.1",
            "--execute",
            "--administrator-approval",
            "--compatibility-report",
            str(tmp_path / "fixture-m4.yaml"),
            "--output",
            str(output),
        ]
    ) == 0

    report = ValidationReport.model_validate(
        yaml.safe_load(output.read_text(encoding="utf-8"))
    )
    result = report.control_results[0]
    assert report.mode is ExecutionMode.EXECUTE
    assert result.result is ValidationDecision.NOT_TESTED
    assert result.precheck.can_mutate is False
    assert any("sandbox operator acknowledgement" in item for item in result.errors)
    assert result.remediation.attempted is False
    assert adapter.execute_calls == 0


def test_cli_ssh_plan_does_not_require_execute_only_recovery_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    adapter = RecordingSshAdapter()
    _install_cli_fakes(
        monkeypatch,
        tmp_path,
        adapter,
        _inputs(_compatibility(control_id="5.1.20"), control_id="5.1.20"),
    )

    assert cli.main(["--control", "5.1.20", "--plan"]) == 0

    report = ValidationReport.model_validate(yaml.safe_load(capsys.readouterr().out))
    result = report.control_results[0]
    assert report.mode is ExecutionMode.PLAN
    assert result.result is ValidationDecision.NOT_TESTED
    assert result.precheck.blockers == []
    assert result.precheck.ssh_recovery_access_acknowledged is False
    assert result.precheck.ssh_non_root_admin_sudo_access_verified is False
    assert result.precheck.ssh_lockout_risk_acknowledged is False
    assert adapter.execute_calls == 0


def test_cli_passwd_execute_is_unaffected_by_missing_ssh_recovery_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = RecordingAdapter()
    _install_cli_fakes(monkeypatch, tmp_path, adapter, _inputs(_compatibility()))
    output = tmp_path / "data" / "sandbox" / "passwd-without-ssh-flags.yaml"

    assert cli.main(
        [
            "--control",
            "7.1.1",
            "--execute",
            "--sandbox-ack",
            "--administrator-approval",
            "--compatibility-report",
            str(tmp_path / "fixture-m4.yaml"),
            "--output",
            str(output),
        ]
    ) == 0

    report = ValidationReport.model_validate(
        yaml.safe_load(output.read_text(encoding="utf-8"))
    )
    result = report.control_results[0]
    assert result.result is ValidationDecision.VALIDATED
    assert result.precheck.can_mutate is True
    assert result.precheck.ssh_recovery_access_acknowledged is False
    assert result.precheck.ssh_non_root_admin_sudo_access_verified is False
    assert result.precheck.ssh_lockout_risk_acknowledged is False
    assert adapter.execute_calls == 1


_SSH_EXECUTE_FLAGS = (
    "--ssh-recovery-access-ack",
    "--ssh-non-root-admin-sudo-access-verified",
    "--ssh-lockout-risk-ack",
)


def test_cli_help_documents_ssh_execute_only_recovery_flags() -> None:
    help_text = cli.build_parser().format_help()
    normalized_help = " ".join(help_text.split())

    assert all(flag in help_text for flag in _SSH_EXECUTE_FLAGS)
    assert "5.1.20 execute only" in normalized_help
    assert "VM console and snapshot recovery access" in normalized_help
    assert "non-root administrator login and sudo path" in normalized_help
    assert "SSH lockout risk" in normalized_help


@pytest.mark.parametrize(
    ("missing_flag", "expected_blocker"),
    [
        ("--ssh-recovery-access-ack", "console or snapshot recovery access"),
        (
            "--ssh-non-root-admin-sudo-access-verified",
            "tested non-root administrator sudo access",
        ),
        ("--ssh-lockout-risk-ack", "lockout-risk acknowledgement"),
    ],
)
def test_cli_ssh_execute_missing_each_recovery_flag_blocks_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_flag: str,
    expected_blocker: str,
) -> None:
    adapter = RecordingSshAdapter()
    _install_cli_fakes(
        monkeypatch,
        tmp_path,
        adapter,
        _inputs(_compatibility(control_id="5.1.20"), control_id="5.1.20"),
    )
    output = (
        tmp_path
        / "data"
        / "sandbox"
        / f"ssh-missing-{missing_flag.removeprefix('--')}.yaml"
    )
    present_flags = [flag for flag in _SSH_EXECUTE_FLAGS if flag != missing_flag]

    assert cli.main(
        [
            "--control",
            "5.1.20",
            "--execute",
            "--sandbox-ack",
            "--administrator-approval",
            "--compatibility-report",
            str(tmp_path / "fixture-m4.yaml"),
            "--output",
            str(output),
            *present_flags,
        ]
    ) == 0

    report = ValidationReport.model_validate(
        yaml.safe_load(output.read_text(encoding="utf-8"))
    )
    result = report.control_results[0]
    assert result.result is ValidationDecision.NOT_TESTED
    assert result.precheck.can_mutate is False
    assert any(expected_blocker in blocker for blocker in result.precheck.blockers)
    assert result.remediation.attempted is False
    assert adapter.execute_calls == 0


def test_cli_ssh_execute_flags_populate_existing_validation_request_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = RecordingSshAdapter()
    inputs = _inputs(_compatibility(control_id="5.1.20"), control_id="5.1.20")
    _install_cli_fakes(monkeypatch, tmp_path, adapter, inputs)
    context = _context(tmp_path)
    validator = SandboxValidator(
        context=context,
        identity_provider=_identity,
        adapters={adapter.control_id: adapter},
    )
    captured: dict[str, ValidationRequest] = {}

    class CapturingValidator:
        def __init__(self, *, context: AdapterContext) -> None:
            assert context is not None

        def validate(
            self, loaded_inputs: ValidationInputs, request: ValidationRequest
        ) -> ValidationReport:
            captured["request"] = request
            return validator.validate(loaded_inputs, request)

    monkeypatch.setattr(cli, "SandboxValidator", CapturingValidator)
    output = tmp_path / "data" / "sandbox" / "ssh-all-recovery-flags.yaml"

    assert cli.main(
        [
            "--control",
            "5.1.20",
            "--execute",
            "--sandbox-ack",
            "--administrator-approval",
            "--compatibility-report",
            str(tmp_path / "fixture-m4.yaml"),
            "--output",
            str(output),
            *_SSH_EXECUTE_FLAGS,
        ]
    ) == 0

    request = captured["request"]
    assert request.ssh_recovery_access_acknowledged is True
    assert request.ssh_non_root_admin_sudo_access_verified is True
    assert request.ssh_lockout_risk_acknowledged is True
    report = ValidationReport.model_validate(
        yaml.safe_load(output.read_text(encoding="utf-8"))
    )
    assert report.control_results[0].precheck.can_mutate is True
    assert adapter.execute_calls == 1


@pytest.mark.parametrize(
    ("decision", "compatibility_ack", "override_reason", "authorized", "blocker"),
    [
        (
            CompatibilityDecision.WARNING,
            False,
            None,
            False,
            "risk acknowledgement",
        ),
        (CompatibilityDecision.WARNING, True, None, True, None),
        (
            CompatibilityDecision.REVIEW_REQUIRED,
            False,
            None,
            False,
            "risk acknowledgement",
        ),
        (CompatibilityDecision.REVIEW_REQUIRED, True, None, True, None),
        (
            CompatibilityDecision.INSUFFICIENT_EVIDENCE,
            False,
            "Research run approved after manual evidence review.",
            False,
            "risk acknowledgement",
        ),
        (
            CompatibilityDecision.INSUFFICIENT_EVIDENCE,
            True,
            None,
            False,
            "override reason",
        ),
        (
            CompatibilityDecision.INSUFFICIENT_EVIDENCE,
            True,
            "Research run approved after manual evidence review.",
            True,
            None,
        ),
    ],
)
def test_m4_policy_gates_and_traceability(
    tmp_path: Path,
    decision: CompatibilityDecision,
    compatibility_ack: bool,
    override_reason: str | None,
    authorized: bool,
    blocker: str | None,
) -> None:
    adapter = RecordingAdapter()
    reference = _compatibility(decision)
    report = _validator(tmp_path, adapter).validate(
        _inputs(reference),
        _authorized_request(
            compatibility_ack=compatibility_ack,
            override_reason=override_reason,
        ),
    )

    result = report.control_results[0]
    assert result.m4_input == reference
    assert result.precheck.compatibility == reference
    assert result.m4_input.result is decision
    assert result.m4_input.provisional is True
    assert (
        result.m4_input.metadata_review_status is DerivationStatus.NEEDS_REVIEW
    )
    assert result.m4_input.report_sha256 == "a" * 64
    assert result.precheck.compatibility_override_reason == override_reason
    assert result.precheck.can_mutate is authorized
    assert adapter.execute_calls == int(authorized)

    if authorized:
        assert result.result is ValidationDecision.VALIDATED
        assert result.remediation.attempted is True
    else:
        assert result.result is ValidationDecision.NOT_TESTED
        assert result.remediation.attempted is False
        assert blocker is not None
        assert any(blocker in item for item in result.precheck.blockers)


def test_unsupported_control_is_refused_as_not_tested_without_host_actions(
    tmp_path: Path,
) -> None:
    adapter = RecordingAdapter()
    control_id = "9.9.9"
    reference = _compatibility(control_id=control_id)
    validator = SandboxValidator(
        context=_context(tmp_path),
        identity_provider=_identity,
        adapters={adapter.control_id: adapter},
    )

    report = validator.validate(
        _inputs(reference, control_id=control_id),
        ValidationRequest(
            control_id=control_id,
            mode=ExecutionMode.EXECUTE,
            sandbox_operator_acknowledged=True,
            administrator_approval_acknowledged=True,
        ),
    )

    result = report.control_results[0]
    assert result.result is ValidationDecision.NOT_TESTED
    assert result.remediation.supported is False
    assert result.remediation.attempted is False
    assert result.pre_audit == []
    assert "No hand-authored M5 adapter" in result.explanation
    assert any("does not support mutation" in item for item in result.errors)
    assert adapter.pre_audit_calls == 0
    assert adapter.execute_calls == 0


def test_report_yaml_round_trip_preserves_m4_lineage_and_m5_semantics(
    tmp_path: Path,
) -> None:
    adapter = RecordingAdapter()
    reference = _compatibility(CompatibilityDecision.REVIEW_REQUIRED)
    original = _validator(tmp_path, adapter).validate(
        _inputs(reference),
        _authorized_request(compatibility_ack=True),
    )

    document = yaml.safe_load(report_to_yaml(original))
    parsed = ValidationReport.model_validate(document)

    assert parsed == original
    assert parsed.summary.model_dump() == {
        "controls_evaluated": 1,
        "validated": 1,
        "warning": 0,
        "failed": 0,
        "not_tested": 0,
        "remediations_attempted": 1,
        "rollbacks_attempted": 0,
    }
    result = parsed.control_results[0]
    assert result.result is ValidationDecision.VALIDATED
    assert result.m4_input == reference
    assert result.precheck.compatibility == reference
    assert document["control_results"][0]["result"] == "validated"
    assert "compliant" not in report_to_yaml(original).casefold()


def test_cli_refuses_output_overwrite_before_loading_or_inspecting_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report_directory = tmp_path / "data" / "sandbox"
    report_directory.mkdir(parents=True)
    monkeypatch.setattr(cli, "REPORT_OUTPUT_DIRECTORY", report_directory)
    output = report_directory / "existing.yaml"
    original = b"operator-owned report\n"
    output.write_bytes(original)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("overwrite refusal crossed into input or host inspection")

    monkeypatch.setattr(cli, "load_validation_inputs", fail)
    monkeypatch.setattr(cli, "AdapterContext", fail)
    monkeypatch.setattr(cli, "SandboxValidator", fail)

    with pytest.raises(SystemExit) as raised:
        cli.main(["--control", "7.1.1", "--plan", "--output", str(output)])

    assert raised.value.code == 2
    assert "output already exists" in capsys.readouterr().err
    assert output.read_bytes() == original


def test_cli_overwrite_requires_explicit_flag_and_replaces_report_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = RecordingAdapter()
    _install_cli_fakes(monkeypatch, tmp_path, adapter, _inputs(_compatibility()))
    output = tmp_path / "data" / "sandbox" / "existing.yaml"
    existing = _validator(tmp_path, RecordingAdapter()).validate(
        _inputs(_compatibility()),
        _authorized_request(mode=ExecutionMode.PLAN),
    )
    output.write_text(report_to_yaml(existing), encoding="utf-8")

    assert cli.main(
        [
            "--control",
            "7.1.1",
            "--plan",
            "--output",
            str(output),
            "--overwrite",
        ]
    ) == 0

    parsed = ValidationReport.model_validate(
        yaml.safe_load(output.read_text(encoding="utf-8"))
    )
    assert parsed.mode is ExecutionMode.PLAN
    assert parsed.control_results[0].result is ValidationDecision.NOT_TESTED
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert not list(output.parent.glob(f".{output.name}.*.tmp"))
    assert adapter.execute_calls == 0


def test_list_controls_is_deterministic_and_host_independent(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("--list-controls attempted input or host inspection")

    monkeypatch.setattr(cli, "load_validation_inputs", fail)
    monkeypatch.setattr(cli, "AdapterContext", fail)
    monkeypatch.setattr(cli, "SandboxValidator", fail)

    assert cli.main(["--list-controls"]) == 0
    first = capsys.readouterr().out
    assert cli.main(["--list-controls"]) == 0
    second = capsys.readouterr().out
    assert first == second

    controls = yaml.safe_load(first)["controls"]
    assert [item["control_id"] for item in controls] == ["7.1.1", "5.1.20", "4.2.3"]
    assert [item["capability"] for item in controls] == [
        "full",
        "conditional",
        "audit_plan_only",
    ]


def test_arbitrary_cis_text_cannot_reach_the_command_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_cis_text = "$(touch /tmp/sentra-must-not-run); chmod 777 /etc/passwd"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("raw CIS text reached subprocess.run")

    monkeypatch.setattr(subprocess, "run", fail)
    runner = CommandRunner()

    with pytest.raises(CommandNotAllowedError):
        runner.run_read(raw_cis_text)  # type: ignore[arg-type]
    with pytest.raises(CommandNotAllowedError):
        runner.run_mutation(  # type: ignore[arg-type]
            raw_cis_text,
            MutationAuthorization(control_id="5.1.20", allowed_actions=frozenset()),
        )


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
    return None


def test_m5_source_has_no_dynamic_execution_and_subprocess_is_fail_closed() -> None:
    forbidden_calls = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "os.spawnv",
        "os.spawnve",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "yaml.load",
        "yaml.unsafe_load",
    }
    subprocess_calls: list[tuple[Path, ast.Call]] = []

    for path in sorted(M5_SOURCE_DIRECTORY.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        calls: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted_name(node.func)
            if name:
                calls.add(name)
            if name == "subprocess.run":
                subprocess_calls.append((path, node))

        assert forbidden_calls.isdisjoint(calls), (path, forbidden_calls & calls)

    assert len(subprocess_calls) == 1
    path, call = subprocess_calls[0]
    assert path == M5_SOURCE_DIRECTORY / "command_runner.py"
    shell_keywords = [item for item in call.keywords if item.arg == "shell"]
    assert len(shell_keywords) == 1
    assert isinstance(shell_keywords[0].value, ast.Constant)
    assert shell_keywords[0].value.value is False

    parser_destinations = {
        action.dest for action in cli.build_parser()._actions if action.dest
    }
    assert {"command", "argv", "script", "audit", "remediation"}.isdisjoint(
        parser_destinations
    )
