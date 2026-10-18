from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from src import sandbox_m5_validation
from src.compatibility_engine.models import CompatibilityDecision
from src.poc_models import DerivationStatus
from src.sandbox_m5_validation import (
    SandboxM5ValidationInput,
    run_m5_validation_after_reproduction,
)
from src.sandbox_runtime.reproduction import SandboxIpForwardingReproductionResult
from src.sandbox_validator.adapters import adapter_registry
from src.sandbox_validator.adapters.base import (
    AdapterContext,
    FileSnapshot,
    SystemFileOperations,
)
from src.sandbox_validator.adapters.ip_forwarding import IpForwardingAdapter
from src.sandbox_validator.command_runner import (
    CommandResult,
    MutationAction,
    MutationAuthorization,
    ReadAction,
)
from src.sandbox_validator.models import (
    ActionStatus,
    CompatibilityReference,
    HealthStatus,
    SandboxIdentity,
    ValidationDecision,
)
from src.sandbox_validator.validator import SandboxValidator
from src.target_profiler.models import TargetInfo


class RootlessTestFileOperations(SystemFileOperations):
    """Test-only filesystem that simulates privileged ownership operations.

    Production still uses SystemFileOperations and requests UID/GID 0.
    Tests run as the local Mac user and therefore must not call fchown(0, 0).
    """

    def snapshot(self, path: Path) -> FileSnapshot:
        snapshot = super().snapshot(path)
        if path.name == "99-sentra-3.3.1.conf":
            return replace(snapshot, uid=0, gid=0)
        return snapshot

    def create_exclusive_text(
        self,
        path: Path,
        content: str,
        *,
        uid: int,
        gid: int,
        mode: int,
    ) -> None:
        # Verify that the adapter still requests the production ownership.
        if uid != 0 or gid != 0:
            raise AssertionError(
                f"adapter requested unexpected ownership: uid={uid}, gid={gid}"
            )

        with path.open("x", encoding="utf-8") as stream:
            stream.write(content)
        path.chmod(mode)


class FakeSysctlRunner:
    def __init__(
        self,
        *,
        ipv4: int = 1,
        ipv6: int = 1,
        fail_actions: set[MutationAction] | None = None,
        fail_once_actions: set[MutationAction] | None = None,
    ) -> None:
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.mutations: list[MutationAction] = []
        self.reads: list[ReadAction] = []
        self.fail_actions = fail_actions or set()
        self.fail_once_actions = fail_once_actions or set()

    def run_read(self, action: ReadAction) -> CommandResult:
        self.reads.append(action)
        if action is ReadAction.IPV4_FORWARDING_STATUS:
            value = self.ipv4
        elif action is ReadAction.IPV6_FORWARDING_STATUS:
            value = self.ipv6
        else:
            raise AssertionError(f"unexpected read action: {action}")

        return CommandResult(
            action=action.value,
            kind="read",
            argv=(action.value,),
            returncode=0,
            stdout=f"{value}\n",
            stderr="",
        )

    def run_mutation(
        self,
        action: MutationAction,
        authorization: MutationAuthorization,
    ) -> CommandResult:
        if authorization.control_id != "3.3.1":
            raise AssertionError("wrong control authorization")
        if not authorization.allows(action):
            raise AssertionError(f"unauthorized mutation: {action}")

        self.mutations.append(action)

        if action in self.fail_actions or action in self.fail_once_actions:
            self.fail_once_actions.discard(action)
            return CommandResult(
                action=action.value,
                kind="mutation",
                argv=(action.value,),
                returncode=1,
                stdout="",
                stderr="",
                error_kind="nonzero_exit",
                reason="fixed test mutation failed",
            )

        if action is MutationAction.IPV4_FORWARDING_DISABLE:
            self.ipv4 = 0
        elif action is MutationAction.IPV4_FORWARDING_ENABLE:
            self.ipv4 = 1
        elif action is MutationAction.IPV6_FORWARDING_DISABLE:
            self.ipv6 = 0
        elif action is MutationAction.IPV6_FORWARDING_ENABLE:
            self.ipv6 = 1
        elif action in {
            MutationAction.IPV4_ROUTE_FLUSH,
            MutationAction.IPV6_ROUTE_FLUSH,
        }:
            pass
        else:
            raise AssertionError(f"unexpected mutation action: {action}")

        return CommandResult(
            action=action.value,
            kind="mutation",
            argv=(action.value,),
            returncode=0,
            stdout="",
            stderr="",
        )


def _authorization() -> MutationAuthorization:
    return MutationAuthorization(
        control_id="3.3.1",
        allowed_actions=frozenset(
            {
                MutationAction.IPV4_FORWARDING_DISABLE,
                MutationAction.IPV4_FORWARDING_ENABLE,
                MutationAction.IPV6_FORWARDING_DISABLE,
                MutationAction.IPV6_FORWARDING_ENABLE,
                MutationAction.IPV4_ROUTE_FLUSH,
                MutationAction.IPV6_ROUTE_FLUSH,
            }
        ),
    )


def _context(
    tmp_path: Path,
    runner: FakeSysctlRunner,
) -> AdapterContext:
    (tmp_path / "etc" / "sysctl.d").mkdir(parents=True)
    module = tmp_path / "sys" / "module" / "ipv6" / "parameters"
    module.mkdir(parents=True)
    (module / "disable").write_text("0\n", encoding="utf-8")
    for family in ("all", "default"):
        directory = tmp_path / "proc" / "sys" / "net" / "ipv6" / "conf" / family
        directory.mkdir(parents=True)
        (directory / "disable_ipv6").write_text("0\n", encoding="utf-8")

    return AdapterContext(
        root=tmp_path,
        runner=runner,  # type: ignore[arg-type]
        files=RootlessTestFileOperations(),
    )


def test_registry_contains_ip_forwarding_adapter() -> None:
    registry = adapter_registry()

    assert "3.3.1" in registry
    assert isinstance(registry["3.3.1"], IpForwardingAdapter)


def test_ip_forwarding_adapter_applies_and_verifies(tmp_path: Path) -> None:
    runner = FakeSysctlRunner(ipv4=1, ipv6=1)
    context = _context(tmp_path, runner)
    adapter = IpForwardingAdapter()

    before = adapter.pre_audit(context)
    outcome = adapter.execute(context, before, _authorization())

    assert outcome.decision is ValidationDecision.VALIDATED
    assert outcome.remediation.succeeded is True
    assert outcome.remediation.changed is True

    assert runner.ipv4 == 0
    assert runner.ipv6 == 0

    managed = tmp_path / "etc" / "sysctl.d" / "99-sentra-3.3.1.conf"
    assert managed.is_file()

    text = managed.read_text(encoding="utf-8")
    assert "net.ipv4.ip_forward = 0" in text
    assert "net.ipv6.conf.all.forwarding = 0" in text


def test_ip_forwarding_adapter_is_idempotent(tmp_path: Path) -> None:
    runner = FakeSysctlRunner(ipv4=1, ipv6=1)
    context = _context(tmp_path, runner)
    adapter = IpForwardingAdapter()

    first = adapter.execute(
        context,
        adapter.pre_audit(context),
        _authorization(),
    )
    assert first.decision is ValidationDecision.VALIDATED

    mutations_before = list(runner.mutations)

    second = adapter.execute(
        context,
        adapter.pre_audit(context),
        _authorization(),
    )

    assert second.decision is ValidationDecision.VALIDATED
    assert second.remediation.succeeded is True
    assert second.remediation.changed is False
    assert runner.mutations == mutations_before


def test_ip_forwarding_adapter_refuses_existing_unmanaged_file(
    tmp_path: Path,
) -> None:
    runner = FakeSysctlRunner(ipv4=1, ipv6=1)
    context = _context(tmp_path, runner)

    managed = tmp_path / "etc" / "sysctl.d" / "99-sentra-3.3.1.conf"
    managed.write_text(
        "net.ipv4.ip_forward = 1\n",
        encoding="utf-8",
    )

    adapter = IpForwardingAdapter()
    outcome = adapter.execute(
        context,
        adapter.pre_audit(context),
        _authorization(),
    )

    assert outcome.decision is ValidationDecision.NOT_TESTED
    assert outcome.remediation.attempted is False
    assert runner.mutations == []
    assert managed.read_text(encoding="utf-8") == "net.ipv4.ip_forward = 1\n"


def test_ip_forwarding_adapter_rejects_wrong_control_authorization(
    tmp_path: Path,
) -> None:
    runner = FakeSysctlRunner(ipv4=1, ipv6=1)
    context = _context(tmp_path, runner)
    adapter = IpForwardingAdapter()

    wrong = MutationAuthorization(
        control_id="7.1.1",
        allowed_actions=frozenset(),
    )

    try:
        adapter.execute(context, adapter.pre_audit(context), wrong)
    except ValueError as exc:
        assert "3.3.1" in str(exc)
    else:
        raise AssertionError("wrong-control authorization was accepted")


def test_ipv6_disabled_does_not_read_or_mutate_ipv6(tmp_path: Path) -> None:
    runner = FakeSysctlRunner(ipv4=1, ipv6=1)
    context = _context(tmp_path, runner)
    (tmp_path / "sys/module/ipv6/parameters/disable").write_text(
        "1\n", encoding="utf-8"
    )

    adapter = IpForwardingAdapter()
    outcome = adapter.execute(context, adapter.pre_audit(context), _authorization())

    assert outcome.decision is ValidationDecision.VALIDATED
    assert ReadAction.IPV6_FORWARDING_STATUS not in runner.reads
    assert all("ipv6" not in action.value for action in runner.mutations)
    assert "net.ipv6" not in (
        tmp_path / "etc/sysctl.d/99-sentra-3.3.1.conf"
    ).read_text(encoding="utf-8")
    assert next(
        check for check in outcome.health_checks
        if check.check_id == "ipv6-forwarding-disabled"
    ).status is HealthStatus.PASSED


def test_ipv4_only_runtime_change_with_enabled_ipv6(tmp_path: Path) -> None:
    runner = FakeSysctlRunner(ipv4=1, ipv6=0)
    context = _context(tmp_path, runner)
    adapter = IpForwardingAdapter()

    outcome = adapter.execute(context, adapter.pre_audit(context), _authorization())

    assert outcome.decision is ValidationDecision.VALIDATED
    assert MutationAction.IPV4_FORWARDING_DISABLE in runner.mutations
    assert all("ipv6" not in action.value for action in runner.mutations)


def test_competing_persistent_assignment_refuses_before_mutation(tmp_path: Path) -> None:
    runner = FakeSysctlRunner()
    context = _context(tmp_path, runner)
    (tmp_path / "etc/sysctl.d/90-other.conf").write_text(
        "net.ipv4.ip_forward = 1\n", encoding="utf-8"
    )
    adapter = IpForwardingAdapter()

    outcome = adapter.execute(context, adapter.pre_audit(context), _authorization())

    assert outcome.decision is ValidationDecision.NOT_TESTED
    assert outcome.remediation.attempted is False
    assert "persistent_sysctl_precedence_unresolved" in outcome.errors
    assert runner.mutations == []
    assert not (tmp_path / "etc/sysctl.d/99-sentra-3.3.1.conf").exists()


def test_duplicate_sysctl_conf_alias_is_scanned_once(tmp_path: Path) -> None:
    runner = FakeSysctlRunner()
    context = _context(tmp_path, runner)
    (tmp_path / "etc/sysctl.conf").write_text(
        "# net.ipv4.ip_forward = 1\n", encoding="utf-8"
    )
    (tmp_path / "etc/sysctl.d/99-sysctl.conf").symlink_to("../sysctl.conf")
    adapter = IpForwardingAdapter()

    outcome = adapter.execute(context, adapter.pre_audit(context), _authorization())

    assert outcome.decision is ValidationDecision.VALIDATED


def test_external_sysctl_source_symlink_refuses_mutation(tmp_path: Path) -> None:
    runner = FakeSysctlRunner()
    context = _context(tmp_path, runner)
    external = tmp_path.parent / f"{tmp_path.name}-external-sysctl.conf"
    external.write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")
    (tmp_path / "etc/sysctl.d/99-external.conf").symlink_to(external)
    adapter = IpForwardingAdapter()

    outcome = adapter.execute(context, adapter.pre_audit(context), _authorization())

    assert outcome.decision is ValidationDecision.NOT_TESTED
    assert outcome.remediation.attempted is False
    assert runner.mutations == []


def test_existing_managed_file_drift_refuses_before_mutation(tmp_path: Path) -> None:
    runner = FakeSysctlRunner()
    context = _context(tmp_path, runner)
    managed = tmp_path / "etc/sysctl.d/99-sentra-3.3.1.conf"
    managed.write_text(
        "# Managed by SENTRA Milestone 5 (control 3.3.1).\n"
        "net.ipv4.ip_forward = 1\n",
        encoding="utf-8",
    )
    adapter = IpForwardingAdapter()

    outcome = adapter.execute(context, adapter.pre_audit(context), _authorization())

    assert outcome.decision is ValidationDecision.NOT_TESTED
    assert "sentra_sysctl_drift" in outcome.errors
    assert runner.mutations == []
    assert "= 1" in managed.read_text(encoding="utf-8")


def test_existing_managed_file_with_unsafe_mode_refuses(tmp_path: Path) -> None:
    runner = FakeSysctlRunner()
    context = _context(tmp_path, runner)
    managed = tmp_path / "etc/sysctl.d/99-sentra-3.3.1.conf"
    managed.write_text(
        "# Managed by SENTRA Milestone 5 (control 3.3.1).\n"
        "net.ipv4.ip_forward = 0\n"
        "net.ipv6.conf.all.forwarding = 0\n",
        encoding="utf-8",
    )
    managed.chmod(0o666)
    adapter = IpForwardingAdapter()

    outcome = adapter.execute(context, adapter.pre_audit(context), _authorization())

    assert outcome.decision is ValidationDecision.NOT_TESTED
    assert "sentra_sysctl_drift" in outcome.errors
    assert runner.mutations == []


def test_exclusive_managed_file_create_does_not_overwrite_collision(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "sysctl.d"
    directory.mkdir()
    target = directory / "99-sentra-3.3.1.conf"
    target.write_text("operator data\n", encoding="utf-8")

    try:
        SystemFileOperations().create_exclusive_text(
            target,
            "candidate\n",
            uid=0,
            gid=0,
            mode=0o644,
        )
    except FileExistsError:
        pass
    else:
        raise AssertionError("exclusive creation replaced a pre-existing file")

    assert target.read_text(encoding="utf-8") == "operator data\n"


def test_partial_mutation_failure_rolls_back_runtime_and_file(tmp_path: Path) -> None:
    runner = FakeSysctlRunner(
        ipv4=1,
        ipv6=0,
        fail_actions={MutationAction.IPV4_ROUTE_FLUSH},
    )
    context = _context(tmp_path, runner)
    adapter = IpForwardingAdapter()

    outcome = adapter.execute(context, adapter.pre_audit(context), _authorization())

    assert outcome.decision is ValidationDecision.FAILED
    assert outcome.rollback.attempted is True
    assert outcome.rollback.succeeded is False  # flush remains failed
    assert runner.ipv4 == 1
    assert not (tmp_path / "etc/sysctl.d/99-sentra-3.3.1.conf").exists()
    assert any(
        action.action_id == "restore-ipv4-forwarding"
        and action.status is ActionStatus.FAILED
        for action in outcome.rollback.actions
    )


def test_partial_mutation_failure_can_roll_back_successfully(tmp_path: Path) -> None:
    runner = FakeSysctlRunner(
        ipv4=1,
        ipv6=0,
        fail_once_actions={MutationAction.IPV4_ROUTE_FLUSH},
    )
    context = _context(tmp_path, runner)
    adapter = IpForwardingAdapter()

    outcome = adapter.execute(context, adapter.pre_audit(context), _authorization())

    assert outcome.decision is ValidationDecision.FAILED
    assert outcome.rollback.attempted is True
    assert outcome.rollback.succeeded is True
    assert runner.ipv4 == 1
    assert not (tmp_path / "etc/sysctl.d/99-sentra-3.3.1.conf").exists()


def test_rollback_failure_is_visible(tmp_path: Path) -> None:
    runner = FakeSysctlRunner(
        ipv4=1,
        ipv6=0,
        fail_actions={
            MutationAction.IPV4_ROUTE_FLUSH,
            MutationAction.IPV4_FORWARDING_ENABLE,
        },
    )
    context = _context(tmp_path, runner)
    adapter = IpForwardingAdapter()

    outcome = adapter.execute(context, adapter.pre_audit(context), _authorization())

    assert outcome.decision is ValidationDecision.FAILED
    assert outcome.rollback.attempted is True
    assert outcome.rollback.succeeded is False
    assert runner.ipv4 == 0
    assert not (tmp_path / "etc/sysctl.d/99-sentra-3.3.1.conf").exists()


def test_reproduced_3_3_1_context_reaches_real_m5_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeSysctlRunner(ipv4=1, ipv6=1)
    local_context = _context(tmp_path, runner)
    identity = SandboxIdentity(
        hostname="isolated-test-sandbox",
        os="Ubuntu",
        version="24.04",
        kernel="6.8.0-test",
        architecture="x86_64",
        architecture_supported=True,
        effective_uid=0,
        privileged=True,
        supported=True,
    )

    def safe_validator(*, context: AdapterContext) -> SandboxValidator:
        assert context.root == Path("/")
        return SandboxValidator(
            context=local_context,
            identity_provider=lambda: identity,
        )

    monkeypatch.setattr(sandbox_m5_validation, "SandboxValidator", safe_validator)
    now = datetime(2026, 10, 18, tzinfo=UTC)
    compatibility = CompatibilityReference(
        control_id="3.3.1",
        report_source="controller-stored-compatibility-report:report-test",
        report_sha256="a" * 64,
        report_version="1",
        report_generated_at=now,
        profile_source="controller-stored-profile:profile-test",
        profile_collected_at=now,
        profile_target=TargetInfo(
            hostname="isolated-test-sandbox",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-test",
            architecture="x86_64",
            supported=True,
        ),
        result=CompatibilityDecision.REVIEW_REQUIRED,
        provisional=True,
        metadata_review_status=DerivationStatus.NEEDS_REVIEW,
        explanation="Deployment role needs administrator review.",
    )
    reproduction = SandboxIpForwardingReproductionResult(
        control_id="3.3.1",
        before_ipv4=0,
        requested_ipv4=1,
        after_ipv4=1,
        ipv6_enabled=True,
        before_ipv6=0,
        requested_ipv6=1,
        after_ipv6=1,
        reproduced=True,
    )
    authorization = SandboxM5ValidationInput(
        control_id="3.3.1",
        administrator_approval_acknowledged=True,
        sandbox_operator_acknowledged=True,
        compatibility_risk_acknowledged=True,
        compatibility_override_reason=None,
        compatibility_reference=compatibility,
    )

    report = run_m5_validation_after_reproduction(reproduction, authorization)

    assert report.control_results[0].control_id == "3.3.1"
    assert report.control_results[0].result is ValidationDecision.VALIDATED
    assert report.control_results[0].m4_input == compatibility
    assert runner.ipv4 == 0
    assert runner.ipv6 == 0
