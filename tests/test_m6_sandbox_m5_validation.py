from __future__ import annotations

import ast
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from src.compatibility_engine.models import CompatibilityDecision
from src.poc_models import DerivationStatus
from src import sandbox_m5_validation as m5_validation
from src.sandbox_m5_validation import (
    SandboxM5ValidationError,
    SandboxM5ValidationInput,
    run_m5_validation_after_reproduction,
)
from src.sandbox_runtime.reproduction import SandboxPasswdReproductionResult
from src.sandbox_validator.adapters.base import AdapterContext, FileSnapshot
from src.sandbox_validator.adapters.passwd_permissions import PasswdPermissionsAdapter
from src.sandbox_validator.models import (
    ActionStatus,
    CompatibilityReference,
    ExecutionMode,
    HealthStatus,
    SandboxIdentity,
    ValidationDecision,
    ValidationReport,
)
from src.sandbox_validator.validator import SandboxValidator as RealSandboxValidator
from src.target_profiler.models import TargetInfo


_NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
_PASSWD_CONTENT = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
)
_RUNTIME_FILE = Path(m5_validation.__file__).resolve()


@dataclass
class _FakeFile:
    text: str
    mode: int
    uid: int
    gid: int
    inode: int


class _TemporaryFileOperations:
    """In-memory M5 filesystem that refuses paths outside the temporary root."""

    def __init__(self, root: Path, *, mode: int, uid: int, gid: int) -> None:
        self.root = root
        self.entries: dict[Path, _FakeFile] = {}
        self.metadata_writes: list[tuple[Path, int, int, int]] = []
        self.operations: list[tuple[str, Path]] = []
        self.next_inode = 100
        self.add_file(root / "etc" / "passwd", text=_PASSWD_CONTENT, mode=mode, uid=uid, gid=gid)

    def _checked(self, path: Path) -> Path:
        path = Path(path)
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise AssertionError(f"test filesystem refused outside path: {path}") from exc
        return path

    def add_file(
        self,
        path: Path,
        *,
        text: str,
        mode: int,
        uid: int,
        gid: int,
    ) -> None:
        path = self._checked(path)
        self.next_inode += 1
        self.entries[path] = _FakeFile(text, mode, uid, gid, self.next_inode)

    def _entry(self, path: Path) -> _FakeFile:
        path = self._checked(path)
        try:
            return self.entries[path]
        except KeyError as exc:
            raise FileNotFoundError(path) from exc

    def snapshot(self, path: Path) -> FileSnapshot:
        path = self._checked(path)
        self.operations.append(("snapshot", path))
        item = self._entry(path)
        return FileSnapshot(
            mode=item.mode,
            uid=item.uid,
            gid=item.gid,
            device=1,
            inode=item.inode,
            size=len(item.text.encode("utf-8")),
        )

    def read_text(self, path: Path, *, max_bytes: int) -> str:
        path = self._checked(path)
        self.operations.append(("read_text", path))
        item = self._entry(path)
        if len(item.text.encode("utf-8")) > max_bytes:
            raise OSError("temporary fixture exceeded read bound")
        return item.text

    def make_private_directory(self, path: Path) -> None:
        path = self._checked(path)
        self.operations.append(("make_private_directory", path))

    def backup_file(
        self, source: Path, destination: Path, expected: FileSnapshot
    ) -> None:
        source = self._checked(source)
        destination = self._checked(destination)
        self.operations.append(("backup_file", destination))
        item = self._entry(source)
        current = self.snapshot(source)
        if (current.device, current.inode) != (expected.device, expected.inode):
            raise OSError("temporary fixture identity changed")
        self.add_file(
            destination,
            text=item.text,
            mode=item.mode,
            uid=item.uid,
            gid=item.gid,
        )

    def set_metadata(
        self,
        path: Path,
        expected: FileSnapshot,
        *,
        uid: int,
        gid: int,
        mode: int,
    ) -> None:
        path = self._checked(path)
        item = self._entry(path)
        current = self.snapshot(path)
        if (current.device, current.inode) != (expected.device, expected.inode):
            raise OSError("temporary fixture identity changed")
        item.uid = uid
        item.gid = gid
        item.mode = mode
        self.metadata_writes.append((path, uid, gid, mode))

    def atomic_write_text(
        self,
        path: Path,
        content: str,
        *,
        uid: int,
        gid: int,
        mode: int,
    ) -> None:
        self.add_file(path, text=content, mode=mode, uid=uid, gid=gid)

    def remove_file(self, path: Path) -> None:
        path = self._checked(path)
        self.entries.pop(path, None)


class _NoCommandRunner:
    def run_read(self, _action: Any) -> Any:
        raise AssertionError("control 7.1.1 must not execute a command")

    def run_mutation(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("control 7.1.1 must not execute a command")


def _reproduction(
    *,
    control_id: str = "7.1.1",
    target_path: str = "/etc/passwd",
    reproduced: bool = True,
    mode: str = "0664",
    uid: int = 0,
    gid: int = 0,
) -> SandboxPasswdReproductionResult:
    return SandboxPasswdReproductionResult(
        control_id=control_id,  # type: ignore[arg-type]
        target_path=target_path,  # type: ignore[arg-type]
        before_mode="0600",
        before_uid=1001,
        before_gid=1002,
        requested_mode=mode,
        requested_uid=uid,
        requested_gid=gid,
        after_mode=mode,
        after_uid=uid,
        after_gid=gid,
        reproduced=reproduced,
    )


def _compatibility(
    decision: CompatibilityDecision = CompatibilityDecision.NO_KNOWN_CONFLICT,
    *,
    control_id: str = "7.1.1",
) -> CompatibilityReference:
    return CompatibilityReference(
        control_id=control_id,
        report_source="controller://compatibility/report-1",
        report_sha256="a" * 64,
        report_version="1",
        report_generated_at=_NOW,
        profile_source="controller://profiles/profile-1",
        profile_collected_at=_NOW,
        profile_target=TargetInfo(
            hostname="m6-sandbox-fixture",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-fixture",
            architecture="x86_64",
            supported=True,
        ),
        result=decision,
        provisional=True,
        metadata_review_status=DerivationStatus.NEEDS_REVIEW,
        explanation=f"Synthetic M4 {decision.value} compatibility input.",
    )


def _authorization(
    *,
    decision: CompatibilityDecision = CompatibilityDecision.NO_KNOWN_CONFLICT,
    administrator_approval_acknowledged: bool = True,
    sandbox_operator_acknowledged: bool = True,
    compatibility_risk_acknowledged: bool = False,
    compatibility_override_reason: str | None = None,
) -> SandboxM5ValidationInput:
    return SandboxM5ValidationInput(
        control_id="7.1.1",
        administrator_approval_acknowledged=administrator_approval_acknowledged,
        sandbox_operator_acknowledged=sandbox_operator_acknowledged,
        compatibility_risk_acknowledged=compatibility_risk_acknowledged,
        compatibility_override_reason=compatibility_override_reason,
        compatibility_reference=_compatibility(decision),
    )


def _identity() -> SandboxIdentity:
    return SandboxIdentity(
        hostname="temporary-sandbox-fixture",
        os="Ubuntu",
        version="24.04",
        kernel="6.8.0-fixture",
        architecture="x86_64",
        architecture_supported=True,
        effective_uid=0,
        privileged=True,
        supported=True,
    )


def _install_temporary_validator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    mode: int = 0o664,
    uid: int = 0,
    gid: int = 0,
) -> tuple[dict[str, Any], _TemporaryFileOperations]:
    files = _TemporaryFileOperations(tmp_path, mode=mode, uid=uid, gid=gid)
    observed: dict[str, Any] = {}

    class TemporaryContextValidator:
        def __init__(self, *, context: AdapterContext) -> None:
            observed["production_root"] = context.root
            assert context.root == Path("/")
            safe_context = AdapterContext(
                root=tmp_path,
                files=files,  # type: ignore[arg-type]
                runner=_NoCommandRunner(),  # type: ignore[arg-type]
                clock=lambda: _NOW,
            )
            self.delegate = RealSandboxValidator(
                context=safe_context,
                identity_provider=_identity,
            )
            observed["validator"] = self.delegate

        def validate(self, inputs: Any, request: Any) -> ValidationReport:
            observed["inputs"] = inputs
            observed["request"] = request
            return self.delegate.validate(inputs, request)

    monkeypatch.setattr(m5_validation, "SandboxValidator", TemporaryContextValidator)
    return observed, files


def _run_refusal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    authorization: SandboxM5ValidationInput,
) -> tuple[ValidationReport, dict[str, Any], _TemporaryFileOperations]:
    observed, files = _install_temporary_validator(monkeypatch, tmp_path)
    report = run_m5_validation_after_reproduction(
        _reproduction(), authorization
    )
    return report, observed, files


def test_successful_reproduction_enters_existing_m5_passwd_adapter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed, files = _install_temporary_validator(monkeypatch, tmp_path)
    loader_calls: list[str] = []
    real_loader = m5_validation.load_validation_inputs

    def record_loader(control_id: str) -> Any:
        loader_calls.append(control_id)
        return real_loader(control_id)

    monkeypatch.setattr(m5_validation, "load_validation_inputs", record_loader)
    compatibility = _compatibility()
    report = run_m5_validation_after_reproduction(
        _reproduction(), _authorization()
    )

    assert type(report) is ValidationReport
    assert report.mode is ExecutionMode.EXECUTE
    assert loader_calls == ["7.1.1"]
    assert observed["production_root"] == Path("/")
    validator = observed["validator"]
    assert isinstance(validator.adapters["7.1.1"], PasswdPermissionsAdapter)
    assert list(validator.adapters) == ["7.1.1", "3.3.1", "5.1.20", "4.2.3"]

    result = report.control_results[0]
    assert result.control_id == "7.1.1"
    assert result.result is ValidationDecision.VALIDATED
    assert result.precheck.can_mutate is True
    assert result.precheck.administrator_approval_acknowledged is True
    assert result.precheck.sandbox_operator_acknowledged is True
    assert result.precheck.compatibility_risk_acknowledged is False
    assert result.m4_input == compatibility
    assert result.m3_profile_source == compatibility.profile_source
    assert result.pre_audit[0].value == "0664"
    assert result.remediation.attempted is True
    assert result.remediation.changed is True
    assert result.remediation.succeeded is True
    assert result.remediation.backups[0].created is True
    assert [action.status for action in result.remediation.actions] == [
        ActionStatus.APPLIED,
        ActionStatus.APPLIED,
        ActionStatus.APPLIED,
    ]
    assert result.post_audit[0].value == "0644"
    assert all(
        check.status is HealthStatus.PASSED
        for check in result.health_checks
        if check.required
    )
    assert result.rollback.attempted is False
    assert result.rollback.succeeded is None
    passwd = files.entries[tmp_path / "etc" / "passwd"]
    assert (passwd.mode, passwd.uid, passwd.gid) == (0o644, 0, 0)
    assert passwd.text == _PASSWD_CONTENT
    assert len(files.metadata_writes) == 1
    assert observed["inputs"].control_title.startswith("Ensure permissions")
    assert observed["inputs"].m4_report_path is None
    assert observed["request"].control_id == "7.1.1"
    assert observed["request"].mode is ExecutionMode.EXECUTE


@pytest.mark.parametrize(
    "bad_result",
    [
        _reproduction(reproduced=False),
        _reproduction(control_id="5.1.20"),
        _reproduction(target_path="/tmp/passwd"),
    ],
    ids=["not-reproduced", "wrong-control", "wrong-target"],
)
def test_invalid_reproduction_is_refused_before_m5(
    bad_result: SandboxPasswdReproductionResult,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        m5_validation,
        "load_validation_inputs",
        lambda *_args, **_kwargs: pytest.fail("invalid reproduction reached loader"),
    )
    monkeypatch.setattr(
        m5_validation,
        "SandboxValidator",
        lambda **_kwargs: pytest.fail("invalid reproduction reached M5"),
    )

    with pytest.raises(SandboxM5ValidationError):
        run_m5_validation_after_reproduction(bad_result, _authorization())


@pytest.mark.parametrize(
    ("missing_field", "values"),
    [
        (
            "administrator_approval_acknowledged",
            {
                "control_id": "7.1.1",
                "sandbox_operator_acknowledged": True,
                "compatibility_risk_acknowledged": False,
                "compatibility_override_reason": None,
                "compatibility_reference": _compatibility(),
            },
        ),
        (
            "sandbox_operator_acknowledged",
            {
                "control_id": "7.1.1",
                "administrator_approval_acknowledged": True,
                "compatibility_risk_acknowledged": False,
                "compatibility_override_reason": None,
                "compatibility_reference": _compatibility(),
            },
        ),
    ],
)
def test_authorization_requires_explicit_separate_acknowledgements(
    missing_field: str,
    values: dict[str, Any],
) -> None:
    assert missing_field not in values
    with pytest.raises(ValidationError):
        SandboxM5ValidationInput.model_validate(values)


@pytest.mark.parametrize(
    ("administrator_approval_acknowledged", "sandbox_operator_acknowledged"),
    [(False, True), (True, False)],
    ids=["missing-administrator-approval", "missing-operator-ack"],
)
def test_missing_approval_or_operator_ack_returns_m5_not_tested_without_mutation(
    administrator_approval_acknowledged: bool,
    sandbox_operator_acknowledged: bool,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report, observed, files = _run_refusal(
        monkeypatch,
        tmp_path,
        _authorization(
            administrator_approval_acknowledged=administrator_approval_acknowledged,
            sandbox_operator_acknowledged=sandbox_operator_acknowledged,
        ),
    )

    result = report.control_results[0]
    assert result.result is ValidationDecision.NOT_TESTED
    assert result.precheck.can_mutate is False
    assert result.precheck.administrator_approval_acknowledged is administrator_approval_acknowledged
    assert result.precheck.sandbox_operator_acknowledged is sandbox_operator_acknowledged
    assert result.remediation.attempted is False
    assert files.metadata_writes == []
    assert observed["request"].administrator_approval_acknowledged is administrator_approval_acknowledged
    assert observed["request"].sandbox_operator_acknowledged is sandbox_operator_acknowledged


@pytest.mark.parametrize(
    "decision",
    [CompatibilityDecision.WARNING, CompatibilityDecision.REVIEW_REQUIRED],
)
def test_warning_or_review_without_risk_ack_returns_not_tested(
    decision: CompatibilityDecision,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report, _, files = _run_refusal(
        monkeypatch,
        tmp_path,
        _authorization(decision=decision, compatibility_risk_acknowledged=False),
    )

    result = report.control_results[0]
    assert result.result is ValidationDecision.NOT_TESTED
    assert any("risk acknowledgement" in blocker for blocker in result.precheck.blockers)
    assert result.remediation.attempted is False
    assert files.metadata_writes == []


@pytest.mark.parametrize(
    ("risk_acknowledged", "override_reason"),
    [(False, None), (True, None)],
    ids=["missing-risk-ack", "missing-override-reason"],
)
def test_insufficient_evidence_requires_risk_ack_and_override(
    risk_acknowledged: bool,
    override_reason: str | None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report, _, files = _run_refusal(
        monkeypatch,
        tmp_path,
        _authorization(
            decision=CompatibilityDecision.INSUFFICIENT_EVIDENCE,
            compatibility_risk_acknowledged=risk_acknowledged,
            compatibility_override_reason=override_reason,
        ),
    )

    result = report.control_results[0]
    assert result.result is ValidationDecision.NOT_TESTED
    assert result.remediation.attempted is False
    assert files.metadata_writes == []


def test_insufficient_evidence_with_both_acknowledgements_reaches_m5(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report, _, files = _run_refusal(
        monkeypatch,
        tmp_path,
        _authorization(
            decision=CompatibilityDecision.INSUFFICIENT_EVIDENCE,
            compatibility_risk_acknowledged=True,
            compatibility_override_reason="Operator reviewed the evidence gap.",
        ),
    )

    result = report.control_results[0]
    assert result.result is ValidationDecision.VALIDATED
    assert result.precheck.compatibility_risk_acknowledged is True
    assert (
        result.precheck.compatibility_override_reason
        == "Operator reviewed the evidence gap."
    )
    assert files.metadata_writes == [(tmp_path / "etc" / "passwd", 0, 0, 0o644)]


def test_m4_control_mismatch_is_rejected_before_m5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad_authorization = SandboxM5ValidationInput.model_construct(
        control_id="7.1.1",
        administrator_approval_acknowledged=True,
        sandbox_operator_acknowledged=True,
        compatibility_risk_acknowledged=False,
        compatibility_override_reason=None,
        compatibility_reference=_compatibility(control_id="5.1.20"),
    )
    monkeypatch.setattr(
        m5_validation,
        "load_validation_inputs",
        lambda *_args, **_kwargs: pytest.fail("invalid M4 reference reached loader"),
    )

    with pytest.raises(SandboxM5ValidationError):
        run_m5_validation_after_reproduction(_reproduction(), bad_authorization)


def test_m5_validator_exception_is_not_converted_to_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = RuntimeError("M5 validator failure")

    class RefusingValidator:
        def __init__(self, *, context: AdapterContext) -> None:
            assert context.root == Path("/")

        def validate(self, *_args: Any, **_kwargs: Any) -> ValidationReport:
            raise error

    monkeypatch.setattr(m5_validation, "SandboxValidator", RefusingValidator)

    with pytest.raises(RuntimeError) as raised:
        run_m5_validation_after_reproduction(_reproduction(), _authorization())

    assert raised.value is error


def test_runner_reuses_existing_m5_and_adds_no_agent_or_execution_surface() -> None:
    source = _RUNTIME_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr)

    assert "src" in imported
    assert "src.agent" not in source
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "src.sandbox_validator.validator" in imported_modules
    assert "src.sandbox_validator.loaders" in imported_modules
    assert "src.sandbox_validator.adapters.base" in imported_modules
    assert not imported.intersection({"subprocess", "socket", "paramiko", "argparse"})
    assert not called.intersection(
        {"system", "eval", "exec", "fchown", "fchmod", "set_metadata"}
    )
    assert "SandboxValidator" in source
    assert "ValidationRequest" in source
    assert "load_validation_inputs(reproduced_control_id)" in source
    assert '_SUPPORTED_CONTROL_IDS = frozenset({"7.1.1", "3.3.1"})' in source
    assert "PasswdPermissionsAdapter" not in source
