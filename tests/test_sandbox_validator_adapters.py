"""Focused adapter tests using only injected, sandboxed fakes.

The fake filesystem refuses every path outside ``tmp_path``.  This is an
additional regression guard: a failing adapter test must never inspect or
mutate the developer machine's real /etc tree.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.sandbox_validator.adapters.base import (
    AdapterContext,
    FileSnapshot,
    UnsafePathError,
)
from src.sandbox_validator.adapters.passwd_permissions import (
    PasswdPermissionsAdapter,
)
from src.sandbox_validator.adapters.ssh_root_login import SshRootLoginAdapter
from src.sandbox_validator.adapters.ufw_service import UfwServiceAdapter
from src.sandbox_validator.command_runner import (
    CommandResult,
    MutationAction,
    MutationAuthorization,
    ReadAction,
)
from src.sandbox_validator.models import (
    ActionStatus,
    EvidenceStatus,
    ValidationDecision,
)


_PASSWD_TEXT = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
_SSHD_MAIN = "Include /etc/ssh/sshd_config.d/*.conf\n"


@dataclass(slots=True)
class _FakeFile:
    text: str
    mode: int
    uid: int
    gid: int
    device: int
    inode: int


class FakeFileOperations:
    """Small in-memory filesystem with a hard temporary-root boundary."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.entries: dict[Path, _FakeFile] = {}
        self.unsafe_paths: set[Path] = set()
        self.operations: list[tuple[str, Path]] = []
        self.metadata_writes: list[tuple[Path, int, int, int]] = []
        self._next_inode = 100
        self.wrong_first_metadata_write = False
        self.fail_reads_after_metadata_write: set[Path] = set()

    def _checked(self, path: Path) -> Path:
        path = Path(path)
        try:
            path.relative_to(self.root)
        except ValueError as exc:  # pragma: no cover - assertion guard
            raise AssertionError(f"test fake refused path outside sandbox: {path}") from exc
        return path

    def add_file(
        self,
        path: Path,
        *,
        text: str,
        mode: int = 0o644,
        uid: int = 0,
        gid: int = 0,
    ) -> None:
        path = self._checked(path)
        self._next_inode += 1
        self.entries[path] = _FakeFile(
            text=text,
            mode=mode,
            uid=uid,
            gid=gid,
            device=1,
            inode=self._next_inode,
        )

    def mark_unsafe(self, path: Path) -> None:
        self.unsafe_paths.add(self._checked(path))

    def _entry(self, path: Path) -> _FakeFile:
        path = self._checked(path)
        if path in self.unsafe_paths:
            raise UnsafePathError(f"refusing symbolic link: {path}")
        try:
            return self.entries[path]
        except KeyError as exc:
            raise FileNotFoundError(path) from exc

    @staticmethod
    def _assert_identity(entry: _FakeFile, expected: FileSnapshot) -> None:
        if (entry.device, entry.inode) != (expected.device, expected.inode):
            raise UnsafePathError("file identity changed")

    def snapshot(self, path: Path) -> FileSnapshot:
        path = self._checked(path)
        self.operations.append(("snapshot", path))
        entry = self._entry(path)
        return FileSnapshot(
            mode=entry.mode,
            uid=entry.uid,
            gid=entry.gid,
            device=entry.device,
            inode=entry.inode,
            size=len(entry.text.encode("utf-8")),
        )

    def read_text(self, path: Path, *, max_bytes: int) -> str:
        path = self._checked(path)
        self.operations.append(("read_text", path))
        entry = self._entry(path)
        if path in self.fail_reads_after_metadata_write and self.metadata_writes:
            raise OSError("injected post-change read failure")
        if len(entry.text.encode("utf-8")) > max_bytes:
            raise OSError("fake file exceeds inspection limit")
        return entry.text

    def make_private_directory(self, path: Path) -> None:
        path = self._checked(path)
        self.operations.append(("make_private_directory", path))

    def backup_file(
        self, source: Path, destination: Path, expected: FileSnapshot
    ) -> None:
        source = self._checked(source)
        destination = self._checked(destination)
        self.operations.append(("backup_file", destination))
        entry = self._entry(source)
        self._assert_identity(entry, expected)
        self.add_file(
            destination,
            text=entry.text,
            mode=entry.mode,
            uid=entry.uid,
            gid=entry.gid,
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
        self.operations.append(("set_metadata", path))
        entry = self._entry(path)
        self._assert_identity(entry, expected)
        self.metadata_writes.append((path, uid, gid, mode))
        if self.wrong_first_metadata_write and len(self.metadata_writes) == 1:
            entry.uid, entry.gid, entry.mode = 0, 0, 0o600
        else:
            entry.uid, entry.gid, entry.mode = uid, gid, mode

    def atomic_write_text(
        self,
        path: Path,
        content: str,
        *,
        uid: int,
        gid: int,
        mode: int,
    ) -> None:
        path = self._checked(path)
        self.operations.append(("atomic_write_text", path))
        self.add_file(path, text=content, mode=mode, uid=uid, gid=gid)

    def remove_file(self, path: Path) -> None:
        path = self._checked(path)
        self.operations.append(("remove_file", path))
        self._entry(path)
        del self.entries[path]


def _result(
    action: ReadAction | MutationAction,
    *,
    stdout: str = "",
    returncode: int = 0,
) -> CommandResult:
    error_kind = None if returncode == 0 else "nonzero_exit"
    return CommandResult(
        action=action.value,
        kind="read" if isinstance(action, ReadAction) else "mutation",
        argv=("/fake/sentra-command", action.value),
        returncode=returncode,
        stdout=stdout,
        stderr="" if returncode == 0 else "injected failure",
        error_kind=error_kind,
        reason=None if returncode == 0 else "command_returned_nonzero",
    )


class FakeCommandRunner:
    """Return queued fixed-action results and record mutation attempts."""

    def __init__(self) -> None:
        self._reads: dict[ReadAction, deque[CommandResult]] = defaultdict(deque)
        self._read_counts: dict[ReadAction, int] = defaultdict(int)
        self.raise_on_read_calls: dict[ReadAction, set[int]] = defaultdict(set)
        self.read_actions: list[ReadAction] = []
        self.mutation_actions: list[MutationAction] = []
        self.mutation_result = _result(MutationAction.SSH_SERVICE_RELOAD)

    def set_reads(self, action: ReadAction, *results: CommandResult) -> None:
        if not results:
            raise ValueError("at least one fake result is required")
        self._reads[action] = deque(results)

    def run_read(self, action: ReadAction) -> CommandResult:
        self.read_actions.append(action)
        self._read_counts[action] += 1
        if self._read_counts[action] in self.raise_on_read_calls[action]:
            raise RuntimeError(f"injected {action.value} read failure")
        results = self._reads.get(action)
        if not results:
            raise AssertionError(f"unexpected read action: {action.value}")
        # Keep the final response reusable for stable checks and rollback audits.
        return results.popleft() if len(results) > 1 else results[0]

    def run_mutation(
        self,
        action: MutationAction,
        authorization: MutationAuthorization,
    ) -> CommandResult:
        self.mutation_actions.append(action)
        if not authorization.allows(action):
            raise AssertionError(f"fake received unauthorized action: {action.value}")
        return self.mutation_result


def _context(tmp_path: Path) -> tuple[AdapterContext, FakeFileOperations, FakeCommandRunner]:
    files = FakeFileOperations(tmp_path)
    runner = FakeCommandRunner()
    context = AdapterContext(
        root=tmp_path,
        files=files,
        runner=runner,
        clock=lambda: datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )
    return context, files, runner


def _passwd_context(
    tmp_path: Path,
    *,
    mode: int = 0o664,
    uid: int = 1000,
    gid: int = 1000,
) -> tuple[AdapterContext, FakeFileOperations, FakeCommandRunner]:
    context, files, runner = _context(tmp_path)
    files.add_file(
        context.resolve("/etc/passwd"),
        text=_PASSWD_TEXT,
        mode=mode,
        uid=uid,
        gid=gid,
    )
    return context, files, runner


def _passwd_authorization() -> MutationAuthorization:
    return MutationAuthorization(control_id="7.1.1", allowed_actions=frozenset())


def test_passwd_pre_audit_uses_injected_filesystem(tmp_path: Path) -> None:
    context, files, runner = _passwd_context(tmp_path, mode=0o640, uid=42, gid=43)

    evidence = PasswdPermissionsAdapter().pre_audit(context)

    assert {item.name: item.value for item in evidence} == {
        "passwd_file_mode": "0640",
        "passwd_file_owner_uid": 42,
        "passwd_file_group_gid": 43,
    }
    assert all(item.status is EvidenceStatus.COLLECTED for item in evidence)
    assert runner.read_actions == []
    assert {path for _, path in files.operations} == {tmp_path / "etc/passwd"}


def test_passwd_successful_simulated_remediation(tmp_path: Path) -> None:
    context, files, runner = _passwd_context(tmp_path)
    adapter = PasswdPermissionsAdapter()
    pre_audit = adapter.pre_audit(context)

    outcome = adapter.execute(context, pre_audit, _passwd_authorization())

    final = files.entries[context.resolve("/etc/passwd")]
    assert outcome.decision is ValidationDecision.VALIDATED
    assert outcome.remediation.attempted is True
    assert outcome.remediation.changed is True
    assert outcome.remediation.succeeded is True
    assert (final.mode, final.uid, final.gid) == (0o644, 0, 0)
    assert outcome.remediation.backups[0].created is True
    assert outcome.rollback.attempted is False
    assert [action.status for action in outcome.remediation.actions] == [
        ActionStatus.APPLIED,
        ActionStatus.APPLIED,
        ActionStatus.APPLIED,
    ]
    assert runner.mutation_actions == []


def test_passwd_failed_post_audit_is_failed_and_rolls_back(tmp_path: Path) -> None:
    context, files, _ = _passwd_context(tmp_path, mode=0o666, uid=1001, gid=1002)
    files.wrong_first_metadata_write = True
    adapter = PasswdPermissionsAdapter()
    pre_audit = adapter.pre_audit(context)

    outcome = adapter.execute(context, pre_audit, _passwd_authorization())

    final = files.entries[context.resolve("/etc/passwd")]
    assert outcome.decision is ValidationDecision.FAILED
    assert outcome.remediation.succeeded is False
    assert "required post-state was not observed" in outcome.errors
    assert outcome.rollback.attempted is True
    assert outcome.rollback.succeeded is True
    assert (final.mode, final.uid, final.gid) == (0o666, 1001, 1002)


def test_passwd_required_health_failure_restores_original_metadata(
    tmp_path: Path,
) -> None:
    context, files, _ = _passwd_context(tmp_path, mode=0o660, uid=123, gid=456)
    passwd_path = context.resolve("/etc/passwd")
    files.fail_reads_after_metadata_write.add(passwd_path)
    adapter = PasswdPermissionsAdapter()

    outcome = adapter.execute(
        context, adapter.pre_audit(context), _passwd_authorization()
    )

    final = files.entries[passwd_path]
    assert outcome.decision is ValidationDecision.FAILED
    assert "required health check failed" in outcome.errors
    assert outcome.rollback.attempted is True
    assert outcome.rollback.succeeded is True
    assert (final.mode, final.uid, final.gid) == (0o660, 123, 456)
    assert files.metadata_writes[-1] == (passwd_path, 123, 456, 0o660)


def test_passwd_unexpected_health_exception_is_failed_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, files, _ = _passwd_context(tmp_path, mode=0o664, uid=1001, gid=1002)
    passwd_path = context.resolve("/etc/passwd")
    adapter = PasswdPermissionsAdapter()

    def fail_health_check(_context: AdapterContext) -> list:
        raise RuntimeError("injected passwd health failure")

    monkeypatch.setattr(
        "src.sandbox_validator.adapters.passwd_permissions.check_passwd_health",
        fail_health_check,
    )

    outcome = adapter.execute(
        context, adapter.pre_audit(context), _passwd_authorization()
    )

    final = files.entries[passwd_path]
    assert outcome.decision is ValidationDecision.FAILED
    assert outcome.remediation.changed is True
    assert outcome.rollback.attempted is True
    assert outcome.rollback.succeeded is True
    assert (final.mode, final.uid, final.gid) == (0o664, 1001, 1002)
    assert outcome.errors[0] == "RuntimeError: injected passwd health failure"


@pytest.mark.parametrize(
    "logical_path",
    ["etc/passwd", "/etc/../passwd", "/etc/passwd\x00replacement"],
)
def test_adapter_context_rejects_unsafe_arbitrary_paths(
    tmp_path: Path, logical_path: str
) -> None:
    context, _, _ = _context(tmp_path)

    with pytest.raises(UnsafePathError):
        context.resolve(logical_path)


def test_passwd_symlink_like_target_is_refused_before_mutation(tmp_path: Path) -> None:
    context, files, runner = _passwd_context(tmp_path)
    passwd_path = context.resolve("/etc/passwd")
    files.mark_unsafe(passwd_path)
    adapter = PasswdPermissionsAdapter()
    pre_audit = adapter.pre_audit(context)

    outcome = adapter.execute(context, pre_audit, _passwd_authorization())

    mutating_operations = {
        "make_private_directory",
        "backup_file",
        "set_metadata",
        "atomic_write_text",
        "remove_file",
    }
    assert all(item.status is EvidenceStatus.ERROR for item in pre_audit)
    assert outcome.decision is ValidationDecision.NOT_TESTED
    assert outcome.remediation.attempted is False
    assert not any(name in mutating_operations for name, _ in files.operations)
    assert runner.mutation_actions == []


def _configure_ssh_runner_for_syntax_failure(runner: FakeCommandRunner) -> None:
    runner.set_reads(
        ReadAction.SSH_PACKAGE_STATUS,
        _result(ReadAction.SSH_PACKAGE_STATUS, stdout="install ok installed"),
    )
    runner.set_reads(
        ReadAction.SSH_SERVICE_ACTIVE,
        _result(ReadAction.SSH_SERVICE_ACTIVE, stdout="active\n"),
    )
    runner.set_reads(
        ReadAction.SSH_SERVICE_CAN_RELOAD,
        _result(ReadAction.SSH_SERVICE_CAN_RELOAD, stdout="yes\n"),
    )
    runner.set_reads(
        ReadAction.SSHD_SYNTAX,
        _result(ReadAction.SSHD_SYNTAX),
        _result(ReadAction.SSHD_SYNTAX, returncode=1),
        _result(ReadAction.SSHD_SYNTAX),
    )
    runner.set_reads(
        ReadAction.SSHD_EFFECTIVE,
        _result(ReadAction.SSHD_EFFECTIVE, stdout="permitrootlogin prohibit-password\n"),
        _result(ReadAction.SSHD_EFFECTIVE, stdout="permitrootlogin no\n"),
        _result(ReadAction.SSHD_EFFECTIVE, stdout="permitrootlogin prohibit-password\n"),
    )


def _configure_ssh_runner_for_guarded_success(runner: FakeCommandRunner) -> None:
    runner.set_reads(
        ReadAction.SSH_PACKAGE_STATUS,
        _result(ReadAction.SSH_PACKAGE_STATUS, stdout="install ok installed"),
    )
    runner.set_reads(
        ReadAction.SSH_SERVICE_ACTIVE,
        _result(ReadAction.SSH_SERVICE_ACTIVE, stdout="active\n"),
    )
    runner.set_reads(
        ReadAction.SSH_SERVICE_CAN_RELOAD,
        _result(ReadAction.SSH_SERVICE_CAN_RELOAD, stdout="yes\n"),
    )
    runner.set_reads(
        ReadAction.SSHD_SYNTAX,
        *[_result(ReadAction.SSHD_SYNTAX) for _ in range(4)],
    )
    runner.set_reads(
        ReadAction.SSHD_EFFECTIVE,
        _result(ReadAction.SSHD_EFFECTIVE, stdout="permitrootlogin prohibit-password\n"),
        _result(ReadAction.SSHD_EFFECTIVE, stdout="permitrootlogin no\n"),
        _result(ReadAction.SSHD_EFFECTIVE, stdout="permitrootlogin no\n"),
        _result(ReadAction.SSHD_EFFECTIVE, stdout="permitrootlogin prohibit-password\n"),
    )


def _guarded_ssh_context(
    tmp_path: Path,
) -> tuple[
    AdapterContext,
    FakeFileOperations,
    FakeCommandRunner,
    SshRootLoginAdapter,
    list,
    MutationAuthorization,
]:
    context, files, runner = _context(tmp_path)
    context.environment = {"SSH_CONNECTION": "fixture-client fixture-server"}
    context.resolve("/etc/ssh/sshd_config.d").mkdir(parents=True)
    files.add_file(context.resolve("/etc/ssh/sshd_config"), text=_SSHD_MAIN)
    _configure_ssh_runner_for_guarded_success(runner)
    adapter = SshRootLoginAdapter()
    pre_audit = adapter.pre_audit(context)
    authorization = MutationAuthorization(
        control_id="5.1.20",
        allowed_actions=frozenset({MutationAction.SSH_SERVICE_RELOAD}),
    )
    return context, files, runner, adapter, pre_audit, authorization


def test_ssh_syntax_failure_prevents_reload_and_removes_candidate(
    tmp_path: Path,
) -> None:
    context, files, runner = _context(tmp_path)
    context.environment = {"SSH_CONNECTION": "client server"}
    context.resolve("/etc/ssh/sshd_config.d").mkdir(parents=True)
    files.add_file(context.resolve("/etc/ssh/sshd_config"), text=_SSHD_MAIN)
    _configure_ssh_runner_for_syntax_failure(runner)
    adapter = SshRootLoginAdapter()
    pre_audit = adapter.pre_audit(context)
    authorization = MutationAuthorization(
        control_id="5.1.20",
        allowed_actions=frozenset({MutationAction.SSH_SERVICE_RELOAD}),
    )

    outcome = adapter.execute(context, pre_audit, authorization)

    target = context.resolve(adapter.target)
    by_action = {item.action_id: item for item in outcome.remediation.actions}
    assert outcome.decision is ValidationDecision.FAILED
    assert by_action["validate-sshd-syntax"].status is ActionStatus.FAILED
    assert by_action["reload-ssh-service"].status is ActionStatus.SKIPPED
    assert runner.mutation_actions == []
    assert target not in files.entries
    assert outcome.rollback.attempted is True
    assert outcome.rollback.succeeded is True
    assert any("reload was not attempted" in error for error in outcome.errors)


@pytest.mark.parametrize("stdout", ["", "sometimes\n", "yes\nno\n"])
def test_ssh_empty_or_malformed_reload_capability_is_structured_error(
    tmp_path: Path,
    stdout: str,
) -> None:
    context, files, runner = _context(tmp_path)
    files.add_file(context.resolve("/etc/ssh/sshd_config"), text=_SSHD_MAIN)
    runner.set_reads(
        ReadAction.SSH_PACKAGE_STATUS,
        _result(ReadAction.SSH_PACKAGE_STATUS, stdout="install ok installed"),
    )
    runner.set_reads(
        ReadAction.SSH_SERVICE_ACTIVE,
        _result(ReadAction.SSH_SERVICE_ACTIVE, stdout="active\n"),
    )
    runner.set_reads(
        ReadAction.SSH_SERVICE_CAN_RELOAD,
        _result(ReadAction.SSH_SERVICE_CAN_RELOAD, stdout=stdout),
    )
    runner.set_reads(ReadAction.SSHD_SYNTAX, _result(ReadAction.SSHD_SYNTAX))
    runner.set_reads(
        ReadAction.SSHD_EFFECTIVE,
        _result(ReadAction.SSHD_EFFECTIVE, stdout="permitrootlogin prohibit-password\n"),
    )

    evidence = SshRootLoginAdapter().pre_audit(context)
    reload_evidence = next(
        item for item in evidence if item.name == "ssh_service_reload_supported"
    )

    assert reload_evidence.status is EvidenceStatus.ERROR
    assert reload_evidence.value is None
    assert reload_evidence.reason == (
        "systemctl returned an unrecognized SSH reload capability"
    )


def test_ssh_failed_reload_capability_command_with_empty_output_is_structured(
    tmp_path: Path,
) -> None:
    context, files, runner = _context(tmp_path)
    files.add_file(context.resolve("/etc/ssh/sshd_config"), text=_SSHD_MAIN)
    runner.set_reads(
        ReadAction.SSH_PACKAGE_STATUS,
        _result(ReadAction.SSH_PACKAGE_STATUS, stdout="install ok installed"),
    )
    runner.set_reads(
        ReadAction.SSH_SERVICE_ACTIVE,
        _result(ReadAction.SSH_SERVICE_ACTIVE, stdout="active\n"),
    )
    runner.set_reads(
        ReadAction.SSH_SERVICE_CAN_RELOAD,
        _result(ReadAction.SSH_SERVICE_CAN_RELOAD, returncode=1),
    )
    runner.set_reads(ReadAction.SSHD_SYNTAX, _result(ReadAction.SSHD_SYNTAX))
    runner.set_reads(
        ReadAction.SSHD_EFFECTIVE,
        _result(ReadAction.SSHD_EFFECTIVE, stdout="permitrootlogin prohibit-password\n"),
    )

    evidence = SshRootLoginAdapter().pre_audit(context)
    reload_evidence = next(
        item for item in evidence if item.name == "ssh_service_reload_supported"
    )

    assert reload_evidence.status is EvidenceStatus.ERROR
    assert reload_evidence.reason == "command_returned_nonzero"


def test_ssh_unexpected_failure_before_target_mutation_is_not_tested(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, files, runner, adapter, pre_audit, authorization = _guarded_ssh_context(
        tmp_path
    )
    target = context.resolve(adapter.target)
    original_snapshot = files.snapshot

    def fail_target_snapshot(path: Path) -> FileSnapshot:
        if path == target:
            raise RuntimeError("injected pre-mutation failure")
        return original_snapshot(path)

    monkeypatch.setattr(files, "snapshot", fail_target_snapshot)

    outcome = adapter.execute(context, pre_audit, authorization)

    assert outcome.decision is ValidationDecision.NOT_TESTED
    assert outcome.remediation.attempted is False
    assert outcome.remediation.changed is False
    assert outcome.rollback.attempted is False
    assert target not in files.entries
    assert runner.mutation_actions == []
    assert outcome.errors == ["RuntimeError: injected pre-mutation failure"]


def test_ssh_exception_after_candidate_write_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, files, runner, adapter, pre_audit, authorization = _guarded_ssh_context(
        tmp_path
    )
    target = context.resolve(adapter.target)
    original_write = files.atomic_write_text

    def write_then_fail(path: Path, content: str, **metadata: int) -> None:
        original_write(path, content, **metadata)
        raise RuntimeError("injected failure after write")

    monkeypatch.setattr(files, "atomic_write_text", write_then_fail)

    outcome = adapter.execute(context, pre_audit, authorization)

    assert outcome.decision is ValidationDecision.FAILED
    assert outcome.remediation.attempted is True
    assert outcome.remediation.changed is True
    assert outcome.remediation.succeeded is False
    assert outcome.rollback.attempted is True
    assert outcome.rollback.succeeded is True
    assert target not in files.entries
    assert runner.mutation_actions == []
    assert outcome.errors[0] == "RuntimeError: injected failure after write"


def test_ssh_exception_during_post_write_audit_rolls_back(
    tmp_path: Path,
) -> None:
    context, files, runner, adapter, pre_audit, authorization = _guarded_ssh_context(
        tmp_path
    )
    target = context.resolve(adapter.target)
    runner.raise_on_read_calls[ReadAction.SSH_PACKAGE_STATUS].add(2)

    outcome = adapter.execute(context, pre_audit, authorization)

    assert outcome.decision is ValidationDecision.FAILED
    assert outcome.rollback.succeeded is True
    assert target not in files.entries
    assert runner.mutation_actions == []
    assert outcome.errors[0] == (
        "RuntimeError: injected ssh_package_status read failure"
    )


def test_ssh_exception_during_health_check_rolls_back_and_reloads_restored_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, files, runner, adapter, pre_audit, authorization = _guarded_ssh_context(
        tmp_path
    )
    target = context.resolve(adapter.target)

    def fail_health_check(_post_audit: list) -> list:
        raise RuntimeError("injected SSH health failure")

    monkeypatch.setattr(
        "src.sandbox_validator.adapters.ssh_root_login.check_ssh_health",
        fail_health_check,
    )

    outcome = adapter.execute(context, pre_audit, authorization)

    assert outcome.decision is ValidationDecision.FAILED
    assert outcome.rollback.succeeded is True
    assert target not in files.entries
    assert runner.mutation_actions == [
        MutationAction.SSH_SERVICE_RELOAD,
        MutationAction.SSH_SERVICE_RELOAD,
    ]
    assert outcome.errors[0] == "RuntimeError: injected SSH health failure"


def test_ssh_emergency_rollback_exception_is_contained(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, files, runner, adapter, pre_audit, authorization = _guarded_ssh_context(
        tmp_path
    )
    target = context.resolve(adapter.target)
    runner.raise_on_read_calls[ReadAction.SSH_PACKAGE_STATUS].add(2)

    def fail_remove(_path: Path) -> None:
        raise RuntimeError("injected rollback failure")

    monkeypatch.setattr(files, "remove_file", fail_remove)

    outcome = adapter.execute(context, pre_audit, authorization)

    assert outcome.decision is ValidationDecision.FAILED
    assert outcome.rollback.attempted is True
    assert outcome.rollback.succeeded is False
    assert target in files.entries
    assert outcome.errors[0] == (
        "RuntimeError: injected ssh_package_status read failure"
    )
    assert outcome.errors[1] == "rollback_error: RuntimeError: injected rollback failure"


@pytest.mark.parametrize(
    ("enabled", "active", "ufw_status", "environment"),
    [
        ("enabled", "active", "active", {"SSH_CONNECTION": "client server"}),
        ("disabled", "inactive", "inactive", {}),
    ],
)
def test_ufw_adapter_is_always_not_tested_and_never_mutates(
    tmp_path: Path,
    enabled: str,
    active: str,
    ufw_status: str,
    environment: dict[str, str],
) -> None:
    context, files, runner = _context(tmp_path)
    context.environment = environment
    runner.set_reads(
        ReadAction.UFW_SERVICE_ENABLED,
        _result(ReadAction.UFW_SERVICE_ENABLED, stdout=f"{enabled}\n"),
    )
    runner.set_reads(
        ReadAction.UFW_SERVICE_ACTIVE,
        _result(ReadAction.UFW_SERVICE_ACTIVE, stdout=f"{active}\n"),
    )
    runner.set_reads(
        ReadAction.UFW_STATUS,
        _result(ReadAction.UFW_STATUS, stdout=f"Status: {ufw_status}\n"),
    )
    runner.set_reads(
        ReadAction.UFW_ADDED_RULES,
        _result(ReadAction.UFW_ADDED_RULES, stdout="ufw allow 22/tcp\n"),
    )
    adapter = UfwServiceAdapter()
    pre_audit = adapter.pre_audit(context)

    outcome = adapter.execute(
        context,
        pre_audit,
        MutationAuthorization(control_id="4.2.3", allowed_actions=frozenset()),
    )

    assert pre_audit
    assert outcome.decision is ValidationDecision.NOT_TESTED
    assert outcome.remediation.supported is False
    assert outcome.remediation.attempted is False
    assert outcome.remediation.changed is False
    assert all(not action.mutating for action in outcome.remediation.actions)
    assert files.operations == []
    assert runner.mutation_actions == []
