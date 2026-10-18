from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from src.sandbox_protocol import (
    IpForwardingSourceState,
    PasswdSourceState,
    SandboxContextManifest,
)
from src.sandbox_runtime import reproduction
from src.sandbox_runtime import ip_forwarding_runtime
from src.sandbox_runtime.reproduction import (
    SandboxIpForwardingReproductionResult,
    SandboxStateReproductionError,
    reproduce_ip_forwarding_source_state,
)


class FakeForwardingRuntime:
    def __init__(
        self,
        *,
        ipv4: int = 0,
        ipv6: int = 0,
        enabled: bool = True,
        fail_after_ipv4: int | None = None,
        fail_restore_ipv4: bool = False,
    ) -> None:
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.enabled = enabled
        self.fail_after_ipv4 = fail_after_ipv4
        self.fail_restore_ipv4 = fail_restore_ipv4
        self.events: list[tuple[str, int | None]] = []

    def ipv6_enabled(self) -> bool:
        self.events.append(("ipv6_enabled", None))
        return self.enabled

    def read_ipv4(self) -> int:
        self.events.append(("read_ipv4", None))
        return self.ipv4

    def read_ipv6(self) -> int:
        self.events.append(("read_ipv6", None))
        return self.ipv6

    def set_ipv4(self, value: int) -> None:
        self.events.append(("set_ipv4", value))
        if self.fail_restore_ipv4 and value == 0:
            raise OSError("test-only restoration failure")
        self.ipv4 = value
        if self.fail_after_ipv4 == value:
            self.fail_after_ipv4 = None
            raise OSError("test-only partial mutation")

    def set_ipv6(self, value: int) -> None:
        self.events.append(("set_ipv6", value))
        self.ipv6 = value


def _manifest(
    *,
    ipv4: int = 1,
    enabled: bool = True,
    ipv6: int | None = 1,
) -> SandboxContextManifest:
    return SandboxContextManifest(
        context_version="1",
        control_id="3.3.1",
        source_state=IpForwardingSourceState(
            ipv4_forwarding_status=ipv4,
            ipv6_enabled=enabled,
            ipv6_forwarding_status=ipv6,
        ),
    )


def test_forwarding_source_state_reproduces_both_fixed_runtime_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = FakeForwardingRuntime()
    monkeypatch.setattr(reproduction, "_FORWARDING_RUNTIME", runtime)

    result = reproduce_ip_forwarding_source_state(_manifest())

    assert result == SandboxIpForwardingReproductionResult(
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
    assert ("set_ipv4", 1) in runtime.events
    assert ("set_ipv6", 1) in runtime.events


def test_forwarding_source_state_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = FakeForwardingRuntime(ipv4=1, ipv6=1)
    monkeypatch.setattr(reproduction, "_FORWARDING_RUNTIME", runtime)

    result = reproduce_ip_forwarding_source_state(_manifest())

    assert result.reproduced is True
    assert all(not event[0].startswith("set_") for event in runtime.events)


def test_ipv6_disabled_reproduction_never_reads_or_mutates_ipv6(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = FakeForwardingRuntime(ipv4=0, enabled=False)
    monkeypatch.setattr(reproduction, "_FORWARDING_RUNTIME", runtime)

    result = reproduce_ip_forwarding_source_state(
        _manifest(ipv4=1, enabled=False, ipv6=None)
    )

    assert result.ipv6_enabled is False
    assert result.before_ipv6 is None
    assert result.requested_ipv6 is None
    assert result.after_ipv6 is None
    assert all("ipv6" not in event[0] for event in runtime.events if event[0] != "ipv6_enabled")


def test_ipv6_enablement_mismatch_refuses_before_any_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = FakeForwardingRuntime(enabled=True)
    monkeypatch.setattr(reproduction, "_FORWARDING_RUNTIME", runtime)

    with pytest.raises(SandboxStateReproductionError):
        reproduce_ip_forwarding_source_state(
            _manifest(ipv4=1, enabled=False, ipv6=None)
        )

    assert runtime.events == [("ipv6_enabled", None)]


def test_partial_runtime_mutation_is_rolled_back_and_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = FakeForwardingRuntime(fail_after_ipv4=1)
    monkeypatch.setattr(reproduction, "_FORWARDING_RUNTIME", runtime)

    with pytest.raises(SandboxStateReproductionError, match="reproduction failed"):
        reproduce_ip_forwarding_source_state(_manifest())

    assert runtime.ipv4 == 0
    assert ("set_ipv4", 0) in runtime.events
    assert runtime.events.count(("read_ipv4", None)) >= 2


def test_runtime_rollback_failure_is_not_hidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = FakeForwardingRuntime(
        fail_after_ipv4=1,
        fail_restore_ipv4=True,
    )
    monkeypatch.setattr(reproduction, "_FORWARDING_RUNTIME", runtime)

    with pytest.raises(SandboxStateReproductionError, match="rollback failed"):
        reproduce_ip_forwarding_source_state(_manifest())

    assert runtime.ipv4 == 1


def test_wrong_control_or_cross_paired_state_is_rejected_before_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = FakeForwardingRuntime()
    monkeypatch.setattr(reproduction, "_FORWARDING_RUNTIME", runtime)
    passwd = SandboxContextManifest(
        context_version="1",
        control_id="7.1.1",
        source_state=PasswdSourceState(
            passwd_file_mode="0644",
            passwd_file_owner_uid=0,
            passwd_file_group_gid=0,
        ),
    )

    with pytest.raises(SandboxStateReproductionError):
        reproduce_ip_forwarding_source_state(passwd)

    assert runtime.events == []


def test_public_forwarding_reproduction_accepts_only_manifest() -> None:
    assert list(inspect.signature(reproduce_ip_forwarding_source_state).parameters) == [
        "manifest"
    ]
    private = inspect.signature(
        reproduction._reproduce_ip_forwarding_source_state
    ).parameters
    assert list(private) == ["manifest", "runtime"]
    assert "path" not in private
    assert "command" not in private


def test_fixed_guest_backend_rejects_unlisted_path_before_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []

    def forbidden_open(path: str, _flags: int) -> int:
        opened.append(path)
        raise AssertionError("unexpected host file access")

    monkeypatch.setattr(ip_forwarding_runtime.os, "open", forbidden_open)
    with pytest.raises(ValueError, match="unsupported"):
        ip_forwarding_runtime._read_fixed_bit("/etc/passwd")
    with pytest.raises(ValueError, match="unsupported"):
        ip_forwarding_runtime._write_fixed_bit("/etc/passwd", 1)
    assert opened == []


def test_fixed_guest_backend_contains_no_shell_or_generic_execution() -> None:
    source = Path(ip_forwarding_runtime.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "shell=True" not in source
    assert "socket" not in source
    assert "ssh" not in source.casefold()
    assert "sandbox_validator" not in source
