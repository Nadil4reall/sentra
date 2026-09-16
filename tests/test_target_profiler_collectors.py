"""Focused tests for the read-only Milestone 3 fact collectors."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

import pytest

from src.target_profiler.collectors import (
    COLLECTORS,
    CollectionContext,
    collect_fact,
)
from src.target_profiler.command_runner import CommandResult
from src.target_profiler.fact_loader import load_required_facts
from src.target_profiler.models import FactStatus, RequiredFact


class FakeRunner:
    def __init__(self, responses: dict[tuple[str, ...], CommandResult] | None = None):
        self.responses = responses or {}
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str]) -> CommandResult:
        command = tuple(argv)
        self.calls.append(command)
        return self.responses.get(
            command,
            CommandResult(
                argv=command,
                returncode=None,
                stdout="",
                stderr="",
                error_kind="not_found",
                reason="command_not_found",
            ),
        )


def command_result(
    argv: tuple[str, ...],
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    error_kind: str | None = None,
    reason: str | None = None,
) -> CommandResult:
    return CommandResult(
        argv=argv,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        error_kind=error_kind,  # type: ignore[arg-type]
        reason=reason,
    )


@pytest.fixture
def ubuntu_root(tmp_path: Path) -> Path:
    files = {
        "boot/config-test-kernel": "CONFIG_CRAMFS=y\nCONFIG_OVERLAY_FS=m\n",
        "proc/modules": "overlay 151552 1 - Live 0x0\n",
        "proc/1/comm": "dockerd\n",
        "proc/sys/net/ipv4/ip_forward": "0\n",
        "proc/sys/net/ipv6/conf/all/disable_ipv6": "0\n",
        "proc/sys/net/ipv6/conf/default/disable_ipv6": "0\n",
        "proc/sys/net/ipv6/conf/all/forwarding": "1\n",
        "etc/modprobe.d/cramfs.conf": "blacklist cramfs\n",
        "etc/sysctl.d/99-sentra-test.conf": "net.ipv4.ip_forward=0\n",
        "etc/sysctl.conf": "# test fixture\n",
        "etc/ufw/sysctl.conf": "net/ipv4/ip_forward=0\n",
        "etc/ufw/applications.d/openssh-server": "[OpenSSH]\nports=22/tcp\n",
        "etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n",
        "etc/ssh/sshd_config.d/10-test.conf": "Match User example\n",
        "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
        "etc/shadow": "root:*:19793:0:99999:7:::\n",
        "etc/group": "root:x:0:\nshadow:x:42:\n",
        "var/lib/dpkg/status": (
            "Package: ufw\nStatus: install ok installed\n\n"
            "Package: iptables\nStatus: install ok installed\n\n"
            "Package: openssh-server\nStatus: install ok installed\n"
        ),
    }
    for relative_path, content in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    for relative_path in (
        "lib/modules/test-kernel/kernel/fs/cramfs/cramfs.ko.xz",
        "lib/modules/test-kernel/kernel/fs/overlayfs/overlay.ko.zst",
    ):
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()

    (tmp_path / "etc/passwd").chmod(0o644)
    (tmp_path / "etc/shadow").chmod(0o640)
    return tmp_path


def populated_runner() -> FakeRunner:
    responses: dict[tuple[str, ...], CommandResult] = {}
    for module, output in (
        ("cramfs", "install /bin/false\n"),
        ("overlay", "insmod /lib/modules/test/overlay.ko\n"),
    ):
        argv = ("modprobe", "-n", "--show-depends", module)
        responses[argv] = command_result(argv, stdout=output)

    service_states = {
        ("systemctl", "is-enabled", "ufw.service"): (1, "masked\n"),
        ("systemctl", "is-active", "ufw.service"): (0, "active\n"),
        ("systemctl", "is-active", "ssh.service"): (0, "active\n"),
        ("systemctl", "is-enabled", "auditd.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "auditd.service"): (3, "inactive\n"),
    }
    for argv, (returncode, stdout) in service_states.items():
        responses[argv] = command_result(
            argv,
            returncode=returncode,
            stdout=stdout,
            error_kind="nonzero_exit" if returncode else None,
            reason="command_returned_nonzero" if returncode else None,
        )
    show_auditd = (
        "systemctl",
        "show",
        "--property=LoadState",
        "--value",
        "auditd.service",
    )
    responses[show_auditd] = command_result(show_auditd, stdout="loaded\n")

    ufw = ("ufw", "status")
    responses[ufw] = command_result(
        ufw,
        stdout="Status: active\n\nTo Action From\n22/tcp ALLOW Anywhere\n",
    )
    ufw_added = ("ufw", "show", "added")
    responses[ufw_added] = command_result(
        ufw_added,
        stdout="Added user rules:\nufw allow 22/tcp\n",
    )
    sshd = ("sshd", "-T")
    responses[sshd] = command_result(
        sshd,
        stdout="permitemptypasswords no\npermitrootlogin prohibit-password\n",
    )
    return FakeRunner(responses)


def test_registry_exactly_covers_every_requested_fact() -> None:
    discovered = {fact.name for fact in load_required_facts()}
    assert len(discovered) == 47
    assert set(COLLECTORS) == discovered


def test_all_collectors_return_valid_fact_results(ubuntu_root: Path) -> None:
    context = CollectionContext(
        root=ubuntu_root,
        runner=populated_runner(),  # type: ignore[arg-type]
        kernel_release="test-kernel",
        environment={},
    )

    results = [collect_fact(fact, context) for fact in load_required_facts()]

    assert len(results) == 47
    assert {result.name for result in results} == set(COLLECTORS)
    assert all(result.status in FactStatus for result in results)
    assert all(result.requested_by for result in results)


def test_representative_values_are_derived_from_fixture(ubuntu_root: Path) -> None:
    context = CollectionContext(
        root=ubuntu_root,
        runner=populated_runner(),  # type: ignore[arg-type]
        kernel_release="test-kernel",
        environment={"SSH_CONNECTION": "fixture-value-is-never-emitted"},
    )

    def value(name: str):
        result = collect_fact(
            RequiredFact(name=name, requested_by=["1.1.1.1"]), context
        )
        assert result.status == FactStatus.COLLECTED
        return result.value

    assert value("cramfs_module_available_in_installed_kernels") is True
    assert value("cramfs_module_precompiled_into_kernel") is True
    assert value("overlayfs_module_precompiled_into_kernel") is False
    assert value("overlayfs_module_loaded") is True
    assert value("cramfs_module_loadable") is False
    assert value("cramfs_module_denylisted") is True
    assert value("container_applications_in_use") == ["docker"]
    assert value("ipv4_forwarding_status") == 0
    assert value("ipv6_enabled") is True
    assert value("sysctl_parameter_sources") == [
        "/etc/sysctl.d/99-sentra-test.conf",
        "/etc/sysctl.conf",
        "/etc/ufw/sysctl.conf",
    ]
    assert value("installed_firewall_utilities") == ["ufw", "iptables"]
    assert value("ufw_service_mask_status") == "masked"
    assert value("ufw_status") == "active"
    assert value("ufw_ssh_port_22_rule_present") is True
    assert value("sshd_permit_empty_passwords_effective") == "no"
    assert value("sshd_match_directives_present") is True
    assert value("sshd_include_locations_enabled") == [
        "/etc/ssh/sshd_config.d/*.conf"
    ]
    assert value("passwd_file_mode") == "0644"
    assert value("shadow_file_mode") == "0640"
    assert value("shadow_group_gid") == 42


def test_permission_failure_is_unavailable_and_never_false(ubuntu_root: Path) -> None:
    argv = ("ufw", "show", "added")
    runner = FakeRunner(
        {
            argv: command_result(
                argv,
                returncode=1,
                stderr="permission denied",
                error_kind="permission_denied",
                reason="permission_denied",
            )
        }
    )
    result = collect_fact(
        RequiredFact(name="ufw_ssh_port_22_rule_present", requested_by=["4.2.3"]),
        CollectionContext(root=ubuntu_root, runner=runner),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.UNAVAILABLE
    assert result.value is None
    assert result.reason


@pytest.mark.parametrize(
    ("all_value", "default_value", "expected"),
    [
        ("0", "0", True),
        ("0", "1", True),
        ("1", "0", True),
        ("1", "1", False),
    ],
)
def test_ipv6_enabled_uses_all_and_default_disable_flags(
    ubuntu_root: Path, all_value: str, default_value: str, expected: bool
) -> None:
    (ubuntu_root / "proc/sys/net/ipv6/conf/all/disable_ipv6").write_text(
        all_value, encoding="utf-8"
    )
    (ubuntu_root / "proc/sys/net/ipv6/conf/default/disable_ipv6").write_text(
        default_value, encoding="utf-8"
    )

    result = collect_fact(
        RequiredFact(name="ipv6_enabled", requested_by=["3.3.1"]),
        CollectionContext(root=ubuntu_root, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value is expected


def test_ipv6_module_disable_proves_disabled_without_proc_flags(
    tmp_path: Path,
) -> None:
    parameter = tmp_path / "sys/module/ipv6/parameters/disable"
    parameter.parent.mkdir(parents=True)
    parameter.write_text("1\n", encoding="utf-8")

    result = collect_fact(
        RequiredFact(name="ipv6_enabled", requested_by=["3.3.1"]),
        CollectionContext(root=tmp_path, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value is False


@pytest.mark.parametrize(("invalid_path", "invalid_value"), [("sys", "2"), ("proc", "x")])
def test_ipv6_enabled_rejects_malformed_boolean_parameters(
    ubuntu_root: Path, invalid_path: str, invalid_value: str
) -> None:
    if invalid_path == "sys":
        parameter = ubuntu_root / "sys/module/ipv6/parameters/disable"
        parameter.parent.mkdir(parents=True)
    else:
        parameter = ubuntu_root / "proc/sys/net/ipv6/conf/default/disable_ipv6"
    parameter.write_text(invalid_value, encoding="utf-8")

    result = collect_fact(
        RequiredFact(name="ipv6_enabled", requested_by=["3.3.1"]),
        CollectionContext(root=ubuntu_root, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.ERROR
    assert result.value is None


def test_ipv6_enabled_propagates_missing_default_flag(ubuntu_root: Path) -> None:
    (ubuntu_root / "proc/sys/net/ipv6/conf/default/disable_ipv6").unlink()

    result = collect_fact(
        RequiredFact(name="ipv6_enabled", requested_by=["3.3.1"]),
        CollectionContext(root=ubuntu_root, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.UNAVAILABLE
    assert result.value is None


def test_sysctl_sources_propagate_ufw_config_permission_error(
    ubuntu_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protected_path = ubuntu_root / "etc/ufw/sysctl.conf"
    original_stat = Path.stat

    def permission_aware_stat(self: Path, *args: object, **kwargs: object):
        if self == protected_path:
            raise PermissionError("fixture permission denial")
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", permission_aware_stat)
    result = collect_fact(
        RequiredFact(name="sysctl_parameter_sources", requested_by=["3.3.1"]),
        CollectionContext(root=ubuntu_root, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.UNAVAILABLE
    assert result.value is None


def test_sysctl_sources_do_not_hide_conf_file_permission_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protected_path = tmp_path / "etc/sysctl.d/protected.conf"
    protected_path.parent.mkdir(parents=True)
    protected_path.write_text("net.ipv4.ip_forward=0\n", encoding="utf-8")
    original_lstat = Path.lstat

    def permission_aware_lstat(self: Path, *args: object, **kwargs: object):
        if self == protected_path:
            raise PermissionError("fixture permission denial")
        return original_lstat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", permission_aware_lstat)
    result = collect_fact(
        RequiredFact(name="sysctl_parameter_sources", requested_by=["3.3.1"]),
        CollectionContext(root=tmp_path, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.UNAVAILABLE
    assert result.value is None


def test_sysctl_sources_apply_basename_precedence_and_dev_null_masks(
    tmp_path: Path,
) -> None:
    vendor_override = tmp_path / "usr/lib/sysctl.d/50-override.conf"
    admin_override = tmp_path / "etc/sysctl.d/50-override.conf"
    vendor_masked = tmp_path / "usr/lib/sysctl.d/60-masked.conf"
    admin_mask = tmp_path / "etc/sysctl.d/60-masked.conf"
    for path in (vendor_override, admin_override, vendor_masked):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("net.ipv4.ip_forward=0\n", encoding="utf-8")
    admin_mask.symlink_to("/dev/null")

    result = collect_fact(
        RequiredFact(name="sysctl_parameter_sources", requested_by=["3.3.1"]),
        CollectionContext(root=tmp_path, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value == ["/etc/sysctl.d/50-override.conf"]


def test_dangling_kernel_module_symlink_is_not_available(tmp_path: Path) -> None:
    candidate = tmp_path / "lib/modules/test/kernel/fs/cramfs/cramfs.ko"
    candidate.parent.mkdir(parents=True)
    candidate.symlink_to(candidate.parent / "missing.ko")

    result = collect_fact(
        RequiredFact(
            name="cramfs_module_available_in_installed_kernels",
            requested_by=["1.1.1.1"],
        ),
        CollectionContext(root=tmp_path, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value is False


def test_modprobe_showconfig_is_authoritative(ubuntu_root: Path) -> None:
    argv = ("modprobe", "--showconfig")
    runner = FakeRunner(
        {argv: command_result(argv, stdout="blacklist overlay\n")}
    )
    context = CollectionContext(root=ubuntu_root, runner=runner)  # type: ignore[arg-type]

    overlay = collect_fact(
        RequiredFact(
            name="overlayfs_module_denylisted", requested_by=["1.1.1.6"]
        ),
        context,
    )
    cramfs = collect_fact(
        RequiredFact(name="cramfs_module_denylisted", requested_by=["1.1.1.1"]),
        context,
    )

    assert overlay.status == FactStatus.COLLECTED
    assert overlay.value is True
    # The lower-level fixture file must not override successful effective output.
    assert cramfs.status == FactStatus.COLLECTED
    assert cramfs.value is False
    assert runner.calls.count(argv) == 1


def test_modprobe_file_fallback_includes_run_directory(tmp_path: Path) -> None:
    config = tmp_path / "run/modprobe.d/overlay.conf"
    config.parent.mkdir(parents=True)
    config.write_text("blacklist overlay\n", encoding="utf-8")

    result = collect_fact(
        RequiredFact(
            name="overlayfs_module_denylisted", requested_by=["1.1.1.6"]
        ),
        CollectionContext(root=tmp_path, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value is True


def test_modprobe_file_fallback_honors_directory_precedence(tmp_path: Path) -> None:
    high = tmp_path / "etc/modprobe.d/same-name.conf"
    low = tmp_path / "lib/modprobe.d/same-name.conf"
    high.parent.mkdir(parents=True)
    low.parent.mkdir(parents=True)
    high.write_text("# intentionally no blacklist\n", encoding="utf-8")
    low.write_text("blacklist cramfs\n", encoding="utf-8")

    result = collect_fact(
        RequiredFact(name="cramfs_module_denylisted", requested_by=["1.1.1.1"]),
        CollectionContext(root=tmp_path, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value is False


def test_modprobe_fallback_permission_error_is_not_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protected = tmp_path / "run/modprobe.d"
    protected.mkdir(parents=True)
    original_iterdir = Path.iterdir

    def permission_aware_iterdir(self: Path):
        if self == protected:
            raise PermissionError("fixture permission denial")
        return original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", permission_aware_iterdir)
    result = collect_fact(
        RequiredFact(name="cramfs_module_denylisted", requested_by=["1.1.1.1"]),
        CollectionContext(root=tmp_path, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.UNAVAILABLE
    assert result.value is None


@pytest.mark.parametrize("rule", ["ufw allow 22", "ufw allow 22/tcp", "ufw allow in 22/tcp"])
def test_ufw_added_numeric_ssh_rules_are_detected(
    ubuntu_root: Path, rule: str
) -> None:
    argv = ("ufw", "show", "added")
    runner = FakeRunner({argv: command_result(argv, stdout=f"{rule}\n")})

    result = collect_fact(
        RequiredFact(
            name="ufw_ssh_port_22_rule_present", requested_by=["4.2.3"]
        ),
        CollectionContext(root=ubuntu_root, runner=runner),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value is True


def test_ufw_added_cis_tcp_port_22_rule_is_detected(ubuntu_root: Path) -> None:
    argv = ("ufw", "show", "added")
    runner = FakeRunner(
        {
            argv: command_result(
                argv,
                stdout="ufw allow proto tcp from any to any port 22\n",
            )
        }
    )
    result = collect_fact(
        RequiredFact(
            name="ufw_ssh_port_22_rule_present", requested_by=["4.2.3"]
        ),
        CollectionContext(root=ubuntu_root, runner=runner),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value is True


def test_ufw_added_udp_port_22_rule_is_not_ssh_evidence(
    ubuntu_root: Path,
) -> None:
    argv = ("ufw", "show", "added")
    runner = FakeRunner(
        {
            argv: command_result(
                argv,
                stdout="ufw allow proto udp from any to any port 22\n",
            )
        }
    )
    result = collect_fact(
        RequiredFact(
            name="ufw_ssh_port_22_rule_present", requested_by=["4.2.3"]
        ),
        CollectionContext(root=ubuntu_root, runner=runner),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value is False


def test_ufw_added_openssh_rule_requires_confirmed_profile(
    ubuntu_root: Path,
) -> None:
    argv = ("ufw", "show", "added")
    runner = FakeRunner(
        {argv: command_result(argv, stdout="ufw allow OpenSSH\n")}
    )
    result = collect_fact(
        RequiredFact(
            name="ufw_ssh_port_22_rule_present", requested_by=["4.2.3"]
        ),
        CollectionContext(root=ubuntu_root, runner=runner),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value is True


def test_ufw_added_openssh_rule_is_unavailable_when_profile_is_not_tcp_22(
    ubuntu_root: Path,
) -> None:
    (ubuntu_root / "etc/ufw/applications.d/openssh-server").write_text(
        "[OpenSSH]\nports=2222/tcp\n", encoding="utf-8"
    )
    argv = ("ufw", "show", "added")
    runner = FakeRunner(
        {argv: command_result(argv, stdout="ufw allow OpenSSH\n")}
    )
    result = collect_fact(
        RequiredFact(
            name="ufw_ssh_port_22_rule_present", requested_by=["4.2.3"]
        ),
        CollectionContext(root=ubuntu_root, runner=runner),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.UNAVAILABLE
    assert result.value is None


def test_ufw_added_outbound_openssh_rule_is_not_inbound_evidence(
    ubuntu_root: Path,
) -> None:
    argv = ("ufw", "show", "added")
    runner = FakeRunner(
        {argv: command_result(argv, stdout="ufw allow out OpenSSH\n")}
    )
    result = collect_fact(
        RequiredFact(
            name="ufw_ssh_port_22_rule_present", requested_by=["4.2.3"]
        ),
        CollectionContext(root=ubuntu_root, runner=runner),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.COLLECTED
    assert result.value is False


@pytest.mark.parametrize(
    "name",
    [
        "cramfs_filesystem_required",
        "router_role",
        "csp_hosted",
        "individual_administrator_account_available",
        "root_escalation_path_available",
    ],
)
def test_semantically_unsafe_inferences_are_explicitly_unsupported(name: str) -> None:
    result = collect_fact(
        RequiredFact(name=name, requested_by=["1.1.1.1"]),
        CollectionContext(runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.UNSUPPORTED
    assert result.value is None
    assert result.reason


@pytest.mark.parametrize(
    "name", ["remote_network_session_active", "ssh_session_active"]
)
def test_session_facts_do_not_invent_false(name: str) -> None:
    result = collect_fact(
        RequiredFact(name=name, requested_by=["4.2.3"]),
        CollectionContext(environment={}, runner=FakeRunner()),  # type: ignore[arg-type]
    )

    assert result.status == FactStatus.UNSUPPORTED
    assert result.value is None
