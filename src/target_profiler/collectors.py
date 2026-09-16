"""Read-only collectors for the Milestone 3 target facts.

The collectors in this module deliberately do not interpret or execute CIS audit
or remediation content.  Each collector reads a small, named piece of local
Ubuntu state, or invokes one of the exact read-only commands accepted by
``CommandRunner``.  Facts that need workload or administrator knowledge are
reported as unsupported rather than guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
import gzip
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import stat
from typing import Any, Callable, Mapping, Sequence

from .command_runner import CommandNotAllowedError, CommandResult, CommandRunner
from .models import FactResult, FactStatus, RequiredFact


_SSH_ENVIRONMENT_KEYS = ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")


def _session_environment() -> dict[str, str]:
    return {
        key: os.environ[key]
        for key in _SSH_ENVIRONMENT_KEYS
        if key in os.environ
    }


@dataclass(frozen=True, slots=True)
class Observation:
    """A collector result before the fact name and provenance are attached."""

    status: FactStatus
    value: Any | None = None
    reason: str | None = None


@dataclass(slots=True)
class CollectionContext:
    """Dependencies and local filesystem view used by collectors.

    ``root`` is injectable so tests can model an Ubuntu filesystem without
    reading the development host.  Absolute target paths are always resolved
    beneath this root.
    """

    root: Path = field(default_factory=lambda: Path("/"))
    runner: CommandRunner = field(default_factory=CommandRunner)
    kernel_release: str = field(default_factory=platform.release)
    environment: Mapping[str, str] = field(default_factory=_session_environment)
    _cache: dict[str, Any] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)

    def resolve(self, target_path: str | PurePosixPath) -> Path:
        path = PurePosixPath(target_path)
        if not path.is_absolute():
            raise ValueError(f"target path must be absolute: {path}")
        return self.root.joinpath(*path.parts[1:])


@dataclass(frozen=True, slots=True)
class _ReadResult:
    text: str | None = None
    error_kind: str | None = None
    reason: str | None = None


Collector = Callable[[CollectionContext], Observation]


def _collected(value: Any) -> Observation:
    return Observation(FactStatus.COLLECTED, value=value)


def _unavailable(reason: str) -> Observation:
    return Observation(FactStatus.UNAVAILABLE, reason=reason)


def _unsupported(reason: str) -> Observation:
    return Observation(FactStatus.UNSUPPORTED, reason=reason)


def _error(reason: str) -> Observation:
    return Observation(FactStatus.ERROR, reason=reason)


def _read_text(context: CollectionContext, target_path: str) -> _ReadResult:
    path = context.resolve(target_path)
    try:
        return _ReadResult(text=path.read_text(encoding="utf-8", errors="replace"))
    except PermissionError:
        return _ReadResult(
            error_kind="permission_denied",
            reason=f"permission denied while reading {target_path}",
        )
    except FileNotFoundError:
        return _ReadResult(
            error_kind="not_found", reason=f"target path is absent: {target_path}"
        )
    except OSError as exc:
        return _ReadResult(
            error_kind="io_error",
            reason=f"unable to read {target_path}: {exc.strerror or type(exc).__name__}",
        )


def _read_failure(result: _ReadResult) -> Observation:
    if result.error_kind in {"permission_denied", "not_found"}:
        return _unavailable(result.reason or "target data is unavailable")
    return _error(result.reason or "target data could not be read")


def _run(context: CollectionContext, argv: Sequence[str]) -> CommandResult | Observation:
    try:
        return context.runner.run(argv)
    except CommandNotAllowedError as exc:
        # This is a profiler programming/configuration failure, not target state.
        return _error(f"read-only command policy rejected collector request: {exc}")
    except OSError as exc:
        return _error(f"command runner failed: {exc.strerror or type(exc).__name__}")


def _command_failure(result: CommandResult, purpose: str) -> Observation:
    if result.error_kind == "permission_denied" or result.permission_denied:
        return _unavailable(f"permission denied while {purpose}")
    if result.error_kind == "not_found":
        return _unavailable(result.reason or f"command unavailable while {purpose}")
    if result.error_kind in {"timeout", "execution_error"}:
        return _error(result.reason or f"command failed while {purpose}")
    if result.reason:
        return _error(f"unable to {purpose}: {result.reason}")
    return _error(f"unable to {purpose} (exit status {result.returncode})")


# ---------------------------------------------------------------------------
# Kernel module facts


def _module_filename_matches(filename: str, module: str) -> bool:
    return bool(re.fullmatch(rf"{re.escape(module)}\.ko(?:\.(?:gz|xz|zst))?", filename))


def _module_available(context: CollectionContext, module: str) -> Observation:
    modules_root = context.resolve("/lib/modules")
    try:
        if not modules_root.is_dir():
            return _unavailable("installed kernel module metadata is unavailable")
        pending = [modules_root]
        while pending:
            directory = pending.pop()
            for candidate in directory.iterdir():
                metadata = candidate.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(candidate)
                elif _module_filename_matches(candidate.name, module):
                    if stat.S_ISREG(metadata.st_mode):
                        return _collected(True)
                    if stat.S_ISLNK(metadata.st_mode):
                        try:
                            target_metadata = candidate.stat()
                        except FileNotFoundError:
                            continue
                        except PermissionError:
                            return _unavailable(
                                "permission denied while resolving an installed "
                                "kernel module"
                            )
                        if stat.S_ISREG(target_metadata.st_mode):
                            return _collected(True)
        return _collected(False)
    except PermissionError:
        return _unavailable("permission denied while scanning installed kernel modules")
    except OSError as exc:
        return _error(
            "unable to scan installed kernel modules: "
            f"{exc.strerror or type(exc).__name__}"
        )


def _kernel_config(context: CollectionContext) -> _ReadResult:
    cache_key = "kernel_config"
    cached = context._cache.get(cache_key)
    if isinstance(cached, _ReadResult):
        return cached

    target_path = f"/boot/config-{context.kernel_release}"
    result = _read_text(context, target_path)
    if result.text is not None or result.error_kind == "permission_denied":
        context._cache[cache_key] = result
        return result

    compressed_path = context.resolve("/proc/config.gz")
    try:
        with gzip.open(compressed_path, mode="rt", encoding="utf-8", errors="replace") as fh:
            result = _ReadResult(text=fh.read())
    except PermissionError:
        result = _ReadResult(
            error_kind="permission_denied",
            reason="permission denied while reading /proc/config.gz",
        )
    except FileNotFoundError:
        result = _ReadResult(
            error_kind="not_found",
            reason=(
                f"kernel configuration is absent from {target_path} and /proc/config.gz"
            ),
        )
    except (OSError, EOFError) as exc:
        result = _ReadResult(
            error_kind="io_error",
            reason=f"unable to read /proc/config.gz: {type(exc).__name__}",
        )
    context._cache[cache_key] = result
    return result


def _module_precompiled(context: CollectionContext, symbol: str) -> Observation:
    result = _kernel_config(context)
    if result.text is None:
        return _read_failure(result)

    assignment = re.search(rf"(?m)^{re.escape(symbol)}=(?P<value>[ym])$", result.text)
    if assignment:
        return _collected(assignment.group("value") == "y")
    if re.search(rf"(?m)^# {re.escape(symbol)} is not set$", result.text):
        return _collected(False)
    return _unavailable(f"{symbol} is not represented in the available kernel configuration")


def _module_loaded(context: CollectionContext, module: str) -> Observation:
    result = _read_text(context, "/proc/modules")
    if result.text is None:
        return _read_failure(result)
    loaded = {
        line.split(maxsplit=1)[0]
        for line in result.text.splitlines()
        if line.strip()
    }
    return _collected(module in loaded)


def _module_loadable(context: CollectionContext, module: str) -> Observation:
    result = _run(context, ("modprobe", "-n", "--show-depends", module))
    if isinstance(result, Observation):
        return result
    combined = "\n".join((result.stdout, result.stderr)).lower()
    if result.succeeded:
        disabled = bool(
            re.search(r"(?:install\s+)?/(?:usr/)?bin/(?:false|true)(?:\s|$)", combined)
        )
        return _collected(not disabled)
    if result.error_kind not in {None, "nonzero_exit"}:
        return _command_failure(result, f"checking whether {module} is loadable")
    if "not found" in combined or "module not found" in combined:
        return _collected(False)
    return _command_failure(result, f"checking whether {module} is loadable")


def _configuration_blacklists_module(text: str, module: str) -> bool:
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if re.fullmatch(rf"blacklist\s+{re.escape(module)}(?:\s+.*)?", line):
            return True
    return False


def _modprobe_showconfig(
    context: CollectionContext,
) -> CommandResult | Observation:
    cache_key = "modprobe:showconfig"
    cached = context._cache.get(cache_key)
    if isinstance(cached, (CommandResult, Observation)):
        return cached
    result = _run(context, ("modprobe", "--showconfig"))
    context._cache[cache_key] = result
    return result


def _module_denylisted_from_files(
    context: CollectionContext, module: str
) -> Observation:
    # modprobe uses the first file with a given basename in this precedence
    # order, then reads the selected files in lexical order.  Mirroring that
    # rule avoids treating a shadowed lower-priority file as effective.
    directories = (
        "/etc/modprobe.d",
        "/run/modprobe.d",
        "/usr/local/lib/modprobe.d",
        "/usr/lib/modprobe.d",
        "/lib/modprobe.d",
    )
    selected_by_name: dict[str, tuple[str, Path]] = {}
    found_directory = False
    try:
        for target_directory in directories:
            directory = context.resolve(target_directory)
            try:
                metadata = directory.stat()
            except FileNotFoundError:
                continue
            except PermissionError:
                return _unavailable(
                    f"permission denied while scanning {target_directory}"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            found_directory = True
            try:
                candidates = sorted(
                    candidate
                    for candidate in directory.iterdir()
                    if fnmatch.fnmatchcase(candidate.name, "*.conf")
                )
            except PermissionError:
                return _unavailable(
                    f"permission denied while scanning {target_directory}"
                )
            for candidate in candidates:
                selected_by_name.setdefault(
                    candidate.name, (target_directory, candidate)
                )

        if not found_directory:
            return _unavailable("modprobe configuration directories are unavailable")

        for _basename, (target_directory, config) in sorted(selected_by_name.items()):
            try:
                text = config.read_text(encoding="utf-8", errors="replace")
            except PermissionError:
                return _unavailable(
                    f"permission denied while reading {target_directory}/{config.name}"
                )
            except FileNotFoundError:
                # Configuration can change during inspection.  Returning an
                # unavailable state avoids asserting a false deny-list result.
                return _unavailable(
                    f"modprobe configuration changed while reading "
                    f"{target_directory}/{config.name}"
                )
            if _configuration_blacklists_module(text, module):
                return _collected(True)
        return _collected(False)
    except PermissionError:
        return _unavailable("permission denied while scanning modprobe configuration")
    except OSError as exc:
        return _error(
            f"unable to scan modprobe configuration: "
            f"{exc.strerror or type(exc).__name__}"
        )


def _module_denylisted(context: CollectionContext, module: str) -> Observation:
    result = _modprobe_showconfig(context)
    if isinstance(result, Observation):
        return result
    if result.succeeded:
        return _collected(_configuration_blacklists_module(result.stdout, module))
    if result.error_kind != "not_found":
        return _command_failure(result, "reading effective modprobe configuration")
    return _module_denylisted_from_files(context, module)


def cramfs_filesystem_required(_context: CollectionContext) -> Observation:
    return _unsupported("filesystem requirements require workload-owner context")


def cramfs_module_available_in_installed_kernels(
    context: CollectionContext,
) -> Observation:
    return _module_available(context, "cramfs")


def cramfs_module_precompiled_into_kernel(context: CollectionContext) -> Observation:
    return _module_precompiled(context, "CONFIG_CRAMFS")


def cramfs_module_loaded(context: CollectionContext) -> Observation:
    return _module_loaded(context, "cramfs")


def cramfs_module_loadable(context: CollectionContext) -> Observation:
    return _module_loadable(context, "cramfs")


def cramfs_module_denylisted(context: CollectionContext) -> Observation:
    return _module_denylisted(context, "cramfs")


def overlayfs_module_available_in_installed_kernels(
    context: CollectionContext,
) -> Observation:
    # The Linux module is named ``overlay`` although the filesystem is
    # conventionally called overlayfs.
    return _module_available(context, "overlay")


def overlayfs_module_precompiled_into_kernel(context: CollectionContext) -> Observation:
    return _module_precompiled(context, "CONFIG_OVERLAY_FS")


def overlayfs_module_loaded(context: CollectionContext) -> Observation:
    return _module_loaded(context, "overlay")


def overlayfs_module_loadable(context: CollectionContext) -> Observation:
    return _module_loadable(context, "overlay")


def overlayfs_module_denylisted(context: CollectionContext) -> Observation:
    return _module_denylisted(context, "overlay")


_CONTAINER_PROCESS_NAMES: dict[str, str] = {
    "containerd": "containerd",
    "containerd-shim": "containerd",
    "conmon": "conmon",
    "crio": "cri-o",
    "dockerd": "docker",
    "kubelet": "kubernetes",
    "lxc-monitord": "lxc",
    "lxc-start": "lxc",
    "lxd": "lxd",
    "podman": "podman",
}


def container_applications_in_use(context: CollectionContext) -> Observation:
    proc_root = context.resolve("/proc")
    detected: set[str] = set()
    try:
        if not proc_root.is_dir():
            return _unavailable("process metadata is unavailable")
        for process_dir in proc_root.iterdir():
            if not process_dir.name.isdigit():
                continue
            try:
                process_name = (process_dir / "comm").read_text(
                    encoding="utf-8", errors="replace"
                ).strip()
            except FileNotFoundError:
                # Processes can terminate during a read-only scan.
                continue
            except PermissionError:
                return _unavailable(
                    "permission denied while enumerating container application processes"
                )
            application = _CONTAINER_PROCESS_NAMES.get(process_name)
            if application:
                detected.add(application)
        return _collected(sorted(detected))
    except PermissionError:
        return _unavailable("permission denied while enumerating processes")
    except OSError as exc:
        return _error(f"unable to enumerate processes: {exc.strerror or type(exc).__name__}")


# ---------------------------------------------------------------------------
# Network and firewall facts


def _proc_sys_integer(context: CollectionContext, target_path: str) -> Observation:
    result = _read_text(context, target_path)
    if result.text is None:
        return _read_failure(result)
    try:
        return _collected(int(result.text.strip()))
    except ValueError:
        return _error(f"unexpected non-integer value in {target_path}")


def ipv4_forwarding_status(context: CollectionContext) -> Observation:
    return _proc_sys_integer(context, "/proc/sys/net/ipv4/ip_forward")


def ipv6_enabled(context: CollectionContext) -> Observation:
    module_disable = _read_text(context, "/sys/module/ipv6/parameters/disable")
    if module_disable.text is not None:
        try:
            module_value = int(module_disable.text.strip())
        except ValueError:
            return _error(
                "unexpected non-integer value in "
                "/sys/module/ipv6/parameters/disable"
            )
        if module_value not in {0, 1}:
            return _error(
                "expected 0 or 1 in /sys/module/ipv6/parameters/disable"
            )
        if module_value == 1:
            return _collected(False)
    elif module_disable.error_kind != "not_found":
        return _read_failure(module_disable)

    paths = (
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    )
    values: list[int] = []
    for target_path in paths:
        observation = _proc_sys_integer(context, target_path)
        if observation.status is not FactStatus.COLLECTED:
            return observation
        if observation.value not in {0, 1}:
            return _error(f"expected 0 or 1 in {target_path}")
        values.append(observation.value)
    return _collected(not all(value == 1 for value in values))


def ipv6_forwarding_status(context: CollectionContext) -> Observation:
    return _proc_sys_integer(context, "/proc/sys/net/ipv6/conf/all/forwarding")


def router_role(_context: CollectionContext) -> Observation:
    return _unsupported("router role requires administrator or deployment context")


def csp_hosted(_context: CollectionContext) -> Observation:
    return _unsupported("cloud hosting cannot be inferred reliably from local read-only state")


def sysctl_parameter_sources(context: CollectionContext) -> Observation:
    # Highest precedence first.  A basename selected from a higher directory
    # shadows the same basename in all lower directories.
    directories = (
        "/etc/sysctl.d",
        "/run/sysctl.d",
        "/usr/local/lib/sysctl.d",
        "/usr/lib/sysctl.d",
    )
    sources: list[str] = []
    selected_by_name: dict[str, tuple[str, Path, os.stat_result]] = {}
    try:
        for target_directory in directories:
            directory = context.resolve(target_directory)
            try:
                metadata = directory.stat()
            except FileNotFoundError:
                continue
            except PermissionError:
                return _unavailable(
                    f"permission denied while enumerating {target_directory}"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            for candidate in directory.iterdir():
                if not fnmatch.fnmatchcase(candidate.name, "*.conf"):
                    continue
                try:
                    candidate_metadata = candidate.lstat()
                except FileNotFoundError:
                    return _unavailable(
                        f"sysctl configuration changed while scanning "
                        f"{target_directory}"
                    )
                except PermissionError:
                    return _unavailable(
                        f"permission denied while inspecting "
                        f"{target_directory}/{candidate.name}"
                    )
                selected_by_name.setdefault(
                    candidate.name,
                    (target_directory, candidate, candidate_metadata),
                )

        for _basename, (target_directory, config, metadata) in sorted(
            selected_by_name.items()
        ):
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    link_target = os.readlink(config)
                except FileNotFoundError:
                    return _unavailable(
                        f"sysctl configuration changed while reading "
                        f"{target_directory}/{config.name}"
                    )
                except PermissionError:
                    return _unavailable(
                        f"permission denied while resolving "
                        f"{target_directory}/{config.name}"
                    )
                if link_target == "/dev/null":
                    # This is the documented way to mask a vendor drop-in.
                    continue
                if PurePosixPath(link_target).is_absolute():
                    resolved_target = context.resolve(link_target)
                else:
                    resolved_target = config.parent / link_target
                normalized_target = resolved_target.resolve(strict=False)
                if normalized_target == context.resolve("/dev/null").resolve(
                    strict=False
                ):
                    continue
                if not normalized_target.is_relative_to(
                    context.root.resolve(strict=False)
                ):
                    return _error(
                        "sysctl configuration symlink resolved outside the "
                        "target filesystem root"
                    )
                try:
                    metadata = normalized_target.stat()
                except FileNotFoundError:
                    return _unavailable(
                        f"sysctl configuration symlink is broken: "
                        f"{target_directory}/{config.name}"
                    )
                except PermissionError:
                    return _unavailable(
                        f"permission denied while resolving "
                        f"{target_directory}/{config.name}"
                    )
            if stat.S_ISREG(metadata.st_mode):
                relative = config.relative_to(context.root)
                sources.append("/" + relative.as_posix())
        for target_path in ("/etc/sysctl.conf", "/etc/ufw/sysctl.conf"):
            config = context.resolve(target_path)
            try:
                if stat.S_ISREG(config.stat().st_mode):
                    sources.append(target_path)
            except FileNotFoundError:
                pass
            except PermissionError:
                return _unavailable(
                    f"permission denied while inspecting {target_path}"
                )
        return _collected(sources)
    except PermissionError:
        return _unavailable("permission denied while enumerating sysctl parameter sources")
    except OSError as exc:
        return _error(
            f"unable to enumerate sysctl parameter sources: {exc.strerror or type(exc).__name__}"
        )


def _installed_packages(context: CollectionContext) -> Observation:
    cached = context._cache.get("installed_packages")
    if isinstance(cached, Observation):
        return cached

    result = _read_text(context, "/var/lib/dpkg/status")
    if result.text is None:
        observation = _read_failure(result)
        context._cache["installed_packages"] = observation
        return observation

    installed: set[str] = set()
    try:
        for paragraph in re.split(r"\n\s*\n", result.text):
            fields: dict[str, str] = {}
            for line in paragraph.splitlines():
                if line[:1].isspace() or ":" not in line:
                    continue
                key, value = line.split(":", 1)
                fields[key] = value.strip()
            if (
                fields.get("Package")
                and fields.get("Status") == "install ok installed"
            ):
                installed.add(fields["Package"])
        observation = _collected(installed)
    except (TypeError, ValueError) as exc:
        observation = _error(f"unable to parse dpkg status metadata: {type(exc).__name__}")
    context._cache["installed_packages"] = observation
    return observation


def _package_installed(context: CollectionContext, package: str) -> Observation:
    packages = _installed_packages(context)
    if packages.status is not FactStatus.COLLECTED:
        return packages
    return _collected(package in packages.value)


def ufw_installed(context: CollectionContext) -> Observation:
    return _package_installed(context, "ufw")


def iptables_installed(context: CollectionContext) -> Observation:
    return _package_installed(context, "iptables")


def installed_firewall_utilities(context: CollectionContext) -> Observation:
    packages = _installed_packages(context)
    if packages.status is not FactStatus.COLLECTED:
        return packages
    candidates = ("ufw", "iptables", "nftables", "firewalld")
    return _collected([name for name in candidates if name in packages.value])


def _systemctl(
    context: CollectionContext, action: str, unit: str
) -> CommandResult | Observation:
    cache_key = f"systemctl:{action}:{unit}"
    cached = context._cache.get(cache_key)
    if isinstance(cached, (CommandResult, Observation)):
        return cached
    if action == "show-load-state":
        argv = ("systemctl", "show", "--property=LoadState", "--value", unit)
    else:
        argv = ("systemctl", action, unit)
    result = _run(context, argv)
    context._cache[cache_key] = result
    return result


def _systemctl_state(context: CollectionContext, action: str, unit: str) -> Observation:
    result = _systemctl(context, action, unit)
    if isinstance(result, Observation):
        return result
    if result.error_kind not in {None, "nonzero_exit"}:
        return _command_failure(result, f"reading {unit} {action} state")
    state = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    # is-active and is-enabled use non-zero return codes for legitimate states
    # such as inactive, disabled, static, and masked.
    if state:
        return _collected(state)
    return _command_failure(result, f"reading {unit} {action} state")


def _service_present(context: CollectionContext, unit: str) -> Observation:
    result = _systemctl(context, "show-load-state", unit)
    if isinstance(result, Observation):
        return result
    if result.error_kind not in {None, "nonzero_exit"}:
        return _command_failure(result, f"checking whether {unit} is present")
    load_state = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    if load_state:
        return _collected(load_state != "not-found")
    return _command_failure(result, f"checking whether {unit} is present")


def _service_mask_status(context: CollectionContext, unit: str) -> Observation:
    enabled = _systemctl_state(context, "is-enabled", unit)
    if enabled.status is not FactStatus.COLLECTED:
        return enabled
    state = str(enabled.value)
    return _collected("masked" if state.startswith("masked") else "not_masked")


def ufw_service_mask_status(context: CollectionContext) -> Observation:
    return _service_mask_status(context, "ufw.service")


def ufw_service_enabled(context: CollectionContext) -> Observation:
    return _systemctl_state(context, "is-enabled", "ufw.service")


def ufw_service_active(context: CollectionContext) -> Observation:
    return _systemctl_state(context, "is-active", "ufw.service")


def _ufw_status_result(context: CollectionContext) -> CommandResult | Observation:
    cached = context._cache.get("ufw_status_command")
    if isinstance(cached, (CommandResult, Observation)):
        return cached
    result = _run(context, ("ufw", "status"))
    context._cache["ufw_status_command"] = result
    return result


def _ufw_added_rules_result(
    context: CollectionContext,
) -> CommandResult | Observation:
    cached = context._cache.get("ufw_added_rules_command")
    if isinstance(cached, (CommandResult, Observation)):
        return cached
    result = _run(context, ("ufw", "show", "added"))
    context._cache["ufw_added_rules_command"] = result
    return result


def ufw_status(context: CollectionContext) -> Observation:
    result = _ufw_status_result(context)
    if isinstance(result, Observation):
        return result
    if not result.succeeded:
        return _command_failure(result, "reading UFW status")
    match = re.search(r"(?im)^Status:\s*(active|inactive)\s*$", result.stdout)
    if not match:
        return _error("UFW returned an unrecognized status response")
    return _collected(match.group(1).lower())


def _ssh_environment_active(context: CollectionContext) -> bool:
    return any(
        bool(context.environment.get(name))
        for name in _SSH_ENVIRONMENT_KEYS
    )


def remote_network_session_active(context: CollectionContext) -> Observation:
    # SSH is the only remote session mechanism implicated by the current PoC.
    # Only presence is recorded; connection addresses are never emitted.
    if _ssh_environment_active(context):
        return _collected(True)
    return _unsupported(
        "no SSH session marker was detected, but other remote session types "
        "cannot be excluded safely"
    )


def ssh_session_active(context: CollectionContext) -> Observation:
    if _ssh_environment_active(context):
        return _collected(True)
    return _unsupported(
        "no SSH session marker was detected; absence cannot be proven after "
        "environment filtering or privilege escalation"
    )


def _ufw_rule_target(tokens: list[str]) -> tuple[str | None, bool]:
    """Return a simple inbound allow target and whether the rule is ambiguous."""

    normalized = [token.casefold() for token in tokens]
    if normalized[:1] == ["ufw"]:
        normalized = normalized[1:]
    if not normalized or normalized[0] != "allow":
        return None, False
    normalized = normalized[1:]
    if normalized[:1] == ["out"]:
        return None, False
    if normalized[:1] == ["in"]:
        normalized = normalized[1:]
    if not normalized:
        return None, True

    if "out" in normalized:
        return None, False
    protocols = [
        normalized[index + 1]
        for index, token in enumerate(normalized[:-1])
        if token == "proto"
    ]
    protocol_set = set(protocols)
    if len(protocol_set) > 1 or any(
        protocol not in {"tcp", "udp"} for protocol in protocols
    ):
        return None, True
    if protocol_set == {"udp"}:
        return None, False

    if normalized[0] in {"22", "22/tcp", "openssh"}:
        return normalized[0], False
    has_port_22 = any(
        normalized[index : index + 2] == ["port", "22"]
        for index in range(len(normalized) - 1)
    )
    if has_port_22 and protocol_set == {"tcp"}:
        return "22/tcp", False
    # A complex inbound allow containing port 22 cannot safely be called absent
    # just because this deliberately narrow parser does not model the grammar.
    if has_port_22 or any(token in {"22", "22/tcp"} for token in normalized):
        return None, True
    return None, False


def _ufw_openssh_profile_is_tcp_22(context: CollectionContext) -> Observation:
    target_directory = "/etc/ufw/applications.d"
    directory = context.resolve(target_directory)
    try:
        try:
            metadata = directory.stat()
        except FileNotFoundError:
            return _unavailable("UFW application profile metadata is unavailable")
        except PermissionError:
            return _unavailable(
                f"permission denied while scanning {target_directory}"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            return _unavailable("UFW application profile metadata is unavailable")

        try:
            candidates = sorted(directory.iterdir())
        except PermissionError:
            return _unavailable(
                f"permission denied while scanning {target_directory}"
            )

        port_values: list[str] = []
        for config in candidates:
            try:
                text = config.read_text(encoding="utf-8", errors="replace")
            except IsADirectoryError:
                continue
            except FileNotFoundError:
                return _unavailable(
                    "UFW application profile metadata changed during inspection"
                )
            except PermissionError:
                return _unavailable(
                    f"permission denied while reading "
                    f"{target_directory}/{config.name}"
                )

            in_openssh_section = False
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    in_openssh_section = (
                        line[1:-1].strip().casefold() == "openssh"
                    )
                    continue
                if not in_openssh_section or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key.strip().casefold() == "ports":
                    port_values.append(value.strip().casefold())

        if not port_values:
            return _unavailable("the OpenSSH UFW application profile is unavailable")
        if len(set(port_values)) != 1:
            return _unavailable(
                "conflicting OpenSSH UFW application profile definitions were found"
            )
        if port_values[0] != "22/tcp":
            return _unavailable(
                "the OpenSSH UFW application profile could not be confirmed as 22/tcp"
            )
        return _collected(True)
    except PermissionError:
        return _unavailable("permission denied while reading UFW application profiles")
    except OSError as exc:
        return _error(
            "unable to inspect UFW application profiles: "
            f"{exc.strerror or type(exc).__name__}"
        )


def ufw_ssh_port_22_rule_present(context: CollectionContext) -> Observation:
    result = _ufw_added_rules_result(context)
    if isinstance(result, Observation):
        return result
    if not result.succeeded:
        return _command_failure(result, "reading configured UFW rules")

    openssh_rule_present = False
    ambiguous_rule_present = False
    for raw_line in result.stdout.splitlines():
        try:
            tokens = shlex.split(raw_line, comments=False, posix=True)
        except ValueError:
            if re.search(r"(?i)\ballow\b", raw_line):
                ambiguous_rule_present = True
            continue
        target, ambiguous = _ufw_rule_target(tokens)
        ambiguous_rule_present = ambiguous_rule_present or ambiguous
        if target in {"22", "22/tcp"}:
            return _collected(True)
        if target == "openssh":
            openssh_rule_present = True

    if openssh_rule_present:
        profile = _ufw_openssh_profile_is_tcp_22(context)
        if profile.status is FactStatus.COLLECTED and profile.value is True:
            return _collected(True)
        return profile
    if ambiguous_rule_present:
        return _unavailable(
            "a possible inbound UFW port 22 rule could not be interpreted safely"
        )
    return _collected(False)


# ---------------------------------------------------------------------------
# SSH and audit service facts


def ssh_installed(context: CollectionContext) -> Observation:
    return _package_installed(context, "openssh-server")


def ssh_service_status(context: CollectionContext) -> Observation:
    return _systemctl_state(context, "is-active", "ssh.service")


def _sshd_effective_settings(context: CollectionContext) -> Observation:
    cached = context._cache.get("sshd_effective_settings")
    if isinstance(cached, Observation):
        return cached
    result = _run(context, ("sshd", "-T"))
    if isinstance(result, Observation):
        context._cache["sshd_effective_settings"] = result
        return result
    if not result.succeeded:
        observation = _command_failure(result, "reading effective sshd configuration")
        context._cache["sshd_effective_settings"] = observation
        return observation
    settings: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.strip().partition(" ")
        if separator and key:
            settings[key.lower()] = value.strip()
    observation = _collected(settings)
    context._cache["sshd_effective_settings"] = observation
    return observation


def _sshd_setting(context: CollectionContext, name: str) -> Observation:
    settings = _sshd_effective_settings(context)
    if settings.status is not FactStatus.COLLECTED:
        return settings
    value = settings.value.get(name.lower())
    if value is None:
        return _unavailable(f"sshd -T did not report {name}")
    return _collected(value)


def sshd_permit_empty_passwords_effective(context: CollectionContext) -> Observation:
    return _sshd_setting(context, "permitemptypasswords")


def sshd_permit_root_login_effective(context: CollectionContext) -> Observation:
    return _sshd_setting(context, "permitrootlogin")


@dataclass(frozen=True, slots=True)
class _SshConfigScan:
    match_present: bool
    include_locations: tuple[str, ...]


def _parse_sshd_tokens(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError:
        # Let sshd -T surface syntax errors; structural scanning simply ignores
        # an incomplete line instead of guessing at it.
        return []


def _scan_sshd_configuration(context: CollectionContext) -> Observation:
    cached = context._cache.get("sshd_configuration_scan")
    if isinstance(cached, Observation):
        return cached

    root_config = context.resolve("/etc/ssh/sshd_config")
    pending = [root_config]
    visited: set[Path] = set()
    include_locations: list[str] = []
    match_present = False

    try:
        while pending:
            config = pending.pop(0)
            normalized = config.resolve(strict=False)
            resolved_root = context.root.resolve(strict=False)
            if not normalized.is_relative_to(resolved_root):
                observation = _error(
                    "sshd Include resolved outside the target filesystem root"
                )
                context._cache["sshd_configuration_scan"] = observation
                return observation
            if normalized in visited:
                continue
            visited.add(normalized)
            try:
                text = config.read_text(encoding="utf-8", errors="replace")
            except FileNotFoundError:
                if config == root_config:
                    observation = _unavailable("target path is absent: /etc/ssh/sshd_config")
                    context._cache["sshd_configuration_scan"] = observation
                    return observation
                continue
            except PermissionError:
                display_path = "/" + config.relative_to(context.root).as_posix()
                observation = _unavailable(
                    f"permission denied while reading {display_path}"
                )
                context._cache["sshd_configuration_scan"] = observation
                return observation

            for raw_line in text.splitlines():
                tokens = _parse_sshd_tokens(raw_line)
                if not tokens:
                    continue
                directive = tokens[0].lower()
                if directive == "match":
                    match_present = True
                elif directive == "include":
                    for location in tokens[1:]:
                        if location not in include_locations:
                            include_locations.append(location)
                        if PurePosixPath(location).is_absolute():
                            pattern = context.resolve(location)
                        else:
                            pattern = context.resolve("/etc/ssh") / location
                        if not pattern.parent.resolve(strict=False).is_relative_to(
                            resolved_root
                        ):
                            observation = _error(
                                "sshd Include resolved outside the target filesystem root"
                            )
                            context._cache["sshd_configuration_scan"] = observation
                            return observation
                        try:
                            matches = [
                                candidate
                                for candidate in pattern.parent.iterdir()
                                if fnmatch.fnmatchcase(candidate.name, pattern.name)
                            ]
                        except FileNotFoundError:
                            matches = []
                        pending.extend(sorted(matches))
        observation = _collected(
            _SshConfigScan(match_present, tuple(include_locations))
        )
    except PermissionError:
        observation = _unavailable("permission denied while scanning sshd configuration")
    except OSError as exc:
        observation = _error(
            f"unable to scan sshd configuration: {exc.strerror or type(exc).__name__}"
        )
    context._cache["sshd_configuration_scan"] = observation
    return observation


def sshd_match_directives_present(context: CollectionContext) -> Observation:
    scan = _scan_sshd_configuration(context)
    if scan.status is not FactStatus.COLLECTED:
        return scan
    return _collected(scan.value.match_present)


def sshd_include_locations_enabled(context: CollectionContext) -> Observation:
    scan = _scan_sshd_configuration(context)
    if scan.status is not FactStatus.COLLECTED:
        return scan
    return _collected(list(scan.value.include_locations))


def individual_administrator_account_available(
    _context: CollectionContext,
) -> Observation:
    return _unsupported(
        "administrator account suitability requires identity and authorization context"
    )


def root_escalation_path_available(_context: CollectionContext) -> Observation:
    return _unsupported(
        "root escalation availability requires authorization and policy context"
    )


def auditd_service_present(context: CollectionContext) -> Observation:
    return _service_present(context, "auditd.service")


def auditd_service_mask_status(context: CollectionContext) -> Observation:
    return _service_mask_status(context, "auditd.service")


def auditd_service_enabled(context: CollectionContext) -> Observation:
    return _systemctl_state(context, "is-enabled", "auditd.service")


def auditd_service_active(context: CollectionContext) -> Observation:
    return _systemctl_state(context, "is-active", "auditd.service")


# ---------------------------------------------------------------------------
# File metadata facts


def _file_stat(context: CollectionContext, target_path: str) -> os.stat_result | Observation:
    cache_key = f"stat:{target_path}"
    cached = context._cache.get(cache_key)
    if isinstance(cached, (os.stat_result, Observation)):
        return cached
    try:
        result: os.stat_result | Observation = context.resolve(target_path).stat()
    except PermissionError:
        result = _unavailable(f"permission denied while reading metadata for {target_path}")
    except FileNotFoundError:
        result = _unavailable(f"target path is absent: {target_path}")
    except OSError as exc:
        result = _error(
            f"unable to read metadata for {target_path}: "
            f"{exc.strerror or type(exc).__name__}"
        )
    context._cache[cache_key] = result
    return result


def _file_mode(context: CollectionContext, target_path: str) -> Observation:
    result = _file_stat(context, target_path)
    if isinstance(result, Observation):
        return result
    return _collected(format(stat.S_IMODE(result.st_mode), "04o"))


def _file_uid(context: CollectionContext, target_path: str) -> Observation:
    result = _file_stat(context, target_path)
    if isinstance(result, Observation):
        return result
    return _collected(result.st_uid)


def _file_gid(context: CollectionContext, target_path: str) -> Observation:
    result = _file_stat(context, target_path)
    if isinstance(result, Observation):
        return result
    return _collected(result.st_gid)


def passwd_file_mode(context: CollectionContext) -> Observation:
    return _file_mode(context, "/etc/passwd")


def passwd_file_owner_uid(context: CollectionContext) -> Observation:
    return _file_uid(context, "/etc/passwd")


def passwd_file_group_gid(context: CollectionContext) -> Observation:
    return _file_gid(context, "/etc/passwd")


def shadow_file_mode(context: CollectionContext) -> Observation:
    return _file_mode(context, "/etc/shadow")


def shadow_file_owner_uid(context: CollectionContext) -> Observation:
    return _file_uid(context, "/etc/shadow")


def shadow_file_group_gid(context: CollectionContext) -> Observation:
    return _file_gid(context, "/etc/shadow")


def shadow_group_gid(context: CollectionContext) -> Observation:
    result = _read_text(context, "/etc/group")
    if result.text is None:
        return _read_failure(result)
    for line in result.text.splitlines():
        if not line.startswith("shadow:"):
            continue
        fields = line.split(":")
        if len(fields) < 4:
            return _error("the shadow group entry in /etc/group is malformed")
        try:
            return _collected(int(fields[2]))
        except ValueError:
            return _error("the shadow group GID in /etc/group is not an integer")
    return _unavailable("the shadow group is not present in /etc/group")


# The registry is deliberately explicit: every fact requested by the current
# ten PoC enrichments has one and only one collector implementation.
COLLECTORS: dict[str, Collector] = {
    "cramfs_filesystem_required": cramfs_filesystem_required,
    "cramfs_module_available_in_installed_kernels": cramfs_module_available_in_installed_kernels,
    "cramfs_module_precompiled_into_kernel": cramfs_module_precompiled_into_kernel,
    "cramfs_module_loaded": cramfs_module_loaded,
    "cramfs_module_loadable": cramfs_module_loadable,
    "cramfs_module_denylisted": cramfs_module_denylisted,
    "overlayfs_module_available_in_installed_kernels": overlayfs_module_available_in_installed_kernels,
    "overlayfs_module_precompiled_into_kernel": overlayfs_module_precompiled_into_kernel,
    "overlayfs_module_loaded": overlayfs_module_loaded,
    "overlayfs_module_loadable": overlayfs_module_loadable,
    "overlayfs_module_denylisted": overlayfs_module_denylisted,
    "container_applications_in_use": container_applications_in_use,
    "ipv4_forwarding_status": ipv4_forwarding_status,
    "ipv6_enabled": ipv6_enabled,
    "ipv6_forwarding_status": ipv6_forwarding_status,
    "router_role": router_role,
    "csp_hosted": csp_hosted,
    "sysctl_parameter_sources": sysctl_parameter_sources,
    "ufw_installed": ufw_installed,
    "iptables_installed": iptables_installed,
    "installed_firewall_utilities": installed_firewall_utilities,
    "ufw_service_mask_status": ufw_service_mask_status,
    "ufw_service_enabled": ufw_service_enabled,
    "ufw_service_active": ufw_service_active,
    "ufw_status": ufw_status,
    "remote_network_session_active": remote_network_session_active,
    "ssh_session_active": ssh_session_active,
    "ufw_ssh_port_22_rule_present": ufw_ssh_port_22_rule_present,
    "ssh_installed": ssh_installed,
    "ssh_service_status": ssh_service_status,
    "sshd_permit_empty_passwords_effective": sshd_permit_empty_passwords_effective,
    "sshd_match_directives_present": sshd_match_directives_present,
    "sshd_include_locations_enabled": sshd_include_locations_enabled,
    "sshd_permit_root_login_effective": sshd_permit_root_login_effective,
    "individual_administrator_account_available": individual_administrator_account_available,
    "root_escalation_path_available": root_escalation_path_available,
    "auditd_service_present": auditd_service_present,
    "auditd_service_mask_status": auditd_service_mask_status,
    "auditd_service_enabled": auditd_service_enabled,
    "auditd_service_active": auditd_service_active,
    "passwd_file_mode": passwd_file_mode,
    "passwd_file_owner_uid": passwd_file_owner_uid,
    "passwd_file_group_gid": passwd_file_group_gid,
    "shadow_file_mode": shadow_file_mode,
    "shadow_file_owner_uid": shadow_file_owner_uid,
    "shadow_file_group_gid": shadow_file_group_gid,
    "shadow_group_gid": shadow_group_gid,
}


def collect_fact(
    required: RequiredFact | str,
    context: CollectionContext,
    requested_by: Sequence[str] = (),
) -> FactResult:
    """Collect one named fact and attach its requesting control IDs."""

    if isinstance(required, RequiredFact):
        name = required.name
        requesters = required.requested_by
    else:
        name = required
        requesters = requested_by
    collector = COLLECTORS.get(name)
    if collector is None:
        observation = _unsupported("no collector is registered for this fact")
    else:
        try:
            observation = collector(context)
        except PermissionError:
            observation = _unavailable("permission denied while collecting this fact")
        except Exception as exc:  # isolate one collector from the rest of a profile
            observation = _error(f"collector failed: {type(exc).__name__}: {exc}")
    return FactResult(
        name=name,
        status=observation.status,
        value=observation.value,
        requested_by=list(dict.fromkeys(requesters)),
        reason=observation.reason,
    )


__all__ = [
    "COLLECTORS",
    "CollectionContext",
    "Observation",
    "collect_fact",
]
