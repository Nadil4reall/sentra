"""Coordinate local host detection and read-only target fact collection."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import platform
import shlex
import socket

import yaml

from .collectors import CollectionContext, collect_fact
from .command_runner import CommandRunner
from .fact_loader import DEFAULT_MANIFEST_PATH, load_required_facts
from .models import (
    FactResult,
    FactStatus,
    TargetInfo,
    TargetProfile,
    build_collection_summary,
)


SUPPORTED_SYSTEM = "Linux"
SUPPORTED_OS_ID = "ubuntu"
SUPPORTED_OS_VERSION = "24.04"
_SSH_ENVIRONMENT_KEYS = ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")


def _rooted_path(root: Path, target_path: str) -> Path:
    path = PurePosixPath(target_path)
    return root.joinpath(*path.parts[1:])


def _parse_os_release(text: str) -> dict[str, str]:
    """Parse os-release assignments as inert text, never as shell code."""

    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        if not key or not key.replace("_", "").isalnum():
            continue
        try:
            parsed = shlex.split(raw_value, comments=False, posix=True)
        except ValueError:
            continue
        if len(parsed) == 1:
            values[key] = parsed[0]
        elif not raw_value:
            values[key] = ""
    return values


def _platform_value(value: str | None, fallback: str) -> str:
    selected = value if value is not None else fallback
    return selected.strip() or "unknown"


def inspect_local_target(
    filesystem_root: str | Path = "/",
    *,
    system_name: str | None = None,
    hostname: str | None = None,
    kernel_release: str | None = None,
    architecture: str | None = None,
    platform_version: str | None = None,
) -> TargetInfo:
    """Inspect local identity and decide whether Ubuntu collectors are supported.

    Optional platform values exist for deterministic unit tests. The production CLI
    supplies none of them and therefore always inspects the machine it runs on.
    """

    root = Path(filesystem_root)
    detected_system = _platform_value(system_name, platform.system())
    detected_hostname = _platform_value(hostname, socket.gethostname())
    detected_kernel = _platform_value(kernel_release, platform.release())
    detected_architecture = _platform_value(architecture, platform.machine())
    fallback_version = _platform_value(platform_version, platform.version())

    if detected_system != SUPPORTED_SYSTEM:
        if detected_system == "Darwin":
            os_name = "macOS"
            if platform_version is None:
                os_version = platform.mac_ver()[0] or fallback_version
            else:
                os_version = fallback_version
        else:
            os_name = detected_system
            os_version = fallback_version
        return TargetInfo(
            hostname=detected_hostname,
            os=os_name,
            os_version=os_version,
            kernel=detected_kernel,
            architecture=detected_architecture,
            supported=False,
            reason="unsupported_operating_system",
        )

    os_release_path = _rooted_path(root, "/etc/os-release")
    try:
        os_release = _parse_os_release(
            os_release_path.read_text(encoding="utf-8", errors="replace")
        )
    except (OSError, UnicodeError):
        return TargetInfo(
            hostname=detected_hostname,
            os="Linux",
            os_version="",
            kernel=detected_kernel,
            architecture=detected_architecture,
            supported=False,
            reason="os_release_unavailable",
        )

    os_id = os_release.get("ID", "").casefold()
    os_version = os_release.get("VERSION_ID", "")
    if os_id == SUPPORTED_OS_ID:
        os_name = "Ubuntu"
    else:
        os_name = os_release.get("NAME") or os_release.get("ID") or "Linux"

    if os_id != SUPPORTED_OS_ID:
        supported = False
        reason = "unsupported_linux_distribution"
    elif os_version != SUPPORTED_OS_VERSION:
        supported = False
        reason = "unsupported_ubuntu_version"
    else:
        supported = True
        reason = None

    return TargetInfo(
        hostname=detected_hostname,
        os=os_name,
        os_version=os_version,
        kernel=detected_kernel,
        architecture=detected_architecture,
        supported=supported,
        reason=reason,
    )


def collect_local_profile(
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
    *,
    filesystem_root: str | Path = "/",
    runner: CommandRunner | None = None,
    environment: Mapping[str, str] | None = None,
    target: TargetInfo | None = None,
    collected_at: datetime | None = None,
) -> TargetProfile:
    """Collect every enrichment-requested fact from this local Ubuntu target."""

    required_facts = load_required_facts(manifest_path)
    root = Path(filesystem_root)
    target_info = target or inspect_local_target(root)
    facts: dict[str, FactResult] = {}

    if not target_info.supported:
        for required in required_facts:
            facts[required.name] = FactResult(
                name=required.name,
                status=FactStatus.UNSUPPORTED,
                value=None,
                requested_by=required.requested_by,
                reason="unsupported_target_operating_system",
            )
    else:
        if environment is None:
            # Only session-presence markers reach collectors; values are never
            # serialized. Other process environment, including secrets, is excluded.
            environment = {
                key: os.environ[key]
                for key in _SSH_ENVIRONMENT_KEYS
                if key in os.environ
            }
        context = CollectionContext(
            root=root,
            runner=runner or CommandRunner(),
            kernel_release=target_info.kernel,
            environment=environment,
        )
        for required in required_facts:
            facts[required.name] = collect_fact(required, context)

    timestamp = collected_at or datetime.now(timezone.utc)
    return TargetProfile(
        collected_at=timestamp,
        target=target_info,
        facts=facts,
        collection_summary=build_collection_summary(facts),
    )


def profile_to_yaml(profile: TargetProfile) -> str:
    """Serialize a validated profile without Python-specific YAML tags."""

    return yaml.safe_dump(
        profile.model_dump(mode="json"),
        sort_keys=False,
        allow_unicode=True,
    )


__all__ = [
    "collect_local_profile",
    "inspect_local_target",
    "profile_to_yaml",
]
