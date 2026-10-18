"""Reproduce only allowlisted source state inside the disposable sandbox guest."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from typing import Literal, Protocol

from src.sandbox_protocol import (
    IpForwardingSourceState,
    PasswdSourceState,
    SandboxContextManifest,
)
from .ip_forwarding_runtime import SystemForwardingRuntime


SANDBOX_PASSWD_TARGET_PATH = "/etc/passwd"
_CONTROL_ID: Literal["7.1.1"] = "7.1.1"
_MODE_PATTERN = re.compile(r"[0-7]{4}\Z")
_FIXED_ERROR_MESSAGE = "sandbox source-state reproduction failed"
_FIXED_ROLLBACK_MESSAGE = "sandbox source-state rollback failed"


class SandboxStateReproductionError(RuntimeError):
    """Fixed, non-sensitive failure for source-state reproduction."""


@dataclass(frozen=True, slots=True)
class SandboxPasswdReproductionResult:
    """Immutable metadata-only record of a successful source-state replay."""

    control_id: Literal["7.1.1"]
    target_path: Literal["/etc/passwd"]
    before_mode: str
    before_uid: int
    before_gid: int
    requested_mode: str
    requested_uid: int
    requested_gid: int
    after_mode: str
    after_uid: int
    after_gid: int
    reproduced: bool


@dataclass(frozen=True, slots=True)
class SandboxIpForwardingReproductionResult:
    """Only before/requested/after forwarding facts; no paths or payloads."""

    control_id: Literal["3.3.1"]
    before_ipv4: int
    requested_ipv4: int
    after_ipv4: int
    ipv6_enabled: bool
    before_ipv6: int | None
    requested_ipv6: int | None
    after_ipv6: int | None
    reproduced: bool


class _ForwardingRuntime(Protocol):
    """Fixed forwarding observations and actions, never caller-supplied argv."""

    def ipv6_enabled(self) -> bool: ...

    def read_ipv4(self) -> int: ...

    def read_ipv6(self) -> int: ...

    def set_ipv4(self, value: int) -> None: ...

    def set_ipv6(self, value: int) -> None: ...


_FORWARDING_RUNTIME: _ForwardingRuntime = SystemForwardingRuntime()


@dataclass(frozen=True, slots=True)
class _MetadataSnapshot:
    mode: int
    uid: int
    gid: int


class _MetadataFilesystem(Protocol):
    """Narrow fd-only metadata operations; no content read/write methods."""

    def open(self, path: str, flags: int) -> int: ...

    def fstat(self, descriptor: int) -> os.stat_result: ...

    def fchown(self, descriptor: int, uid: int, gid: int) -> None: ...

    def fchmod(self, descriptor: int, mode: int) -> None: ...

    def close(self, descriptor: int) -> None: ...


_FILESYSTEM: _MetadataFilesystem = os


def _validated_source_values(
    manifest: SandboxContextManifest,
) -> tuple[str, int, int, int]:
    if type(manifest) is not SandboxContextManifest:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
    if manifest.control_id != _CONTROL_ID:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)

    source_state = manifest.source_state
    if type(source_state) is not PasswdSourceState:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)

    mode_text = source_state.passwd_file_mode
    uid = source_state.passwd_file_owner_uid
    gid = source_state.passwd_file_group_gid
    if type(mode_text) is not str or _MODE_PATTERN.fullmatch(mode_text) is None:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
    if type(uid) is not int or uid < 0 or type(gid) is not int or gid < 0:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)

    return mode_text, int(mode_text, 8), uid, gid


def _snapshot(filesystem: _MetadataFilesystem, descriptor: int) -> _MetadataSnapshot:
    metadata = filesystem.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
    return _MetadataSnapshot(
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def _restore_metadata(
    filesystem: _MetadataFilesystem,
    descriptor: int,
    before: _MetadataSnapshot,
) -> None:
    filesystem.fchown(descriptor, before.uid, before.gid)
    filesystem.fchmod(descriptor, before.mode)
    if _snapshot(filesystem, descriptor) != before:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)


def _reproduce_source_state(
    manifest: SandboxContextManifest,
    *,
    filesystem: _MetadataFilesystem,
) -> SandboxPasswdReproductionResult:
    mode_text, requested_mode, requested_uid, requested_gid = (
        _validated_source_values(manifest)
    )

    descriptor: int | None = None
    before: _MetadataSnapshot | None = None
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = filesystem.open(SANDBOX_PASSWD_TARGET_PATH, flags)
        before = _snapshot(filesystem, descriptor)

        try:
            filesystem.fchown(descriptor, requested_uid, requested_gid)
            filesystem.fchmod(descriptor, requested_mode)
            after = _snapshot(filesystem, descriptor)
            if after != _MetadataSnapshot(
                mode=requested_mode,
                uid=requested_uid,
                gid=requested_gid,
            ):
                raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
        except Exception:
            try:
                _restore_metadata(filesystem, descriptor, before)
            except Exception:
                pass
            raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE) from None

        return SandboxPasswdReproductionResult(
            control_id=_CONTROL_ID,
            target_path=SANDBOX_PASSWD_TARGET_PATH,
            before_mode=f"{before.mode:04o}",
            before_uid=before.uid,
            before_gid=before.gid,
            requested_mode=mode_text,
            requested_uid=requested_uid,
            requested_gid=requested_gid,
            after_mode=f"{after.mode:04o}",
            after_uid=after.uid,
            after_gid=after.gid,
            reproduced=True,
        )
    except SandboxStateReproductionError:
        raise
    except Exception:
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE) from None
    finally:
        if descriptor is not None:
            try:
                filesystem.close(descriptor)
            except Exception:
                pass


def reproduce_passwd_source_state(
    manifest: SandboxContextManifest,
) -> SandboxPasswdReproductionResult:
    """Apply only validated 7.1.1 metadata to the fixed sandbox passwd file."""

    return _reproduce_source_state(
        manifest,
        filesystem=_FILESYSTEM,
    )


def _reproduce_ip_forwarding_source_state(
    manifest: SandboxContextManifest,
    *,
    runtime: _ForwardingRuntime,
) -> SandboxIpForwardingReproductionResult:
    """Reproduce fixed runtime keys; refuse mismatched IPv6 availability."""

    if (
        type(manifest) is not SandboxContextManifest
        or manifest.control_id != "3.3.1"
        or type(manifest.source_state) is not IpForwardingSourceState
    ):
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
    source = manifest.source_state
    requested_ipv4 = source.ipv4_forwarding_status
    requested_ipv6 = source.ipv6_forwarding_status
    enabled = source.ipv6_enabled
    if (
        type(requested_ipv4) is not int
        or requested_ipv4 not in {0, 1}
        or type(enabled) is not bool
        or (enabled and (type(requested_ipv6) is not int or requested_ipv6 not in {0, 1}))
        or (not enabled and requested_ipv6 is not None)
    ):
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)

    ipv4_started = False
    ipv6_started = False
    before_ipv4: int | None = None
    before_ipv6: int | None = None
    try:
        if runtime.ipv6_enabled() is not enabled:
            raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
        before_ipv4 = runtime.read_ipv4()
        before_ipv6 = runtime.read_ipv6() if enabled else None
        if (
            type(before_ipv4) is not int or before_ipv4 not in {0, 1}
            or (enabled and (type(before_ipv6) is not int or before_ipv6 not in {0, 1}))
        ):
            raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)

        if before_ipv4 != requested_ipv4:
            ipv4_started = True
            runtime.set_ipv4(requested_ipv4)
        if enabled and before_ipv6 != requested_ipv6:
            ipv6_started = True
            runtime.set_ipv6(requested_ipv6)  # type: ignore[arg-type]

        after_ipv4 = runtime.read_ipv4()
        after_ipv6 = runtime.read_ipv6() if enabled else None
        if (
            after_ipv4 != requested_ipv4
            or after_ipv6 != requested_ipv6
            or runtime.ipv6_enabled() is not enabled
        ):
            raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE)
        return SandboxIpForwardingReproductionResult(
            control_id="3.3.1",
            before_ipv4=before_ipv4,
            requested_ipv4=requested_ipv4,
            after_ipv4=after_ipv4,
            ipv6_enabled=enabled,
            before_ipv6=before_ipv6,
            requested_ipv6=requested_ipv6,
            after_ipv6=after_ipv6,
            reproduced=True,
        )
    except Exception:
        # A failed fixed action may already have changed the kernel before
        # reporting failure. Reverse every started action and verify both keys.
        rollback_failed = False
        if ipv6_started and before_ipv6 is not None:
            try:
                runtime.set_ipv6(before_ipv6)
            except Exception:
                rollback_failed = True
        if ipv4_started and before_ipv4 is not None:
            try:
                runtime.set_ipv4(before_ipv4)
            except Exception:
                rollback_failed = True
        if ipv4_started or ipv6_started:
            try:
                if (
                    runtime.read_ipv4() != before_ipv4
                    or (enabled and runtime.read_ipv6() != before_ipv6)
                    or runtime.ipv6_enabled() is not enabled
                ):
                    rollback_failed = True
            except Exception:
                rollback_failed = True
        if rollback_failed:
            raise SandboxStateReproductionError(_FIXED_ROLLBACK_MESSAGE) from None
        raise SandboxStateReproductionError(_FIXED_ERROR_MESSAGE) from None


def reproduce_ip_forwarding_source_state(
    manifest: SandboxContextManifest,
) -> SandboxIpForwardingReproductionResult:
    """Apply one strict 3.3.1 source-state context inside the sandbox guest."""

    return _reproduce_ip_forwarding_source_state(
        manifest,
        runtime=_FORWARDING_RUNTIME,
    )
