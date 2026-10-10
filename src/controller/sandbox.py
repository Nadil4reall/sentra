"""Typed M6E sandbox provider and orchestration boundaries.

The provider receives only a Controller-issued sandbox-session UUID.  VM
configuration is derived from protected server-side configuration and a fixed
plan; no API request can introduce commands, XML, paths, mounts, resources, or
provider-specific payloads.

The libvirt storage/domain adapter is lazy-loaded and uses only the libvirt
Python API. Importing this module and exercising fake backends on macOS never
imports libvirt.
"""

from __future__ import annotations

from enum import StrEnum
import hashlib
import importlib
import json
import logging
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Callable, Literal, Protocol
from uuid import UUID, uuid5
from xml.etree import ElementTree as ET

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.controller.models import (
    AdminAuth,
    SandboxProviderType,
    SandboxSessionRecord,
    SandboxSessionStatus,
)
from src.controller.service import (
    ControllerConflictError,
    ControllerService,
)
from src.sandbox_protocol.models import SENTRA_VALIDATION_CHANNEL_NAME


_RESOURCE_PREFIX = "sentra-sbx-"
_POOL_PREFIX = "sentra-pool-"
_OVERLAY_FILENAME = "root.qcow2"
_DOMAIN_NAMESPACE = UUID("3f928c87-cb68-49d7-b17a-18d3131958dc")
_DOMAIN_METADATA_NAMESPACE = "urn:sentra:sandbox:v1"
_INSTANCE_PATTERN = r"^sentra-sbx-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_LIBVIRT_CHANNEL_READY_TIMEOUT_SECONDS = 30.0
_LIBVIRT_CHANNEL_READY_POLL_INTERVAL_SECONDS = 0.05
_LOG = logging.getLogger(__name__)
_LIBVIRT_EVENT_REGISTRATION_LOCK = threading.Lock()
_LIBVIRT_EVENT_RUN_LOCK = threading.Lock()
_LIBVIRT_EVENT_MODULES: set[object] = set()


def _ensure_default_libvirt_events(libvirt: object) -> None:
    """Register libvirt's default event implementation before opening a stream."""

    register = getattr(libvirt, "virEventRegisterDefaultImpl", None)
    if not callable(register):
        raise SandboxProviderUnavailableError("libvirt event API is unavailable")
    with _LIBVIRT_EVENT_REGISTRATION_LOCK:
        if libvirt in _LIBVIRT_EVENT_MODULES:
            return
        if register() == -1:
            raise SandboxProviderUnavailableError("libvirt event API is unavailable")
        _LIBVIRT_EVENT_MODULES.add(libvirt)


class SandboxRuntimeState(StrEnum):
    """Closed runtime observation vocabulary returned by a provider."""

    PROVISIONING = "PROVISIONING"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    MISSING = "MISSING"


class SandboxStorageMode(StrEnum):
    """Explicit filesystem ownership models for fake and libvirt backends."""

    PRIVATE_DIRECTORY = "private_directory"
    LIBVIRT_POOL = "libvirt_pool"


class _StrictProviderModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
    )


class SandboxInstance(_StrictProviderModel):
    """Opaque provider observation safe to expose as session identity."""

    sandbox_instance_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=_INSTANCE_PATTERN,
    )
    provider_type: Literal[
        SandboxProviderType.LOCAL_NESTED_VM
    ] = SandboxProviderType.LOCAL_NESTED_VM
    runtime_state: SandboxRuntimeState


class LocalNestedVmConfig(_StrictProviderModel):
    """Trusted appliance configuration; never accepted by the HTTP API."""

    sandbox_root: Path
    base_image: Path
    image_release: Literal["ubuntu-24.04"] = "ubuntu-24.04"
    network: str = Field(default="default", pattern=_NAME_PATTERN)
    memory_mib: int = Field(default=2048, ge=512, le=65_536)
    vcpus: int = Field(default=2, ge=1, le=32)
    storage_mode: SandboxStorageMode = SandboxStorageMode.PRIVATE_DIRECTORY
    libvirt_connection_uri: Literal["qemu:///system"] = "qemu:///system"
    libvirt_qemu_uid: int | None = Field(default=None, ge=1)
    libvirt_qemu_gid: int | None = Field(default=None, ge=1)
    libvirt_storage_parent_uid: int = Field(default=0, ge=0)
    architecture: Literal["x86_64"] = "x86_64"
    machine: Literal["q35"] = "q35"
    disk_capacity_bytes: int = Field(default=8 * 1024**3, ge=4 * 1024**3)

    @model_validator(mode="after")
    def validate_lexical_paths(self) -> "LocalNestedVmConfig":
        for name, path in (
            ("sandbox_root", self.sandbox_root),
            ("base_image", self.base_image),
        ):
            if not path.is_absolute():
                raise ValueError(f"{name} must be an absolute server path")
            if ".." in path.parts:
                raise ValueError(f"{name} must not contain path traversal")
            if Path(os.path.normpath(os.fspath(path))) != path:
                raise ValueError(f"{name} must use canonical lexical form")
        if self.base_image == self.sandbox_root:
            raise ValueError("base_image must not be the sandbox root")
        if self.storage_mode is SandboxStorageMode.LIBVIRT_POOL:
            if self.libvirt_qemu_uid is None or self.libvirt_qemu_gid is None:
                raise ValueError(
                    "libvirt storage requires trusted QEMU UID and GID settings"
                )
            if self.libvirt_qemu_uid == 0:
                raise ValueError("libvirt QEMU UID must be unprivileged")
        elif self.libvirt_qemu_uid is not None or self.libvirt_qemu_gid is not None:
            raise ValueError(
                "QEMU storage ownership is valid only for libvirt pool mode"
            )
        return self


class LocalNestedVmPlan(_StrictProviderModel):
    """Sealed backend plan generated only by SENTRA code."""

    sandbox_session_id: UUID
    sandbox_instance_id: str = Field(pattern=_INSTANCE_PATTERN)
    provider_type: Literal[
        SandboxProviderType.LOCAL_NESTED_VM
    ] = SandboxProviderType.LOCAL_NESTED_VM
    image_release: Literal["ubuntu-24.04"] = "ubuntu-24.04"
    base_image: Path
    base_image_read_only: Literal[True] = True
    overlay_path: Path
    overlay_format: Literal["qcow2"] = "qcow2"
    network: str = Field(pattern=_NAME_PATTERN)
    memory_mib: int = Field(ge=512, le=65_536)
    vcpus: int = Field(ge=1, le=32)
    host_mounts: tuple[()] = ()
    device_passthrough: tuple[()] = ()
    cloud_init: None = None
    storage_mode: SandboxStorageMode = SandboxStorageMode.PRIVATE_DIRECTORY
    storage_pool_name: str | None = Field(
        default=None,
        pattern=r"^sentra-pool-[0-9a-f-]{36}$",
    )
    libvirt_connection_uri: Literal["qemu:///system"] = "qemu:///system"
    libvirt_qemu_uid: int | None = Field(default=None, ge=1)
    libvirt_qemu_gid: int | None = Field(default=None, ge=1)
    libvirt_storage_parent_uid: int = Field(default=0, ge=0)
    architecture: Literal["x86_64"] = "x86_64"
    machine: Literal["q35"] = "q35"
    disk_capacity_bytes: int = Field(default=8 * 1024**3, ge=4 * 1024**3)

    @model_validator(mode="after")
    def validate_storage_identity(self) -> "LocalNestedVmPlan":
        if self.storage_mode is SandboxStorageMode.LIBVIRT_POOL:
            if self.storage_pool_name != sandbox_pool_name_for(
                self.sandbox_session_id
            ):
                raise ValueError("libvirt pool identity is not canonical")
            if self.libvirt_qemu_uid is None or self.libvirt_qemu_gid is None:
                raise ValueError("libvirt storage owner identity is required")
            if self.libvirt_qemu_uid == 0:
                raise ValueError("libvirt QEMU UID must be unprivileged")
        elif any(
            value is not None
            for value in (
                self.storage_pool_name,
                self.libvirt_qemu_uid,
                self.libvirt_qemu_gid,
            )
        ):
            raise ValueError("private storage plan contains libvirt ownership")
        return self


class BackendObservation(_StrictProviderModel):
    """Narrow assertion returned by the trusted virtualization backend."""

    sandbox_instance_id: str = Field(pattern=_INSTANCE_PATTERN)
    runtime_state: SandboxRuntimeState
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SandboxProviderError(RuntimeError):
    """Base for controlled provider failures with no backend detail."""


class SandboxProviderUnavailableError(SandboxProviderError):
    """The configured provider/backend is unavailable."""


class SandboxProviderSecurityError(SandboxProviderError):
    """A path, identity, or plan invariant failed closed."""


class SandboxProvisioningError(SandboxProviderError):
    """The backend could not ensure the disposable instance."""


class SandboxInspectionError(SandboxProviderError):
    """The backend could not inspect the disposable instance."""


class SandboxProvider(Protocol):
    """Closed provider interface: UUID in, typed observation out."""

    @property
    def provider_type(self) -> SandboxProviderType: ...

    def instance_id_for(self, sandbox_session_id: UUID) -> str: ...

    def provision(self, sandbox_session_id: UUID) -> SandboxInstance: ...

    def inspect(self, sandbox_session_id: UUID) -> SandboxInstance: ...

    def destroy(self, sandbox_session_id: UUID) -> None: ...


class LocalNestedVmBackend(Protocol):
    """No shell/argv surface; a backend accepts only a sealed typed plan."""

    def ensure_provisioned(self, plan: LocalNestedVmPlan) -> BackendObservation: ...

    def inspect(self, plan: LocalNestedVmPlan) -> BackendObservation: ...

    def destroy(self, plan: LocalNestedVmPlan) -> None: ...


def sandbox_resource_name(sandbox_session_id: UUID) -> str:
    """Derive the sole allowed provider identity from a canonical UUID."""

    if not isinstance(sandbox_session_id, UUID):
        raise SandboxProviderSecurityError("sandbox session identity is invalid")
    return f"{_RESOURCE_PREFIX}{str(sandbox_session_id)}"


def sandbox_pool_name_for(sandbox_session_id: UUID) -> str:
    """Derive a dedicated per-session libvirt pool identifier."""

    if not isinstance(sandbox_session_id, UUID):
        raise SandboxProviderSecurityError("sandbox session identity is invalid")
    return f"{_POOL_PREFIX}{str(sandbox_session_id)}"


def sandbox_domain_uuid_for(sandbox_session_id: UUID) -> UUID:
    """Derive a stable libvirt domain UUID without target/customer metadata."""

    if not isinstance(sandbox_session_id, UUID):
        raise SandboxProviderSecurityError("sandbox session identity is invalid")
    return uuid5(_DOMAIN_NAMESPACE, str(sandbox_session_id))


def _canonical_plan_json(plan: LocalNestedVmPlan) -> str:
    return json.dumps(
        plan.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def plan_sha256(plan: LocalNestedVmPlan) -> str:
    return hashlib.sha256(_canonical_plan_json(plan).encode("utf-8")).hexdigest()


def _path_components(path: Path) -> list[Path]:
    current = Path(path.anchor)
    components = [current]
    for part in path.parts[1:]:
        current /= part
        components.append(current)
    return components


def _require_trusted_ancestry(
    path: Path,
    *,
    extra_trusted_owners: frozenset[int] = frozenset(),
) -> None:
    """Reject replaceable or symlinked existing server path components."""

    effective_uid = os.geteuid()
    allowed_owners = {0, effective_uid, *extra_trusted_owners}
    for component in _path_components(path):
        try:
            component_stat = os.lstat(component)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(component_stat.st_mode):
            raise SandboxProviderSecurityError(
                "sandbox configuration ancestry must not contain symlinks"
            )
        if component != path and not stat.S_ISDIR(component_stat.st_mode):
            raise SandboxProviderSecurityError(
                "sandbox configuration ancestry must contain directories"
            )
        if component_stat.st_uid not in allowed_owners:
            raise SandboxProviderSecurityError(
                "sandbox configuration ancestry is not trusted"
            )
        if stat.S_IMODE(component_stat.st_mode) & 0o022:
            raise SandboxProviderSecurityError(
                "sandbox configuration ancestry is group/world writable"
            )


def _stat_trusted_root(root: Path) -> os.stat_result:
    _require_trusted_ancestry(root)
    try:
        root_stat = os.lstat(root)
    except FileNotFoundError as error:
        raise SandboxProviderSecurityError(
            "configured sandbox root does not exist"
        ) from error
    if not stat.S_ISDIR(root_stat.st_mode):
        raise SandboxProviderSecurityError(
            "configured sandbox root must be a directory"
        )
    if root_stat.st_uid != os.geteuid():
        raise SandboxProviderSecurityError(
            "configured sandbox root must be owned by the service user"
        )
    if stat.S_IMODE(root_stat.st_mode) & 0o077:
        raise SandboxProviderSecurityError(
            "configured sandbox root permissions must exclude group/other access"
        )
    return root_stat


def _stat_libvirt_storage_root(
    root: Path,
    *,
    expected_owner_uid: int,
    qemu_gid: int,
) -> os.stat_result:
    """Validate the dedicated system-libvirt pool parent without repairing it.

    The parent is root (or another explicitly configured trusted owner), with
    group search access only for QEMU. Libvirt creates each private pool child
    through its storage API with QEMU ownership; this service does not chmod or
    chown the configured parent.
    """

    _require_trusted_ancestry(
        root,
        extra_trusted_owners=frozenset({expected_owner_uid}),
    )
    try:
        root_stat = os.lstat(root)
    except FileNotFoundError as error:
        raise SandboxProviderSecurityError(
            "configured libvirt storage root does not exist"
        ) from error
    if not stat.S_ISDIR(root_stat.st_mode):
        raise SandboxProviderSecurityError(
            "configured libvirt storage root must be a directory"
        )
    if root_stat.st_uid != expected_owner_uid or root_stat.st_gid != qemu_gid:
        raise SandboxProviderSecurityError(
            "configured libvirt storage root ownership is not trusted"
        )
    if stat.S_IMODE(root_stat.st_mode) != 0o710:
        raise SandboxProviderSecurityError(
            "configured libvirt storage root must use root/group-search mode 0710"
        )
    return root_stat


def _mode_grants(st: os.stat_result, *, uid: int, gid: int, bit: int) -> bool:
    mode = stat.S_IMODE(st.st_mode)
    if uid == st.st_uid:
        return bool(mode & (bit << 6))
    if gid == st.st_gid:
        return bool(mode & (bit << 3))
    return bool(mode & bit)


def _require_qemu_read_access(path: Path, *, qemu_uid: int, qemu_gid: int) -> None:
    """Conservatively verify POSIX mode access for the configured QEMU IDs."""

    _require_trusted_ancestry(
        path,
        extra_trusted_owners=frozenset({qemu_uid}),
    )
    for component in _path_components(path)[:-1]:
        try:
            component_stat = os.lstat(component)
        except FileNotFoundError as error:
            raise SandboxProviderSecurityError(
                "base image ancestry does not exist"
            ) from error
        if not stat.S_ISDIR(component_stat.st_mode) or not _mode_grants(
            component_stat,
            uid=qemu_uid,
            gid=qemu_gid,
            bit=0o1,
        ):
            raise SandboxProviderSecurityError(
                "configured QEMU identity cannot traverse base image ancestry"
            )
    try:
        image_stat = os.lstat(path)
    except FileNotFoundError as error:
        raise SandboxProviderSecurityError(
            "configured sandbox base image does not exist"
        ) from error
    if not _mode_grants(
        image_stat,
        uid=qemu_uid,
        gid=qemu_gid,
        bit=0o4,
    ):
        raise SandboxProviderSecurityError(
            "configured QEMU identity cannot read the base image"
        )


def _stat_trusted_base_image(path: Path) -> os.stat_result:
    _require_trusted_ancestry(path)
    try:
        image_stat = os.lstat(path)
    except FileNotFoundError as error:
        raise SandboxProviderSecurityError(
            "configured sandbox base image does not exist"
        ) from error
    if not stat.S_ISREG(image_stat.st_mode):
        raise SandboxProviderSecurityError(
            "configured sandbox base image must be a regular file"
        )
    if image_stat.st_nlink != 1:
        raise SandboxProviderSecurityError(
            "configured sandbox base image must not be hard linked"
        )
    effective_uid = os.geteuid()
    if image_stat.st_uid not in {0, effective_uid}:
        raise SandboxProviderSecurityError(
            "configured sandbox base image owner is not trusted"
        )
    if stat.S_IMODE(image_stat.st_mode) & 0o022:
        raise SandboxProviderSecurityError(
            "configured sandbox base image must not be group/world writable"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SandboxProviderSecurityError(
            "configured sandbox base image could not be opened safely"
        ) from error
    try:
        opened_stat = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        opened_stat.st_dev != image_stat.st_dev
        or opened_stat.st_ino != image_stat.st_ino
        or not stat.S_ISREG(opened_stat.st_mode)
    ):
        raise SandboxProviderSecurityError(
            "configured sandbox base image changed during validation"
        )
    return opened_stat


def _base_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        stat.S_IMODE(value.st_mode),
    )


class LocalNestedVmProvider:
    """Deterministic local nested-VM provider over an injected backend."""

    def __init__(
        self,
        config: LocalNestedVmConfig,
        backend: LocalNestedVmBackend,
    ) -> None:
        self._config = config
        self._backend = backend
        if config.storage_mode is SandboxStorageMode.LIBVIRT_POOL:
            assert config.libvirt_qemu_gid is not None
            _stat_libvirt_storage_root(
                config.sandbox_root,
                expected_owner_uid=config.libvirt_storage_parent_uid,
                qemu_gid=config.libvirt_qemu_gid,
            )
            assert config.libvirt_qemu_uid is not None
            _require_qemu_read_access(
                config.base_image,
                qemu_uid=config.libvirt_qemu_uid,
                qemu_gid=config.libvirt_qemu_gid,
            )
            backend_mode = getattr(
                backend,
                "storage_mode",
                SandboxStorageMode.PRIVATE_DIRECTORY,
            )
            if backend_mode is not SandboxStorageMode.LIBVIRT_POOL:
                raise SandboxProviderSecurityError(
                    "libvirt storage configuration requires the libvirt backend"
                )
        else:
            _stat_trusted_root(config.sandbox_root)
        _stat_trusted_base_image(config.base_image)

    @property
    def provider_type(self) -> SandboxProviderType:
        return SandboxProviderType.LOCAL_NESTED_VM

    def instance_id_for(self, sandbox_session_id: UUID) -> str:
        return sandbox_resource_name(sandbox_session_id)

    def _session_directory(self, sandbox_session_id: UUID) -> Path:
        return self._config.sandbox_root / self.instance_id_for(sandbox_session_id)

    def _ensure_session_directory(self, sandbox_session_id: UUID) -> Path:
        root = self._config.sandbox_root
        _stat_trusted_root(root)
        resource_name = self.instance_id_for(sandbox_session_id)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            root_descriptor = os.open(root, flags)
        except OSError as error:
            raise SandboxProviderSecurityError(
                "configured sandbox root could not be opened safely"
            ) from error
        try:
            try:
                os.mkdir(resource_name, mode=0o700, dir_fd=root_descriptor)
            except FileExistsError:
                pass
            directory_stat = os.stat(
                resource_name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise SandboxProviderSecurityError(
                "sandbox instance directory could not be prepared safely"
            ) from error
        finally:
            os.close(root_descriptor)
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise SandboxProviderSecurityError(
                "sandbox instance path must be a directory"
            )
        if directory_stat.st_uid != os.geteuid():
            raise SandboxProviderSecurityError(
                "sandbox instance directory owner is not trusted"
            )
        if stat.S_IMODE(directory_stat.st_mode) != 0o700:
            raise SandboxProviderSecurityError(
                "sandbox instance directory permissions must be 0700"
            )
        directory = root / resource_name
        if self._config.storage_mode is SandboxStorageMode.LIBVIRT_POOL:
            assert self._config.libvirt_qemu_uid is not None
            _require_trusted_ancestry(
                directory,
                extra_trusted_owners=frozenset(
                    {self._config.libvirt_storage_parent_uid,
                     self._config.libvirt_qemu_uid}
                ),
            )
        else:
            _require_trusted_ancestry(directory)
        return directory

    @staticmethod
    def _validate_overlay(
        path: Path,
        *,
        required: bool,
        expected_uid: int | None = None,
        expected_gid: int | None = None,
        expected_mode: int | None = None,
    ) -> None:
        try:
            overlay_stat = os.lstat(path)
        except FileNotFoundError:
            if required:
                raise SandboxProviderSecurityError(
                    "sandbox backend did not create the disposable overlay"
                )
            return
        if not stat.S_ISREG(overlay_stat.st_mode):
            raise SandboxProviderSecurityError(
                "sandbox overlay must be a regular file"
            )
        if overlay_stat.st_nlink != 1:
            raise SandboxProviderSecurityError(
                "sandbox overlay must not be hard linked"
            )
        owner_uid = os.geteuid() if expected_uid is None else expected_uid
        owner_gid = os.getegid() if expected_gid is None else expected_gid
        if overlay_stat.st_uid != owner_uid or overlay_stat.st_gid != owner_gid:
            raise SandboxProviderSecurityError(
                "sandbox overlay owner is not trusted"
            )
        mode = stat.S_IMODE(overlay_stat.st_mode)
        if expected_mode is not None and mode != expected_mode:
            raise SandboxProviderSecurityError(
                "sandbox overlay permissions are not trusted"
            )
        if mode & 0o022:
            raise SandboxProviderSecurityError(
                "sandbox overlay must not be group/world writable"
            )

    @staticmethod
    def _validate_libvirt_session_directory(
        path: Path,
        *,
        required: bool,
        qemu_uid: int,
        qemu_gid: int,
        expected_mode: int,
    ) -> None:
        try:
            directory_stat = os.lstat(path)
        except FileNotFoundError:
            if required:
                raise SandboxProviderSecurityError(
                    "libvirt sandbox pool directory is missing"
                )
            return
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise SandboxProviderSecurityError(
                "libvirt sandbox pool target must be a directory"
            )
        if (
            directory_stat.st_uid != qemu_uid
            or directory_stat.st_gid != qemu_gid
            or stat.S_IMODE(directory_stat.st_mode) != expected_mode
        ):
            raise SandboxProviderSecurityError(
                "libvirt sandbox pool target permissions are not trusted"
            )

    def _plan(
        self,
        sandbox_session_id: UUID,
        *,
        prepare_directory: bool,
    ) -> LocalNestedVmPlan:
        root = self._config.sandbox_root
        if self._config.storage_mode is SandboxStorageMode.LIBVIRT_POOL:
            assert self._config.libvirt_qemu_gid is not None
            _stat_libvirt_storage_root(
                root,
                expected_owner_uid=self._config.libvirt_storage_parent_uid,
                qemu_gid=self._config.libvirt_qemu_gid,
            )
            assert self._config.libvirt_qemu_uid is not None
            _require_qemu_read_access(
                self._config.base_image,
                qemu_uid=self._config.libvirt_qemu_uid,
                qemu_gid=self._config.libvirt_qemu_gid,
            )
        else:
            _stat_trusted_root(root)
        _stat_trusted_base_image(self._config.base_image)
        directory = self._session_directory(sandbox_session_id)
        if self._config.storage_mode is SandboxStorageMode.PRIVATE_DIRECTORY:
            if prepare_directory:
                directory = self._ensure_session_directory(sandbox_session_id)
            else:
                self._validate_libvirt_session_directory(
                    directory,
                    required=False,
                    qemu_uid=os.geteuid(),
                    qemu_gid=os.getegid(),
                    expected_mode=0o700,
                )
        else:
            assert self._config.libvirt_qemu_uid is not None
            assert self._config.libvirt_qemu_gid is not None
            self._validate_libvirt_session_directory(
                directory,
                required=False,
                qemu_uid=self._config.libvirt_qemu_uid,
                qemu_gid=self._config.libvirt_qemu_gid,
                expected_mode=0o750,
            )
        try:
            directory.relative_to(root)
        except ValueError as error:  # defense-in-depth for later config changes
            raise SandboxProviderSecurityError(
                "sandbox runtime path escaped the configured root"
            ) from error
        try:
            self._config.base_image.relative_to(directory)
        except ValueError:
            pass
        else:
            raise SandboxProviderSecurityError(
                "sandbox base image must be separate from session storage"
            )
        if self._config.storage_mode is SandboxStorageMode.LIBVIRT_POOL:
            assert self._config.libvirt_qemu_uid is not None
            _require_trusted_ancestry(
                directory,
                extra_trusted_owners=frozenset(
                    {self._config.libvirt_qemu_uid}
                ),
            )
        else:
            _require_trusted_ancestry(directory)
        overlay = directory / _OVERLAY_FILENAME
        try:
            overlay.relative_to(root)
        except ValueError as error:
            raise SandboxProviderSecurityError(
                "sandbox overlay escaped the configured root"
            ) from error
        if self._config.storage_mode is SandboxStorageMode.PRIVATE_DIRECTORY:
            self._validate_overlay(overlay, required=False)
        else:
            self._validate_overlay(
                overlay,
                required=False,
                expected_uid=self._config.libvirt_qemu_uid,
                expected_gid=self._config.libvirt_qemu_gid,
                expected_mode=0o600,
            )
        session_id = sandbox_session_id
        return LocalNestedVmPlan(
            sandbox_session_id=sandbox_session_id,
            sandbox_instance_id=self.instance_id_for(sandbox_session_id),
            base_image=self._config.base_image,
            overlay_path=overlay,
            network=self._config.network,
            memory_mib=self._config.memory_mib,
            vcpus=self._config.vcpus,
            storage_mode=self._config.storage_mode,
            storage_pool_name=(
                sandbox_pool_name_for(session_id)
                if self._config.storage_mode is SandboxStorageMode.LIBVIRT_POOL
                else None
            ),
            libvirt_connection_uri=self._config.libvirt_connection_uri,
            libvirt_qemu_uid=self._config.libvirt_qemu_uid,
            libvirt_qemu_gid=self._config.libvirt_qemu_gid,
            libvirt_storage_parent_uid=self._config.libvirt_storage_parent_uid,
            architecture=self._config.architecture,
            machine=self._config.machine,
            disk_capacity_bytes=self._config.disk_capacity_bytes,
        )

    def _validate_plan_overlay(
        self,
        plan: LocalNestedVmPlan,
        *,
        required: bool,
    ) -> None:
        if plan.storage_mode is SandboxStorageMode.LIBVIRT_POOL:
            assert plan.libvirt_qemu_uid is not None
            assert plan.libvirt_qemu_gid is not None
            self._validate_libvirt_session_directory(
                plan.overlay_path.parent,
                required=required,
                qemu_uid=plan.libvirt_qemu_uid,
                qemu_gid=plan.libvirt_qemu_gid,
                expected_mode=0o750,
            )
            self._validate_overlay(
                plan.overlay_path,
                required=required,
                expected_uid=plan.libvirt_qemu_uid,
                expected_gid=plan.libvirt_qemu_gid,
                expected_mode=0o600,
            )
        else:
            self._validate_overlay(plan.overlay_path, required=required)

    @staticmethod
    def _validate_observation(
        plan: LocalNestedVmPlan,
        observation: BackendObservation,
    ) -> SandboxInstance:
        if not isinstance(observation, BackendObservation):
            raise SandboxProviderSecurityError(
                "sandbox backend returned malformed observation evidence"
            )
        if (
            observation.sandbox_instance_id != plan.sandbox_instance_id
            or observation.plan_sha256 != plan_sha256(plan)
        ):
            raise SandboxProviderSecurityError(
                "sandbox backend observation does not match the sealed plan"
            )
        return SandboxInstance(
            sandbox_instance_id=observation.sandbox_instance_id,
            runtime_state=observation.runtime_state,
        )

    def provision(self, sandbox_session_id: UUID) -> SandboxInstance:
        plan = self._plan(sandbox_session_id, prepare_directory=True)
        base_before = _base_identity(_stat_trusted_base_image(plan.base_image))
        try:
            try:
                observation = self._backend.ensure_provisioned(plan)
            except SandboxProviderError:
                raise
            except Exception as error:
                raise SandboxProvisioningError(
                    "sandbox backend provisioning failed"
                ) from error
        finally:
            base_after = _base_identity(
                _stat_trusted_base_image(plan.base_image)
            )
            if base_after != base_before:
                raise SandboxProviderSecurityError(
                    "sandbox base image changed during provisioning"
                )
        self._validate_plan_overlay(plan, required=True)
        return self._validate_observation(plan, observation)

    def inspect(self, sandbox_session_id: UUID) -> SandboxInstance:
        plan = self._plan(sandbox_session_id, prepare_directory=False)
        base_before = _base_identity(_stat_trusted_base_image(plan.base_image))
        try:
            try:
                observation = self._backend.inspect(plan)
            except SandboxProviderError:
                raise
            except Exception as error:
                raise SandboxInspectionError(
                    "sandbox backend inspection failed"
                ) from error
        finally:
            base_after = _base_identity(
                _stat_trusted_base_image(plan.base_image)
            )
            if base_after != base_before:
                raise SandboxProviderSecurityError(
                    "sandbox base image changed during inspection"
                )
        if not isinstance(observation, BackendObservation):
            raise SandboxProviderSecurityError(
                "sandbox backend returned malformed observation evidence"
            )
        if observation.runtime_state is not SandboxRuntimeState.MISSING:
            self._validate_plan_overlay(
                plan,
                required=(
                    observation.runtime_state
                    is not SandboxRuntimeState.PROVISIONING
                ),
            )
        return self._validate_observation(plan, observation)

    def open_validation_channel(
        self,
        sandbox_session_id: UUID,
    ) -> "_LibvirtValidationStream":
        """Open only the fixed SENTRA channel for an existing sandbox."""

        plan = self._plan(
            sandbox_session_id,
            prepare_directory=False,
        )

        opener = getattr(self._backend, "open_validation_channel", None)
        if not callable(opener):
            raise SandboxProviderUnavailableError(
                "sandbox backend does not support the SENTRA validation channel"
            )

        base_before = _base_identity(
            _stat_trusted_base_image(plan.base_image)
        )

        channel = None
        try:
            channel = opener(plan)
            if channel is None:
                raise SandboxProviderUnavailableError(
                    "sandbox backend returned no validation channel"
                )
        except SandboxProviderError:
            raise
        except Exception as error:
            raise SandboxProviderUnavailableError(
                "sandbox validation channel could not be opened"
            ) from error
        finally:
            base_after = _base_identity(
                _stat_trusted_base_image(plan.base_image)
            )
            if base_after != base_before:
                if channel is not None:
                    abort = getattr(channel, "abort", None)
                    if callable(abort):
                        try:
                            abort()
                        except Exception:
                            pass
                raise SandboxProviderSecurityError(
                    "sandbox base image changed while opening validation channel"
                )

        return channel

    def destroy(self, sandbox_session_id: UUID) -> None:
        plan = self._plan(sandbox_session_id, prepare_directory=False)
        base_before = _base_identity(_stat_trusted_base_image(plan.base_image))
        try:
            try:
                self._backend.destroy(plan)
            except SandboxProviderError:
                raise
            except Exception as error:
                raise SandboxProvisioningError(
                    "sandbox backend destruction failed"
                ) from error
        finally:
            base_after = _base_identity(
                _stat_trusted_base_image(plan.base_image)
            )
            if base_after != base_before:
                raise SandboxProviderSecurityError(
                    "sandbox base image changed during destruction"
                )


class _LibvirtValidationStream:
    """BinaryIO-like adapter over SENTRA's fixed libvirt validation channel."""

    def __init__(
        self,
        stream: object,
        connection: object,
        libvirt: object,
        *,
        timeout_seconds: float = 30.0,
        retry_seconds: float = 0.05,
    ) -> None:
        self._stream = stream
        self._connection = connection
        self._libvirt = libvirt
        self._timeout_seconds = timeout_seconds
        self._retry_seconds = retry_seconds
        self._terminal = False
        self._connection_closed = False

    def _wait_for_event(self, event_name: str, deadline: float) -> None:
        """Pump one bounded libvirt event-loop turn after EAGAIN (-2)."""

        event_flag = getattr(self._libvirt, event_name, None)
        error_flag = getattr(self._libvirt, "VIR_STREAM_EVENT_ERROR", None)
        hangup_flag = getattr(self._libvirt, "VIR_STREAM_EVENT_HANGUP", None)
        add_callback = getattr(self._stream, "eventAddCallback", None)
        remove_callback = getattr(self._stream, "eventRemoveCallback", None)
        add_timeout = getattr(self._libvirt, "virEventAddTimeout", None)
        remove_timeout = getattr(self._libvirt, "virEventRemoveTimeout", None)
        run_events = getattr(self._libvirt, "virEventRunDefaultImpl", None)
        if (
            any(type(flag) is not int for flag in (event_flag, error_flag, hangup_flag))
            or not all(callable(method) for method in (
                add_callback, remove_callback, add_timeout, remove_timeout, run_events
            ))
        ):
            raise OSError("libvirt stream event capability is unavailable")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        timeout_ms = max(1, min(int(self._retry_seconds * 1000), int(remaining * 1000)))
        observed_events = 0

        def on_stream_event(_stream: object, events: int, _opaque: object) -> None:
            nonlocal observed_events
            observed_events |= events

        def on_timeout(_timer: int, _opaque: object) -> None:
            pass

        # The default event loop is process-global and must not be entered by
        # two Controller requests at once.  A short libvirt timer bounds each
        # iteration; the outer deadline remains the existing 30 seconds.
        with _LIBVIRT_EVENT_RUN_LOCK:
            callback_added = False
            timer_id: int | None = None
            try:
                if add_callback(event_flag | error_flag | hangup_flag, on_stream_event, None) == -1:
                    raise OSError("libvirt stream event registration failed")
                callback_added = True
                timer_id = add_timeout(timeout_ms, on_timeout, None)
                if type(timer_id) is not int or timer_id < 0:
                    raise OSError("libvirt stream event timer failed")
                if run_events() == -1:
                    raise OSError("libvirt stream event dispatch failed")
            finally:
                try:
                    if timer_id is not None and timer_id >= 0:
                        remove_timeout(timer_id)
                finally:
                    if callback_added:
                        remove_callback()
        if observed_events & error_flag:
            raise OSError("libvirt stream signalled an error")

    def _require_open(self) -> None:
        if self._terminal:
            raise ValueError("SENTRA validation stream is closed")

    def _close_connection(self) -> None:
        if self._connection_closed:
            return
        self._connection_closed = True
        close = getattr(self._connection, "close", None)
        if callable(close):
            close()

    def read(self, size: int) -> bytes:
        self._require_open()
        if type(size) is not int or size <= 0:
            raise ValueError("SENTRA validation stream read size is invalid")

        deadline = time.monotonic() + self._timeout_seconds
        try:
            while True:
                data = self._stream.recv(size)

                if data == -2:
                    if time.monotonic() >= deadline:
                        _LOG.warning(
                            "sandbox controller stage=stream_read_timeout "
                            "exception_type=TimeoutError"
                        )
                        raise TimeoutError("SENTRA validation stream read timed out")
                    self._wait_for_event("VIR_STREAM_EVENT_READABLE", deadline)
                    continue

                if type(data) is not bytes or len(data) > size:
                    raise OSError("libvirt validation stream returned invalid data")

                if not data:
                    _LOG.warning("sandbox controller stage=stream_peer_eof")

                return data
        except Exception:
            try:
                self.abort()
            except Exception:
                pass
            raise

    def write(self, data: bytes) -> int:
        self._require_open()
        if type(data) is not bytes:
            raise TypeError("SENTRA validation stream accepts bytes only")
        if not data:
            return 0

        deadline = time.monotonic() + self._timeout_seconds
        try:
            while True:
                count = self._stream.send(data)

                if count == -2:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("SENTRA validation stream write timed out")
                    self._wait_for_event("VIR_STREAM_EVENT_WRITABLE", deadline)
                    continue

                if (
                    type(count) is not int
                    or count <= 0
                    or count > len(data)
                ):
                    raise OSError("libvirt validation stream write failed")

                return count
        except Exception:
            try:
                self.abort()
            except Exception:
                pass
            raise

    def finish(self) -> None:
        if self._terminal:
            return

        try:
            self._stream.finish()
        except Exception:
            try:
                self._stream.abort()
            except Exception:
                pass
            self._terminal = True
            self._close_connection()
            raise

        self._terminal = True
        self._close_connection()

    def abort(self) -> None:
        if self._terminal:
            return

        try:
            self._stream.abort()
        finally:
            self._terminal = True
            self._close_connection()

    def close(self) -> None:
        self.abort()

    def __enter__(self) -> "_LibvirtValidationStream":
        self._require_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if exc_type is None:
            self.finish()
        else:
            try:
                self.abort()
            except Exception:
                pass
        return False


class LibvirtBackend:
    """Narrow system-libvirt backend using only the Python libvirt API.

    The module import and connection are lazy. Storage is isolated in one
    deterministic, per-session directory pool. The configured shared parent
    must be prepared by an operator as trusted-owner:QEMU-group mode 0710;
    libvirt creates each unique child with QEMU ownership through its storage
    API. The backend never repairs or changes the shared parent.
    """

    def __init__(
        self,
        *,
        module_loader: Callable[[str], object] | None = None,
    ) -> None:
        self._module_loader = module_loader
        self._libvirt: object | None = None

    @property
    def storage_mode(self) -> SandboxStorageMode:
        return SandboxStorageMode.LIBVIRT_POOL

    def _load(self) -> object:
        if self._libvirt is not None:
            return self._libvirt
        loader = self._module_loader or importlib.import_module
        try:
            self._libvirt = loader("libvirt")
        except (ImportError, ModuleNotFoundError) as error:
            raise SandboxProviderUnavailableError(
                "libvirt backend is unavailable"
            ) from error
        return self._libvirt

    @staticmethod
    def _expect_libvirt_plan(plan: LocalNestedVmPlan) -> None:
        if (
            not isinstance(plan, LocalNestedVmPlan)
            or plan.storage_mode is not SandboxStorageMode.LIBVIRT_POOL
            or plan.storage_pool_name
            != sandbox_pool_name_for(plan.sandbox_session_id)
            or plan.libvirt_qemu_uid is None
            or plan.libvirt_qemu_gid is None
            or plan.libvirt_qemu_uid == 0
            or plan.libvirt_connection_uri != "qemu:///system"
            or plan.base_image == plan.overlay_path
            or plan.base_image.is_relative_to(plan.overlay_path.parent)
            or plan.overlay_path.name != _OVERLAY_FILENAME
            or plan.overlay_path.parent.name != plan.sandbox_instance_id
            or not plan.overlay_path.is_absolute()
            or ".." in plan.overlay_path.parts
            or Path(os.path.normpath(os.fspath(plan.overlay_path)))
            != plan.overlay_path
        ):
            raise SandboxProviderSecurityError(
                "libvirt backend received an invalid sealed plan"
            )
        try:
            LocalNestedVmPlan.model_validate(plan.model_dump(mode="python"))
        except Exception as error:
            raise SandboxProviderSecurityError(
                "libvirt backend received an invalid sealed plan"
            ) from error
        assert plan.libvirt_qemu_uid is not None
        assert plan.libvirt_qemu_gid is not None
        _stat_libvirt_storage_root(
            plan.overlay_path.parent.parent,
            expected_owner_uid=plan.libvirt_storage_parent_uid,
            qemu_gid=plan.libvirt_qemu_gid,
        )
        _require_qemu_read_access(
            plan.base_image,
            qemu_uid=plan.libvirt_qemu_uid,
            qemu_gid=plan.libvirt_qemu_gid,
        )

    @staticmethod
    def _pool_target(plan: LocalNestedVmPlan) -> Path:
        return plan.overlay_path.parent

    @staticmethod
    def _storage_root(plan: LocalNestedVmPlan) -> Path:
        return plan.overlay_path.parent.parent

    @staticmethod
    def _xml_root(xml: str) -> ET.Element:
        try:
            return ET.fromstring(xml)
        except (ET.ParseError, TypeError) as error:
            raise SandboxProviderSecurityError(
                "libvirt returned malformed resource XML"
            ) from error

    @staticmethod
    def _text(parent: ET.Element, path: str) -> str | None:
        element = parent.find(path)
        return None if element is None else (element.text or "").strip()

    @staticmethod
    def _is_error_code(error: Exception, expected: int | None) -> bool:
        if expected is None:
            return False
        getter = getattr(error, "get_error_code", None)
        try:
            return callable(getter) and getter() == expected
        except Exception:
            return False

    def _open(self, plan: LocalNestedVmPlan):
        libvirt = self._load()
        try:
            connection = libvirt.open(plan.libvirt_connection_uri)
        except Exception as error:
            raise SandboxProviderUnavailableError(
                "system libvirt connection is unavailable"
            ) from error
        if connection is None:
            raise SandboxProviderUnavailableError(
                "system libvirt connection is unavailable"
            )
        return libvirt, connection

    @staticmethod
    def _close(connection: object) -> None:
        close = getattr(connection, "close", None)
        if callable(close):
            close()

    @staticmethod
    def _pool_xml(plan: LocalNestedVmPlan) -> str:
        root = ET.Element("pool", {"type": "dir"})
        ET.SubElement(root, "name").text = plan.storage_pool_name
        target = ET.SubElement(root, "target")
        ET.SubElement(target, "path").text = os.fspath(
            LibvirtBackend._pool_target(plan)
        )
        permissions = ET.SubElement(target, "permissions")
        ET.SubElement(permissions, "owner").text = str(plan.libvirt_qemu_uid)
        ET.SubElement(permissions, "group").text = str(plan.libvirt_qemu_gid)
        ET.SubElement(permissions, "mode").text = "0750"
        return ET.tostring(root, encoding="unicode")

    @staticmethod
    def _volume_xml(plan: LocalNestedVmPlan) -> str:
        root = ET.Element("volume")
        ET.SubElement(root, "name").text = _OVERLAY_FILENAME
        ET.SubElement(root, "capacity", {"unit": "bytes"}).text = str(
            plan.disk_capacity_bytes
        )
        ET.SubElement(root, "allocation", {"unit": "bytes"}).text = "0"
        target = ET.SubElement(root, "target")
        ET.SubElement(target, "format", {"type": "qcow2"})
        permissions = ET.SubElement(target, "permissions")
        ET.SubElement(permissions, "owner").text = str(plan.libvirt_qemu_uid)
        ET.SubElement(permissions, "group").text = str(plan.libvirt_qemu_gid)
        ET.SubElement(permissions, "mode").text = "0600"
        backing = ET.SubElement(root, "backingStore")
        ET.SubElement(backing, "path").text = os.fspath(plan.base_image)
        ET.SubElement(backing, "format", {"type": "qcow2"})
        return ET.tostring(root, encoding="unicode")

    @staticmethod
    def _domain_xml(plan: LocalNestedVmPlan) -> str:
        ET.register_namespace("sentra", _DOMAIN_METADATA_NAMESPACE)
        root = ET.Element("domain", {"type": "kvm"})
        ET.SubElement(root, "name").text = plan.sandbox_instance_id
        ET.SubElement(root, "uuid").text = str(
            sandbox_domain_uuid_for(plan.sandbox_session_id)
        )
        ET.SubElement(root, "memory", {"unit": "KiB"}).text = str(
            plan.memory_mib * 1024
        )
        ET.SubElement(root, "currentMemory", {"unit": "KiB"}).text = str(
            plan.memory_mib * 1024
        )
        ET.SubElement(root, "vcpu", {"placement": "static"}).text = str(
            plan.vcpus
        )
        if plan.libvirt_qemu_uid is None or plan.libvirt_qemu_gid is None:
            raise SandboxProviderSecurityError(
                "libvirt domain requires trusted QEMU UID and GID values"
            )
        os_element = ET.SubElement(root, "os")
        ET.SubElement(
            os_element,
            "type",
            {"arch": plan.architecture, "machine": plan.machine},
        ).text = "hvm"
        ET.SubElement(os_element, "boot", {"dev": "hd"})
        ET.SubElement(root, "on_poweroff").text = "destroy"
        ET.SubElement(root, "on_reboot").text = "restart"
        ET.SubElement(root, "on_crash").text = "destroy"
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(
            metadata,
            f"{{{_DOMAIN_METADATA_NAMESPACE}}}sandbox",
            {
                "session-id": str(plan.sandbox_session_id),
                "provider": SandboxProviderType.LOCAL_NESTED_VM.value,
                "plan-sha256": plan_sha256(plan),
                "pool-name": plan.storage_pool_name or "",
            },
        )
        devices = ET.SubElement(root, "devices")
        disk = ET.SubElement(devices, "disk", {"type": "file", "device": "disk"})
        ET.SubElement(disk, "driver", {"name": "qemu", "type": "qcow2"})
        ET.SubElement(disk, "source", {"file": os.fspath(plan.overlay_path)})

        backing_store = ET.SubElement(
            disk,
            "backingStore",
            {"type": "file"},
        )
        ET.SubElement(backing_store, "format", {"type": "qcow2"})
        backing_source = ET.SubElement(
            backing_store,
            "source",
            {"file": os.fspath(plan.base_image)},
        )
        ET.SubElement(backing_store, "backingStore")

        ET.SubElement(disk, "target", {"dev": "vda", "bus": "virtio"})
        interface = ET.SubElement(devices, "interface", {"type": "network"})
        ET.SubElement(interface, "source", {"network": plan.network})
        ET.SubElement(interface, "model", {"type": "virtio"})
        channel = ET.SubElement(devices, "channel", {"type": "unix"})
        ET.SubElement(
            channel,
            "target",
            {"type": "virtio", "name": SENTRA_VALIDATION_CHANNEL_NAME},
        )
        ET.SubElement(devices, "controller", {"type": "usb", "model": "none"})
        ET.SubElement(devices, "memballoon", {"model": "none"})
        ET.SubElement(
            root,
            "seclabel",
            {"type": "dynamic", "model": "apparmor"},
        )
        dac_label = ET.SubElement(
            root,
            "seclabel",
            {"type": "static", "model": "dac", "relabel": "no"},
        )
        ET.SubElement(dac_label, "label").text = (
            f"+{plan.libvirt_qemu_uid}:+{plan.libvirt_qemu_gid}"
        )
        return ET.tostring(root, encoding="unicode")

    def _validate_pool_xml(
        self,
        pool: object,
        plan: LocalNestedVmPlan,
    ) -> None:
        if pool.name() != plan.storage_pool_name:
            raise SandboxProviderSecurityError(
                "libvirt storage pool name does not match the sandbox plan"
            )
        root = self._xml_root(pool.XMLDesc(0))
        if root.tag != "pool" or root.get("type") != "dir":
            raise SandboxProviderSecurityError(
                "libvirt storage pool type does not match SENTRA policy"
            )
        if self._text(root, "name") != plan.storage_pool_name:
            raise SandboxProviderSecurityError(
                "libvirt storage pool XML identity does not match"
            )
        source = root.find("source")
        if source is not None:
            if (
                source.attrib
                or len(source) != 0
                or (source.text or "").strip()
            ):
                raise SandboxProviderSecurityError(
                    "libvirt storage pool has an unexpected source"
                )
        target = root.find("target")
        if target is None or self._text(root, "target/path") != os.fspath(
            self._pool_target(plan)
        ):
            raise SandboxProviderSecurityError(
                "libvirt storage pool path does not match the sandbox plan"
            )
        if (
            self._text(root, "target/permissions/owner")
            != str(plan.libvirt_qemu_uid)
            or self._text(root, "target/permissions/group")
            != str(plan.libvirt_qemu_gid)
            or self._text(root, "target/permissions/mode") != "0750"
        ):
            raise SandboxProviderSecurityError(
                "libvirt storage pool permissions do not match SENTRA policy"
            )

    def _validate_pool_target(
        self,
        plan: LocalNestedVmPlan,
        *,
        required: bool,
    ) -> bool:
        path = self._pool_target(plan)
        try:
            value = os.lstat(path)
        except FileNotFoundError:
            if required:
                raise SandboxProviderSecurityError(
                    "libvirt storage pool directory is missing"
                )
            return False
        if (
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid != plan.libvirt_qemu_uid
            or value.st_gid != plan.libvirt_qemu_gid
            or stat.S_IMODE(value.st_mode) != 0o750
        ):
            raise SandboxProviderSecurityError(
                "libvirt storage pool directory permissions are not trusted"
            )
        return True

    def _lookup_pool(self, connection: object, libvirt: object, plan: LocalNestedVmPlan):
        try:
            pool = connection.storagePoolLookupByName(plan.storage_pool_name)
        except Exception as error:
            if self._is_error_code(
                error,
                getattr(libvirt, "VIR_ERR_NO_STORAGE_POOL", None),
            ):
                return None
            raise
        return pool

    def _ensure_pool(self, connection: object, libvirt: object, plan: LocalNestedVmPlan):
        pool = self._lookup_pool(connection, libvirt, plan)
        if pool is None:
            target = self._pool_target(plan)
            try:
                os.lstat(target)
            except FileNotFoundError:
                pass
            else:
                raise SandboxProviderSecurityError(
                    "unregistered libvirt pool path already exists"
                )
            try:
                pool = connection.storagePoolDefineXML(self._pool_xml(plan), 0)
                if pool is None:
                    raise SandboxProvisioningError(
                        "libvirt storage pool definition failed"
                    )
                pool.build(0)
            except Exception:
                # A concurrent or interrupted request may have defined the
                # same deterministic pool. Reconcile only after re-reading
                # and validating that exact resource.
                pool = self._lookup_pool(connection, libvirt, plan)
                if pool is None:
                    raise
                self._validate_pool_xml(pool, plan)
                if not self._validate_pool_target(plan, required=False):
                    pool.build(0)
        else:
            self._validate_pool_xml(pool, plan)
            if not self._validate_pool_target(plan, required=False):
                pool.build(0)
        self._validate_pool_xml(pool, plan)
        self._validate_pool_target(plan, required=True)
        if not pool.isActive():
            pool.create(0)
        self._validate_pool_target(plan, required=True)
        return pool

    def _lookup_domain(self, connection: object, libvirt: object, plan: LocalNestedVmPlan):
        try:
            return connection.lookupByName(plan.sandbox_instance_id)
        except Exception as error:
            if self._is_error_code(
                error,
                getattr(libvirt, "VIR_ERR_NO_DOMAIN", None),
            ):
                return None
            raise

    def _lookup_volume(self, pool: object, libvirt: object):
        try:
            return pool.storageVolLookupByName(_OVERLAY_FILENAME)
        except Exception as error:
            if self._is_error_code(
                error,
                getattr(libvirt, "VIR_ERR_NO_STORAGE_VOL", None),
            ):
                return None
            raise

    def _validate_volume(self, volume: object, plan: LocalNestedVmPlan) -> None:
        if volume.name() != _OVERLAY_FILENAME:
            raise SandboxProviderSecurityError(
                "libvirt volume identity does not match the sandbox plan"
            )
        if Path(volume.path()) != plan.overlay_path:
            raise SandboxProviderSecurityError(
                "libvirt volume path does not match the sandbox plan"
            )
        root = self._xml_root(volume.XMLDesc(0))
        if root.tag != "volume" or self._text(root, "name") != _OVERLAY_FILENAME:
            raise SandboxProviderSecurityError(
                "libvirt volume XML identity does not match"
            )
        target = root.find("target")
        fmt = None if target is None else target.find("format")
        if fmt is None or fmt.get("type") != "qcow2":
            raise SandboxProviderSecurityError(
                "libvirt overlay is not qcow2"
            )
        backing = root.find("backingStore")
        backing_format = None if backing is None else backing.find("format")
        if (
            backing is None
            or self._text(root, "backingStore/path") != os.fspath(plan.base_image)
            or backing_format is None
            or backing_format.get("type") != "qcow2"
        ):
            raise SandboxProviderSecurityError(
                "libvirt overlay backing image does not match the trusted base"
            )
        if (
            self._text(root, "target/permissions/owner")
            != str(plan.libvirt_qemu_uid)
            or self._text(root, "target/permissions/group")
            != str(plan.libvirt_qemu_gid)
            or self._text(root, "target/permissions/mode") != "0600"
        ):
            raise SandboxProviderSecurityError(
                "libvirt overlay permissions do not match SENTRA policy"
            )
        st = os.lstat(plan.overlay_path)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != plan.libvirt_qemu_uid
            or st.st_gid != plan.libvirt_qemu_gid
            or stat.S_IMODE(st.st_mode) != 0o600
        ):
            raise SandboxProviderSecurityError(
                "libvirt overlay filesystem identity is not trusted"
            )
        target_path = self._text(root, "target/path")
        if target_path is not None and target_path != os.fspath(plan.overlay_path):
            raise SandboxProviderSecurityError(
                "libvirt volume XML target path does not match the sandbox plan"
            )
        if self._text(root, "capacity") != str(plan.disk_capacity_bytes):
            raise SandboxProviderSecurityError(
                "libvirt overlay capacity does not match SENTRA policy"
            )

    def _create_or_reconcile_volume(
        self,
        pool: object,
        libvirt: object,
        plan: LocalNestedVmPlan,
    ):
        volume = self._lookup_volume(pool, libvirt)
        if volume is None:
            try:
                os.lstat(plan.overlay_path)
            except FileNotFoundError:
                pass
            else:
                raise SandboxProviderSecurityError(
                    "unregistered overlay path already exists"
                )
            try:
                volume = pool.createXML(self._volume_xml(plan), 0)
            except Exception:
                volume = self._lookup_volume(pool, libvirt)
                if volume is None:
                    raise
        self._validate_volume(volume, plan)
        return volume

    @staticmethod
    def _domain_xml_identity(
        domain: object,
        plan: LocalNestedVmPlan,
    ) -> ET.Element:
        if domain.name() != plan.sandbox_instance_id:
            raise SandboxProviderSecurityError(
                "libvirt domain name does not match the sandbox plan"
            )
        root = LibvirtBackend._xml_root(domain.XMLDesc(0))
        if root.tag != "domain" or root.get("type") != "kvm":
            raise SandboxProviderSecurityError(
                "libvirt domain type does not match SENTRA policy"
            )
        def find_text(path: str) -> str | None:
            node = root.find(path)
            return None if node is None else (node.text or "").strip()

        if find_text("name") != plan.sandbox_instance_id:
            raise SandboxProviderSecurityError("libvirt domain XML name mismatch")
        if find_text("uuid") != str(sandbox_domain_uuid_for(plan.sandbox_session_id)):
            raise SandboxProviderSecurityError("libvirt domain UUID mismatch")
        if find_text("memory") != str(plan.memory_mib * 1024):
            raise SandboxProviderSecurityError("libvirt domain memory mismatch")
        memory = root.find("memory")
        current_memory = root.find("currentMemory")
        if (
            memory is None
            or memory.get("unit") != "KiB"
            or current_memory is None
            or current_memory.get("unit") != "KiB"
            or find_text("currentMemory") != str(plan.memory_mib * 1024)
            or find_text("vcpu") != str(plan.vcpus)
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain resource limits mismatch"
            )
        os_type = root.find("os/type")
        if (
            os_type is None
            or (os_type.text or "").strip() != "hvm"
            or os_type.get("arch") != plan.architecture
            or not (
                os_type.get("machine") == plan.machine
                or re.fullmatch(
                    r"pc-q35-(?:[0-9]+(?:\.[0-9]+)*|noble)",
                    os_type.get("machine", ""),
                )
            )
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain architecture or machine mismatch"
            )

        os_boots = root.findall("os/boot")
        if (
            len(os_boots) != 1
            or os_boots[0].attrib != {"dev": "hd"}
            or (os_boots[0].text or "").strip()
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain boot policy does not match SENTRA policy"
            )

        metadata_nodes = [
            node
            for node in root.findall("metadata/*")
            if node.tag == f"{{{_DOMAIN_METADATA_NAMESPACE}}}sandbox"
        ]
        if len(metadata_nodes) != 1:
            raise SandboxProviderSecurityError(
                "libvirt domain SENTRA metadata is missing or ambiguous"
            )
        metadata = metadata_nodes[0]
        expected_metadata = {
            "session-id": str(plan.sandbox_session_id),
            "provider": SandboxProviderType.LOCAL_NESTED_VM.value,
            "plan-sha256": plan_sha256(plan),
            "pool-name": plan.storage_pool_name or "",
        }
        if metadata.attrib != expected_metadata:
            raise SandboxProviderSecurityError(
                "libvirt domain SENTRA metadata does not match the plan"
            )

        if plan.libvirt_qemu_uid is None or plan.libvirt_qemu_gid is None:
            raise SandboxProviderSecurityError(
                "libvirt domain has no trusted QEMU UID and GID plan"
            )
        domain_security_labels = root.findall("seclabel")
        apparmor_labels = [
            label
            for label in domain_security_labels
            if label.get("model") == "apparmor"
        ]
        dac_labels = [
            label
            for label in domain_security_labels
            if label.get("model") == "dac"
        ]
        if (
            len(domain_security_labels) != 2
            or len(apparmor_labels) != 1
            or len(dac_labels) != 1
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain security labels do not match SENTRA policy"
            )

        apparmor = apparmor_labels[0]
        apparmor_children = list(apparmor)
        apparmor_child_names = [child.tag for child in apparmor_children]
        if (
            apparmor.get("type") != "dynamic"
            or set(apparmor.attrib) - {"type", "model", "relabel"}
            or apparmor.get("relabel", "yes") != "yes"
            or any(
                name not in {"label", "imagelabel"}
                for name in apparmor_child_names
            )
            or len(apparmor_child_names) != len(set(apparmor_child_names))
            or any(
                child.attrib
                or list(child)
                or not (child.text or "").strip()
                for child in apparmor_children
            )
            or (apparmor.text or "").strip()
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain AppArmor confinement is missing or disabled"
            )

        dac = dac_labels[0]
        dac_children = list(dac)
        expected_dac_label = (
            f"+{plan.libvirt_qemu_uid}:+{plan.libvirt_qemu_gid}"
        )
        if (
            dac.attrib
            != {"type": "static", "model": "dac", "relabel": "no"}
            or len(dac_children) != 1
            or dac_children[0].tag != "label"
            or dac_children[0].attrib
            or list(dac_children[0])
            or (dac_children[0].text or "").strip() != expected_dac_label
            or (dac.text or "").strip()
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain DAC ownership policy does not match the sandbox plan"
            )

        devices = root.find("devices")
        if devices is None:
            raise SandboxProviderSecurityError("libvirt domain devices are missing")
        LibvirtBackend._validate_q35_normalized_devices(devices)
        LibvirtBackend._validate_sentra_validation_channel(
            devices,
            plan,
            domain_id=root.get("id"),
        )

        disks = devices.findall("disk")
        interfaces = devices.findall("interface")
        if len(disks) != 1 or len(interfaces) != 1:
            raise SandboxProviderSecurityError(
                "libvirt domain must have exactly one disk and network interface"
            )

        disk = disks[0]
        driver = disk.find("driver")
        source = disk.find("source")
        target = disk.find("target")
        if (
            disk.get("type") != "file"
            or disk.get("device") != "disk"
            or driver is None
            or driver.get("name") != "qemu"
            or driver.get("type") != "qcow2"
            or source is None
            or source.get("file") != os.fspath(plan.overlay_path)
            or target is None
            or target.get("dev") != "vda"
            or target.get("bus") != "virtio"
            or disk.find("readonly") is not None
            or disk.find("boot") is not None
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain disk does not match the disposable overlay"
            )

        backing_stores = disk.findall("backingStore")
        if len(backing_stores) != 1:
            raise SandboxProviderSecurityError(
                "libvirt domain backing store is missing or ambiguous"
            )

        backing_store = backing_stores[0]
        backing_format = backing_store.find("format")
        backing_source = backing_store.find("source")
        terminal_backing = backing_store.findall("backingStore")

        if backing_source is None:
            raise SandboxProviderSecurityError(
                "libvirt domain trusted backing source is missing"
            )

        if (
            backing_store.get("type") != "file"
            or set(backing_store.attrib) - {"type", "index"}
            or backing_format is None
            or backing_format.attrib != {"type": "qcow2"}
            or backing_source.get("file") != os.fspath(plan.base_image)
            or set(backing_source.attrib) - {"file", "index"}
            or backing_source.findall("seclabel")
            or len(terminal_backing) != 1
            or terminal_backing[0].attrib
            or list(terminal_backing[0])
            or (terminal_backing[0].text or "").strip()
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain backing store does not match the trusted base policy"
            )

        interface = interfaces[0]
        network_source = interface.find("source")
        network_model = interface.find("model")
        if (
            interface.get("type") != "network"
            or network_source is None
            or network_source.get("network") != plan.network
            or network_model is None
            or network_model.get("type") != "virtio"
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain network does not match SENTRA policy"
            )

        return root

    @staticmethod
    def _validate_sentra_validation_channel(
        devices: ET.Element,
        plan: LocalNestedVmPlan,
        *,
        domain_id: str | None,
    ) -> None:
        """Validate SENTRA's single fixed, private virtio-serial channel."""

        channels = devices.findall("channel")
        if len(channels) != 1:
            raise SandboxProviderSecurityError(
                "libvirt domain must contain exactly one SENTRA validation channel"
            )

        channel = channels[0]
        children = list(channel)
        child_names = [child.tag for child in children]
        targets = [child for child in children if child.tag == "target"]
        sources = [child for child in children if child.tag == "source"]
        aliases = [child for child in children if child.tag == "alias"]
        addresses = [child for child in children if child.tag == "address"]
        if (
            channel.attrib != {"type": "unix"}
            or (channel.text or "").strip()
            or any(
                name not in {"source", "target", "alias", "address"}
                for name in child_names
            )
            or len(targets) != 1
            or len(sources) > 1
            or len(aliases) > 1
            or len(addresses) > 1
        ):
            raise SandboxProviderSecurityError(
                "libvirt SENTRA validation channel structure is not permitted"
            )

        target = targets[0]
        target_attributes = target.attrib
        target_state = target_attributes.get("state")
        if (
            target_attributes.get("type") != "virtio"
            or target_attributes.get("name") != SENTRA_VALIDATION_CHANNEL_NAME
            or set(target_attributes) - {"type", "name", "state"}
            or target_state not in {None, "connected", "disconnected"}
            or list(target)
            or (target.text or "").strip()
        ):
            raise SandboxProviderSecurityError(
                "libvirt SENTRA validation channel target does not match policy"
            )

        if sources:
            source = sources[0]
            expected_path = None
            if domain_id is not None and re.fullmatch(
                r"[1-9][0-9]*", domain_id
            ):
                expected_path = (
                    "/run/libvirt/qemu/channel/"
                    f"{domain_id}-{plan.sandbox_instance_id[:20]}/"
                    f"{SENTRA_VALIDATION_CHANNEL_NAME}"
                )
            if (
                set(source.attrib) != {"mode", "path"}
                or source.get("mode") != "bind"
                or expected_path is None
                or source.get("path") != expected_path
                or list(source)
                or (source.text or "").strip()
            ):
                raise SandboxProviderSecurityError(
                    "libvirt SENTRA validation channel source is not permitted"
                )

        if aliases:
            alias = aliases[0]
            if (
                set(alias.attrib) != {"name"}
                or re.fullmatch(r"channel[0-9]+", alias.get("name", "")) is None
                or list(alias)
                or (alias.text or "").strip()
            ):
                raise SandboxProviderSecurityError(
                    "libvirt SENTRA validation channel alias is not normalized"
                )

        if addresses:
            address = addresses[0]
            expected_address = {
                "type": "virtio-serial",
                "controller": "0",
                "bus": "0",
            }
            allowed_address_forms = (
                expected_address,
                {**expected_address, "port": "1"},
            )
            if (
                address.attrib not in allowed_address_forms
                or list(address)
                or (address.text or "").strip()
            ):
                raise SandboxProviderSecurityError(
                    "libvirt SENTRA validation channel address is not normalized"
                )

    @staticmethod
    def _validate_q35_normalized_devices(devices: ET.Element) -> None:
        """Validate security-relevant devices after libvirt Q35 normalization."""

        allowed_devices = {
            "disk",
            "interface",
            "controller",
            "channel",
            "memballoon",
            "input",
            "emulator",
            "audio",
            "watchdog",
            "video",
        }

        unexpected = [
            child.tag for child in devices if child.tag not in allowed_devices
        ]
        if unexpected:
            raise SandboxProviderSecurityError(
                "libvirt domain contains an unsupported host-facing device"
            )

        balloons = devices.findall("memballoon")
        if len(balloons) != 1 or balloons[0].get("model") != "none":
            raise SandboxProviderSecurityError(
                "libvirt domain balloon device is not disabled"
            )

        audio_devices = devices.findall("audio")
        if len(audio_devices) > 1 or (
            audio_devices and audio_devices[0].get("type") != "none"
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain audio device is not disabled"
            )

        watchdogs = devices.findall("watchdog")
        if len(watchdogs) > 1 or (
            watchdogs
            and (
                watchdogs[0].get("model") != "itco"
                or watchdogs[0].get("action") != "reset"
            )
        ):
            raise SandboxProviderSecurityError(
                "libvirt domain watchdog does not match Q35 policy"
            )

        video_devices = devices.findall("video")
        if len(video_devices) > 1:
            raise SandboxProviderSecurityError(
                "libvirt domain contains unexpected video devices"
            )
        if video_devices:
            video_model = video_devices[0].find("model")
            if video_model is None or video_model.get("type") != "none":
                raise SandboxProviderSecurityError(
                    "libvirt domain video device is not disabled"
                )

        usb_controllers = []
        virtio_serial_controllers = []
        for controller in devices.findall("controller"):
            kind = controller.get("type")
            model = controller.get("model")

            if kind == "usb":
                if model != "none":
                    raise SandboxProviderSecurityError(
                        "libvirt domain USB controller is not disabled"
                    )
                usb_controllers.append(controller)
                continue

            if kind == "pci":
                if model not in {"pcie-root", "pcie-root-port"}:
                    raise SandboxProviderSecurityError(
                        "libvirt domain PCI controller is not allowed"
                    )

                model_node = controller.find("model")
                if (
                    model_node is not None
                    and model_node.get("name") != model
                ):
                    raise SandboxProviderSecurityError(
                        "libvirt domain PCI controller normalization mismatch"
                    )
                continue

            if kind == "sata":
                if model not in {None, "ich9-ahci"}:
                    raise SandboxProviderSecurityError(
                        "libvirt domain SATA controller is not allowed"
                    )
                continue

            if kind == "virtio-serial":
                if (
                    controller.attrib
                    not in (
                        {"type": "virtio-serial", "index": "0"},
                        {
                            "type": "virtio-serial",
                            "index": "0",
                            "ports": "16",
                            "vectors": "4",
                        },
                    )
                    or model is not None
                ):
                    raise SandboxProviderSecurityError(
                        "libvirt virtio-serial controller does not match SENTRA policy"
                    )
                controller_children = list(controller)
                aliases = [child for child in controller_children if child.tag == "alias"]
                addresses = [
                    child for child in controller_children if child.tag == "address"
                ]
                if (
                    any(
                        child.tag not in {"alias", "address"}
                        for child in controller_children
                    )
                    or len(aliases) > 1
                    or len(addresses) > 1
                    or (controller.text or "").strip()
                ):
                    raise SandboxProviderSecurityError(
                        "libvirt virtio-serial controller children are not normalized"
                    )
                if aliases and (
                    set(aliases[0].attrib) != {"name"}
                    or re.fullmatch(
                        r"virtio-serial[0-9]+", aliases[0].get("name", "")
                    )
                    is None
                    or list(aliases[0])
                    or (aliases[0].text or "").strip()
                ):
                    raise SandboxProviderSecurityError(
                        "libvirt virtio-serial controller alias is not normalized"
                    )
                if addresses and (
                    addresses[0].attrib
                    != {
                        "type": "pci",
                        "domain": "0x0000",
                        "bus": "0x02",
                        "slot": "0x00",
                        "function": "0x0",
                    }
                    or list(addresses[0])
                    or (addresses[0].text or "").strip()
                ):
                    raise SandboxProviderSecurityError(
                        "libvirt virtio-serial controller PCI address is not normalized"
                    )
                virtio_serial_controllers.append(controller)
                continue

            raise SandboxProviderSecurityError(
                "libvirt domain controller is not an allowed virtual model"
            )

        if len(usb_controllers) != 1:
            raise SandboxProviderSecurityError(
                "libvirt domain must have exactly one disabled USB controller"
            )
        if len(virtio_serial_controllers) > 1:
            raise SandboxProviderSecurityError(
                "libvirt domain contains multiple virtio-serial controllers"
            )

        for input_device in devices.findall("input"):
            if (
                input_device.get("bus") != "ps2"
                or input_device.get("type") not in {"mouse", "keyboard"}
            ):
                raise SandboxProviderSecurityError(
                    "libvirt domain input device is outside Q35 policy"
                )

        emulator_nodes = devices.findall("emulator")
        if len(emulator_nodes) > 1:
            raise SandboxProviderSecurityError(
                "libvirt domain contains multiple emulator definitions"
            )

        if emulator_nodes:
            emulator = (emulator_nodes[0].text or "").strip()
            if emulator != "/usr/bin/qemu-system-x86_64":
                raise SandboxProviderSecurityError(
                    "libvirt domain emulator does not match the appliance default"
                )

    def _runtime_state(self, domain: object, libvirt: object) -> SandboxRuntimeState:
        state, _reason = domain.state(0)
        if state == getattr(libvirt, "VIR_DOMAIN_RUNNING", 1):
            return SandboxRuntimeState.RUNNING
        if state == getattr(libvirt, "VIR_DOMAIN_BLOCKED", 2):
            return SandboxRuntimeState.PROVISIONING
        if state in {
            getattr(libvirt, "VIR_DOMAIN_NOSTATE", 0),
            getattr(libvirt, "VIR_DOMAIN_PAUSED", 3),
            getattr(libvirt, "VIR_DOMAIN_SHUTDOWN", 4),
            getattr(libvirt, "VIR_DOMAIN_SHUTOFF", 5),
            getattr(libvirt, "VIR_DOMAIN_PMSUSPENDED", 7),
        }:
            return SandboxRuntimeState.STOPPED
        if state == getattr(libvirt, "VIR_DOMAIN_CRASHED", 6):
            return SandboxRuntimeState.FAILED
        return SandboxRuntimeState.FAILED

    def _observation(
        self,
        plan: LocalNestedVmPlan,
        state: SandboxRuntimeState,
    ) -> BackendObservation:
        return BackendObservation(
            sandbox_instance_id=plan.sandbox_instance_id,
            runtime_state=state,
            plan_sha256=plan_sha256(plan),
        )

    def ensure_provisioned(self, plan: LocalNestedVmPlan) -> BackendObservation:
        self._expect_libvirt_plan(plan)
        libvirt, connection = self._open(plan)
        try:
            pool = self._lookup_pool(connection, libvirt, plan)
            domain = self._lookup_domain(connection, libvirt, plan)
            if pool is None:
                if domain is not None:
                    raise SandboxProviderSecurityError(
                        "libvirt domain exists without its SENTRA storage pool"
                    )
                pool = self._ensure_pool(connection, libvirt, plan)
            else:
                self._validate_pool_xml(pool, plan)
                if not pool.isActive():
                    if not self._validate_pool_target(plan, required=False):
                        pool.build(0)
                    self._validate_pool_target(plan, required=True)
                    pool.create(0)
                self._validate_pool_target(plan, required=True)

            volume = self._lookup_volume(pool, libvirt)
            if domain is not None and volume is None:
                raise SandboxProviderSecurityError(
                    "libvirt domain exists without its expected overlay"
                )
            if volume is None:
                volume = self._create_or_reconcile_volume(pool, libvirt, plan)
            else:
                self._validate_volume(volume, plan)

            if domain is None:
                try:
                    domain = connection.defineXML(self._domain_xml(plan))
                except Exception:
                    domain = self._lookup_domain(connection, libvirt, plan)
                    if domain is None:
                        raise
                if domain is None:
                    raise SandboxProvisioningError(
                        "libvirt domain definition failed"
                    )
            self._domain_xml_identity(domain, plan)
            if not domain.isActive():
                domain.create()
            return self._observation(plan, self._runtime_state(domain, libvirt))
        finally:
            self._close(connection)

    def inspect(self, plan: LocalNestedVmPlan) -> BackendObservation:
        self._expect_libvirt_plan(plan)
        libvirt, connection = self._open(plan)
        try:
            pool = self._lookup_pool(connection, libvirt, plan)
            domain = self._lookup_domain(connection, libvirt, plan)
            if pool is None:
                try:
                    os.lstat(self._pool_target(plan))
                except FileNotFoundError:
                    if domain is not None:
                        raise SandboxProviderSecurityError(
                            "libvirt domain exists without its SENTRA storage pool"
                        )
                    return self._observation(plan, SandboxRuntimeState.MISSING)
                raise SandboxProviderSecurityError(
                    "unregistered libvirt pool path exists"
                )
            self._validate_pool_xml(pool, plan)
            target_exists = self._validate_pool_target(plan, required=False)
            if not target_exists and domain is not None:
                raise SandboxProviderSecurityError(
                    "libvirt domain exists without its storage directory"
                )
            if not target_exists:
                return self._observation(
                    plan,
                    SandboxRuntimeState.PROVISIONING,
                )
            volume = self._lookup_volume(pool, libvirt)
            if domain is None:
                if volume is not None:
                    self._validate_volume(volume, plan)
                return self._observation(
                    plan,
                    SandboxRuntimeState.PROVISIONING,
                )
            if volume is None:
                raise SandboxProviderSecurityError(
                    "libvirt domain exists without its expected overlay"
                )
            if not target_exists:
                raise SandboxProviderSecurityError(
                    "libvirt domain exists without its storage directory"
                )
            self._validate_volume(volume, plan)
            self._domain_xml_identity(domain, plan)
            if not pool.isActive():
                raise SandboxProviderSecurityError(
                    "libvirt storage pool is inactive during domain inspection"
                )
            return self._observation(plan, self._runtime_state(domain, libvirt))
        finally:
            self._close(connection)

    def open_validation_channel(
        self,
        plan: LocalNestedVmPlan,
    ) -> _LibvirtValidationStream:
        """Open SENTRA's sole fixed virtio validation channel."""

        self._expect_libvirt_plan(plan)
        # The event implementation must exist before opening the connection
        # used by the nonblocking stream (and before the inspection connection).
        _ensure_default_libvirt_events(self._load())

        observation = self.inspect(plan)
        if observation.runtime_state is not SandboxRuntimeState.RUNNING:
            raise SandboxInspectionError(
                "sandbox must be running before validation channel access"
            )

        libvirt, connection = self._open(plan)
        stream = None

        try:
            domain = self._lookup_domain(connection, libvirt, plan)
            if domain is None:
                raise SandboxInspectionError(
                    "sandbox domain disappeared before channel access"
                )

            self._domain_xml_identity(domain, plan)

            if (
                self._runtime_state(domain, libvirt)
                is not SandboxRuntimeState.RUNNING
            ):
                raise SandboxInspectionError(
                    "sandbox is not running during validation channel access"
                )

            new_stream = getattr(connection, "newStream", None)
            if not callable(new_stream):
                raise SandboxProviderUnavailableError(
                    "libvirt stream API is unavailable"
                )

            nonblocking_flag = getattr(
                libvirt,
                "VIR_STREAM_NONBLOCK",
                None,
            )
            if type(nonblocking_flag) is not int:
                raise SandboxProviderUnavailableError(
                    "libvirt non-blocking stream capability is unavailable"
                )

            stream = new_stream(nonblocking_flag)
            if stream is None:
                raise SandboxProviderUnavailableError(
                    "libvirt failed to create validation stream"
                )

            open_channel = getattr(domain, "openChannel", None)
            if not callable(open_channel):
                raise SandboxProviderUnavailableError(
                    "libvirt domain channel API is unavailable"
                )

            open_channel(
                SENTRA_VALIDATION_CHANNEL_NAME,
                stream,
                0,
            )

            # openChannel() attaches the host stream but does not itself prove
            # that a process in the guest has opened the virtio port. Active
            # domain XML reports that guest-side state; do not send context
            # until the guest receiver is actually connected.
            deadline = (
                time.monotonic()
                + _LIBVIRT_CHANNEL_READY_TIMEOUT_SECONDS
            )
            while True:
                active_root = self._domain_xml_identity(domain, plan)
                target = active_root.find("devices/channel/target")
                if target is None:
                    raise SandboxProviderSecurityError(
                        "libvirt SENTRA validation channel disappeared"
                    )
                if target.get("state") == "connected":
                    _LOG.warning("sandbox controller stage=guest_channel_connected")
                    break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SandboxProviderUnavailableError(
                        "guest SENTRA validation channel did not become ready"
                    )
                time.sleep(
                    min(
                        _LIBVIRT_CHANNEL_READY_POLL_INTERVAL_SECONDS,
                        remaining,
                    )
                )

            return _LibvirtValidationStream(
                stream,
                connection,
                libvirt,
            )

        except SandboxProviderError:
            if stream is not None:
                abort = getattr(stream, "abort", None)
                if callable(abort):
                    try:
                        abort()
                    except Exception:
                        pass
            self._close(connection)
            raise

        except Exception as error:
            if stream is not None:
                abort = getattr(stream, "abort", None)
                if callable(abort):
                    try:
                        abort()
                    except Exception:
                        pass
            self._close(connection)
            raise SandboxProviderUnavailableError(
                "libvirt SENTRA validation channel is unavailable"
            ) from error

    def destroy(self, plan: LocalNestedVmPlan) -> None:
        self._expect_libvirt_plan(plan)
        libvirt, connection = self._open(plan)
        try:
            pool = self._lookup_pool(connection, libvirt, plan)
            domain = self._lookup_domain(connection, libvirt, plan)
            if pool is None:
                if domain is not None:
                    raise SandboxProviderSecurityError(
                        "libvirt domain exists without its SENTRA storage pool"
                    )
                try:
                    os.lstat(self._pool_target(plan))
                except FileNotFoundError:
                    return
                raise SandboxProviderSecurityError(
                    "refusing to remove an unregistered libvirt pool path"
                )
            self._validate_pool_xml(pool, plan)
            self._validate_pool_target(plan, required=True)
            if not pool.isActive():
                pool.create(0)
            volume = self._lookup_volume(pool, libvirt)
            volume_names = pool.listVolumes()
            if any(name != _OVERLAY_FILENAME for name in volume_names):
                raise SandboxProviderSecurityError(
                    "refusing to delete a SENTRA pool containing other volumes"
                )
            if (_OVERLAY_FILENAME in volume_names) != (volume is not None):
                raise SandboxProviderSecurityError(
                    "libvirt volume listing is inconsistent with the sandbox plan"
                )
            try:
                before_cleanup = set(os.listdir(self._pool_target(plan)))
            except OSError as error:
                raise SandboxProviderSecurityError(
                    "libvirt pool target cannot be verified for cleanup"
                ) from error
            expected_entries = {_OVERLAY_FILENAME} if volume is not None else set()
            if before_cleanup != expected_entries:
                raise SandboxProviderSecurityError(
                    "refusing to remove unexpected files from a SENTRA pool"
                )
            if domain is not None:
                if volume is None:
                    raise SandboxProviderSecurityError(
                        "libvirt domain exists without its expected overlay"
                    )
                self._validate_volume(volume, plan)
                self._domain_xml_identity(domain, plan)
                if domain.isActive():
                    domain.destroy()
                domain.undefine()
            if volume is not None:
                self._validate_volume(volume, plan)
                volume.delete(0)
            names = pool.listVolumes()
            if names:
                raise SandboxProviderSecurityError(
                    "refusing to delete a SENTRA pool containing other volumes"
                )
            try:
                remaining_entries = os.listdir(self._pool_target(plan))
            except OSError as error:
                raise SandboxProviderSecurityError(
                    "libvirt pool target cannot be verified for cleanup"
                ) from error
            if remaining_entries:
                raise SandboxProviderSecurityError(
                    "refusing to remove unexpected files from a SENTRA pool"
                )
            if pool.isActive():
                pool.destroy()
            pool.delete(0)
            pool.undefine()
        finally:
            self._close(connection)


class SandboxManager:
    """Controller-side M6E-B provisioning/reconciliation orchestrator."""

    PROVIDER_UNAVAILABLE_REASON = "sandbox provider is unavailable"
    PROVISIONING_FAILED_REASON = "sandbox provisioning failed"
    INSPECTION_FAILED_REASON = "sandbox inspection failed"
    IDENTITY_FAILED_REASON = "sandbox provider identity verification failed"
    RUNTIME_NOT_RUNNING_REASON = "sandbox runtime was not confirmed running"

    def __init__(
        self,
        service: ControllerService,
        provider: SandboxProvider | None,
    ) -> None:
        self._service = service
        self._provider = provider

    def _get(
        self,
        auth: AdminAuth,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord:
        return self._service.get_sandbox_session(
            auth,
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
            sandbox_session_id=sandbox_session_id,
        )

    @staticmethod
    def _expected_instance_id(sandbox_session_id: UUID) -> str:
        return sandbox_resource_name(sandbox_session_id)

    def _fail(
        self,
        auth: AdminAuth,
        session: SandboxSessionRecord,
        *,
        reason: str,
    ) -> SandboxSessionRecord:
        try:
            return self._service.mark_provisioning_failed(
                session.sandbox_session_id,
                failure_reason=reason,
            )
        except ControllerConflictError:
            current = self._get(
                auth,
                target_id=session.source_target_id,
                profile_id=session.source_profile_id,
                compatibility_report_id=(
                    session.source_compatibility_report_id
                ),
                sandbox_session_id=session.sandbox_session_id,
            )
            if current.status is SandboxSessionStatus.FAILED:
                return current
            if (
                current.status is SandboxSessionStatus.READY
                and current.sandbox_instance_id
                == self._expected_instance_id(current.sandbox_session_id)
            ):
                return current
            raise

    def provision(
        self,
        auth: AdminAuth,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord:
        """Ensure one deterministic instance and record READY only after inspect."""

        session = self._get(
            auth,
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
            sandbox_session_id=sandbox_session_id,
        )
        expected_id = self._expected_instance_id(sandbox_session_id)
        if session.status is SandboxSessionStatus.READY:
            if session.sandbox_instance_id != expected_id:
                raise ControllerConflictError(
                    "stored sandbox provider identity is invalid"
                )
            return session
        if session.status is SandboxSessionStatus.REQUESTED:
            try:
                session = self._service.mark_provisioning(sandbox_session_id)
            except ControllerConflictError:
                session = self._get(
                    auth,
                    target_id=target_id,
                    profile_id=profile_id,
                    compatibility_report_id=compatibility_report_id,
                    sandbox_session_id=sandbox_session_id,
                )
        if session.status is SandboxSessionStatus.READY:
            if session.sandbox_instance_id == expected_id:
                return session
            raise ControllerConflictError(
                "stored sandbox provider identity is invalid"
            )
        if session.status is not SandboxSessionStatus.PROVISIONING:
            raise ControllerConflictError(
                "sandbox session is not eligible for provisioning"
            )
        if self._provider is None:
            return self._fail(
                auth,
                session,
                reason=self.PROVIDER_UNAVAILABLE_REASON,
            )
        try:
            if (
                self._provider.provider_type
                is not SandboxProviderType.LOCAL_NESTED_VM
                or self._provider.instance_id_for(sandbox_session_id)
                != expected_id
            ):
                return self._fail(
                    auth,
                    session,
                    reason=self.IDENTITY_FAILED_REASON,
                )
        except Exception:
            return self._fail(
                auth,
                session,
                reason=self.IDENTITY_FAILED_REASON,
            )

        try:
            provisioned = self._provider.provision(sandbox_session_id)
        except SandboxProviderUnavailableError:
            return self._fail(
                auth,
                session,
                reason=self.PROVIDER_UNAVAILABLE_REASON,
            )
        except SandboxProviderSecurityError:
            return self._fail(
                auth,
                session,
                reason=self.IDENTITY_FAILED_REASON,
            )
        except Exception:
            return self._fail(
                auth,
                session,
                reason=self.PROVISIONING_FAILED_REASON,
            )
        if (
            not isinstance(provisioned, SandboxInstance)
            or provisioned.provider_type
            is not SandboxProviderType.LOCAL_NESTED_VM
            or provisioned.sandbox_instance_id != expected_id
        ):
            return self._fail(
                auth,
                session,
                reason=self.IDENTITY_FAILED_REASON,
            )

        try:
            inspected = self._provider.inspect(sandbox_session_id)
        except SandboxProviderUnavailableError:
            return self._fail(
                auth,
                session,
                reason=self.PROVIDER_UNAVAILABLE_REASON,
            )
        except SandboxProviderSecurityError:
            return self._fail(
                auth,
                session,
                reason=self.IDENTITY_FAILED_REASON,
            )
        except Exception:
            return self._fail(
                auth,
                session,
                reason=self.INSPECTION_FAILED_REASON,
            )
        if (
            not isinstance(inspected, SandboxInstance)
            or inspected.provider_type
            is not SandboxProviderType.LOCAL_NESTED_VM
            or inspected.sandbox_instance_id != expected_id
            or inspected.sandbox_instance_id
            != provisioned.sandbox_instance_id
        ):
            return self._fail(
                auth,
                session,
                reason=self.IDENTITY_FAILED_REASON,
            )
        if inspected.runtime_state is SandboxRuntimeState.PROVISIONING:
            return session
        if inspected.runtime_state is not SandboxRuntimeState.RUNNING:
            return self._fail(
                auth,
                session,
                reason=self.RUNTIME_NOT_RUNNING_REASON,
            )
        try:
            return self._service.mark_ready(
                sandbox_session_id,
                sandbox_instance_id=inspected.sandbox_instance_id,
            )
        except ControllerConflictError:
            current = self._get(
                auth,
                target_id=target_id,
                profile_id=profile_id,
                compatibility_report_id=compatibility_report_id,
                sandbox_session_id=sandbox_session_id,
            )
            if (
                current.status is SandboxSessionStatus.READY
                and current.sandbox_instance_id == expected_id
            ):
                return current
            raise


__all__ = [
    "BackendObservation",
    "LibvirtBackend",
    "LocalNestedVmBackend",
    "LocalNestedVmConfig",
    "LocalNestedVmPlan",
    "LocalNestedVmProvider",
    "SandboxInspectionError",
    "SandboxInstance",
    "SandboxManager",
    "SandboxProvider",
    "SandboxProviderError",
    "SandboxProviderSecurityError",
    "SandboxProviderUnavailableError",
    "SandboxProvisioningError",
    "SandboxRuntimeState",
    "plan_sha256",
    "sandbox_resource_name",
]
