"""Typed M6E-B sandbox provider and orchestration boundaries.

The provider receives only a Controller-issued sandbox-session UUID.  VM
configuration is derived from protected server-side configuration and a fixed
plan; no API request can introduce commands, XML, paths, mounts, resources, or
provider-specific payloads.

The real libvirt storage/domain adapter is intentionally left behind a lazy
backend boundary until the Ubuntu SENTRA Appliance experiment.  Importing this
module and exercising fake backends on macOS never imports libvirt.
"""

from __future__ import annotations

from enum import StrEnum
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
from typing import Callable, Literal, Protocol
from uuid import UUID

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


_RESOURCE_PREFIX = "sentra-sbx-"
_OVERLAY_FILENAME = "root.qcow2"
_INSTANCE_PATTERN = r"^sentra-sbx-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"


class SandboxRuntimeState(StrEnum):
    """Closed runtime observation vocabulary returned by a provider."""

    PROVISIONING = "PROVISIONING"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    MISSING = "MISSING"


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


def _require_trusted_ancestry(path: Path) -> None:
    """Reject replaceable or symlinked existing server path components."""

    effective_uid = os.geteuid()
    allowed_owners = {0} if effective_uid == 0 else {0, effective_uid}
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
        _require_trusted_ancestry(directory)
        return directory

    @staticmethod
    def _validate_overlay(path: Path, *, required: bool) -> None:
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
        if overlay_stat.st_uid != os.geteuid():
            raise SandboxProviderSecurityError(
                "sandbox overlay owner is not trusted"
            )
        if stat.S_IMODE(overlay_stat.st_mode) & 0o022:
            raise SandboxProviderSecurityError(
                "sandbox overlay must not be group/world writable"
            )

    def _plan(
        self,
        sandbox_session_id: UUID,
        *,
        prepare_directory: bool,
    ) -> LocalNestedVmPlan:
        root = self._config.sandbox_root
        _stat_trusted_root(root)
        _stat_trusted_base_image(self._config.base_image)
        directory = (
            self._ensure_session_directory(sandbox_session_id)
            if prepare_directory
            else self._session_directory(sandbox_session_id)
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
        _require_trusted_ancestry(directory)
        overlay = directory / _OVERLAY_FILENAME
        try:
            overlay.relative_to(root)
        except ValueError as error:
            raise SandboxProviderSecurityError(
                "sandbox overlay escaped the configured root"
            ) from error
        self._validate_overlay(overlay, required=False)
        return LocalNestedVmPlan(
            sandbox_session_id=sandbox_session_id,
            sandbox_instance_id=self.instance_id_for(sandbox_session_id),
            base_image=self._config.base_image,
            overlay_path=overlay,
            network=self._config.network,
            memory_mib=self._config.memory_mib,
            vcpus=self._config.vcpus,
        )

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
        self._validate_overlay(plan.overlay_path, required=True)
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
            self._validate_overlay(plan.overlay_path, required=True)
        return self._validate_observation(plan, observation)

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


class LibvirtBackend:
    """Lazy fail-closed boundary for the later Ubuntu libvirt adapter.

    M6E-B intentionally does not issue real libvirt storage/domain mutations.
    The appliance experiment will implement and validate these typed methods.
    """

    def __init__(
        self,
        *,
        module_loader: Callable[[str], object] | None = None,
    ) -> None:
        self._module_loader = module_loader
        self._libvirt: object | None = None

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

    def _not_enabled(self) -> None:
        self._load()
        raise SandboxProviderUnavailableError(
            "libvirt appliance integration is not enabled"
        )

    def ensure_provisioned(self, plan: LocalNestedVmPlan) -> BackendObservation:
        self._not_enabled()

    def inspect(self, plan: LocalNestedVmPlan) -> BackendObservation:
        self._not_enabled()

    def destroy(self, plan: LocalNestedVmPlan) -> None:
        self._not_enabled()


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
