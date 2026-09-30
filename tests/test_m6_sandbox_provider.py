"""M6E-B sandbox provider, orchestration, and provisioning-route tests.

All virtualization behavior in this module is deterministic and fake.  The
tests intentionally do not require libvirt, KVM, qemu, or an Ubuntu image.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from http import HTTPStatus
import json
from pathlib import Path
import sqlite3
from typing import Callable
from uuid import UUID, uuid4

from pydantic import SecretStr, ValidationError
import pytest
import yaml

from src.controller.api import ControllerAPI, ENDPOINTS
from src.controller.models import (
    AdminAuth,
    AgentAuth,
    CompatibilityAnalysisRequest,
    EnrollmentRequest,
    JobCreateRequest,
    JobPollRequest,
    JobType,
    ObservedTargetMetadata,
    ProfileSubmissionRequest,
    SandboxProviderType,
    SandboxProvisionRequest,
    SandboxSessionCreateRequest,
    SandboxSessionStatus,
)
from src.controller.sandbox import (
    BackendObservation,
    LibvirtBackend,
    LocalNestedVmConfig,
    LocalNestedVmPlan,
    LocalNestedVmProvider,
    SandboxInstance,
    SandboxManager,
    SandboxProviderSecurityError,
    SandboxProviderUnavailableError,
    SandboxRuntimeState,
    plan_sha256,
    sandbox_resource_name,
)
from src.controller.service import (
    ControllerConflictError,
    ControllerNotFoundError,
    ControllerService,
    ControllerSettings,
)
from src.controller.storage import SQLiteControllerRepository
from src.controller.transport import ControllerHTTPSApplication
from src.target_profiler.models import TargetProfile


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "data" / "profiles" / "target-profile.yaml"
NOW = datetime(2026, 9, 30, 8, 30, tzinfo=UTC)
BOOTSTRAP = SecretStr("m6e-b-bootstrap-fixture")
ADMIN = SecretStr("m6e-b-admin-fixture")


class FakeSandboxProvider:
    """Deterministic manager fake with an idempotent resource registry."""

    provider_type = SandboxProviderType.LOCAL_NESTED_VM

    def __init__(
        self,
        *,
        provision_state: SandboxRuntimeState = SandboxRuntimeState.PROVISIONING,
        inspect_state: SandboxRuntimeState = SandboxRuntimeState.RUNNING,
        provision_error: Exception | None = None,
        inspect_error: Exception | None = None,
        identity_for: Callable[[UUID], str] = sandbox_resource_name,
        provision_identity_for: Callable[[UUID], str] | None = None,
        inspect_identity_for: Callable[[UUID], str] | None = None,
    ) -> None:
        self.provision_state = provision_state
        self.inspect_state = inspect_state
        self.provision_error = provision_error
        self.inspect_error = inspect_error
        self.identity_for = identity_for
        self.provision_identity_for = provision_identity_for or identity_for
        self.inspect_identity_for = inspect_identity_for or identity_for
        self.resources: set[str] = set()
        self.creation_count = 0
        self.calls: list[tuple[str, UUID]] = []

    def instance_id_for(self, sandbox_session_id: UUID) -> str:
        return self.identity_for(sandbox_session_id)

    def provision(self, sandbox_session_id: UUID) -> SandboxInstance:
        self.calls.append(("provision", sandbox_session_id))
        if self.provision_error is not None:
            raise self.provision_error
        resource = self.provision_identity_for(sandbox_session_id)
        if resource not in self.resources:
            self.resources.add(resource)
            self.creation_count += 1
        return SandboxInstance(
            sandbox_instance_id=resource,
            runtime_state=self.provision_state,
        )

    def inspect(self, sandbox_session_id: UUID) -> SandboxInstance:
        self.calls.append(("inspect", sandbox_session_id))
        if self.inspect_error is not None:
            raise self.inspect_error
        return SandboxInstance(
            sandbox_instance_id=self.inspect_identity_for(sandbox_session_id),
            runtime_state=self.inspect_state,
        )

    def destroy(self, sandbox_session_id: UUID) -> None:
        self.calls.append(("destroy", sandbox_session_id))
        self.resources.discard(self.identity_for(sandbox_session_id))


class RecordingBackend:
    """Typed local-provider backend fake that creates only an overlay file."""

    def __init__(
        self,
        *,
        provision_state: SandboxRuntimeState = SandboxRuntimeState.PROVISIONING,
        inspect_state: SandboxRuntimeState = SandboxRuntimeState.RUNNING,
    ) -> None:
        self.provision_state = provision_state
        self.inspect_state = inspect_state
        self.ensure_calls: list[LocalNestedVmPlan] = []
        self.inspect_calls: list[LocalNestedVmPlan] = []
        self.destroy_calls: list[LocalNestedVmPlan] = []
        self.resources: set[str] = set()
        self.creation_count = 0

    @staticmethod
    def _observation(
        plan: LocalNestedVmPlan,
        state: SandboxRuntimeState,
    ) -> BackendObservation:
        return BackendObservation(
            sandbox_instance_id=plan.sandbox_instance_id,
            runtime_state=state,
            plan_sha256=plan_sha256(plan),
        )

    def ensure_provisioned(
        self,
        plan: LocalNestedVmPlan,
    ) -> BackendObservation:
        self.ensure_calls.append(plan)
        if plan.sandbox_instance_id not in self.resources:
            plan.overlay_path.touch(mode=0o600, exist_ok=False)
            self.resources.add(plan.sandbox_instance_id)
            self.creation_count += 1
        return self._observation(plan, self.provision_state)

    def inspect(self, plan: LocalNestedVmPlan) -> BackendObservation:
        self.inspect_calls.append(plan)
        state = (
            self.inspect_state
            if plan.sandbox_instance_id in self.resources
            else SandboxRuntimeState.MISSING
        )
        return self._observation(plan, state)

    def destroy(self, plan: LocalNestedVmPlan) -> None:
        self.destroy_calls.append(plan)
        self.resources.discard(plan.sandbox_instance_id)


def _profile() -> TargetProfile:
    return TargetProfile.model_validate(
        yaml.safe_load(PROFILE_PATH.read_text(encoding="utf-8"))
    )


def _controller(
    tmp_path: Path,
) -> tuple[Path, ControllerService]:
    database = tmp_path / "controller.sqlite3"
    service = ControllerService(
        SQLiteControllerRepository(database),
        ControllerSettings(
            bootstrap_credential=BOOTSTRAP,
            admin_credential=ADMIN,
        ),
        clock=lambda: NOW,
    )
    return database, service


def _admin() -> AdminAuth:
    return AdminAuth(admin_credential=ADMIN)


def _agent_auth(enrollment) -> AgentAuth:
    return AgentAuth(
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
        agent_credential=enrollment.agent_credential,
    )


def _stored_profile_and_report(
    service: ControllerService,
    *,
    hostname: str = "m6e-b-source-target",
):
    enrollment = service.enroll(
        EnrollmentRequest(
            bootstrap_credential=BOOTSTRAP,
            installation_id=uuid4(),
            agent_version="m6e-b-test",
            observed_metadata=ObservedTargetMetadata(
                hostname=hostname,
                os="Ubuntu",
                os_version="24.04",
                kernel="6.8.0-m6e-b-test",
                architecture="x86_64",
            ),
        )
    )
    job = service.create_job(
        _admin(),
        JobCreateRequest(
            target_id=enrollment.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )
    polled = service.poll_jobs(JobPollRequest(auth=_agent_auth(enrollment)))
    assert [candidate.job_id for candidate in polled.jobs] == [job.job_id]
    profile = service.submit_profile(
        ProfileSubmissionRequest(
            auth=_agent_auth(enrollment),
            job_id=job.job_id,
            profile=_profile(),
            profiler_version="m3-m6e-b-test",
            sentra_version="m6e-b-test",
        )
    )
    report = service.run_compatibility_analysis(
        _admin(),
        CompatibilityAnalysisRequest(
            target_id=enrollment.target_id,
            profile_id=profile.profile_id,
        ),
    )
    return enrollment, profile, report


def _create_session(service, enrollment, profile, report):
    return service.create_sandbox_session(
        _admin(),
        target_id=enrollment.target_id,
        profile_id=profile.profile_id,
        compatibility_report_id=report.compatibility_report_id,
        request=SandboxSessionCreateRequest(
            request_id=uuid4(),
            control_id="7.1.1",
            administrator_sandbox_authorization_acknowledged=True,
        ),
    )


def _manager_provision(manager, enrollment, profile, report, session):
    return manager.provision(
        _admin(),
        target_id=enrollment.target_id,
        profile_id=profile.profile_id,
        compatibility_report_id=report.compatibility_report_id,
        sandbox_session_id=session.sandbox_session_id,
    )


def _provision_path(enrollment, profile, report, session) -> str:
    return (
        f"/api/v1/admin/targets/{enrollment.target_id}/profiles/"
        f"{profile.profile_id}/compatibility-reports/"
        f"{report.compatibility_report_id}/sandbox-sessions/"
        f"{session.sandbox_session_id}/provision"
    )


def _local_provider_fixture(
    tmp_path: Path,
    backend: RecordingBackend | LibvirtBackend,
) -> tuple[LocalNestedVmProvider, Path, Path]:
    trusted_parent = tmp_path.resolve()
    sandbox_root = trusted_parent / "sandbox-root"
    sandbox_root.mkdir(mode=0o700)
    sandbox_root.chmod(0o700)
    base_image = sandbox_root / "ubuntu-24.04-base.qcow2"
    base_image.write_bytes(b"immutable fake Ubuntu base image")
    base_image.chmod(0o600)
    provider = LocalNestedVmProvider(
        LocalNestedVmConfig(
            sandbox_root=sandbox_root,
            base_image=base_image,
        ),
        backend,
    )
    return provider, sandbox_root, base_image


def test_manager_success_requires_provision_then_running_inspection(
    tmp_path: Path,
) -> None:
    _, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, profile, report)
    provider = FakeSandboxProvider()
    manager = SandboxManager(service, provider)

    ready = _manager_provision(manager, enrollment, profile, report, session)

    expected = sandbox_resource_name(session.sandbox_session_id)
    assert ready.status is SandboxSessionStatus.READY
    assert ready.sandbox_instance_id == expected
    assert ready.provisioning_started_at == NOW
    assert ready.ready_at == NOW
    assert provider.calls == [
        ("provision", session.sandbox_session_id),
        ("inspect", session.sandbox_session_id),
    ]
    assert provider.resources == {expected}


@pytest.mark.parametrize(
    "runtime_state, expected_status",
    [
        (SandboxRuntimeState.PROVISIONING, SandboxSessionStatus.PROVISIONING),
        (SandboxRuntimeState.STOPPED, SandboxSessionStatus.FAILED),
        (SandboxRuntimeState.FAILED, SandboxSessionStatus.FAILED),
        (SandboxRuntimeState.MISSING, SandboxSessionStatus.FAILED),
    ],
)
def test_manager_never_marks_ready_without_running_inspection(
    tmp_path: Path,
    runtime_state: SandboxRuntimeState,
    expected_status: SandboxSessionStatus,
) -> None:
    _, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, profile, report)
    provider = FakeSandboxProvider(inspect_state=runtime_state)

    result = _manager_provision(
        SandboxManager(service, provider),
        enrollment,
        profile,
        report,
        session,
    )

    assert result.status is expected_status
    assert result.ready_at is None
    assert result.sandbox_instance_id is None
    if expected_status is SandboxSessionStatus.FAILED:
        assert result.failure_reason == SandboxManager.RUNTIME_NOT_RUNNING_REASON


@pytest.mark.parametrize(
    "provision_error, inspect_error, expected_reason",
    [
        (
            SandboxProviderUnavailableError(
                "libvirt URI qemu+ssh://root:secret@host/system"
            ),
            None,
            SandboxManager.PROVIDER_UNAVAILABLE_REASON,
        ),
        (
            RuntimeError(
                "traceback: /srv/sentra/private/base.qcow2 token=top-secret"
            ),
            None,
            SandboxManager.PROVISIONING_FAILED_REASON,
        ),
        (
            None,
            RuntimeError(
                "traceback: /srv/sentra/private/domain.xml password=top-secret"
            ),
            SandboxManager.INSPECTION_FAILED_REASON,
        ),
        (
            None,
            SandboxProviderUnavailableError(
                "libvirt socket /run/libvirt/private.sock is unavailable"
            ),
            SandboxManager.PROVIDER_UNAVAILABLE_REASON,
        ),
    ],
)
def test_provider_errors_fail_closed_with_bounded_sanitized_reason(
    tmp_path: Path,
    provision_error: Exception | None,
    inspect_error: Exception | None,
    expected_reason: str,
) -> None:
    _, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, profile, report)
    provider = FakeSandboxProvider(
        provision_error=provision_error,
        inspect_error=inspect_error,
    )

    result = _manager_provision(
        SandboxManager(service, provider),
        enrollment,
        profile,
        report,
        session,
    )

    assert result.status is SandboxSessionStatus.FAILED
    assert result.failure_reason == expected_reason
    assert len(result.failure_reason) < 256
    serialized = result.model_dump_json()
    for secret in ("top-secret", "root:secret", "/srv/", "/run/libvirt"):
        assert secret not in serialized


def test_missing_configured_provider_fails_closed(tmp_path: Path) -> None:
    _, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, profile, report)

    result = _manager_provision(
        SandboxManager(service, None),
        enrollment,
        profile,
        report,
        session,
    )

    assert result.status is SandboxSessionStatus.FAILED
    assert result.failure_reason == SandboxManager.PROVIDER_UNAVAILABLE_REASON


def test_retry_from_provisioning_reconciles_one_deterministic_resource(
    tmp_path: Path,
) -> None:
    _, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, profile, report)
    provisioning = service.mark_provisioning(session.sandbox_session_id)
    provider = FakeSandboxProvider()

    # Simulate the pre-crash provider call: the VM exists, but READY was never
    # committed.  The manager must replay ensure/inspect, not create a second VM.
    provider.provision(provisioning.sandbox_session_id)
    ready = _manager_provision(
        SandboxManager(service, provider),
        enrollment,
        profile,
        report,
        provisioning,
    )

    assert ready.status is SandboxSessionStatus.READY
    assert provider.creation_count == 1
    assert provider.resources == {
        sandbox_resource_name(provisioning.sandbox_session_id)
    }
    assert provider.calls == [
        ("provision", provisioning.sandbox_session_id),
        ("provision", provisioning.sandbox_session_id),
        ("inspect", provisioning.sandbox_session_id),
    ]

    replay = _manager_provision(
        SandboxManager(service, provider),
        enrollment,
        profile,
        report,
        ready,
    )
    assert replay == ready
    assert provider.creation_count == 1
    assert len(provider.calls) == 3


def test_mismatched_provider_identities_fail_closed(tmp_path: Path) -> None:
    _, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    other_id = uuid4()

    providers = [
        FakeSandboxProvider(identity_for=lambda _: sandbox_resource_name(other_id)),
        FakeSandboxProvider(
            provision_identity_for=lambda _: sandbox_resource_name(other_id)
        ),
        FakeSandboxProvider(
            inspect_identity_for=lambda _: sandbox_resource_name(other_id)
        ),
    ]
    for provider in providers:
        session = _create_session(service, enrollment, profile, report)
        result = _manager_provision(
            SandboxManager(service, provider),
            enrollment,
            profile,
            report,
            session,
        )
        assert result.status is SandboxSessionStatus.FAILED
        assert result.failure_reason == SandboxManager.IDENTITY_FAILED_REASON
        assert result.sandbox_instance_id is None


def test_malformed_persisted_provider_identity_fails_closed(
    tmp_path: Path,
) -> None:
    database, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, profile, report)
    service.mark_provisioning(session.sandbox_session_id)
    service.mark_ready(
        session.sandbox_session_id,
        sandbox_instance_id=sandbox_resource_name(session.sandbox_session_id),
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE sandbox_sessions SET sandbox_instance_id = ? "
            "WHERE sandbox_session_id = ?",
            ("../../caller-controlled", str(session.sandbox_session_id)),
        )

    with pytest.raises(ControllerConflictError):
        _manager_provision(
            SandboxManager(service, FakeSandboxProvider()),
            enrollment,
            profile,
            report,
            session,
        )


@pytest.mark.parametrize(
    "persisted_session_id",
    [
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
        "{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}",
        "not-a-sandbox-session-uuid",
    ],
)
def test_noncanonical_or_malformed_persisted_session_id_fails_closed(
    tmp_path: Path,
    persisted_session_id: str,
) -> None:
    database, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, profile, report)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE sandbox_sessions SET sandbox_session_id = ? "
            "WHERE sandbox_session_id = ?",
            (persisted_session_id, str(session.sandbox_session_id)),
        )

    with pytest.raises(ControllerConflictError):
        service.list_sandbox_sessions(
            _admin(),
            target_id=enrollment.target_id,
            profile_id=profile.profile_id,
            compatibility_report_id=report.compatibility_report_id,
        )
    with pytest.raises(ControllerNotFoundError):
        _manager_provision(
            SandboxManager(service, FakeSandboxProvider()),
            enrollment,
            profile,
            report,
            session,
        )


def test_resource_name_uses_only_canonical_session_uuid() -> None:
    session_id = UUID("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")

    resource = sandbox_resource_name(session_id)

    assert resource == "sentra-sbx-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    assert "customer" not in resource
    with pytest.raises(SandboxProviderSecurityError):
        sandbox_resource_name("customer-hostname")  # type: ignore[arg-type]


def test_local_provider_plan_uses_read_only_base_and_unique_overlays(
    tmp_path: Path,
) -> None:
    backend = RecordingBackend()
    provider, sandbox_root, base_image = _local_provider_fixture(tmp_path, backend)
    base_before = base_image.read_bytes()
    first_session = uuid4()
    second_session = uuid4()

    first = provider.provision(first_session)
    second = provider.provision(second_session)

    assert first.sandbox_instance_id == sandbox_resource_name(first_session)
    assert second.sandbox_instance_id == sandbox_resource_name(second_session)
    assert first.sandbox_instance_id != second.sandbox_instance_id
    assert base_image.read_bytes() == base_before
    assert backend.creation_count == 2
    first_plan, second_plan = backend.ensure_calls
    assert first_plan.base_image == second_plan.base_image == base_image
    assert first_plan.base_image_read_only is True
    assert second_plan.base_image_read_only is True
    assert first_plan.overlay_path != second_plan.overlay_path
    assert first_plan.overlay_path.name == second_plan.overlay_path.name == "root.qcow2"
    assert first_plan.overlay_path.is_relative_to(sandbox_root)
    assert second_plan.overlay_path.is_relative_to(sandbox_root)
    assert first_plan.host_mounts == second_plan.host_mounts == ()
    assert first_plan.device_passthrough == second_plan.device_passthrough == ()
    assert first_plan.cloud_init is second_plan.cloud_init is None
    assert first_plan.memory_mib == second_plan.memory_mib == 2048
    assert first_plan.vcpus == second_plan.vcpus == 2
    assert first_plan.network == second_plan.network == "default"


def test_local_provider_rejects_base_image_inside_session_storage(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path.resolve() / "sandbox-root"
    sandbox_root.mkdir(mode=0o700)
    sandbox_root.chmod(0o700)
    session_id = uuid4()
    session_directory = sandbox_root / sandbox_resource_name(session_id)
    session_directory.mkdir(mode=0o700)
    session_directory.chmod(0o700)
    colliding_base = session_directory / "root.qcow2"
    colliding_base.write_bytes(b"misconfigured base image")
    colliding_base.chmod(0o600)
    backend = RecordingBackend()
    provider = LocalNestedVmProvider(
        LocalNestedVmConfig(
            sandbox_root=sandbox_root,
            base_image=colliding_base,
        ),
        backend,
    )

    with pytest.raises(
        SandboxProviderSecurityError,
        match="base image must be separate",
    ):
        provider.provision(session_id)

    assert backend.ensure_calls == []
    assert colliding_base.read_bytes() == b"misconfigured base image"


def test_local_provider_replay_is_idempotent_and_inspects_same_plan(
    tmp_path: Path,
) -> None:
    backend = RecordingBackend()
    provider, _, _ = _local_provider_fixture(tmp_path, backend)
    session_id = uuid4()

    first = provider.provision(session_id)
    overlay = backend.ensure_calls[0].overlay_path
    first_inode = overlay.stat().st_ino
    replay = provider.provision(session_id)
    inspected = provider.inspect(session_id)

    assert first == replay
    assert inspected.runtime_state is SandboxRuntimeState.RUNNING
    assert inspected.sandbox_instance_id == first.sandbox_instance_id
    assert backend.creation_count == 1
    assert len(backend.resources) == 1
    assert overlay.stat().st_ino == first_inode
    assert backend.ensure_calls[0] == backend.ensure_calls[1]
    assert backend.inspect_calls == [backend.ensure_calls[0]]


@pytest.mark.parametrize(
    "document",
    [
        {"sandbox_root": "relative/root", "base_image": "/trusted/base.qcow2"},
        {
            "sandbox_root": "/trusted/root/../escape",
            "base_image": "/trusted/base.qcow2",
        },
        {
            "sandbox_root": "/trusted/root",
            "base_image": "/trusted/root/../escape/base.qcow2",
        },
    ],
)
def test_local_provider_config_rejects_relative_and_traversal_paths(
    document: dict[str, str],
) -> None:
    with pytest.raises(ValidationError):
        LocalNestedVmConfig.model_validate(document)


def test_local_provider_rejects_symlinked_root_and_session_directory(
    tmp_path: Path,
) -> None:
    trusted_parent = tmp_path.resolve()
    real_root = trusted_parent / "real-root"
    real_root.mkdir(mode=0o700)
    real_root.chmod(0o700)
    base_image = real_root / "base.qcow2"
    base_image.write_bytes(b"base")
    base_image.chmod(0o600)
    linked_root = trusted_parent / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(SandboxProviderSecurityError):
        LocalNestedVmProvider(
            LocalNestedVmConfig(
                sandbox_root=linked_root,
                base_image=base_image,
            ),
            RecordingBackend(),
        )

    provider = LocalNestedVmProvider(
        LocalNestedVmConfig(
            sandbox_root=real_root,
            base_image=base_image,
        ),
        RecordingBackend(),
    )
    session_id = uuid4()
    escaped = trusted_parent / "escaped"
    escaped.mkdir(mode=0o700)
    (real_root / sandbox_resource_name(session_id)).symlink_to(
        escaped,
        target_is_directory=True,
    )
    with pytest.raises(SandboxProviderSecurityError):
        provider.provision(session_id)
    assert list(escaped.iterdir()) == []


def test_local_provider_rejects_unsafe_root_or_ancestor_permissions(
    tmp_path: Path,
) -> None:
    trusted_parent = tmp_path.resolve()
    for unsafe_component in ("ancestor", "root"):
        parent = trusted_parent / f"{unsafe_component}-case"
        parent.mkdir(mode=0o700)
        parent.chmod(0o700)
        sandbox_root = parent / "sandbox-root"
        sandbox_root.mkdir(mode=0o700)
        sandbox_root.chmod(0o700)
        base_image = sandbox_root / "base.qcow2"
        base_image.write_bytes(b"base")
        base_image.chmod(0o600)
        target = parent if unsafe_component == "ancestor" else sandbox_root
        target.chmod(0o770)

        with pytest.raises(SandboxProviderSecurityError):
            LocalNestedVmProvider(
                LocalNestedVmConfig(
                    sandbox_root=sandbox_root,
                    base_image=base_image,
                ),
                RecordingBackend(),
            )


def test_local_provider_rejects_symlinked_base_image_and_overlay(
    tmp_path: Path,
) -> None:
    trusted_parent = tmp_path.resolve()
    sandbox_root = trusted_parent / "sandbox-root"
    sandbox_root.mkdir(mode=0o700)
    sandbox_root.chmod(0o700)
    real_base = sandbox_root / "real-base.qcow2"
    real_base.write_bytes(b"base")
    real_base.chmod(0o600)
    linked_base = sandbox_root / "linked-base.qcow2"
    linked_base.symlink_to(real_base)

    with pytest.raises(SandboxProviderSecurityError):
        LocalNestedVmProvider(
            LocalNestedVmConfig(
                sandbox_root=sandbox_root,
                base_image=linked_base,
            ),
            RecordingBackend(),
        )

    backend = RecordingBackend()
    provider = LocalNestedVmProvider(
        LocalNestedVmConfig(
            sandbox_root=sandbox_root,
            base_image=real_base,
        ),
        backend,
    )
    session_id = uuid4()
    session_directory = sandbox_root / sandbox_resource_name(session_id)
    session_directory.mkdir(mode=0o700)
    session_directory.chmod(0o700)
    escaped_overlay = trusted_parent / "escaped-overlay.qcow2"
    escaped_overlay.write_bytes(b"must remain untouched")
    escaped_overlay.chmod(0o600)
    (session_directory / "root.qcow2").symlink_to(escaped_overlay)

    with pytest.raises(SandboxProviderSecurityError):
        provider.provision(session_id)
    assert escaped_overlay.read_bytes() == b"must remain untouched"
    assert backend.ensure_calls == []


def test_local_provider_rejects_backend_observation_for_another_plan(
    tmp_path: Path,
) -> None:
    class MismatchedBackend(RecordingBackend):
        def ensure_provisioned(
            self,
            plan: LocalNestedVmPlan,
        ) -> BackendObservation:
            super().ensure_provisioned(plan)
            return BackendObservation(
                sandbox_instance_id=sandbox_resource_name(uuid4()),
                runtime_state=SandboxRuntimeState.RUNNING,
                plan_sha256=plan_sha256(plan),
            )

    provider, _, _ = _local_provider_fixture(tmp_path, MismatchedBackend())
    with pytest.raises(SandboxProviderSecurityError):
        provider.provision(uuid4())


def test_local_provider_rejects_backend_observation_for_another_plan_hash(
    tmp_path: Path,
) -> None:
    class MismatchedHashBackend(RecordingBackend):
        def ensure_provisioned(
            self,
            plan: LocalNestedVmPlan,
        ) -> BackendObservation:
            super().ensure_provisioned(plan)
            return BackendObservation(
                sandbox_instance_id=plan.sandbox_instance_id,
                runtime_state=SandboxRuntimeState.RUNNING,
                plan_sha256="0" * 64,
            )

    provider, _, _ = _local_provider_fixture(tmp_path, MismatchedHashBackend())
    with pytest.raises(SandboxProviderSecurityError):
        provider.provision(uuid4())


def test_libvirt_is_loaded_lazily_and_unavailability_is_controlled(
    tmp_path: Path,
) -> None:
    module_requests: list[str] = []

    def unavailable_loader(module_name: str) -> object:
        module_requests.append(module_name)
        raise ModuleNotFoundError("raw host import detail")

    backend = LibvirtBackend(module_loader=unavailable_loader)
    provider, _, _ = _local_provider_fixture(tmp_path, backend)
    assert module_requests == []

    with pytest.raises(
        SandboxProviderUnavailableError,
        match="libvirt backend is unavailable",
    ):
        provider.provision(uuid4())
    assert module_requests == ["libvirt"]


def test_sandbox_provider_module_has_no_process_execution_surface() -> None:
    path = ROOT / "src" / "controller" / "sandbox.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    forbidden_imports = {"subprocess", "pty", "shlex"}
    forbidden_names = {"eval", "exec"}
    forbidden_os_calls = {"system", "popen"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not ({alias.name for alias in node.names} & forbidden_imports)
        if isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden_imports
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            assert node.func.id not in forbidden_names
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        ):
            assert node.func.attr not in forbidden_os_calls
            assert not node.func.attr.startswith(("exec", "spawn"))


@pytest.mark.parametrize(
    "field, value",
    [
        ("memory", 4096),
        ("memory_mib", 4096),
        ("cpu", 8),
        ("vcpus", 8),
        ("image", "ubuntu.qcow2"),
        ("base_image", "/srv/base.qcow2"),
        ("path", "/tmp/escape"),
        ("disk_path", "/tmp/disk.qcow2"),
        ("network", "production"),
        ("command", "id"),
        ("shell", True),
        ("argv", ["sh", "-c", "id"]),
        ("script", "echo unsafe"),
        ("executable", "/bin/sh"),
        ("xml", "<domain/>"),
        ("domain_xml", "<domain/>"),
        ("libvirt_xml", "<domain/>"),
        ("provider_payload", {"unsafe": True}),
        ("provider_type", "local_nested_vm"),
        ("adapter", "arbitrary"),
        ("mounts", ["/"]),
        ("host_mount", "/"),
        ("environment", {"TOKEN": "secret"}),
        ("qemu_args", ["-device", "hostdev"]),
        ("virsh_args", ["--connect", "production"]),
        ("sandbox_instance_id", "caller-selected"),
    ],
)
def test_provision_http_request_rejects_every_caller_infrastructure_field(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    _, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, profile, report)
    provider = FakeSandboxProvider()
    application = ControllerHTTPSApplication(
        ControllerAPI(service, SandboxManager(service, provider))
    )
    headers = {"Authorization": f"Bearer {ADMIN.get_secret_value()}"}

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SandboxProvisionRequest.model_validate({field: value})
    response = application.dispatch(
        "POST",
        _provision_path(enrollment, profile, report, session),
        json.dumps({field: value}).encode("utf-8"),
        headers,
    )

    assert response.status is HTTPStatus.BAD_REQUEST
    assert provider.calls == []
    unchanged = service.get_sandbox_session(
        _admin(),
        target_id=enrollment.target_id,
        profile_id=profile.profile_id,
        compatibility_report_id=report.compatibility_report_id,
        sandbox_session_id=session.sandbox_session_id,
    )
    assert unchanged.status is SandboxSessionStatus.REQUESTED


def test_provision_http_route_requires_admin_and_validates_full_lineage(
    tmp_path: Path,
) -> None:
    _, service = _controller(tmp_path)
    first, first_profile, first_report = _stored_profile_and_report(
        service,
        hostname="first-customer-hostname",
    )
    session = _create_session(service, first, first_profile, first_report)
    second, second_profile, second_report = _stored_profile_and_report(
        service,
        hostname="second-customer-hostname",
    )
    provider = FakeSandboxProvider()
    application = ControllerHTTPSApplication(
        ControllerAPI(service, SandboxManager(service, provider))
    )
    valid_path = _provision_path(first, first_profile, first_report, session)
    admin_header = {"Authorization": f"Bearer {ADMIN.get_secret_value()}"}
    agent_header = {
        "Authorization": f"Bearer {first.agent_credential.get_secret_value()}"
    }

    assert application.dispatch("POST", valid_path, b"{}").status is (
        HTTPStatus.UNAUTHORIZED
    )
    assert application.dispatch(
        "POST", valid_path, b"{}", agent_header
    ).status is HTTPStatus.UNAUTHORIZED
    assert provider.calls == []

    wrong_paths = [
        valid_path.replace(str(first.target_id), str(second.target_id), 1),
        valid_path.replace(str(first_profile.profile_id), str(second_profile.profile_id), 1),
        valid_path.replace(
            str(first_report.compatibility_report_id),
            str(second_report.compatibility_report_id),
            1,
        ),
        valid_path.replace(str(session.sandbox_session_id), str(uuid4()), 1),
    ]
    for wrong_path in wrong_paths:
        rejected = application.dispatch("POST", wrong_path, b"{}", admin_header)
        assert rejected.status in {
            HTTPStatus.FORBIDDEN,
            HTTPStatus.NOT_FOUND,
            HTTPStatus.CONFLICT,
        }
    assert provider.calls == []

    provisioned = application.dispatch("POST", valid_path, b"{}", admin_header)
    assert provisioned.status is HTTPStatus.OK
    body = json.loads(provisioned.body)
    assert body["status"] == SandboxSessionStatus.READY.value
    assert body["sandbox_instance_id"] == sandbox_resource_name(
        session.sandbox_session_id
    )
    assert "first-customer-hostname" not in body["sandbox_instance_id"]


def test_no_generic_sandbox_lifecycle_or_destroy_http_endpoint_exists(
    tmp_path: Path,
) -> None:
    _, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    session = _create_session(service, enrollment, profile, report)
    application = ControllerHTTPSApplication(
        ControllerAPI(service, SandboxManager(service, FakeSandboxProvider()))
    )
    admin_header = {"Authorization": f"Bearer {ADMIN.get_secret_value()}"}
    item_path = _provision_path(enrollment, profile, report, session).removesuffix(
        "/provision"
    )

    for suffix in ("status", "lifecycle", "inspect", "destroy"):
        response = application.dispatch(
            "POST",
            f"{item_path}/{suffix}",
            b"{}",
            admin_header,
        )
        assert response.status is HTTPStatus.NOT_FOUND
    assert all(
        not endpoint.path.endswith(("/status", "/lifecycle", "/inspect", "/destroy"))
        for endpoint in ENDPOINTS
    )
