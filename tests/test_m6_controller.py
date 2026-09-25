"""M6A controller, storage, API, isolation, and evidence-lineage tests."""

from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import UUID, uuid4

from pydantic import SecretStr, ValidationError
import pytest

from src.controller.api import API_PREFIX, ENDPOINTS, ControllerAPI
from src.controller.models import (
    AdminAuth,
    AgentAuth,
    EnrollmentRequest,
    HeartbeatRequest,
    JobCreateRequest,
    JobPollRequest,
    JobStatus,
    JobType,
    ObservedTargetMetadata,
    ProfileRecord,
    ProfileSubmissionRequest,
    TargetStatus,
)
from src.controller.service import (
    AuthenticationError,
    AuthorizationError,
    ControllerConflictError,
    ControllerNotFoundError,
    ControllerService,
    ControllerSettings,
)
from src.controller.storage import (
    ControllerStorageSecurityError,
    SQLiteControllerRepository,
    StorageConflictError,
    StorageNotFoundError,
)
from src.target_profiler.models import (
    CollectionSummary,
    FactResult,
    FactStatus,
    TargetInfo,
    TargetProfile,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 23, 8, 30, tzinfo=timezone.utc)
BOOTSTRAP = SecretStr("bootstrap-fixture-that-is-not-logged")
ADMIN = SecretStr("admin-fixture-that-is-not-logged")


def _metadata(hostname: str, *, kernel: str = "6.8.0-fixture") -> ObservedTargetMetadata:
    return ObservedTargetMetadata(
        hostname=hostname,
        os="Ubuntu",
        os_version="24.04",
        kernel=kernel,
        architecture="x86_64",
    )


def _controller(
    tmp_path: Path,
) -> tuple[SQLiteControllerRepository, ControllerService, ControllerAPI]:
    repository = SQLiteControllerRepository(tmp_path / "controller.sqlite3")
    service = ControllerService(
        repository,
        ControllerSettings(
            bootstrap_credential=BOOTSTRAP,
            admin_credential=ADMIN,
            polling_interval_seconds=20,
        ),
        clock=lambda: NOW,
    )
    return repository, service, ControllerAPI(service)


def _enroll(
    api: ControllerAPI,
    hostname: str,
    *,
    installation_id: UUID | None = None,
):
    return api.enroll(
        EnrollmentRequest(
            bootstrap_credential=BOOTSTRAP,
            installation_id=installation_id or uuid4(),
            agent_version="0.6a-test",
            observed_metadata=_metadata(hostname),
        )
    )


def _auth(enrollment) -> AgentAuth:
    return AgentAuth(
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
        agent_credential=enrollment.agent_credential,
    )


def _admin() -> AdminAuth:
    return AdminAuth(admin_credential=ADMIN)


def _profile() -> TargetProfile:
    requested_by = ["3.3.1"]
    facts = {
        "collected_fixture": FactResult(
            name="collected_fixture",
            status=FactStatus.COLLECTED,
            value=True,
            requested_by=requested_by,
        ),
        "unavailable_fixture": FactResult(
            name="unavailable_fixture",
            status=FactStatus.UNAVAILABLE,
            value=None,
            requested_by=requested_by,
            reason="fixture permission boundary",
        ),
        "unsupported_fixture": FactResult(
            name="unsupported_fixture",
            status=FactStatus.UNSUPPORTED,
            value=None,
            requested_by=requested_by,
            reason="fixture platform boundary",
        ),
        "error_fixture": FactResult(
            name="error_fixture",
            status=FactStatus.ERROR,
            value=None,
            requested_by=requested_by,
            reason="fixture collection error",
        ),
    }
    return TargetProfile(
        collected_at=NOW - timedelta(minutes=1),
        target=TargetInfo(
            hostname="observed-profile-host",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-profile",
            architecture="x86_64",
            supported=True,
        ),
        facts=facts,
        collection_summary=CollectionSummary(
            requested=4,
            collected=1,
            unavailable=1,
            unsupported=1,
            errors=1,
        ),
    )


def _create_and_poll_profile_job(
    api: ControllerAPI, enrollment
):
    job = api.create_profile_job(
        enrollment.target_id,
        _admin(),
        JobCreateRequest(
            target_id=enrollment.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )
    response = api.poll_jobs(
        enrollment.agent_id,
        JobPollRequest(auth=_auth(enrollment)),
    )
    assert [item.job_id for item in response.jobs] == [job.job_id]
    assert response.jobs[0].status is JobStatus.DISPATCHED
    return job


def test_api_namespace_contains_only_narrow_controller_operations() -> None:
    assert API_PREFIX == "/api/v1"
    assert {(endpoint.method, endpoint.path) for endpoint in ENDPOINTS} == {
        ("POST", "/api/v1/enrollment"),
        ("POST", "/api/v1/agents/{agent_id}/heartbeat"),
        ("POST", "/api/v1/agents/{agent_id}/jobs/poll"),
        ("POST", "/api/v1/agents/{agent_id}/profiles"),
        ("GET", "/api/v1/admin/targets"),
        ("POST", "/api/v1/admin/targets/{target_id}/jobs"),
        (
            "POST",
            "/api/v1/admin/targets/{target_id}/profiles/{profile_id}/"
            "compatibility-reports",
        ),
        (
            "GET",
            "/api/v1/admin/targets/{target_id}/profiles/{profile_id}/"
            "compatibility-reports",
        ),
        (
            "GET",
            "/api/v1/admin/targets/{target_id}/profiles/{profile_id}/"
            "compatibility-reports/{compatibility_report_id}",
        ),
    }


def test_controller_settings_redact_plain_strings_and_reject_noninteger_limits() -> None:
    settings = ControllerSettings(
        bootstrap_credential="bootstrap-plaintext-sentinel",
        admin_credential="admin-plaintext-sentinel",
    )

    assert "bootstrap-plaintext-sentinel" not in repr(settings)
    assert "admin-plaintext-sentinel" not in repr(settings)
    assert "**********" in repr(settings)
    with pytest.raises(ValidationError):
        ControllerSettings(
            bootstrap_credential="bootstrap",
            admin_credential="admin",
            polling_interval_seconds=5.5,
        )
    with pytest.raises(ValidationError):
        ControllerSettings(
            bootstrap_credential="bootstrap",
            admin_credential="admin",
            max_jobs_per_poll=1.5,
        )
    assert {endpoint.operation for endpoint in ENDPOINTS} == {
        "enroll",
        "heartbeat",
        "poll_jobs",
        "submit_profile",
        "list_targets",
        "create_profile_job",
        "run_compatibility_analysis",
        "list_compatibility_reports",
        "get_compatibility_report",
    }


def test_controller_ids_are_opaque_and_independent_of_observed_metadata(
    tmp_path: Path,
) -> None:
    _, _, api = _controller(tmp_path)
    first = _enroll(api, "same-observed-host")
    second = _enroll(api, "same-observed-host")

    assert first.target_id != second.target_id
    assert first.agent_id != second.agent_id
    assert first.target_id != first.agent_id
    assert "same-observed-host" not in str(first)
    with pytest.raises(ValidationError):
        ObservedTargetMetadata.model_validate(
            {
                **_metadata("host").model_dump(),
                "ip_address": "192.0.2.10",
            }
        )


def test_enrollment_rejects_invalid_bootstrap_and_duplicate_installation(
    tmp_path: Path,
) -> None:
    _, _, api = _controller(tmp_path)
    installation_id = uuid4()
    with pytest.raises(AuthenticationError, match="invalid enrollment"):
        api.enroll(
            EnrollmentRequest(
                bootstrap_credential=SecretStr("wrong"),
                installation_id=installation_id,
                agent_version="0.6a-test",
                observed_metadata=_metadata("target-one"),
            )
        )

    _enroll(api, "target-one", installation_id=installation_id)
    with pytest.raises(ControllerConflictError, match="already enrolled"):
        _enroll(api, "renamed-observation", installation_id=installation_id)


def test_controller_persists_only_agent_credential_verifier(tmp_path: Path) -> None:
    database = tmp_path / "controller.sqlite3"
    _, _, api = _controller(tmp_path)
    enrollment = _enroll(api, "credential-target")
    plaintext = enrollment.agent_credential.get_secret_value()

    assert plaintext not in database.read_bytes().decode("latin-1")
    assert plaintext not in repr(enrollment)
    with sqlite3.connect(database) as connection:
        stored = connection.execute(
            "SELECT credential_hash FROM agents WHERE agent_id = ?",
            (str(enrollment.agent_id),),
        ).fetchone()[0]
    assert stored.startswith("pbkdf2_sha256$")


def test_controller_database_path_is_private_absolute_and_not_symlinked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_directory = tmp_path / "first"
    first_directory.mkdir()
    monkeypatch.chdir(first_directory)
    repository = SQLiteControllerRepository(Path("state") / "controller.sqlite3")
    database = repository.path

    assert database.is_absolute()
    assert database.stat().st_mode & 0o777 == 0o600
    second_directory = tmp_path / "second"
    second_directory.mkdir()
    monkeypatch.chdir(second_directory)
    assert repository.list_targets() == []

    link = tmp_path / "controller-link.sqlite3"
    link.symlink_to(database)
    with pytest.raises(ControllerStorageSecurityError, match="symlink"):
        SQLiteControllerRepository(link)
    with pytest.raises(ControllerStorageSecurityError, match="filesystem"):
        SQLiteControllerRepository(":memory:")


def test_controller_identity_and_authentication_survive_repository_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "controller.sqlite3"
    _, _, first_api = _controller(tmp_path)
    enrollment = _enroll(first_api, "persistent-target")

    restarted_repository = SQLiteControllerRepository(database)
    restarted_service = ControllerService(
        restarted_repository,
        ControllerSettings(
            bootstrap_credential=BOOTSTRAP,
            admin_credential=ADMIN,
            polling_interval_seconds=20,
        ),
        clock=lambda: NOW,
    )
    heartbeat = restarted_service.heartbeat(
        HeartbeatRequest(
            auth=_auth(enrollment),
            sent_at=NOW,
            agent_version="0.6a-test",
            observed_metadata=_metadata("persistent-target"),
        )
    )

    assert heartbeat.accepted is True
    assert restarted_service.list_targets(_admin())[0].target_id == enrollment.target_id


def test_authenticated_heartbeat_records_status_last_seen_and_metadata_change(
    tmp_path: Path,
) -> None:
    repository, service, api = _controller(tmp_path)
    enrollment = _enroll(api, "heartbeat-target")
    changed = _metadata("heartbeat-target", kernel="6.8.0-updated")
    response = api.heartbeat(
        enrollment.agent_id,
        HeartbeatRequest(
            auth=_auth(enrollment),
            sent_at=NOW - timedelta(seconds=1),
            agent_version="0.6a-updated",
            observed_metadata=changed,
        ),
    )

    assert response.accepted is True
    assert response.last_seen == NOW
    target = service.list_targets(_admin())[0]
    assert target.status is TargetStatus.ONLINE
    assert target.last_seen == NOW
    assert target.agent_version == "0.6a-updated"
    changes = repository.list_metadata_changes(enrollment.target_id)
    assert len(changes) == 1
    assert changes[0].previous_metadata.kernel == "6.8.0-fixture"
    assert changes[0].current_metadata.kernel == "6.8.0-updated"


def test_invalid_agent_credential_and_cross_target_impersonation_are_rejected(
    tmp_path: Path,
) -> None:
    _, service, api = _controller(tmp_path)
    first = _enroll(api, "target-a")
    second = _enroll(api, "target-b")

    invalid = AgentAuth(
        target_id=first.target_id,
        agent_id=first.agent_id,
        agent_credential=SecretStr("wrong"),
    )
    with pytest.raises(AuthenticationError):
        service.poll_jobs(JobPollRequest(auth=invalid))

    impersonating = AgentAuth(
        target_id=second.target_id,
        agent_id=first.agent_id,
        agent_credential=first.agent_credential,
    )
    with pytest.raises(AuthenticationError):
        service.heartbeat(
            HeartbeatRequest(
                auth=impersonating,
                sent_at=NOW,
                agent_version="0.6a-test",
                observed_metadata=_metadata("target-b"),
            )
        )

    exact_agent_b_identity_with_agent_a_credential = AgentAuth(
        target_id=second.target_id,
        agent_id=second.agent_id,
        agent_credential=first.agent_credential,
    )
    with pytest.raises(AuthenticationError):
        api.heartbeat(
            second.agent_id,
            HeartbeatRequest(
                auth=exact_agent_b_identity_with_agent_a_credential,
                sent_at=NOW,
                agent_version="0.6a-test",
                observed_metadata=_metadata("target-b"),
            ),
        )


def test_controller_maintains_two_targets_and_isolates_jobs(tmp_path: Path) -> None:
    _, service, api = _controller(tmp_path)
    first = _enroll(api, "target-a")
    second = _enroll(api, "target-b")
    first_job = api.create_profile_job(
        first.target_id,
        _admin(),
        JobCreateRequest(
            target_id=first.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )
    second_job = api.create_profile_job(
        second.target_id,
        _admin(),
        JobCreateRequest(
            target_id=second.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )

    first_poll = service.poll_jobs(JobPollRequest(auth=_auth(first)))
    second_poll = service.poll_jobs(JobPollRequest(auth=_auth(second)))
    assert [item.job_id for item in first_poll.jobs] == [first_job.job_id]
    assert [item.job_id for item in second_poll.jobs] == [second_job.job_id]
    assert {item.target_id for item in first_poll.jobs} == {first.target_id}
    assert {item.target_id for item in second_poll.jobs} == {second.target_id}
    assert {target.target_id for target in service.list_targets(_admin())} == {
        first.target_id,
        second.target_id,
    }


def test_repository_itself_refuses_cross_target_job_assignment(tmp_path: Path) -> None:
    repository, _, api = _controller(tmp_path)
    first = _enroll(api, "target-a")
    second = _enroll(api, "target-b")
    api.create_profile_job(
        first.target_id,
        _admin(),
        JobCreateRequest(
            target_id=first.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )

    with pytest.raises(StorageNotFoundError, match="binding"):
        repository.poll_jobs(
            target_id=first.target_id,
            agent_id=second.agent_id,
            dispatched_at=NOW,
            limit=10,
        )


@pytest.mark.parametrize(
    "forbidden_type",
    ["RUN_COMMAND", "RUN_SHELL", "EXEC", "COMMAND_STRING", "REMEDIATE"],
)
def test_command_like_and_unknown_job_types_are_rejected(
    forbidden_type: str,
) -> None:
    with pytest.raises(ValidationError):
        JobCreateRequest(
            target_id=uuid4(),
            job_type=forbidden_type,  # type: ignore[arg-type]
        )


def test_admin_auth_and_path_body_bindings_are_enforced(tmp_path: Path) -> None:
    _, service, api = _controller(tmp_path)
    enrollment = _enroll(api, "binding-target")
    request = JobCreateRequest(
        target_id=enrollment.target_id,
        job_type=JobType.PROFILE_TARGET,
    )
    with pytest.raises(AuthenticationError):
        service.list_targets(AdminAuth(admin_credential=SecretStr("wrong")))
    with pytest.raises(AuthenticationError, match="target path"):
        api.create_profile_job(uuid4(), _admin(), request)
    with pytest.raises(AuthenticationError, match="agent path"):
        api.poll_jobs(uuid4(), JobPollRequest(auth=_auth(enrollment)))
    with pytest.raises(ControllerNotFoundError):
        service.create_job(
            _admin(),
            JobCreateRequest(
                target_id=uuid4(),
                job_type=JobType.PROFILE_TARGET,
            ),
        )


def test_controller_computes_profile_hash_and_preserves_m3_states(
    tmp_path: Path,
) -> None:
    database = tmp_path / "controller.sqlite3"
    _, _, api = _controller(tmp_path)
    enrollment = _enroll(api, "profile-target")
    job = _create_and_poll_profile_job(api, enrollment)
    profile = _profile()
    request = ProfileSubmissionRequest(
        auth=_auth(enrollment),
        job_id=job.job_id,
        profile=profile,
        profiler_version="m3-schema-1",
        sentra_version="m6a",
    )
    record = api.submit_profile(enrollment.agent_id, request)
    canonical = json.dumps(
        profile.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )

    assert record.target_id == enrollment.target_id
    assert record.agent_id == enrollment.agent_id
    assert record.job_id == job.job_id
    assert record.profile_sha256 == hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()
    with sqlite3.connect(database) as connection:
        payload = connection.execute(
            "SELECT payload_json FROM profiles WHERE profile_id = ?",
            (str(record.profile_id),),
        ).fetchone()[0]
    stored = json.loads(payload)
    assert {value["status"] for value in stored["facts"].values()} == {
        "collected",
        "unavailable",
        "unsupported",
        "error",
    }


def test_agent_cannot_submit_or_overwrite_another_targets_profile(
    tmp_path: Path,
) -> None:
    _, _, api = _controller(tmp_path)
    first = _enroll(api, "target-a")
    second = _enroll(api, "target-b")
    second_job = _create_and_poll_profile_job(api, second)

    with pytest.raises(AuthorizationError):
        api.submit_profile(
            first.agent_id,
            ProfileSubmissionRequest(
                auth=_auth(first),
                job_id=second_job.job_id,
                profile=_profile(),
            ),
        )

    exact_agent_b_identity_with_agent_a_credential = AgentAuth(
        target_id=second.target_id,
        agent_id=second.agent_id,
        agent_credential=first.agent_credential,
    )
    with pytest.raises(AuthenticationError):
        api.submit_profile(
            second.agent_id,
            ProfileSubmissionRequest(
                auth=exact_agent_b_identity_with_agent_a_credential,
                job_id=second_job.job_id,
                profile=_profile(),
            ),
        )

    valid = ProfileSubmissionRequest(
        auth=_auth(second),
        job_id=second_job.job_id,
        profile=_profile(),
    )
    api.submit_profile(second.agent_id, valid)
    with pytest.raises(ControllerConflictError, match="not awaiting"):
        api.submit_profile(second.agent_id, valid)


def test_clock_rollback_is_rejected_before_job_or_heartbeat_state_mutates(
    tmp_path: Path,
) -> None:
    repository, _, api = _controller(tmp_path)
    enrollment = _enroll(api, "clock-target")
    job = api.create_profile_job(
        enrollment.target_id,
        _admin(),
        JobCreateRequest(
            target_id=enrollment.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )

    with pytest.raises(StorageConflictError, match="dispatch time"):
        repository.poll_jobs(
            target_id=enrollment.target_id,
            agent_id=enrollment.agent_id,
            dispatched_at=NOW - timedelta(seconds=1),
            limit=10,
        )
    stored_job = repository.get_job(job.job_id)
    assert stored_job is not None
    assert stored_job.job.status is JobStatus.PENDING

    with pytest.raises(StorageConflictError, match="heartbeat time"):
        repository.record_heartbeat(
            target_id=enrollment.target_id,
            agent_id=enrollment.agent_id,
            seen_at=NOW - timedelta(seconds=1),
            agent_version="0.6a-test",
            metadata=_metadata("clock-target"),
            change_id=uuid4(),
        )
    target = repository.get_target(enrollment.target_id)
    assert target is not None
    assert target.status is TargetStatus.ENROLLED


def test_profile_completion_before_dispatch_is_rejected_without_mutation(
    tmp_path: Path,
) -> None:
    repository, _, api = _controller(tmp_path)
    enrollment = _enroll(api, "profile-clock-target")
    job = _create_and_poll_profile_job(api, enrollment)
    profile = _profile()
    record = ProfileRecord(
        profile_id=uuid4(),
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
        job_id=job.job_id,
        collected_at=NOW - timedelta(minutes=2),
        received_at=NOW - timedelta(seconds=1),
        profile_sha256="a" * 64,
    )

    with pytest.raises(StorageConflictError, match="receipt time"):
        repository.store_profile(record, "{}")
    stored_job = repository.get_job(job.job_id)
    assert stored_job is not None
    assert stored_job.job.status is JobStatus.DISPATCHED
    assert repository.get_profile(record.profile_id) is None


def test_controller_and_agent_packages_have_no_command_execution_imports() -> None:
    forbidden_imports = {"subprocess", "pty", "shlex"}
    forbidden_names = {"eval", "exec"}
    forbidden_os_calls = {"system", "popen"}
    forbidden_asyncio_calls = {"create_subprocess_exec", "create_subprocess_shell"}
    for package in (ROOT / "src" / "controller", ROOT / "src" / "agent"):
        for path in package.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    assert not ({alias.name for alias in node.names} & forbidden_imports)
                if isinstance(node, ast.ImportFrom):
                    assert node.module not in forbidden_imports
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        assert node.func.id not in forbidden_names
                    if (
                        isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                    ):
                        owner = node.func.value.id
                        name = node.func.attr
                        assert not (
                            owner == "os"
                            and (
                                name in forbidden_os_calls
                                or name.startswith("exec")
                                or name.startswith("spawn")
                            )
                        )
                        assert not (
                            owner == "asyncio" and name in forbidden_asyncio_calls
                        )
