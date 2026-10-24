"""Focused tests for the constrained one-cycle M6B Agent runtime."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from pydantic import SecretStr
import pytest

from src.agent.protocol import AgentProtocol
from src.agent.runtime import AgentRuntime, AgentRuntimeError
from src.agent.state import AgentStateStore
from src.agent.transport import AgentTransportError
from src.controller.models import (
    EnrollmentResponse,
    HeartbeatResponse,
    JobPollResponse,
    JobRecord,
    JobStatus,
    JobType,
    ObservedTargetMetadata,
    ProfileRecord,
)
from src.target_profiler.models import (
    CollectionSummary,
    FactResult,
    FactStatus,
    TargetInfo,
    TargetProfile,
)


NOW = datetime(2026, 9, 24, 9, 0, tzinfo=UTC)
BOOTSTRAP = "runtime-bootstrap-secret"
AGENT_CREDENTIAL = "runtime-agent-secret"


def _metadata() -> ObservedTargetMetadata:
    return ObservedTargetMetadata(
        hostname="runtime-target",
        os="Ubuntu",
        os_version="24.04",
        kernel="6.8.0-fixture",
        architecture="x86_64",
    )


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
            reason="fixture unavailable",
        ),
        "unsupported_fixture": FactResult(
            name="unsupported_fixture",
            status=FactStatus.UNSUPPORTED,
            value=None,
            requested_by=requested_by,
            reason="fixture unsupported",
        ),
        "error_fixture": FactResult(
            name="error_fixture",
            status=FactStatus.ERROR,
            value=None,
            requested_by=requested_by,
            reason="fixture error",
        ),
    }
    return TargetProfile(
        collected_at=NOW - timedelta(minutes=1),
        target=TargetInfo(
            hostname="runtime-target",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-fixture",
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


class _Profiler:
    def __init__(self, profile: TargetProfile | None = None) -> None:
        self.profile = profile or _profile()
        self.calls = 0

    def collect(self) -> TargetProfile:
        self.calls += 1
        return self.profile


class _Transport:
    def __init__(
        self,
        enrollment: EnrollmentResponse,
        *,
        jobs: list[JobRecord] | None = None,
        heartbeat_error: Exception | None = None,
    ) -> None:
        self.enrollment = enrollment
        self.jobs = jobs or []
        self.heartbeat_error = heartbeat_error
        self.enroll_requests: list[object] = []
        self.heartbeat_requests: list[object] = []
        self.poll_requests: list[object] = []
        self.profile_requests: list[object] = []

    def enroll(self, request: object) -> EnrollmentResponse:
        self.enroll_requests.append(request)
        return self.enrollment

    def heartbeat(self, request: object) -> HeartbeatResponse:
        self.heartbeat_requests.append(request)
        if self.heartbeat_error is not None:
            raise self.heartbeat_error
        return HeartbeatResponse(accepted=True, last_seen=NOW)

    def poll_jobs(self, request: object) -> JobPollResponse:
        self.poll_requests.append(request)
        return JobPollResponse(jobs=self.jobs)

    def submit_profile(self, request: object) -> ProfileRecord:
        self.profile_requests.append(request)
        return ProfileRecord(
            profile_id=uuid4(),
            target_id=request.auth.target_id,
            agent_id=request.auth.agent_id,
            job_id=request.job_id,
            collected_at=request.profile.collected_at,
            received_at=NOW,
            profile_sha256="0" * 64,
            profiler_version=request.profiler_version,
            sentra_version=request.sentra_version,
        )


def _enrollment() -> EnrollmentResponse:
    return EnrollmentResponse(
        target_id=uuid4(),
        agent_id=uuid4(),
        agent_credential=SecretStr(AGENT_CREDENTIAL),
        polling_interval_seconds=30,
    )


def _protocol(path: Path) -> AgentProtocol:
    return AgentProtocol(
        AgentStateStore(path),
        observed_metadata=_metadata(),
        agent_version="m6b-test",
    )


def test_first_cycle_enrolls_then_restart_reuses_identity_without_reenrollment(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "agent" / "state.json"
    enrollment = _enrollment()
    first_transport = _Transport(enrollment)
    first_profiler = _Profiler()
    first_protocol = _protocol(state_path)
    installation_id = first_protocol.state.installation_id

    first = AgentRuntime(
        protocol=first_protocol,
        transport=first_transport,
        profiler=first_profiler,
        bootstrap_credential=SecretStr(BOOTSTRAP),
    ).run_once()

    restarted_protocol = _protocol(state_path)
    restarted_transport = _Transport(enrollment)
    restarted = AgentRuntime(
        protocol=restarted_protocol,
        transport=restarted_transport,
        profiler=_Profiler(),
        bootstrap_credential=None,
    ).run_once()

    assert first.enrolled_during_run is True
    assert restarted.enrolled_during_run is False
    assert restarted_protocol.state.installation_id == installation_id
    assert restarted_protocol.state.target_id == enrollment.target_id
    assert len(first_transport.enroll_requests) == 1
    assert restarted_transport.enroll_requests == []
    assert first_profiler.calls == 0
    assert first.jobs_polled == restarted.jobs_polled == 0
    assert first.profiles_submitted == restarted.profiles_submitted == 0


def test_enrollment_is_persisted_before_heartbeat_transport_failure(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    enrollment = _enrollment()
    transport = _Transport(
        enrollment,
        heartbeat_error=AgentTransportError("sanitized transport failure"),
    )

    with pytest.raises(AgentTransportError, match="sanitized"):
        AgentRuntime(
            protocol=_protocol(state_path),
            transport=transport,
            profiler=_Profiler(),
            bootstrap_credential=SecretStr(BOOTSTRAP),
        ).run_once()

    restarted = _protocol(state_path)
    assert restarted.state.is_enrolled is True
    assert restarted.state.target_id == enrollment.target_id
    assert restarted.state.agent_id == enrollment.agent_id
    assert len(transport.enroll_requests) == 1


def test_profile_target_invokes_m3_adapter_and_preserves_all_four_states(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    enrollment = _enrollment()
    AgentStateStore(state_path).save_enrollment(enrollment)
    job = JobRecord(
        job_id=uuid4(),
        target_id=enrollment.target_id,
        job_type=JobType.PROFILE_TARGET,
        status=JobStatus.DISPATCHED,
        created_at=NOW - timedelta(minutes=2),
        dispatched_at=NOW - timedelta(minutes=1),
    )
    transport = _Transport(enrollment, jobs=[job])
    profiler = _Profiler()

    result = AgentRuntime(
        protocol=_protocol(state_path),
        transport=transport,
        profiler=profiler,
        profiler_version="m3-test",
        sentra_version="m6b-test",
    ).run_once()

    assert result.jobs_polled == 1
    assert result.profiles_submitted == 1
    assert profiler.calls == 1
    assert len(transport.profile_requests) == 1
    submitted = transport.profile_requests[0]
    assert submitted.job_id == job.job_id
    assert submitted.profiler_version == "m3-test"
    assert submitted.sentra_version == "m6b-test"
    assert {fact.status for fact in submitted.profile.facts.values()} == set(
        FactStatus
    )
    assert submitted.profile.collection_summary.model_dump() == {
        "requested": 4,
        "collected": 1,
        "unavailable": 1,
        "unsupported": 1,
        "errors": 1,
    }


def test_runtime_rejects_any_non_profile_target_job_before_profiling(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    enrollment = _enrollment()
    AgentStateStore(state_path).save_enrollment(enrollment)
    transport = _Transport(enrollment)
    transport.poll_jobs = lambda request: SimpleNamespace(
        jobs=[
            SimpleNamespace(
                target_id=enrollment.target_id,
                job_type="RUN_COMMAND",
                status=JobStatus.DISPATCHED,
            )
        ]
    )
    profiler = _Profiler()

    with pytest.raises(AgentRuntimeError, match="unsupported Agent job"):
        AgentRuntime(
            protocol=_protocol(state_path),
            transport=transport,
            profiler=profiler,
        ).run_once()

    assert profiler.calls == 0
    assert transport.profile_requests == []


def test_runtime_rejects_another_targets_profile_job_before_profiling(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    enrollment = _enrollment()
    AgentStateStore(state_path).save_enrollment(enrollment)
    foreign_job = JobRecord(
        job_id=uuid4(),
        target_id=uuid4(),
        job_type=JobType.PROFILE_TARGET,
        status=JobStatus.DISPATCHED,
        created_at=NOW - timedelta(minutes=2),
        dispatched_at=NOW - timedelta(minutes=1),
    )
    transport = _Transport(enrollment, jobs=[foreign_job])
    profiler = _Profiler()

    with pytest.raises(AgentRuntimeError, match="outside this Agent identity"):
        AgentRuntime(
            protocol=_protocol(state_path),
            transport=transport,
            profiler=profiler,
        ).run_once()

    assert profiler.calls == 0
    assert transport.profile_requests == []


def test_runtime_and_safe_result_repr_do_not_expose_credentials(
    tmp_path: Path,
) -> None:
    runtime = AgentRuntime(
        protocol=_protocol(tmp_path / "state.json"),
        transport=_Transport(_enrollment()),
        profiler=_Profiler(),
        bootstrap_credential=SecretStr(BOOTSTRAP),
    )

    result = runtime.run_once()

    for rendered in (repr(runtime), repr(result), str(result)):
        assert BOOTSTRAP not in rendered
        assert AGENT_CREDENTIAL not in rendered
    assert result.heartbeat_accepted is True
