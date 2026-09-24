"""One-cycle orchestration for the narrow M6B Agent workflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from pydantic import SecretStr

from src.agent.profiler import TargetProfilerAdapter
from src.agent.protocol import AgentProtocol
from src.controller.models import (
    EnrollmentRequest,
    EnrollmentResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    JobPollRequest,
    JobPollResponse,
    JobStatus,
    JobType,
    ProfileRecord,
    ProfileSubmissionRequest,
)


class AgentRuntimeError(RuntimeError):
    """The constrained Agent cycle could not safely continue."""


class AgentControllerTransport(Protocol):
    """The only Controller operations available to the Agent runtime."""

    def enroll(self, request: EnrollmentRequest) -> EnrollmentResponse: ...

    def heartbeat(self, request: HeartbeatRequest) -> HeartbeatResponse: ...

    def poll_jobs(self, request: JobPollRequest) -> JobPollResponse: ...

    def submit_profile(
        self, request: ProfileSubmissionRequest
    ) -> ProfileRecord: ...


@dataclass(frozen=True)
class AgentRunResult:
    """Credential-free summary of one completed Agent cycle."""

    enrolled_during_run: bool
    heartbeat_accepted: bool
    jobs_polled: int
    profiles_submitted: int


class AgentRuntime:
    """Enroll if necessary, heartbeat, poll, profile locally, and submit.

    This class deliberately exposes no generic executor.  The only accepted
    job is ``PROFILE_TARGET``, which maps to the injected read-only M3 adapter.
    """

    def __init__(
        self,
        *,
        protocol: AgentProtocol,
        transport: AgentControllerTransport,
        profiler: TargetProfilerAdapter,
        bootstrap_credential: SecretStr | None = None,
        profiler_version: str | None = None,
        sentra_version: str | None = None,
    ) -> None:
        self._protocol = protocol
        self._transport = transport
        self._profiler = profiler
        self._bootstrap_credential = bootstrap_credential
        self._profiler_version = profiler_version
        self._sentra_version = sentra_version

    def run_once(self) -> AgentRunResult:
        enrolled_during_run = False
        if not self._protocol.state.is_enrolled:
            credential = self._bootstrap_credential
            if credential is None or not credential.get_secret_value().strip():
                raise AgentRuntimeError(
                    "bootstrap credential is required for first enrollment"
                )
            enrollment = self._transport.enroll(
                self._protocol.create_enrollment_request(credential)
            )
            self._protocol.accept_enrollment(enrollment)
            enrolled_during_run = True

        heartbeat = self._transport.heartbeat(
            self._protocol.create_heartbeat_request()
        )
        if not heartbeat.accepted:
            raise AgentRuntimeError("Controller did not accept the heartbeat")

        polled = self._transport.poll_jobs(
            self._protocol.create_job_poll_request()
        )
        profiles_submitted = 0
        for job in polled.jobs:
            state = self._protocol.state
            if (
                state.target_id is None
                or state.agent_id is None
                or job.target_id != state.target_id
            ):
                raise AgentRuntimeError(
                    "Controller returned a job outside this Agent identity"
                )
            if (
                job.job_type is not JobType.PROFILE_TARGET
                or job.status is not JobStatus.DISPATCHED
            ):
                raise AgentRuntimeError(
                    "Controller returned an unsupported Agent job"
                )

            profile = self._profiler.collect()
            request = self._protocol.create_profile_submission_request(
                job_id=job.job_id,
                profile=profile,
                profiler_version=self._profiler_version,
                sentra_version=self._sentra_version,
            )
            stored = self._transport.submit_profile(request)
            if (
                stored.target_id != state.target_id
                or stored.agent_id != state.agent_id
                or stored.job_id != job.job_id
                or stored.collected_at != profile.collected_at
            ):
                raise AgentRuntimeError(
                    "Controller returned inconsistent profile lineage"
                )
            profiles_submitted += 1

        return AgentRunResult(
            enrolled_during_run=enrolled_during_run,
            heartbeat_accepted=True,
            jobs_polled=len(polled.jobs),
            profiles_submitted=profiles_submitted,
        )


__all__ = [
    "AgentControllerTransport",
    "AgentRunResult",
    "AgentRuntime",
    "AgentRuntimeError",
]
