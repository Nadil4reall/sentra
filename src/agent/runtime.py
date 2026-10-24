"""One-cycle orchestration for the narrow M6B/M6D Agent workflow."""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from typing import Protocol
from uuid import UUID

from pydantic import SecretStr

from src.agent.profiler import TargetProfilerAdapter
from src.agent import enforcement as enforcement_preflight
from src.agent import enforcement_execute
from src.agent.enforcement_result import (
    payload_from_trusted_journal, payload_from_verified_delivery,
)
from src.agent.enforcement_journal import (
    EnforcementJournalStore,
    EnforcementPreflightOutcome,
)
from src.agent.protocol import AgentProtocol
from src.agent.validation import ControlValidationAdapter
from src.agent.validation_journal import (
    ValidationJournalInterruptedError,
    ValidationJournalState,
    ValidationJournalStore,
    validation_payload_sha256,
)
from src.controller.models import (
    EnrollmentRequest,
    EnrollmentResponse,
    EnforcementJobDelivery,
    EnforcementResultRecord,
    EnforcementResultSubmissionRequest,
    HeartbeatRequest,
    HeartbeatResponse,
    JobPollRequest,
    JobPollResponse,
    JobRecord,
    JobStatus,
    JobType,
    ProfileRecord,
    ProfileSubmissionRequest,
    ValidationJobRecord,
    ValidationResultRecord,
    ValidationResultSubmissionRequest,
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

    def submit_validation_result(
        self, request: ValidationResultSubmissionRequest
    ) -> ValidationResultRecord: ...

    def submit_enforcement_result(
        self, request: EnforcementResultSubmissionRequest,
    ) -> EnforcementResultRecord: ...


@dataclass(frozen=True)
class AgentRunResult:
    """Credential-free summary of one completed Agent cycle."""

    enrolled_during_run: bool
    heartbeat_accepted: bool
    jobs_polled: int
    profiles_submitted: int
    validation_count: InitVar[int | None] = None

    def __post_init__(self, validation_count: int | None) -> None:
        object.__setattr__(
            self, "_validation_count",
            self.jobs_polled - self.profiles_submitted
            if validation_count is None else validation_count,
        )

    @property
    def validation_results_submitted(self) -> int:
        """Count completed validation submissions without changing M6B output.

        An internal count keeps M7-B preflights out of this M6D metric while
        preserving the established credential-free CLI JSON shape from M6B.
        """

        return self._validation_count


class AgentRuntime:
    """Enroll if necessary, heartbeat, poll, profile locally, and submit.

    This class deliberately exposes no generic executor. ``PROFILE_TARGET``
    maps to read-only M3, ``VALIDATE_CONTROL`` retains its gated M5 path, and
    M7 ``ENFORCE_CONTROL`` has a separate journal-gated fixed metadata boundary.
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
        control_validator: ControlValidationAdapter | None = None,
        validation_journal: ValidationJournalStore | None = None,
        enforcement_journal: EnforcementJournalStore | None = None,
        sandbox_validation_acknowledged: bool = False,
        retry_interrupted_enforcement: bool = False,
        enforcement_result_submission_enabled: bool = False,
    ) -> None:
        self._protocol = protocol
        self._transport = transport
        self._profiler = profiler
        self._bootstrap_credential = bootstrap_credential
        self._profiler_version = profiler_version
        self._sentra_version = sentra_version
        self._control_validator = control_validator
        self._validation_journal = validation_journal
        self._enforcement_journal = enforcement_journal
        self._sandbox_validation_acknowledged = (
            sandbox_validation_acknowledged
        )
        self._retry_interrupted_enforcement = retry_interrupted_enforcement
        self._enforcement_result_submission_enabled = enforcement_result_submission_enabled

    def _submit_enforcement_entry(
        self, entry, *, target_id: UUID, agent_id: UUID,
        delivery: EnforcementJobDelivery | None = None,
    ) -> None:
        journal = self._enforcement_journal
        if journal is None:
            raise AgentRuntimeError("enforcement journal is not configured")
        payload = (
            payload_from_verified_delivery(
                delivery, entry, target_id=target_id, agent_id=agent_id,
            )
            if delivery is not None else
            payload_from_trusted_journal(
                entry, target_id=target_id, agent_id=agent_id,
            )
        )
        request = self._protocol.create_enforcement_result_submission_request(payload)
        record = self._transport.submit_enforcement_result(request)
        journal.acknowledge_result(entry, record)

    @staticmethod
    def _preflight_jobs(
        jobs: list[JobRecord | ValidationJobRecord | EnforcementJobDelivery],
        *,
        target_id: UUID,
        agent_id: UUID,
    ) -> None:
        validation_jobs = 0
        enforcement_jobs = 0
        for job in jobs:
            if job.target_id != target_id:
                raise AgentRuntimeError(
                    "Controller returned a job outside this Agent identity"
                )
            if job.status is not JobStatus.DISPATCHED:
                raise AgentRuntimeError(
                    "Controller returned a job that is not dispatched"
                )
            if isinstance(job, JobRecord):
                if job.job_type is not JobType.PROFILE_TARGET:
                    raise AgentRuntimeError(
                        "Controller returned an unsupported Agent job"
                    )
            elif isinstance(job, ValidationJobRecord):
                if job.job_type is not JobType.VALIDATE_CONTROL:
                    raise AgentRuntimeError(
                        "Controller returned an unsupported Agent job"
                    )
                validation_jobs += 1
            elif isinstance(job, EnforcementJobDelivery):
                try:
                    enforcement_preflight.verify_enforcement_delivery(
                        job, target_id=target_id, agent_id=agent_id,
                    )
                except (ValueError, TypeError):
                    raise AgentRuntimeError("enforcement delivery is invalid") from None
                enforcement_jobs += 1
            else:  # defensive boundary around injected transports
                raise AgentRuntimeError(
                    "Controller returned an unsupported Agent job"
                )
        if validation_jobs > 1:
            raise AgentRuntimeError(
                "Controller returned more than one validation job in one cycle"
            )
        if enforcement_jobs > 1 or (enforcement_jobs and validation_jobs):
            raise AgentRuntimeError(
                "Controller returned incompatible or multiple mutation-capable jobs"
            )

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
        state = self._protocol.state
        if state.target_id is None or state.agent_id is None:
            raise AgentRuntimeError("Agent identity is incomplete after enrollment")
        if self._enforcement_result_submission_enabled:
            journal = self._enforcement_journal
            if journal is None:
                raise AgentRuntimeError("enforcement journal is not configured")
            for entry in journal.pending_results(
                target_id=state.target_id, agent_id=state.agent_id,
            ):
                self._submit_enforcement_entry(
                    entry, target_id=state.target_id, agent_id=state.agent_id,
                )
        self._preflight_jobs(
            polled.jobs, target_id=state.target_id, agent_id=state.agent_id,
        )

        profiles_submitted = 0
        validation_results_submitted = 0
        for job in polled.jobs:
            if isinstance(job, JobRecord):
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
                continue

            if isinstance(job, EnforcementJobDelivery):
                journal = self._enforcement_journal
                if journal is None:
                    raise AgentRuntimeError(
                        "enforcement journal is not configured"
                    )
                with journal.acquire(
                    job, target_id=state.target_id, agent_id=state.agent_id,
                ) as locked:
                    if locked.entry is None:
                        observed, outcome = enforcement_preflight.verify_and_observe(
                            job, target_id=state.target_id, agent_id=state.agent_id,
                        )
                        locked.prepare(
                            observed, EnforcementPreflightOutcome(outcome),
                        )
                    terminal_entry = enforcement_execute.execute_prepared_enforcement(
                        job, locked,
                        retry_interrupted=self._retry_interrupted_enforcement,
                    )
                if (
                    self._enforcement_result_submission_enabled
                    and terminal_entry.outcome.value in {
                        "SUCCEEDED", "BLOCKED_DRIFT", "FAILED",
                        "ROLLED_BACK", "ROLLBACK_FAILED",
                    }
                    and terminal_entry.acknowledged_at is None
                ):
                    self._submit_enforcement_entry(
                        terminal_entry, target_id=state.target_id,
                        agent_id=state.agent_id, delivery=job,
                    )
                continue  # M7-D submits evidence; no further mutation in this cycle.

            validator = self._control_validator
            journal = self._validation_journal
            if validator is None or journal is None:
                raise AgentRuntimeError(
                    "Agent validation support is not configured"
                )
            with journal.acquire(
                job,
                target_id=state.target_id,
                agent_id=state.agent_id,
            ) as locked:
                entry = locked.entry
                if entry is None:
                    locked.mark_started()
                    try:
                        payload = validator.validate(
                            job,
                            sandbox_operator_acknowledged=(
                                self._sandbox_validation_acknowledged
                            ),
                        )
                    except Exception:
                        # The durable STARTED state intentionally survives.  A
                        # subsequent Agent cycle must not repeat a mutation
                        # whose outcome was not journaled.
                        raise ValidationJournalInterruptedError(
                            "validation stopped after execution was armed; "
                            "manual sandbox inspection is required"
                        ) from None
                    entry = locked.cache_result(payload)
                elif entry.state is ValidationJournalState.STARTED:
                    raise ValidationJournalInterruptedError(
                        "a previous validation stopped before evidence was "
                        "journaled; manual sandbox inspection is required"
                    )

                payload = entry.result
                if payload is None:  # guarded by ValidationJournalEntry
                    raise AgentRuntimeError(
                        "validation journal contains no result evidence"
                    )
                request = (
                    self._protocol.create_validation_result_submission_request(
                        payload
                    )
                )
                stored = self._transport.submit_validation_result(request)
                if (
                    stored.agent_id != state.agent_id
                    or stored.payload != payload
                    or stored.result_sha256
                    != validation_payload_sha256(payload)
                ):
                    raise AgentRuntimeError(
                        "Controller returned inconsistent validation lineage"
                )
                locked.mark_acknowledged(stored)
                validation_results_submitted += 1

        return AgentRunResult(
            enrolled_during_run=enrolled_during_run,
            heartbeat_accepted=True,
            jobs_polled=len(polled.jobs),
            profiles_submitted=profiles_submitted,
            validation_count=validation_results_submitted,
        )


__all__ = [
    "AgentControllerTransport",
    "AgentRunResult",
    "AgentRuntime",
    "AgentRuntimeError",
]
