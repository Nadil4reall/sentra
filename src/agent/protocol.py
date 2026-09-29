"""In-process construction of the constrained M6 agent protocol messages."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from pydantic import SecretStr

from src.agent.state import (
    AgentEnrollmentError,
    AgentState,
    AgentStateStore,
)
from src.controller.models import (
    AgentAuth,
    EnrollmentRequest,
    EnrollmentResponse,
    HeartbeatRequest,
    JobPollRequest,
    ObservedTargetMetadata,
    ProfileSubmissionRequest,
    ValidationResultPayload,
    ValidationResultSubmissionRequest,
)
from src.target_profiler.models import TargetProfile


class AgentNotEnrolledError(AgentEnrollmentError):
    """A post-enrollment message was requested before enrollment."""


class AgentAlreadyEnrolledError(AgentEnrollmentError):
    """A bootstrap enrollment was requested for an enrolled installation."""


class AgentProtocol:
    """Bind protocol messages to one persistent local agent identity.

    This helper performs no network I/O and has no command-execution facility.
    Transport and M3 profiler integration are intentionally outside M6A.
    """

    def __init__(
        self,
        state_store: AgentStateStore,
        *,
        observed_metadata: ObservedTargetMetadata,
        agent_version: str,
    ) -> None:
        if not agent_version.strip():
            raise ValueError("agent_version must not be empty")
        self._state_store = state_store
        self._observed_metadata = observed_metadata
        self._agent_version = agent_version
        self._state = state_store.load_or_create()

    @property
    def state(self) -> AgentState:
        """The current local identity/enrollment snapshot."""

        return self._state

    def create_enrollment_request(
        self,
        bootstrap_credential: str | SecretStr,
    ) -> EnrollmentRequest:
        """Create the sole bootstrap-authenticated protocol message."""

        if self._state.is_enrolled:
            raise AgentAlreadyEnrolledError("agent installation is already enrolled")
        secret = (
            bootstrap_credential
            if isinstance(bootstrap_credential, SecretStr)
            else SecretStr(bootstrap_credential)
        )
        return EnrollmentRequest(
            bootstrap_credential=secret,
            installation_id=self._state.installation_id,
            agent_version=self._agent_version,
            observed_metadata=self._observed_metadata,
        )

    def accept_enrollment(self, response: EnrollmentResponse) -> AgentState:
        """Persist the opaque identities and credential issued by Controller."""

        self._state = self._state_store.save_enrollment(response)
        return self._state

    def create_heartbeat_request(
        self,
        *,
        sent_at: datetime | None = None,
    ) -> HeartbeatRequest:
        return HeartbeatRequest(
            auth=self._auth(),
            sent_at=sent_at or datetime.now(UTC),
            agent_version=self._agent_version,
            observed_metadata=self._observed_metadata,
        )

    def create_job_poll_request(self) -> JobPollRequest:
        return JobPollRequest(auth=self._auth())

    def create_profile_submission_request(
        self,
        *,
        job_id: UUID,
        profile: TargetProfile,
        profiler_version: str | None = None,
        sentra_version: str | None = None,
    ) -> ProfileSubmissionRequest:
        return ProfileSubmissionRequest(
            auth=self._auth(),
            job_id=job_id,
            profile=profile,
            profiler_version=profiler_version,
            sentra_version=sentra_version,
        )

    def create_validation_result_submission_request(
        self,
        payload: ValidationResultPayload,
    ) -> ValidationResultSubmissionRequest:
        """Bind one already-journaled M5 result to this Agent credential."""

        state = self._state
        if state.target_id is None or payload.target_id != state.target_id:
            raise AgentNotEnrolledError(
                "validation result target does not match this Agent"
            )
        return ValidationResultSubmissionRequest(
            auth=self._auth(),
            payload=payload,
        )

    def _auth(self) -> AgentAuth:
        state = self._state
        if (
            state.target_id is None
            or state.agent_id is None
            or state.agent_credential is None
        ):
            raise AgentNotEnrolledError(
                "agent must complete enrollment before authenticated requests"
            )
        return AgentAuth(
            target_id=state.target_id,
            agent_id=state.agent_id,
            agent_credential=state.agent_credential,
        )
