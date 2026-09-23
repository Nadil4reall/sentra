"""Versioned, transport-independent API surface for M6A.

The methods are intentionally ordinary in-process calls.  A later HTTPS transport can
bind these operations to the documented paths while enforcing TLS certificate/CA
verification.  M6A does not normalize plaintext HTTP as a deployment mode.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from src.controller.models import (
    AdminAuth,
    EnrollmentRequest,
    EnrollmentResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    JobCreateRequest,
    JobPollRequest,
    JobPollResponse,
    JobRecord,
    ProfileRecord,
    ProfileSubmissionRequest,
    TargetRecord,
)
from src.controller.service import AuthenticationError, ControllerService


API_PREFIX = "/api/v1"


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    operation: str


ENDPOINTS = (
    Endpoint("POST", f"{API_PREFIX}/enrollment", "enroll"),
    Endpoint(
        "POST", f"{API_PREFIX}/agents/{{agent_id}}/heartbeat", "heartbeat"
    ),
    Endpoint(
        "POST", f"{API_PREFIX}/agents/{{agent_id}}/jobs/poll", "poll_jobs"
    ),
    Endpoint(
        "POST", f"{API_PREFIX}/agents/{{agent_id}}/profiles", "submit_profile"
    ),
    Endpoint("GET", f"{API_PREFIX}/admin/targets", "list_targets"),
    Endpoint(
        "POST",
        f"{API_PREFIX}/admin/targets/{{target_id}}/jobs",
        "create_profile_job",
    ),
)


class ControllerAPI:
    """Thin endpoint-shaped facade that adds path/body identity binding."""

    def __init__(self, service: ControllerService) -> None:
        self._service = service

    def enroll(self, request: EnrollmentRequest) -> EnrollmentResponse:
        return self._service.enroll(request)

    def heartbeat(
        self, agent_id: UUID, request: HeartbeatRequest
    ) -> HeartbeatResponse:
        self._require_agent_path_binding(agent_id, request.auth.agent_id)
        return self._service.heartbeat(request)

    def poll_jobs(self, agent_id: UUID, request: JobPollRequest) -> JobPollResponse:
        self._require_agent_path_binding(agent_id, request.auth.agent_id)
        return self._service.poll_jobs(request)

    def submit_profile(
        self, agent_id: UUID, request: ProfileSubmissionRequest
    ) -> ProfileRecord:
        self._require_agent_path_binding(agent_id, request.auth.agent_id)
        return self._service.submit_profile(request)

    def list_targets(self, auth: AdminAuth) -> list[TargetRecord]:
        return self._service.list_targets(auth)

    def create_profile_job(
        self,
        target_id: UUID,
        auth: AdminAuth,
        request: JobCreateRequest,
    ) -> JobRecord:
        if target_id != request.target_id:
            raise AuthenticationError("target path does not match request")
        return self._service.create_job(auth, request)

    @staticmethod
    def _require_agent_path_binding(path_agent_id: UUID, body_agent_id: UUID) -> None:
        if path_agent_id != body_agent_id:
            raise AuthenticationError("agent path does not match authenticated identity")
