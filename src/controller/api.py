"""Versioned, transport-independent SENTRA Controller API surface.

The HTTPS transport binds these narrow operations to documented paths; identity,
authorization, and evidence-lineage decisions remain in the service layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from src.controller.models import (
    AdminAuth,
    CompatibilityAnalysisRequest,
    CompatibilityReportRecord,
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
    Endpoint(
        "POST",
        (
            f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/"
            "{profile_id}/compatibility-reports"
        ),
        "run_compatibility_analysis",
    ),
    Endpoint(
        "GET",
        (
            f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/"
            "{profile_id}/compatibility-reports"
        ),
        "list_compatibility_reports",
    ),
    Endpoint(
        "GET",
        (
            f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/"
            "{profile_id}/compatibility-reports/{compatibility_report_id}"
        ),
        "get_compatibility_report",
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

    def run_compatibility_analysis(
        self,
        target_id: UUID,
        profile_id: UUID,
        auth: AdminAuth,
        request: CompatibilityAnalysisRequest,
    ) -> CompatibilityReportRecord:
        self._require_compatibility_path_binding(target_id, profile_id, request)
        return self._service.run_compatibility_analysis(auth, request)

    def list_compatibility_reports(
        self,
        target_id: UUID,
        profile_id: UUID,
        auth: AdminAuth,
    ) -> list[CompatibilityReportRecord]:
        return self._service.list_compatibility_reports(
            auth,
            target_id=target_id,
            profile_id=profile_id,
        )

    def get_compatibility_report(
        self,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        auth: AdminAuth,
    ) -> CompatibilityReportRecord:
        return self._service.get_compatibility_report(
            auth,
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
        )

    @staticmethod
    def _require_compatibility_path_binding(
        target_id: UUID,
        profile_id: UUID,
        request: CompatibilityAnalysisRequest,
    ) -> None:
        if target_id != request.target_id or profile_id != request.profile_id:
            raise AuthenticationError(
                "compatibility path does not match request"
            )

    @staticmethod
    def _require_agent_path_binding(path_agent_id: UUID, body_agent_id: UUID) -> None:
        if path_agent_id != body_agent_id:
            raise AuthenticationError("agent path does not match authenticated identity")
