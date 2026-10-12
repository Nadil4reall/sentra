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
    EnforcementResultRecord,
    EnforcementJobCreateRequest,
    EnforcementJobRecord,
    EnforcementResultSubmissionRequest,
    HeartbeatRequest,
    HeartbeatResponse,
    JobCreateRequest,
    JobPollRequest,
    JobPollResponse,
    JobRecord,
    ProfileRecord,
    ProfileSubmissionRequest,
    PostEnforcementVerificationRecord,
    SandboxProvisionRequest,
    SandboxCloseRequest,
    SandboxSessionCreateRequest,
    SandboxSessionRecord,
    SandboxValidationRunRecord,
    TargetRecord,
    ValidationJobCreateRequest,
    ValidationJobRecord,
    ValidationResultRecord,
    ValidationResultSubmissionRequest,
)
from src.controller.sandbox import SandboxManager
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
    Endpoint(
        "POST",
        f"{API_PREFIX}/agents/{{agent_id}}/validation-results",
        "submit_validation_result",
    ),
    Endpoint(
        "POST",
        f"{API_PREFIX}/agents/{{agent_id}}/enforcement-results",
        "submit_enforcement_result",
    ),
    Endpoint(
        "GET", f"{API_PREFIX}/admin/enforcement-jobs/{{job_id}}/result",
        "get_enforcement_result",
    ),
    Endpoint(
        "GET", f"{API_PREFIX}/admin/enforcement-results/{{result_id}}/post-verification",
        "get_post_enforcement_verification",
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
    Endpoint(
        "POST",
        (
            f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/{{profile_id}}/"
            "compatibility-reports/{compatibility_report_id}/sandbox-sessions"
        ),
        "create_sandbox_session",
    ),
    Endpoint(
        "GET",
        (
            f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/{{profile_id}}/"
            "compatibility-reports/{compatibility_report_id}/sandbox-sessions"
        ),
        "list_sandbox_sessions",
    ),
    Endpoint(
        "GET",
        (
            f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/{{profile_id}}/"
            "compatibility-reports/{compatibility_report_id}/sandbox-sessions/"
            "{sandbox_session_id}"
        ),
        "get_sandbox_session",
    ),
    Endpoint(
        "POST",
        (
            f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/{{profile_id}}/"
            "compatibility-reports/{compatibility_report_id}/sandbox-sessions/"
            "{sandbox_session_id}/provision"
        ),
        "provision_sandbox_session",
    ),
    Endpoint(
        "POST",
        (f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/{{profile_id}}/"
         "compatibility-reports/{compatibility_report_id}/sandbox-sessions/"
         "{sandbox_session_id}/validate"),
        "execute_sandbox_validation",
    ),
    Endpoint(
        "POST",
        (f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/{{profile_id}}/"
         "compatibility-reports/{compatibility_report_id}/sandbox-sessions/"
         "{sandbox_session_id}/close"),
        "close_completed_sandbox",
    ),
    Endpoint("POST", f"{API_PREFIX}/admin/targets/{{target_id}}/enforcement-jobs",
             "create_enforcement_job"),
    Endpoint(
        "POST",
        (
            f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/{{profile_id}}/"
            "compatibility-reports/{compatibility_report_id}/validation-jobs"
        ),
        "create_validation_job",
    ),
    Endpoint(
        "GET",
        (
            f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/{{profile_id}}/"
            "compatibility-reports/{compatibility_report_id}/validation-results"
        ),
        "list_validation_results",
    ),
    Endpoint(
        "GET",
        (
            f"{API_PREFIX}/admin/targets/{{target_id}}/profiles/{{profile_id}}/"
            "compatibility-reports/{compatibility_report_id}/validation-results/"
            "{validation_result_id}"
        ),
        "get_validation_result",
    ),
)


class ControllerAPI:
    """Thin endpoint-shaped facade that adds path/body identity binding."""

    def __init__(
        self,
        service: ControllerService,
        sandbox_manager: SandboxManager | None = None,
    ) -> None:
        self._service = service
        self._sandbox_manager = sandbox_manager or SandboxManager(service, None)

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

    def submit_validation_result(
        self,
        agent_id: UUID,
        request: ValidationResultSubmissionRequest,
    ) -> ValidationResultRecord:
        self._require_agent_path_binding(agent_id, request.auth.agent_id)
        return self._service.submit_validation_result(request)

    def submit_enforcement_result(
        self, agent_id: UUID, request: EnforcementResultSubmissionRequest,
    ) -> EnforcementResultRecord:
        self._require_agent_path_binding(agent_id, request.auth.agent_id)
        return self._service.submit_enforcement_result(request)

    def get_enforcement_result(
        self, auth: AdminAuth, job_id: UUID,
    ) -> EnforcementResultRecord:
        return self._service.get_enforcement_result(auth, job_id)

    def get_post_enforcement_verification(
        self, auth: AdminAuth, result_id: UUID,
    ) -> PostEnforcementVerificationRecord | None:
        return self._service.get_post_enforcement_verification(
            auth, enforcement_result_id=result_id,
        )

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

    def create_validation_job(
        self,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        auth: AdminAuth,
        request: ValidationJobCreateRequest,
    ) -> ValidationJobRecord:
        self._require_validation_path_binding(
            target_id,
            profile_id,
            compatibility_report_id,
            request,
        )
        return self._service.create_validation_job(auth, request)

    def create_sandbox_session(
        self,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        auth: AdminAuth,
        request: SandboxSessionCreateRequest,
    ) -> SandboxSessionRecord:
        return self._service.create_sandbox_session(
            auth,
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
            request=request,
        )

    def list_sandbox_sessions(
        self,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        auth: AdminAuth,
    ) -> list[SandboxSessionRecord]:
        return self._service.list_sandbox_sessions(
            auth,
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
        )

    def get_sandbox_session(
        self,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        sandbox_session_id: UUID,
        auth: AdminAuth,
    ) -> SandboxSessionRecord:
        return self._service.get_sandbox_session(
            auth,
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
            sandbox_session_id=sandbox_session_id,
        )

    def provision_sandbox_session(
        self,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        sandbox_session_id: UUID,
        auth: AdminAuth,
        request: SandboxProvisionRequest,
    ) -> SandboxSessionRecord:
        # ``request`` is deliberately empty and strict.  Keeping it in this
        # signature ensures the transport cannot bypass model validation.
        del request
        return self._sandbox_manager.provision(
            auth,
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
            sandbox_session_id=sandbox_session_id,
        )

    def execute_sandbox_validation(
        self, target_id: UUID, profile_id: UUID, compatibility_report_id: UUID,
        sandbox_session_id: UUID, auth: AdminAuth,
        request: ValidationJobCreateRequest,
    ) -> SandboxValidationRunRecord:
        self._require_validation_path_binding(
            target_id, profile_id, compatibility_report_id, request,
        )
        return self._sandbox_manager.execute_validation(
            auth, target_id=target_id, profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
            sandbox_session_id=sandbox_session_id, request=request,
        )

    def close_completed_sandbox(
        self, target_id: UUID, profile_id: UUID, compatibility_report_id: UUID,
        sandbox_session_id: UUID, auth: AdminAuth,
        request: SandboxCloseRequest,
    ) -> SandboxSessionRecord:
        del request
        return self._sandbox_manager.close_completed(
            auth, target_id=target_id, profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
            sandbox_session_id=sandbox_session_id,
        )

    def create_enforcement_job(
        self, target_id: UUID, auth: AdminAuth,
        request: EnforcementJobCreateRequest,
    ) -> EnforcementJobRecord:
        if target_id != request.target_id:
            raise AuthenticationError("enforcement path does not match request")
        return self._service.create_enforcement_job(auth, request)

    def list_validation_results(
        self,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        auth: AdminAuth,
    ) -> list[ValidationResultRecord]:
        return self._service.list_validation_results(
            auth,
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
        )

    def get_validation_result(
        self,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        validation_result_id: UUID,
        auth: AdminAuth,
    ) -> ValidationResultRecord:
        return self._service.get_validation_result(
            auth,
            target_id=target_id,
            profile_id=profile_id,
            compatibility_report_id=compatibility_report_id,
            validation_result_id=validation_result_id,
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
    def _require_validation_path_binding(
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        request: ValidationJobCreateRequest,
    ) -> None:
        if (
            target_id != request.target_id
            or profile_id != request.profile_id
            or compatibility_report_id != request.compatibility_report_id
        ):
            raise AuthenticationError("validation path does not match request")

    @staticmethod
    def _require_agent_path_binding(path_agent_id: UUID, body_agent_id: UUID) -> None:
        if path_agent_id != body_agent_id:
            raise AuthenticationError("agent path does not match authenticated identity")
