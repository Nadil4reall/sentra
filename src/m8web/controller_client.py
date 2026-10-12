"""Narrow, TLS-verified server-side client for existing Controller operations."""

from __future__ import annotations

import json
import os
import ssl
import stat
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from pydantic import BaseModel, ValidationError

from src.controller.models import (
    CompatibilityAnalysisRequest, CompatibilityReportRecord,
    EnforcementJobCreateRequest, EnforcementJobRecord, JobCreateRequest,
    JobRecord, SandboxCloseRequest, SandboxProvisionRequest,
    SandboxSessionCreateRequest, SandboxSessionRecord,
    SandboxValidationRunRecord, ValidationJobCreateRequest,
)

from .config import M8WebSettings


class ControllerClientError(RuntimeError):
    """Non-sensitive Controller call failure for web presentation."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise ControllerClientError("Controller redirect was refused")


def _read_protected_credential(path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            item = os.fstat(descriptor)
            if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid()
                    or stat.S_IMODE(item.st_mode) != 0o600 or item.st_nlink != 1
                    or item.st_size > 16 * 1024):
                raise ControllerClientError("Controller credential file is unsafe")
            content = os.read(descriptor, 16 * 1024 + 1).decode("utf-8").rstrip("\r\n")
        finally:
            os.close(descriptor)
    except (OSError, UnicodeError) as error:
        raise ControllerClientError("Controller credential is unavailable") from error
    if (not content or len(content) > 16 * 1024
            or "\n" in content or "\r" in content):
        raise ControllerClientError("Controller credential is invalid")
    return content


class M8ControllerClient:
    __slots__ = ("_origin", "_credential", "_opener")

    def __init__(self, settings: M8WebSettings, *, opener=None) -> None:
        if (settings.controller_url is None or settings.controller_ca_file is None
                or settings.controller_admin_credential_file is None):
            raise ControllerClientError("Controller integration is not configured")
        self._origin = settings.controller_url
        self._credential = _read_protected_credential(
            settings.controller_admin_credential_file
        )
        context = ssl.create_default_context(cafile=str(settings.controller_ca_file))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        self._opener = opener or build_opener(HTTPSHandler(context=context), _NoRedirect())

    def _post(self, path: str, request: BaseModel, response_type: type[BaseModel]):
        if not path.startswith("/api/v1/admin/"):
            raise ControllerClientError("Controller operation is not admin-scoped")
        body = request.model_dump_json().encode("utf-8")
        wire = Request(
            self._origin + path, data=body, method="POST",
            headers={
                "Authorization": f"Bearer {self._credential}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with self._opener.open(wire, timeout=180) as response:
                if response.status not in (200, 201):
                    raise ControllerClientError("Controller operation was refused")
                content = response.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024:
                raise ControllerClientError("Controller response exceeded limit")
            return response_type.model_validate_json(content, strict=True)
        except (HTTPError, URLError, OSError, ssl.SSLError, TimeoutError,
                ValidationError, ValueError, json.JSONDecodeError) as error:
            raise ControllerClientError("Controller operation failed") from error

    @staticmethod
    def _lineage(target_id, profile_id, report_id) -> str:
        return (f"/api/v1/admin/targets/{target_id}/profiles/{profile_id}"
                f"/compatibility-reports/{report_id}")

    def create_profile_job(self, request: JobCreateRequest) -> JobRecord:
        return self._post(
            f"/api/v1/admin/targets/{request.target_id}/jobs", request, JobRecord,
        )

    def run_compatibility(
        self, request: CompatibilityAnalysisRequest,
    ) -> CompatibilityReportRecord:
        path = (f"/api/v1/admin/targets/{request.target_id}/profiles/"
                f"{request.profile_id}/compatibility-reports")
        return self._post(path, request, CompatibilityReportRecord)

    def create_sandbox_session(
        self, target_id, profile_id, report_id,
        request: SandboxSessionCreateRequest,
    ) -> SandboxSessionRecord:
        return self._post(
            self._lineage(target_id, profile_id, report_id) + "/sandbox-sessions",
            request, SandboxSessionRecord,
        )

    def provision_sandbox(
        self, target_id, profile_id, report_id, session_id,
    ) -> SandboxSessionRecord:
        return self._post(
            self._lineage(target_id, profile_id, report_id)
            + f"/sandbox-sessions/{session_id}/provision",
            SandboxProvisionRequest(), SandboxSessionRecord,
        )

    def validate_sandbox(
        self, target_id, profile_id, report_id, session_id,
        request: ValidationJobCreateRequest,
    ) -> SandboxValidationRunRecord:
        return self._post(
            self._lineage(target_id, profile_id, report_id)
            + f"/sandbox-sessions/{session_id}/validate",
            request, SandboxValidationRunRecord,
        )

    def close_sandbox(
        self, target_id, profile_id, report_id, session_id,
    ) -> SandboxSessionRecord:
        return self._post(
            self._lineage(target_id, profile_id, report_id)
            + f"/sandbox-sessions/{session_id}/close",
            SandboxCloseRequest(), SandboxSessionRecord,
        )

    def create_enforcement_job(
        self, request: EnforcementJobCreateRequest,
    ) -> EnforcementJobRecord:
        return self._post(
            f"/api/v1/admin/targets/{request.target_id}/enforcement-jobs",
            request, EnforcementJobRecord,
        )
