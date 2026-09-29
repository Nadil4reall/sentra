"""TLS-verifying HTTPS adapter for the constrained SENTRA Agent protocol."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import ssl
import stat
from typing import TypeVar
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from pydantic import BaseModel, ValidationError

from src.agent.config import AgentTransportConfig
from src.controller.models import (
    EnrollmentRequest,
    EnrollmentResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    JobPollRequest,
    JobPollResponse,
    ProfileRecord,
    ProfileSubmissionRequest,
    ValidationResultRecord,
    ValidationResultSubmissionRequest,
)


_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_API_PREFIX = "/api/v1"
_ResponseModel = TypeVar("_ResponseModel", bound=BaseModel)


class AgentTransportError(RuntimeError):
    """A safe, credential-free HTTPS transport failure."""


class AgentTransportConfigurationError(AgentTransportError):
    """The configured trust material cannot support a verified connection."""


class AgentControllerResponseError(AgentTransportError):
    """The Controller returned a failed or invalid protocol response."""


class _RejectRedirects(HTTPRedirectHandler):
    """Never replay an authenticated request to a redirected location."""

    def redirect_request(
        self,
        request: Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> None:
        raise HTTPError(
            request.full_url,
            code,
            "Controller redirects are not accepted",
            headers,  # type: ignore[arg-type]
            file_pointer,  # type: ignore[arg-type]
        )


def _validated_ca_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        path_stat = os.lstat(absolute)
    except FileNotFoundError:
        raise AgentTransportConfigurationError(
            "Controller CA bundle does not exist"
        ) from None
    if stat.S_ISLNK(path_stat.st_mode):
        raise AgentTransportConfigurationError(
            "Controller CA bundle must not be a symlink"
        )
    if not stat.S_ISREG(path_stat.st_mode):
        raise AgentTransportConfigurationError(
            "Controller CA bundle must be a regular file"
        )
    return absolute


def _request_payload(
    request: EnrollmentRequest
    | HeartbeatRequest
    | JobPollRequest
    | ProfileSubmissionRequest
    | ValidationResultSubmissionRequest,
) -> bytes:
    """Serialize one known request, materializing only its required wire secret."""

    payload = request.model_dump(mode="json")
    if isinstance(request, EnrollmentRequest):
        payload["bootstrap_credential"] = (
            request.bootstrap_credential.get_secret_value()
        )
    else:
        payload["auth"]["agent_credential"] = (
            request.auth.agent_credential.get_secret_value()
        )
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class AgentHTTPSClient:
    """Map existing Agent request models to the versioned HTTPS API.

    The client always uses a dedicated CA-backed ``SSLContext`` with hostname
    verification enabled.  Environment proxy settings and redirects are
    disabled so authenticated JSON cannot be replayed to another endpoint.
    """

    def __init__(self, config: AgentTransportConfig) -> None:
        self._config = config
        ca_path = _validated_ca_path(config.controller_ca_path)
        try:
            context = ssl.create_default_context(
                purpose=ssl.Purpose.SERVER_AUTH,
                cafile=os.fspath(ca_path),
            )
        except (OSError, ssl.SSLError):
            raise AgentTransportConfigurationError(
                "Controller CA bundle could not be loaded"
            ) from None
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        configured_url = str(config.controller_url).rstrip("/")
        if config.controller_url.path.rstrip("/") == _API_PREFIX:
            self._api_base = configured_url
        else:
            self._api_base = f"{configured_url}{_API_PREFIX}"
        self._opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=context),
            _RejectRedirects(),
        )

    def enroll(self, request: EnrollmentRequest) -> EnrollmentResponse:
        return self._post(
            "enrollment",
            request,
            EnrollmentResponse,
            expected_status=201,
        )

    def heartbeat(self, request: HeartbeatRequest) -> HeartbeatResponse:
        return self._post(
            f"agents/{request.auth.agent_id}/heartbeat",
            request,
            HeartbeatResponse,
            expected_status=200,
        )

    def poll_jobs(self, request: JobPollRequest) -> JobPollResponse:
        return self._post(
            f"agents/{request.auth.agent_id}/jobs/poll",
            request,
            JobPollResponse,
            expected_status=200,
        )

    def submit_profile(
        self, request: ProfileSubmissionRequest
    ) -> ProfileRecord:
        return self._post(
            f"agents/{request.auth.agent_id}/profiles",
            request,
            ProfileRecord,
            expected_status=200,
        )

    def submit_validation_result(
        self,
        request: ValidationResultSubmissionRequest,
    ) -> ValidationResultRecord:
        return self._post(
            f"agents/{request.auth.agent_id}/validation-results",
            request,
            ValidationResultRecord,
            expected_status=200,
        )

    def _post(
        self,
        path: str,
        request_model: EnrollmentRequest
        | HeartbeatRequest
        | JobPollRequest
        | ProfileSubmissionRequest
        | ValidationResultSubmissionRequest,
        response_model: type[_ResponseModel],
        *,
        expected_status: int,
    ) -> _ResponseModel:
        body = _request_payload(request_model)
        request = Request(
            f"{self._api_base}/{path}",
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener.open(
                request,
                timeout=self._config.request_timeout_seconds,
            ) as response:
                status = response.getcode()
                if status != expected_status:
                    raise AgentControllerResponseError(
                        f"Controller returned unexpected HTTP status {status}"
                    )
                content_type = response.headers.get_content_type()
                if content_type != "application/json":
                    raise AgentControllerResponseError(
                        "Controller response is not JSON"
                    )
                declared_size = response.headers.get("Content-Length")
                if declared_size is not None:
                    try:
                        parsed_size = int(declared_size)
                    except ValueError:
                        raise AgentControllerResponseError(
                            "Controller response has an invalid length"
                        ) from None
                    if parsed_size < 0 or parsed_size > _MAX_RESPONSE_BYTES:
                        raise AgentControllerResponseError(
                            "Controller response exceeds the size limit"
                        )
                response_body = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            error.close()
            raise AgentControllerResponseError(
                f"Controller request failed with HTTP status {error.code}"
            ) from None
        except (URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError):
            raise AgentTransportError("Controller HTTPS request failed") from None

        if len(response_body) > _MAX_RESPONSE_BYTES:
            raise AgentControllerResponseError(
                "Controller response exceeds the size limit"
            )
        try:
            return response_model.model_validate_json(response_body)
        except ValidationError:
            raise AgentControllerResponseError(
                "Controller returned an invalid protocol response"
            ) from None


__all__ = [
    "AgentControllerResponseError",
    "AgentHTTPSClient",
    "AgentTransportConfigurationError",
    "AgentTransportError",
]
