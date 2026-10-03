"""Real HTTPS transport for the narrow SENTRA M6 controller protocol.

The transport owns HTTP parsing, TLS termination, and safe error mapping only.
Identity, authentication, authorization, job, and evidence-lineage decisions
remain in :mod:`src.controller.service` and its repository.
"""

from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import ssl
import stat
from typing import Literal, Mapping
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

from src.controller.api import API_PREFIX, ControllerAPI
from src.controller.models import (
    AdminAuth,
    CompatibilityAnalysisRequest,
    EnrollmentRequest,
    EnrollmentResponse,
    HeartbeatRequest,
    JobCreateRequest,
    JobPollRequest,
    ProfileSubmissionRequest,
    SandboxProvisionRequest,
    SandboxSessionCreateRequest,
    ValidationJobCreateRequest,
    ValidationResultSubmissionRequest,
)
from src.controller.service import (
    AuthenticationError,
    AuthorizationError,
    ControllerConflictError,
    ControllerNotFoundError,
    ControllerService,
    ControllerSettings,
)
from src.controller.sandbox import (
    LibvirtBackend,
    LocalNestedVmConfig,
    LocalNestedVmProvider,
    SandboxManager,
    SandboxStorageMode,
)
from src.controller.storage import SQLiteControllerRepository


_AGENT_ROUTE = re.compile(
    rf"^{re.escape(API_PREFIX)}/agents/([^/]+)/"
    r"(heartbeat|jobs/poll|profiles|validation-results)$"
)
_ADMIN_JOB_ROUTE = re.compile(
    rf"^{re.escape(API_PREFIX)}/admin/targets/([^/]+)/jobs$"
)
_ADMIN_COMPATIBILITY_COLLECTION_ROUTE = re.compile(
    rf"^{re.escape(API_PREFIX)}/admin/targets/([^/]+)/profiles/([^/]+)/"
    r"compatibility-reports$"
)
_ADMIN_COMPATIBILITY_ITEM_ROUTE = re.compile(
    rf"^{re.escape(API_PREFIX)}/admin/targets/([^/]+)/profiles/([^/]+)/"
    r"compatibility-reports/([^/]+)$"
)
_ADMIN_VALIDATION_JOB_ROUTE = re.compile(
    rf"^{re.escape(API_PREFIX)}/admin/targets/([^/]+)/profiles/([^/]+)/"
    r"compatibility-reports/([^/]+)/validation-jobs$"
)
_ADMIN_SANDBOX_SESSION_COLLECTION_ROUTE = re.compile(
    rf"^{re.escape(API_PREFIX)}/admin/targets/([^/]+)/profiles/([^/]+)/"
    r"compatibility-reports/([^/]+)/sandbox-sessions$"
)
_ADMIN_SANDBOX_SESSION_ITEM_ROUTE = re.compile(
    rf"^{re.escape(API_PREFIX)}/admin/targets/([^/]+)/profiles/([^/]+)/"
    r"compatibility-reports/([^/]+)/sandbox-sessions/([^/]+)$"
)
_ADMIN_SANDBOX_PROVISION_ROUTE = re.compile(
    rf"^{re.escape(API_PREFIX)}/admin/targets/([^/]+)/profiles/([^/]+)/"
    r"compatibility-reports/([^/]+)/sandbox-sessions/([^/]+)/provision$"
)
_ADMIN_VALIDATION_RESULT_COLLECTION_ROUTE = re.compile(
    rf"^{re.escape(API_PREFIX)}/admin/targets/([^/]+)/profiles/([^/]+)/"
    r"compatibility-reports/([^/]+)/validation-results$"
)
_ADMIN_VALIDATION_RESULT_ITEM_ROUTE = re.compile(
    rf"^{re.escape(API_PREFIX)}/admin/targets/([^/]+)/profiles/([^/]+)/"
    r"compatibility-reports/([^/]+)/validation-results/([^/]+)$"
)
_JSON_CONTENT_TYPE = "application/json"


class ControllerTransportConfig(BaseModel):
    """Complete runtime configuration for one TLS-only controller listener."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
    )

    listen_host: str
    listen_port: int = Field(ge=1, le=65_535)
    tls_certificate_path: Path
    tls_private_key_path: Path
    database_path: Path
    bootstrap_credential: SecretStr
    admin_credential: SecretStr
    tls_required: Literal[True] = True
    polling_interval_seconds: int = Field(default=30, ge=5, le=3_600)
    max_jobs_per_poll: int = Field(default=10, ge=1, le=100)
    max_request_bytes: int = Field(default=8 * 1024 * 1024, ge=1_024)
    sandbox_storage_root: Path | None = None
    sandbox_base_image: Path | None = None
    libvirt_qemu_uid: int | None = Field(default=None, ge=1)
    libvirt_qemu_gid: int | None = Field(default=None, ge=1)
    sandbox_storage_parent_uid: int = Field(default=0, ge=0)

    @field_validator("listen_host")
    @classmethod
    def reject_blank_host(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("listen_host must not be blank")
        return value

    @field_validator("bootstrap_credential", "admin_credential")
    @classmethod
    def reject_blank_credentials(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("controller credentials must not be blank")
        return value

    @model_validator(mode="after")
    def validate_sandbox_runtime_configuration(self) -> "ControllerTransportConfig":
        settings = (
            self.sandbox_storage_root,
            self.sandbox_base_image,
            self.libvirt_qemu_uid,
            self.libvirt_qemu_gid,
        )
        if any(value is not None for value in settings) and any(
            value is None for value in settings
        ):
            raise ValueError(
                "sandbox storage root, base image, and QEMU UID/GID must be configured together"
            )
        if self.libvirt_qemu_uid == 0:
            raise ValueError("libvirt QEMU UID must be unprivileged")
        return self


@dataclass(frozen=True)
class TransportResponse:
    """An already serialized HTTP response safe for the request handler."""

    status: HTTPStatus
    body: bytes


def _json_response(status: HTTPStatus, payload: object) -> TransportResponse:
    return TransportResponse(
        status=status,
        body=json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"),
    )


def _error_response(
    status: HTTPStatus,
    code: str,
    message: str,
) -> TransportResponse:
    return _json_response(
        status,
        {"error": {"code": code, "message": message}},
    )


def _model_payload(model: BaseModel) -> dict[str, object]:
    """Return JSON-safe response data while keeping secrets redacted by default."""

    payload = model.model_dump(mode="json")
    if isinstance(model, EnrollmentResponse):
        # Enrollment is the sole response that must transfer a newly generated
        # secret.  Keep this exception local to the TLS wire boundary so normal
        # model repr/dumps and all other responses retain SecretStr redaction.
        payload["agent_credential"] = model.agent_credential.get_secret_value()
    return payload


def _list_payload(models: list[BaseModel]) -> list[dict[str, object]]:
    return [_model_payload(model) for model in models]


class ControllerHTTPSApplication:
    """Route strict JSON requests to the existing transport-independent API."""

    def __init__(self, api: ControllerAPI) -> None:
        self._api = api

    def dispatch(
        self,
        method: str,
        raw_path: str,
        body: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> TransportResponse:
        normalized_headers = {
            key.lower(): value for key, value in (headers or {}).items()
        }
        try:
            parsed_path = urlsplit(raw_path)
            if parsed_path.query or parsed_path.fragment:
                return _error_response(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    "query strings and fragments are not supported",
                )
            path = parsed_path.path
            if path == f"{API_PREFIX}/enrollment":
                if method != "POST":
                    return self._method_not_allowed()
                request = EnrollmentRequest.model_validate_json(body)
                response = self._api.enroll(request)
                return _json_response(
                    HTTPStatus.CREATED,
                    _model_payload(response),
                )

            agent_match = _AGENT_ROUTE.fullmatch(path)
            if agent_match is not None:
                if method != "POST":
                    return self._method_not_allowed()
                agent_id = UUID(agent_match.group(1))
                operation = agent_match.group(2)
                if operation == "heartbeat":
                    request = HeartbeatRequest.model_validate_json(body)
                    response = self._api.heartbeat(agent_id, request)
                elif operation == "jobs/poll":
                    request = JobPollRequest.model_validate_json(body)
                    response = self._api.poll_jobs(agent_id, request)
                elif operation == "profiles":
                    request = ProfileSubmissionRequest.model_validate_json(body)
                    response = self._api.submit_profile(agent_id, request)
                else:
                    request = ValidationResultSubmissionRequest.model_validate_json(
                        body
                    )
                    response = self._api.submit_validation_result(agent_id, request)
                return _json_response(HTTPStatus.OK, _model_payload(response))

            if path == f"{API_PREFIX}/admin/targets":
                if method != "GET":
                    return self._method_not_allowed()
                auth = self._admin_auth(normalized_headers)
                targets = self._api.list_targets(auth)
                return _json_response(HTTPStatus.OK, _list_payload(targets))

            validation_result_item_match = (
                _ADMIN_VALIDATION_RESULT_ITEM_ROUTE.fullmatch(path)
            )
            if validation_result_item_match is not None:
                if method != "GET":
                    return self._method_not_allowed()
                target_id = UUID(validation_result_item_match.group(1))
                profile_id = UUID(validation_result_item_match.group(2))
                report_id = UUID(validation_result_item_match.group(3))
                result_id = UUID(validation_result_item_match.group(4))
                auth = self._admin_auth(normalized_headers)
                result = self._api.get_validation_result(
                    target_id,
                    profile_id,
                    report_id,
                    result_id,
                    auth,
                )
                return _json_response(HTTPStatus.OK, _model_payload(result))

            validation_result_collection_match = (
                _ADMIN_VALIDATION_RESULT_COLLECTION_ROUTE.fullmatch(path)
            )
            if validation_result_collection_match is not None:
                if method != "GET":
                    return self._method_not_allowed()
                target_id = UUID(validation_result_collection_match.group(1))
                profile_id = UUID(validation_result_collection_match.group(2))
                report_id = UUID(validation_result_collection_match.group(3))
                auth = self._admin_auth(normalized_headers)
                results = self._api.list_validation_results(
                    target_id,
                    profile_id,
                    report_id,
                    auth,
                )
                return _json_response(HTTPStatus.OK, _list_payload(results))

            validation_job_match = _ADMIN_VALIDATION_JOB_ROUTE.fullmatch(path)
            if validation_job_match is not None:
                if method != "POST":
                    return self._method_not_allowed()
                target_id = UUID(validation_job_match.group(1))
                profile_id = UUID(validation_job_match.group(2))
                report_id = UUID(validation_job_match.group(3))
                auth = self._admin_auth(normalized_headers)
                request = ValidationJobCreateRequest.model_validate_json(body)
                job = self._api.create_validation_job(
                    target_id,
                    profile_id,
                    report_id,
                    auth,
                    request,
                )
                return _json_response(HTTPStatus.CREATED, _model_payload(job))

            sandbox_provision_match = _ADMIN_SANDBOX_PROVISION_ROUTE.fullmatch(
                path
            )
            if sandbox_provision_match is not None:
                if method != "POST":
                    return self._method_not_allowed()
                target_id = UUID(sandbox_provision_match.group(1))
                profile_id = UUID(sandbox_provision_match.group(2))
                report_id = UUID(sandbox_provision_match.group(3))
                sandbox_session_id = UUID(sandbox_provision_match.group(4))
                auth = self._admin_auth(normalized_headers)
                request = SandboxProvisionRequest.model_validate_json(body)
                session = self._api.provision_sandbox_session(
                    target_id,
                    profile_id,
                    report_id,
                    sandbox_session_id,
                    auth,
                    request,
                )
                return _json_response(HTTPStatus.OK, _model_payload(session))

            sandbox_item_match = _ADMIN_SANDBOX_SESSION_ITEM_ROUTE.fullmatch(path)
            if sandbox_item_match is not None:
                if method != "GET":
                    return self._method_not_allowed()
                target_id = UUID(sandbox_item_match.group(1))
                profile_id = UUID(sandbox_item_match.group(2))
                report_id = UUID(sandbox_item_match.group(3))
                sandbox_session_id = UUID(sandbox_item_match.group(4))
                auth = self._admin_auth(normalized_headers)
                session = self._api.get_sandbox_session(
                    target_id,
                    profile_id,
                    report_id,
                    sandbox_session_id,
                    auth,
                )
                return _json_response(HTTPStatus.OK, _model_payload(session))

            sandbox_collection_match = (
                _ADMIN_SANDBOX_SESSION_COLLECTION_ROUTE.fullmatch(path)
            )
            if sandbox_collection_match is not None:
                target_id = UUID(sandbox_collection_match.group(1))
                profile_id = UUID(sandbox_collection_match.group(2))
                report_id = UUID(sandbox_collection_match.group(3))
                auth = self._admin_auth(normalized_headers)
                if method == "POST":
                    request = SandboxSessionCreateRequest.model_validate_json(
                        body
                    )
                    session = self._api.create_sandbox_session(
                        target_id,
                        profile_id,
                        report_id,
                        auth,
                        request,
                    )
                    return _json_response(
                        HTTPStatus.CREATED,
                        _model_payload(session),
                    )
                if method == "GET":
                    sessions = self._api.list_sandbox_sessions(
                        target_id,
                        profile_id,
                        report_id,
                        auth,
                    )
                    return _json_response(
                        HTTPStatus.OK,
                        _list_payload(sessions),
                    )
                return self._method_not_allowed()

            compatibility_item_match = (
                _ADMIN_COMPATIBILITY_ITEM_ROUTE.fullmatch(path)
            )
            if compatibility_item_match is not None:
                if method != "GET":
                    return self._method_not_allowed()
                target_id = UUID(compatibility_item_match.group(1))
                profile_id = UUID(compatibility_item_match.group(2))
                report_id = UUID(compatibility_item_match.group(3))
                auth = self._admin_auth(normalized_headers)
                response = self._api.get_compatibility_report(
                    target_id,
                    profile_id,
                    report_id,
                    auth,
                )
                return _json_response(HTTPStatus.OK, _model_payload(response))

            compatibility_collection_match = (
                _ADMIN_COMPATIBILITY_COLLECTION_ROUTE.fullmatch(path)
            )
            if compatibility_collection_match is not None:
                target_id = UUID(compatibility_collection_match.group(1))
                profile_id = UUID(compatibility_collection_match.group(2))
                auth = self._admin_auth(normalized_headers)
                if method == "POST":
                    request = CompatibilityAnalysisRequest.model_validate_json(body)
                    response = self._api.run_compatibility_analysis(
                        target_id,
                        profile_id,
                        auth,
                        request,
                    )
                    return _json_response(
                        HTTPStatus.CREATED,
                        _model_payload(response),
                    )
                if method == "GET":
                    reports = self._api.list_compatibility_reports(
                        target_id,
                        profile_id,
                        auth,
                    )
                    return _json_response(HTTPStatus.OK, _list_payload(reports))
                return self._method_not_allowed()

            admin_job_match = _ADMIN_JOB_ROUTE.fullmatch(path)
            if admin_job_match is not None:
                if method != "POST":
                    return self._method_not_allowed()
                target_id = UUID(admin_job_match.group(1))
                auth = self._admin_auth(normalized_headers)
                request = JobCreateRequest.model_validate_json(body)
                response = self._api.create_profile_job(target_id, auth, request)
                return _json_response(
                    HTTPStatus.CREATED,
                    _model_payload(response),
                )

            return _error_response(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "endpoint does not exist",
            )
        except (ValidationError, ValueError, UnicodeError):
            return _error_response(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "request body or path is invalid",
            )
        except AuthenticationError:
            return _error_response(
                HTTPStatus.UNAUTHORIZED,
                "authentication_failed",
                "authentication failed",
            )
        except AuthorizationError:
            return _error_response(
                HTTPStatus.FORBIDDEN,
                "not_authorized",
                "request is not authorized",
            )
        except ControllerNotFoundError:
            return _error_response(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "requested controller object does not exist",
            )
        except ControllerConflictError:
            return _error_response(
                HTTPStatus.CONFLICT,
                "conflict",
                "request conflicts with controller state",
            )

    @staticmethod
    def _admin_auth(headers: Mapping[str, str]) -> AdminAuth:
        scheme, separator, credential = headers.get("authorization", "").partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not credential.strip()
        ):
            raise AuthenticationError("administrator authentication is required")
        return AdminAuth(admin_credential=credential)

    @staticmethod
    def _method_not_allowed() -> TransportResponse:
        return _error_response(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "HTTP method is not allowed for this endpoint",
        )


class _ControllerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        application: ControllerHTTPSApplication,
        max_request_bytes: int,
    ) -> None:
        self.application = application
        self.max_request_bytes = max_request_bytes
        super().__init__(server_address, ControllerRequestHandler)


class ControllerRequestHandler(BaseHTTPRequestHandler):
    """Minimal JSON-only handler with request logging deliberately disabled."""

    protocol_version = "HTTP/1.1"
    server_version = "SENTRA-Controller"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle_request()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle_request()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle_request()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle_request()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle_request()

    def log_message(self, format: str, *args: object) -> None:
        # BaseHTTPRequestHandler logs raw request paths by default.  Keep the
        # narrow PoC transport silent so credentials or evidence can never be
        # exposed by an accidentally malformed URL or body.
        return

    def _handle_request(self) -> None:
        server = self.server
        assert isinstance(server, _ControllerHTTPServer)

        if self.headers.get("Transfer-Encoding") is not None:
            self._write_response(
                _error_response(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    "transfer encoding is not supported",
                )
            )
            return

        body = b""
        if self.command in {"POST", "PUT", "PATCH"}:
            media_type = self.headers.get_content_type()
            if media_type != _JSON_CONTENT_TYPE:
                self._write_response(
                    _error_response(
                        HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                        "unsupported_media_type",
                        "Content-Type must be application/json",
                    )
                )
                return
            raw_length = self.headers.get("Content-Length")
            try:
                content_length = int(raw_length) if raw_length is not None else -1
            except ValueError:
                content_length = -1
            if content_length < 0:
                self._write_response(
                    _error_response(
                        HTTPStatus.LENGTH_REQUIRED,
                        "length_required",
                        "a valid Content-Length header is required",
                    )
                )
                return
            if content_length > server.max_request_bytes:
                self._write_response(
                    _error_response(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        "request_too_large",
                        "request body exceeds the configured limit",
                    )
                )
                return
            body = self.rfile.read(content_length)
            if len(body) != content_length:
                self._write_response(
                    _error_response(
                        HTTPStatus.BAD_REQUEST,
                        "invalid_request",
                        "request body is incomplete",
                    )
                )
                return

        response = server.application.dispatch(
            self.command,
            self.path,
            body,
            dict(self.headers.items()),
        )
        self._write_response(response)

    def _write_response(self, response: TransportResponse) -> None:
        # This first transport intentionally avoids persistent connections.
        # Closing after every response prevents an unexpected body on GET or an
        # unsupported method from being parsed as the next request.
        self.close_connection = True
        self.send_response(response.status.value)
        self.send_header("Content-Type", f"{_JSON_CONTENT_TYPE}; charset=utf-8")
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(response.body)


def build_controller_api(config: ControllerTransportConfig) -> ControllerAPI:
    """Compose the existing repository, service, and API from runtime config."""

    repository = SQLiteControllerRepository(config.database_path)
    service = ControllerService(
        repository,
        ControllerSettings(
            bootstrap_credential=config.bootstrap_credential,
            admin_credential=config.admin_credential,
            polling_interval_seconds=config.polling_interval_seconds,
            max_jobs_per_poll=config.max_jobs_per_poll,
        ),
    )
    sandbox_manager = None
    if config.sandbox_storage_root is not None:
        # Local nested-VM settings are trusted host configuration only. The
        # provisioning request remains an empty strict object.
        provider = LocalNestedVmProvider(
            LocalNestedVmConfig(
                sandbox_root=config.sandbox_storage_root,
                base_image=config.sandbox_base_image,
                storage_mode=SandboxStorageMode.LIBVIRT_POOL,
                libvirt_qemu_uid=config.libvirt_qemu_uid,
                libvirt_qemu_gid=config.libvirt_qemu_gid,
                libvirt_storage_parent_uid=config.sandbox_storage_parent_uid,
            ),
            LibvirtBackend(),
        )
        sandbox_manager = SandboxManager(service, provider)
    return ControllerAPI(service, sandbox_manager)


def _require_tls_file(path: Path, description: str, *, private: bool) -> Path:
    resolved = Path(os.path.abspath(os.fspath(path.expanduser())))
    file_stat = os.lstat(resolved)
    if stat.S_ISLNK(file_stat.st_mode):
        raise ValueError(f"{description} must not be a symlink")
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(f"{description} must be a regular file")
    if private:
        if file_stat.st_uid != os.geteuid():
            raise ValueError("TLS private key must be owned by the current user")
        if stat.S_IMODE(file_stat.st_mode) & 0o077:
            raise ValueError("TLS private key must not be group/world accessible")
    return resolved


def build_server_ssl_context(config: ControllerTransportConfig) -> ssl.SSLContext:
    """Load an externally provisioned certificate; never generate or downgrade."""

    if config.tls_required is not True:
        # The Literal field already prevents this through normal construction;
        # keep the runtime assertion at the security boundary as defense-in-depth.
        raise ValueError("controller authenticated transport requires TLS")
    certificate = _require_tls_file(
        config.tls_certificate_path,
        "TLS certificate",
        private=False,
    )
    private_key = _require_tls_file(
        config.tls_private_key_path,
        "TLS private key",
        private=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certificate, keyfile=private_key)
    return context


def create_https_server(
    config: ControllerTransportConfig,
    *,
    api: ControllerAPI | None = None,
) -> ThreadingHTTPServer:
    """Create and TLS-wrap a real listener without starting its serve loop."""

    # Validate and load TLS before creating controller state or binding a socket.
    # A bad or unsafe certificate/key configuration therefore cannot leave a
    # partly initialized authenticated listener behind.
    context = build_server_ssl_context(config)
    application = ControllerHTTPSApplication(api or build_controller_api(config))
    server = _ControllerHTTPServer(
        (config.listen_host, config.listen_port),
        application,
        config.max_request_bytes,
    )
    try:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    except BaseException:
        server.server_close()
        raise
    return server


__all__ = [
    "ControllerHTTPSApplication",
    "ControllerRequestHandler",
    "ControllerTransportConfig",
    "TransportResponse",
    "build_controller_api",
    "build_server_ssl_context",
    "create_https_server",
]
