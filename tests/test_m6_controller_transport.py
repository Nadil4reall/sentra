"""Focused M6B tests for the real Controller HTTPS boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from http import HTTPStatus
from io import BytesIO
import json
from pathlib import Path
import ssl
from uuid import UUID, uuid4

from pydantic import SecretStr, ValidationError
import pytest
import yaml

from src.controller.api import ControllerAPI
from src.controller.cli import (
    ControllerCLIConfigurationError,
    build_parser,
    config_from_args,
)
from src.controller.models import (
    AdminAuth,
    AgentAuth,
    EnrollmentRequest,
    JobCreateRequest,
    JobPollRequest,
    JobType,
    ProfileSubmissionRequest,
)
from src.controller.service import ControllerService, ControllerSettings
from src.controller.storage import SQLiteControllerRepository
from src.controller.transport import (
    ControllerHTTPSApplication,
    ControllerRequestHandler,
    ControllerTransportConfig,
    TransportResponse,
    build_server_ssl_context,
)
from src.target_profiler.models import TargetProfile


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = "transport-bootstrap-secret"
ADMIN = "transport-admin-secret"
NOW = datetime(2026, 9, 24, 8, 0, tzinfo=UTC)


def _config(tmp_path: Path, **updates: object) -> ControllerTransportConfig:
    values: dict[str, object] = {
        "listen_host": "127.0.0.1",
        "listen_port": 8443,
        "tls_certificate_path": tmp_path / "controller.crt",
        "tls_private_key_path": tmp_path / "controller.key",
        "database_path": tmp_path / "controller.sqlite3",
        "bootstrap_credential": SecretStr(BOOTSTRAP),
        "admin_credential": SecretStr(ADMIN),
    }
    values.update(updates)
    return ControllerTransportConfig(**values)


def _application(tmp_path: Path) -> tuple[ControllerHTTPSApplication, SQLiteControllerRepository]:
    repository = SQLiteControllerRepository(tmp_path / "controller.sqlite3")
    service = ControllerService(
        repository,
        ControllerSettings(
            bootstrap_credential=BOOTSTRAP,
            admin_credential=ADMIN,
        ),
        clock=lambda: NOW,
    )
    return ControllerHTTPSApplication(ControllerAPI(service)), repository


def _metadata(hostname: str = "transport-target") -> dict[str, object]:
    return {
        "hostname": hostname,
        "os": "Ubuntu",
        "os_version": "24.04",
        "kernel": "6.8.0-test",
        "architecture": "x86_64",
        "machine_identity_hash": None,
    }


def _enrollment_body(installation_id: UUID) -> bytes:
    return json.dumps(
        {
            "bootstrap_credential": BOOTSTRAP,
            "installation_id": str(installation_id),
            "agent_version": "0.6b-test",
            "observed_metadata": _metadata(),
        }
    ).encode("utf-8")


def test_controller_transport_configuration_is_tls_only_and_redacts_secrets(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)

    assert config.tls_required is True
    assert BOOTSTRAP not in repr(config)
    assert ADMIN not in repr(config)
    assert "**********" in repr(config)
    with pytest.raises(ValidationError):
        _config(tmp_path, tls_required=False)
    with pytest.raises(ValidationError):
        _config(tmp_path, listen_host="   ")
    with pytest.raises(ValidationError):
        _config(tmp_path, listen_port=0)


def test_enrollment_transport_maps_to_existing_service_and_materializes_secret_once(
    tmp_path: Path,
) -> None:
    application, repository = _application(tmp_path)
    installation_id = uuid4()

    response = application.dispatch(
        "POST",
        "/api/v1/enrollment",
        _enrollment_body(installation_id),
    )

    assert response.status is HTTPStatus.CREATED
    payload = json.loads(response.body)
    assert payload["agent_credential"] != "**********"
    assert isinstance(payload["agent_credential"], str)
    assert payload["agent_credential"]
    target = repository.get_target(UUID(payload["target_id"]))
    assert target is not None
    assert target.agent_id == UUID(payload["agent_id"])
    assert target.installation_id == installation_id


def test_heartbeat_transport_preserves_agent_path_binding_and_authentication(
    tmp_path: Path,
) -> None:
    application, repository = _application(tmp_path)
    enrolled = json.loads(
        application.dispatch(
            "POST",
            "/api/v1/enrollment",
            _enrollment_body(uuid4()),
        ).body
    )
    heartbeat = json.dumps(
        {
            "auth": {
                "target_id": enrolled["target_id"],
                "agent_id": enrolled["agent_id"],
                "agent_credential": enrolled["agent_credential"],
            },
            "sent_at": NOW.isoformat(),
            "agent_version": "0.6b-test",
            "observed_metadata": _metadata(),
        }
    ).encode("utf-8")

    accepted = application.dispatch(
        "POST",
        f"/api/v1/agents/{enrolled['agent_id']}/heartbeat",
        heartbeat,
    )
    wrong_path = application.dispatch(
        "POST",
        f"/api/v1/agents/{uuid4()}/heartbeat",
        heartbeat,
    )

    assert accepted.status is HTTPStatus.OK
    assert json.loads(accepted.body) == {
        "accepted": True,
        "last_seen": NOW.isoformat().replace("+00:00", "Z"),
    }
    assert repository.get_target(UUID(enrolled["target_id"])).last_seen == NOW
    assert wrong_path.status is HTTPStatus.UNAUTHORIZED


def test_admin_transport_uses_bearer_header_and_exact_existing_job_model(
    tmp_path: Path,
) -> None:
    application, _ = _application(tmp_path)
    enrolled = json.loads(
        application.dispatch(
            "POST",
            "/api/v1/enrollment",
            _enrollment_body(uuid4()),
        ).body
    )
    job_body = json.dumps(
        {
            "target_id": enrolled["target_id"],
            "job_type": "PROFILE_TARGET",
        }
    ).encode("utf-8")

    unauthenticated = application.dispatch(
        "POST",
        f"/api/v1/admin/targets/{enrolled['target_id']}/jobs",
        job_body,
    )
    created = application.dispatch(
        "POST",
        f"/api/v1/admin/targets/{enrolled['target_id']}/jobs",
        job_body,
        {"Authorization": f"Bearer {ADMIN}"},
    )

    assert unauthenticated.status is HTTPStatus.UNAUTHORIZED
    assert created.status is HTTPStatus.CREATED
    assert json.loads(created.body)["job_type"] == "PROFILE_TARGET"


def test_m6c_transport_is_admin_only_and_retrieves_controller_report(
    tmp_path: Path,
) -> None:
    repository = SQLiteControllerRepository(tmp_path / "controller.sqlite3")
    service = ControllerService(
        repository,
        ControllerSettings(
            bootstrap_credential=BOOTSTRAP,
            admin_credential=ADMIN,
        ),
        clock=lambda: NOW,
    )
    api = ControllerAPI(service)
    application = ControllerHTTPSApplication(api)
    enrollment = api.enroll(
        EnrollmentRequest(
            bootstrap_credential=BOOTSTRAP,
            installation_id=uuid4(),
            agent_version="0.6c-test",
            observed_metadata=_metadata(),
        )
    )
    auth = AgentAuth(
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
        agent_credential=enrollment.agent_credential,
    )
    job = api.create_profile_job(
        enrollment.target_id,
        AdminAuth(admin_credential=ADMIN),
        JobCreateRequest(
            target_id=enrollment.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )
    api.poll_jobs(enrollment.agent_id, JobPollRequest(auth=auth))
    profile_payload = yaml.safe_load(
        (ROOT / "data" / "profiles" / "target-profile.yaml").read_text(
            encoding="utf-8"
        )
    )
    profile = api.submit_profile(
        enrollment.agent_id,
        ProfileSubmissionRequest(
            auth=auth,
            job_id=job.job_id,
            profile=TargetProfile.model_validate(profile_payload),
        ),
    )
    collection_path = (
        f"/api/v1/admin/targets/{enrollment.target_id}/profiles/"
        f"{profile.profile_id}/compatibility-reports"
    )
    body = json.dumps(
        {
            "target_id": str(enrollment.target_id),
            "profile_id": str(profile.profile_id),
        }
    ).encode("utf-8")

    unauthenticated = application.dispatch("POST", collection_path, body)
    agent_authenticated = application.dispatch(
        "POST",
        collection_path,
        body,
        {
            "Authorization": (
                "Bearer "
                f"{enrollment.agent_credential.get_secret_value()}"
            )
        },
    )
    arbitrary_command_attempt = application.dispatch(
        "POST",
        collection_path,
        json.dumps(
            {
                "target_id": str(enrollment.target_id),
                "profile_id": str(profile.profile_id),
                "command": "id",
            }
        ).encode("utf-8"),
        {"Authorization": f"Bearer {ADMIN}"},
    )
    created = application.dispatch(
        "POST",
        collection_path,
        body,
        {"Authorization": f"Bearer {ADMIN}"},
    )

    assert unauthenticated.status is HTTPStatus.UNAUTHORIZED
    assert agent_authenticated.status is HTTPStatus.UNAUTHORIZED
    assert arbitrary_command_attempt.status is HTTPStatus.BAD_REQUEST
    assert created.status is HTTPStatus.CREATED
    created_payload = json.loads(created.body)
    assert created_payload["target_id"] == str(enrollment.target_id)
    assert created_payload["profile_id"] == str(profile.profile_id)
    assert created_payload["benchmark_identity"] == (
        "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0"
    )
    assert len(created_payload["report"]["control_results"]) == 10

    report_id = created_payload["compatibility_report_id"]
    listed = application.dispatch(
        "GET",
        collection_path,
        headers={"Authorization": f"Bearer {ADMIN}"},
    )
    unauthenticated_list = application.dispatch("GET", collection_path)
    retrieved = application.dispatch(
        "GET",
        f"{collection_path}/{report_id}",
        headers={"Authorization": f"Bearer {ADMIN}"},
    )
    agent_authenticated_get = application.dispatch(
        "GET",
        f"{collection_path}/{report_id}",
        headers={
            "Authorization": (
                "Bearer "
                f"{enrollment.agent_credential.get_secret_value()}"
            )
        },
    )
    nonexistent_agent_route = application.dispatch(
        "POST",
        f"/api/v1/agents/{enrollment.agent_id}/compatibility-reports",
        body,
    )

    assert listed.status is HTTPStatus.OK
    assert unauthenticated_list.status is HTTPStatus.UNAUTHORIZED
    assert [item["compatibility_report_id"] for item in json.loads(listed.body)] == [
        report_id
    ]
    assert retrieved.status is HTTPStatus.OK
    assert agent_authenticated_get.status is HTTPStatus.UNAUTHORIZED
    assert json.loads(retrieved.body) == created_payload
    assert nonexistent_agent_route.status is HTTPStatus.NOT_FOUND


def test_invalid_transport_input_is_sanitized_and_never_echoed(tmp_path: Path) -> None:
    application, _ = _application(tmp_path)
    sentinel = "plaintext-secret-that-must-not-be-echoed"

    response = application.dispatch(
        "POST",
        "/api/v1/enrollment",
        json.dumps({"bootstrap_credential": sentinel}).encode("utf-8"),
    )

    assert response.status is HTTPStatus.BAD_REQUEST
    assert sentinel.encode() not in response.body
    assert json.loads(response.body) == {
        "error": {
            "code": "invalid_request",
            "message": "request body or path is invalid",
        }
    }


def test_tls_context_requires_regular_non_symlink_files_and_protected_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate = tmp_path / "controller.crt"
    private_key = tmp_path / "controller.key"
    certificate.write_text("test certificate", encoding="utf-8")
    private_key.write_text("test key", encoding="utf-8")
    private_key.chmod(0o600)
    config = _config(
        tmp_path,
        tls_certificate_path=certificate,
        tls_private_key_path=private_key,
    )
    calls: dict[str, object] = {}

    class FakeSSLContext:
        minimum_version: ssl.TLSVersion | None = None

        def __init__(self, protocol: ssl._SSLMethod) -> None:
            calls["protocol"] = protocol

        def load_cert_chain(self, *, certfile: Path, keyfile: Path) -> None:
            calls["certfile"] = certfile
            calls["keyfile"] = keyfile

    monkeypatch.setattr("src.controller.transport.ssl.SSLContext", FakeSSLContext)

    context = build_server_ssl_context(config)

    assert context.minimum_version is ssl.TLSVersion.TLSv1_2
    assert calls == {
        "protocol": ssl.PROTOCOL_TLS_SERVER,
        "certfile": certificate,
        "keyfile": private_key,
    }

    certificate_link = tmp_path / "certificate-link.pem"
    certificate_link.symlink_to(certificate)
    with pytest.raises(ValueError, match="symlink"):
        build_server_ssl_context(
            _config(tmp_path, tls_certificate_path=certificate_link)
        )

    private_key.chmod(0o644)
    with pytest.raises(ValueError, match="group/world"):
        build_server_ssl_context(config)


def test_controller_cli_uses_environment_sources_and_has_no_plaintext_secret_flag(
    tmp_path: Path,
) -> None:
    parser = build_parser()
    help_text = parser.format_help()
    args = parser.parse_args(
        [
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            "8443",
            "--tls-certificate",
            str(tmp_path / "controller.crt"),
            "--tls-private-key",
            str(tmp_path / "controller.key"),
            "--database",
            str(tmp_path / "controller.sqlite3"),
        ]
    )

    config = config_from_args(
        args,
        environ={
            "SENTRA_CONTROLLER_BOOTSTRAP_CREDENTIAL": BOOTSTRAP,
            "SENTRA_CONTROLLER_ADMIN_CREDENTIAL": ADMIN,
        },
    )

    assert config.bootstrap_credential.get_secret_value() == BOOTSTRAP
    assert config.admin_credential.get_secret_value() == ADMIN
    assert "--bootstrap-credential " not in help_text
    assert "--admin-credential " not in help_text
    assert BOOTSTRAP not in repr(config)
    assert ADMIN not in repr(config)


def test_controller_cli_accepts_only_protected_credential_files(
    tmp_path: Path,
) -> None:
    bootstrap_file = tmp_path / "bootstrap.secret"
    admin_file = tmp_path / "admin.secret"
    bootstrap_file.write_text(f"{BOOTSTRAP}\n", encoding="utf-8")
    admin_file.write_text(f"{ADMIN}\n", encoding="utf-8")
    bootstrap_file.chmod(0o600)
    admin_file.chmod(0o600)
    parser = build_parser()
    arguments = [
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        "8443",
        "--tls-certificate",
        str(tmp_path / "controller.crt"),
        "--tls-private-key",
        str(tmp_path / "controller.key"),
        "--database",
        str(tmp_path / "controller.sqlite3"),
        "--bootstrap-credential-file",
        str(bootstrap_file),
        "--admin-credential-file",
        str(admin_file),
    ]

    config = config_from_args(parser.parse_args(arguments), environ={})

    assert config.bootstrap_credential.get_secret_value() == BOOTSTRAP
    assert config.admin_credential.get_secret_value() == ADMIN

    admin_file.chmod(0o644)
    with pytest.raises(ControllerCLIConfigurationError, match="group/world"):
        config_from_args(parser.parse_args(arguments), environ={})


def test_handler_closes_every_connection_to_prevent_body_desynchronization() -> None:
    handler = object.__new__(ControllerRequestHandler)
    handler.close_connection = False
    handler.wfile = BytesIO()
    headers: list[tuple[str, str]] = []
    handler.send_response = lambda status: None  # type: ignore[method-assign]
    handler.send_header = (  # type: ignore[method-assign]
        lambda name, value: headers.append((name, value))
    )
    handler.end_headers = lambda: None  # type: ignore[method-assign]

    handler._write_response(
        TransportResponse(status=HTTPStatus.OK, body=b"{}")
    )

    assert handler.close_connection is True
    assert ("Connection", "close") in headers
    assert handler.wfile.getvalue() == b"{}"
