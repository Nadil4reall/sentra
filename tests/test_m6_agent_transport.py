"""Focused M6B tests for the Agent HTTPS serialization and trust boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from email.message import Message
import json
from pathlib import Path
import ssl
from urllib.error import HTTPError
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import SecretStr
import pytest

from src.agent.config import AgentTransportConfig
from src.agent.protocol import AgentProtocol
from src.agent.runtime import AgentRuntime
from src.agent.state import AgentStateStore
from src.agent.transport import (
    AgentControllerResponseError,
    AgentHTTPSClient,
    AgentTransportConfigurationError,
)
from src.controller.models import (
    AdminAuth,
    AgentAuth,
    EnrollmentRequest,
    HeartbeatRequest,
    JobCreateRequest,
    JobStatus,
    JobType,
    ObservedTargetMetadata,
)
from src.controller.api import ControllerAPI
from src.controller.service import ControllerService, ControllerSettings
from src.controller.storage import SQLiteControllerRepository
from src.controller.transport import ControllerHTTPSApplication
from src.target_profiler.models import (
    CollectionSummary,
    FactResult,
    FactStatus,
    TargetInfo,
    TargetProfile,
)


BOOTSTRAP_SECRET = "bootstrap-wire-secret"
AGENT_SECRET = "agent-wire-secret"


def _metadata() -> ObservedTargetMetadata:
    return ObservedTargetMetadata(
        hostname="transport-fixture",
        os="Ubuntu",
        os_version="24.04",
        kernel="6.8.0-fixture",
        architecture="x86_64",
    )


class _FakeSSLContext:
    check_hostname = False
    verify_mode = ssl.CERT_NONE
    minimum_version: ssl.TLSVersion | None = None


class _Response:
    def __init__(self, status: int, body: bytes) -> None:
        self._status = status
        self._body = body
        self.headers = Message()
        self.headers["Content-Type"] = "application/json; charset=utf-8"
        self.headers["Content-Length"] = str(len(body))

    def getcode(self) -> int:
        return self._status

    def read(self, size: int) -> bytes:
        return self._body[:size]

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class _QueueOpener:
    def __init__(self, responses: list[_Response | BaseException]) -> None:
        self.responses = responses
        self.requests: list[tuple[object, float]] = []

    def open(self, request: object, *, timeout: float) -> _Response:
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class _ApplicationOpener:
    """Exercise wire JSON against the real Controller application facade."""

    def __init__(self, application: ControllerHTTPSApplication) -> None:
        self.application = application
        self.requests: list[tuple[object, float]] = []

    def open(self, request: object, *, timeout: float) -> _Response:
        self.requests.append((request, timeout))
        response = self.application.dispatch(
            request.get_method(),
            urlsplit(request.full_url).path,
            request.data or b"",
            dict(request.header_items()),
        )
        return _Response(response.status.value, response.body)


class _FourStateProfiler:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self) -> TargetProfile:
        self.calls += 1
        requested_by = ["3.3.1"]
        facts = {
            "collected_fixture": FactResult(
                name="collected_fixture",
                status=FactStatus.COLLECTED,
                value=True,
                requested_by=requested_by,
            ),
            "unavailable_fixture": FactResult(
                name="unavailable_fixture",
                status=FactStatus.UNAVAILABLE,
                requested_by=requested_by,
                reason="fixture unavailable",
            ),
            "unsupported_fixture": FactResult(
                name="unsupported_fixture",
                status=FactStatus.UNSUPPORTED,
                requested_by=requested_by,
                reason="fixture unsupported",
            ),
            "error_fixture": FactResult(
                name="error_fixture",
                status=FactStatus.ERROR,
                requested_by=requested_by,
                reason="fixture error",
            ),
        }
        return TargetProfile(
            collected_at=datetime(2026, 9, 24, 7, 59, tzinfo=UTC),
            target=TargetInfo(
                hostname="transport-fixture",
                os="Ubuntu",
                os_version="24.04",
                kernel="6.8.0-fixture",
                architecture="x86_64",
                supported=True,
            ),
            facts=facts,
            collection_summary=CollectionSummary(
                requested=4,
                collected=1,
                unavailable=1,
                unsupported=1,
                errors=1,
            ),
        )


def _client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    opener: _QueueOpener,
    *,
    controller_url: str = "https://controller.example.test:8443",
) -> tuple[AgentHTTPSClient, _FakeSSLContext, Path]:
    ca_path = tmp_path / "controller-ca.pem"
    ca_path.write_text("fixture CA", encoding="utf-8")
    context = _FakeSSLContext()
    calls: dict[str, object] = {}

    def create_default_context(*, purpose: ssl.Purpose, cafile: str) -> _FakeSSLContext:
        calls["purpose"] = purpose
        calls["cafile"] = cafile
        return context

    monkeypatch.setattr(
        "src.agent.transport.ssl.create_default_context",
        create_default_context,
    )
    monkeypatch.setattr(
        "src.agent.transport.build_opener",
        lambda *handlers: opener,
    )
    client = AgentHTTPSClient(
        AgentTransportConfig(
            controller_url=controller_url,
            controller_ca_path=ca_path,
            request_timeout_seconds=12.0,
        )
    )
    assert calls == {
        "purpose": ssl.Purpose.SERVER_AUTH,
        "cafile": str(ca_path),
    }
    return client, context, ca_path


def test_https_client_loads_ca_and_requires_hostname_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, context, _ = _client(tmp_path, monkeypatch, _QueueOpener([]))

    assert isinstance(client, AgentHTTPSClient)
    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.minimum_version is ssl.TLSVersion.TLSv1_2
    assert "verify=False" not in repr(client)


def test_https_client_refuses_missing_ca_before_any_request(tmp_path: Path) -> None:
    config = AgentTransportConfig(
        controller_url="https://controller.example.test:8443",
        controller_ca_path=tmp_path / "missing-ca.pem",
    )

    with pytest.raises(
        AgentTransportConfigurationError,
        match="CA bundle does not exist",
    ):
        AgentHTTPSClient(config)


def test_wire_materializes_bootstrap_and_agent_secrets_only_in_request_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_id = uuid4()
    agent_id = uuid4()
    enrollment_response = json.dumps(
        {
            "target_id": str(target_id),
            "agent_id": str(agent_id),
            "agent_credential": AGENT_SECRET,
            "polling_interval_seconds": 30,
        }
    ).encode()
    heartbeat_response = json.dumps(
        {
            "accepted": True,
            "last_seen": "2026-09-24T08:00:00Z",
        }
    ).encode()
    opener = _QueueOpener(
        [_Response(201, enrollment_response), _Response(200, heartbeat_response)]
    )
    client, _, _ = _client(tmp_path, monkeypatch, opener)
    enrollment_request = EnrollmentRequest(
        bootstrap_credential=SecretStr(BOOTSTRAP_SECRET),
        installation_id=uuid4(),
        agent_version="m6b-test",
        observed_metadata=_metadata(),
    )

    enrolled = client.enroll(enrollment_request)
    heartbeat_request = HeartbeatRequest(
        auth=AgentAuth(
            target_id=target_id,
            agent_id=agent_id,
            agent_credential=SecretStr(AGENT_SECRET),
        ),
        sent_at=datetime(2026, 9, 24, 8, 0, tzinfo=UTC),
        agent_version="m6b-test",
        observed_metadata=_metadata(),
    )
    client.heartbeat(heartbeat_request)

    enrollment_wire = opener.requests[0][0].data
    heartbeat_wire = opener.requests[1][0].data
    assert json.loads(enrollment_wire)["bootstrap_credential"] == BOOTSTRAP_SECRET
    assert json.loads(heartbeat_wire)["auth"]["agent_credential"] == AGENT_SECRET
    assert b"**********" not in enrollment_wire
    assert b"**********" not in heartbeat_wire
    assert enrolled.agent_credential.get_secret_value() == AGENT_SECRET
    assert BOOTSTRAP_SECRET not in repr(enrollment_request)
    assert AGENT_SECRET not in repr(heartbeat_request)
    assert opener.requests[0][0].full_url.endswith("/api/v1/enrollment")
    assert opener.requests[1][1] == 12.0


def test_redirect_or_http_error_is_sanitized_without_request_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = HTTPError(
        "https://controller.example.test/api/v1/enrollment",
        307,
        "redirect",
        Message(),
        None,
    )
    client, _, _ = _client(tmp_path, monkeypatch, _QueueOpener([failure]))
    request = EnrollmentRequest(
        bootstrap_credential=SecretStr(BOOTSTRAP_SECRET),
        installation_id=uuid4(),
        agent_version="m6b-test",
        observed_metadata=_metadata(),
    )

    with pytest.raises(AgentControllerResponseError) as raised:
        client.enroll(request)

    assert "307" in str(raised.value)
    assert BOOTSTRAP_SECRET not in str(raised.value)
    assert BOOTSTRAP_SECRET not in repr(raised.value)


def test_agent_https_runtime_maps_full_profile_flow_to_existing_controller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 9, 24, 8, 0, tzinfo=UTC)
    repository = SQLiteControllerRepository(tmp_path / "controller.sqlite3")
    service = ControllerService(
        repository,
        ControllerSettings(
            bootstrap_credential=BOOTSTRAP_SECRET,
            admin_credential="admin-wire-secret",
        ),
        clock=lambda: now,
    )
    api = ControllerAPI(service)
    opener = _ApplicationOpener(ControllerHTTPSApplication(api))
    client, _, _ = _client(tmp_path, monkeypatch, opener)  # type: ignore[arg-type]
    state_path = tmp_path / "agent" / "state.json"
    profiler = _FourStateProfiler()
    first_protocol = AgentProtocol(
        AgentStateStore(state_path),
        observed_metadata=_metadata(),
        agent_version="m6b-test",
    )

    initial = AgentRuntime(
        protocol=first_protocol,
        transport=client,
        profiler=profiler,
        bootstrap_credential=SecretStr(BOOTSTRAP_SECRET),
    ).run_once()
    target_id = first_protocol.state.target_id
    assert target_id is not None
    job = api.create_profile_job(
        target_id,
        AdminAuth(admin_credential="admin-wire-secret"),
        JobCreateRequest(
            target_id=target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )

    restarted_protocol = AgentProtocol(
        AgentStateStore(state_path),
        observed_metadata=_metadata(),
        agent_version="m6b-test",
    )
    completed = AgentRuntime(
        protocol=restarted_protocol,
        transport=client,
        profiler=profiler,
        bootstrap_credential=None,
        profiler_version="m3-test",
        sentra_version="m6b-test",
    ).run_once()

    assert initial.enrolled_during_run is True
    assert initial.jobs_polled == 0
    assert completed.enrolled_during_run is False
    assert completed.jobs_polled == 1
    assert completed.profiles_submitted == 1
    assert profiler.calls == 1
    assert len(service.list_targets(AdminAuth(admin_credential="admin-wire-secret"))) == 1
    assert sum(
        request.full_url.endswith("/enrollment")
        for request, _ in opener.requests
    ) == 1
    stored_job = repository.get_job(job.job_id)
    assert stored_job is not None
    assert stored_job.job.status is JobStatus.COMPLETED
    profile_wires = [
        json.loads(request.data)
        for request, _ in opener.requests
        if request.full_url.endswith("/profiles")
    ]
    assert len(profile_wires) == 1
    transported_statuses = {
        fact["status"] for fact in profile_wires[0]["profile"]["facts"].values()
    }
    assert transported_statuses == {status.value for status in FactStatus}
    assert profile_wires[0]["job_id"] == str(job.job_id)


@pytest.mark.parametrize(
    "updates",
    [
        {"controller_url": "http://controller.example.test:8080"},
        {"controller_url": "https://user:secret@controller.example.test"},
        {"controller_url": "https://controller.example.test/other"},
        {"tls_required": False},
        {"verify_controller_certificate": False},
    ],
)
def test_transport_configuration_rejects_insecure_variants(
    tmp_path: Path,
    updates: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "controller_url": "https://controller.example.test:8443",
        "controller_ca_path": tmp_path / "controller-ca.pem",
    }
    values.update(updates)

    with pytest.raises(ValueError):
        AgentTransportConfig(**values)
