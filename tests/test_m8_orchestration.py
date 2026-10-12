"""M8 browser orchestration remains a client of authoritative Controller gates."""

from __future__ import annotations

import io
import json
import os
from html.parser import HTMLParser
from pathlib import Path
import ssl
from types import SimpleNamespace
from uuid import UUID, uuid4

import pymupdf
import pytest

from src.controller.api import ControllerAPI
from src.controller.models import (
    SandboxSessionCreateRequest, SandboxSessionStatus,
    SandboxValidationRunRecord, ValidationJobCreateRequest,
)
from src.controller.sandbox import SandboxManager
from src.controller.transport import ControllerHTTPSApplication
from src.m8db.migrations import open_db
from src.m8db.repository import M8Repository
from src.m8web.benchmark_import import (
    BenchmarkImportError, MAX_BENCHMARK_PDF_BYTES,
    validate_supported_benchmark_pdf,
)
from src.m8web.config import M8WebSettings
from src.m8web.app import create_app
from src.m8web.controller_client import M8ControllerClient
from src.controller.models import JobCreateRequest

from test_m6_validation import (
    _admin, _controller, _sandbox_sqlite_fixture, _stored_profile_and_report,
    _validation_payload,
)
from test_m7_enforcement import _case
from test_m8db import _assessment_for_case
from test_m8_product import _empty, _login, _token


ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_PDF = ROOT / "benchmark/CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.pdf"


def _unrelated_pdf() -> bytes:
    document = pymupdf.open()
    for _ in range(20):
        page = document.new_page()
        page.insert_text((72, 72), "Unrelated Linux research document")
    data = document.tobytes()
    document.close()
    return data


def test_supported_benchmark_identity_and_source_hash():
    import hashlib
    content = SUPPORTED_PDF.read_bytes()
    result = validate_supported_benchmark_pdf(content)
    assert result.supported is True
    assert result.source_sha256 == hashlib.sha256(content).hexdigest()
    assert result.reason == "supported_text_identity"


def test_unrelated_malformed_and_oversized_pdfs_fail_identity_gate():
    assert not validate_supported_benchmark_pdf(_unrelated_pdf()).supported
    with pytest.raises(BenchmarkImportError):
        validate_supported_benchmark_pdf(b"%PDF-1.7 not a PDF" + b"x" * 1024)
    with pytest.raises(BenchmarkImportError):
        validate_supported_benchmark_pdf(b"%PDF-" + b"x" * MAX_BENCHMARK_PDF_BYTES)


def test_failed_pdf_upload_creates_no_benchmark_or_control_and_ignores_filename(tmp_path):
    database, _, _, _ = _empty(tmp_path)
    client = create_app(M8WebSettings(database=database, secure_cookie=False)).test_client()
    _login(client, "admin", "correct-admin-password")
    response = client.post("/benchmarks/import", data={
        "csrf_token": _token(client),
        "pdf": (io.BytesIO(_unrelated_pdf()), "../../outside.pdf"),
    }, content_type="multipart/form-data")
    assert response.status_code == 400
    with open_db(database) as db:
        assert db.execute("SELECT count(*) FROM m8_benchmarks").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM m8_controls").fetchone()[0] == 0
    assert not (tmp_path / "outside.pdf").exists()


def test_real_supported_pdf_imports_only_selected_controls_and_hash(tmp_path):
    database, _, admin, _ = _empty(tmp_path)
    client = create_app(M8WebSettings(database=database, secure_cookie=False)).test_client()
    _login(client, "admin", "correct-admin-password")
    content = SUPPORTED_PDF.read_bytes()
    response = client.post("/benchmarks/import", data={
        "csrf_token": _token(client),
        "pdf": (io.BytesIO(content), "../../never-trusted.pdf"),
    }, content_type="multipart/form-data")
    assert response.status_code == 302
    with open_db(database) as db:
        source = db.execute("SELECT identity,version,source_reference FROM m8_benchmarks").fetchone()
        assert source[0] == "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0"
        assert source[1] == "v1.0.0"
        assert source[2] == "sha256:" + validate_supported_benchmark_pdf(content).source_sha256
        assert db.execute("SELECT count(*) FROM m8_controls").fetchone()[0] == 10
        metadata = db.execute("SELECT metadata_json FROM m8_controls "
                              "WHERE control_id='7.1.1'").fetchone()[0]
        assert json.loads(metadata)["source_sha256"] == source[2].removeprefix("sha256:")
        assert "audit" not in json.loads(metadata)
        assert "remediation" not in json.loads(metadata)
        assert db.execute("SELECT count(*) FROM m8_audit_events WHERE "
                          "event_type='benchmark_imported' AND actor_user_id=?",
                          (admin["user_id"],)).fetchone()[0] == 1
    assert not (tmp_path / "never-trusted.pdf").exists()


def test_m6_admin_route_delegates_to_existing_runner_and_requires_auth(tmp_path, monkeypatch):
    database, repository, service = _controller(tmp_path)
    enrollment, profile, report = _stored_profile_and_report(service)
    session = service.create_sandbox_session(
        _admin(), target_id=enrollment.target_id, profile_id=profile.profile_id,
        compatibility_report_id=report.compatibility_report_id,
        request=SandboxSessionCreateRequest(
            request_id=uuid4(), control_id="7.1.1",
            administrator_sandbox_authorization_acknowledged=True,
        ),
    )
    service.mark_provisioning(session.sandbox_session_id)
    ready = service.mark_ready(
        session.sandbox_session_id,
        sandbox_instance_id=f"sentra-sbx-{session.sandbox_session_id}",
    )
    provider = object()
    called = []

    def fixed_runner(actual_service, actual_provider, auth, *, session, request, manifest):
        called.append((actual_service, actual_provider, session, manifest))
        return (SimpleNamespace(validation_job_id=uuid4()),
                SimpleNamespace(sandbox_session_id=session.sandbox_session_id,
                                status=SandboxSessionStatus.COMPLETED))

    monkeypatch.setattr("src.controller.sandbox_m5.run_controller_owned_sandbox_validation",
                        fixed_runner)
    app = ControllerHTTPSApplication(ControllerAPI(service, SandboxManager(service, provider)))
    path = (f"/api/v1/admin/targets/{enrollment.target_id}/profiles/{profile.profile_id}"
            f"/compatibility-reports/{report.compatibility_report_id}/sandbox-sessions/"
            f"{ready.sandbox_session_id}/validate")
    request = ValidationJobCreateRequest(
        request_id=uuid4(), target_id=enrollment.target_id,
        profile_id=profile.profile_id,
        compatibility_report_id=report.compatibility_report_id,
        control_id="7.1.1", administrator_approval_acknowledged=True,
        compatibility_risk_acknowledged=True,
    )
    assert app.dispatch("POST", path, request.model_dump_json().encode()).status == 401
    assert not called
    result = app.dispatch("POST", path, request.model_dump_json().encode(),
                          {"Authorization": "Bearer m6d-admin-fixture"})
    assert result.status == 200
    assert json.loads(result.body)["sandbox_session_id"] == str(ready.sandbox_session_id)
    assert len(called) == 1 and called[0][0] is service and called[0][1] is provider
    assert called[0][3].control_id == "7.1.1"
    bad = json.loads(request.model_dump_json())
    bad["command"] = "id"
    assert app.dispatch("POST", path, json.dumps(bad).encode(),
                        {"Authorization": "Bearer m6d-admin-fixture"}).status == 400
    assert len(called) == 1


def test_m7_admin_route_uses_authoritative_service_gate(tmp_path):
    case = _case(tmp_path)
    app = ControllerHTTPSApplication(ControllerAPI(case.service))
    path = f"/api/v1/admin/targets/{case.enrollment.target_id}/enforcement-jobs"
    body = {
        "request_id": str(uuid4()), "target_id": str(case.enrollment.target_id),
        "profile_id": str(case.profile_id),
        "compatibility_report_id": str(case.report_id),
        "sandbox_session_id": str(case.session_id), "control_id": "7.1.1",
        "administrator_enforcement_approval_acknowledged": True,
    }
    assert app.dispatch("POST", path, json.dumps(body).encode()).status == 401
    with open_db(case.database) as db:
        assert db.execute("SELECT count(*) FROM enforcement_jobs").fetchone()[0] == 0
    body["shell"] = "whoami"
    assert app.dispatch("POST", path, json.dumps(body).encode(),
                        {"Authorization": "Bearer m6d-admin-fixture"}).status == 400
    del body["shell"]
    response = app.dispatch("POST", path, json.dumps(body).encode(),
                            {"Authorization": "Bearer m6d-admin-fixture"})
    assert response.status == 201
    created = json.loads(response.body)
    assert created["job_type"] == "ENFORCE_CONTROL"
    assert case.repository.get_enforcement_job(UUID(created["enforcement_job_id"])) is not None
    repeated = app.dispatch("POST", path, json.dumps(body).encode(),
                            {"Authorization": "Bearer m6d-admin-fixture"})
    assert json.loads(repeated.body)["enforcement_job_id"] == created["enforcement_job_id"]


def test_m7_admin_route_preserves_authoritative_evidence_refusal(tmp_path):
    case = _case(tmp_path, validated=False)
    app = ControllerHTTPSApplication(ControllerAPI(case.service))
    path = f"/api/v1/admin/targets/{case.enrollment.target_id}/enforcement-jobs"
    body = {
        "request_id": str(uuid4()), "target_id": str(case.enrollment.target_id),
        "profile_id": str(case.profile_id),
        "compatibility_report_id": str(case.report_id),
        "sandbox_session_id": str(case.session_id), "control_id": "7.1.1",
        "administrator_enforcement_approval_acknowledged": True,
    }
    response = app.dispatch("POST", path, json.dumps(body).encode(),
                            {"Authorization": "Bearer m6d-admin-fixture"})
    assert response.status == 409
    with open_db(case.database) as db:
        assert db.execute("SELECT count(*) FROM enforcement_jobs").fetchone()[0] == 0


def test_viewer_and_csrf_refuse_wizard_mutations(tmp_path):
    database, _, _, _ = _empty(tmp_path)
    client = create_app(M8WebSettings(database=database, secure_cookie=False)).test_client()
    _login(client, "viewer", "correct-viewer-password")
    target = str(uuid4())
    assert client.post("/runs/profile", data={
        "csrf_token": _token(client), "target_id": target,
        "benchmark_id": target,
    }).status_code == 403
    assert client.post("/benchmarks/import", data={"csrf_token": _token(client)}).status_code == 403
    assert client.post("/runs/sandbox/validate", data={
        "csrf_token": _token(client),
    }).status_code == 403
    assert client.post("/deployments/" + target + "/start", data={
        "csrf_token": _token(client), "enforcement_ack": "on",
    }).status_code == 403
    assert client.post("/runs/profile", data={
        "target_id": target, "benchmark_id": target,
    }).status_code == 400


@pytest.mark.parametrize("path", [
    "/benchmarks/import", "/runs/profile", "/runs/analyze",
    "/runs/sandbox/create", "/runs/sandbox/provision",
    "/runs/sandbox/validate", "/runs/sandbox/close",
])
def test_every_new_wizard_mutation_requires_csrf(tmp_path, path):
    database, _, _, _ = _empty(tmp_path)
    client = create_app(M8WebSettings(database=database, secure_cookie=False)).test_client()
    _login(client, "admin", "correct-admin-password")
    assert client.post(path, data={}).status_code == 400


def test_approval_alone_does_not_deploy_but_separate_action_calls_m7(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    _, _, result, _ = _assessment_for_case(repo, case)
    admin = repo.create_user(username="admin", password="correct-admin-password",
                             role_name="admin")
    calls = []

    class M7Client:
        def create_enforcement_job(self, request):
            calls.append(request)
            return case.service.create_enforcement_job(_admin(), request)

    client = create_app(
        M8WebSettings(database=case.database, secure_cookie=False),
        controller_client=M7Client(),
    ).test_client()
    _login(client, "admin", "correct-admin-password")
    assert client.post("/deployments/request", data={
        "csrf_token": _token(client),
        "assessment_result_id": result["assessment_result_id"],
        "sandbox_session_id": str(case.session_id),
    }).status_code == 302
    with open_db(case.database) as db:
        deployment_id = db.execute(
            "SELECT deployment_id FROM m8_deployment_requests"
        ).fetchone()[0]
        assert db.execute("SELECT count(*) FROM enforcement_jobs").fetchone()[0] == 0
    assert client.post(f"/deployments/{deployment_id}/decision", data={
        "csrf_token": _token(client), "decision": "approved",
        "reason": "Reviewed exact sandbox evidence",
    }).status_code == 302
    assert calls == []
    assert client.post(f"/deployments/{deployment_id}/start", data={
        "csrf_token": "bad", "enforcement_ack": "on",
    }).status_code == 400
    assert client.post(f"/deployments/{deployment_id}/start", data={
        "csrf_token": _token(client), "enforcement_ack": "on",
    }).status_code == 302
    assert len(calls) == 1
    with open_db(case.database) as db:
        assert db.execute("SELECT count(*) FROM enforcement_jobs").fetchone()[0] == 1
        row = db.execute("SELECT enforcement_job_id FROM m8_deployment_requests").fetchone()
        assert row[0] is not None
        event = db.execute("SELECT actor_user_id FROM m8_audit_events "
                           "WHERE event_type='controlled_deployment_started'").fetchone()
        assert event[0] == admin["user_id"]


def test_wizard_exposes_separate_review_approval_and_start_stages(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    benchmark, _, result, _ = _assessment_for_case(repo, case)
    repo.create_user(username="admin", password="correct-admin-password",
                     role_name="admin")
    client = create_app(
        M8WebSettings(database=case.database, secure_cookie=False),
    ).test_client()
    _login(client, "admin", "correct-admin-password")
    run = (f"/runs?target_id={case.enrollment.target_id}"
           f"&benchmark_id={benchmark['benchmark_id']}")
    assert b'action="/deployments/request"' in client.get(run).data
    assert client.post("/deployments/request", data={
        "csrf_token": _token(client),
        "assessment_result_id": result["assessment_result_id"],
        "sandbox_session_id": str(case.session_id),
    }).status_code == 302
    with open_db(case.database) as db:
        deployment_id = db.execute(
            "SELECT deployment_id FROM m8_deployment_requests"
        ).fetchone()[0]
    assert f'action="/deployments/{deployment_id}/decision"'.encode() in client.get(run).data
    assert client.post(f"/deployments/{deployment_id}/decision", data={
        "csrf_token": _token(client), "decision": "approved",
        "reason": "Reviewed exact M6 evidence",
    }).status_code == 302
    assert f'action="/deployments/{deployment_id}/start"'.encode() in client.get(run).data
    with open_db(case.database) as db:
        assert db.execute("SELECT count(*) FROM enforcement_jobs").fetchone()[0] == 0


def test_rejected_request_never_reaches_m7_client(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    _, _, result, _ = _assessment_for_case(repo, case)
    repo.create_user(username="admin", password="correct-admin-password",
                     role_name="admin")

    class RefuseClient:
        def create_enforcement_job(self, request):
            raise AssertionError("rejected request reached M7")

    client = create_app(M8WebSettings(database=case.database, secure_cookie=False),
                        controller_client=RefuseClient()).test_client()
    _login(client, "admin", "correct-admin-password")
    client.post("/deployments/request", data={
        "csrf_token": _token(client),
        "assessment_result_id": result["assessment_result_id"],
        "sandbox_session_id": str(case.session_id),
    })
    with open_db(case.database) as db:
        deployment_id = db.execute("SELECT deployment_id FROM m8_deployment_requests").fetchone()[0]
    client.post(f"/deployments/{deployment_id}/decision", data={
        "csrf_token": _token(client), "decision": "rejected", "reason": "Not approved",
    })
    assert client.post(f"/deployments/{deployment_id}/start", data={
        "csrf_token": _token(client), "enforcement_ack": "on",
    }).status_code == 409


def test_wizard_profile_and_analysis_use_controller_operations(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    benchmark, _, _, _ = _assessment_for_case(repo, case)
    admin = repo.create_user(username="admin", password="correct-admin-password",
                             role_name="admin")
    calls = []

    class ExistingControllerClient:
        def create_profile_job(self, request):
            calls.append("M3")
            return case.service.create_job(_admin(), request)

        def run_compatibility(self, request):
            calls.append("M4")
            return case.service.run_compatibility_analysis(_admin(), request)

    app = create_app(M8WebSettings(database=case.database, secure_cookie=False),
                     controller_client=ExistingControllerClient())
    app.testing = True
    client = app.test_client()
    _login(client, "admin", "correct-admin-password")
    target_id = str(case.enrollment.target_id)
    benchmark_id = benchmark["benchmark_id"]
    page = client.get(f"/runs?target_id={target_id}&benchmark_id={benchmark_id}")
    assert page.status_code == 200
    assert b"Hardening run" in page.data
    assert client.post("/runs/analyze", data={
        "csrf_token": _token(client), "target_id": target_id,
        "benchmark_id": benchmark_id, "profile_id": str(case.profile_id),
    }).status_code == 302
    assert calls == ["M4"]
    class FormFields(HTMLParser):
        def __init__(self):
            super().__init__()
            self.action = None
            self.fields = {}

        def handle_starttag(self, tag, attrs):
            values = dict(attrs)
            if tag == "form":
                self.action = values.get("action")
                self.fields.setdefault(self.action, set())
            elif tag == "input" and self.action:
                self.fields[self.action].add(values.get("name"))

        def handle_endtag(self, tag):
            if tag == "form":
                self.action = None

    forms = FormFields()
    forms.feed(client.get(f"/runs?target_id={target_id}&benchmark_id={benchmark_id}").text)
    assert forms.fields["/runs/profile"] == {"csrf_token", "target_id", "benchmark_id"}
    assert forms.fields["/runs/analyze"] == {
        "csrf_token", "target_id", "benchmark_id", "profile_id",
    }
    with open_db(case.database) as db:
        row = db.execute("SELECT state,reason FROM m8_assessment_results "
                         "ORDER BY observed_at DESC LIMIT 1").fetchone()
        assert row[0] == "not_tested"
        assert "not a CIS audit" in row[1]
        event = db.execute("SELECT actor_user_id FROM m8_audit_events "
                           "WHERE event_type='compatibility_analysis_requested'").fetchone()
        assert event[0] == admin["user_id"]
    assert client.post("/runs/profile", data={
        "csrf_token": "wrong", "target_id": target_id,
        "benchmark_id": benchmark_id,
    }).status_code == 400
    assert client.post("/runs/profile", data={
        "csrf_token": _token(client), "target_id": target_id,
        "benchmark_id": benchmark_id,
    }).status_code == 302
    assert calls == ["M4", "M3"]
    with open_db(case.database) as db:
        assert db.execute("SELECT count(*) FROM jobs WHERE target_id=?",
                          (target_id,)).fetchone()[0] >= 2


def test_wizard_sandbox_action_calls_narrow_controller_client_only(tmp_path):
    database, repository, service, enrollment, ready, pending = _sandbox_sqlite_fixture(tmp_path)
    case = SimpleNamespace(
        database=database, repository=repository, service=service,
        enrollment=enrollment, profile_id=ready.source_profile_id,
        report_id=ready.source_compatibility_report_id,
        session_id=ready.sandbox_session_id,
    )
    repo = M8Repository(database)
    benchmark, _, _, _ = _assessment_for_case(repo, case)
    repo.create_user(username="admin", password="correct-admin-password", role_name="admin")
    calls = []

    class NarrowClient:
        def validate_sandbox(self, target, profile, report, session, request):
            calls.append((target, profile, report, session, request))
            return SandboxValidationRunRecord(
                sandbox_session_id=session, validation_job_id=uuid4(),
                status=SandboxSessionStatus.COMPLETED,
            )

    app = create_app(M8WebSettings(database=database, secure_cookie=False),
                     controller_client=NarrowClient())
    app.testing = True
    client = app.test_client()
    _login(client, "admin", "correct-admin-password")
    response = client.post("/runs/sandbox/validate", data={
        "csrf_token": _token(client), "target_id": str(enrollment.target_id),
        "benchmark_id": benchmark["benchmark_id"],
        "profile_id": str(case.profile_id), "report_id": str(case.report_id),
        "session_id": str(case.session_id), "approval_ack": "on",
        "risk_ack": "on", "override_reason": "",
    })
    assert response.status_code == 302
    assert len(calls) == 1 and calls[0][4].control_id == "7.1.1"
    with open_db(database) as db:
        assert db.execute("SELECT count(*) FROM sandbox_validation_executions").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM m8_audit_events "
                          "WHERE event_type='sandbox_validation_requested'").fetchone()[0] == 1


def test_controller_completed_sandbox_cleanup_precedes_closed_state(tmp_path):
    database, repository, service, enrollment, ready, pending = _sandbox_sqlite_fixture(tmp_path)
    dispatched, _ = service.dispatch_sandbox_validation_job(
        _admin(), sandbox_session_id=ready.sandbox_session_id,
        validation_job_id=pending.validation_job_id,
    )
    payload, _ = _validation_payload(dispatched, tmp_path / "inert-sandbox")
    service.complete_sandbox_validation_job(
        _admin(), sandbox_session_id=ready.sandbox_session_id,
        validation_job_id=dispatched.validation_job_id, payload=payload,
    )
    destroyed = []

    class Provider:
        def destroy(self, session_id):
            destroyed.append(session_id)

    manager = SandboxManager(service, Provider())
    closed = manager.close_completed(
        _admin(), target_id=enrollment.target_id, profile_id=ready.source_profile_id,
        compatibility_report_id=ready.source_compatibility_report_id,
        sandbox_session_id=ready.sandbox_session_id,
    )
    assert destroyed == [ready.sandbox_session_id]
    assert closed.status is SandboxSessionStatus.CLOSED


def test_completed_m6_request_replay_is_read_only_and_changed_request_conflicts(tmp_path):
    from src.controller.service import ControllerConflictError

    database, repository, service, enrollment, ready, pending = _sandbox_sqlite_fixture(tmp_path)
    dispatched, _ = service.dispatch_sandbox_validation_job(
        _admin(), sandbox_session_id=ready.sandbox_session_id,
        validation_job_id=pending.validation_job_id,
    )
    payload, _ = _validation_payload(dispatched, tmp_path / "inert-replay")
    service.complete_sandbox_validation_job(
        _admin(), sandbox_session_id=ready.sandbox_session_id,
        validation_job_id=dispatched.validation_job_id, payload=payload,
    )
    manager = SandboxManager(service, object())
    request = ValidationJobCreateRequest(
        request_id=pending.request_id, target_id=pending.target_id,
        profile_id=pending.profile_id,
        compatibility_report_id=pending.compatibility_report_id,
        control_id="7.1.1", administrator_approval_acknowledged=True,
        compatibility_risk_acknowledged=pending.compatibility_risk_acknowledged,
        compatibility_override_reason=pending.compatibility_override_reason,
    )
    lineage = {
        "target_id": enrollment.target_id, "profile_id": ready.source_profile_id,
        "compatibility_report_id": ready.source_compatibility_report_id,
        "sandbox_session_id": ready.sandbox_session_id,
    }
    result = manager.execute_validation(_admin(), request=request, **lineage)
    assert result.validation_job_id == pending.validation_job_id
    assert result.status is SandboxSessionStatus.COMPLETED
    changed = request.model_copy(update={"request_id": uuid4()})
    with pytest.raises(ControllerConflictError):
        manager.execute_validation(_admin(), request=changed, **lineage)
    with open_db(database) as db:
        assert db.execute("SELECT count(*) FROM sandbox_validation_executions").fetchone()[0] == 1


def test_controller_client_requires_verified_https_and_keeps_credential_server_side(
    tmp_path, monkeypatch,
):
    database, _, _, _ = _empty(tmp_path)
    ca = tmp_path / "ca.pem"
    ca.write_text("test CA path")
    credential = tmp_path / "admin.secret"
    credential.write_text("controller-secret-sentinel\n")
    os.chmod(credential, 0o600)
    with pytest.raises(ValueError):
        M8WebSettings(
            database=database, controller_url="http://localhost:8443",
            controller_ca_file=ca, controller_admin_credential_file=credential,
        )
    settings = M8WebSettings(
        database=database, controller_url="https://localhost:8443",
        controller_ca_file=ca, controller_admin_credential_file=credential,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    monkeypatch.setattr("src.m8web.controller_client.ssl.create_default_context",
                        lambda **kwargs: context)
    seen = []
    target_id, job_id = uuid4(), uuid4()

    class Response:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            return json.dumps({
                "job_id": str(job_id), "target_id": str(target_id),
                "job_type": "PROFILE_TARGET", "status": "pending",
                "created_at": "2026-10-12T00:00:00Z",
                "dispatched_at": None, "completed_at": None,
            }).encode()

    class Opener:
        def open(self, request, timeout):
            seen.append((request, timeout))
            return Response()

    client = M8ControllerClient(settings, opener=Opener())
    record = client.create_profile_job(JobCreateRequest(target_id=target_id))
    assert record.job_id == job_id
    assert seen[0][0].full_url.startswith("https://localhost:8443/api/v1/admin/")
    assert seen[0][0].get_header("Authorization") == "Bearer controller-secret-sentinel"
    assert "controller-secret-sentinel" not in repr(client)
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    web = create_app(settings).test_client()
    web.get("/login")
    with web.session_transaction() as session:
        assert "controller-secret-sentinel" not in repr(dict(session))
    assert b"controller-secret-sentinel" not in web.get("/login").data
