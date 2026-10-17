"""M8 run labels are projections, not a second workflow state machine."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import re
from threading import Barrier
from types import SimpleNamespace

import pytest

from src.controller.models import JobCreateRequest, JobPollRequest, ProfileSubmissionRequest
from src.m8db.migrations import open_db
from src.m8db.repository import M8Repository
from src.m8web.app import create_app
from src.m8web.config import M8WebSettings
from src.m8web.read_model import M8ReadModel
from src.m8web.run_status import project_run

from test_m6_validation import _admin, _auth, _profile, _sandbox_sqlite_fixture
from test_m7_enforcement import _case, _request
from test_m8db import _assessment_for_case
from test_m8_product import _login, _token
from test_m7_enforcement_result import _complete_reprofile, _terminal


def _progress():
    return {
        "target": {"target_id": "target", "hostname": "server", "created_at": "2026-01-01T00:00:00+00:00"},
        "benchmark": {"identity": "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0", "active": 1},
        "job": None, "profile": None, "report": None, "session": None,
        "validation": None, "deployment": None, "enforcement": None,
        "verification": None,
    }


def _stage(progress, key):
    return next(item for item in project_run(progress)["stages"] if item["key"] == key)


@pytest.mark.parametrize("job_status,expected_state,expected_label", [
    (None, "action_required", "Ready to collect host evidence"),
    ("pending", "waiting", "Waiting for Agent"),
    ("dispatched", "in_progress", "Agent is collecting host evidence"),
])
def test_m3_status_comes_from_profile_job(job_status, expected_state, expected_label):
    progress = _progress()
    if job_status:
        progress["job"] = {"status": job_status, "created_at": "2026-01-01T00:00:00+00:00"}
    result = _stage(progress, "evidence")
    assert (result["state"], result["label"]) == (expected_state, expected_label)


def test_m3_completed_profile_unlocks_analysis_without_fabricated_pass():
    progress = _progress()
    progress["job"] = {"status": "completed", "created_at": "2026-01-01T00:00:00+00:00"}
    progress["profile"] = {"received_at": "2026-01-01T00:01:00+00:00"}
    assert _stage(progress, "evidence")["state"] == "complete"
    assert _stage(progress, "compatibility")["state"] == "action_required"


@pytest.mark.parametrize("decision", ["review_required", "no_known_conflict", "warning", "insufficient_evidence"])
def test_m4_decision_is_preserved_without_compliance_translation(decision):
    progress = _progress()
    progress["report"] = {"control_results": [{"control_id": "7.1.1", "result": decision}],
                          "generated_at": "2026-01-01T00:02:00+00:00"}
    result = _stage(progress, "compatibility")
    assert result["state"] == "complete"
    assert result["label"].lower().replace(" ", "_") == decision
    assert all(word not in result["label"].lower() for word in ("pass", "safe", "compliant"))


@pytest.mark.parametrize("session_status,expected", [
    ("REQUESTED", "action_required"), ("PROVISIONING", "in_progress"),
    ("READY", "action_required"), ("VALIDATING", "in_progress"),
    ("COMPLETED", "action_required"), ("FAILED", "failed"),
    ("QUARANTINED", "failed"), ("CLOSED", "complete"),
])
def test_m6_lifecycle_uses_recorded_session_state(session_status, expected):
    progress = _progress()
    progress["session"] = {"status": session_status, "created_at": "2026-01-01T00:00:00+00:00"}
    progress["validation"] = {"result": "validated"} if session_status == "CLOSED" else None
    assert _stage(progress, "sandbox")["state"] == expected


def test_failed_closed_sandbox_never_becomes_successful_approval():
    progress = _progress()
    progress["session"] = {"status": "CLOSED", "created_at": "2026-01-01T00:00:00+00:00"}
    progress["validation"] = {"result": "failed"}
    assert _stage(progress, "sandbox")["state"] == "failed"
    assert _stage(progress, "approval")["state"] == "waiting"


@pytest.mark.parametrize("job_status,expected_state,expected_label", [
    ("pending", "waiting", "Waiting for target Agent"),
    ("dispatched", "in_progress", "Enforcement job assigned to Agent"),
])
def test_m7_pending_and_dispatched_are_not_claimed_as_applying(job_status, expected_state, expected_label):
    progress = _progress()
    progress["deployment"] = {"state": "approved", "requested_at": "2026-01-01T00:00:00+00:00"}
    progress["enforcement"] = {"status": job_status, "result_outcome": None,
                               "created_at": "2026-01-01T00:00:00+00:00"}
    result = _stage(progress, "deployment")
    assert (result["state"], result["label"]) == (expected_state, expected_label)


def test_only_fresh_verification_can_complete_final_step():
    progress = _progress()
    progress["deployment"] = {"state": "approved", "requested_at": "2026-01-01T00:00:00+00:00"}
    progress["enforcement"] = {"status": "completed", "result_outcome": "SUCCEEDED",
                               "created_at": "2026-01-01T00:00:00+00:00"}
    assert _stage(progress, "deployment")["state"] == "complete"
    assert _stage(progress, "verification")["state"] == "waiting"
    progress["verification"] = {"outcome": "VERIFIED", "verified_at": "2026-01-01T00:01:00+00:00"}
    assert _stage(progress, "verification")["state"] == "complete"


def _web_case(tmp_path, controller_client=None):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    benchmark, _, _, _ = _assessment_for_case(repo, case)
    repo.create_user(username="admin", password="correct-admin-password", role_name="admin")
    app = create_app(M8WebSettings(database=case.database, secure_cookie=False),
                     controller_client=controller_client)
    app.testing = True
    client = app.test_client()
    _login(client, "admin", "correct-admin-password")
    return case, benchmark, client


def test_status_endpoint_requires_login_and_never_writes_or_exposes_secrets(tmp_path):
    case, benchmark, client = _web_case(tmp_path)
    url = f"/runs/status?target_id={case.enrollment.target_id}&benchmark_id={benchmark['benchmark_id']}"
    with open_db(case.database) as db:
        before = db.total_changes
        profile_count = db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    result = client.get(url)
    assert result.status_code == 200
    assert len(result.json["stages"]) == 8
    body = result.text.lower()
    assert all(term not in body for term in ("credential", "private_key", "payload_json", "auth_header"))
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == profile_count
    client.post("/logout", data={"csrf_token": _token(client)})
    assert client.get(url).status_code == 302


def test_repeated_m3_posts_reuse_existing_pending_job_and_preserve_csrf(tmp_path):
    calls = []

    class Controller:
        def create_profile_job(self, request):
            calls.append(request)
            return case.service.create_job(_admin(), request)

    case, benchmark, client = _web_case(tmp_path, Controller())
    target_id = str(case.enrollment.target_id)
    data = {"csrf_token": _token(client), "target_id": target_id,
            "benchmark_id": benchmark["benchmark_id"]}
    assert client.post("/runs/profile", data={**data, "csrf_token": "wrong"}).status_code == 400
    assert client.post("/runs/profile", data=data).status_code == 302
    assert client.post("/runs/profile", data=data).status_code == 302
    assert len(calls) == 1
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM jobs WHERE target_id=? AND status='pending'",
                          (target_id,)).fetchone()[0] == 1
    run = client.get(f"/runs?target_id={target_id}&benchmark_id={benchmark['benchmark_id']}")
    assert b"Profile collection already queued" in run.data
    assert b'action="/runs/profile"' not in run.data
    assert b"run-status.js" in run.data
    assert b"data-run-status-url" in run.data
    assert b"Historical sandbox attempts for this server" in run.data
    assert "script-src 'self'" in run.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in run.headers["Content-Security-Policy"]
    assert b"STEP 3 OF 8" in run.data
    assert run.data.index(b'id="run-active"') < run.data.index(b'id="run-completed"')
    assert run.data.index(b'id="run-evidence"') < run.data.index(b'id="run-server"')
    assert re.findall(rb'<details id="run-([a-z]+)"[^>]*\bopen\b', run.data) == [b"evidence"]
    assert b'id="run-compatibility"' not in run.data  # future steps stay in the rail
    assert b"Profile job created" in run.data
    assert b"Waiting for Agent" in run.data
    assert b"Agent received job" in run.data
    assert b"Collecting host evidence" in run.data
    assert b"Profile stored" in run.data
    assert b"data-run-relative" in run.data
    assert b"Controller records checked at" in run.data


def test_new_completed_m3_job_wins_when_controller_timestamps_tie(tmp_path):
    case, benchmark, client = _web_case(tmp_path)
    job = case.service.create_job(_admin(), JobCreateRequest(
        target_id=case.enrollment.target_id,
    ))
    polled = case.service.poll_jobs(JobPollRequest(auth=_auth(case.enrollment))).jobs
    assert any(item.job_id == job.job_id for item in polled)
    stored = case.service.submit_profile(ProfileSubmissionRequest(
        auth=_auth(case.enrollment), job_id=job.job_id, profile=_profile(),
    ))
    progress = M8ReadModel(case.database).run_progress(
        str(case.enrollment.target_id), benchmark["benchmark_id"])
    assert progress["job"]["job_id"] == str(job.job_id)
    assert progress["profile"]["profile_id"] == str(stored.profile_id)
    assert progress["report"] is None
    assert _stage(progress, "compatibility")["state"] == "action_required"
    page = client.get(f"/runs?target_id={case.enrollment.target_id}"
                      f"&benchmark_id={benchmark['benchmark_id']}")
    assert b"STEP 4 OF 8" in page.data
    assert b"Profile stored" in page.data
    assert page.data.index(b'id="run-active"') < page.data.index(b'id="run-completed"')


def test_m3_dispatched_card_shows_agent_received_and_collection_active(tmp_path):
    case, benchmark, client = _web_case(tmp_path)
    job = case.service.create_job(_admin(), JobCreateRequest(target_id=case.enrollment.target_id))
    polled = case.service.poll_jobs(JobPollRequest(auth=_auth(case.enrollment))).jobs
    assert any(item.job_id == job.job_id for item in polled)
    page = client.get(f"/runs?target_id={case.enrollment.target_id}"
                      f"&benchmark_id={benchmark['benchmark_id']}")
    assert b"STEP 3 OF 8" in page.data
    assert b"Agent is collecting host evidence" in page.data
    assert b'class="done">Agent received job' in page.data
    assert b'class="current">Collecting host evidence' in page.data


@pytest.mark.parametrize("validating", [False, True])
def test_m6_active_card_tracks_ready_and_validating_from_session(tmp_path, validating):
    database, repository, service, enrollment, ready, _ = _sandbox_sqlite_fixture(tmp_path)
    if validating:
        service.mark_validating(ready.sandbox_session_id)
    repo = M8Repository(database)
    case = SimpleNamespace(enrollment=enrollment, repository=repository,
                           profile_id=ready.source_profile_id,
                           report_id=ready.source_compatibility_report_id)
    benchmark, _, _, _ = _assessment_for_case(repo, case)
    repo.create_user(username="admin", password="correct-admin-password", role_name="admin")
    client = create_app(M8WebSettings(database=database, secure_cookie=False)).test_client()
    _login(client, "admin", "correct-admin-password")
    page = client.get(f"/runs?target_id={enrollment.target_id}"
                      f"&benchmark_id={benchmark['benchmark_id']}")
    assert b"STEP 5 OF 8" in page.data
    assert b"Sandbox validation does not modify the target server" in page.data
    assert b"Isolated VM provisioned" in page.data
    assert b"Sandbox ready" in page.data
    assert b"Running validation" in page.data
    if validating:
        assert b'class="current">Running validation' in page.data
    else:
        assert b'class="done">Sandbox ready' in page.data


def test_m7_pending_and_dispatched_cards_never_claim_applying(tmp_path):
    case, benchmark, client = _web_case(tmp_path)
    repo = M8Repository(case.database)
    progress = M8ReadModel(case.database).run_progress(
        str(case.enrollment.target_id), benchmark["benchmark_id"])
    deployment = repo.create_deployment_request(
        assessment_result_id=progress["assessment"]["assessment_result_id"],
        sandbox_session_id=case.session_id,
    )
    admin = repo.authenticate_user(username="admin", password="correct-admin-password")
    repo.record_approval(deployment_id=deployment["deployment_id"],
                         user_id=admin["user_id"], decision="approved",
                         reason="Reviewed sandbox evidence")
    job = case.service.create_enforcement_job(_admin(), _request(case))
    repo.link_enforcement_job(deployment_id=deployment["deployment_id"],
                              enforcement_job_id=job.enforcement_job_id)
    url = (f"/runs?target_id={case.enrollment.target_id}"
           f"&benchmark_id={benchmark['benchmark_id']}")
    pending = client.get(url)
    assert b"STEP 7 OF 8" in pending.data
    assert b"Waiting for target Agent" in pending.data
    assert b'class="current">Waiting for Agent' in pending.data
    assert b"Applying" not in pending.data
    assert pending.data.index(b'id="run-active"') < pending.data.index(b'id="run-completed"')
    case.service.poll_jobs(JobPollRequest(auth=_auth(case.enrollment)))
    dispatched = client.get(url)
    assert b"Enforcement job assigned to Agent" in dispatched.data
    assert b"assigned to the enrolled Agent" in dispatched.data
    assert b"Applying" not in dispatched.data


def test_parallel_m8_profile_posts_share_one_controller_job(tmp_path):
    calls = []

    class Controller:
        def create_profile_job(self, request):
            calls.append(request)
            return case.service.create_job(_admin(), request)

    controller = Controller()
    case, benchmark, client_a = _web_case(tmp_path, controller)
    app_b = create_app(M8WebSettings(database=case.database, secure_cookie=False),
                       controller_client=controller)
    client_b = app_b.test_client()
    _login(client_b, "admin", "correct-admin-password")
    barrier = Barrier(2)

    def submit(client):
        form = {"csrf_token": _token(client),
                "target_id": str(case.enrollment.target_id),
                "benchmark_id": benchmark["benchmark_id"]}
        barrier.wait()
        return client.post("/runs/profile", data=form).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(submit, (client_a, client_b)))
    assert statuses == [302, 302]
    assert len(calls) == 1
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM jobs WHERE target_id=? AND status='pending'",
                          (str(case.enrollment.target_id),)).fetchone()[0] == 1


def test_profile_action_rejects_symlink_lock_without_creating_job(tmp_path):
    case, benchmark, client = _web_case(tmp_path)
    lock_path = case.database.with_name(case.database.name + ".m8-profile.lock")
    os.symlink(case.database, lock_path)
    response = client.post("/runs/profile", data={
        "csrf_token": _token(client), "target_id": str(case.enrollment.target_id),
        "benchmark_id": benchmark["benchmark_id"],
    })
    assert response.status_code == 503
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM jobs WHERE status='pending'").fetchone()[0] == 0


def test_status_endpoint_and_run_page_never_create_m7_job(tmp_path):
    case, benchmark, client = _web_case(tmp_path)
    url = f"/runs?target_id={case.enrollment.target_id}&benchmark_id={benchmark['benchmark_id']}"
    assert client.get(url).status_code == 200
    assert client.get(url.replace("/runs?", "/runs/status?")).status_code == 200
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0] == 0


def test_failed_sandbox_reason_and_history_remain_visible_on_run_page(tmp_path):
    database, repository, service, enrollment, ready, _ = _sandbox_sqlite_fixture(tmp_path)
    service.mark_failed(ready.sandbox_session_id, failure_reason="provisioning_failed")
    repo = M8Repository(database)
    case = SimpleNamespace(
        enrollment=enrollment, repository=repository,
        profile_id=ready.source_profile_id,
        report_id=ready.source_compatibility_report_id,
    )
    benchmark, _, _, _ = _assessment_for_case(repo, case)
    repo.create_user(username="admin", password="correct-admin-password", role_name="admin")
    client = create_app(M8WebSettings(database=database, secure_cookie=False)).test_client()
    _login(client, "admin", "correct-admin-password")
    response = client.get(f"/runs?target_id={enrollment.target_id}"
                          f"&benchmark_id={benchmark['benchmark_id']}")
    assert response.status_code == 200
    assert b"Failed sandbox attempt" in response.data
    assert b"provisioning_failed" in response.data
    assert b"All sandbox attempts" in response.data
    assert b"Request approval" not in response.data


def test_approval_page_requires_separate_explicit_deployment_action(tmp_path):
    case, benchmark, client = _web_case(tmp_path)
    repo = M8Repository(case.database)
    progress = M8ReadModel(case.database).run_progress(
        str(case.enrollment.target_id), benchmark["benchmark_id"])
    deployment = repo.create_deployment_request(
        assessment_result_id=progress["assessment"]["assessment_result_id"],
        sandbox_session_id=case.session_id,
    )
    admin = repo.authenticate_user(username="admin", password="correct-admin-password")
    repo.record_approval(deployment_id=deployment["deployment_id"],
                         user_id=admin["user_id"], decision="approved",
                         reason="Reviewed evidence before separate enforcement")
    response = client.get(f"/runs?target_id={case.enrollment.target_id}"
                          f"&benchmark_id={benchmark['benchmark_id']}")
    assert response.status_code == 200
    assert b"Start Controlled Deployment" in response.data
    assert b"Reviewed evidence before separate enforcement" in response.data
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0] == 0


def test_fresh_post_enforcement_profile_preserves_original_run_and_verified_result(tmp_path):
    case, _, _, _, submission = _terminal(tmp_path)
    result = case.service.submit_enforcement_result(submission)
    fresh = _complete_reprofile(case, result)
    repo = M8Repository(case.database)
    benchmark, _, assessment_result, _ = _assessment_for_case(repo, case)
    admin = repo.create_user(username="admin", password="correct-admin-password",
                             role_name="admin")
    deployment = repo.create_deployment_request(
        assessment_result_id=assessment_result["assessment_result_id"],
        sandbox_session_id=case.session_id, requested_by_user_id=admin["user_id"],
    )
    repo.record_approval(deployment_id=deployment["deployment_id"],
                         user_id=admin["user_id"], decision="approved",
                         reason="Reviewed exact source evidence")
    repo.link_enforcement_job(deployment_id=deployment["deployment_id"],
                              enforcement_job_id=result.enforcement_job_id,
                              initiated_by_user_id=admin["user_id"])
    progress = M8ReadModel(case.database).run_progress(
        str(case.enrollment.target_id), benchmark["benchmark_id"])
    assert progress["profile"]["profile_id"] == str(case.profile_id)
    assert progress["verification"]["profile_id"] == str(fresh.profile_id)
    assert _stage(progress, "verification")["label"] == "Selected control verified"
    client = create_app(M8WebSettings(database=case.database, secure_cookie=False)).test_client()
    _login(client, "admin", "correct-admin-password")
    page = client.get(f"/runs?target_id={case.enrollment.target_id}"
                      f"&benchmark_id={benchmark['benchmark_id']}")
    assert page.status_code == 200
    assert b"Selected control verified" in page.data
    assert b"Fresh target verification: VERIFIED" in page.data
    assert b"Target was already in the required state; no unnecessary change was made." in page.data
    assert str(fresh.profile_id).encode() in page.data
    assert b"STEP 8 OF 8" in page.data
    assert b'class="run-final-wordmark">VERIFIED' in page.data
    assert b"Post-enforcement verification VERIFIED" in page.data
    assert b"View Evidence" in page.data and b"View Operational Timeline" in page.data
    assert page.data.index(b'id="run-active"') < page.data.index(b'id="run-completed"')


def test_run_presentation_uses_self_script_and_reduced_motion(tmp_path):
    case, benchmark, client = _web_case(tmp_path)
    page = client.get(f"/runs?target_id={case.enrollment.target_id}"
                      f"&benchmark_id={benchmark['benchmark_id']}")
    assert page.status_code == 200
    assert b"data-run-relative" in page.data
    assert b"Controller records checked at" in page.data
    assert b"Ubuntu 24.04" in page.data
    assert b'<script src="/static/run-status.js" defer></script>' in page.data
    csp = page.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    stylesheet = client.get("/static/sentra.css")
    assert b"prefers-reduced-motion: reduce" in stylesheet.data
    assert b".run-rail-step.is-current.state-waiting" in stylesheet.data
