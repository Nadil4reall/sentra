"""Overview presentation uses existing Controller records and run projection."""

from __future__ import annotations

from html.parser import HTMLParser

from flask import render_template

from src.m8db.migrations import apply_migrations
from src.m8db.repository import M8Repository
from src.m8web.read_model import M8ReadModel

from test_m7_enforcement import _case
from test_m7_enforcement_result import _complete_reprofile, _terminal
from test_m8_product import _app, _empty, _login
from test_m8db import _assessment_for_case, _benchmark


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, value):
        self.parts.append(value)


def _text(markup: bytes) -> str:
    parser = _VisibleText()
    parser.feed(markup.decode())
    return " ".join(parser.parts)


def _client(database):
    client = _app(database).test_client()
    assert _login(client, "admin", "correct-admin-password").status_code == 302
    return client


def test_new_install_has_guided_setup_and_no_empty_metrics(tmp_path):
    database, _, _, _ = _empty(tmp_path)
    page = _client(database).get("/")
    assert page.status_code == 200
    body = _text(page.data)
    assert "SENTRA" in body and "Start Hardening Run" in body
    assert "Setup required" in body
    assert "Controller records available" in body
    assert "No enrolled server" in body and "No active supported benchmark" in body
    assert "Add your first server" in body and "Add a CIS benchmark" in body
    assert "Waiting for prerequisites" in body
    assert "No hardening run yet" in body
    assert "System summary" not in body
    assert "Agent connectivity and sandbox health have not been checked" in body


def test_target_without_benchmark_and_benchmark_without_target(tmp_path):
    case = _case(tmp_path / "target")
    apply_migrations(case.database)
    M8Repository(case.database).create_user(
        username="admin", password="correct-admin-password", role_name="admin")
    target_body = _text(_client(case.database).get("/").data)
    assert "Setup required" in target_body and "1 enrolled server" in target_body
    assert "No active supported benchmark" in target_body
    assert "✓ Server enrolled" in target_body
    assert "Import Benchmark" in target_body
    assert "System summary" not in target_body

    database, repo, _, _ = _empty(tmp_path / "benchmark")
    benchmark = _benchmark(repo)
    repo.activate_benchmark(benchmark["benchmark_id"])
    benchmark_body = _text(_client(database).get("/").data)
    assert "Setup required" in benchmark_body and "No enrolled server" in benchmark_body
    assert "Supported benchmark active" in benchmark_body
    assert "Add Server" in benchmark_body
    assert "System summary" not in benchmark_body


def test_ready_environment_and_current_run_use_authoritative_stage(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    benchmark, _, _, _ = _assessment_for_case(repo, case)
    repo.create_user(username="admin", password="correct-admin-password",
                     role_name="admin")
    snapshot = M8ReadModel(case.database).dashboard()
    assert snapshot["readiness"]["ready"] is True
    assert snapshot["run"]["kind"] == "current"
    assert snapshot["run"]["benchmark_id"] == benchmark["benchmark_id"]
    body = _text(_client(case.database).get("/").data)
    assert "Ready to start" in body
    assert "Current hardening run" in body and "Continue Hardening Run" in body
    assert snapshot["run"]["stage"]["label"] in body
    assert "Servers" in body and "Enrolled targets" in body
    assert "Host evidence" in body and "M3 profile snapshots" in body
    assert "Compatibility reviews" in body and "M4 reports" in body
    assert "Deployment decisions" in body and "Verified outcomes" in body
    assert "VERIFIED" not in body
    assert "Sandbox validation does not modify the target server" in body
    assert "Final verification uses fresh evidence from the real target" in body
    primary = _text(_client(case.database).get("/").data)
    assert str(case.enrollment.target_id) not in primary
    assert str(case.profile_id) not in primary
    assert "credential" not in primary.lower()


def test_verified_summary_requires_fresh_authoritative_verification(tmp_path):
    case, _, _, _, submission = _terminal(tmp_path)
    result = case.service.submit_enforcement_result(submission)
    repo = M8Repository(case.database)
    benchmark, _, assessment_result, _ = _assessment_for_case(repo, case)
    admin = repo.create_user(username="admin", password="correct-admin-password",
                             role_name="admin")
    deployment = repo.create_deployment_request(
        assessment_result_id=assessment_result["assessment_result_id"],
        sandbox_session_id=case.session_id, requested_by_user_id=admin["user_id"])
    repo.record_approval(deployment_id=deployment["deployment_id"],
                         user_id=admin["user_id"], decision="approved",
                         reason="Reviewed exact sandbox evidence")
    repo.link_enforcement_job(deployment_id=deployment["deployment_id"],
                              enforcement_job_id=result.enforcement_job_id,
                              initiated_by_user_id=admin["user_id"])
    before = M8ReadModel(case.database).dashboard()
    assert before["run"]["kind"] == "current"
    assert "VERIFIED" not in _text(_client(case.database).get("/").data)
    fresh = _complete_reprofile(case, result)
    after = M8ReadModel(case.database).dashboard()
    assert after["run"]["kind"] == "verified"
    assert after["run"]["target_id"] == str(case.enrollment.target_id)
    assert after["run"]["control_id"] == "7.1.1"
    page = _client(case.database).get("/")
    body = _text(page.data)
    assert "Last completed run" in body and "VERIFIED" in body
    assert "View Result" in body
    assert str(fresh.profile_id) not in body
    assert "Continue Hardening Run" not in body
    assert benchmark["benchmark_id"] not in body


def test_recent_activity_is_bounded_and_does_not_change_audit(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    _assessment_for_case(repo, case)
    repo.create_user(username="admin", password="correct-admin-password",
                     role_name="admin")
    client = _client(case.database)
    for _ in range(7):
        assert _login(client, "admin", "correct-admin-password").status_code == 302
    before = M8ReadModel(case.database).audit()
    page = client.get("/")
    after = M8ReadModel(case.database).audit()
    assert len(before) == len(after)
    assert before == after
    snapshot = M8ReadModel(case.database).dashboard()
    assert len(snapshot["activity"]) <= 5
    assert all(event["event_type"] not in {
        "login_succeeded", "logout_succeeded", "sandbox_provisioning_started",
        "sandbox_ready", "sandbox_validation_started",
    } for event in snapshot["activity"])
    assert b"View Operational Timeline" in page.data
    assert page.data.count(b'class="overview-activity"') == 1
    assert page.data.count(b'<li><div><strong>') <= 5


def test_no_known_conflict_is_explained_without_compliance_translation(tmp_path):
    database, _, _, _ = _empty(tmp_path)
    app = _app(database)
    snapshot = M8ReadModel(database).dashboard()
    snapshot["selected_controls"] = [{
        "control_id": "7.1.1", "title": "Ensure permissions on /etc/passwd are configured",
        "assessment_state": "not_tested", "compatibility_decision": "no_known_conflict",
    }]
    with app.test_request_context("/"):
        rendered = render_template("dashboard.html", snapshot=snapshot)
    assert "Assessment</dt><dd>Not Tested" in rendered
    assert "Compatibility</dt><dd>No Known Conflict" in rendered
    assert "It is not a compliance or safety verdict" in rendered
    assert "Compatibility</dt><dd>Pass" not in rendered
    assert "Compatibility</dt><dd>Safe" not in rendered


def test_overview_shows_bounded_selected_control_subset(tmp_path):
    database, repo, _, _ = _empty(tmp_path)
    benchmark = _benchmark(repo)
    for number in range(1, 7):
        repo.create_control(
            benchmark_id=benchmark["benchmark_id"],
            control_id=f"7.1.{number}", title=f"Selected control {number}",
            required_facts=["passwd_file_mode"], adapter_capability="audit_plan_only",
        )
    snapshot = M8ReadModel(database).dashboard()
    assert len(snapshot["selected_controls"]) == 4
    page = _client(database).get("/")
    assert page.status_code == 200
    assert b"View all controls" in page.data
    assert b"Selected control 6" not in page.data


def test_overview_preserves_auth_csp_and_reduced_motion(tmp_path):
    database, _, _, _ = _empty(tmp_path)
    client = _app(database).test_client()
    assert client.get("/").status_code == 302
    _login(client, "viewer", "correct-viewer-password")
    page = client.get("/")
    assert page.status_code == 200
    assert "script-src 'self'" in page.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in page.headers["Content-Security-Policy"]
    assert b"<script" not in page.data
    assert b"How SENTRA works" in page.data
    stylesheet = client.get("/static/sentra.css").data
    assert b"prefers-reduced-motion: reduce" in stylesheet
