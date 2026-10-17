"""Final M8 controls: explicit run lineage and presentation-only conveniences."""

from pathlib import Path
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from src.controller.models import JobRecord, JobStatus
from src.m8db.migrations import (
    _migrations, _statements, apply_migrations, check_db, open_db,
)
from src.m8db.repository import M8DataError, M8Repository
from src.m8web.read_model import M8ReadModel
from src.m8web.config import M8WebSettings
from src.m8web.app import create_app

from test_m6_validation import _admin
from test_m7_enforcement import _case, _request
from test_m8db import _assessment_for_case
from test_m8_product import _app, _login, _token


def _populated(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    benchmark, assessment, _, _ = _assessment_for_case(repo, case)
    admin = repo.create_user(
        username="admin", password="correct-admin-password", role_name="admin",
    )
    repo.create_user(
        username="viewer", password="correct-viewer-password", role_name="viewer",
    )
    return case, repo, benchmark, assessment, admin


def test_new_run_post_is_explicit_idempotent_and_never_inherits_old_lineage(tmp_path):
    case, repo, benchmark, old, admin = _populated(tmp_path)
    client = _app(case.database).test_client()
    _login(client, "admin", "correct-admin-password")
    target, benchmark_id = str(case.enrollment.target_id), benchmark["benchmark_id"]
    request_id = str(uuid4())
    form = {"csrf_token": _token(client), "run_id": request_id,
            "target_id": target, "benchmark_id": benchmark_id}
    with open_db(case.database) as db:
        before = {table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in ("profiles", "compatibility_reports", "sandbox_sessions",
                                "m8_assessments", "m8_approvals", "enforcement_jobs")}
    assert client.get("/runs/new").status_code == 200
    assert client.get("/runs/new?target_id=" + target + "&benchmark_id=" + benchmark_id).status_code == 200
    assert client.get("/runs/new", query_string=form).status_code == 200
    assert client.post("/runs/new", data={**form, "csrf_token": "bad"}).status_code == 400
    assert client.post("/runs/new", data=form).status_code == 302
    assert client.post("/runs/new", data=form).status_code == 302
    run_page = client.get("/runs", query_string={
        "target_id": target, "benchmark_id": benchmark_id, "run_id": request_id,
    })
    assert run_page.status_code == 200
    assert b"Fresh host evidence is required for this run" in run_page.data
    assert str(case.report_id).encode() not in run_page.data
    assert (b'name="session_id" value="' + str(case.session_id).encode()) not in run_page.data
    progress = M8ReadModel(case.database).run_progress(target, benchmark_id, request_id)
    assert progress["run_start"]["run_id"] == request_id
    assert all(progress[key] is None for key in (
        "job", "profile", "report", "assessment", "session", "validation",
        "deployment", "enforcement", "verification",
    ))
    assert progress["run_start"]["selected_controls_json"] == '["7.1.1"]'
    old_progress = M8ReadModel(case.database).run_progress(
        target, benchmark_id, old["assessment_id"],
    )
    assert old_progress["profile"] is not None
    assert old_progress["report"] is not None
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_run_starts").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM m8_audit_events WHERE "
                          "event_type='hardening_run_started' AND actor_user_id=?",
                          (admin["user_id"],)).fetchone()[0] == 1
        assert before == {table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                          for table in before}
    assert check_db(case.database)["ok"]


def test_run_profile_job_cannot_rebind_old_evidence_and_history_is_read_only(tmp_path):
    case, repo, benchmark, old, admin = _populated(tmp_path)
    target, benchmark_id = str(case.enrollment.target_id), benchmark["benchmark_id"]
    run = repo.start_hardening_run(run_id=uuid4(), target_id=target,
                                   benchmark_id=benchmark_id,
                                   initiated_by_user_id=admin["user_id"])
    with open_db(case.database) as db:
        old_job = db.execute("SELECT job_id FROM profiles WHERE profile_id=?",
                             (str(case.profile_id),)).fetchone()[0]
    with pytest.raises(M8DataError):
        repo.link_run_profile_job(run_id=run["run_id"], target_id=target, job_id=old_job)
    new_job = case.repository.create_job(JobRecord(
        job_id=uuid4(), target_id=case.enrollment.target_id,
        status=JobStatus.PENDING, created_at=datetime.now(UTC),
    ))
    repo.link_run_profile_job(run_id=run["run_id"], target_id=target, job_id=new_job.job_id)
    repo.link_run_profile_job(run_id=run["run_id"], target_id=target, job_id=new_job.job_id)
    progress = M8ReadModel(case.database).run_progress(target, benchmark_id, run["run_id"])
    assert progress["job"]["job_id"] == str(new_job.job_id)
    assert progress["profile"] is None and progress["report"] is None
    with pytest.raises(M8DataError):
        repo.record_compatibility_assessment(
            target_id=target, profile_id=case.profile_id,
            benchmark_id=benchmark_id, compatibility_report_id=case.report_id,
            initiated_by_user_id=admin["user_id"], run_id=run["run_id"],
        )
    client = _app(case.database).test_client()
    _login(client, "viewer", "correct-viewer-password")
    assert client.get("/runs/history").status_code == 200
    assert client.get(f"/runs/history/{run['run_id']}").status_code == 200
    assert client.get(f"/runs/history/{old['assessment_id']}").status_code == 200
    assert client.post("/runs/new", data={"csrf_token": _token(client),
        "run_id": str(uuid4()), "target_id": target, "benchmark_id": benchmark_id}).status_code == 403
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_run_starts").fetchone()[0] == 1


def test_theme_agent_guidance_and_source_first_evidence_keep_security_boundaries(tmp_path):
    case, repo, benchmark, _, _ = _populated(tmp_path)
    client = _app(case.database).test_client()
    _login(client, "admin", "correct-admin-password")
    overview = client.get("/")
    assert b'aria-label="Appearance"' in overview.data
    assert b'value="system"' in overview.data
    assert b'value="light"' in overview.data
    assert b'value="dark"' in overview.data
    assert b'<script src="/static/theme.js"></script>' in overview.data
    assert "script-src 'self'" in overview.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in overview.headers["Content-Security-Policy"]
    theme = client.get("/static/theme.js").data
    assert b"window.localStorage" in theme and b"systemDark.addEventListener" in theme
    assert b"document.documentElement.dataset.theme" in theme
    assert b"fetch(" not in theme
    css = client.get("/static/sentra.css").data
    assert b':root[data-theme="dark"]' in css
    assert b"prefers-reduced-motion: reduce" in css
    onboarding = client.get("/targets/new")
    assert onboarding.status_code == 200
    for expected in (b"/opt/sentra/.venv", b"/etc/sentra/controller-ca.pem",
                     b"/var/lib/sentra/agent/state.json",
                     b"--bootstrap-credential-file", b"sudo rm -f /etc/sentra/bootstrap.credential",
                     b"one-cycle program", b"Never copy the Controller private key"):
        assert expected in onboarding.data
    assert onboarding.data.count(b"--bootstrap-credential-file") == 1
    assert b"--insecure" not in onboarding.data
    assert b"sudo ssh " not in onboarding.data.lower()
    targets = client.get("/targets").data
    target_detail = client.get(f"/targets/{case.enrollment.target_id}").data
    for page in (targets, target_detail):
        assert b"No heartbeat timestamp recorded" in page
        assert b"Never contacted" not in page
        assert b"Online" not in page
    evidence = client.get("/evidence").data
    assert b"Authoritative source" in evidence and b"Host Evidence" in evidence
    assert b"Sandbox Evidence" in evidence and b"M8 Evidence References" in evidence
    assert b"Authoritative evidence remains" in evidence
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_run_starts").fetchone()[0] == 0


def test_viewer_cannot_access_agent_onboarding_and_timeline_filters_do_not_write(tmp_path):
    case, _, _, _, _ = _populated(tmp_path)
    client = _app(case.database).test_client()
    _login(client, "viewer", "correct-viewer-password")
    assert client.get("/targets/new").status_code == 403
    with open_db(case.database) as db:
        before = db.execute("SELECT COUNT(*) FROM m8_audit_events").fetchone()[0]
    for filter_name in ("all", "workflow", "administrator", "authentication", "failures"):
        page = client.get("/audit", query_string={"filter": filter_name})
        assert page.status_code == 200
        assert b"Timeline filters" in page.data
    assert client.get("/audit?filter=made-up").status_code == 400
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_audit_events").fetchone()[0] == before


def test_failure_timeline_filter_includes_a_recorded_rejection(tmp_path):
    case, repo, _, _, admin = _populated(tmp_path)
    with open_db(case.database) as db:
        result_id = db.execute(
            "SELECT assessment_result_id FROM m8_assessment_results "
            "WHERE target_id=?", (str(case.enrollment.target_id),)
        ).fetchone()[0]
    request = repo.create_deployment_request(
        assessment_result_id=result_id, sandbox_session_id=case.session_id,
        requested_by_user_id=admin["user_id"],
    )
    repo.record_approval(
        deployment_id=request["deployment_id"], user_id=admin["user_id"],
        decision="rejected", reason="Reviewed evidence did not warrant deployment",
    )
    client = _app(case.database).test_client()
    _login(client, "admin", "correct-admin-password")
    page = client.get("/audit?filter=failures")
    assert page.status_code == 200
    assert b"Deployment Rejected" in page.data
    assert b"admin" in page.data


def test_new_run_profile_button_uses_controller_job_and_deduplicates_retries(tmp_path):
    case, repo, benchmark, _, admin = _populated(tmp_path)
    target, benchmark_id = str(case.enrollment.target_id), benchmark["benchmark_id"]
    run = repo.start_hardening_run(run_id=uuid4(), target_id=target,
                                   benchmark_id=benchmark_id,
                                   initiated_by_user_id=admin["user_id"])

    class FixedControllerClient:
        def __init__(self):
            self.calls = 0

        def create_profile_job(self, request):
            self.calls += 1
            assert str(request.target_id) == target
            return case.repository.create_job(JobRecord(
                job_id=uuid4(), target_id=request.target_id,
                status=JobStatus.PENDING, created_at=datetime.now(UTC),
            ))

    controller = FixedControllerClient()
    client = create_app(M8WebSettings(database=case.database, secure_cookie=False),
                        controller_client=controller).test_client()
    _login(client, "admin", "correct-admin-password")
    form = {"csrf_token": _token(client), "target_id": target,
            "benchmark_id": benchmark_id, "run_id": run["run_id"]}
    assert client.post("/runs/profile", data={**form, "csrf_token": "bad"}).status_code == 400
    assert client.post("/runs/profile", data=form).status_code == 302
    assert client.post("/runs/profile", data=form).status_code == 302
    assert controller.calls == 1
    progress = M8ReadModel(case.database).run_progress(target, benchmark_id, run["run_id"])
    assert progress["job"] is not None
    assert progress["profile"] is None and progress["report"] is None
    assert progress["session"] is None and progress["verification"] is None
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_audit_events WHERE "
                          "event_type='profile_collection_requested' AND actor_user_id=?",
                          (admin["user_id"],)).fetchone()[0] == 1


def test_active_old_m7_job_blocks_new_deployment_gate_without_cancelling_it(tmp_path):
    case, repo, benchmark, _, admin = _populated(tmp_path)
    with open_db(case.database) as db:
        result_id = db.execute("SELECT assessment_result_id FROM m8_assessment_results "
                               "WHERE target_id=?", (str(case.enrollment.target_id),)).fetchone()[0]
    request = repo.create_deployment_request(
        assessment_result_id=result_id, sandbox_session_id=case.session_id,
        requested_by_user_id=admin["user_id"],
    )
    repo.record_approval(deployment_id=request["deployment_id"],
                         user_id=admin["user_id"], decision="approved",
                         reason="Reviewed validated sandbox evidence")
    active = case.service.create_enforcement_job(_admin(), _request(case))
    assert active.status is JobStatus.PENDING
    with pytest.raises(M8DataError, match="another enforcement job"):
        repo.approved_deployment_lineage(request["deployment_id"])
    second = repo.record_compatibility_assessment(
        target_id=case.enrollment.target_id, profile_id=case.profile_id,
        benchmark_id=benchmark["benchmark_id"],
        compatibility_report_id=case.report_id,
        initiated_by_user_id=admin["user_id"],
    )
    with open_db(case.database) as db:
        second_result_id = db.execute(
            "SELECT assessment_result_id FROM m8_assessment_results "
            "WHERE assessment_id=?", (second["assessment_id"],)
        ).fetchone()[0]
    with pytest.raises(M8DataError, match="an enforcement job is active"):
        repo.create_deployment_request(
            assessment_result_id=second_result_id,
            sandbox_session_id=case.session_id,
            requested_by_user_id=admin["user_id"],
        )
    assert M8ReadModel(case.database).deployments()["eligible"] == []
    run = repo.start_hardening_run(run_id=uuid4(),
                                   target_id=case.enrollment.target_id,
                                   benchmark_id=benchmark["benchmark_id"],
                                   initiated_by_user_id=admin["user_id"])
    progress = M8ReadModel(case.database).run_progress(
        str(case.enrollment.target_id), benchmark["benchmark_id"], run["run_id"],
    )
    assert progress["conflicting_m7"]["enforcement_job_id"] == str(active.enforcement_job_id)
    assert progress["profile"] is None and progress["enforcement"] is None


def test_additive_run_migration_upgrades_existing_v2_database_without_rewriting_rows(tmp_path):
    database = tmp_path / "controller.sqlite3"
    migrations = _migrations()
    with open_db(database) as db:
        for version, name, sql, digest in migrations[:2]:
            for statement in _statements(sql):
                db.execute(statement)
            db.execute("INSERT INTO m8_schema_migrations "
                       "(version,name,checksum,applied_at) VALUES (?,?,?,?)",
                       (version, name, digest, datetime.now(UTC).isoformat()))
        db.execute("INSERT INTO m8_users (user_id,username,password_hash,active,created_at,"
                   "updated_at) VALUES (?,?,?,?,?,?)", (
                       str(uuid4()), "legacy", "scrypt$" + "a" * 80, 1,
                       datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat()))
    assert apply_migrations(database) == [3]
    assert apply_migrations(database) == []
    with open_db(database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_users WHERE username='legacy'").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM m8_run_starts").fetchone()[0] == 0
    assert check_db(database)["ok"]
