"""M8 web product tests use the canonical disposable Controller database."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import sys
from uuid import uuid4

import pytest

from src.m8db.migrations import apply_migrations, open_db
from src.m8db.repository import M8Repository
from src.m8web import M8WebConfigurationError, M8WebSettings, create_app
from src.m8web.__main__ import main as web_main
from src.m8web.read_model import M8ReadModel
from src.m8web.users import main as users_main

from test_m7_enforcement import _case
from test_m7_enforcement_result import _complete_reprofile, _terminal
from test_m6_validation import _sandbox_sqlite_fixture
from test_m8db import _assessment_for_case


def _app(database: Path):
    app = create_app(M8WebSettings(database=database, secure_cookie=False))
    app.config["TESTING"] = True
    return app


def _login(client, username: str, password: str):
    client.get("/login")
    with client.session_transaction() as session:
        token = session["_csrf"]
    return client.post("/login", data={
        "csrf_token": token, "username": username, "password": password,
    })


def _token(client):
    with client.session_transaction() as session:
        return session["_csrf"]


def _empty(tmp_path: Path):
    database = tmp_path / "controller.sqlite3"
    apply_migrations(database)
    repo = M8Repository(database)
    admin = repo.create_user(username="admin", password="correct-admin-password")
    repo.assign_role(user_id=admin["user_id"], role_name="admin")
    viewer = repo.create_user(username="viewer", password="correct-viewer-password")
    repo.assign_role(user_id=viewer["user_id"], role_name="viewer")
    return database, repo, admin, viewer


def test_login_logout_anonymous_and_empty_dashboard(tmp_path):
    database, _, _, _ = _empty(tmp_path)
    client = _app(database).test_client()
    assert client.get("/").status_code == 302
    assert client.get("/login").status_code == 200
    assert client.post("/login", data={"username": "admin", "password": "x"}).status_code == 400
    assert _login(client, "unknown", "correct-admin-password").status_code == 200
    failed = _login(client, "admin", "wrong-password")
    assert failed.status_code == 200
    assert b"Invalid username or password" in failed.data
    assert _login(client, "admin", "correct-admin-password").status_code == 302
    overview = client.get("/")
    assert overview.status_code == 200
    assert b"No operational activity" not in overview.data  # login audit is real activity
    assert b"Welcome to SENTRA" in overview.data
    assert b"System summary" not in overview.data
    assert client.get("/targets").status_code == 200
    assert b"No targets are enrolled" in client.get("/targets").data
    assert client.post("/logout", data={"csrf_token": _token(client)}).status_code == 302
    assert client.get("/").status_code == 302
    events = M8ReadModel(database).audit()
    user_events = [event for event in events if event["event_type"] in {
        "login_succeeded", "logout_succeeded",
    }]
    assert [event["event_type"] for event in reversed(user_events)] == [
        "login_succeeded", "logout_succeeded",
    ]
    assert all(event["actor_name"] == "admin" for event in user_events)
    assert all(event["actor_user_id"] is not None for event in user_events)


def test_login_requires_valid_csrf_and_inactive_user_cannot_continue(tmp_path):
    database, _, admin, _ = _empty(tmp_path)
    client = _app(database).test_client()
    client.get("/login")
    assert client.post("/login", data={"csrf_token": "bad", "username": "admin",
                                       "password": "correct-admin-password"}).status_code == 400
    assert _login(client, "admin", "correct-admin-password").status_code == 302
    with open_db(database) as db:
        db.execute("UPDATE m8_users SET active = 0 WHERE user_id = ?", (admin["user_id"],))
    assert client.get("/targets").status_code == 302
    assert _login(client, "admin", "correct-admin-password").status_code == 200


def test_roles_and_posts_are_explicitly_bounded(tmp_path):
    database, _, _, _ = _empty(tmp_path)
    client = _app(database).test_client()
    assert _login(client, "viewer", "correct-viewer-password").status_code == 302
    assert client.get("/deployments").status_code == 200
    fake = str(uuid4())
    form = {"csrf_token": _token(client), "assessment_result_id": fake,
            "sandbox_session_id": fake}
    assert client.post("/deployments/request", data=form).status_code == 403
    assert client.post(f"/deployments/{fake}/decision", data={
        "csrf_token": _token(client), "decision": "approved", "reason": "x",
    }).status_code == 403
    assert client.get("/deployments/request").status_code == 405
    with open_db(database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_deployment_requests").fetchone()[0] == 0


def test_populated_pages_use_real_lineage_and_do_not_expose_credentials(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    _, _, result, _ = _assessment_for_case(repo, case)
    admin = repo.create_user(username="admin", password="correct-admin-password")
    repo.assign_role(user_id=admin["user_id"], role_name="admin")
    client = _app(case.database).test_client()
    assert _login(client, "admin", "correct-admin-password").status_code == 302
    for path in ("/", "/targets", f"/targets/{case.enrollment.target_id}",
                 f"/targets/{case.enrollment.target_id}/controls/7.1.1",
                 "/controls", "/compatibility", "/sandboxes",
                 "/deployments", "/evidence", "/audit"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert b"correct-admin-password" not in response.data
        assert b"credential_hash" not in response.data
    assert b"review_required" in client.get("/compatibility").data
    assert b"provisional" in client.get("/compatibility").data
    assert str(result["assessment_result_id"]).encode() in client.get("/deployments").data
    assert client.get(f"/targets/{uuid4()}").status_code == 404


def test_admin_request_and_approval_do_not_create_m7_job(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    _, _, result, _ = _assessment_for_case(repo, case)
    admin = repo.create_user(username="admin", password="correct-admin-password")
    repo.assign_role(user_id=admin["user_id"], role_name="admin")
    client = _app(case.database).test_client()
    _login(client, "admin", "correct-admin-password")
    with open_db(case.database) as db:
        jobs_before = db.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0]
    good = {"csrf_token": _token(client),
            "assessment_result_id": result["assessment_result_id"],
            "sandbox_session_id": str(case.session_id)}
    assert client.post("/deployments/request", data={**good, "command": "id"}).status_code == 400
    assert client.post("/deployments/request", data={**good, "csrf_token": "bad"}).status_code == 400
    assert client.post("/deployments/request", data={**good, "sandbox_session_id": str(uuid4())}).status_code == 400
    response = client.post("/deployments/request", data=good)
    assert response.status_code == 302
    with open_db(case.database) as db:
        deployment_id = db.execute("SELECT deployment_id FROM m8_deployment_requests").fetchone()[0]
        assert db.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0] == jobs_before
    decision = {"csrf_token": _token(client), "decision": "approved",
                "reason": "Reviewed validation lineage"}
    assert client.post(f"/deployments/{deployment_id}/decision", data=decision).status_code == 302
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0] == jobs_before
        assert db.execute("SELECT COUNT(*) FROM m8_approvals").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM m8_audit_events WHERE event_type = 'deployment_requested'").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM m8_audit_events WHERE event_type = 'deployment_approved'").fetchone()[0] == 1
    assert b"Awaiting separate Controller action" in client.get("/deployments").data
    page = client.get("/deployments").data
    assert f"By admin ({admin['user_id']})".encode() in page
    assert b"Reason: Reviewed validation lineage" in page
    timeline = M8ReadModel(case.database).audit()
    for event_type in ("deployment_requested", "deployment_approved"):
        matching = [event for event in timeline if event["event_type"] == event_type]
        assert len(matching) == 1
        assert matching[0]["actor_name"] == "admin"
        assert matching[0]["actor_user_id"] == admin["user_id"]


def test_rejected_request_shows_reviewer_reason_without_m7_job(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    _, _, result, _ = _assessment_for_case(repo, case)
    admin = repo.create_user(
        username="reviewer", password="correct-admin-password", role_name="admin",
    )
    client = _app(case.database).test_client()
    _login(client, "reviewer", "correct-admin-password")
    assert client.post("/deployments/request", data={
        "csrf_token": _token(client),
        "assessment_result_id": result["assessment_result_id"],
        "sandbox_session_id": str(case.session_id),
    }).status_code == 302
    with open_db(case.database) as db:
        deployment_id = db.execute(
            "SELECT deployment_id FROM m8_deployment_requests"
        ).fetchone()[0]
        jobs_before = db.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0]
    assert client.post(f"/deployments/{deployment_id}/decision", data={
        "csrf_token": _token(client), "decision": "rejected",
        "reason": "Source state needs further review",
    }).status_code == 302
    page = client.get("/deployments").data
    assert f"By reviewer ({admin['user_id']})".encode() in page
    assert b"Reason: Source state needs further review" in page
    timeline = M8ReadModel(case.database).audit()
    rejected = [event for event in timeline if event["event_type"] == "deployment_rejected"]
    assert len(rejected) == 1 and rejected[0]["actor_name"] == "reviewer"
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0] == jobs_before


def test_operational_timeline_projects_real_m6_m7_and_fresh_verification(tmp_path):
    case, _, _, _, submission = _terminal(tmp_path)
    result = case.service.submit_enforcement_result(submission)
    verification = _complete_reprofile(case, result)
    M8Repository(case.database)

    events = M8ReadModel(case.database).audit()
    types = {event["event_type"] for event in events}
    assert {"target_agent_enrolled", "profile_collected",
            "compatibility_report_created", "sandbox_session_created",
            "sandbox_validation_completed", "sandbox_session_closed",
            "enforcement_job_created", "enforcement_result_received",
            "post_enforcement_verification"} <= types
    assert any(event["related_id"] == str(verification.enforcement_result_id)
               and event["outcome"] == "VERIFIED" for event in events)
    assert all(event["actor_name"] is None and event["actor_user_id"] is None
               for event in events if event["source"] != "M8 audit")
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_audit_events").fetchone()[0] == 0
    admin = M8Repository(case.database).create_user(
        username="admin", password="correct-admin-password", role_name="admin",
    )
    client = _app(case.database).test_client()
    assert _login(client, admin["username"], "correct-admin-password").status_code == 302
    page = client.get("/audit").data
    assert b"Operational timeline" in page
    assert b"System/Controller" in page and b"Agent" in page
    assert str(result.enforcement_result_id).encode() in page


def test_failed_sandbox_is_visible_without_validation_payload(tmp_path):
    database, _, service, _, ready, _ = _sandbox_sqlite_fixture(tmp_path)
    failed = service.mark_failed(ready.sandbox_session_id, failure_reason="provisioning_failed")
    assert failed.status.value == "FAILED"
    repo = M8Repository(database)
    admin = repo.create_user(
        username="admin", password="correct-admin-password", role_name="admin",
    )
    rows = M8ReadModel(database).sandboxes()
    row = next(item for item in rows if item["sandbox_session_id"] == str(ready.sandbox_session_id))
    assert row["status"] == "FAILED"
    assert row["result"] is None and row["result_sha256"] is None
    assert row["failure_reason"] == "provisioning_failed"
    events = M8ReadModel(database).audit()
    assert any(event["event_type"] == "sandbox_failed"
               and event["related_id"] == str(ready.sandbox_session_id)
               and event["actor_name"] is None for event in events)
    client = _app(database).test_client()
    _login(client, admin["username"], "correct-admin-password")
    page = client.get("/sandboxes").data
    assert b"FAILED" in page and b"provisioning_failed" in page
    assert b"Not recorded" in page


def test_unvalidated_sandbox_cannot_be_requested(tmp_path):
    case = _case(tmp_path, validated=False)
    repo = M8Repository(case.database)
    _, _, result, _ = _assessment_for_case(repo, case)
    admin = repo.create_user(username="admin", password="correct-admin-password")
    repo.assign_role(user_id=admin["user_id"], role_name="admin")
    client = _app(case.database).test_client()
    _login(client, "admin", "correct-admin-password")
    response = client.post("/deployments/request", data={
        "csrf_token": _token(client), "assessment_result_id": result["assessment_result_id"],
        "sandbox_session_id": str(case.session_id),
    })
    assert response.status_code == 400
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_deployment_requests").fetchone()[0] == 0


def test_secret_key_file_is_protected_and_cookie_defaults_secure(tmp_path):
    database, _, _, _ = _empty(tmp_path)
    secret = tmp_path / "web.secret"
    secret.write_bytes(os.urandom(32))
    secret.chmod(0o600)
    settings = M8WebSettings(database=database, secret_key_file=secret)
    app = create_app(settings)
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert "secret_key=" not in repr(settings)
    secret.chmod(0o644)
    with pytest.raises(M8WebConfigurationError):
        M8WebSettings(database=database, secret_key_file=secret)
    secret.chmod(0o600)
    link = tmp_path / "linked.secret"
    link.symlink_to(secret)
    with pytest.raises(M8WebConfigurationError):
        M8WebSettings(database=database, secret_key_file=link)
    parent_link = tmp_path / "linked-parent"
    parent_link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(M8WebConfigurationError):
        M8WebSettings(database=database, secret_key_file=parent_link / "web.secret")
    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir(mode=0o700)
    unsafe_parent.chmod(0o777)
    unsafe_secret = unsafe_parent / "web.secret"
    unsafe_secret.write_bytes(os.urandom(32))
    unsafe_secret.chmod(0o600)
    with pytest.raises(M8WebConfigurationError):
        M8WebSettings(database=database, secret_key_file=unsafe_secret)


def test_atomic_role_bootstrap_and_damaged_hash_fail_closed(tmp_path):
    database = tmp_path / "controller.sqlite3"
    repo = M8Repository(database)
    user = repo.create_user(
        username="bootstrap", password="correct-bootstrap-password", role_name="admin",
    )
    assert repo.authenticate_user(
        username="bootstrap", password="correct-bootstrap-password",
    )["roles"] == frozenset({"admin"})
    assert "password_hash" not in user
    with open_db(database) as db:
        db.execute("UPDATE m8_users SET password_hash = ? WHERE user_id = ?",
                   ("scrypt$" + "x" * 100, user["user_id"]))
    assert repo.authenticate_user(
        username="bootstrap", password="correct-bootstrap-password",
    ) is None


def test_development_cli_refuses_network_listener(monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "sentra-m8", "--database", "/not/opened.sqlite3",
        "--secret-key-file", "/not/opened.secret", "--listen-host", "0.0.0.0",
    ])
    with pytest.raises(SystemExit, match="2"):
        web_main()


def test_create_admin_refuses_relative_missing_symlink_and_non_m8_database(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr("src.m8web.users.getpass", lambda prompt: pytest.fail(
        "invalid database must be rejected before password prompt"
    ))
    missing = tmp_path / "missing.sqlite3"
    wrong = tmp_path / "wrong.sqlite3"
    with sqlite3.connect(wrong) as db:
        db.execute("CREATE TABLE unrelated (value TEXT)")
    link = tmp_path / "linked.sqlite3"
    link.symlink_to(wrong)
    for path in (Path("relative.sqlite3"), missing, wrong, link, tmp_path):
        with pytest.raises(SystemExit, match="2"):
            users_main(["--database", str(path), "create-admin", "--username", "admin"])
    assert not missing.exists()
