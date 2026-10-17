"""M8 action replay is safe without rewriting earlier duplicate history."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import sqlite3
from threading import Barrier
from uuid import UUID, uuid4

import pytest

from src.controller.service import ControllerConflictError
from src.m8db.migrations import apply_migrations, check_db, open_db
from src.m8db.repository import M8DataError, M8Repository
from src.m8web.app import create_app
from src.m8web.config import M8WebSettings
from src.m8web.read_model import M8ReadModel

from test_m7_enforcement import _case, _request
from test_m6_validation import _admin
from test_m8db import _assessment_for_case
from test_m8_product import _login, _token


def _web_case(tmp_path, *, controller_client=None):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    benchmark, _, result, _ = _assessment_for_case(repo, case)
    repo.create_user(username="admin", password="correct-admin-password",
                     role_name="admin")
    app = create_app(
        M8WebSettings(database=case.database, secure_cookie=False),
        controller_client=controller_client,
    )
    client = app.test_client()
    _login(client, "admin", "correct-admin-password")
    return case, repo, benchmark, result, app, client


def _request_form(client, case, result):
    return {
        "csrf_token": _token(client),
        "assessment_result_id": result["assessment_result_id"],
        "sandbox_session_id": str(case.session_id),
    }


def test_double_request_post_and_refresh_reuse_one_deployment(tmp_path):
    case, repo, benchmark, result, _, client = _web_case(tmp_path)
    form = _request_form(client, case, result)
    assert client.post("/deployments/request", data=form).status_code == 302
    assert client.post("/deployments/request", data=form).status_code == 302
    assert client.get("/deployments").status_code == 200
    assert b'action="/deployments/request"' not in client.get("/deployments").data
    run = (f"/runs?target_id={case.enrollment.target_id}"
           f"&benchmark_id={benchmark['benchmark_id']}")
    page = client.get(run)
    assert b"Approval requested" in page.data
    assert b'action="/deployments/request"' not in page.data
    with open_db(case.database) as db:
        rows = db.execute("SELECT deployment_id FROM m8_deployment_requests").fetchall()
        assert len(rows) == 1
        assert db.execute("SELECT COUNT(*) FROM m8_audit_events WHERE "
                          "event_type='deployment_requested'").fetchone()[0] == 1
    replay = repo.create_deployment_request(
        assessment_result_id=result["assessment_result_id"],
        sandbox_session_id=case.session_id,
    )
    assert replay["deployment_id"] == rows[0][0]


def test_concurrent_request_retries_serialize_to_one_lineage(tmp_path):
    case, repo, _, result, _, _ = _web_case(tmp_path)
    barrier = Barrier(2)

    def submit():
        barrier.wait()
        return repo.create_deployment_request(
            assessment_result_id=result["assessment_result_id"],
            sandbox_session_id=case.session_id,
        )["deployment_id"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.map(lambda _: submit(), range(2))
        assert first == second
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_deployment_requests").fetchone()[0] == 1


def test_double_approval_is_one_decision_and_conflict_fails_closed(tmp_path):
    case, repo, _, result, _, client = _web_case(tmp_path)
    client.post("/deployments/request", data=_request_form(client, case, result))
    with open_db(case.database) as db:
        deployment_id = db.execute(
            "SELECT deployment_id FROM m8_deployment_requests"
        ).fetchone()[0]
    path = f"/deployments/{deployment_id}/decision"
    approval = {"csrf_token": _token(client), "decision": "approved",
                "reason": "Reviewed exact sandbox evidence"}
    assert client.post(path, data=approval).status_code == 302
    assert client.post(path, data=approval).status_code == 302
    assert client.post(path, data={**approval, "decision": "rejected"}).status_code == 400
    assert client.post(path, data={**approval, "reason": "Different reason"}).status_code == 400
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_approvals").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM m8_audit_events WHERE "
                          "event_type='deployment_approved'").fetchone()[0] == 1
    assert b"Approved" in client.get("/deployments").data


def test_rejection_replay_is_one_decision_and_later_approval_conflicts(tmp_path):
    case, _, _, result, _, client = _web_case(tmp_path)
    client.post("/deployments/request", data=_request_form(client, case, result))
    with open_db(case.database) as db:
        deployment_id = db.execute(
            "SELECT deployment_id FROM m8_deployment_requests"
        ).fetchone()[0]
    path = f"/deployments/{deployment_id}/decision"
    form = {"csrf_token": _token(client), "decision": "rejected",
            "reason": "Risk not accepted"}
    assert client.post(path, data=form).status_code == 302
    assert client.post(path, data=form).status_code == 302
    assert client.post(path, data={**form, "decision": "approved"}).status_code == 400
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_approvals").fetchone()[0] == 1
        assert db.execute("SELECT state FROM m8_deployment_requests").fetchone()[0] \
            == "rejected"
    assert client.post(f"/deployments/{deployment_id}/start", data={
        "csrf_token": _token(client), "enforcement_ack": "on",
    }).status_code == 409


def test_two_browser_retries_and_existing_link_never_create_second_m7_job(tmp_path):
    case = _case(tmp_path)
    calls = []

    class ControllerClient:
        def create_enforcement_job(self, request):
            calls.append(request)
            return case.service.create_enforcement_job(_admin(), request)

    repo = M8Repository(case.database)
    _, _, result, _ = _assessment_for_case(repo, case)
    repo.create_user(username="admin", password="correct-admin-password",
                     role_name="admin")
    app = create_app(M8WebSettings(database=case.database, secure_cookie=False),
                     controller_client=ControllerClient())
    first, second = app.test_client(), app.test_client()
    for browser in (first, second):
        _login(browser, "admin", "correct-admin-password")
    first.post("/deployments/request", data=_request_form(first, case, result))
    with open_db(case.database) as db:
        deployment_id = db.execute(
            "SELECT deployment_id FROM m8_deployment_requests"
        ).fetchone()[0]
    first.post(f"/deployments/{deployment_id}/decision", data={
        "csrf_token": _token(first), "decision": "approved",
        "reason": "Reviewed exact sandbox evidence",
    })
    path = f"/deployments/{deployment_id}/start"
    assert first.post(path, data={"csrf_token": _token(first),
                                  "enforcement_ack": "on"}).status_code == 302
    assert second.post(path, data={"csrf_token": _token(second),
                                   "enforcement_ack": "on"}).status_code == 302
    assert len(calls) == 1
    assert calls[0].request_id == UUID(deployment_id)
    with open_db(case.database) as db:
        job_id = db.execute(
            "SELECT enforcement_job_id FROM m8_deployment_requests"
        ).fetchone()[0]
        admin_id = db.execute(
            "SELECT user_id FROM m8_users WHERE username='admin'"
        ).fetchone()[0]
        assert job_id is not None
        assert db.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM m8_audit_events WHERE "
                          "event_type='controlled_deployment_started'").fetchone()[0] == 1
    repo.link_enforcement_job(
        deployment_id=deployment_id, enforcement_job_id=job_id,
        initiated_by_user_id=admin_id,
    )
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_audit_events WHERE "
                          "event_type='controlled_deployment_started'").fetchone()[0] == 1

    class RefuseClient:
        def create_enforcement_job(self, request):
            raise AssertionError("an already-linked deployment called Controller")

    another = create_app(
        M8WebSettings(database=case.database, secure_cookie=False),
        controller_client=RefuseClient(),
    ).test_client()
    _login(another, "admin", "correct-admin-password")
    assert another.post(path, data={"csrf_token": _token(another),
                                    "enforcement_ack": "on"}).status_code == 302
    assert f"Deployment already started: M7 job {job_id}".encode() in \
        another.get("/deployments").data
    assert another.post(path, data={"enforcement_ack": "on"}).status_code == 400


def test_controller_rejects_new_active_job_for_same_lineage(tmp_path):
    case = _case(tmp_path)
    first = case.service.create_enforcement_job(_admin(), _request(case))
    assert case.service.create_enforcement_job(
        _admin(), _request(case, request_id=first.request_id),
    ).enforcement_job_id == first.enforcement_job_id
    with pytest.raises(ControllerConflictError):
        case.service.create_enforcement_job(_admin(), _request(case))
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM enforcement_jobs").fetchone()[0] == 1


def test_migration_keeps_old_duplicate_requests_and_decisions_read_only(tmp_path):
    case, repo, benchmark, result, _, client = _web_case(tmp_path)
    client.post("/deployments/request", data=_request_form(client, case, result))
    with open_db(case.database) as db:
        original_id = db.execute(
            "SELECT deployment_id FROM m8_deployment_requests"
        ).fetchone()[0]
    client.post(f"/deployments/{original_id}/decision", data={
        "csrf_token": _token(client), "decision": "approved",
        "reason": "Original review",
    })
    duplicate_id = str(uuid4())
    with open_db(case.database) as db:
        db.execute("DROP TRIGGER m8_deployment_no_duplicate_lineage")
        db.execute("DROP TRIGGER m8_approval_no_second_decision")
        db.execute("DROP INDEX m8_deployment_exact_lineage")
        db.execute("DELETE FROM m8_schema_migrations WHERE version=2")
        db.execute(
            """INSERT INTO m8_deployment_requests (
                deployment_id,assessment_result_id,target_id,control_id,
                sandbox_session_id,state,requested_at,updated_at)
               SELECT ?,assessment_result_id,target_id,control_id,
                      sandbox_session_id,'awaiting_approval',
                      '2099-01-01T00:00:00+00:00','2099-01-01T00:00:00+00:00'
               FROM m8_deployment_requests WHERE deployment_id=?""",
            (duplicate_id, original_id),
        )
        db.execute(
            """INSERT INTO m8_approvals (
                approval_id,deployment_id,target_id,control_id,user_id,
                decision,reason,validation_evidence_sha256,decided_at)
               SELECT ?,deployment_id,target_id,control_id,user_id,
                      decision,reason,validation_evidence_sha256,decided_at
               FROM m8_approvals WHERE deployment_id=?""",
            (str(uuid4()), original_id),
        )
    assert apply_migrations(case.database) == [2]
    assert check_db(case.database)["ok"]
    rows = M8ReadModel(case.database).deployments()
    assert len(rows["requests"]) == 2
    assert {item["deployment_id"] for item in rows["requests"]} == {
        original_id, duplicate_id,
    }
    assert [item["deployment_id"] for item in rows["requests"]
            if item["is_canonical"]] == [original_id]
    assert rows["eligible"] == []
    assert b"Historical duplicate" in client.get("/deployments").data
    assert b'action="/deployments/request"' not in client.get("/deployments").data
    run = (f"/runs?target_id={case.enrollment.target_id}"
           f"&benchmark_id={benchmark['benchmark_id']}")
    wizard = client.get(run).data
    assert original_id.encode() in wizard
    assert duplicate_id.encode() not in wizard
    assert f'action="/deployments/{original_id}/start"'.encode() not in wizard
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_deployment_requests").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM m8_approvals").fetchone()[0] == 2
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                """INSERT INTO m8_deployment_requests (
                    deployment_id,assessment_result_id,target_id,control_id,
                    sandbox_session_id,state,requested_at,updated_at)
                   SELECT ?,assessment_result_id,target_id,control_id,
                          sandbox_session_id,'awaiting_approval',requested_at,updated_at
                   FROM m8_deployment_requests WHERE deployment_id=?""",
                (str(uuid4()), original_id),
            )
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                """INSERT INTO m8_approvals (
                    approval_id,deployment_id,target_id,control_id,user_id,
                    decision,reason,validation_evidence_sha256,decided_at)
                   SELECT ?,deployment_id,target_id,control_id,user_id,
                          decision,reason,validation_evidence_sha256,decided_at
                   FROM m8_approvals WHERE approval_id=(
                       SELECT approval_id FROM m8_approvals
                       WHERE deployment_id=? LIMIT 1)""",
                (str(uuid4()), original_id),
            )
    with open_db(case.database) as db:
        admin_id = db.execute(
            "SELECT user_id FROM m8_users WHERE username='admin'"
        ).fetchone()[0]
    with pytest.raises(M8DataError):
        repo.record_approval(
            deployment_id=original_id,
            user_id=admin_id,
            decision="approved", reason="Original review",
        )


def test_old_pending_duplicates_offer_only_one_decision_form(tmp_path):
    case, _, benchmark, result, _, client = _web_case(tmp_path)
    client.post("/deployments/request", data=_request_form(client, case, result))
    with open_db(case.database) as db:
        original_id = db.execute(
            "SELECT deployment_id FROM m8_deployment_requests"
        ).fetchone()[0]
        db.execute("DROP TRIGGER m8_deployment_no_duplicate_lineage")
        db.execute("DROP TRIGGER m8_approval_no_second_decision")
        db.execute("DROP INDEX m8_deployment_exact_lineage")
        db.execute("DELETE FROM m8_schema_migrations WHERE version=2")
        db.execute(
            """INSERT INTO m8_deployment_requests (
                deployment_id,assessment_result_id,target_id,control_id,
                sandbox_session_id,state,requested_at,updated_at)
               SELECT ?,assessment_result_id,target_id,control_id,
                      sandbox_session_id,state,
                      '2099-01-01T00:00:00+00:00','2099-01-01T00:00:00+00:00'
               FROM m8_deployment_requests WHERE deployment_id=?""",
            (str(uuid4()), original_id),
        )
    assert apply_migrations(case.database) == [2]
    detail = client.get("/deployments").data
    assert detail.count(b'action="/deployments/') == 1
    assert f'action="/deployments/{original_id}/decision"'.encode() in detail
    assert b"Historical duplicate" in detail
    run = (f"/runs?target_id={case.enrollment.target_id}"
           f"&benchmark_id={benchmark['benchmark_id']}")
    assert f'action="/deployments/{original_id}/decision"'.encode() in client.get(run).data


def test_viewer_and_csrf_still_block_action_retries(tmp_path):
    case, repo, _, result, app, admin = _web_case(tmp_path)
    viewer = repo.create_user(username="viewer", password="correct-viewer-password",
                              role_name="viewer")
    browser = app.test_client()
    _login(browser, "viewer", "correct-viewer-password")
    assert browser.post("/deployments/request", data=_request_form(browser, case, result)) \
        .status_code == 403
    assert admin.post("/deployments/request", data={
        "assessment_result_id": result["assessment_result_id"],
        "sandbox_session_id": str(case.session_id),
    }).status_code == 400
    assert viewer["user_id"]
    with open_db(case.database) as db:
        assert db.execute("SELECT COUNT(*) FROM m8_deployment_requests").fetchone()[0] == 0
