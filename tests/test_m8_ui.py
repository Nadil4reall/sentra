"""Presentation checks for the evidence-bound M8 interface."""

from __future__ import annotations

from pathlib import Path

from src.m8db.repository import M8Repository
from src.m8web.read_model import M8ReadModel

from test_m7_enforcement import _case
from test_m8_product import _app, _empty, _login, _token
from test_m8db import _assessment_for_case


def test_empty_overview_shows_unrecorded_workflow_without_demo_evidence(tmp_path: Path):
    database, _, _, _ = _empty(tmp_path)
    snapshot = M8ReadModel(database).dashboard()
    assert snapshot["focus"] is None
    assert [stage["title"] for stage in snapshot["workflow"]] == [
        "Profile", "Analyze", "Sandbox", "Approve", "Enforce", "Verify",
    ]
    assert all(stage["state"] is None for stage in snapshot["workflow"])
    client = _app(database).test_client()
    assert _login(client, "admin", "correct-admin-password").status_code == 302
    page = client.get("/").data
    assert b"No target is stored yet" in page
    assert b"No stage evidence yet" in page
    assert b"compliance percentage" not in page.lower()


def test_overview_focus_uses_real_target_control_and_distinct_stage_states(tmp_path: Path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    _assessment_for_case(repo, case)
    admin = repo.create_user(
        username="admin", password="correct-admin-password", role_name="admin",
    )
    snapshot = M8ReadModel(case.database).dashboard()
    assert snapshot["focus"]["target_id"] == str(case.enrollment.target_id)
    assert snapshot["focus"]["control_id"] == "7.1.1"
    states = {stage["key"]: stage["state"] for stage in snapshot["workflow"]}
    assert states["profile"] == "stored"
    assert states["analyze"] == "review_required"
    assert states["sandbox"] == "validated"
    assert states["approve"] is None
    assert states["enforce"] is None
    assert states["verify"] is None
    assert snapshot["counts"]["sandbox_validations"] == 1
    client = _app(case.database).test_client()
    assert _login(client, admin["username"], "correct-admin-password").status_code == 302
    page = client.get("/").data
    assert str(case.enrollment.target_id).encode() in page
    assert b'Control 7.1.1' in page
    assert b'data-state="review_required"' in page
    assert b'data-state="validated"' in page
    assert b"M8 approval does not itself run M7" in page
    target_page = client.get(f"/targets/{case.enrollment.target_id}").data
    assert b"Selected-control catalogue" in target_page
    assert b"Control 7.1.1" in target_page


def test_redesigned_approval_form_keeps_role_and_csrf_boundaries(tmp_path: Path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    _assessment_for_case(repo, case)
    admin = repo.create_user(
        username="admin", password="correct-admin-password", role_name="admin",
    )
    repo.create_user(
        username="viewer", password="correct-viewer-password", role_name="viewer",
    )
    viewer = _app(case.database).test_client()
    assert _login(viewer, "viewer", "correct-viewer-password").status_code == 302
    viewer_page = viewer.get("/deployments").data
    assert b"Request approval" not in viewer_page
    assert b"Record decision" not in viewer_page
    admin_client = _app(case.database).test_client()
    assert _login(admin_client, admin["username"], "correct-admin-password").status_code == 302
    admin_page = admin_client.get("/deployments").data
    assert b'name="csrf_token"' in admin_page
    assert _token(admin_client).encode() in admin_page
    assert b'name="assessment_result_id"' in admin_page
    assert b'name="sandbox_session_id"' in admin_page
    assert b"Request approval" in admin_page


def test_static_design_respects_focus_and_reduced_motion():
    stylesheet = Path("src/m8web/static/sentra.css").read_text(encoding="utf-8")
    assert ":focus-visible" in stylesheet
    assert "prefers-reduced-motion: reduce" in stylesheet
    assert '[data-state="no_known_conflict" i]' in stylesheet
    assert '[data-state="validated" i]' in stylesheet
