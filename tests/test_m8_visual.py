"""Visual composition checks without changing M8 evidence or workflow state."""

from pathlib import Path

from test_m8_product import _app, _empty, _login
from test_m8_run_status import _web_case


def test_overview_hero_pipeline_and_bento_keep_real_cta(tmp_path):
    database, _, _, _ = _empty(tmp_path)
    client = _app(database).test_client()
    _login(client, "admin", "correct-admin-password")
    page = client.get("/")
    assert page.status_code == 200
    markup = page.data
    assert b'id="overview-title">SENTRA' in markup
    assert b"Security controls assessment &amp; enforcement" in markup
    assert b'class="hero-pipeline" aria-hidden="true"' in markup
    assert b"Profile</span><span>Analyze</span><span>Sandbox</span>" in markup
    assert b"Start Hardening Run" in markup
    assert markup.index(b'class="overview-hero"') < markup.index(b'class="overview-bento')
    assert markup.index(b'id="readiness-title"') < markup.index(b'id="current-title"')
    assert markup.index(b'id="current-title"') < markup.index(b'id="process-title"')
    assert b"Controller records checked at" in markup
    assert b'<details><summary>Technical details</summary>' in markup


def test_current_run_bento_and_guided_step_preserve_status_hooks(tmp_path):
    case, benchmark, client = _web_case(tmp_path)
    overview = client.get("/")
    assert overview.status_code == 200
    assert b'class="overview-bento has-current"' in overview.data
    assert b"Continue Hardening Run" in overview.data
    assert b"VERIFIED</strong>" not in overview.data
    run = client.get(f"/runs?target_id={case.enrollment.target_id}"
                     f"&benchmark_id={benchmark['benchmark_id']}")
    assert run.status_code == 200
    assert run.data.index(b'class="run-rail"') < run.data.index(b'id="run-active"')
    assert b'data-run-status-url=' in run.data
    assert b'data-run-state=' in run.data
    assert b"Sandbox validation does not modify the target server" in run.data
    assert "script-src 'self'" in run.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in run.headers["Content-Security-Policy"]


def test_neutral_system_visuals_motion_and_mobile_fallback():
    css = Path("src/m8web/static/sentra.css").read_text(encoding="utf-8")
    assert "--canvas: #f5f5f7" in css
    assert 'font-family: -apple-system, BlinkMacSystemFont, "Segoe UI"' in css
    assert ".overview-bento.has-current" in css
    assert ".hero-pipeline" in css and ".process-list::before" in css
    assert ".run-rail::before" in css
    assert "backdrop-filter: blur" in css
    assert "@media (max-width: 550px)" in css
    assert ".process-list { grid-template-columns: 1fr;" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "animation-duration: .01ms !important" in css
