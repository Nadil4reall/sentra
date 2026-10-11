"""Flask application factory for SENTRA M8."""

from __future__ import annotations

from datetime import timedelta
import hmac
import secrets
from uuid import UUID

from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template, request,
    session, url_for,
)

from src.m8db.repository import M8DataError, M8Repository

from .config import M8WebSettings
from .read_model import M8ReadModel
from .status import database_health, system_status


def create_app(settings: M8WebSettings) -> Flask:
    """Create one M8 Flask application without global mutable state."""

    app = Flask(__name__)

    app.config.update(
        TESTING=False,
        JSON_SORT_KEYS=False,
        SECRET_KEY=settings.secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.secure_cookie,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    )

    app.json.sort_keys = False
    read_model = M8ReadModel(settings.database)

    def repository() -> M8Repository:
        return M8Repository(settings.database)

    def canonical_id(raw: str) -> str:
        try:
            parsed = UUID(raw)
        except (TypeError, ValueError):
            abort(404)
        if raw != str(parsed):
            abort(404)
        return raw

    def csrf_token() -> str:
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return session["_csrf"]

    @app.context_processor
    def template_context():
        return {"csrf_token": csrf_token, "current_user": getattr(g, "user", None)}

    @app.before_request
    def authenticate_request():
        g.user = None
        if request.routing_exception is not None:
            return None
        if request.endpoint in {"health", "api_status", "static"}:
            return None
        user_id = session.get("user_id")
        if user_id:
            try:
                g.user = repository().get_user_for_session(user_id)
            except (M8DataError, ValueError):
                g.user = None
            if g.user is None:
                session.clear()
        if request.method == "POST":
            expected = session.get("_csrf", "")
            supplied = request.form.get("csrf_token", "")
            if not expected or not hmac.compare_digest(expected, supplied):
                abort(400)
        if request.endpoint != "login" and g.user is None:
            return redirect(url_for("login"))
        return None

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'none'; style-src 'self'; "
            "img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.endpoint not in {"health", "api_status", "static"}:
            response.headers["Cache-Control"] = "no-store"
        return response

    def require_admin():
        if g.user is None or "admin" not in g.user["roles"]:
            abort(403)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user is not None:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            if set(request.form) != {"username", "password", "csrf_token"}:
                abort(400)
            user = repository().authenticate_user(
                username=request.form["username"], password=request.form["password"],
            )
            if user is not None:
                session.clear()
                session["user_id"] = user["user_id"]
                session["_csrf"] = secrets.token_urlsafe(32)
                session.permanent = True
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.", "error")
        return render_template("login.html", title="Sign in")

    @app.post("/logout")
    def logout():
        if set(request.form) != {"csrf_token"}:
            abort(400)
        try:
            repository().append_audit_event(
                actor_type="user", actor_user_id=g.user["user_id"],
                event_type="logout_succeeded", related_type="user",
                related_id=g.user["user_id"], outcome="accepted",
                reason_code="session_cleared",
            )
        finally:
            session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html", title="Overview",
                               snapshot=read_model.dashboard())

    @app.get("/targets")
    def targets():
        return render_template("targets.html", title="Targets",
                               targets=read_model.targets())

    @app.get("/targets/<target_id>")
    def target_detail(target_id: str):
        detail = read_model.target(canonical_id(target_id))
        if detail is None:
            abort(404)
        return render_template("target_detail.html", title="Target detail", **detail)

    @app.get("/targets/<target_id>/controls/<control_id>")
    def target_control(target_id: str, control_id: str):
        target_id = canonical_id(target_id)
        if read_model.target(target_id) is None:
            abort(404)
        try:
            history = repository().target_control_history(
                target_id=target_id, control_id=control_id,
            )
        except M8DataError:
            abort(404)
        return render_template("control_history.html", title="Control history",
                               history=history)

    @app.get("/controls")
    def controls():
        return render_template("controls.html", title="Selected controls & assessments",
                               **read_model.controls_and_assessments())

    @app.get("/compatibility")
    def compatibility():
        return render_template("compatibility.html", title="Compatibility evidence",
                               decisions=read_model.compatibility())

    @app.get("/sandboxes")
    def sandboxes():
        return render_template("sandboxes.html", title="Sandbox validation",
                               sandboxes=read_model.sandboxes())

    @app.get("/deployments")
    def deployments():
        return render_template("deployments.html", title="Controlled enforcement",
                               **read_model.deployments())

    @app.post("/deployments/request")
    def deployment_request():
        require_admin()
        if set(request.form) != {"csrf_token", "assessment_result_id", "sandbox_session_id"}:
            abort(400)
        try:
            result = repository().create_deployment_request(
                assessment_result_id=request.form["assessment_result_id"],
                sandbox_session_id=request.form["sandbox_session_id"],
                requested_by_user_id=g.user["user_id"],
            )
        except (M8DataError, ValueError):
            abort(400)
        flash(f"Request {result['deployment_id']} recorded for administrator review.", "success")
        return redirect(url_for("deployments"))

    @app.post("/deployments/<deployment_id>/decision")
    def deployment_decision(deployment_id: str):
        require_admin()
        deployment_id = canonical_id(deployment_id)
        if set(request.form) != {"csrf_token", "decision", "reason"}:
            abort(400)
        try:
            repository().record_approval(
                deployment_id=deployment_id, user_id=g.user["user_id"],
                decision=request.form["decision"], reason=request.form["reason"],
            )
        except (M8DataError, ValueError):
            abort(400)
        flash("Decision recorded. M7 authorization and execution remain separate.", "success")
        return redirect(url_for("deployments"))

    @app.get("/evidence")
    def evidence():
        return render_template("evidence.html", title="Evidence index",
                               evidence=read_model.evidence())

    @app.get("/audit")
    def audit():
        return render_template("audit.html", title="Operational timeline",
                               events=read_model.audit())

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(500)
    def safe_error(error):
        code = getattr(error, "code", 500)
        return render_template("error.html", title="Request unavailable",
                               code=code), code

    @app.get("/health")
    def health():
        try:
            result = database_health(settings.database)
        except Exception:
            return (
                jsonify(
                    {
                        "service": "sentra-m8",
                        "status": "unhealthy",
                        "database": {
                            "ok": False,
                        },
                    }
                ),
                503,
            )

        status = "ok" if result["ok"] else "unhealthy"
        code = 200 if result["ok"] else 503

        return (
            jsonify(
                {
                    "service": "sentra-m8",
                    "status": status,
                    "database": result,
                }
            ),
            code,
        )

    @app.get("/api/status")
    def api_status():
        try:
            result = system_status(settings.database)
        except Exception:
            return (
                jsonify(
                    {
                        "service": "sentra-m8",
                        "status": "unavailable",
                        "error": "database_unavailable",
                    }
                ),
                503,
            )

        return jsonify(
            {
                "service": "sentra-m8",
                "status": "ok",
                **result,
            }
        )

    return app


__all__ = [
    "create_app",
]
