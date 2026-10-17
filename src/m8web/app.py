"""Flask application factory for SENTRA M8."""

from __future__ import annotations

from datetime import timedelta
import hmac
import secrets
from uuid import UUID, uuid4

from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template, request,
    session, url_for,
)

from src.m8db.repository import M8DataError, M8Repository
from src.controller.models import (
    CompatibilityAnalysisRequest, EnforcementJobCreateRequest, JobCreateRequest,
    SandboxSessionCreateRequest, ValidationJobCreateRequest,
)

from .benchmark_import import (
    BenchmarkImportError, MAX_BENCHMARK_PDF_BYTES, convert_supported_benchmark,
)
from .config import M8WebSettings
from .controller_client import ControllerClientError, M8ControllerClient
from .read_model import M8ReadModel
from .status import database_health, system_status


def create_app(settings: M8WebSettings, *, controller_client=None) -> Flask:
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
        MAX_CONTENT_LENGTH=MAX_BENCHMARK_PDF_BYTES + 1024 * 1024,
    )

    app.json.sort_keys = False
    read_model = M8ReadModel(settings.database)

    def repository() -> M8Repository:
        return M8Repository(settings.database)

    def controller():
        try:
            return controller_client if controller_client is not None else M8ControllerClient(settings)
        except ControllerClientError:
            abort(503)

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

    def exact_form(*fields: str) -> None:
        if (set(request.form) != {"csrf_token", *fields}
                or sum(len(values) for _, values in request.form.lists()) != len(fields) + 1):
            abort(400)

    def run_url(target_id: str, benchmark_id: str) -> str:
        return url_for("hardening_run", target_id=target_id, benchmark_id=benchmark_id)

    def audit_action(event: str, related_type: str, related_id: str,
                     *, target_id: str | None = None,
                     control_id: str | None = None) -> None:
        repository().append_audit_event(
            actor_type="user", actor_user_id=g.user["user_id"],
            event_type=event, related_type=related_type, related_id=related_id,
            target_id=target_id, control_id=control_id,
            outcome="accepted", reason_code="controller_operation_requested",
        )

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
        active = next((item for item in read_model.benchmarks() if item["active"]), None)
        return render_template("dashboard.html", title="Overview",
                               snapshot=read_model.dashboard(), active_benchmark=active)

    @app.get("/benchmarks")
    def benchmarks():
        return render_template("benchmarks.html", title="Benchmarks",
                               benchmarks=read_model.benchmarks())

    @app.post("/benchmarks/import")
    def benchmark_import():
        require_admin()
        exact_form()
        if (set(request.files) != {"pdf"}
                or sum(len(values) for _, values in request.files.lists()) != 1):
            abort(400)
        content = request.files["pdf"].stream.read(MAX_BENCHMARK_PDF_BYTES + 1)
        try:
            identity, controls = convert_supported_benchmark(content)
            result = repository().import_supported_benchmark(
                source_sha256=identity.source_sha256, controls=controls,
                imported_by_user_id=g.user["user_id"],
            )
        except (BenchmarkImportError, M8DataError, OSError, ValueError):
            abort(400)
        flash(f"Supported benchmark imported: {result['benchmark_id']}", "success")
        return redirect(url_for("benchmarks"))

    @app.post("/benchmarks/<benchmark_id>/activate")
    def benchmark_activate(benchmark_id: str):
        require_admin()
        exact_form()
        try:
            repository().activate_benchmark(
                canonical_id(benchmark_id),
                activated_by_user_id=g.user["user_id"],
            )
        except M8DataError:
            abort(400)
        return redirect(url_for("benchmarks"))

    @app.post("/benchmarks/<benchmark_id>/controls/<control_id>/selection")
    def control_selection(benchmark_id: str, control_id: str):
        require_admin()
        exact_form("selected")
        if request.form["selected"] not in {"0", "1"}:
            abort(400)
        try:
            repository().set_control_selected(
                benchmark_id=canonical_id(benchmark_id), control_id=control_id,
                selected=request.form["selected"] == "1",
                user_id=g.user["user_id"],
            )
        except M8DataError:
            abort(400)
        return redirect(url_for("benchmarks"))

    @app.get("/runs")
    def hardening_run():
        target_id = request.args.get("target_id")
        benchmark_id = request.args.get("benchmark_id")
        progress = None
        if target_id is not None or benchmark_id is not None:
            if not target_id or not benchmark_id:
                abort(400)
            progress = read_model.run_progress(
                canonical_id(target_id), canonical_id(benchmark_id),
            )
            if progress is None:
                abort(404)
        return render_template(
            "run.html", title="Hardening run", progress=progress,
            targets=read_model.targets(), benchmarks=read_model.benchmarks(),
        )

    @app.post("/runs/profile")
    def run_profile():
        require_admin()
        exact_form("target_id", "benchmark_id")
        target_id = canonical_id(request.form["target_id"])
        benchmark_id = canonical_id(request.form["benchmark_id"])
        progress = read_model.run_progress(target_id, benchmark_id)
        if progress is None or progress["benchmark"]["active"] != 1:
            abort(400)
        try:
            job = controller().create_profile_job(JobCreateRequest(target_id=UUID(target_id)))
            if str(job.target_id) != target_id or job.job_type.value != "PROFILE_TARGET":
                raise ControllerClientError("Controller profile response lineage is invalid")
            audit_action("profile_collection_requested", "target", target_id,
                         target_id=target_id)
        except (ControllerClientError, M8DataError):
            abort(503)
        flash(f"M3 profile job {job.job_id} queued for the enrolled Agent.", "success")
        return redirect(run_url(target_id, benchmark_id))

    @app.post("/runs/analyze")
    def run_analyze():
        require_admin()
        exact_form("target_id", "benchmark_id", "profile_id")
        target_id = canonical_id(request.form["target_id"])
        benchmark_id = canonical_id(request.form["benchmark_id"])
        profile_id = canonical_id(request.form["profile_id"])
        progress = read_model.run_progress(target_id, benchmark_id)
        if (progress is None or progress["benchmark"]["active"] != 1
                or progress["profile"] is None
                or progress["profile"]["profile_id"] != profile_id):
            abort(400)
        try:
            report = controller().run_compatibility(CompatibilityAnalysisRequest(
                target_id=UUID(target_id), profile_id=UUID(profile_id),
            ))
            if str(report.target_id) != target_id or str(report.profile_id) != profile_id:
                raise ControllerClientError("Controller M4 response lineage is invalid")
            repository().record_compatibility_assessment(
                target_id=target_id, profile_id=profile_id, benchmark_id=benchmark_id,
                compatibility_report_id=report.compatibility_report_id,
                initiated_by_user_id=g.user["user_id"],
            )
        except (ControllerClientError, M8DataError, ValueError):
            abort(409)
        return redirect(run_url(target_id, benchmark_id))

    @app.post("/runs/sandbox/create")
    def run_sandbox_create():
        require_admin()
        exact_form("target_id", "benchmark_id", "profile_id", "report_id", "sandbox_ack")
        if request.form["sandbox_ack"] != "on":
            abort(400)
        target_id, benchmark_id, profile_id, report_id = (
            canonical_id(request.form[field]) for field in
            ("target_id", "benchmark_id", "profile_id", "report_id")
        )
        progress = read_model.run_progress(target_id, benchmark_id)
        if (progress is None or progress["report"] is None
                or progress["report"]["compatibility_report_id"] != report_id
                or progress["benchmark"]["active"] != 1
                or progress["assessment"] is None
                or progress["assessment"]["assessment_result_id"] is None):
            abort(400)
        try:
            item = controller().create_sandbox_session(
                UUID(target_id), UUID(profile_id), UUID(report_id),
                SandboxSessionCreateRequest(
                    request_id=uuid4(), control_id="7.1.1",
                    administrator_sandbox_authorization_acknowledged=True,
                ),
            )
            if (str(item.source_target_id) != target_id
                    or str(item.source_profile_id) != profile_id
                    or str(item.source_compatibility_report_id) != report_id
                    or item.control_id != "7.1.1"):
                raise ControllerClientError("Controller sandbox lineage is invalid")
            audit_action("sandbox_requested", "sandbox_session",
                         str(item.sandbox_session_id), target_id=target_id,
                         control_id="7.1.1")
        except (ControllerClientError, M8DataError):
            abort(409)
        return redirect(run_url(target_id, benchmark_id))

    def sandbox_lineage():
        exact_form("target_id", "benchmark_id", "profile_id", "report_id", "session_id")
        ids = tuple(canonical_id(request.form[field]) for field in
                    ("target_id", "benchmark_id", "profile_id", "report_id", "session_id"))
        progress = read_model.run_progress(ids[0], ids[1])
        if (progress is None or progress["session"] is None
                or progress["session"]["sandbox_session_id"] != ids[4]
                or progress["profile"]["profile_id"] != ids[2]
                or progress["report"]["compatibility_report_id"] != ids[3]):
            abort(400)
        return ids, progress

    @app.post("/runs/sandbox/provision")
    def run_sandbox_provision():
        require_admin()
        ids, _ = sandbox_lineage()
        try:
            item = controller().provision_sandbox(
                *map(UUID, (ids[0], ids[2], ids[3], ids[4]))
            )
            if str(item.sandbox_session_id) != ids[4]:
                raise ControllerClientError("Controller sandbox response is invalid")
            audit_action("sandbox_provision_requested", "sandbox_session", ids[4],
                         target_id=ids[0], control_id="7.1.1")
        except (ControllerClientError, M8DataError):
            abort(409)
        return redirect(run_url(ids[0], ids[1]))

    @app.post("/runs/sandbox/validate")
    def run_sandbox_validate():
        require_admin()
        exact_form("target_id", "benchmark_id", "profile_id", "report_id",
                   "session_id", "approval_ack", "risk_ack", "override_reason")
        if request.form["approval_ack"] != "on" or request.form["risk_ack"] != "on":
            abort(400)
        ids = tuple(canonical_id(request.form[field]) for field in
                    ("target_id", "benchmark_id", "profile_id", "report_id", "session_id"))
        progress = read_model.run_progress(ids[0], ids[1])
        if (progress is None or progress["session"] is None
                or progress["session"]["sandbox_session_id"] != ids[4]
                or progress["session"]["status"] != "READY"
                or progress["profile"]["profile_id"] != ids[2]
                or progress["report"]["compatibility_report_id"] != ids[3]):
            abort(400)
        reason = request.form["override_reason"].strip() or None
        if reason is not None and len(reason) > 1024:
            abort(400)
        try:
            item = controller().validate_sandbox(
                *map(UUID, (ids[0], ids[2], ids[3], ids[4])),
                ValidationJobCreateRequest(
                    request_id=uuid4(), target_id=UUID(ids[0]), profile_id=UUID(ids[2]),
                    compatibility_report_id=UUID(ids[3]), control_id="7.1.1",
                    administrator_approval_acknowledged=True,
                    compatibility_risk_acknowledged=True,
                    compatibility_override_reason=reason,
                ),
            )
            if str(item.sandbox_session_id) != ids[4] or item.status.value != "COMPLETED":
                raise ControllerClientError("Controller M6 result lineage is invalid")
            audit_action("sandbox_validation_requested", "sandbox_session", ids[4],
                         target_id=ids[0], control_id="7.1.1")
        except (ControllerClientError, M8DataError, ValueError):
            abort(409)
        flash(f"M6 validation job {item.validation_job_id} completed.", "success")
        return redirect(run_url(ids[0], ids[1]))

    @app.post("/runs/sandbox/close")
    def run_sandbox_close():
        require_admin()
        ids, progress = sandbox_lineage()
        if progress["session"]["status"] != "COMPLETED":
            abort(400)
        try:
            item = controller().close_sandbox(
                *map(UUID, (ids[0], ids[2], ids[3], ids[4]))
            )
            if str(item.sandbox_session_id) != ids[4] or item.status.value != "CLOSED":
                raise ControllerClientError("Controller sandbox closure is invalid")
            audit_action("sandbox_cleanup_requested", "sandbox_session", ids[4],
                         target_id=ids[0], control_id="7.1.1")
        except (ControllerClientError, M8DataError):
            abort(409)
        return redirect(run_url(ids[0], ids[1]))

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
        flash(f"Approval requested: {result['deployment_id']}.", "success")
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

    @app.post("/deployments/<deployment_id>/start")
    def deployment_start(deployment_id: str):
        require_admin()
        exact_form("enforcement_ack")
        if request.form["enforcement_ack"] != "on":
            abort(400)
        deployment_id = canonical_id(deployment_id)
        repo = repository()
        try:
            existing_job_id = repo.linked_enforcement_job(deployment_id)
            if existing_job_id is not None:
                flash(f"Deployment already started: M7 job {existing_job_id}.", "success")
                return redirect(url_for("deployments"))
            approved = repo.approved_deployment_lineage(deployment_id)
            job = controller().create_enforcement_job(EnforcementJobCreateRequest(
                request_id=UUID(deployment_id),
                target_id=UUID(approved["target_id"]),
                profile_id=UUID(approved["profile_id"]),
                compatibility_report_id=UUID(approved["compatibility_report_id"]),
                sandbox_session_id=UUID(approved["sandbox_session_id"]),
                control_id="7.1.1",
                administrator_enforcement_approval_acknowledged=True,
            ))
            repo.link_enforcement_job(
                deployment_id=deployment_id, enforcement_job_id=job.enforcement_job_id,
                initiated_by_user_id=g.user["user_id"],
            )
        except (M8DataError, ControllerClientError, ValueError):
            abort(409)
        flash("M7 controlled deployment job created; Agent execution is separate.", "success")
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
    @app.errorhandler(409)
    @app.errorhandler(413)
    @app.errorhandler(503)
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
