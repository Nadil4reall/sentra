"""Read-only presentation of one stored Hardening Run lineage.

These labels are never persisted and never authorize a Controller operation.
"""

from __future__ import annotations

from datetime import UTC, datetime


def _elapsed(start: str | None, end: str | None = None) -> str | None:
    if not start:
        return None
    try:
        since = datetime.fromisoformat(start.replace("Z", "+00:00"))
        until = datetime.fromisoformat(end.replace("Z", "+00:00")) if end else datetime.now(UTC)
        seconds = max(0, int((until - since).total_seconds()))
    except (TypeError, ValueError):
        return None
    return f"{seconds // 60}m {seconds % 60:02d}s"


def project_run(progress: dict) -> dict:
    """Derive eight UI stages from authoritative Controller and M8 rows only."""

    target = progress["target"]
    job, profile, report = (progress[key] for key in ("job", "profile", "report"))
    session, validation = progress["session"], progress["validation"]
    deployment, enforcement, verification = (
        progress[key] for key in ("deployment", "enforcement", "verification")
    )
    decision = next((item for item in report["control_results"]
                     if item["control_id"] == "7.1.1"), None) if report else None
    stages = [
        {"key": "server", "title": "Server", "state": "complete",
         "label": target["hostname"] or "Enrolled server", "at": target["created_at"]},
        {"key": "benchmark", "title": "Benchmark",
         "state": "complete" if progress["benchmark"]["active"] else "blocked",
         "label": progress["benchmark"]["identity"], "at": None},
    ]
    if profile:
        evidence_state, evidence_label = "complete", "Host evidence collected"
    elif job and job["status"] == "pending":
        evidence_state, evidence_label = "waiting", "Waiting for Agent"
    elif job and job["status"] == "dispatched":
        evidence_state, evidence_label = "in_progress", "Agent is collecting host evidence"
    elif job and job["status"] == "completed":
        evidence_state, evidence_label = "blocked", "Completed job has no stored profile"
    else:
        evidence_state, evidence_label = "action_required", "Ready to collect host evidence"
    stages.append({"key": "evidence", "title": "Host Evidence", "state": evidence_state,
                   "label": evidence_label, "at": (profile or job or {}).get("received_at")
                   or (job or {}).get("created_at"),
                   "elapsed": _elapsed((job or {}).get("created_at"),
                                       (profile or {}).get("received_at"))})
    stages.append({"key": "compatibility", "title": "Compatibility",
                   "state": "complete" if decision else
                   ("action_required" if profile else "waiting"),
                   "label": decision["result"].replace("_", " ").title() if decision
                   else ("Analysis ready" if profile else "Waiting for host evidence"),
                   "at": (report or {}).get("generated_at")})
    sandbox_state = "waiting"
    sandbox_label = "Waiting for compatibility analysis"
    if report and not session:
        sandbox_state, sandbox_label = "action_required", "Sandbox validation ready to request"
    elif session:
        status = session["status"]
        sandbox_state, sandbox_label = {
            "REQUESTED": ("action_required", "Sandbox requested; provisioning required"),
            "PROVISIONING": ("in_progress", "Provisioning isolated sandbox"),
            "READY": ("action_required", "Sandbox ready for explicit validation"),
            "VALIDATING": ("in_progress", "Testing selected control in sandbox"),
            "COMPLETED": ("action_required", "Validation complete; close sandbox"),
            "FAILED": ("failed", "Sandbox failed"),
            "QUARANTINED": ("failed", "Sandbox quarantined"),
            "CLOSED": ("complete" if validation and validation["result"] == "validated"
                       else "failed", "Sandbox closed"),
        }[status]
    stages.append({"key": "sandbox", "title": "Sandbox", "state": sandbox_state,
                   "label": sandbox_label, "at": (session or {}).get("created_at"),
                   "elapsed": _elapsed((session or {}).get("created_at"),
                                       (session or {}).get("closed_at"))})
    if deployment is None:
        approval_state = "action_required" if sandbox_state == "complete" else "waiting"
        approval_label = "Request administrator review" if approval_state == "action_required" else "Waiting for sandbox evidence"
    else:
        approval_state, approval_label = {
            "awaiting_approval": ("action_required", "Approval requested"),
            "approved": ("complete", "Approved"),
            "rejected": ("blocked", "Rejected"),
        }.get(deployment["state"], ("blocked", "Review unavailable"))
    stages.append({"key": "approval", "title": "Approval", "state": approval_state,
                   "label": approval_label, "at": (deployment or {}).get("requested_at")})
    if approval_state != "complete":
        deploy_state, deploy_label = "waiting", "Waiting for approval"
    elif not enforcement:
        deploy_state, deploy_label = "action_required", "Ready for controlled deployment"
    elif enforcement["result_outcome"]:
        deploy_state = "complete" if enforcement["result_outcome"] == "SUCCEEDED" else "failed"
        deploy_label = "Controlled enforcement completed" if deploy_state == "complete" else enforcement["result_outcome"].replace("_", " ").title()
    elif enforcement["status"] == "pending":
        deploy_state, deploy_label = "waiting", "Waiting for target Agent"
    elif enforcement["status"] == "dispatched":
        deploy_state, deploy_label = "in_progress", "Enforcement job assigned to Agent"
    else:
        deploy_state, deploy_label = "blocked", "Awaiting authoritative enforcement result"
    stages.append({"key": "deployment", "title": "Deployment", "state": deploy_state,
                   "label": deploy_label, "at": (enforcement or {}).get("created_at")})
    if verification:
        verify_state = "complete" if verification["outcome"] == "VERIFIED" else "failed"
        verify_label = "Selected control verified" if verify_state == "complete" else verification["outcome"].replace("_", " ").title()
    else:
        verify_state = "waiting"
        verify_label = "Waiting for fresh target evidence" if deploy_state == "complete" else "Waiting for controlled enforcement"
    stages.append({"key": "verification", "title": "Verification", "state": verify_state,
                   "label": verify_label, "at": (verification or {}).get("verified_at")})
    current = next((stage["key"] for stage in stages if stage["state"] != "complete"),
                   "verification")
    for stage in stages:
        stage["current"] = stage["key"] == current
    return {"stages": stages, "current": current,
            "read_at": datetime.now(UTC).isoformat(timespec="seconds")}
