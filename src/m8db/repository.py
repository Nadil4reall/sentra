"""M8 metadata/history operations over the authoritative Controller database.

This module does not create targets, Agents, profiles, M4/M6/M7 evidence, or
execute enforcement. Those remain owned by their existing services.
"""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from uuid import UUID, uuid4

from src.controller.storage import SQLiteControllerRepository
from src.controller.models import JobStatus, SandboxSessionStatus
from src.sandbox_validator.models import ExecutionMode, ValidationDecision

from .migrations import MigrationError, apply_migrations, check_db, open_db


class M8DataError(ValueError):
    """A proposed M8 record lacks trustworthy lineage or valid fields."""


_ASSESSMENT_STATES = frozenset({
    "pass", "fail", "needs_review", "not_tested", "insufficient_evidence",
    "not_applicable", "error",
})
_REASON_CODE = re.compile(r"^[a-z][a-z0-9_.:-]{0,95}$")
_RELATED_LOOKUPS = {
    "benchmark": "SELECT NULL AS target_id, NULL AS authoritative_sha FROM m8_benchmarks WHERE benchmark_id = ?",
    "target": "SELECT target_id, NULL AS authoritative_sha FROM targets WHERE target_id = ?",
    "agent": "SELECT target_id, NULL AS authoritative_sha FROM agents WHERE agent_id = ?",
    "profile": "SELECT target_id, profile_sha256 AS authoritative_sha FROM profiles WHERE profile_id = ?",
    "compatibility_report": "SELECT target_id, report_sha256 AS authoritative_sha FROM compatibility_reports WHERE compatibility_report_id = ?",
    "sandbox_session": "SELECT source_target_id AS target_id, NULL AS authoritative_sha FROM sandbox_sessions WHERE sandbox_session_id = ?",
    "validation_result": "SELECT source_target_id AS target_id, result_sha256 AS authoritative_sha FROM sandbox_validation_executions WHERE sandbox_session_id = ?",
    "enforcement_result": "SELECT target_id, result_sha256 AS authoritative_sha FROM enforcement_results WHERE enforcement_result_id = ?",
    "post_verification": "SELECT target_id, profile_sha256 AS authoritative_sha FROM post_enforcement_verifications WHERE enforcement_result_id = ?",
    "assessment": "SELECT target_id, NULL AS authoritative_sha FROM m8_assessments WHERE assessment_id = ?",
    "assessment_result": "SELECT target_id, NULL AS authoritative_sha FROM m8_assessment_results WHERE assessment_result_id = ?",
    "deployment": "SELECT target_id, NULL AS authoritative_sha FROM m8_deployment_requests WHERE deployment_id = ?",
    "approval": "SELECT target_id, validation_evidence_sha256 AS authoritative_sha FROM m8_approvals WHERE approval_id = ?",
}


def _uuid(value: UUID | str) -> str:
    raw = str(value)
    try:
        parsed = UUID(raw)
    except (TypeError, ValueError, AttributeError) as error:
        raise M8DataError("identifier must be a UUID") from error
    if raw != str(parsed):
        raise M8DataError("identifier must use canonical UUID text")
    return raw


def _text(value: str, *, field: str, limit: int = 1024) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise M8DataError(f"{field} must be nonempty bounded text")
    return value.strip()


def _json(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError) as error:
        raise M8DataError("structured evidence is not JSON") from error


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _row(row: sqlite3.Row | None) -> dict[str, object] | None:
    return None if row is None else dict(row)


def _require_related(
    connection: sqlite3.Connection, *, related_type: str,
    related_id: UUID | str, target_id: UUID | str | None,
    sha256: str | None = None,
) -> str:
    query = _RELATED_LOOKUPS.get(related_type)
    if query is None:
        raise M8DataError("related object type is unsupported")
    identifier = _uuid(related_id)
    row = connection.execute(query, (identifier,)).fetchone()
    if row is None:
        raise M8DataError("related object does not exist")
    expected_target = None if target_id is None else _uuid(target_id)
    if row["target_id"] != expected_target:
        raise M8DataError("related object target lineage differs")
    if row["authoritative_sha"] is not None and sha256 is not None \
            and row["authoritative_sha"] != sha256:
        raise M8DataError("evidence hash differs from authoritative source")
    return identifier


class M8Repository:
    """Additive persistence; operational truth remains in Controller storage."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        apply_migrations(self.database_path)
        if not check_db(self.database_path)["ok"]:
            raise MigrationError("Controller database failed M8 integrity checks")
        self.controller = SQLiteControllerRepository(self.database_path)

    def create_benchmark(
        self, *, identity: str, version: str, platform: str,
        source_reference: str, benchmark_id: UUID | None = None,
    ) -> dict[str, object]:
        identifier = _uuid(benchmark_id or uuid4())
        values = (
            identifier, _text(identity, field="identity"),
            _text(version, field="version", limit=64),
            _text(platform, field="platform", limit=128),
            _text(source_reference, field="source reference", limit=2048), _now(),
        )
        with open_db(self.database_path) as connection:
            connection.execute(
                "INSERT INTO m8_benchmarks (benchmark_id, identity, version, platform, "
                "source_reference, imported_at) VALUES (?, ?, ?, ?, ?, ?)", values,
            )
            return _row(connection.execute(
                "SELECT * FROM m8_benchmarks WHERE benchmark_id = ?", (identifier,),
            ).fetchone())

    def get_benchmark(self, benchmark_id: UUID | str) -> dict[str, object] | None:
        with open_db(self.database_path) as connection:
            return _row(connection.execute(
                "SELECT * FROM m8_benchmarks WHERE benchmark_id = ?",
                (_uuid(benchmark_id),),
            ).fetchone())

    def activate_benchmark(self, benchmark_id: UUID | str) -> None:
        identifier = _uuid(benchmark_id)
        with open_db(self.database_path) as connection:
            item = connection.execute(
                "SELECT platform FROM m8_benchmarks WHERE benchmark_id = ?", (identifier,),
            ).fetchone()
            if item is None:
                raise M8DataError("benchmark does not exist")
            connection.execute(
                "UPDATE m8_benchmarks SET active = 0 WHERE platform = ?",
                (item["platform"],),
            )
            connection.execute(
                "UPDATE m8_benchmarks SET active = 1 WHERE benchmark_id = ?",
                (identifier,),
            )

    def create_control(
        self, *, benchmark_id: UUID | str, control_id: str, title: str,
        required_facts: list[str], adapter_capability: str,
        selected: bool = True, review_state: str = "needs_review",
        description: str = "", profile_level: str = "", assessment_type: str = "",
        metadata: dict[str, object] | None = None,
    ) -> None:
        if type(selected) is not bool or review_state not in {"needs_review", "reviewed"}:
            raise M8DataError("control selection or review state is invalid")
        if not re.fullmatch(r"\d+(?:\.\d+){2,}", control_id):
            raise M8DataError("control ID is invalid")
        if not isinstance(required_facts, list) or not all(
            isinstance(item, str) and item for item in required_facts
        ) or len(required_facts) != len(set(required_facts)):
            raise M8DataError("required facts must be distinct names")
        with open_db(self.database_path) as connection:
            connection.execute(
                """INSERT INTO m8_controls (
                    benchmark_id, control_id, title, description, profile_level,
                    assessment_type, selected, review_state, required_facts_json,
                    adapter_capability, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (_uuid(benchmark_id), control_id, _text(title, field="title"),
                 description, profile_level, assessment_type, int(selected),
                 review_state, _json(required_facts),
                 _text(adapter_capability, field="adapter capability"),
                 _json(metadata or {})),
            )

    def create_user(
        self, *, username: str, password: str, user_id: UUID | None = None,
    ) -> dict[str, object]:
        username = _text(username, field="username", limit=128)
        if not isinstance(password, str) or len(password) < 12:
            raise M8DataError("password must have at least 12 characters")
        salt = os.urandom(16)
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                                n=2**14, r=8, p=1)
        encoded = f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"
        identifier, now = _uuid(user_id or uuid4()), _now()
        with open_db(self.database_path) as connection:
            connection.execute(
                "INSERT INTO m8_users (user_id, username, password_hash, active, "
                "created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
                (identifier, username, encoded, now, now),
            )
        return {"user_id": identifier, "username": username, "active": True}

    def assign_role(self, *, user_id: UUID | str, role_name: str) -> None:
        if role_name not in {"admin", "viewer"}:
            raise M8DataError("role is unsupported")
        with open_db(self.database_path) as connection:
            connection.execute(
                "INSERT INTO m8_user_roles (user_id, role_name) VALUES (?, ?)",
                (_uuid(user_id), role_name),
            )

    def get_target(self, target_id: UUID | str):
        return self.controller.get_target(UUID(_uuid(target_id)))

    def get_agent(self, agent_id: UUID | str) -> dict[str, object] | None:
        """Return enrollment metadata, never the private credential hash."""

        stored = self.controller.get_agent(UUID(_uuid(agent_id)))
        if stored is None:
            return None
        return {
            "agent_id": stored.agent_id, "target_id": stored.target_id,
            "installation_id": stored.installation_id,
            "created_at": stored.created_at, "last_seen": stored.last_seen,
        }

    def list_profile_history(self, target_id: UUID | str) -> list[dict[str, object]]:
        with open_db(self.database_path) as connection:
            return [dict(row) for row in connection.execute(
                "SELECT profile_id, target_id, agent_id, job_id, collected_at, "
                "received_at, profile_sha256, profiler_version, sentra_version "
                "FROM profiles WHERE target_id = ? ORDER BY received_at, profile_id",
                (_uuid(target_id),),
            )]

    def create_assessment(
        self, *, target_id: UUID | str, profile_id: UUID | str,
        benchmark_id: UUID | str, assessment_id: UUID | None = None,
    ) -> dict[str, object]:
        identifier = _uuid(assessment_id or uuid4())
        target, profile, benchmark = map(_uuid, (target_id, profile_id, benchmark_id))
        with open_db(self.database_path) as connection:
            connection.execute(
                "INSERT INTO m8_assessments (assessment_id, target_id, profile_id, "
                "benchmark_id, state, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
                (identifier, target, profile, benchmark, _now()),
            )
            return _row(connection.execute(
                "SELECT * FROM m8_assessments WHERE assessment_id = ?",
                (identifier,),
            ).fetchone())

    def start_assessment(self, assessment_id: UUID | str) -> None:
        with open_db(self.database_path) as connection:
            changed = connection.execute(
                "UPDATE m8_assessments SET state = 'running', started_at = ? "
                "WHERE assessment_id = ? AND state = 'pending'",
                (_now(), _uuid(assessment_id)),
            )
            if changed.rowcount != 1:
                raise M8DataError("assessment is not pending")

    def complete_assessment(self, assessment_id: UUID | str) -> None:
        identifier = _uuid(assessment_id)
        with open_db(self.database_path) as connection:
            assessment = connection.execute(
                "SELECT benchmark_id, state FROM m8_assessments WHERE assessment_id = ?",
                (identifier,),
            ).fetchone()
            if assessment is None or assessment["state"] != "running":
                raise M8DataError("assessment is not running")
            selected = connection.execute(
                "SELECT COUNT(*) FROM m8_controls WHERE benchmark_id = ? AND selected = 1",
                (assessment["benchmark_id"],),
            ).fetchone()[0]
            recorded = connection.execute(
                "SELECT COUNT(*) FROM m8_assessment_results WHERE assessment_id = ?",
                (identifier,),
            ).fetchone()[0]
            if selected == 0 or selected != recorded:
                raise M8DataError("every selected control needs one result")
            connection.execute(
                "UPDATE m8_assessments SET state = 'completed', completed_at = ? "
                "WHERE assessment_id = ? AND state = 'running'",
                (_now(), identifier),
            )

    def record_assessment_result(
        self, *, assessment_id: UUID | str, control_id: str, state: str,
        reason: str, observed_facts: dict[str, object],
        evidence_id: UUID | str | None = None,
        assessment_result_id: UUID | None = None,
    ) -> dict[str, object]:
        if state not in _ASSESSMENT_STATES:
            raise M8DataError("assessment result state is invalid")
        if state in {"pass", "fail"} and evidence_id is None:
            raise M8DataError("pass/fail requires an evidence reference")
        identifier = _uuid(assessment_result_id or uuid4())
        with open_db(self.database_path) as connection:
            assessment = connection.execute(
                "SELECT target_id, benchmark_id, state FROM m8_assessments WHERE assessment_id = ?",
                (_uuid(assessment_id),),
            ).fetchone()
            if assessment is None or assessment["state"] != "running":
                raise M8DataError("assessment is not running")
            selected = connection.execute(
                "SELECT selected FROM m8_controls WHERE benchmark_id = ? AND control_id = ?",
                (assessment["benchmark_id"], control_id),
            ).fetchone()
            if selected is None or selected["selected"] != 1:
                raise M8DataError("control is not selected for this assessment")
            if evidence_id is not None:
                evidence = connection.execute(
                    "SELECT target_id, control_id FROM m8_evidence_records "
                    "WHERE evidence_id = ?", (_uuid(evidence_id),),
                ).fetchone()
                if evidence is None or (
                    evidence["target_id"] != assessment["target_id"]
                    or evidence["control_id"] != control_id
                ):
                    raise M8DataError("assessment evidence belongs to another target/control")
            connection.execute(
                """INSERT INTO m8_assessment_results (
                    assessment_result_id, assessment_id, target_id, benchmark_id,
                    control_id, state, reason, observed_facts_json, evidence_id, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (identifier, _uuid(assessment_id), assessment["target_id"],
                 assessment["benchmark_id"], control_id, state,
                 _text(reason, field="reason", limit=2048), _json(observed_facts),
                 None if evidence_id is None else _uuid(evidence_id), _now()),
            )
            return _row(connection.execute(
                "SELECT * FROM m8_assessment_results WHERE assessment_result_id = ?",
                (identifier,),
            ).fetchone())

    def link_compatibility_report(
        self, *, assessment_id: UUID | str, compatibility_report_id: UUID | str,
    ) -> None:
        with open_db(self.database_path) as connection:
            assessment = connection.execute(
                "SELECT * FROM m8_assessments WHERE assessment_id = ?",
                (_uuid(assessment_id),),
            ).fetchone()
            if assessment is None:
                raise M8DataError("assessment does not exist")
            report = self.controller.get_compatibility_report(
                target_id=UUID(assessment["target_id"]),
                profile_id=UUID(assessment["profile_id"]),
                compatibility_report_id=UUID(_uuid(compatibility_report_id)),
            )
            benchmark = connection.execute(
                "SELECT identity, version FROM m8_benchmarks WHERE benchmark_id = ?",
                (assessment["benchmark_id"],),
            ).fetchone()
            if report is None or benchmark is None or (
                report.benchmark_identity != benchmark["identity"]
                or report.benchmark_version != benchmark["version"]
            ):
                raise M8DataError("M4 report does not match assessment lineage")
            connection.execute(
                """INSERT INTO m8_assessment_report_links (
                    assessment_id, target_id, profile_id, benchmark_id,
                    compatibility_report_id, linked_at
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (_uuid(assessment_id), assessment["target_id"],
                 assessment["profile_id"], assessment["benchmark_id"],
                 _uuid(compatibility_report_id), _now()),
            )

    def create_deployment_request(
        self, *, assessment_result_id: UUID | str,
        sandbox_session_id: UUID | str, deployment_id: UUID | None = None,
    ) -> dict[str, object]:
        """Record an administrative proposal, never initiate M7 execution."""

        result_id, session_id = map(_uuid, (assessment_result_id, sandbox_session_id))
        with open_db(self.database_path) as connection:
            linked = connection.execute(
                """SELECT r.target_id, r.control_id, a.profile_id,
                          l.compatibility_report_id
                   FROM m8_assessment_results r
                   JOIN m8_assessments a ON a.assessment_id = r.assessment_id
                   JOIN m8_assessment_report_links l ON l.assessment_id = a.assessment_id
                   WHERE r.assessment_result_id = ?""", (result_id,),
            ).fetchone()
            if linked is None:
                raise M8DataError("assessment and stored M4 report are not linked")
            if linked["control_id"] != "7.1.1":
                raise M8DataError("M7 supports only control 7.1.1")
            session = self.controller.get_sandbox_session(
                target_id=UUID(linked["target_id"]),
                profile_id=UUID(linked["profile_id"]),
                compatibility_report_id=UUID(linked["compatibility_report_id"]),
                sandbox_session_id=UUID(session_id),
            )
            evidence = self.controller.get_sandbox_validation_evidence(
                sandbox_session_id=UUID(session_id),
            )
            if session is None or session.status is not SandboxSessionStatus.CLOSED \
                    or evidence is None:
                raise M8DataError("closed sandbox and validated evidence are required")
            payload, _ = evidence
            if (
                payload.target_id != UUID(linked["target_id"])
                or payload.profile_id != UUID(linked["profile_id"])
                or payload.compatibility_report_id
                != UUID(linked["compatibility_report_id"])
                or payload.control_id != "7.1.1"
                or payload.execution_mode is not ExecutionMode.EXECUTE
                or payload.report.mode is not ExecutionMode.EXECUTE
                or len(payload.report.control_results) != 1
                or payload.report.control_results[0].result
                is not ValidationDecision.VALIDATED
            ):
                raise M8DataError("sandbox evidence does not authorize a proposal")
            identifier, now = _uuid(deployment_id or uuid4()), _now()
            connection.execute(
                """INSERT INTO m8_deployment_requests (
                    deployment_id, assessment_result_id, target_id, control_id,
                    sandbox_session_id, state, requested_at, updated_at
                ) VALUES (?, ?, ?, '7.1.1', ?, 'awaiting_approval', ?, ?)""",
                (identifier, result_id, linked["target_id"], session_id, now, now),
            )
            return _row(connection.execute(
                "SELECT * FROM m8_deployment_requests WHERE deployment_id = ?",
                (identifier,),
            ).fetchone())

    def record_approval(
        self, *, deployment_id: UUID | str, user_id: UUID | str,
        decision: str, reason: str, approval_id: UUID | None = None,
    ) -> dict[str, object]:
        """Historical user decision; M7's separate approval gate still applies."""

        if decision not in {"approved", "rejected"}:
            raise M8DataError("approval decision is invalid")
        identifier = _uuid(approval_id or uuid4())
        with open_db(self.database_path) as connection:
            request = connection.execute(
                "SELECT * FROM m8_deployment_requests WHERE deployment_id = ?",
                (_uuid(deployment_id),),
            ).fetchone()
            user = connection.execute(
                """SELECT u.user_id FROM m8_users u JOIN m8_user_roles r
                   ON r.user_id = u.user_id WHERE u.user_id = ?
                   AND u.active = 1 AND r.role_name = 'admin'""",
                (_uuid(user_id),),
            ).fetchone()
            if request is None or request["state"] != "awaiting_approval" or user is None:
                raise M8DataError("active admin and pending deployment request required")
            evidence = self.controller.get_sandbox_validation_evidence(
                sandbox_session_id=UUID(request["sandbox_session_id"]),
            )
            if evidence is None:
                raise M8DataError("validated M6 evidence is unavailable")
            payload, digest = evidence
            if payload.target_id != UUID(request["target_id"]) or (
                payload.control_id != request["control_id"]
                or payload.execution_mode is not ExecutionMode.EXECUTE
                or payload.report.mode is not ExecutionMode.EXECUTE
                or len(payload.report.control_results) != 1
                or payload.report.control_results[0].result
                is not ValidationDecision.VALIDATED
            ):
                raise M8DataError("M6 evidence lineage changed")
            now = _now()
            connection.execute(
                """INSERT INTO m8_approvals (
                    approval_id, deployment_id, target_id, control_id,
                    user_id, decision, reason, validation_evidence_sha256, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (identifier, _uuid(deployment_id), request["target_id"],
                 request["control_id"], _uuid(user_id), decision,
                 _text(reason, field="approval reason", limit=2048), digest, now),
            )
            changed = connection.execute(
                "UPDATE m8_deployment_requests SET state = ?, updated_at = ? "
                "WHERE deployment_id = ? AND state = 'awaiting_approval'",
                (decision, now, _uuid(deployment_id)),
            )
            if changed.rowcount != 1:
                raise M8DataError("approval state changed concurrently")
            return _row(connection.execute(
                "SELECT * FROM m8_approvals WHERE approval_id = ?", (identifier,),
            ).fetchone())

    def link_enforcement_job(
        self, *, deployment_id: UUID | str, enforcement_job_id: UUID | str,
    ) -> None:
        """Only attach a separately authorized, Controller-created M7 job."""

        job = self.controller.get_enforcement_job(UUID(_uuid(enforcement_job_id)))
        if job is None:
            raise M8DataError("M7 enforcement job does not exist")
        with open_db(self.database_path) as connection:
            request = connection.execute(
                """SELECT d.*, a.profile_id, l.compatibility_report_id
                   FROM m8_deployment_requests d
                   JOIN m8_assessment_results r
                     ON r.assessment_result_id = d.assessment_result_id
                   JOIN m8_assessments a ON a.assessment_id = r.assessment_id
                   JOIN m8_assessment_report_links l ON l.assessment_id = a.assessment_id
                   WHERE d.deployment_id = ?""", (_uuid(deployment_id),),
            ).fetchone()
            approval = connection.execute(
                "SELECT validation_evidence_sha256 FROM m8_approvals "
                "WHERE deployment_id = ? AND decision = 'approved'",
                (_uuid(deployment_id),),
            ).fetchone()
            if request is None or approval is None or request["state"] != "approved" or (
                job.target_id != UUID(request["target_id"])
                or job.profile_id != UUID(request["profile_id"])
                or job.compatibility_report_id
                != UUID(request["compatibility_report_id"])
                or job.sandbox_session_id != UUID(request["sandbox_session_id"])
                or job.control_id != request["control_id"]
                or job.sandbox_evidence_sha256 != approval["validation_evidence_sha256"]
                or job.administrator_enforcement_approval_acknowledged is not True
                or job.status not in {JobStatus.PENDING, JobStatus.DISPATCHED,
                                     JobStatus.COMPLETED}
            ):
                raise M8DataError("M7 job does not match this approved request")
            changed = connection.execute(
                "UPDATE m8_deployment_requests SET enforcement_job_id = ?, updated_at = ? "
                "WHERE deployment_id = ? AND enforcement_job_id IS NULL",
                (_uuid(enforcement_job_id), _now(), _uuid(deployment_id)),
            )
            if changed.rowcount != 1:
                raise M8DataError("deployment was already linked")

    def create_evidence(
        self, *, evidence_type: str, producer: str, related_type: str,
        related_id: UUID | str, storage_reference: str,
        target_id: UUID | str | None = None, control_id: str | None = None,
        sha256: str | None = None, evidence_id: UUID | None = None,
    ) -> str:
        if sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise M8DataError("evidence digest is invalid")
        identifier = _uuid(evidence_id or uuid4())
        with open_db(self.database_path) as connection:
            related = _require_related(
                connection, related_type=related_type, related_id=related_id,
                target_id=target_id, sha256=sha256,
            )
            connection.execute(
                """INSERT INTO m8_evidence_records (
                    evidence_id, evidence_type, producer, target_id, control_id,
                    related_type, related_id, created_at, storage_reference, sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (identifier, _text(evidence_type, field="evidence type", limit=64),
                 _text(producer, field="producer", limit=64),
                 None if target_id is None else _uuid(target_id), control_id,
                 _text(related_type, field="related type", limit=64),
                 related, _now(),
                 _text(storage_reference, field="storage reference", limit=4096),
                 sha256),
            )
        return identifier

    def append_audit_event(
        self, *, actor_type: str, event_type: str, related_type: str,
        related_id: UUID | str, outcome: str, reason_code: str,
        target_id: UUID | str | None = None, control_id: str | None = None,
        actor_user_id: UUID | str | None = None,
        evidence_id: UUID | str | None = None,
    ) -> str:
        if actor_type not in {"user", "agent", "controller", "system"}:
            raise M8DataError("actor type is invalid")
        if (actor_type == "user") != (actor_user_id is not None):
            raise M8DataError("user actor must identify a user")
        if not _REASON_CODE.fullmatch(reason_code):
            raise M8DataError("audit reason must be a nonsecret code")
        identifier = _uuid(uuid4())
        with open_db(self.database_path) as connection:
            related = _require_related(
                connection, related_type=related_type, related_id=related_id,
                target_id=target_id,
            )
            connection.execute(
                """INSERT INTO m8_audit_events (
                    event_id, occurred_at, actor_type, actor_user_id, event_type,
                    target_id, control_id, related_type, related_id, outcome,
                    reason, evidence_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (identifier, _now(), actor_type,
                 None if actor_user_id is None else _uuid(actor_user_id),
                 _text(event_type, field="event type", limit=96),
                 None if target_id is None else _uuid(target_id), control_id,
                 _text(related_type, field="related type", limit=64),
                 related, _text(outcome, field="outcome", limit=64),
                 reason_code, None if evidence_id is None else _uuid(evidence_id)),
            )
        return identifier

    def target_control_history(
        self, *, target_id: UUID | str, control_id: str,
    ) -> dict[str, object]:
        """IDs and hashes across M3→M4→M6→M7; no compliance inference."""

        target = _uuid(target_id)
        if not re.fullmatch(r"\d+(?:\.\d+){2,}", control_id):
            raise M8DataError("control ID is invalid")
        with open_db(self.database_path) as connection:
            def rows(query: str, parameters: tuple[str, ...]) -> list[dict[str, object]]:
                return [dict(item) for item in connection.execute(query, parameters)]

            reports: list[dict[str, object]] = []
            for item in rows(
                "SELECT compatibility_report_id, profile_id, report_sha256, generated_at "
                "FROM compatibility_reports WHERE target_id = ? ORDER BY generated_at",
                (target,),
            ):
                stored = self.controller.get_compatibility_report(
                    target_id=UUID(target), profile_id=UUID(item["profile_id"]),
                    compatibility_report_id=UUID(item["compatibility_report_id"]),
                )
                if stored is None:
                    raise M8DataError("M4 report disappeared during history query")
                decision = next(
                    (result for result in stored.report.control_results
                     if result.control_id == control_id), None,
                )
                if decision is not None:
                    reports.append({
                        **item, "decision": decision.result.value,
                        "provisional": decision.provisional,
                        "metadata_review_status": decision.metadata_review_status.value,
                    })
            profiles = rows(
                "SELECT profile_id, profile_sha256, collected_at FROM profiles "
                "WHERE target_id = ? ORDER BY collected_at", (target,),
            )
            for item in profiles:
                stored_profile = self.controller.get_stored_profile(
                    UUID(item["profile_id"]),
                )
                if stored_profile is None or (
                    stored_profile.record.profile_sha256 != item["profile_sha256"]
                ):
                    raise M8DataError("M3 profile evidence changed")
            validations = rows(
                "SELECT x.sandbox_session_id, x.validation_job_id, x.status, "
                "x.result_sha256, x.completed_at FROM sandbox_validation_executions x "
                "JOIN sandbox_sessions s ON s.sandbox_session_id = x.sandbox_session_id "
                "WHERE s.source_target_id = ? AND s.control_id = ? ORDER BY x.completed_at",
                (target, control_id),
            )
            for item in validations:
                if item["status"] == "COMPLETED":
                    evidence = self.controller.get_sandbox_validation_evidence(
                        sandbox_session_id=UUID(item["sandbox_session_id"]),
                    )
                    if evidence is None or evidence[1] != item["result_sha256"]:
                        raise M8DataError("M6 validation evidence changed")
            enforcement_jobs = rows(
                "SELECT enforcement_job_id, profile_id, compatibility_report_id, "
                "sandbox_session_id, sandbox_evidence_sha256, "
                "administrator_enforcement_approval_acknowledged, status, created_at "
                "FROM enforcement_jobs WHERE target_id = ? AND control_id = ? "
                "ORDER BY created_at", (target, control_id),
            )
            for item in enforcement_jobs:
                job = self.controller.get_enforcement_job(
                    UUID(item["enforcement_job_id"]),
                )
                if job is None or (
                    job.sandbox_evidence_sha256 != item["sandbox_evidence_sha256"]
                ):
                    raise M8DataError("M7 authorization lineage changed")
            enforcement = rows(
                "SELECT r.enforcement_result_id, r.enforcement_job_id, r.result_sha256, "
                "r.outcome, r.post_enforcement_profile_job_id FROM enforcement_results r "
                "WHERE r.target_id = ? AND r.control_id = ? ORDER BY r.received_at",
                (target, control_id),
            )
            for item in enforcement:
                result = self.controller.get_enforcement_result_for_job(
                    UUID(item["enforcement_job_id"]),
                )
                if result is None or result.result_sha256 != item["result_sha256"]:
                    raise M8DataError("M7 enforcement evidence changed")
            verifications = rows(
                "SELECT v.enforcement_result_id, v.profile_id, v.profile_sha256, "
                "v.outcome, v.verified_at FROM post_enforcement_verifications v "
                "JOIN enforcement_results r ON r.enforcement_result_id = "
                "v.enforcement_result_id WHERE v.target_id = ? AND r.control_id = ? "
                "ORDER BY v.verified_at", (target, control_id),
            )
            for item in verifications:
                verified = self.controller.get_post_enforcement_verification(
                    UUID(item["enforcement_result_id"]),
                )
                if verified is None or verified.profile_sha256 != item["profile_sha256"]:
                    raise M8DataError("post-enforcement observation changed")

            return {
                "target_id": target, "control_id": control_id,
                "profiles": profiles,
                "assessment_results": rows(
                    "SELECT r.*, a.profile_id, a.benchmark_id FROM m8_assessment_results r "
                    "JOIN m8_assessments a ON a.assessment_id = r.assessment_id "
                    "WHERE r.target_id = ? AND r.control_id = ? ORDER BY r.observed_at",
                    (target, control_id),
                ),
                "compatibility_reports": reports,
                "sandbox_sessions": rows(
                    "SELECT sandbox_session_id, source_profile_id, "
                    "source_compatibility_report_id, status, created_at FROM sandbox_sessions "
                    "WHERE source_target_id = ? AND control_id = ? ORDER BY created_at",
                    (target, control_id),
                ),
                "validation_results": validations,
                "enforcement_jobs": enforcement_jobs,
                "approvals": rows(
                    "SELECT a.approval_id, a.deployment_id, a.user_id, a.decision, "
                    "a.validation_evidence_sha256, a.decided_at FROM m8_approvals a "
                    "WHERE a.target_id = ? AND a.control_id = ? ORDER BY a.decided_at",
                    (target, control_id),
                ),
                "deployments": rows(
                    "SELECT deployment_id, assessment_result_id, sandbox_session_id, "
                    "enforcement_job_id, deployment_state FROM m8_deployments "
                    "WHERE target_id = ? AND control_id = ? ORDER BY requested_at",
                    (target, control_id),
                ),
                "enforcement_results": enforcement,
                "verifications": verifications,
                "evidence": rows(
                    "SELECT evidence_id, evidence_type, producer, related_type, related_id, "
                    "sha256, created_at FROM m8_evidence_records WHERE target_id = ? "
                    "AND control_id = ? ORDER BY created_at", (target, control_id),
                ),
                "audit": rows(
                    "SELECT event_id, actor_type, event_type, related_type, related_id, "
                    "outcome, reason, occurred_at FROM m8_audit_events WHERE target_id = ? "
                    "AND control_id = ? ORDER BY occurred_at", (target, control_id),
                ),
            }


__all__ = ["M8DataError", "M8Repository"]
