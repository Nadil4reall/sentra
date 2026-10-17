"""Bounded, read-only projections of the canonical Controller/M8 database.

The projections contain identifiers, states, timestamps and authoritative hashes;
they never expose agent credentials or raw profile/evidence payloads.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import sqlite3

from .status import _open_read_only
from .run_status import project_run


def _rows(connection: sqlite3.Connection, sql: str, parameters: tuple = ()) -> list[dict]:
    return [dict(row) for row in connection.execute(sql, parameters).fetchall()]


def _first(connection: sqlite3.Connection, sql: str, parameters: tuple = ()) -> dict | None:
    row = connection.execute(sql, parameters).fetchone()
    return dict(row) if row is not None else None


class M8ReadModel:
    def __init__(self, database: Path) -> None:
        self.database = database

    def benchmarks(self) -> list[dict]:
        with _open_read_only(self.database) as db:
            return _rows(db, """
                SELECT b.benchmark_id,b.identity,b.version,b.platform,
                       b.source_reference,b.imported_at,b.active,
                       COUNT(c.control_id) AS control_count,
                       COALESCE(SUM(c.selected),0) AS selected_count
                FROM m8_benchmarks b LEFT JOIN m8_controls c
                  ON c.benchmark_id=b.benchmark_id
                GROUP BY b.benchmark_id ORDER BY b.active DESC,b.imported_at DESC
                LIMIT 25
            """)

    def active_profile_job(self, target_id: str) -> dict | None:
        """Find an existing unfinished M3 job without changing Controller state."""
        with _open_read_only(self.database) as db:
            return _first(db, "SELECT j.job_id,j.status,j.created_at,j.dispatched_at "
                          "FROM jobs j WHERE j.target_id=? AND j.job_type='PROFILE_TARGET' "
                          "AND NOT EXISTS (SELECT 1 FROM enforcement_results e "
                          "WHERE e.post_enforcement_profile_job_id=j.job_id) "
                          "AND j.status IN ('pending','dispatched') "
                          "ORDER BY j.created_at DESC,j.rowid DESC LIMIT 1", (target_id,))

    def run_start(self, run_id: str) -> dict | None:
        with _open_read_only(self.database) as db:
            row = _first(db, "SELECT run_id,target_id,benchmark_id,created_at,"
                         "selected_controls_json FROM m8_run_starts WHERE run_id=?",
                         (run_id,))
            if row:
                return row
            return _first(db, "SELECT assessment_id AS run_id,target_id,benchmark_id,"
                          "created_at FROM m8_assessments WHERE assessment_id=?",
                          (run_id,))

    def run_history(self) -> list[dict]:
        """Read-only histories; never infer that an older run owns newer evidence."""
        with _open_read_only(self.database) as db:
            starts = _rows(db, """
                SELECT s.run_id,s.target_id,s.benchmark_id,s.created_at,
                       s.selected_controls_json,
                       json_array_length(s.selected_controls_json) AS control_count,
                       json_extract(t.observed_metadata_json,'$.hostname') AS hostname,
                       b.identity AS benchmark_identity
                FROM m8_run_starts s JOIN targets t ON t.target_id=s.target_id
                JOIN m8_benchmarks b ON b.benchmark_id=s.benchmark_id
                UNION ALL
                SELECT a.assessment_id,a.target_id,a.benchmark_id,a.created_at,
                       NULL,(SELECT COUNT(*) FROM m8_assessment_results r
                            WHERE r.assessment_id=a.assessment_id),
                       json_extract(t.observed_metadata_json,'$.hostname'),b.identity
                FROM m8_assessments a JOIN targets t ON t.target_id=a.target_id
                JOIN m8_benchmarks b ON b.benchmark_id=a.benchmark_id
                WHERE NOT EXISTS (SELECT 1 FROM m8_run_starts s
                                  WHERE s.run_id=a.assessment_id)
                ORDER BY 4 DESC LIMIT 100
            """)
        import json
        result = []
        for row in starts:
            progress = self.run_progress(row["target_id"], row["benchmark_id"], row["run_id"])
            if progress is None:
                continue
            status = project_run(progress)
            current = next(item for item in status["stages"] if item["current"])
            row["control_scope"] = (len(json.loads(row["selected_controls_json"]))
                                    if row["selected_controls_json"]
                                    else row["control_count"])
            row["control_id"] = "7.1.1" if progress["assessment"] else None
            row["stage"] = current["title"]
            row["outcome"] = ("Verified" if progress["verification"] and
                              progress["verification"]["outcome"] == "VERIFIED"
                              else current["label"])
            result.append(row)
        return result

    def run_progress(self, target_id: str, benchmark_id: str,
                     run_id: str | None = None) -> dict | None:
        """Project a wizard from source rows; never persist a second workflow state."""
        with _open_read_only(self.database) as db:
            target = _first(db, "SELECT target_id,agent_id,status,created_at,last_seen,"
                            "json_extract(observed_metadata_json, '$.hostname') AS hostname "
                            "FROM targets WHERE target_id=?", (target_id,))
            benchmark = _first(db, "SELECT benchmark_id,identity,version,active "
                               "FROM m8_benchmarks WHERE benchmark_id=?", (benchmark_id,))
            if target is None or benchmark is None:
                return None
            latest_start = _first(db, "SELECT * FROM m8_run_starts WHERE target_id=? "
                                  "AND benchmark_id=? ORDER BY created_at DESC, "
                                  "rowid DESC LIMIT 1", (target_id, benchmark_id))
            run_start = (_first(db, "SELECT * FROM m8_run_starts WHERE run_id=? AND "
                                "target_id=? AND benchmark_id=?",
                                (run_id, target_id, benchmark_id))
                         if run_id is not None else latest_start)
            legacy_assessment = (_first(db, "SELECT assessment_id,profile_id FROM "
                                        "m8_assessments WHERE assessment_id=? AND "
                                        "target_id=? AND benchmark_id=?",
                                        (run_id, target_id, benchmark_id))
                                 if run_id is not None and run_start is None else None)
            if run_id is not None and run_start is None and legacy_assessment is None:
                return None
            job_sql = ("SELECT j.job_id,j.status,j.created_at,j.dispatched_at,"
                         "j.completed_at,j.assigned_agent_id FROM jobs j "
                         "WHERE j.target_id=? AND j.job_type='PROFILE_TARGET' "
                         "AND NOT EXISTS (SELECT 1 FROM enforcement_results e "
                         "WHERE e.post_enforcement_profile_job_id=j.job_id) ")
            if run_start:
                job = _first(db, job_sql + "AND j.job_id=? LIMIT 1",
                             (target_id, run_start["profile_job_id"] or ""))
            elif legacy_assessment:
                job = _first(db, job_sql + "AND j.job_id=(SELECT job_id FROM profiles "
                             "WHERE profile_id=?) LIMIT 1",
                             (target_id, legacy_assessment["profile_id"]))
            else:
                job = _first(db, job_sql + "ORDER BY CASE WHEN j.status IN "
                             "('pending','dispatched') THEN 0 ELSE 1 END,"
                             "j.created_at DESC,j.rowid DESC LIMIT 1", (target_id,))
            profile = _first(db, "SELECT profile_id,job_id,collected_at,received_at,"
                             "profile_sha256 FROM profiles WHERE target_id=? AND job_id=?",
                             (target_id, job["job_id"] if job else ""))
            if run_start or legacy_assessment:
                report = _first(db, "SELECT r.compatibility_report_id,r.generated_at,"
                                "r.report_sha256,r.payload_json FROM "
                                "m8_assessment_report_links l JOIN compatibility_reports r "
                                "ON r.compatibility_report_id=l.compatibility_report_id "
                                "WHERE l.assessment_id=? AND r.target_id=? AND "
                                "r.profile_id=?",
                                ((run_start or legacy_assessment)["run_id" if run_start else "assessment_id"], target_id,
                                 profile["profile_id"] if profile else ""))
            else:
                report = _first(db, "SELECT compatibility_report_id,generated_at,"
                                "report_sha256,payload_json FROM compatibility_reports "
                                "WHERE target_id=? AND profile_id=? ORDER BY "
                                "generated_at DESC,rowid DESC LIMIT 1",
                                (target_id, profile["profile_id"] if profile else ""))
            assessment_sql = """
                SELECT a.assessment_id,a.state,a.created_at,
                       r.assessment_result_id
                FROM m8_assessments a
                LEFT JOIN m8_assessment_report_links l ON l.assessment_id=a.assessment_id
                LEFT JOIN m8_assessment_results r ON r.assessment_id=a.assessment_id
                     AND r.control_id='7.1.1'
                WHERE a.target_id=? AND a.profile_id=? AND a.benchmark_id=?
                  AND l.compatibility_report_id=?
            """
            if run_start or legacy_assessment:
                assessment = _first(db, assessment_sql + "AND a.assessment_id=? LIMIT 1",
                                    (target_id, profile["profile_id"] if profile else "",
                                     benchmark_id, report["compatibility_report_id"] if report else "",
                                     (run_start or legacy_assessment)["run_id" if run_start else "assessment_id"]))
            else:
                assessment = _first(db, assessment_sql + "ORDER BY a.created_at DESC LIMIT 1",
                                    (target_id, profile["profile_id"] if profile else "",
                                     benchmark_id, report["compatibility_report_id"] if report else ""))
            session = _first(db, """
                SELECT sandbox_session_id,status,created_at,provisioning_started_at,
                       ready_at,validation_started_at,completed_at,closed_at,
                       failure_reason,quarantine_reason
                FROM sandbox_sessions WHERE source_target_id=?
                  AND source_profile_id=? AND source_compatibility_report_id=?
                  AND control_id='7.1.1'
                ORDER BY created_at DESC,rowid DESC LIMIT 1
            """, (target_id, profile["profile_id"] if profile else "",
                  report["compatibility_report_id"] if report else ""))
            validation = _first(db, "SELECT status,result,result_sha256,validation_job_id,"
                                "completed_at "
                                "FROM m8_validation_outcomes WHERE sandbox_session_id=?",
                                (session["sandbox_session_id"] if session else "",))
            deployment = _first(db, """
                SELECT d.deployment_id,d.state,d.enforcement_job_id,d.requested_at,
                       p.approval_id,p.decision,p.reason AS approval_reason,
                       p.decided_at,p.user_id AS reviewer_id,u.username AS reviewer_username,
                       (SELECT COUNT(*) FROM m8_approvals p2
                        WHERE p2.deployment_id=d.deployment_id) AS approval_count
                FROM m8_deployment_requests d
                LEFT JOIN m8_approvals p ON p.approval_id=(
                    SELECT p2.approval_id FROM m8_approvals p2
                    WHERE p2.deployment_id=d.deployment_id
                    ORDER BY p2.decided_at,p2.approval_id LIMIT 1)
                LEFT JOIN m8_users u ON u.user_id=p.user_id
                WHERE d.assessment_result_id=? AND d.sandbox_session_id=?
                ORDER BY CASE
                    WHEN d.enforcement_job_id IS NOT NULL THEN 0
                    WHEN d.state='approved' THEN 1
                    WHEN d.state='awaiting_approval' THEN 2
                    WHEN d.state='rejected' THEN 3
                    ELSE 4 END,
                    d.requested_at,d.deployment_id LIMIT 1
            """, (assessment["assessment_result_id"] if assessment else "",
                  session["sandbox_session_id"] if session else ""))
            enforcement = _first(db, "SELECT j.enforcement_job_id,j.status,j.created_at,"
                                 "j.dispatched_at,j.completed_at,r.enforcement_result_id,"
                                 "r.outcome AS result_outcome,r.result_sha256,"
                                 "json_extract(r.payload_json, '$.mutation_attempted') AS mutation_attempted,"
                                 "json_extract(r.payload_json, '$.mutation_changed') AS mutation_changed,"
                                 "json_extract(r.payload_json, '$.verification_succeeded') AS verification_succeeded "
                                 "FROM enforcement_jobs j LEFT JOIN enforcement_results r "
                                 "ON r.enforcement_job_id=j.enforcement_job_id "
                                 "WHERE j.enforcement_job_id=? AND j.target_id=?",
                                 ((deployment or {}).get("enforcement_job_id", ""), target_id))
            conflicting_m7 = _first(db, "SELECT enforcement_job_id,status FROM "
                                    "enforcement_jobs WHERE target_id=? AND "
                                    "control_id='7.1.1' AND status IN "
                                    "('pending','dispatched') AND enforcement_job_id<>? "
                                    "ORDER BY created_at DESC LIMIT 1",
                                    (target_id,
                                     (enforcement or {}).get("enforcement_job_id", "")))
            verification = _first(db, "SELECT outcome,verified_at,profile_id,"
                                  "enforcement_result_id,profile_sha256 "
                                  "FROM m8_verifications WHERE deployment_id=?",
                                  (deployment["deployment_id"] if deployment else "",))
            sandbox_history = _rows(db, "SELECT sandbox_session_id,"
                                    "source_profile_id,source_compatibility_report_id,"
                                    "status,created_at,closed_at,failure_reason,"
                                    "quarantine_reason FROM sandbox_sessions "
                                    "WHERE source_target_id=? AND control_id='7.1.1' "
                                    "ORDER BY created_at DESC LIMIT 25", (target_id,))
            if report:
                import json
                controls = json.loads(report.pop("payload_json"))["control_results"]
                report["control_results"] = [
                    {"control_id": item["control_id"], "result": item["result"],
                     "explanation": item.get("explanation", ""),
                     "provisional": item.get("provisional", True)}
                    for item in controls
                ]
            return {
                "run_start": run_start,
                "legacy_assessment_id": legacy_assessment["assessment_id"] if legacy_assessment else None,
                "is_latest_run": legacy_assessment is None and (
                    not run_start or latest_start["run_id"] == run_start["run_id"]),
                "target": target, "benchmark": benchmark, "job": job,
                "profile": profile, "report": report, "assessment": assessment,
                "session": session, "validation": validation,
                "deployment": deployment, "enforcement": enforcement,
                "verification": verification, "sandbox_history": sandbox_history,
                "conflicting_m7": conflicting_m7,
            }

    def dashboard(self) -> dict[str, object]:
        with _open_read_only(self.database) as db:
            active_benchmark = _first(db, "SELECT benchmark_id,identity,version "
                                      "FROM m8_benchmarks WHERE active=1 "
                                      "ORDER BY imported_at DESC LIMIT 1")
            enrolled_servers = db.execute("SELECT COUNT(*) FROM targets t JOIN agents a "
                                          "ON a.target_id=t.target_id AND a.agent_id=t.agent_id").fetchone()[0]
            counts = {
                "targets": "SELECT COUNT(*) FROM targets",
                "profiles": "SELECT COUNT(*) FROM profiles",
                "assessments": "SELECT COUNT(*) FROM m8_assessments",
                "compatibility_reports": "SELECT COUNT(*) FROM compatibility_reports",
                "m4_review_decisions": "SELECT COUNT(*) FROM compatibility_reports r, "
                    "json_each(r.payload_json, '$.control_results') c "
                    "WHERE json_extract(c.value, '$.result') = 'review_required'",
                "validated_sandboxes": "SELECT COUNT(*) FROM m8_validation_outcomes "
                    "WHERE result = 'validated' AND status = 'COMPLETED'",
                "sandbox_validations": "SELECT COUNT(*) FROM m8_validation_outcomes "
                    "WHERE status = 'COMPLETED'",
                "deployment_requests": "SELECT COUNT(*) FROM m8_deployment_requests",
                "deployment_decisions": "SELECT COUNT(*) FROM m8_approvals",
                "pending_requests": "SELECT COUNT(*) FROM m8_deployment_requests "
                    "WHERE state = 'awaiting_approval'",
                "successful_m7_results": "SELECT COUNT(*) FROM enforcement_results "
                    "WHERE outcome = 'SUCCEEDED'",
                "verified_outcomes": "SELECT COUNT(*) FROM post_enforcement_verifications "
                    "WHERE outcome = 'VERIFIED'",
            }
            focus = self._focus(db)
            workflow = self._workflow(db, focus["target_id"], focus["control_id"]) \
                if focus else [
                    {"key": key, "title": title, "state": None, "at": None,
                     "related_id": None}
                    for key, title in (("profile", "Profile"), ("analyze", "Analyze"),
                                       ("sandbox", "Sandbox"), ("approve", "Approve"),
                                       ("enforce", "Enforce"), ("verify", "Verify"))
                ]
            selected_controls = _rows(db, """
                SELECT c.control_id, c.title, c.review_state
                FROM m8_controls c JOIN m8_benchmarks b ON b.benchmark_id = c.benchmark_id
                WHERE c.selected = 1 ORDER BY b.active DESC, c.control_id LIMIT 4
            """)
            if focus:
                for control in selected_controls:
                    control_id = control["control_id"]
                    target_id = focus["target_id"]
                    assessed = _first(db, """
                        SELECT state FROM m8_assessment_results
                        WHERE target_id = ? AND control_id = ?
                        ORDER BY observed_at DESC LIMIT 1
                    """, (target_id, control_id))
                    analyzed = _first(db, """
                        SELECT json_extract(c.value, '$.result') AS decision
                        FROM compatibility_reports r,
                             json_each(r.payload_json, '$.control_results') c
                        WHERE r.target_id = ?
                          AND json_extract(c.value, '$.control_id') = ?
                        ORDER BY r.generated_at DESC LIMIT 1
                    """, (target_id, control_id))
                    sandbox = _first(db, """
                        SELECT v.result FROM sandbox_sessions s
                        LEFT JOIN m8_validation_outcomes v
                          ON v.sandbox_session_id = s.sandbox_session_id
                        WHERE s.source_target_id = ? AND s.control_id = ?
                        ORDER BY s.created_at DESC LIMIT 1
                    """, (target_id, control_id))
                    control.update(
                        assessment_state=assessed["state"] if assessed else None,
                        compatibility_decision=analyzed["decision"] if analyzed else None,
                        sandbox_result=sandbox["result"] if sandbox else None,
                    )
            else:
                for control in selected_controls:
                    control.update(assessment_state=None, compatibility_decision=None,
                                   sandbox_result=None)
            result = {
                "counts": {key: int(db.execute(sql).fetchone()[0])
                           for key, sql in counts.items()},
                "focus": focus, "workflow": workflow,
                "selected_controls": selected_controls,
                "readiness": {"records_available": True,
                              "enrolled_servers": int(enrolled_servers),
                              "active_benchmark": active_benchmark,
                              "ready": bool(enrolled_servers and active_benchmark)},
                "read_at": datetime.now(UTC).isoformat(timespec="seconds"),
            }
        events = self.audit()
        useful_types = {
            "target_agent_enrolled", "benchmark_imported", "benchmark_activated",
            "profile_collected", "compatibility_report_created",
            "sandbox_validation_completed", "sandbox_validation_failed",
            "sandbox_failed", "sandbox_quarantined", "sandbox_session_closed",
            "deployment_requested", "deployment_approved", "deployment_rejected",
            "deployment_started", "enforcement_job_created",
            "enforcement_result_received", "post_enforcement_verification",
        }
        useful = [event for event in events if event["event_type"] in useful_types]
        # Authentication events remain in the full timeline. Show at most one
        # here when no operational milestone has been recorded yet.
        result["activity"] = useful[:5] if useful else events[:1]
        result["run"] = self._overview_run(active_benchmark)
        return result

    def _overview_run(self, active_benchmark: dict | None) -> dict | None:
        """Reuse the Hardening Run projection; only source records choose a run."""

        if active_benchmark:
            candidates = []
            with _open_read_only(self.database) as db:
                targets_with_runs = _rows(db, """
                    SELECT target_id FROM (
                        SELECT j.target_id,j.created_at FROM jobs j
                        WHERE j.job_type='PROFILE_TARGET'
                          AND NOT EXISTS (SELECT 1 FROM enforcement_results e
                              WHERE e.post_enforcement_profile_job_id=j.job_id)
                        UNION ALL
                        SELECT target_id,created_at FROM m8_run_starts
                    ) GROUP BY target_id ORDER BY MAX(created_at) DESC
                """)
            for target in targets_with_runs:
                progress = self.run_progress(target["target_id"], active_benchmark["benchmark_id"])
                if not progress or not any(progress[key] for key in (
                    "run_start", "job", "profile", "report", "session", "deployment", "enforcement"
                )):
                    continue
                if progress["verification"] and progress["verification"]["outcome"] == "VERIFIED":
                    continue
                projection = project_run(progress)
                stage = next(item for item in projection["stages"] if item["current"])
                timestamps = [row.get(field) for row, field in (
                    (progress["job"] or {}, "created_at"),
                    (progress["profile"] or {}, "received_at"),
                    (progress["report"] or {}, "generated_at"),
                    (progress["session"] or {}, "created_at"),
                    (progress["deployment"] or {}, "requested_at"),
                    (progress["enforcement"] or {}, "created_at"),
                    (progress["run_start"] or {}, "created_at"),
                )]
                candidates.append((max((value for value in timestamps if value), default=""),
                                   {"kind": "current", "target": progress["target"],
                                    "control_id": "7.1.1", "stage": stage,
                                    "benchmark_id": active_benchmark["benchmark_id"],
                                    "run_id": (progress["run_start"] or {}).get("run_id")}))
            if candidates:
                return max(candidates, key=lambda item: item[0])[1]
        # A final result is shown only from the authoritative post-enforcement
        # verification table, never from sandbox or enforcement success alone.
        with _open_read_only(self.database) as db:
            verified = _first(db, """
                SELECT v.target_id,r.control_id,v.verified_at,
                       json_extract(t.observed_metadata_json, '$.hostname') AS hostname
                FROM post_enforcement_verifications v
                JOIN enforcement_results r
                  ON r.enforcement_result_id=v.enforcement_result_id
                JOIN targets t ON t.target_id=v.target_id
                WHERE v.outcome='VERIFIED'
                ORDER BY v.verified_at DESC LIMIT 1
            """)
        return {"kind": "verified", **verified} if verified else None

    @staticmethod
    def _focus(db: sqlite3.Connection, target_id: str | None = None) -> dict | None:
        """Choose a real target/control with the most recent sandbox lineage."""

        focus = _first(db, """
            SELECT t.target_id, s.control_id,
                   json_extract(t.observed_metadata_json, '$.hostname') AS hostname,
                   t.status AS target_status
            FROM sandbox_sessions s JOIN targets t ON t.target_id = s.source_target_id
            WHERE (? IS NULL OR s.source_target_id = ?)
            ORDER BY s.created_at DESC LIMIT 1
        """, (target_id, target_id))
        if focus:
            return focus
        focus = _first(db, """
            SELECT t.target_id, r.control_id,
                   json_extract(t.observed_metadata_json, '$.hostname') AS hostname,
                   t.status AS target_status
            FROM m8_assessment_results r JOIN targets t ON t.target_id = r.target_id
            WHERE (? IS NULL OR r.target_id = ?)
            ORDER BY r.observed_at DESC LIMIT 1
        """, (target_id, target_id))
        if focus:
            return focus
        focus = _first(db, """
            SELECT t.target_id, json_extract(c.value, '$.control_id') AS control_id,
                   json_extract(t.observed_metadata_json, '$.hostname') AS hostname,
                   t.status AS target_status
            FROM compatibility_reports r JOIN targets t ON t.target_id = r.target_id,
                 json_each(r.payload_json, '$.control_results') c
            WHERE (? IS NULL OR r.target_id = ?)
            ORDER BY r.generated_at DESC, control_id LIMIT 1
        """, (target_id, target_id))
        if focus:
            return focus
        return _first(db, """
            SELECT t.target_id, NULL AS control_id,
                   json_extract(t.observed_metadata_json, '$.hostname') AS hostname,
                   t.status AS target_status
            FROM targets t WHERE (? IS NULL OR t.target_id = ?)
            ORDER BY COALESCE(t.last_seen, t.created_at) DESC LIMIT 1
        """, (target_id, target_id))

    @staticmethod
    def _workflow(db: sqlite3.Connection, target_id: str, control_id: str | None) -> list[dict]:
        """Latest stored state per stage for one target/control, never a verdict."""

        stages = [
            ("profile", "Profile", _first(db, """
                SELECT profile_id AS related_id, received_at AS at, 'stored' AS state
                FROM profiles WHERE target_id = ? ORDER BY received_at DESC LIMIT 1
            """, (target_id,))),
        ]
        if control_id:
            stages.extend([
                ("analyze", "Analyze", _first(db, """
                    SELECT r.compatibility_report_id AS related_id,
                           r.generated_at AS at,
                           json_extract(c.value, '$.result') AS state
                    FROM compatibility_reports r,
                         json_each(r.payload_json, '$.control_results') c
                    WHERE r.target_id = ? AND json_extract(c.value, '$.control_id') = ?
                    ORDER BY r.generated_at DESC LIMIT 1
                """, (target_id, control_id))),
                ("sandbox", "Sandbox", _first(db, """
                    SELECT s.sandbox_session_id AS related_id,
                           COALESCE(v.completed_at, s.closed_at, s.completed_at,
                                    s.created_at) AS at,
                           CASE WHEN s.status IN ('FAILED', 'QUARANTINED')
                                THEN lower(s.status)
                                ELSE COALESCE(v.result, lower(s.status)) END AS state
                    FROM sandbox_sessions s LEFT JOIN m8_validation_outcomes v
                      ON v.sandbox_session_id = s.sandbox_session_id
                    WHERE s.source_target_id = ? AND s.control_id = ?
                    ORDER BY s.created_at DESC LIMIT 1
                """, (target_id, control_id))),
                ("approve", "Approve", _first(db, """
                    SELECT d.deployment_id AS related_id,
                           COALESCE(a.decided_at, d.requested_at) AS at,
                           COALESCE(a.decision, d.state) AS state
                    FROM m8_deployment_requests d LEFT JOIN m8_approvals a
                      ON a.deployment_id = d.deployment_id
                    WHERE d.target_id = ? AND d.control_id = ?
                    ORDER BY d.requested_at DESC, a.decided_at DESC LIMIT 1
                """, (target_id, control_id))),
                ("enforce", "Enforce", _first(db, """
                    SELECT j.enforcement_job_id AS related_id,
                           COALESCE(r.received_at, j.completed_at,
                                    j.dispatched_at, j.created_at) AS at,
                           COALESCE(r.outcome, j.status) AS state
                    FROM enforcement_jobs j LEFT JOIN enforcement_results r
                      ON r.enforcement_job_id = j.enforcement_job_id
                    WHERE j.target_id = ? AND j.control_id = ?
                    ORDER BY j.created_at DESC LIMIT 1
                """, (target_id, control_id))),
                ("verify", "Verify", _first(db, """
                    SELECT v.enforcement_result_id AS related_id,
                           v.verified_at AS at, v.outcome AS state
                    FROM post_enforcement_verifications v JOIN enforcement_results r
                      ON r.enforcement_result_id = v.enforcement_result_id
                    WHERE v.target_id = ? AND r.control_id = ?
                    ORDER BY v.verified_at DESC LIMIT 1
                """, (target_id, control_id))),
            ])
        else:
            stages.extend((key, title, None) for key, title in (
                ("analyze", "Analyze"), ("sandbox", "Sandbox"),
                ("approve", "Approve"), ("enforce", "Enforce"),
                ("verify", "Verify"),
            ))
        return [{"key": key, "title": title,
                 "state": record["state"] if record else None,
                 "at": record["at"] if record else None,
                 "related_id": record["related_id"] if record else None}
                for key, title, record in stages]

    def targets(self) -> list[dict]:
        with _open_read_only(self.database) as db:
            return _rows(db, """
                SELECT t.target_id, t.agent_id, t.status, t.agent_version,
                       t.created_at, t.last_seen,
                       json_extract(t.observed_metadata_json, '$.hostname') AS hostname,
                       json_extract(t.observed_metadata_json, '$.os') AS os,
                       json_extract(t.observed_metadata_json, '$.os_version') AS os_version,
                       json_extract(t.observed_metadata_json, '$.architecture') AS architecture,
                       (SELECT p.profile_id FROM profiles p WHERE p.target_id = t.target_id
                        ORDER BY p.received_at DESC, p.profile_id DESC LIMIT 1) AS latest_profile_id,
                       (SELECT p.received_at FROM profiles p WHERE p.target_id = t.target_id
                        ORDER BY p.received_at DESC, p.profile_id DESC LIMIT 1) AS latest_profile_at,
                       (SELECT v.outcome FROM post_enforcement_verifications v
                        WHERE v.target_id = t.target_id ORDER BY v.verified_at DESC LIMIT 1)
                        AS latest_verification
                FROM targets t ORDER BY t.created_at DESC LIMIT 500
            """)

    def target(self, target_id: str) -> dict | None:
        with _open_read_only(self.database) as db:
            target = db.execute("""
                SELECT t.target_id, t.agent_id, t.status, t.agent_version,
                       t.created_at, t.last_seen,
                       json_extract(t.observed_metadata_json, '$.hostname') AS hostname,
                       json_extract(t.observed_metadata_json, '$.os') AS os,
                       json_extract(t.observed_metadata_json, '$.os_version') AS os_version,
                       json_extract(t.observed_metadata_json, '$.architecture') AS architecture,
                       json_extract(t.observed_metadata_json, '$.kernel') AS kernel
                FROM targets t WHERE t.target_id = ?
            """, (target_id,)).fetchone()
            if target is None:
                return None
            detail = {
                "target": dict(target),
                "profiles": _rows(db, """
                    SELECT profile_id, collected_at, received_at, profile_sha256,
                           profiler_version, sentra_version,
                           json_extract(payload_json, '$.collection_summary.collected') AS collected,
                           json_extract(payload_json, '$.collection_summary.unavailable') AS unavailable,
                           json_extract(payload_json, '$.collection_summary.unsupported') AS unsupported,
                           json_extract(payload_json, '$.collection_summary.errors') AS errors
                    FROM profiles WHERE target_id = ? ORDER BY received_at DESC LIMIT 100
                """, (target_id,)),
                "reports": _rows(db, """
                    SELECT compatibility_report_id, profile_id, report_sha256, generated_at
                    FROM compatibility_reports WHERE target_id = ?
                    ORDER BY generated_at DESC LIMIT 100
                """, (target_id,)),
                "selected_controls": _rows(db, """
                    SELECT c.control_id, c.title, c.review_state
                    FROM m8_controls c JOIN m8_benchmarks b
                      ON b.benchmark_id = c.benchmark_id
                    WHERE c.selected = 1
                    ORDER BY b.active DESC, c.control_id LIMIT 12
                """),
                "sandboxes": _rows(db, """
                    SELECT sandbox_session_id, source_profile_id,
                           source_compatibility_report_id, control_id, status, created_at,
                           closed_at FROM sandbox_sessions WHERE source_target_id = ?
                    ORDER BY created_at DESC LIMIT 100
                """, (target_id,)),
                "deployments": _rows(db, """
                    SELECT deployment_id, control_id, deployment_state,
                           enforcement_job_id, requested_at
                    FROM m8_deployments WHERE target_id = ?
                    ORDER BY requested_at DESC LIMIT 100
                """, (target_id,)),
                "verifications": _rows(db, """
                    SELECT enforcement_result_id, profile_id, profile_sha256,
                           outcome, verified_at FROM post_enforcement_verifications
                    WHERE target_id = ? ORDER BY verified_at DESC LIMIT 100
                """, (target_id,)),
            }
            focus = self._focus(db, target_id)
            detail["focus_control_id"] = focus["control_id"] if focus else None
            detail["workflow"] = self._workflow(db, target_id, detail["focus_control_id"])
        detail["timeline"] = [event for event in self.audit()
                              if event["target_id"] == target_id][:8]
        return detail

    def controls_and_assessments(self) -> dict[str, list[dict]]:
        with _open_read_only(self.database) as db:
            return {
                "controls": _rows(db, """
                    SELECT c.benchmark_id, c.control_id, c.title, c.selected, c.review_state,
                           c.adapter_capability, b.identity, b.version, b.active
                    FROM m8_controls c JOIN m8_benchmarks b ON b.benchmark_id = c.benchmark_id
                    ORDER BY b.active DESC, c.control_id LIMIT 500
                """),
                "assessments": _rows(db, """
                    SELECT a.assessment_id, a.target_id, a.profile_id, a.state,
                           a.created_at, a.completed_at, b.identity, b.version
                    FROM m8_assessments a JOIN m8_benchmarks b ON b.benchmark_id = a.benchmark_id
                    ORDER BY a.created_at DESC LIMIT 200
                """),
                "results": _rows(db, """
                    SELECT r.assessment_result_id, r.assessment_id, r.target_id,
                           r.control_id, r.state, r.reason, r.observed_at,
                           d.decision AS compatibility_decision,
                           d.provisional, d.metadata_review_status
                    FROM m8_assessment_results r
                    LEFT JOIN m8_compatibility_decisions d
                      ON d.assessment_result_id = r.assessment_result_id
                    ORDER BY r.observed_at DESC LIMIT 500
                """),
            }

    def compatibility(self) -> list[dict]:
        with _open_read_only(self.database) as db:
            decisions = _rows(db, """
                SELECT r.compatibility_report_id, r.target_id, r.profile_id,
                       r.report_sha256, r.generated_at,
                       json_extract(c.value, '$.control_id') AS control_id,
                       json_extract(c.value, '$.result') AS decision,
                       json_extract(c.value, '$.explanation') AS explanation,
                       json_extract(c.value, '$.provisional') AS provisional,
                       json_extract(c.value, '$.metadata_review_status') AS metadata_review_status,
                       json_extract(c.value, '$.triggered_rules') AS rules_json,
                       json_extract(c.value, '$.evidence_used') AS evidence_json,
                       json_extract(c.value, '$.missing_or_contextual_evidence') AS missing_json
                FROM compatibility_reports r,
                     json_each(r.payload_json, '$.control_results') c
                ORDER BY r.generated_at DESC, control_id LIMIT 500
            """)
        import json
        for item in decisions:
            rules = json.loads(item.pop("rules_json") or "[]")
            evidence = json.loads(item.pop("evidence_json") or "[]")
            missing = json.loads(item.pop("missing_json") or "[]")
            item["reasons"] = [rule["explanation"] for rule in rules]
            item["relevant_facts"] = [row["fact"] for row in evidence]
            item["uncertainty"] = [
                {"fact": row["fact"], "state": row["status"],
                 "reason": row.get("reason")}
                for row in missing
            ]
        return decisions

    def sandboxes(self) -> list[dict]:
        with _open_read_only(self.database) as db:
            return _rows(db, """
                SELECT s.sandbox_session_id, s.source_target_id AS target_id,
                       s.source_profile_id AS profile_id, s.control_id,
                       s.provider_type, s.status, s.created_at, s.ready_at,
                       s.completed_at, s.closed_at,
                       s.failure_reason, s.quarantine_reason,
                       v.result, v.result_sha256
                FROM sandbox_sessions s LEFT JOIN m8_validation_outcomes v
                  ON v.sandbox_session_id = s.sandbox_session_id
                ORDER BY s.created_at DESC LIMIT 200
            """)

    def deployments(self) -> dict[str, list[dict]]:
        with _open_read_only(self.database) as db:
            return {
                "requests": _rows(db, """
                    SELECT d.deployment_id, d.target_id, d.control_id,
                           d.assessment_result_id, d.sandbox_session_id,
                           d.enforcement_job_id, d.deployment_state, d.requested_at,
                           a.user_id AS reviewer_id, u.username AS reviewer_username,
                           a.decision AS approval_decision, a.reason AS approval_reason,
                           a.validation_evidence_sha256,
                           (SELECT COUNT(*) FROM enforcement_jobs j
                            WHERE j.target_id=d.target_id AND j.control_id=d.control_id
                              AND j.status IN ('pending','dispatched')
                              AND j.request_id<>d.deployment_id) AS active_other_m7,
                           (SELECT COUNT(*) FROM m8_approvals a2
                            WHERE a2.deployment_id=d.deployment_id) AS approval_count,
                           CASE WHEN d.deployment_id=(
                               SELECT x.deployment_id FROM m8_deployment_requests x
                               WHERE x.assessment_result_id=d.assessment_result_id
                                 AND x.target_id=d.target_id
                                 AND x.control_id=d.control_id
                                 AND x.sandbox_session_id=d.sandbox_session_id
                               ORDER BY CASE
                                   WHEN x.enforcement_job_id IS NOT NULL THEN 0
                                   WHEN x.state='approved' THEN 1
                                   WHEN x.state='awaiting_approval' THEN 2
                                   WHEN x.state='rejected' THEN 3
                                   ELSE 4 END,
                                   x.requested_at,x.deployment_id LIMIT 1)
                             THEN 1 ELSE 0 END AS is_canonical
                    FROM m8_deployments d LEFT JOIN m8_approvals a
                      ON a.approval_id=(
                          SELECT a2.approval_id FROM m8_approvals a2
                          WHERE a2.deployment_id=d.deployment_id
                          ORDER BY a2.decided_at,a2.approval_id LIMIT 1)
                    LEFT JOIN m8_users u ON u.user_id = a.user_id
                    ORDER BY d.requested_at DESC LIMIT 200
                """),
                "eligible": _rows(db, """
                    SELECT r.assessment_result_id, r.target_id, r.control_id,
                           json_extract(t.observed_metadata_json,'$.hostname') AS hostname,
                           s.sandbox_session_id, s.source_profile_id AS profile_id
                    FROM m8_assessment_results r
                    JOIN m8_assessments a ON a.assessment_id = r.assessment_id
                    JOIN targets t ON t.target_id=r.target_id
                    JOIN m8_assessment_report_links l ON l.assessment_id = a.assessment_id
                    JOIN sandbox_sessions s ON s.source_target_id = r.target_id
                      AND s.source_profile_id = a.profile_id
                      AND s.source_compatibility_report_id = l.compatibility_report_id
                      AND s.control_id = r.control_id AND s.status = 'CLOSED'
                    JOIN m8_validation_outcomes v ON v.sandbox_session_id = s.sandbox_session_id
                    WHERE r.control_id = '7.1.1' AND v.result = 'validated'
                      AND v.status = 'COMPLETED'
                      AND NOT EXISTS (
                          SELECT 1 FROM enforcement_jobs j
                          WHERE j.target_id=r.target_id AND j.control_id=r.control_id
                            AND j.status IN ('pending','dispatched'))
                      AND NOT EXISTS (
                          SELECT 1 FROM m8_deployment_requests d
                          WHERE d.assessment_result_id=r.assessment_result_id
                            AND d.target_id=r.target_id
                            AND d.control_id=r.control_id
                            AND d.sandbox_session_id=s.sandbox_session_id)
                    ORDER BY s.closed_at DESC LIMIT 100
                """),
                "historical_m7": _rows(db, """
                    SELECT j.enforcement_job_id, j.target_id, j.control_id, j.status,
                           j.created_at, r.outcome, r.result_sha256,
                           v.outcome AS verification_outcome
                    FROM enforcement_jobs j
                    LEFT JOIN enforcement_results r ON r.enforcement_job_id = j.enforcement_job_id
                    LEFT JOIN post_enforcement_verifications v
                      ON v.enforcement_result_id = r.enforcement_result_id
                    ORDER BY j.created_at DESC LIMIT 200
                """),
                "gate_explanations": _rows(db, """
                    SELECT r.assessment_result_id,r.target_id,r.control_id,
                           a.assessment_id,a.profile_id,a.benchmark_id,
                           l.compatibility_report_id,
                           s.sandbox_session_id,s.status AS sandbox_status,
                           v.result AS validation_result,v.status AS validation_status,
                           (SELECT COUNT(*) FROM m8_deployment_requests d
                            WHERE d.assessment_result_id=r.assessment_result_id
                              AND d.sandbox_session_id=s.sandbox_session_id)
                            AS request_count,
                           (SELECT COUNT(*) FROM enforcement_jobs j
                            WHERE j.target_id=r.target_id AND j.control_id=r.control_id
                              AND j.status IN ('pending','dispatched')) AS active_m7_count
                    FROM m8_assessment_results r
                    JOIN m8_assessments a ON a.assessment_id=r.assessment_id
                    LEFT JOIN m8_assessment_report_links l ON l.assessment_id=a.assessment_id
                    LEFT JOIN sandbox_sessions s ON s.sandbox_session_id=(
                        SELECT s2.sandbox_session_id FROM sandbox_sessions s2
                        WHERE s2.source_target_id=r.target_id
                          AND s2.source_profile_id=a.profile_id
                          AND s2.source_compatibility_report_id=l.compatibility_report_id
                          AND s2.control_id=r.control_id
                        ORDER BY s2.created_at DESC,s2.rowid DESC LIMIT 1)
                    LEFT JOIN m8_validation_outcomes v
                      ON v.sandbox_session_id=s.sandbox_session_id
                    WHERE r.control_id='7.1.1'
                    ORDER BY r.observed_at DESC LIMIT 15
                """),
            }

    def evidence(self) -> list[dict]:
        with _open_read_only(self.database) as db:
            return _rows(db, """
                SELECT evidence_id, evidence_type, producer, target_id, control_id,
                       related_type, related_id, created_at, storage_reference, sha256
                FROM m8_evidence_records ORDER BY created_at DESC LIMIT 300
            """)

    def evidence_sources(self) -> dict[str, int]:
        """Count authoritative source rows without duplicating their payloads."""
        with _open_read_only(self.database) as db:
            return {
                key: int(db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0])
                for key, table in (
                    ("profiles", "profiles"),
                    ("compatibility_reports", "compatibility_reports"),
                    ("sandbox_sessions", "sandbox_sessions"),
                    ("enforcement_results", "enforcement_results"),
                    ("verifications", "post_enforcement_verifications"),
                )
            }

    def audit(self) -> list[dict]:
        """Read-only operational timeline; M8 user actions remain append-only rows.

        Historical Controller/Agent events are projected from their own source
        records, never backfilled into m8_audit_events or attributed to a user.
        """

        with _open_read_only(self.database) as db:
            events = _rows(db, """
                SELECT e.event_id, e.occurred_at, e.actor_type, e.event_type,
                       e.target_id, e.control_id, e.related_type, e.related_id,
                       e.outcome, e.reason, e.actor_user_id,
                       u.username AS actor_name, 'M8 audit' AS source
                FROM m8_audit_events e LEFT JOIN m8_users u ON u.user_id = e.actor_user_id
                ORDER BY e.occurred_at DESC LIMIT 500
            """)

            # Each query selects only immutable identifiers, timestamps and states.
            # The source tables retain authority; this projection writes nothing.
            projections = (
                ("""SELECT t.created_at AS occurred_at, 'controller' AS actor_type,
                           'target_agent_enrolled' AS event_type, t.target_id,
                           NULL AS control_id, 'target' AS related_type,
                           t.target_id AS related_id, 'enrolled' AS outcome,
                           NULL AS reason
                    FROM targets t JOIN agents a
                      ON a.target_id = t.target_id AND a.agent_id = t.agent_id
                    ORDER BY t.created_at DESC LIMIT 500""", "Controller"),
                ("""SELECT p.received_at AS occurred_at, 'agent' AS actor_type,
                           'profile_collected' AS event_type, p.target_id,
                           NULL AS control_id, 'profile' AS related_type,
                           p.profile_id AS related_id, 'stored' AS outcome,
                           NULL AS reason
                    FROM profiles p ORDER BY p.received_at DESC LIMIT 500""", "M3 profile"),
                ("""SELECT r.generated_at AS occurred_at, 'controller' AS actor_type,
                           'compatibility_report_created' AS event_type, r.target_id,
                           NULL AS control_id, 'compatibility_report' AS related_type,
                           r.compatibility_report_id AS related_id, 'stored' AS outcome,
                           NULL AS reason
                    FROM compatibility_reports r ORDER BY r.generated_at DESC LIMIT 500""", "M4 report"),
                ("""SELECT s.created_at AS occurred_at, 'controller' AS actor_type,
                           'sandbox_session_created' AS event_type,
                           s.source_target_id AS target_id, s.control_id,
                           'sandbox_session' AS related_type,
                           s.sandbox_session_id AS related_id, 'REQUESTED' AS outcome,
                           NULL AS reason
                    FROM sandbox_sessions s ORDER BY s.created_at DESC LIMIT 500""", "Sandbox session"),
                ("""SELECT s.provisioning_started_at AS occurred_at,
                           'controller' AS actor_type, 'sandbox_provisioning_started' AS event_type,
                           s.source_target_id AS target_id, s.control_id,
                           'sandbox_session' AS related_type,
                           s.sandbox_session_id AS related_id, 'PROVISIONING' AS outcome,
                           NULL AS reason
                    FROM sandbox_sessions s WHERE s.provisioning_started_at IS NOT NULL
                    ORDER BY s.provisioning_started_at DESC LIMIT 500""", "Sandbox session"),
                ("""SELECT s.ready_at AS occurred_at, 'controller' AS actor_type,
                           'sandbox_ready' AS event_type, s.source_target_id AS target_id,
                           s.control_id, 'sandbox_session' AS related_type,
                           s.sandbox_session_id AS related_id, 'READY' AS outcome,
                           NULL AS reason
                    FROM sandbox_sessions s WHERE s.ready_at IS NOT NULL
                    ORDER BY s.ready_at DESC LIMIT 500""", "Sandbox session"),
                ("""SELECT s.validation_started_at AS occurred_at,
                           'controller' AS actor_type, 'sandbox_validation_started' AS event_type,
                           s.source_target_id AS target_id, s.control_id,
                           'sandbox_session' AS related_type,
                           s.sandbox_session_id AS related_id, 'VALIDATING' AS outcome,
                           NULL AS reason
                    FROM sandbox_sessions s WHERE s.validation_started_at IS NOT NULL
                    ORDER BY s.validation_started_at DESC LIMIT 500""", "Sandbox session"),
                ("""SELECT s.completed_at AS occurred_at, 'controller' AS actor_type,
                           CASE WHEN s.quarantine_reason IS NOT NULL THEN 'sandbox_quarantined'
                                WHEN s.failure_reason IS NOT NULL THEN 'sandbox_failed'
                                ELSE 'sandbox_completed' END AS event_type,
                           s.source_target_id AS target_id, s.control_id,
                           'sandbox_session' AS related_type,
                           s.sandbox_session_id AS related_id,
                           CASE WHEN s.quarantine_reason IS NOT NULL THEN 'QUARANTINED'
                                WHEN s.failure_reason IS NOT NULL THEN 'FAILED'
                                ELSE 'COMPLETED' END AS outcome,
                           COALESCE(s.quarantine_reason, s.failure_reason) AS reason
                    FROM sandbox_sessions s WHERE s.completed_at IS NOT NULL
                    ORDER BY s.completed_at DESC LIMIT 500""", "Sandbox session"),
                ("""SELECT s.closed_at AS occurred_at, 'controller' AS actor_type,
                           'sandbox_session_closed' AS event_type,
                           s.source_target_id AS target_id, s.control_id,
                           'sandbox_session' AS related_type,
                           s.sandbox_session_id AS related_id, 'CLOSED' AS outcome,
                           COALESCE(s.quarantine_reason, s.failure_reason) AS reason
                    FROM sandbox_sessions s WHERE s.closed_at IS NOT NULL
                    ORDER BY s.closed_at DESC LIMIT 500""", "Sandbox session"),
                ("""SELECT v.completed_at AS occurred_at, 'controller' AS actor_type,
                           CASE WHEN json_extract(v.payload_json,
                             '$.report.control_results[0].result') = 'failed'
                             THEN 'sandbox_validation_failed'
                             ELSE 'sandbox_validation_completed' END AS event_type,
                           v.source_target_id AS target_id, s.control_id,
                           'sandbox_validation' AS related_type,
                           v.validation_job_id AS related_id,
                           json_extract(v.payload_json,
                             '$.report.control_results[0].result') AS outcome,
                           NULL AS reason
                    FROM sandbox_validation_executions v JOIN sandbox_sessions s
                      ON s.sandbox_session_id = v.sandbox_session_id
                    WHERE v.status = 'COMPLETED' AND v.completed_at IS NOT NULL
                    ORDER BY v.completed_at DESC LIMIT 500""", "M6 validation"),
                ("""SELECT j.created_at AS occurred_at, 'controller' AS actor_type,
                           'enforcement_job_created' AS event_type, j.target_id,
                           j.control_id, 'enforcement_job' AS related_type,
                           j.enforcement_job_id AS related_id, 'pending' AS outcome,
                           NULL AS reason
                    FROM enforcement_jobs j ORDER BY j.created_at DESC LIMIT 500""", "M7 enforcement"),
                ("""SELECT j.dispatched_at AS occurred_at, 'controller' AS actor_type,
                           'enforcement_job_dispatched' AS event_type, j.target_id,
                           j.control_id, 'enforcement_job' AS related_type,
                           j.enforcement_job_id AS related_id, 'dispatched' AS outcome,
                           NULL AS reason
                    FROM enforcement_jobs j WHERE j.dispatched_at IS NOT NULL
                    ORDER BY j.dispatched_at DESC LIMIT 500""", "M7 enforcement"),
                ("""SELECT r.received_at AS occurred_at, 'agent' AS actor_type,
                           'enforcement_result_received' AS event_type, r.target_id,
                           r.control_id, 'enforcement_result' AS related_type,
                           r.enforcement_result_id AS related_id, r.outcome,
                           NULL AS reason
                    FROM enforcement_results r ORDER BY r.received_at DESC LIMIT 500""", "M7 enforcement"),
                ("""SELECT v.verified_at AS occurred_at, 'controller' AS actor_type,
                           'post_enforcement_verification' AS event_type, v.target_id,
                           r.control_id, 'verification' AS related_type,
                           v.enforcement_result_id AS related_id, v.outcome,
                           NULL AS reason
                    FROM post_enforcement_verifications v JOIN enforcement_results r
                      ON r.enforcement_result_id = v.enforcement_result_id
                    ORDER BY v.verified_at DESC LIMIT 500""", "Fresh verification"),
                ("""SELECT d.requested_at AS occurred_at, 'controller' AS actor_type,
                           'deployment_requested' AS event_type, d.target_id,
                           d.control_id, 'deployment' AS related_type,
                           d.deployment_id AS related_id, d.state AS outcome,
                           NULL AS reason
                    FROM m8_deployment_requests d WHERE NOT EXISTS (
                      SELECT 1 FROM m8_audit_events e
                      WHERE e.related_type = 'deployment' AND e.related_id = d.deployment_id
                        AND e.event_type = 'deployment_requested')
                    ORDER BY d.requested_at DESC LIMIT 500""", "M8 request"),
                ("""SELECT a.decided_at AS occurred_at, 'user' AS actor_type,
                           CASE WHEN a.decision = 'approved' THEN 'deployment_approved'
                                ELSE 'deployment_rejected' END AS event_type,
                           a.target_id, a.control_id, 'approval' AS related_type,
                           a.approval_id AS related_id, a.decision AS outcome,
                           a.reason, a.user_id AS actor_user_id,
                           u.username AS actor_name
                    FROM m8_approvals a JOIN m8_users u ON u.user_id = a.user_id
                    WHERE NOT EXISTS (
                      SELECT 1 FROM m8_audit_events e
                      WHERE e.related_type = 'approval' AND e.related_id = a.approval_id
                        AND e.event_type IN ('deployment_approved', 'deployment_rejected'))
                    ORDER BY a.decided_at DESC LIMIT 500""", "M8 approval"),
            )
            for sql, source in projections:
                for row in _rows(db, sql):
                    row.update(event_id=None, source=source)
                    row.setdefault("actor_user_id", None)
                    row.setdefault("actor_name", None)
                    events.append(row)
            return sorted(events, key=lambda row: (row["occurred_at"], row["event_type"],
                                                   row["related_id"]), reverse=True)[:500]


__all__ = ["M8ReadModel"]
