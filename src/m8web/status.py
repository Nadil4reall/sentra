"""Read-only status model for the SENTRA M8 dashboard."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from urllib.parse import quote

from src.m8db.migrations import check_db


class M8StatusError(RuntimeError):
    """Raised when M8 status cannot be safely derived."""


_COUNT_TABLES = (
    "targets",
    "agents",
    "profiles",
    "compatibility_reports",
    "sandbox_sessions",
    "sandbox_validation_executions",
    "enforcement_jobs",
    "enforcement_results",
    "post_enforcement_verifications",
    "m8_benchmarks",
    "m8_controls",
    "m8_users",
    "m8_assessments",
    "m8_assessment_results",
    "m8_deployment_requests",
    "m8_approvals",
    "m8_evidence_records",
    "m8_audit_events",
)


def _open_read_only(database: Path) -> sqlite3.Connection:
    encoded = quote(str(database), safe="/")
    uri = f"file:{encoded}?mode=ro"

    connection = sqlite3.connect(
        uri,
        uri=True,
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def database_health(database: Path) -> dict[str, object]:
    """Return only bounded M8 database health information."""

    report = check_db(database)

    return {
        "ok": bool(report["ok"]),
        "migration_versions": list(
            report["migration_versions"]
        ),
        "sqlite_integrity": report["sqlite_integrity"],
        "foreign_key_violations": int(
            report["foreign_key_violations"]
        ),
        "missing_tables": list(report["missing_tables"]),
        "missing_views": list(report["missing_views"]),
        "missing_triggers": list(report["missing_triggers"]),
        "schema_mismatches": list(
            report["schema_mismatches"]
        ),
    }


def system_status(database: Path) -> dict[str, object]:
    """Read a bounded status snapshot without mutating Controller state."""

    health = database_health(database)

    if not health["ok"]:
        raise M8StatusError(
            "M8 database health check failed"
        )

    counts: dict[str, int] = {}

    with _open_read_only(database) as connection:
        for table in _COUNT_TABLES:
            row = connection.execute(
                f"SELECT COUNT(*) AS count FROM {table}"
            ).fetchone()

            if row is None:
                raise M8StatusError(
                    "could not read M8 status"
                )

            counts[table] = int(row["count"])

        enforcement_rows = connection.execute(
            """
            SELECT outcome, COUNT(*) AS count
            FROM enforcement_results
            GROUP BY outcome
            ORDER BY outcome
            """
        ).fetchall()

        verification_rows = connection.execute(
            """
            SELECT outcome, COUNT(*) AS count
            FROM post_enforcement_verifications
            GROUP BY outcome
            ORDER BY outcome
            """
        ).fetchall()

    enforcement_outcomes = {
        str(row["outcome"]): int(row["count"])
        for row in enforcement_rows
    }

    verification_outcomes = {
        str(row["outcome"]): int(row["count"])
        for row in verification_rows
    }

    return {
        "database": health,
        "counts": counts,
        "enforcement_outcomes": enforcement_outcomes,
        "verification_outcomes": verification_outcomes,
    }


__all__ = [
    "M8StatusError",
    "database_health",
    "system_status",
]
