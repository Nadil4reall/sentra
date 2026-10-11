"""Additive M8 migrations for the existing protected Controller SQLite file."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
from typing import Iterator

from src.controller.storage import SQLiteControllerRepository


MIGRATION_DIR = Path(__file__).resolve().parent / "sql"
_EXPECTED_TABLES = frozenset({
    "targets", "agents", "jobs", "profiles", "compatibility_reports",
    "sandbox_sessions", "validation_jobs", "validation_results",
    "sandbox_validation_executions", "enforcement_jobs", "enforcement_results",
    "post_enforcement_verifications", "m8_schema_migrations", "m8_benchmarks",
    "m8_controls", "m8_users", "m8_roles", "m8_user_roles",
    "m8_assessments", "m8_assessment_results", "m8_assessment_report_links",
    "m8_deployment_requests", "m8_approvals", "m8_evidence_records",
    "m8_audit_events",
})
_EXPECTED_TRIGGERS = frozenset({
    "m8_evidence_no_update", "m8_evidence_no_delete",
    "m8_audit_no_update", "m8_audit_no_delete",
    "m8_approval_no_update", "m8_approval_no_delete",
    "m8_assessment_result_no_update", "m8_assessment_result_no_delete",
    "m8_report_link_no_update", "m8_report_link_no_delete",
})
_EXPECTED_VIEWS = frozenset({
    "m8_compatibility_decisions", "m8_validation_outcomes",
    "m8_deployments", "m8_verifications",
})


class MigrationError(RuntimeError):
    """Migration or integrity validation failed closed."""


def _migrations() -> list[tuple[int, str, str, str]]:
    found: list[tuple[int, str, str, str]] = []
    for path in sorted(MIGRATION_DIR.glob("[0-9][0-9][0-9]_*.sql")):
        version = int(path.name[:3])
        sql = path.read_text(encoding="utf-8")
        digest = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        found.append((version, path.stem, sql, digest))
    if not found or len({item[0] for item in found}) != len(found):
        raise MigrationError("migration sequence is missing or ambiguous")
    return found


def _statements(sql: str) -> Iterator[str]:
    pending = ""
    for line in sql.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            yield pending
            pending = ""
    if pending.strip():
        raise MigrationError("migration contains incomplete SQL")


def _applied(connection: sqlite3.Connection) -> dict[int, tuple[str, str]]:
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
        "AND name = 'm8_schema_migrations'"
    ).fetchone()
    if exists is None:
        return {}
    return {
        row["version"]: (row["name"], row["checksum"])
        for row in connection.execute(
            "SELECT version, name, checksum FROM m8_schema_migrations"
        )
    }


@contextmanager
def open_db(database_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Use Controller path/permission checks and close connections deterministically."""

    repository = SQLiteControllerRepository(database_path)
    with repository._connection() as connection, connection:
        yield connection


def apply_migrations(database_path: str | Path) -> list[int]:
    """Initialize M1–M7 if needed, then add only missing M8 tables atomically."""

    migrations = _migrations()
    applied_now: list[int] = []
    with open_db(database_path) as connection:
        existing = _applied(connection)
        expected = {version for version, _, _, _ in migrations}
        if set(existing) - expected:
            raise MigrationError("unknown newer migration exists")
        for version, name, sql, digest in migrations:
            if version in existing:
                if existing[version] != (name, digest):
                    raise MigrationError("applied migration checksum or name changed")
                continue
            try:
                connection.execute("BEGIN IMMEDIATE")
                for statement in _statements(sql):
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO m8_schema_migrations "
                    "(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                    (version, name, digest, datetime.now(UTC).isoformat()),
                )
                connection.commit()
            except (sqlite3.Error, MigrationError) as error:
                connection.rollback()
                raise MigrationError(f"migration {version} failed without partial M8 changes") from error
            applied_now.append(version)
    return applied_now


def _read_only_connection(database_path: str | Path) -> sqlite3.Connection:
    path = Path(os.path.abspath(os.fspath(database_path)))
    current = Path(path.anchor)
    for part in path.parent.parts[1:]:
        current /= part
        try:
            ancestor = os.lstat(current)
        except FileNotFoundError as error:
            raise MigrationError("Controller database parent does not exist") from error
        if not stat.S_ISDIR(ancestor.st_mode):
            raise MigrationError("Controller database parent is not a real directory")
    parent = os.lstat(path.parent)
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o022:
        raise MigrationError("Controller database parent is not protected")
    try:
        item = os.lstat(path)
    except FileNotFoundError as error:
        raise MigrationError("Controller database does not exist") from error
    if (
        not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) != 0o600
    ):
        raise MigrationError("Controller database file must be current-user-owned mode 0600")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _schema_fingerprint(connection: sqlite3.Connection) -> dict[str, str]:
    return {
        row[0]: " ".join(row[1].split())
        for row in connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE name LIKE 'm8_%' "
            "AND type IN ('table', 'index', 'trigger', 'view') AND sql IS NOT NULL"
        )
    }


def _expected_schema(migrations: list[tuple[int, str, str, str]]) -> dict[str, str]:
    reference = sqlite3.connect(":memory:")
    try:
        for _, _, sql, _ in migrations:
            for statement in _statements(sql):
                reference.execute(statement)
        return _schema_fingerprint(reference)
    finally:
        reference.close()


def check_db(database_path: str | Path) -> dict[str, object]:
    """Read-only SQLite, FK, migration and required-table integrity report."""

    migrations = _migrations()
    expected_schema = _expected_schema(migrations)
    connection = _read_only_connection(database_path)
    try:
        applied = _applied(connection)
        expected = {version: (name, digest) for version, name, _, digest in migrations}
        mismatch = sorted(version for version in expected if applied.get(version) != expected[version])
        unknown = sorted(set(applied) - set(expected))
        tables = {
            row["name"] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        missing_tables = sorted(_EXPECTED_TABLES - tables)
        views = {
            row["name"] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'view'"
            )
        }
        missing_views = sorted(_EXPECTED_VIEWS - views)
        triggers = {
            row["name"] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            )
        }
        missing_triggers = sorted(_EXPECTED_TRIGGERS - triggers)
        actual_schema = _schema_fingerprint(connection)
        schema_mismatches = sorted(
            key for key in expected_schema.keys() | actual_schema.keys()
            if expected_schema.get(key) != actual_schema.get(key)
        )
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_key_violations = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        return {
            "ok": not (mismatch or unknown or missing_tables or missing_views
                       or missing_triggers
                       or schema_mismatches
                       or foreign_key_violations)
            and integrity == "ok",
            "migration_versions": sorted(applied),
            "migration_mismatches": mismatch,
            "unknown_versions": unknown,
            "missing_tables": missing_tables,
            "missing_views": missing_views,
            "missing_triggers": missing_triggers,
            "schema_mismatches": schema_mismatches,
            "sqlite_integrity": integrity,
            "foreign_key_violations": foreign_key_violations,
            "tables": sorted(tables - {"sqlite_sequence"}),
        }
    finally:
        connection.close()


__all__ = ["MigrationError", "apply_migrations", "check_db", "open_db"]
