"""M9 Controller schema migration and fail-closed constraint tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from src.controller import storage as controller_storage
from src.controller.storage import (
    ControllerStorageSecurityError,
    SQLiteControllerRepository,
)
from src.m8db.migrations import apply_migrations, check_db


def _downgrade_m9_to_pre_m9(database: Path) -> None:
    """Build a genuine pre-M9 Controller fixture while preserving all rows.

    The current repository creates an M9 database immediately. Historical
    migration tests must therefore downgrade all five M9 control-constrained
    tables together and remove the M9 marker before simulating an older
    M6/M7 schema. Partial downgrades are intentionally rejected by production.
    """

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")

        marker = connection.execute(
            "SELECT version, name FROM controller_schema_migrations"
        ).fetchall()
        assert marker == [(9, "m9_two_control_constraints")]

        snapshots: dict[str, tuple[list[tuple], int]] = {}

        for table in controller_storage._M9_CONTROL_SCHEMAS:
            schema_row = connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type='table' AND name=?",
                (table,),
            ).fetchone()

            assert schema_row is not None
            assert isinstance(schema_row[0], str)
            assert (
                controller_storage._normalized_schema_sql(schema_row[0])
                == controller_storage._normalized_schema_sql(
                    controller_storage._m9_expected_schema(table)
                )
            )

            cursor = connection.execute(f"SELECT * FROM {table}")
            rows = cursor.fetchall()
            width = len(cursor.description or ())
            snapshots[table] = (rows, width)

        for table, (
            old_sql,
            _new_sql,
        ) in controller_storage._M9_CONTROL_SCHEMAS.items():
            rows, width = snapshots[table]

            connection.execute(f"DROP TABLE {table}")
            connection.execute(old_sql)

            if rows:
                placeholders = ",".join("?" for _ in range(width))
                connection.executemany(
                    f"INSERT INTO {table} VALUES ({placeholders})",
                    rows,
                )

            assert (
                connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
                == len(rows)
            )

        connection.execute("DROP TABLE controller_schema_migrations")

        assert connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0] == "ok"

        assert connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall() == []


def test_fresh_controller_database_has_one_idempotent_m9_migration(
    tmp_path: Path,
) -> None:
    database = tmp_path / "controller.sqlite3"
    SQLiteControllerRepository(database)
    SQLiteControllerRepository(database)

    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT version, name FROM controller_schema_migrations"
        ).fetchall()
        assert rows == [(9, "m9_two_control_constraints")]
        for table in controller_storage._M9_CONTROL_SCHEMAS:
            schema = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()[0]
            assert "control_id IN ('7.1.1', '3.3.1')" in schema
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        for table in ("targets", "profiles", "validation_jobs", "enforcement_jobs"):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_mixed_or_tampered_m9_schema_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "controller.sqlite3"
    SQLiteControllerRepository(database)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("DROP TABLE validation_results")
        connection.execute(controller_storage._CREATE_VALIDATION_RESULTS_SQL)

    with pytest.raises(ControllerStorageSecurityError, match="mixed"):
        SQLiteControllerRepository(database)


def test_m9_migration_preserves_existing_m8_views(tmp_path: Path) -> None:
    database = tmp_path / "controller.sqlite3"
    SQLiteControllerRepository(database)
    apply_migrations(database)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        for table, (old_sql, _new_sql) in controller_storage._M9_CONTROL_SCHEMAS.items():
            connection.execute(f"DROP TABLE {table}")
            connection.execute(old_sql)
        connection.execute("DROP TABLE controller_schema_migrations")

    SQLiteControllerRepository(database)

    assert check_db(database)["ok"] is True
