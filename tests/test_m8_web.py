from __future__ import annotations

from pathlib import Path

import pytest

from src.controller.storage import SQLiteControllerRepository
from src.m8db.migrations import apply_migrations
from src.m8web import (
    M8WebConfigurationError,
    M8WebSettings,
    create_app,
)


def _valid_database(tmp_path: Path) -> Path:
    database = tmp_path / "controller.sqlite3"

    SQLiteControllerRepository(database)
    apply_migrations(database)

    return database


def test_settings_require_absolute_database_path() -> None:
    with pytest.raises(
        M8WebConfigurationError,
        match="must be absolute",
    ):
        M8WebSettings(
            database=Path("controller.sqlite3"),
        )


def test_health_reports_valid_m8_database(
    tmp_path: Path,
) -> None:
    database = _valid_database(tmp_path)

    app = create_app(
        M8WebSettings(database=database)
    )

    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200

    payload = response.get_json()

    assert payload["service"] == "sentra-m8"
    assert payload["status"] == "ok"
    assert payload["database"]["ok"] is True
    assert payload["database"]["sqlite_integrity"] == "ok"
    assert (
        payload["database"]["foreign_key_violations"]
        == 0
    )


def test_status_is_read_only_and_bounded(
    tmp_path: Path,
) -> None:
    database = _valid_database(tmp_path)

    app = create_app(
        M8WebSettings(database=database)
    )

    client = app.test_client()

    response = client.get("/api/status")

    assert response.status_code == 200

    payload = response.get_json()

    assert payload["service"] == "sentra-m8"
    assert payload["status"] == "ok"

    assert payload["counts"]["targets"] == 0
    assert payload["counts"]["profiles"] == 0
    assert payload["counts"]["enforcement_jobs"] == 0
    assert payload["counts"]["m8_assessments"] == 0

    assert payload["enforcement_outcomes"] == {}
    assert payload["verification_outcomes"] == {}


def test_status_does_not_accept_post(
    tmp_path: Path,
) -> None:
    database = _valid_database(tmp_path)

    app = create_app(
        M8WebSettings(database=database)
    )

    client = app.test_client()

    response = client.post("/api/status")

    assert response.status_code == 405


def test_health_fails_closed_for_invalid_database(
    tmp_path: Path,
) -> None:
    database = tmp_path / "broken.sqlite3"
    database.write_bytes(b"not-a-sqlite-database")

    app = create_app(
        M8WebSettings(database=database)
    )

    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 503

    payload = response.get_json()

    assert payload == {
        "service": "sentra-m8",
        "status": "unhealthy",
        "database": {
            "ok": False,
        },
    }
