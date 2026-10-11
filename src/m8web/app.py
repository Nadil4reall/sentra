"""Flask application factory for SENTRA M8."""

from __future__ import annotations

from flask import Flask, jsonify

from .config import M8WebSettings
from .status import database_health, system_status


def create_app(settings: M8WebSettings) -> Flask:
    """Create one M8 Flask application without global mutable state."""

    app = Flask(__name__)

    app.config.update(
        TESTING=False,
        JSON_SORT_KEYS=False,
    )

    app.json.sort_keys = False

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
