"""Manage the same protected SQLite file passed to the Controller --database."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
from typing import Sequence

from src.controller.storage import ControllerStorageSecurityError
from .migrations import MigrationError, apply_migrations, check_db


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SENTRA Controller database foundation")
    parser.add_argument(
        "--database", required=True, type=Path,
        help="the exact protected SQLite path used by Controller --database",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("init", help="initialize or upgrade without creating records")
    actions.add_parser("check", help="read-only integrity and foreign-key check")
    actions.add_parser("migrations", help="read-only migration status")
    args = parser.parse_args(argv)
    try:
        if args.action == "init":
            changed = apply_migrations(args.database)
            report = check_db(args.database)
            print(json.dumps({"applied_migrations": changed, **report}))
        else:
            report = check_db(args.database)
            if args.action == "migrations":
                report = {key: report[key] for key in (
                    "ok", "migration_versions", "migration_mismatches", "unknown_versions",
                )}
            print(json.dumps(report))
        return 0 if report["ok"] else 2
    except (MigrationError, ControllerStorageSecurityError, OSError, sqlite3.Error) as error:
        parser.exit(2, f"Database operation refused: {type(error).__name__}\n")


if __name__ == "__main__":
    raise SystemExit(main())
