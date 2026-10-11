"""Explicit local administrator bootstrap; never runs at web startup."""

from __future__ import annotations

import argparse
from getpass import getpass
import os
from pathlib import Path
import stat

from src.m8db.migrations import check_db
from src.m8db.repository import M8Repository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create one SENTRA M8 web administrator")
    parser.add_argument("--database", required=True, help="Canonical Controller SQLite path")
    parser.add_argument("create-admin", choices=["create-admin"])
    parser.add_argument("--username", required=True)
    args = parser.parse_args(argv)
    database = Path(args.database)
    if not database.is_absolute():
        parser.error("database path must be absolute")
    try:
        metadata = os.lstat(database)
    except OSError:
        parser.error("database must already exist")
    if not stat.S_ISREG(metadata.st_mode):
        parser.error("database must be an existing regular file, not a symlink")
    try:
        health = check_db(database)
    except Exception:
        parser.error("database health check failed")
    if not health["ok"]:
        parser.error("database is not a healthy SENTRA M8 database")
    password = getpass("New password: ")
    if password != getpass("Confirm password: "):
        parser.error("password confirmation did not match")
    repo = M8Repository(database)
    user = repo.create_user(username=args.username, password=password, role_name="admin")
    print(f"Created administrator {user['username']} ({user['user_id']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
