"""Development entry point for the SENTRA M8 web application."""

from __future__ import annotations

import argparse
from pathlib import Path

from .app import create_app
from .config import M8WebSettings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the SENTRA M8 web foundation"
    )

    parser.add_argument(
        "--database",
        required=True,
        help="Absolute path to the canonical Controller SQLite database",
    )

    parser.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="Development bind address (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--listen-port",
        type=int,
        default=8080,
        help="Development port (default: 8080)",
    )

    args = parser.parse_args()

    settings = M8WebSettings(
        database=Path(args.database).expanduser(),
    )

    app = create_app(settings)

    app.run(
        host=args.listen_host,
        port=args.listen_port,
        debug=False,
        use_reloader=False,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
