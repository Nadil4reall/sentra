"""Development entry point for the SENTRA M8 web application."""

from __future__ import annotations

import argparse
from pathlib import Path

from .app import create_app
from .config import M8WebSettings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the SENTRA M8 research web interface"
    )

    parser.add_argument(
        "--secret-key-file",
        required=True,
        help="Absolute path to a current-user-owned mode-0600 file containing 32–256 random bytes",
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
    parser.add_argument(
        "--insecure-cookie-for-local-http",
        action="store_true",
        help="Permit non-Secure cookies only for 127.0.0.1/localhost development HTTP",
    )

    args = parser.parse_args()
    if args.listen_host not in {
        "127.0.0.1", "localhost", "::1",
    }:
        parser.error("the development server may bind only to loopback")

    settings = M8WebSettings(
        database=Path(args.database).expanduser(),
        secret_key_file=Path(args.secret_key_file).expanduser(),
        secure_cookie=not args.insecure_cookie_for_local_http,
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
