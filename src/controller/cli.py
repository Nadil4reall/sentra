"""Command-line entry point for the TLS-only SENTRA M6B Controller."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import ssl
import stat
import sys
from typing import Mapping, Sequence

from pydantic import SecretStr, ValidationError

from src.controller.storage import ControllerStorageSecurityError
from src.controller.transport import ControllerTransportConfig, create_https_server


DEFAULT_BOOTSTRAP_ENV = "SENTRA_CONTROLLER_BOOTSTRAP_CREDENTIAL"
DEFAULT_ADMIN_ENV = "SENTRA_CONTROLLER_ADMIN_CREDENTIAL"
_MAX_CREDENTIAL_FILE_BYTES = 16 * 1024


class ControllerCLIConfigurationError(RuntimeError):
    """A credential source or CLI runtime option was unsafe or unavailable."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the SENTRA M6B Controller over authenticated HTTPS.",
    )
    parser.add_argument("--listen-host", required=True)
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--tls-certificate", required=True, type=Path)
    parser.add_argument("--tls-private-key", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument(
        "--polling-interval-seconds",
        type=int,
        default=30,
    )
    parser.add_argument("--max-jobs-per-poll", type=int, default=10)
    parser.add_argument(
        "--max-request-bytes",
        type=int,
        default=8 * 1024 * 1024,
    )

    bootstrap = parser.add_mutually_exclusive_group()
    bootstrap.add_argument(
        "--bootstrap-credential-env",
        default=DEFAULT_BOOTSTRAP_ENV,
        metavar="NAME",
        help=(
            "environment variable containing the enrollment credential "
            f"(default: {DEFAULT_BOOTSTRAP_ENV})"
        ),
    )
    bootstrap.add_argument(
        "--bootstrap-credential-file",
        type=Path,
        metavar="PATH",
        help="current-user-owned protected file containing the enrollment credential",
    )

    admin = parser.add_mutually_exclusive_group()
    admin.add_argument(
        "--admin-credential-env",
        default=DEFAULT_ADMIN_ENV,
        metavar="NAME",
        help=(
            "environment variable containing the administrator credential "
            f"(default: {DEFAULT_ADMIN_ENV})"
        ),
    )
    admin.add_argument(
        "--admin-credential-file",
        type=Path,
        metavar="PATH",
        help="current-user-owned protected file containing the administrator credential",
    )
    return parser


def _credential_from_file(path: Path) -> SecretStr:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ControllerCLIConfigurationError(
            "credential file could not be opened safely"
        ) from error
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ControllerCLIConfigurationError(
                "credential source must be a regular file"
            )
        if file_stat.st_uid != os.geteuid():
            raise ControllerCLIConfigurationError(
                "credential file must be owned by the current user"
            )
        if stat.S_IMODE(file_stat.st_mode) & 0o077:
            raise ControllerCLIConfigurationError(
                "credential file must not be group/world accessible"
            )
        if file_stat.st_size > _MAX_CREDENTIAL_FILE_BYTES:
            raise ControllerCLIConfigurationError("credential file is too large")
        raw = os.read(descriptor, _MAX_CREDENTIAL_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise ControllerCLIConfigurationError(
            "credential file must contain UTF-8 text"
        ) from error
    if not value.strip():
        raise ControllerCLIConfigurationError("credential must not be blank")
    return SecretStr(value)


def _credential_from_environment(
    variable_name: str,
    environ: Mapping[str, str],
) -> SecretStr:
    if not variable_name.strip():
        raise ControllerCLIConfigurationError(
            "credential environment variable name must not be blank"
        )
    value = environ.get(variable_name)
    if value is None or not value.strip():
        raise ControllerCLIConfigurationError(
            f"required credential environment variable {variable_name!r} is unset"
        )
    return SecretStr(value)


def config_from_args(
    args: argparse.Namespace,
    *,
    environ: Mapping[str, str] | None = None,
) -> ControllerTransportConfig:
    environment = os.environ if environ is None else environ
    bootstrap = (
        _credential_from_file(args.bootstrap_credential_file)
        if args.bootstrap_credential_file is not None
        else _credential_from_environment(args.bootstrap_credential_env, environment)
    )
    admin = (
        _credential_from_file(args.admin_credential_file)
        if args.admin_credential_file is not None
        else _credential_from_environment(args.admin_credential_env, environment)
    )
    return ControllerTransportConfig(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        tls_certificate_path=args.tls_certificate,
        tls_private_key_path=args.tls_private_key,
        database_path=args.database,
        bootstrap_credential=bootstrap,
        admin_credential=admin,
        polling_interval_seconds=args.polling_interval_seconds,
        max_jobs_per_poll=args.max_jobs_per_poll,
        max_request_bytes=args.max_request_bytes,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        config = config_from_args(parser.parse_args(argv))
        server = create_https_server(config)
    except (
        ControllerCLIConfigurationError,
        ControllerStorageSecurityError,
        OSError,
        ValueError,
        ValidationError,
        ssl.SSLError,
    ) as error:
        print(f"Controller startup refused: {error}", file=sys.stderr)
        return 2

    bound_host, bound_port = server.server_address[:2]
    print(f"SENTRA Controller listening on https://{bound_host}:{bound_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via module entry point
    raise SystemExit(main())


__all__ = [
    "ControllerCLIConfigurationError",
    "build_parser",
    "config_from_args",
    "main",
]
