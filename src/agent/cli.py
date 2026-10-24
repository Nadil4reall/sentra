"""Command-line entry point for one safe M6B/M6D Agent execution cycle."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import errno
import json
import os
from pathlib import Path
import stat
import sys

from pydantic import SecretStr, ValidationError

from src.agent.config import AgentRuntimeConfig, AgentTransportConfig
from src.agent.profiler import LocalTargetProfiler
from src.agent.protocol import AgentProtocol
from src.agent.runtime import AgentRuntime, AgentRuntimeError
from src.agent.state import AgentStateError, AgentStateStore
from src.agent.transport import AgentHTTPSClient, AgentTransportError
from src.agent.validation import LocalSandboxControlValidator
from src.agent.validation_journal import ValidationJournalStore
from src.agent.enforcement_journal import EnforcementJournalError, EnforcementJournalStore
from src.agent.enforcement import EnforcementPreflightError
from src.agent.enforcement_execute import EnforcementExecutionError
from src.controller.models import ObservedTargetMetadata
from src.target_profiler.profiler import inspect_local_target


BOOTSTRAP_CREDENTIAL_ENV = "SENTRA_AGENT_BOOTSTRAP_CREDENTIAL"
_MAX_CREDENTIAL_BYTES = 64 * 1024


class AgentCredentialSourceError(RuntimeError):
    """A bootstrap credential source does not meet the local safety contract."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one TLS-verified SENTRA Agent cycle: enroll if needed, "
            "heartbeat, poll constrained jobs, and submit validated evidence"
        )
    )
    parser.add_argument(
        "--controller-url",
        required=True,
        help="HTTPS Controller origin or /api/v1 URL (HTTPS is mandatory)",
    )
    parser.add_argument(
        "--controller-ca",
        required=True,
        type=Path,
        help="trusted PEM CA bundle used to verify the Controller certificate",
    )
    parser.add_argument(
        "--state",
        required=True,
        type=Path,
        help="persistent local Agent state file (created atomically as mode 0600)",
    )
    parser.add_argument(
        "--bootstrap-credential-file",
        type=Path,
        help=(
            "mode-0600 file used only for first enrollment; otherwise use the "
            f"{BOOTSTRAP_CREDENTIAL_ENV} environment variable"
        ),
    )
    parser.add_argument(
        "--agent-version",
        default="m6b-poc",
        help="Agent implementation version recorded by the Controller",
    )
    parser.add_argument(
        "--profiler-version",
        default="m3",
        help="existing target-profiler version recorded with submitted evidence",
    )
    parser.add_argument(
        "--sentra-version",
        default="m6b-poc",
        help="SENTRA version recorded with submitted evidence",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="per-request HTTPS timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--sandbox-validation-ack",
        action="store_true",
        help=(
            "locally acknowledge that this host is the dedicated M5 sandbox "
            "for this Agent cycle; this is separate from Controller administrator "
            "approval and does not select a control or action"
        ),
    )
    parser.add_argument(
        "--retry-interrupted-enforcement",
        action="store_true",
        help=(
            "explicitly retry a fixed 7.1.1 enforcement journal left EXECUTING "
            "only when current metadata still equals its approved original state"
        ),
    )
    return parser


def _read_credential_file(path: Path) -> SecretStr:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        expected = os.lstat(absolute)
    except FileNotFoundError:
        raise AgentCredentialSourceError(
            "bootstrap credential file does not exist"
        ) from None
    if stat.S_ISLNK(expected.st_mode):
        raise AgentCredentialSourceError(
            "bootstrap credential file must not be a symlink"
        )
    if not stat.S_ISREG(expected.st_mode):
        raise AgentCredentialSourceError(
            "bootstrap credential file must be a regular file"
        )
    if stat.S_IMODE(expected.st_mode) != 0o600:
        raise AgentCredentialSourceError(
            "bootstrap credential file permissions must be 0600"
        )
    if hasattr(os, "geteuid") and expected.st_uid != os.geteuid():
        raise AgentCredentialSourceError(
            "bootstrap credential file must be owned by the current user"
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise AgentCredentialSourceError(
                "bootstrap credential file must not be a symlink"
            ) from None
        raise AgentCredentialSourceError(
            "bootstrap credential file could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != expected.st_dev
            or opened.st_ino != expected.st_ino
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise AgentCredentialSourceError(
                "bootstrap credential file changed while opening"
            )
        raw = os.read(descriptor, _MAX_CREDENTIAL_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_CREDENTIAL_BYTES:
        raise AgentCredentialSourceError(
            "bootstrap credential file exceeds the size limit"
        )
    try:
        value = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        raise AgentCredentialSourceError(
            "bootstrap credential file is not valid UTF-8"
        ) from None
    if not value.strip():
        raise AgentCredentialSourceError("bootstrap credential is empty")
    return SecretStr(value)


def _bootstrap_credential(path: Path | None) -> SecretStr:
    if path is not None:
        return _read_credential_file(path)
    value = os.environ.get(BOOTSTRAP_CREDENTIAL_ENV)
    if value is None or not value.strip():
        raise AgentCredentialSourceError(
            "first enrollment requires a protected bootstrap credential source"
        )
    return SecretStr(value)


def _observed_metadata() -> ObservedTargetMetadata:
    target = inspect_local_target()
    return ObservedTargetMetadata(
        hostname=target.hostname,
        os=target.os,
        os_version=target.os_version or "unknown",
        kernel=target.kernel,
        architecture=target.architecture,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        transport_config = AgentTransportConfig(
            controller_url=args.controller_url,
            controller_ca_path=args.controller_ca,
            request_timeout_seconds=args.timeout,
        )
        runtime_config = AgentRuntimeConfig(
            transport=transport_config,
            state_path=args.state,
            agent_version=args.agent_version,
            profiler_version=args.profiler_version,
            sentra_version=args.sentra_version,
        )
        protocol = AgentProtocol(
            AgentStateStore(runtime_config.state_path),
            observed_metadata=_observed_metadata(),
            agent_version=runtime_config.agent_version,
        )
        credential = (
            None
            if protocol.state.is_enrolled
            else _bootstrap_credential(args.bootstrap_credential_file)
        )
        runtime = AgentRuntime(
            protocol=protocol,
            transport=AgentHTTPSClient(runtime_config.transport),
            profiler=LocalTargetProfiler(),
            bootstrap_credential=credential,
            profiler_version=runtime_config.profiler_version,
            sentra_version=runtime_config.sentra_version,
            control_validator=LocalSandboxControlValidator(),
            validation_journal=ValidationJournalStore.for_agent_state(
                runtime_config.state_path
            ),
            enforcement_journal=EnforcementJournalStore.for_agent_state(
                runtime_config.state_path
            ),
            sandbox_validation_acknowledged=args.sandbox_validation_ack,
            retry_interrupted_enforcement=args.retry_interrupted_enforcement,
            enforcement_result_submission_enabled=True,
        )
        result = runtime.run_once()
    except (
        AgentCredentialSourceError,
        AgentRuntimeError,
        EnforcementJournalError,
        EnforcementPreflightError,
        EnforcementExecutionError,
        AgentStateError,
        AgentTransportError,
        ValidationError,
        ValueError,
    ) as error:
        print(f"Agent cycle failed: {error}", file=sys.stderr)
        return 1

    print(json.dumps(asdict(result), sort_keys=True))
    return 0


__all__ = ["BOOTSTRAP_CREDENTIAL_ENV", "build_parser", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
