"""Acceptance tests for the safe M6B Agent command-line boundary."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from uuid import uuid4

from pydantic import SecretStr
import pytest

from src.agent import cli
from src.agent.state import AgentStateStore
from src.controller.models import (
    EnrollmentResponse,
    HeartbeatResponse,
    JobPollResponse,
    ObservedTargetMetadata,
)


def _metadata() -> ObservedTargetMetadata:
    return ObservedTargetMetadata(
        hostname="cli-fixture",
        os="Ubuntu",
        os_version="24.04",
        kernel="6.8.0-fixture",
        architecture="x86_64",
    )


class _NoJobTransport:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.enrollment_calls = 0

    def enroll(self, request: object) -> EnrollmentResponse:
        self.enrollment_calls += 1
        raise AssertionError("an enrolled Agent must not enroll again")

    def heartbeat(self, request: object) -> HeartbeatResponse:
        return HeartbeatResponse(
            accepted=True,
            last_seen=datetime(2026, 9, 24, 10, 0, tzinfo=UTC),
        )

    def poll_jobs(self, request: object) -> JobPollResponse:
        return JobPollResponse(jobs=[])

    def submit_profile(self, request: object) -> object:
        raise AssertionError("there is no profile job")


def test_agent_help_exposes_tls_inputs_and_has_no_insecure_switch() -> None:
    help_text = cli.build_parser().format_help()

    assert "--controller-url" in help_text
    assert "--controller-ca" in help_text
    assert "--state" in help_text
    assert "--bootstrap-credential-file" in help_text
    assert cli.BOOTSTRAP_CREDENTIAL_ENV in help_text
    assert "--insecure" not in help_text
    assert "verification disabled" not in help_text


def test_bootstrap_credential_file_must_be_private_and_never_echoes_value(
    tmp_path: Path,
) -> None:
    secret = "protected-file-bootstrap-secret"
    credential_path = tmp_path / "bootstrap.secret"
    credential_path.write_text(f"{secret}\n", encoding="utf-8")
    credential_path.chmod(0o644)

    with pytest.raises(cli.AgentCredentialSourceError) as raised:
        cli._read_credential_file(credential_path)
    assert "0600" in str(raised.value)
    assert secret not in str(raised.value)

    credential_path.chmod(0o600)
    loaded = cli._read_credential_file(credential_path)
    assert loaded.get_secret_value() == secret
    assert secret not in repr(loaded)


def test_enrolled_cli_cycle_needs_no_bootstrap_source_and_prints_safe_summary(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    state_path = tmp_path / "agent-state.json"
    secret = "persisted-agent-secret-not-for-output"
    AgentStateStore(state_path).save_enrollment(
        EnrollmentResponse(
            target_id=uuid4(),
            agent_id=uuid4(),
            agent_credential=SecretStr(secret),
            polling_interval_seconds=30,
        )
    )
    monkeypatch.delenv(cli.BOOTSTRAP_CREDENTIAL_ENV, raising=False)
    monkeypatch.setattr(cli, "_observed_metadata", _metadata)
    monkeypatch.setattr(cli, "AgentHTTPSClient", _NoJobTransport)

    result = cli.main(
        [
            "--controller-url",
            "https://controller.example.test:8443",
            "--controller-ca",
            str(tmp_path / "not-opened-by-fake-client.pem"),
            "--state",
            str(state_path),
            "--bootstrap-credential-file",
            str(tmp_path / "must-not-be-read"),
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "enrolled_during_run": False,
        "heartbeat_accepted": True,
        "jobs_polled": 0,
        "profiles_submitted": 0,
    }
    assert secret not in captured.out
    assert secret not in captured.err


def test_cli_failure_does_not_print_bootstrap_credential(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    bootstrap = "environment-bootstrap-secret-not-for-output"
    monkeypatch.setenv(cli.BOOTSTRAP_CREDENTIAL_ENV, bootstrap)
    monkeypatch.setattr(cli, "_observed_metadata", _metadata)

    result = cli.main(
        [
            "--controller-url",
            "https://controller.example.test:8443",
            "--controller-ca",
            str(tmp_path / "missing-ca.pem"),
            "--state",
            str(tmp_path / "new-state.json"),
        ]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "CA bundle does not exist" in captured.err
    assert bootstrap not in captured.err
    assert bootstrap not in captured.out
