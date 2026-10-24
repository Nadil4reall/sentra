"""Focused tests for the M6A local agent identity/protocol boundary."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretStr

from src.agent import (
    AgentAlreadyEnrolledError,
    AgentEnrollmentError,
    AgentNotEnrolledError,
    AgentProtocol,
    AgentStateError,
    AgentStateSecurityError,
    AgentStateStore,
    AgentTransportConfig,
)
from src.controller.models import EnrollmentResponse, ObservedTargetMetadata
from src.target_profiler.models import (
    CollectionSummary,
    FactResult,
    FactStatus,
    TargetInfo,
    TargetProfile,
)


def _metadata(hostname: str = "observed-host") -> ObservedTargetMetadata:
    return ObservedTargetMetadata(
        hostname=hostname,
        os="Ubuntu",
        os_version="24.04",
        kernel="6.8.0-test",
        architecture="x86_64",
    )


def _enrollment() -> EnrollmentResponse:
    return EnrollmentResponse(
        target_id=uuid4(),
        agent_id=uuid4(),
        agent_credential=SecretStr("per-agent-secret"),
        polling_interval_seconds=30,
    )


def _profile(hostname: str = "observed-host") -> TargetProfile:
    fact = FactResult(
        name="ssh_installed",
        status=FactStatus.COLLECTED,
        value=True,
        requested_by=["5.1.20"],
    )
    return TargetProfile(
        collected_at=datetime(2026, 9, 23, 5, 0, tzinfo=UTC),
        target=TargetInfo(
            hostname=hostname,
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-test",
            architecture="x86_64",
            supported=True,
        ),
        facts={fact.name: fact},
        collection_summary=CollectionSummary(
            requested=1,
            collected=1,
            unavailable=0,
            unsupported=0,
            errors=0,
        ),
    )


def test_installation_identity_and_enrollment_survive_restart(tmp_path: Path) -> None:
    state_path = tmp_path / "agent" / "state.json"
    first_store = AgentStateStore(state_path)
    initial = first_store.load_or_create()

    assert initial.is_enrolled is False
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600

    response = _enrollment()
    enrolled = first_store.save_enrollment(response)
    restarted = AgentStateStore(state_path).load_or_create()

    assert restarted.installation_id == initial.installation_id
    assert restarted == enrolled
    assert restarted.target_id == response.target_id
    assert restarted.agent_id == response.agent_id
    assert restarted.agent_credential is not None
    assert restarted.agent_credential.get_secret_value() == "per-agent-secret"
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600


def test_observed_hostname_is_metadata_not_persistent_identity(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    first = AgentProtocol(
        AgentStateStore(state_path),
        observed_metadata=_metadata("first-observed-name"),
        agent_version="6.0.0",
    )
    installation_id = first.state.installation_id

    restarted = AgentProtocol(
        AgentStateStore(state_path),
        observed_metadata=_metadata("changed-observed-name"),
        agent_version="6.0.0",
    )
    request = restarted.create_enrollment_request("bootstrap-secret")

    assert restarted.state.installation_id == installation_id
    assert request.installation_id == installation_id
    assert request.observed_metadata.hostname == "changed-observed-name"


def test_secret_values_are_redacted_from_model_repr(tmp_path: Path) -> None:
    store = AgentStateStore(tmp_path / "state.json")
    enrolled = store.save_enrollment(_enrollment())
    protocol = AgentProtocol(
        store,
        observed_metadata=_metadata(),
        agent_version="6.0.0",
    )
    heartbeat = protocol.create_heartbeat_request()

    assert "per-agent-secret" not in repr(enrolled)
    assert "per-agent-secret" not in repr(heartbeat)
    assert "**********" in repr(enrolled)
    assert "**********" in repr(heartbeat)


def test_protocol_builds_bootstrap_request_then_binds_all_auth_ids(
    tmp_path: Path,
) -> None:
    store = AgentStateStore(tmp_path / "state.json")
    protocol = AgentProtocol(
        store,
        observed_metadata=_metadata(),
        agent_version="6.0.0",
    )
    enrollment_request = protocol.create_enrollment_request(
        SecretStr("bootstrap-secret")
    )

    assert enrollment_request.installation_id == protocol.state.installation_id
    assert enrollment_request.agent_version == "6.0.0"
    assert "bootstrap-secret" not in repr(enrollment_request)

    response = _enrollment()
    protocol.accept_enrollment(response)
    sent_at = datetime(2026, 9, 23, 5, 30, tzinfo=UTC)
    job_id = uuid4()
    messages = (
        protocol.create_heartbeat_request(sent_at=sent_at),
        protocol.create_job_poll_request(),
        protocol.create_profile_submission_request(
            job_id=job_id,
            profile=_profile(),
            profiler_version="m3-test",
            sentra_version="m6a-test",
        ),
    )

    for message in messages:
        assert message.auth.target_id == response.target_id
        assert message.auth.agent_id == response.agent_id
        assert (
            message.auth.agent_credential.get_secret_value()
            == "per-agent-secret"
        )
    assert messages[0].sent_at == sent_at
    assert messages[2].job_id == job_id
    assert messages[2].profile.target.hostname == "observed-host"


def test_post_enrollment_messages_require_complete_enrollment(
    tmp_path: Path,
) -> None:
    protocol = AgentProtocol(
        AgentStateStore(tmp_path / "state.json"),
        observed_metadata=_metadata(),
        agent_version="6.0.0",
    )

    with pytest.raises(AgentNotEnrolledError, match="complete enrollment"):
        protocol.create_heartbeat_request()
    with pytest.raises(AgentNotEnrolledError, match="complete enrollment"):
        protocol.create_job_poll_request()
    with pytest.raises(AgentNotEnrolledError, match="complete enrollment"):
        protocol.create_profile_submission_request(
            job_id=uuid4(),
            profile=_profile(),
        )


def test_enrolled_installation_rejects_bootstrap_and_rebinding(tmp_path: Path) -> None:
    store = AgentStateStore(tmp_path / "state.json")
    first_response = _enrollment()
    store.save_enrollment(first_response)
    protocol = AgentProtocol(
        store,
        observed_metadata=_metadata(),
        agent_version="6.0.0",
    )

    with pytest.raises(AgentAlreadyEnrolledError, match="already enrolled"):
        protocol.create_enrollment_request("another-bootstrap-secret")
    with pytest.raises(AgentEnrollmentError, match="refusing to replace"):
        protocol.accept_enrollment(_enrollment())

    persisted = AgentStateStore(store.path).load_or_create()
    assert persisted.target_id == first_response.target_id
    assert persisted.agent_id == first_response.agent_id


def test_incomplete_persisted_enrollment_is_rejected_without_secret_leak(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    raw_secret = "must-not-appear-in-error"
    state_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "installation_id": str(uuid4()),
                "target_id": str(uuid4()),
                "agent_id": None,
                "agent_credential": raw_secret,
                "polling_interval_seconds": 30,
            }
        ),
        encoding="utf-8",
    )
    state_path.chmod(0o600)

    with pytest.raises(AgentStateError) as raised:
        AgentStateStore(state_path).load_or_create()
    assert "invalid" in str(raised.value)
    assert raw_secret not in str(raised.value)


def test_state_store_rejects_symlinks_non_regular_files_and_open_permissions(
    tmp_path: Path,
) -> None:
    regular = tmp_path / "regular.json"
    AgentStateStore(regular).load_or_create()

    symlink = tmp_path / "linked.json"
    symlink.symlink_to(regular)
    with pytest.raises(AgentStateSecurityError, match="symlink"):
        AgentStateStore(symlink).load_or_create()

    directory = tmp_path / "directory-state"
    directory.mkdir()
    with pytest.raises(AgentStateSecurityError, match="regular file"):
        AgentStateStore(directory).load_or_create()

    regular.chmod(0o644)
    with pytest.raises(AgentStateSecurityError, match="0600"):
        AgentStateStore(regular).load_or_create()


def test_state_store_rejects_symlinked_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(AgentStateSecurityError, match="parent.*symlinks"):
        AgentStateStore(linked_parent / "state.json").load_or_create()
    assert not (real_parent / "state.json").exists()


def test_future_transport_configuration_requires_tls_and_ca_verification(
    tmp_path: Path,
) -> None:
    configuration = AgentTransportConfig(
        controller_url="https://controller.example.test/api/v1",
        controller_ca_path=tmp_path / "controller-ca.pem",
    )

    assert configuration.controller_url.scheme == "https"
    assert configuration.tls_required is True
    assert configuration.verify_controller_certificate is True


@pytest.mark.parametrize(
    "updates",
    [
        {"controller_url": "http://controller.example.test/api/v1"},
        {"controller_url": "https://user:secret@controller.example.test/api/v1"},
        {"tls_required": False},
        {"verify_controller_certificate": False},
    ],
)
def test_future_transport_configuration_has_no_plaintext_or_insecure_mode(
    tmp_path: Path,
    updates: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "controller_url": "https://controller.example.test/api/v1",
        "controller_ca_path": tmp_path / "controller-ca.pem",
    }
    values.update(updates)
    with pytest.raises(ValueError):
        AgentTransportConfig(**values)
