"""Focused security and validation tests for M6 controller contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr, ValidationError

from src.controller.models import (
    AdminAuth,
    AgentAuth,
    EnrollmentRequest,
    EnrollmentResponse,
    HeartbeatRequest,
    JobCreateRequest,
    JobRecord,
    JobStatus,
    JobType,
    ObservedTargetMetadata,
    ProfileRecord,
)
from src.controller.security import (
    AdminCredentialVerifier,
    BootstrapCredentialVerifier,
    CredentialHash,
    generate_credential,
    hash_credential,
    verify_credential,
)


def metadata(**updates: str) -> ObservedTargetMetadata:
    values = {
        "hostname": "customer-ubuntu",
        "os": "Ubuntu",
        "os_version": "24.04",
        "kernel": "6.8.0-generic",
        "architecture": "aarch64",
    }
    values.update(updates)
    return ObservedTargetMetadata(**values)


def test_protocol_secret_fields_are_redacted_from_normal_repr() -> None:
    plaintext = "credential-that-must-not-appear"
    enrollment = EnrollmentRequest(
        bootstrap_credential=plaintext,
        installation_id=uuid4(),
        agent_version="0.1.0",
        observed_metadata=metadata(),
    )
    response = EnrollmentResponse(
        target_id=uuid4(),
        agent_id=uuid4(),
        agent_credential=plaintext,
        polling_interval_seconds=30,
    )
    auth = AgentAuth(
        target_id=response.target_id,
        agent_id=response.agent_id,
        agent_credential=plaintext,
    )
    admin = AdminAuth(admin_credential=plaintext)

    for value in (enrollment, response, auth, admin):
        assert plaintext not in repr(value)
        assert "**********" in repr(value)


def test_protocol_rejects_blank_credentials_without_echoing_them() -> None:
    with pytest.raises(ValidationError) as raised:
        EnrollmentRequest(
            bootstrap_credential="   ",
            installation_id=uuid4(),
            agent_version="0.1.0",
            observed_metadata=metadata(),
        )
    assert "credential must not be blank" in str(raised.value)
    assert "input_value" not in str(raised.value)


@pytest.mark.parametrize(
    "job_type",
    ["RUN_COMMAND", "RUN_SHELL", "EXEC", "COMMAND_STRING", "rm -rf /"],
)
def test_unknown_or_command_like_job_types_are_rejected(job_type: str) -> None:
    with pytest.raises(ValidationError):
        JobCreateRequest(target_id=uuid4(), job_type=job_type)


def test_only_profile_target_job_type_is_available() -> None:
    assert list(JobType) == [JobType.PROFILE_TARGET]
    request = JobCreateRequest(
        target_id=uuid4(),
        job_type=JobType.PROFILE_TARGET,
    )
    assert request.job_type is JobType.PROFILE_TARGET


def test_aware_timestamps_are_required() -> None:
    auth = AgentAuth(
        target_id=uuid4(),
        agent_id=uuid4(),
        agent_credential="agent-secret",
    )
    with pytest.raises(ValidationError, match="timezone"):
        HeartbeatRequest(
            auth=auth,
            sent_at=datetime(2026, 9, 23, 10, 0),
            agent_version="0.1.0",
            observed_metadata=metadata(),
        )

    with pytest.raises(ValidationError, match="timezone"):
        JobRecord(
            job_id=uuid4(),
            target_id=auth.target_id,
            job_type=JobType.PROFILE_TARGET,
            status=JobStatus.PENDING,
            created_at=datetime(2026, 9, 23, 10, 0),
        )


@pytest.mark.parametrize(
    "bad_hash",
    ["", "0" * 63, "0" * 65, "g" * 64, "A" * 64],
)
def test_profile_sha256_is_canonical_lowercase_hex(bad_hash: str) -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        ProfileRecord(
            profile_id=uuid4(),
            target_id=uuid4(),
            agent_id=uuid4(),
            job_id=uuid4(),
            collected_at=now,
            received_at=now,
            profile_sha256=bad_hash,
        )


def test_machine_identity_hash_is_optional_non_authoritative_evidence() -> None:
    observed = metadata(machine_identity_hash="a" * 64)
    assert observed.machine_identity_hash == "a" * 64
    assert "target_id" not in type(observed).model_fields
    assert "agent_id" not in type(observed).model_fields

    with pytest.raises(ValidationError):
        metadata(machine_identity_hash="raw-machine-id")


def test_controller_identity_fields_require_explicit_uuids_not_metadata() -> None:
    observed = metadata(hostname="same-host")
    first_target = uuid4()
    second_target = uuid4()
    assert first_target != second_target

    with pytest.raises(ValidationError):
        AgentAuth(
            target_id=observed.hostname,
            agent_id=uuid4(),
            agent_credential="secret",
        )
    assert isinstance(first_target, UUID)
    assert observed.hostname == "same-host"


def test_models_forbid_undocumented_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        ObservedTargetMetadata(
            hostname="target",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0",
            architecture="x86_64",
            ip_address="192.0.2.10",
        )


def test_generated_credentials_are_opaque_unique_and_redacted() -> None:
    first = generate_credential()
    second = generate_credential()
    assert isinstance(first, SecretStr)
    assert first.get_secret_value() != second.get_secret_value()
    assert first.get_secret_value() not in repr(first)
    assert len(first.get_secret_value()) >= 43


def test_salted_hash_round_trip_and_constant_api_behavior() -> None:
    credential = SecretStr("correct horse battery staple")
    first = hash_credential(credential, iterations=100_000)
    second = hash_credential(credential, iterations=100_000)

    assert first != second
    assert credential.get_secret_value() not in first.to_storage()
    assert credential.get_secret_value() not in repr(first)
    assert CredentialHash.from_storage(first.to_storage()) == first
    assert verify_credential(credential, first)
    assert verify_credential(credential, first.to_storage())
    assert not verify_credential("wrong", first)
    assert not verify_credential(credential, "malformed")


def test_bootstrap_and_admin_verifiers_retain_no_plaintext() -> None:
    plaintext = "separate-boundary-secret"
    stored = hash_credential(plaintext, iterations=100_000)
    bootstrap = BootstrapCredentialVerifier(stored)
    admin = AdminCredentialVerifier(stored.to_storage())

    assert bootstrap.verify(plaintext)
    assert admin.verify(SecretStr(plaintext))
    assert not bootstrap.verify("wrong")
    assert plaintext not in repr(bootstrap)
    assert plaintext not in repr(admin)


def test_credential_hash_rejects_weak_or_malformed_storage() -> None:
    with pytest.raises(ValueError):
        hash_credential("secret", iterations=99_999)
    with pytest.raises(ValueError):
        CredentialHash.from_storage("sha256$100000$00$00")
    with pytest.raises(ValueError):
        generate_credential(token_bytes=16)
