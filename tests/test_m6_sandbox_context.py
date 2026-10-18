from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.compatibility_engine.models import CompatibilityDecision
from src.controller.sandbox_context import (
    IpForwardingSourceState,
    PasswdSourceState,
    SandboxContextManifest,
    derive_sandbox_context,
)
from src.sandbox_protocol import (
    decode_sandbox_context_frame,
    encode_sandbox_context_frame,
)
from src.poc_models import DerivationStatus
from src.sandbox_validator.models import CompatibilityReference
from src.target_profiler.models import (
    CollectionSummary,
    FactResult,
    FactStatus,
    TargetInfo,
    TargetProfile,
)


COLLECTED_AT = datetime(2026, 10, 4, 8, 30, tzinfo=timezone.utc)
REPORT_GENERATED_AT = datetime(2026, 10, 4, 8, 35, tzinfo=timezone.utc)
PASSWD_FACTS = {
    "passwd_file_mode": "0644",
    "passwd_file_owner_uid": 0,
    "passwd_file_group_gid": 0,
}
UNRELATED_FACTS = {
    "sshd_config_material": "SSH_CONFIG_SENTINEL",
    "firewall_state": {"active": True},
    "auditd_state": "AUDITD_SENTINEL",
    "hostname_fact": "HOSTNAME_SENTINEL",
    "kernel_fact": "KERNEL_SENTINEL",
    "passwd_contents": "PASSWD_CONTENT_SENTINEL",
    "credential_fact": "CREDENTIAL_SENTINEL",
    "arbitrary_path": "/tmp/ARBITRARY_PATH_SENTINEL",
    "command_fact": "COMMAND_SENTINEL",
    "script_fact": "SCRIPT_SENTINEL",
}


def _target_info(*, hostname: str = "profile-host") -> TargetInfo:
    return TargetInfo(
        hostname=hostname,
        os="Ubuntu",
        os_version="24.04",
        kernel="6.8.0-test",
        architecture="aarch64",
        supported=True,
    )


def _profile(
    *,
    values: dict[str, object] | None = None,
    statuses: dict[str, FactStatus] | None = None,
    requested_by: dict[str, list[str]] | None = None,
    missing: set[str] | None = None,
    collected_at: datetime = COLLECTED_AT,
    target: TargetInfo | None = None,
    include_unrelated: bool = True,
) -> TargetProfile:
    selected_values: dict[str, object] = {**PASSWD_FACTS, **(values or {})}
    if include_unrelated:
        selected_values.update(UNRELATED_FACTS)
    missing_names = missing or set()
    selected_statuses = statuses or {}
    selected_requesters = requested_by or {}
    facts: dict[str, FactResult] = {}
    for name, value in selected_values.items():
        if name in missing_names:
            continue
        status = selected_statuses.get(name, FactStatus.COLLECTED)
        facts[name] = FactResult(
            name=name,
            status=status,
            value=value if status is FactStatus.COLLECTED else None,
            requested_by=selected_requesters.get(
                name,
                ["7.1.1"] if name in PASSWD_FACTS else ["5.1.20"],
            ),
            reason=(
                None if status is FactStatus.COLLECTED else "fixture collection gap"
            ),
        )
    return TargetProfile(
        collected_at=collected_at,
        target=target or _target_info(),
        facts=facts,
        collection_summary=CollectionSummary(
            requested=len(facts),
            collected=sum(
                item.status is FactStatus.COLLECTED for item in facts.values()
            ),
            unavailable=sum(
                item.status is FactStatus.UNAVAILABLE for item in facts.values()
            ),
            unsupported=sum(
                item.status is FactStatus.UNSUPPORTED for item in facts.values()
            ),
            errors=sum(item.status is FactStatus.ERROR for item in facts.values()),
        ),
    )


def _compatibility(
    *,
    control_id: str = "7.1.1",
    collected_at: datetime = COLLECTED_AT,
    target: TargetInfo | None = None,
) -> CompatibilityReference:
    return CompatibilityReference(
        control_id=control_id,
        report_source="controller-stored-compatibility-report:report-1",
        report_sha256="a" * 64,
        report_version="1",
        report_generated_at=REPORT_GENERATED_AT,
        profile_source="controller-stored-profile:profile-1",
        profile_collected_at=collected_at,
        profile_target=target or _target_info(),
        result=CompatibilityDecision.REVIEW_REQUIRED,
        provisional=True,
        metadata_review_status=DerivationStatus.NEEDS_REVIEW,
        explanation="review is required; this model does not authorize execution",
    )


def _derive(
    profile: TargetProfile | None = None,
    compatibility: CompatibilityReference | None = None,
    *,
    control_id: str = "7.1.1",
) -> SandboxContextManifest:
    return derive_sandbox_context(
        control_id,
        profile or _profile(),
        compatibility or _compatibility(),
    )


def test_derives_valid_compliant_passwd_state() -> None:
    context = _derive()

    assert context.source_state == PasswdSourceState(
        passwd_file_mode="0644",
        passwd_file_owner_uid=0,
        passwd_file_group_gid=0,
    )
    assert encode_sandbox_context_frame(context)[4:] == (
        b'{"context_version":"1","control_id":"7.1.1","source_state":'
        b'{"passwd_file_group_gid":0,"passwd_file_mode":"0644",'
        b'"passwd_file_owner_uid":0}}'
    )


def _forwarding_profile(
    *,
    ipv6_enabled: bool = True,
    ipv6_status: FactStatus = FactStatus.COLLECTED,
) -> TargetProfile:
    return _profile(
        values={
            "ipv4_forwarding_status": 1,
            "ipv6_enabled": ipv6_enabled,
            "ipv6_forwarding_status": 1,
        },
        statuses={"ipv6_forwarding_status": ipv6_status},
        requested_by={
            name: ["3.3.1"] for name in (
                "ipv4_forwarding_status", "ipv6_enabled", "ipv6_forwarding_status"
            )
        },
    )


def test_derives_only_selected_forwarding_source_facts() -> None:
    manifest = _derive(
        _forwarding_profile(),
        _compatibility(control_id="3.3.1"),
        control_id="3.3.1",
    )

    assert manifest.source_state == IpForwardingSourceState(
        ipv4_forwarding_status=1,
        ipv6_enabled=True,
        ipv6_forwarding_status=1,
    )
    assert decode_sandbox_context_frame(
        encode_sandbox_context_frame(manifest)
    ) == manifest
    assert "passwd_file_mode" not in manifest.model_dump_json()


def test_ipv6_disabled_does_not_require_forwarding_status() -> None:
    manifest = _derive(
        _forwarding_profile(
            ipv6_enabled=False,
            ipv6_status=FactStatus.UNAVAILABLE,
        ),
        _compatibility(control_id="3.3.1"),
        control_id="3.3.1",
    )

    assert manifest.source_state == IpForwardingSourceState(
        ipv4_forwarding_status=1,
        ipv6_enabled=False,
    )
    assert "ipv6_forwarding_status" not in (
        encode_sandbox_context_frame(manifest)[4:].decode("utf-8")
    )


def test_forwarding_required_unknown_fact_fails_closed() -> None:
    with pytest.raises(ValueError, match="not collected"):
        _derive(
            _forwarding_profile(ipv6_status=FactStatus.ERROR),
            _compatibility(control_id="3.3.1"),
            control_id="3.3.1",
        )


def test_context_control_and_source_state_cannot_be_cross_paired() -> None:
    with pytest.raises(ValidationError):
        SandboxContextManifest(
            context_version="1",
            control_id="3.3.1",
            source_state=PasswdSourceState(
                passwd_file_mode="0644",
                passwd_file_owner_uid=0,
                passwd_file_group_gid=0,
            ),
        )
    with pytest.raises(ValidationError):
        SandboxContextManifest(
            context_version="1",
            control_id="7.1.1",
            source_state=IpForwardingSourceState(
                ipv4_forwarding_status=1,
                ipv6_enabled=True,
                ipv6_forwarding_status=1,
            ),
        )


@pytest.mark.parametrize(
    "state",
    [
        {"ipv4_forwarding_status": 2, "ipv6_enabled": False},
        {"ipv4_forwarding_status": "1", "ipv6_enabled": False},
        {"ipv4_forwarding_status": 1, "ipv6_enabled": "false"},
        {"ipv4_forwarding_status": 1, "ipv6_enabled": True},
        {
            "ipv4_forwarding_status": 1,
            "ipv6_enabled": False,
            "ipv6_forwarding_status": 0,
        },
        {
            "ipv4_forwarding_status": 1,
            "ipv6_enabled": True,
            "ipv6_forwarding_status": 2,
        },
    ],
)
def test_malformed_forwarding_state_is_rejected(state: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        IpForwardingSourceState.model_validate(state)


def test_derives_representative_noncompliant_state_without_normalizing() -> None:
    context = _derive(
        _profile(
            values={
                "passwd_file_mode": "0666",
                "passwd_file_owner_uid": 42,
                "passwd_file_group_gid": 43,
            }
        )
    )

    assert context.source_state.passwd_file_mode == "0666"
    assert context.source_state.passwd_file_owner_uid == 42
    assert context.source_state.passwd_file_group_gid == 43


@pytest.mark.parametrize(
    "missing_fact",
    [
        "passwd_file_mode",
        "passwd_file_owner_uid",
        "passwd_file_group_gid",
    ],
)
def test_missing_required_fact_fails_closed(missing_fact: str) -> None:
    with pytest.raises(ValueError, match="missing"):
        _derive(_profile(missing={missing_fact}))


@pytest.mark.parametrize(
    "status",
    [FactStatus.UNAVAILABLE, FactStatus.UNSUPPORTED, FactStatus.ERROR],
)
def test_noncollected_required_fact_status_fails_closed(status: FactStatus) -> None:
    with pytest.raises(ValueError, match="not collected"):
        _derive(_profile(statuses={"passwd_file_mode": status}))


def test_required_fact_not_requested_by_control_fails_closed() -> None:
    profile = _profile(requested_by={"passwd_file_mode": ["5.1.20"]})

    with pytest.raises(ValueError, match="provenance"):
        _derive(profile)


def test_wrong_mode_value_type_fails_closed() -> None:
    with pytest.raises(ValidationError):
        _derive(_profile(values={"passwd_file_mode": 644}))


@pytest.mark.parametrize("mode", ["644", "0o644", "0888", "064x"])
def test_malformed_mode_fails_closed(mode: str) -> None:
    with pytest.raises(ValidationError):
        _derive(_profile(values={"passwd_file_mode": mode}))


@pytest.mark.parametrize(
    ("fact_name", "value"),
    [
        ("passwd_file_owner_uid", "0"),
        ("passwd_file_group_gid", "0"),
        ("passwd_file_owner_uid", True),
        ("passwd_file_group_gid", True),
        ("passwd_file_owner_uid", -1),
        ("passwd_file_group_gid", -1),
    ],
)
def test_uid_and_gid_require_nonnegative_strict_integers(
    fact_name: str,
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        _derive(_profile(values={fact_name: value}))


def test_compatibility_control_mismatch_fails_closed() -> None:
    with pytest.raises(ValueError, match="control"):
        _derive(compatibility=_compatibility(control_id="5.1.20"))


def test_profile_and_compatibility_timestamp_mismatch_fails_closed() -> None:
    different_time = datetime(2026, 10, 4, 9, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="timestamps"):
        _derive(compatibility=_compatibility(collected_at=different_time))


def test_profile_and_compatibility_target_mismatch_fails_closed() -> None:
    with pytest.raises(ValueError, match="targets"):
        _derive(
            compatibility=_compatibility(
                target=_target_info(hostname="different-profile-host")
            )
        )


def test_unsupported_control_fails_closed() -> None:
    with pytest.raises(ValueError, match="does not support this control"):
        _derive(control_id="5.1.20")


@pytest.mark.parametrize(
    "factory",
    [
        lambda: PasswdSourceState(
            passwd_file_mode="0644",
            passwd_file_owner_uid=0,
            passwd_file_group_gid=0,
            extra_fact="not allowed",
        ),
        lambda: SandboxContextManifest(
            context_version="1",
            control_id="7.1.1",
            source_state=PasswdSourceState(
                passwd_file_mode="0644",
                passwd_file_owner_uid=0,
                passwd_file_group_gid=0,
            ),
            hostname="not allowed",
        ),
    ],
)
def test_context_models_reject_extra_fields(factory) -> None:
    with pytest.raises(ValidationError):
        factory()


def test_context_models_are_immutable() -> None:
    context = _derive()

    with pytest.raises(ValidationError):
        context.control_id = "5.1.20"  # type: ignore[misc]


def test_manifest_rejects_unsupported_context_version() -> None:
    with pytest.raises(ValidationError):
        SandboxContextManifest(
            context_version="2",
            control_id="7.1.1",
            source_state=PasswdSourceState(
                passwd_file_mode="0644",
                passwd_file_owner_uid=0,
                passwd_file_group_gid=0,
            ),
        )


def test_manifest_rejects_unsupported_control_id() -> None:
    with pytest.raises(ValidationError):
        SandboxContextManifest(
            context_version="1",
            control_id="5.1.20",
            source_state=PasswdSourceState(
                passwd_file_mode="0644",
                passwd_file_owner_uid=0,
                passwd_file_group_gid=0,
            ),
        )


def test_passwd_source_state_is_immutable() -> None:
    source_state = PasswdSourceState(
        passwd_file_mode="0644",
        passwd_file_owner_uid=0,
        passwd_file_group_gid=0,
    )

    with pytest.raises(ValidationError):
        source_state.passwd_file_mode = "0666"  # type: ignore[misc]


def test_context_serialization_contains_only_allowlisted_fields() -> None:
    context = _derive()
    serialized = context.model_dump_json()
    payload = json.loads(serialized)

    assert set(payload) == {"context_version", "control_id", "source_state"}
    assert set(payload["source_state"]) == {
        "passwd_file_mode",
        "passwd_file_owner_uid",
        "passwd_file_group_gid",
    }
    assert payload == {
        "context_version": "1",
        "control_id": "7.1.1",
        "source_state": {
            "passwd_file_mode": "0644",
            "passwd_file_owner_uid": 0,
            "passwd_file_group_gid": 0,
        },
    }


def test_unrelated_target_profile_data_never_enters_serialized_context() -> None:
    serialized = _derive().model_dump_json()

    for sentinel in UNRELATED_FACTS.values():
        if isinstance(sentinel, dict):
            for value in sentinel.values():
                assert str(value) not in serialized
        else:
            assert str(sentinel) not in serialized


def test_caller_mapping_is_not_accepted_as_a_profile() -> None:
    with pytest.raises(ValueError, match="validated TargetProfile"):
        derive_sandbox_context("7.1.1", {}, _compatibility())  # type: ignore[arg-type]
