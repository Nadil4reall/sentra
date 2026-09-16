from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.target_profiler.fact_loader import load_required_facts
from src.target_profiler.models import (
    FactResult,
    FactStatus,
    TargetInfo,
    TargetProfile,
    build_collection_summary,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "data" / "poc" / "poc_controls.yaml"


def test_required_facts_are_deduplicated_with_ordered_traceability() -> None:
    facts = load_required_facts(MANIFEST_PATH)

    assert len(facts) == 47
    assert len({fact.name for fact in facts}) == len(facts)
    assert facts[0].name == "cramfs_filesystem_required"
    assert facts[-1].name == "shadow_group_gid"
    by_name = {fact.name: fact for fact in facts}
    assert by_name["ssh_service_status"].requested_by == ["5.1.19", "5.1.20"]
    assert by_name["sshd_match_directives_present"].requested_by == [
        "5.1.19",
        "5.1.20",
    ]


@pytest.mark.parametrize(
    ("status", "value", "reason"),
    [
        (FactStatus.UNAVAILABLE, None, "permission_denied"),
        (FactStatus.UNSUPPORTED, None, "requires_administrator_context"),
        (FactStatus.ERROR, None, "read_failed"),
        (FactStatus.COLLECTED, False, None),
        (FactStatus.COLLECTED, [], None),
    ],
)
def test_fact_result_accepts_valid_terminal_states(
    status: FactStatus, value: object, reason: str | None
) -> None:
    result = FactResult(
        name="example_fact",
        status=status,
        value=value,
        reason=reason,
        requested_by=["1.1.1.1"],
    )
    assert result.status == status


@pytest.mark.parametrize(
    ("status", "value", "reason"),
    [
        (FactStatus.COLLECTED, None, None),
        (FactStatus.COLLECTED, True, "collection_failed"),
        (FactStatus.UNAVAILABLE, False, "permission_denied"),
        (FactStatus.UNAVAILABLE, None, None),
    ],
)
def test_fact_result_rejects_invented_or_ambiguous_values(
    status: FactStatus, value: object, reason: str | None
) -> None:
    with pytest.raises(ValidationError):
        FactResult(
            name="example_fact",
            status=status,
            value=value,
            reason=reason,
            requested_by=["1.1.1.1"],
        )


def test_profile_schema_checks_summary_and_traceability() -> None:
    facts = {
        "example_fact": FactResult(
            name="example_fact",
            status=FactStatus.COLLECTED,
            value=False,
            requested_by=["1.1.1.1"],
        )
    }
    profile = TargetProfile(
        collected_at=datetime.now(timezone.utc),
        target=TargetInfo(
            hostname="sentra-test",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-test",
            architecture="x86_64",
            supported=True,
        ),
        facts=facts,
        collection_summary=build_collection_summary(facts),
    )

    assert profile.profile_version == "1"
    assert profile.collection_summary.collected == 1


def test_non_ubuntu_target_cannot_be_marked_supported() -> None:
    with pytest.raises(ValidationError):
        TargetInfo(
            hostname="developer-mac",
            os="macOS",
            os_version="15.0",
            kernel="Darwin",
            architecture="arm64",
            supported=True,
        )


def test_supported_target_cannot_carry_a_failure_reason() -> None:
    with pytest.raises(ValidationError):
        TargetInfo(
            hostname="sentra-test",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-test",
            architecture="x86_64",
            supported=True,
            reason="contradictory_failure",
        )
