"""M6B tests for the narrow Agent-to-M3 profiling boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.agent.profiler import LocalTargetProfiler, TargetProfilerAdapter
from src.target_profiler import profiler as m3_profiler
from src.target_profiler.models import (
    CollectionSummary,
    FactResult,
    FactStatus,
    TargetInfo,
    TargetProfile,
)


def _four_state_profile() -> TargetProfile:
    requested_by = ["3.3.1"]
    facts = {
        "collected_fixture": FactResult(
            name="collected_fixture",
            status=FactStatus.COLLECTED,
            value=True,
            requested_by=requested_by,
        ),
        "unavailable_fixture": FactResult(
            name="unavailable_fixture",
            status=FactStatus.UNAVAILABLE,
            value=None,
            requested_by=requested_by,
            reason="fixture unavailable",
        ),
        "unsupported_fixture": FactResult(
            name="unsupported_fixture",
            status=FactStatus.UNSUPPORTED,
            value=None,
            requested_by=requested_by,
            reason="fixture unsupported",
        ),
        "error_fixture": FactResult(
            name="error_fixture",
            status=FactStatus.ERROR,
            value=None,
            requested_by=requested_by,
            reason="fixture error",
        ),
    }
    return TargetProfile(
        collected_at=datetime(2026, 9, 23, 12, 0, tzinfo=UTC),
        target=TargetInfo(
            hostname="profile-fixture",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-fixture",
            architecture="x86_64",
            supported=True,
        ),
        facts=facts,
        collection_summary=CollectionSummary(
            requested=4,
            collected=1,
            unavailable=1,
            unsupported=1,
            errors=1,
        ),
    )


def test_local_profiler_delegates_to_existing_m3_and_preserves_states(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "poc-controls.yaml"
    expected = _four_state_profile()
    calls: list[Path] = []

    def existing_m3_collector(path: str | Path) -> TargetProfile:
        calls.append(Path(path))
        return expected

    adapter = LocalTargetProfiler(
        manifest_path,
        collector=existing_m3_collector,
    )
    result = adapter.collect()

    assert isinstance(adapter, TargetProfilerAdapter)
    assert calls == [manifest_path]
    assert result is expected
    assert {fact.status for fact in result.facts.values()} == set(FactStatus)
    assert result.collection_summary.model_dump() == {
        "requested": 4,
        "collected": 1,
        "unavailable": 1,
        "unsupported": 1,
        "errors": 1,
    }


def test_default_adapter_calls_the_existing_m3_profiler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = tmp_path / "manifest.yaml"
    expected = _four_state_profile()
    calls: list[Path] = []

    def collect_local_profile(path: str | Path) -> TargetProfile:
        calls.append(Path(path))
        return expected

    monkeypatch.setattr(m3_profiler, "collect_local_profile", collect_local_profile)

    assert LocalTargetProfiler(manifest_path).collect() is expected
    assert calls == [manifest_path]
