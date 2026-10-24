"""Controller-only adapter to the existing Milestone 4 compatibility engine.

The adapter accepts an already stored, validated M3 ``TargetProfile`` and never
performs target-side collection, command execution, or remediation.  It keeps
the M4 engine authoritative for compatibility semantics while exposing the
benchmark identity needed by Controller evidence lineage.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol
from uuid import UUID

from src.compatibility_engine.engine import evaluate_compatibility
from src.compatibility_engine.loaders import (
    DEFAULT_MANIFEST_PATH,
    build_compatibility_inputs,
)
from src.compatibility_engine.models import CompatibilityReport
from src.target_profiler.models import TargetProfile


@dataclass(frozen=True)
class CompatibilityAnalysis:
    """One M4 report plus the validated benchmark metadata that produced it."""

    report: CompatibilityReport
    benchmark_identity: str
    benchmark_version: str


class CompatibilityAnalyzer(Protocol):
    """Narrow injectable Controller boundary for deterministic M4 analysis."""

    def analyze(
        self,
        *,
        profile: TargetProfile,
        profile_id: UUID,
        generated_at: datetime,
    ) -> CompatibilityAnalysis: ...


class ExistingM4CompatibilityAnalyzer:
    """Run the existing ten-control M4 engine against in-memory M3 evidence."""

    def __init__(self, manifest_path: str | Path = DEFAULT_MANIFEST_PATH) -> None:
        self._manifest_path = Path(manifest_path)

    def analyze(
        self,
        *,
        profile: TargetProfile,
        profile_id: UUID,
        generated_at: datetime,
    ) -> CompatibilityAnalysis:
        inputs = build_compatibility_inputs(
            profile,
            profile_source=f"controller-stored-profile:{profile_id}",
            manifest_path=self._manifest_path,
        )
        report = evaluate_compatibility(inputs, generated_at=generated_at)
        manifest_benchmark = inputs.manifest.benchmark
        benchmark_version = f"v{manifest_benchmark.version}"
        return CompatibilityAnalysis(
            report=report,
            benchmark_identity=(
                f"{manifest_benchmark.name} {benchmark_version}"
            ),
            benchmark_version=benchmark_version,
        )


__all__ = [
    "CompatibilityAnalysis",
    "CompatibilityAnalyzer",
    "ExistingM4CompatibilityAnalyzer",
]
