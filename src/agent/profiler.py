"""Narrow Agent adapter for the existing read-only M3 target profiler."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol, runtime_checkable

from src.target_profiler import profiler as m3_profiler
from src.target_profiler.fact_loader import DEFAULT_MANIFEST_PATH
from src.target_profiler.models import TargetProfile


@runtime_checkable
class TargetProfilerAdapter(Protocol):
    """The only local operation needed by a ``PROFILE_TARGET`` job."""

    def collect(self) -> TargetProfile: ...


class LocalTargetProfiler:
    """Delegate one profile operation to the existing M3 implementation.

    The adapter deliberately does not copy collectors or reinterpret evidence.
    In particular, M3's ``collected``, ``unavailable``, ``unsupported``, and
    ``error`` states pass through in the returned ``TargetProfile`` unchanged.
    """

    def __init__(
        self,
        manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
        *,
        collector: Callable[[str | Path], TargetProfile] | None = None,
    ) -> None:
        self._manifest_path = Path(manifest_path)
        self._collector = collector or m3_profiler.collect_local_profile

    def collect(self) -> TargetProfile:
        return self._collector(self._manifest_path)


__all__ = ["LocalTargetProfiler", "TargetProfilerAdapter"]
