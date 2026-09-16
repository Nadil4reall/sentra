"""Validated data models for read-only SENTRA target profiles."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


CONTROL_ID_PATTERN = re.compile(r"^\d+(?:\.\d+){2,}$")


class StrictProfileModel(BaseModel):
    """Base model that rejects accidental, undocumented profile fields."""

    model_config = ConfigDict(extra="forbid")


class FactStatus(StrEnum):
    """Outcome of attempting to collect one requested target fact."""

    COLLECTED = "collected"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class RequiredFact(StrictProfileModel):
    """A deduplicated fact and the controls that requested it."""

    name: str = Field(pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
    requested_by: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_requesters(self) -> "RequiredFact":
        if len(self.requested_by) != len(set(self.requested_by)):
            raise ValueError("requested_by control IDs must be unique")
        invalid = [
            control_id
            for control_id in self.requested_by
            if CONTROL_ID_PATTERN.fullmatch(control_id) is None
        ]
        if invalid:
            raise ValueError(f"Invalid requested_by control IDs: {invalid}")
        return self


class FactResult(StrictProfileModel):
    """One collected fact, including its provenance and failure state."""

    name: str = Field(pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
    status: FactStatus
    value: JsonValue | None = None
    requested_by: list[str] = Field(default_factory=list)
    reason: str | None = None

    @model_validator(mode="after")
    def validate_result_state(self) -> "FactResult":
        if self.status == FactStatus.COLLECTED:
            if self.value is None:
                raise ValueError("A collected fact must have a non-null value")
            if self.reason is not None:
                raise ValueError("A collected fact must not include a failure reason")
        else:
            if self.value is not None:
                raise ValueError("A non-collected fact must have a null value")
            if not self.reason or not self.reason.strip():
                raise ValueError("A non-collected fact must include a reason")

        if len(self.requested_by) != len(set(self.requested_by)):
            raise ValueError("requested_by control IDs must be unique")
        invalid = [
            control_id
            for control_id in self.requested_by
            if CONTROL_ID_PATTERN.fullmatch(control_id) is None
        ]
        if invalid:
            raise ValueError(f"Invalid requested_by control IDs: {invalid}")
        return self


class TargetInfo(StrictProfileModel):
    """Local host identity; it deliberately contains no network address."""

    hostname: str = Field(min_length=1)
    os: str = Field(min_length=1)
    os_version: str
    kernel: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    supported: bool
    reason: str | None = None

    @model_validator(mode="after")
    def validate_support_state(self) -> "TargetInfo":
        if self.supported:
            if self.os.casefold() != "ubuntu" or self.os_version != "24.04":
                raise ValueError("Only Ubuntu 24.04 can be marked as supported")
            if self.reason is not None:
                raise ValueError("A supported target must not include a failure reason")
        elif not self.reason or not self.reason.strip():
            raise ValueError("An unsupported target must include a reason")
        return self


class CollectionSummary(StrictProfileModel):
    """Counts for every terminal fact collection state."""

    requested: int = Field(ge=0)
    collected: int = Field(ge=0)
    unavailable: int = Field(ge=0)
    unsupported: int = Field(ge=0)
    errors: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_total(self) -> "CollectionSummary":
        completed = self.collected + self.unavailable + self.unsupported + self.errors
        if completed != self.requested:
            raise ValueError("Collection summary states must add up to requested")
        return self


class TargetProfile(StrictProfileModel):
    """Complete serializable profile for one local collection run."""

    profile_version: Literal["1"] = "1"
    collected_at: datetime
    target: TargetInfo
    facts: dict[str, FactResult]
    collection_summary: CollectionSummary

    @model_validator(mode="after")
    def validate_profile_consistency(self) -> "TargetProfile":
        if self.collected_at.utcoffset() is None:
            raise ValueError("collected_at must include a timezone")

        for fact_name, result in self.facts.items():
            if fact_name != result.name:
                raise ValueError(
                    f"Fact mapping key {fact_name!r} does not match result name "
                    f"{result.name!r}"
                )
            if not result.requested_by:
                raise ValueError(f"Fact {fact_name!r} must include requested_by")

        expected_counts = {
            FactStatus.COLLECTED: self.collection_summary.collected,
            FactStatus.UNAVAILABLE: self.collection_summary.unavailable,
            FactStatus.UNSUPPORTED: self.collection_summary.unsupported,
            FactStatus.ERROR: self.collection_summary.errors,
        }
        actual_counts = {
            status: sum(result.status == status for result in self.facts.values())
            for status in FactStatus
        }
        if self.collection_summary.requested != len(self.facts):
            raise ValueError("collection_summary.requested must equal the fact count")
        if actual_counts != expected_counts:
            raise ValueError("Collection summary counts do not match fact statuses")
        return self


def build_collection_summary(facts: dict[str, FactResult]) -> CollectionSummary:
    """Build a schema-valid summary from fact results."""

    return CollectionSummary(
        requested=len(facts),
        collected=sum(item.status == FactStatus.COLLECTED for item in facts.values()),
        unavailable=sum(
            item.status == FactStatus.UNAVAILABLE for item in facts.values()
        ),
        unsupported=sum(
            item.status == FactStatus.UNSUPPORTED for item in facts.values()
        ),
        errors=sum(item.status == FactStatus.ERROR for item in facts.values()),
    )
