"""Narrow persistence boundary for the SENTRA Controller.

The SQLite implementation stores controller-issued identities, credential verifiers,
jobs, and immutable evidence lineage.  Protocol and service code depend on the
``ControllerRepository`` interface rather than on SQLite directly.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Iterator, Protocol
from uuid import UUID

from pydantic import ValidationError

from src.compatibility_engine.models import CompatibilityReport
from src.controller.models import (
    CompatibilityReportRecord,
    EnforcementOutcome,
    EnforcementJobRecord,
    EnforcementResultPayload,
    EnforcementResultRecord,
    PostEnforcementVerificationOutcome,
    PostEnforcementVerificationRecord,
    JobRecord,
    JobStatus,
    JobType,
    MetadataChangeRecord,
    ObservedTargetMetadata,
    ProfileRecord,
    SANDBOX_SESSION_TRANSITIONS,
    SandboxProviderType,
    SandboxSessionRecord,
    SandboxSessionStatus,
    TargetRecord,
    TargetStatus,
    ValidationJobRecord,
    ValidationMode,
    ValidationResultPayload,
    ValidationResultRecord,
)
from src.controller.validation import (
    canonical_validation_payload_json,
    compatibility_reference_from_record,
    require_payload_matches_job,
)
from src.controller.enforcement import (
    canonical_enforcement_payload_json, observed_passwd_state,
    post_enforcement_outcome,
)
from src.controller.sandbox_context import derive_sandbox_context
from src.sandbox_validator.models import CompatibilityReference, ExecutionMode
from src.target_profiler.models import TargetProfile


class StorageConflictError(RuntimeError):
    """A unique or state invariant prevented a storage operation."""


class StorageNotFoundError(RuntimeError):
    """A referenced controller record does not exist."""


class ControllerStorageSecurityError(RuntimeError):
    """The configured controller database path is unsafe for local evidence."""


@dataclass(frozen=True)
class StoredAgent:
    """Private authentication record; never exposed through the API models."""

    agent_id: UUID
    target_id: UUID
    installation_id: UUID
    credential_hash: str
    created_at: datetime
    last_seen: datetime | None


@dataclass(frozen=True)
class StoredJob:
    """Job plus its assigned agent, if it has been dispatched."""

    job: JobRecord
    assigned_agent_id: UUID | None


@dataclass(frozen=True)
class StoredProfile:
    """A profile whose canonical payload and authoritative hash were revalidated."""

    record: ProfileRecord
    profile: TargetProfile
    canonical_payload_json: str


@dataclass(frozen=True)
class StoredCompatibilityReport:
    """A compatibility report revalidated at the SQLite trust boundary."""

    record: CompatibilityReportRecord
    canonical_payload_json: str


@dataclass(frozen=True)
class StoredValidationJob:
    """A constrained validation job plus its assigned Agent, if dispatched."""

    job: ValidationJobRecord
    assigned_agent_id: UUID | None


class ControllerRepository(Protocol):
    """Replaceable persistence operations used by ``ControllerService``."""

    def enroll(
        self,
        *,
        target_id: UUID,
        agent_id: UUID,
        installation_id: UUID,
        credential_hash: str,
        agent_version: str,
        metadata: ObservedTargetMetadata,
        created_at: datetime,
    ) -> TargetRecord: ...

    def get_agent(self, agent_id: UUID) -> StoredAgent | None: ...

    def get_target(self, target_id: UUID) -> TargetRecord | None: ...

    def list_targets(self) -> list[TargetRecord]: ...

    def record_heartbeat(
        self,
        *,
        target_id: UUID,
        agent_id: UUID,
        seen_at: datetime,
        agent_version: str,
        metadata: ObservedTargetMetadata,
        change_id: UUID,
    ) -> MetadataChangeRecord | None: ...

    def list_metadata_changes(self, target_id: UUID) -> list[MetadataChangeRecord]: ...

    def create_job(self, job: JobRecord) -> JobRecord: ...

    def get_job(self, job_id: UUID) -> StoredJob | None: ...

    def poll_jobs(
        self,
        *,
        target_id: UUID,
        agent_id: UUID,
        dispatched_at: datetime,
        limit: int,
    ) -> list[JobRecord]: ...

    def poll_validation_jobs(
        self,
        *,
        target_id: UUID,
        agent_id: UUID,
        dispatched_at: datetime,
        limit: int,
    ) -> list[ValidationJobRecord]: ...

    def store_profile(self, record: ProfileRecord, payload_json: str) -> ProfileRecord: ...

    def get_profile(self, profile_id: UUID) -> ProfileRecord | None: ...

    def get_stored_profile(self, profile_id: UUID) -> StoredProfile | None: ...

    def store_compatibility_report(
        self, record: CompatibilityReportRecord, payload_json: str
    ) -> CompatibilityReportRecord: ...

    def get_compatibility_report(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
    ) -> CompatibilityReportRecord | None: ...

    def list_compatibility_reports(
        self, *, target_id: UUID, profile_id: UUID
    ) -> list[CompatibilityReportRecord]: ...

    def create_validation_job(
        self, job: ValidationJobRecord
    ) -> ValidationJobRecord: ...

    def dispatch_sandbox_validation_job(
        self, *, sandbox_session_id: UUID, validation_job_id: UUID,
        dispatched_at: datetime, pending_job: ValidationJobRecord | None = None,
    ) -> tuple[ValidationJobRecord, SandboxSessionRecord]: ...

    def complete_sandbox_validation_job(
        self, *, sandbox_session_id: UUID, validation_job_id: UUID,
        payload: ValidationResultPayload, completed_at: datetime,
    ) -> SandboxSessionRecord: ...

    def get_sandbox_validation_evidence(
        self, *, sandbox_session_id: UUID,
    ) -> tuple[ValidationResultPayload, str] | None: ...

    def create_enforcement_job(
        self, job: EnforcementJobRecord,
    ) -> EnforcementJobRecord: ...

    def poll_enforcement_jobs(
        self, *, target_id: UUID, agent_id: UUID,
        dispatched_at: datetime, limit: int,
    ) -> list[EnforcementJobRecord]: ...

    def get_enforcement_job(self, enforcement_job_id: UUID) -> EnforcementJobRecord | None: ...

    def store_enforcement_result(
        self, record: EnforcementResultRecord, payload_json: str,
    ) -> EnforcementResultRecord: ...

    def get_enforcement_result_for_job(
        self, enforcement_job_id: UUID,
    ) -> EnforcementResultRecord | None: ...

    def get_post_enforcement_verification(
        self, enforcement_result_id: UUID,
    ) -> PostEnforcementVerificationRecord | None: ...

    def get_validation_job(
        self, validation_job_id: UUID
    ) -> StoredValidationJob | None: ...

    def store_validation_result(
        self, record: ValidationResultRecord, payload_json: str
    ) -> ValidationResultRecord: ...

    def get_validation_result_for_job(
        self, validation_job_id: UUID
    ) -> ValidationResultRecord | None: ...

    def get_validation_result(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        validation_result_id: UUID,
    ) -> ValidationResultRecord | None: ...

    def list_validation_results(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
    ) -> list[ValidationResultRecord]: ...

    def create_sandbox_session(
        self, session: SandboxSessionRecord
    ) -> SandboxSessionRecord: ...

    def get_sandbox_session(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord | None: ...

    def get_sandbox_session_by_id(
        self, sandbox_session_id: UUID
    ) -> SandboxSessionRecord | None: ...

    def list_sandbox_sessions(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
    ) -> list[SandboxSessionRecord]: ...

    def mark_provisioning(
        self, session: SandboxSessionRecord
    ) -> SandboxSessionRecord: ...

    def mark_ready(
        self, session: SandboxSessionRecord
    ) -> SandboxSessionRecord: ...

    def mark_validating(
        self, session: SandboxSessionRecord
    ) -> SandboxSessionRecord: ...

    def mark_completed(
        self, session: SandboxSessionRecord
    ) -> SandboxSessionRecord: ...

    def mark_failed(
        self, session: SandboxSessionRecord
    ) -> SandboxSessionRecord: ...

    def mark_provisioning_failed(
        self, session: SandboxSessionRecord
    ) -> SandboxSessionRecord: ...

    def mark_quarantined(
        self, session: SandboxSessionRecord
    ) -> SandboxSessionRecord: ...

    def close_session(
        self, session: SandboxSessionRecord
    ) -> SandboxSessionRecord: ...


def _canonical_json(model: ObservedTargetMetadata) -> str:
    return json.dumps(
        model.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_payload_json(model: TargetProfile | CompatibilityReport) -> str:
    return json.dumps(
        model.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_compatibility_reference_json(
    reference: CompatibilityReference,
) -> str:
    return json.dumps(
        reference.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256(payload_json: str) -> str:
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def _parse_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None


_COMPATIBILITY_REPORT_COLUMNS = {
    "compatibility_report_id",
    "target_id",
    "profile_id",
    "benchmark_identity",
    "benchmark_version",
    "generated_at",
    "report_version",
    "report_sha256",
    "payload_json",
}
_LEGACY_COMPATIBILITY_REPORT_COLUMNS = _COMPATIBILITY_REPORT_COLUMNS - {
    "report_version",
    "payload_json",
}
_CREATE_COMPATIBILITY_REPORTS_SQL = """
    CREATE TABLE compatibility_reports (
        compatibility_report_id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        benchmark_identity TEXT NOT NULL CHECK (
            benchmark_identity =
                'CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0'
        ),
        benchmark_version TEXT NOT NULL CHECK (
            benchmark_version = 'v1.0.0'
        ),
        generated_at TEXT NOT NULL,
        report_version TEXT NOT NULL CHECK (report_version = '1'),
        report_sha256 TEXT NOT NULL CHECK (
            length(report_sha256) = 64
            AND report_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        payload_json TEXT NOT NULL,
        UNIQUE (target_id, profile_id, compatibility_report_id),
        FOREIGN KEY (target_id) REFERENCES targets(target_id),
        FOREIGN KEY (profile_id) REFERENCES profiles(profile_id),
        FOREIGN KEY (target_id, profile_id)
            REFERENCES profiles(target_id, profile_id)
    )
"""

_VALIDATION_JOB_COLUMNS = {
    "validation_job_id",
    "request_id",
    "target_id",
    "profile_id",
    "compatibility_report_id",
    "assigned_agent_id",
    "job_type",
    "control_id",
    "validation_mode",
    "execution_mode",
    "administrator_approval_acknowledged",
    "compatibility_risk_acknowledged",
    "compatibility_override_reason",
    "compatibility_reference_json",
    "status",
    "created_at",
    "dispatched_at",
    "completed_at",
}
_VALIDATION_RESULT_COLUMNS = {
    "validation_result_id",
    "validation_job_id",
    "target_id",
    "profile_id",
    "compatibility_report_id",
    "agent_id",
    "control_id",
    "validation_mode",
    "execution_mode",
    "created_at",
    "dispatched_at",
    "completed_at",
    "result_sha256",
    "payload_json",
}
_CREATE_VALIDATION_JOBS_SQL = """
    CREATE TABLE validation_jobs (
        validation_job_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        target_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        compatibility_report_id TEXT NOT NULL,
        assigned_agent_id TEXT,
        job_type TEXT NOT NULL CHECK (job_type = 'VALIDATE_CONTROL'),
        control_id TEXT NOT NULL CHECK (control_id = '7.1.1'),
        validation_mode TEXT NOT NULL CHECK (validation_mode = 'sandbox'),
        execution_mode TEXT NOT NULL CHECK (execution_mode = 'execute'),
        administrator_approval_acknowledged INTEGER NOT NULL CHECK (
            administrator_approval_acknowledged = 1
        ),
        compatibility_risk_acknowledged INTEGER NOT NULL CHECK (
            compatibility_risk_acknowledged IN (0, 1)
        ),
        compatibility_override_reason TEXT CHECK (
            compatibility_override_reason IS NULL
            OR length(trim(compatibility_override_reason)) > 0
        ),
        compatibility_reference_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN ('pending', 'dispatched', 'completed')
        ),
        created_at TEXT NOT NULL,
        dispatched_at TEXT,
        completed_at TEXT,
        CHECK (
            (
                status = 'pending'
                AND assigned_agent_id IS NULL
                AND dispatched_at IS NULL
                AND completed_at IS NULL
            ) OR (
                status = 'dispatched'
                AND assigned_agent_id IS NOT NULL
                AND dispatched_at IS NOT NULL
                AND completed_at IS NULL
            ) OR (
                status = 'completed'
                AND assigned_agent_id IS NOT NULL
                AND dispatched_at IS NOT NULL
                AND completed_at IS NOT NULL
            )
        ),
        UNIQUE (
            target_id, profile_id, compatibility_report_id, validation_job_id
        ),
        UNIQUE (target_id, validation_job_id, assigned_agent_id),
        FOREIGN KEY (target_id) REFERENCES targets(target_id),
        FOREIGN KEY (profile_id) REFERENCES profiles(profile_id),
        FOREIGN KEY (target_id, profile_id)
            REFERENCES profiles(target_id, profile_id),
        FOREIGN KEY (compatibility_report_id)
            REFERENCES compatibility_reports(compatibility_report_id),
        FOREIGN KEY (target_id, profile_id, compatibility_report_id)
            REFERENCES compatibility_reports(
                target_id, profile_id, compatibility_report_id
            ),
        FOREIGN KEY (assigned_agent_id) REFERENCES agents(agent_id),
        FOREIGN KEY (target_id, assigned_agent_id)
            REFERENCES agents(target_id, agent_id)
    )
"""
_CREATE_VALIDATION_RESULTS_SQL = """
    CREATE TABLE validation_results (
        validation_result_id TEXT PRIMARY KEY,
        validation_job_id TEXT NOT NULL UNIQUE,
        target_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        compatibility_report_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        control_id TEXT NOT NULL CHECK (control_id = '7.1.1'),
        validation_mode TEXT NOT NULL CHECK (validation_mode = 'sandbox'),
        execution_mode TEXT NOT NULL CHECK (execution_mode = 'execute'),
        created_at TEXT NOT NULL,
        dispatched_at TEXT NOT NULL,
        completed_at TEXT NOT NULL,
        result_sha256 TEXT NOT NULL CHECK (
            length(result_sha256) = 64
            AND result_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        payload_json TEXT NOT NULL,
        UNIQUE (
            target_id, profile_id, compatibility_report_id,
            validation_job_id, validation_result_id
        ),
        FOREIGN KEY (target_id) REFERENCES targets(target_id),
        FOREIGN KEY (profile_id) REFERENCES profiles(profile_id),
        FOREIGN KEY (target_id, profile_id)
            REFERENCES profiles(target_id, profile_id),
        FOREIGN KEY (compatibility_report_id)
            REFERENCES compatibility_reports(compatibility_report_id),
        FOREIGN KEY (target_id, profile_id, compatibility_report_id)
            REFERENCES compatibility_reports(
                target_id, profile_id, compatibility_report_id
            ),
        FOREIGN KEY (
            target_id, profile_id, compatibility_report_id, validation_job_id
        ) REFERENCES validation_jobs(
            target_id, profile_id, compatibility_report_id, validation_job_id
        ),
        FOREIGN KEY (agent_id) REFERENCES agents(agent_id),
        FOREIGN KEY (target_id, validation_job_id, agent_id)
            REFERENCES validation_jobs(
                target_id, validation_job_id, assigned_agent_id
            )
    )
"""

_SANDBOX_SESSION_COLUMNS = {
    "sandbox_session_id",
    "request_id",
    "source_target_id",
    "source_profile_id",
    "source_compatibility_report_id",
    "control_id",
    "provider_type",
    "status",
    "sandbox_instance_id",
    "administrator_sandbox_authorization_acknowledged",
    "compatibility_reference_json",
    "compatibility_reference_sha256",
    "created_at",
    "provisioning_started_at",
    "ready_at",
    "validation_started_at",
    "completed_at",
    "closed_at",
    "failure_reason",
    "quarantine_reason",
}
_CREATE_SANDBOX_SESSIONS_SQL = """
    CREATE TABLE sandbox_sessions (
        sandbox_session_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        source_target_id TEXT NOT NULL,
        source_profile_id TEXT NOT NULL,
        source_compatibility_report_id TEXT NOT NULL,
        control_id TEXT NOT NULL CHECK (control_id = '7.1.1'),
        provider_type TEXT NOT NULL CHECK (provider_type = 'local_nested_vm'),
        status TEXT NOT NULL CHECK (
            status IN (
                'REQUESTED', 'PROVISIONING', 'READY', 'VALIDATING',
                'COMPLETED', 'FAILED', 'QUARANTINED', 'CLOSED'
            )
        ),
        sandbox_instance_id TEXT CHECK (
            sandbox_instance_id IS NULL
            OR length(trim(sandbox_instance_id)) > 0
        ),
        administrator_sandbox_authorization_acknowledged INTEGER NOT NULL
            CHECK (administrator_sandbox_authorization_acknowledged = 1),
        compatibility_reference_json TEXT NOT NULL,
        compatibility_reference_sha256 TEXT NOT NULL CHECK (
            length(compatibility_reference_sha256) = 64
            AND compatibility_reference_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL,
        provisioning_started_at TEXT,
        ready_at TEXT,
        validation_started_at TEXT,
        completed_at TEXT,
        closed_at TEXT,
        failure_reason TEXT CHECK (
            failure_reason IS NULL OR length(trim(failure_reason)) > 0
        ),
        quarantine_reason TEXT CHECK (
            quarantine_reason IS NULL OR length(trim(quarantine_reason)) > 0
        ),
        CHECK (
            (
                status = 'REQUESTED'
                AND sandbox_instance_id IS NULL
                AND provisioning_started_at IS NULL
                AND ready_at IS NULL
                AND validation_started_at IS NULL
                AND completed_at IS NULL
                AND closed_at IS NULL
                AND failure_reason IS NULL
                AND quarantine_reason IS NULL
            ) OR (
                status = 'PROVISIONING'
                AND sandbox_instance_id IS NULL
                AND provisioning_started_at IS NOT NULL
                AND ready_at IS NULL
                AND validation_started_at IS NULL
                AND completed_at IS NULL
                AND closed_at IS NULL
                AND failure_reason IS NULL
                AND quarantine_reason IS NULL
            ) OR (
                status = 'READY'
                AND sandbox_instance_id IS NOT NULL
                AND provisioning_started_at IS NOT NULL
                AND ready_at IS NOT NULL
                AND validation_started_at IS NULL
                AND completed_at IS NULL
                AND closed_at IS NULL
                AND failure_reason IS NULL
                AND quarantine_reason IS NULL
            ) OR (
                status = 'VALIDATING'
                AND sandbox_instance_id IS NOT NULL
                AND provisioning_started_at IS NOT NULL
                AND ready_at IS NOT NULL
                AND validation_started_at IS NOT NULL
                AND completed_at IS NULL
                AND closed_at IS NULL
                AND failure_reason IS NULL
                AND quarantine_reason IS NULL
            ) OR (
                status = 'COMPLETED'
                AND sandbox_instance_id IS NOT NULL
                AND provisioning_started_at IS NOT NULL
                AND ready_at IS NOT NULL
                AND validation_started_at IS NOT NULL
                AND completed_at IS NOT NULL
                AND closed_at IS NULL
                AND failure_reason IS NULL
                AND quarantine_reason IS NULL
            ) OR (
                status = 'FAILED'
                AND provisioning_started_at IS NOT NULL
                AND completed_at IS NOT NULL
                AND closed_at IS NULL
                AND failure_reason IS NOT NULL
                AND quarantine_reason IS NULL
                AND (
                    (
                        sandbox_instance_id IS NULL
                        AND ready_at IS NULL
                        AND validation_started_at IS NULL
                    ) OR (
                        sandbox_instance_id IS NOT NULL
                        AND ready_at IS NOT NULL
                    )
                )
            ) OR (
                status = 'QUARANTINED'
                AND sandbox_instance_id IS NOT NULL
                AND provisioning_started_at IS NOT NULL
                AND ready_at IS NOT NULL
                AND validation_started_at IS NOT NULL
                AND completed_at IS NOT NULL
                AND closed_at IS NULL
                AND failure_reason IS NULL
                AND quarantine_reason IS NOT NULL
            ) OR (
                status = 'CLOSED'
                AND provisioning_started_at IS NOT NULL
                AND completed_at IS NOT NULL
                AND closed_at IS NOT NULL
                AND NOT (
                    failure_reason IS NOT NULL
                    AND quarantine_reason IS NOT NULL
                )
                AND (
                    (
                        failure_reason IS NOT NULL
                        AND quarantine_reason IS NULL
                        AND (
                            (
                                sandbox_instance_id IS NULL
                                AND ready_at IS NULL
                                AND validation_started_at IS NULL
                            ) OR (
                                sandbox_instance_id IS NOT NULL
                                AND ready_at IS NOT NULL
                            )
                        )
                    ) OR (
                        failure_reason IS NULL
                        AND quarantine_reason IS NOT NULL
                        AND sandbox_instance_id IS NOT NULL
                        AND ready_at IS NOT NULL
                        AND validation_started_at IS NOT NULL
                    ) OR (
                        failure_reason IS NULL
                        AND quarantine_reason IS NULL
                        AND sandbox_instance_id IS NOT NULL
                        AND ready_at IS NOT NULL
                        AND validation_started_at IS NOT NULL
                    )
                )
            )
        ),
        UNIQUE (
            source_target_id, source_profile_id,
            source_compatibility_report_id, sandbox_session_id
        ),
        UNIQUE (provider_type, sandbox_instance_id),
        FOREIGN KEY (source_target_id) REFERENCES targets(target_id),
        FOREIGN KEY (source_profile_id) REFERENCES profiles(profile_id),
        FOREIGN KEY (source_target_id, source_profile_id)
            REFERENCES profiles(target_id, profile_id),
        FOREIGN KEY (source_compatibility_report_id)
            REFERENCES compatibility_reports(compatibility_report_id),
        FOREIGN KEY (
            source_target_id, source_profile_id,
            source_compatibility_report_id
        ) REFERENCES compatibility_reports(
            target_id, profile_id, compatibility_report_id
        )
    )
"""


_SANDBOX_VALIDATION_EXECUTION_COLUMNS = {
    "sandbox_session_id",
    "validation_job_id",
    "request_id",
    "source_target_id",
    "source_profile_id",
    "source_compatibility_report_id",
    "job_json",
    "status",
    "dispatched_at",
    "completed_at",
    "result_sha256",
    "payload_json",
}

_CREATE_SANDBOX_VALIDATION_EXECUTIONS_SQL = """
    CREATE TABLE sandbox_validation_executions (
        sandbox_session_id TEXT PRIMARY KEY,
        validation_job_id TEXT NOT NULL UNIQUE,
        request_id TEXT NOT NULL UNIQUE,
        source_target_id TEXT NOT NULL,
        source_profile_id TEXT NOT NULL,
        source_compatibility_report_id TEXT NOT NULL,
        job_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN ('DISPATCHED', 'COMPLETED')
        ),
        dispatched_at TEXT NOT NULL,
        completed_at TEXT,
        result_sha256 TEXT CHECK (
            result_sha256 IS NULL OR (
                length(result_sha256) = 64
                AND result_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        payload_json TEXT,
        CHECK (
            (
                status = 'DISPATCHED'
                AND completed_at IS NULL
                AND result_sha256 IS NULL
                AND payload_json IS NULL
            ) OR (
                status = 'COMPLETED'
                AND completed_at IS NOT NULL
                AND result_sha256 IS NOT NULL
                AND payload_json IS NOT NULL
            )
        ),
        FOREIGN KEY (validation_job_id)
            REFERENCES validation_jobs(validation_job_id),
        FOREIGN KEY (
            source_target_id,
            source_profile_id,
            source_compatibility_report_id,
            sandbox_session_id
        ) REFERENCES sandbox_sessions (
            source_target_id,
            source_profile_id,
            source_compatibility_report_id,
            sandbox_session_id
        )
    )
"""

_ENFORCEMENT_JOB_COLUMNS = {
    "enforcement_job_id", "request_id", "target_id", "profile_id",
    "compatibility_report_id", "sandbox_session_id", "control_id",
    "job_type", "administrator_enforcement_approval_acknowledged",
    "sandbox_evidence_sha256", "status", "created_at", "assigned_agent_id", "dispatched_at",
    "completed_at",
}
_CREATE_ENFORCEMENT_JOBS_M7A_SQL = """
    CREATE TABLE enforcement_jobs (
        enforcement_job_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        target_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        compatibility_report_id TEXT NOT NULL,
        sandbox_session_id TEXT NOT NULL,
        control_id TEXT NOT NULL CHECK (control_id = '7.1.1'),
        job_type TEXT NOT NULL CHECK (job_type = 'ENFORCE_CONTROL'),
        administrator_enforcement_approval_acknowledged INTEGER NOT NULL
            CHECK (administrator_enforcement_approval_acknowledged = 1),
        sandbox_evidence_sha256 TEXT NOT NULL CHECK (
            length(sandbox_evidence_sha256) = 64
            AND sandbox_evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        status TEXT NOT NULL CHECK (status = 'pending'),
        created_at TEXT NOT NULL,
        dispatched_at TEXT CHECK (dispatched_at IS NULL),
        completed_at TEXT CHECK (completed_at IS NULL),
        UNIQUE (
            target_id, profile_id, compatibility_report_id,
            sandbox_session_id, enforcement_job_id
        ),
        FOREIGN KEY (target_id) REFERENCES targets(target_id),
        FOREIGN KEY (target_id, profile_id)
            REFERENCES profiles(target_id, profile_id),
        FOREIGN KEY (target_id, profile_id, compatibility_report_id)
            REFERENCES compatibility_reports(
                target_id, profile_id, compatibility_report_id
            ),
        FOREIGN KEY (
            target_id, profile_id, compatibility_report_id,
            sandbox_session_id
        ) REFERENCES sandbox_sessions (
            source_target_id, source_profile_id,
            source_compatibility_report_id, sandbox_session_id
        ),
        FOREIGN KEY (sandbox_session_id)
            REFERENCES sandbox_validation_executions(sandbox_session_id)
    )
"""
_CREATE_ENFORCEMENT_JOBS_SQL = """
    CREATE TABLE enforcement_jobs (
        enforcement_job_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        target_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        compatibility_report_id TEXT NOT NULL,
        sandbox_session_id TEXT NOT NULL,
        control_id TEXT NOT NULL CHECK (control_id = '7.1.1'),
        job_type TEXT NOT NULL CHECK (job_type = 'ENFORCE_CONTROL'),
        administrator_enforcement_approval_acknowledged INTEGER NOT NULL
            CHECK (administrator_enforcement_approval_acknowledged = 1),
        sandbox_evidence_sha256 TEXT NOT NULL CHECK (
            length(sandbox_evidence_sha256) = 64
            AND sandbox_evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        status TEXT NOT NULL CHECK (status IN ('pending', 'dispatched')),
        created_at TEXT NOT NULL,
        assigned_agent_id TEXT,
        dispatched_at TEXT,
        completed_at TEXT CHECK (completed_at IS NULL),
        CHECK (
            (status = 'pending' AND assigned_agent_id IS NULL
                AND dispatched_at IS NULL)
            OR (status = 'dispatched' AND assigned_agent_id IS NOT NULL
                AND dispatched_at IS NOT NULL)
        ),
        UNIQUE (
            target_id, profile_id, compatibility_report_id,
            sandbox_session_id, enforcement_job_id
        ),
        FOREIGN KEY (target_id) REFERENCES targets(target_id),
        FOREIGN KEY (target_id, profile_id)
            REFERENCES profiles(target_id, profile_id),
        FOREIGN KEY (target_id, profile_id, compatibility_report_id)
            REFERENCES compatibility_reports(
                target_id, profile_id, compatibility_report_id
            ),
        FOREIGN KEY (
            target_id, profile_id, compatibility_report_id,
            sandbox_session_id
        ) REFERENCES sandbox_sessions (
            source_target_id, source_profile_id,
            source_compatibility_report_id, sandbox_session_id
        ),
        FOREIGN KEY (sandbox_session_id)
            REFERENCES sandbox_validation_executions(sandbox_session_id),
        FOREIGN KEY (target_id, assigned_agent_id)
            REFERENCES agents(target_id, agent_id)
    )
"""
_CREATE_ENFORCEMENT_JOBS_M7D_SQL = """
    CREATE TABLE enforcement_jobs (
        enforcement_job_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        target_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        compatibility_report_id TEXT NOT NULL,
        sandbox_session_id TEXT NOT NULL,
        control_id TEXT NOT NULL CHECK (control_id = '7.1.1'),
        job_type TEXT NOT NULL CHECK (job_type = 'ENFORCE_CONTROL'),
        administrator_enforcement_approval_acknowledged INTEGER NOT NULL
            CHECK (administrator_enforcement_approval_acknowledged = 1),
        sandbox_evidence_sha256 TEXT NOT NULL CHECK (
            length(sandbox_evidence_sha256) = 64
            AND sandbox_evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        status TEXT NOT NULL CHECK (status IN ('pending', 'dispatched', 'completed')),
        created_at TEXT NOT NULL,
        assigned_agent_id TEXT,
        dispatched_at TEXT,
        completed_at TEXT,
        CHECK (
            (status = 'pending' AND assigned_agent_id IS NULL
                AND dispatched_at IS NULL AND completed_at IS NULL)
            OR (status = 'dispatched' AND assigned_agent_id IS NOT NULL
                AND dispatched_at IS NOT NULL AND completed_at IS NULL)
            OR (status = 'completed' AND assigned_agent_id IS NOT NULL
                AND dispatched_at IS NOT NULL AND completed_at IS NOT NULL)
        ),
        UNIQUE (
            target_id, profile_id, compatibility_report_id,
            sandbox_session_id, enforcement_job_id
        ),
        UNIQUE (target_id, enforcement_job_id, assigned_agent_id),
        FOREIGN KEY (target_id) REFERENCES targets(target_id),
        FOREIGN KEY (target_id, profile_id)
            REFERENCES profiles(target_id, profile_id),
        FOREIGN KEY (target_id, profile_id, compatibility_report_id)
            REFERENCES compatibility_reports(
                target_id, profile_id, compatibility_report_id
            ),
        FOREIGN KEY (
            target_id, profile_id, compatibility_report_id,
            sandbox_session_id
        ) REFERENCES sandbox_sessions (
            source_target_id, source_profile_id,
            source_compatibility_report_id, sandbox_session_id
        ),
        FOREIGN KEY (sandbox_session_id)
            REFERENCES sandbox_validation_executions(sandbox_session_id),
        FOREIGN KEY (target_id, assigned_agent_id)
            REFERENCES agents(target_id, agent_id)
    )
"""

_ENFORCEMENT_RESULT_COLUMNS = {
    "enforcement_result_id", "enforcement_job_id", "target_id", "agent_id",
    "control_id", "m6_evidence_sha256", "outcome", "received_at",
    "result_sha256", "payload_json", "post_enforcement_profile_job_id",
}
_CREATE_ENFORCEMENT_RESULTS_SQL = """
    CREATE TABLE enforcement_results (
        enforcement_result_id TEXT PRIMARY KEY,
        enforcement_job_id TEXT NOT NULL UNIQUE,
        target_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        control_id TEXT NOT NULL CHECK (control_id = '7.1.1'),
        m6_evidence_sha256 TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK (outcome IN (
            'SUCCEEDED', 'BLOCKED_DRIFT', 'FAILED', 'ROLLED_BACK', 'ROLLBACK_FAILED'
        )),
        received_at TEXT NOT NULL,
        result_sha256 TEXT NOT NULL CHECK (
            length(result_sha256) = 64
            AND result_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        payload_json TEXT NOT NULL,
        post_enforcement_profile_job_id TEXT NOT NULL UNIQUE,
        UNIQUE (target_id, enforcement_result_id),
        FOREIGN KEY (target_id, enforcement_job_id, agent_id)
            REFERENCES enforcement_jobs(target_id, enforcement_job_id, assigned_agent_id),
        FOREIGN KEY (target_id, post_enforcement_profile_job_id)
            REFERENCES jobs(target_id, job_id)
    )
"""
_POST_ENFORCEMENT_VERIFICATION_COLUMNS = {
    "enforcement_result_id", "target_id", "profile_job_id", "profile_id",
    "profile_sha256", "outcome", "observed_source_state_json", "verified_at",
}
_CREATE_POST_ENFORCEMENT_VERIFICATIONS_SQL = """
    CREATE TABLE post_enforcement_verifications (
        enforcement_result_id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        profile_job_id TEXT NOT NULL UNIQUE,
        profile_id TEXT NOT NULL UNIQUE,
        profile_sha256 TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK (outcome IN (
            'VERIFIED', 'DRIFT_DETECTED', 'OBSERVED_FAILURE_STATE'
        )),
        observed_source_state_json TEXT,
        verified_at TEXT NOT NULL,
        FOREIGN KEY (target_id, enforcement_result_id)
            REFERENCES enforcement_results(target_id, enforcement_result_id),
        FOREIGN KEY (target_id, profile_job_id)
            REFERENCES jobs(target_id, job_id),
        FOREIGN KEY (target_id, profile_id)
            REFERENCES profiles(target_id, profile_id)
    )
"""

def _normalized_schema_sql(value: str) -> str:
    """Normalize insignificant SQL whitespace for an exact schema fingerprint."""

    return " ".join(value.strip().rstrip(";").split())


def _canonical_stored_uuid_text(
    raw: object,
    field_name: str,
) -> UUID:
    """Require persisted UUID text to already use canonical representation."""

    if not isinstance(raw, str):
        raise StorageConflictError(
            f"stored {field_name} is not canonical UUID text"
        )

    try:
        parsed = UUID(raw)
    except (TypeError, ValueError, AttributeError) as error:
        raise StorageConflictError(
            f"stored {field_name} is not a valid UUID"
        ) from error

    if raw != str(parsed):
        raise StorageConflictError(
            f"stored {field_name} is not a canonical UUID"
        )

    return parsed


class SQLiteControllerRepository:
    """Small local SQLite repository suitable for a multi-target PoC."""

    def __init__(self, path: Path | str) -> None:
        supplied = os.fspath(path)
        if supplied == ":memory:":
            raise ControllerStorageSecurityError(
                "controller identity persistence requires a filesystem database"
            )
        self.path = Path(os.path.abspath(supplied))
        self._ensure_safe_parent()
        self._prepare_database_file()
        self._initialize()

    def _ensure_safe_parent(self) -> None:
        parent = self.path.parent
        anchor = Path(parent.anchor)
        current = anchor
        relative_parts = parent.parts[1:] if parent.is_absolute() else parent.parts
        for part in relative_parts:
            current /= part
            try:
                item_stat = os.lstat(current)
            except FileNotFoundError:
                try:
                    os.mkdir(current, mode=0o700)
                except FileExistsError:
                    pass
                item_stat = os.lstat(current)
            if stat.S_ISLNK(item_stat.st_mode):
                raise ControllerStorageSecurityError(
                    "controller database parent must not contain symlinks"
                )
            if not stat.S_ISDIR(item_stat.st_mode):
                raise ControllerStorageSecurityError(
                    "controller database parent must contain only directories"
                )
        parent_stat = os.stat(parent, follow_symlinks=False)
        if parent_stat.st_uid != os.geteuid():
            raise ControllerStorageSecurityError(
                "controller database parent must be owned by the current user"
            )
        if stat.S_IMODE(parent_stat.st_mode) & 0o022:
            raise ControllerStorageSecurityError(
                "controller database parent must not be group/world writable"
            )

    def _prepare_database_file(self) -> None:
        try:
            existing = os.lstat(self.path)
        except FileNotFoundError:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self.path, flags, 0o600)
            except FileExistsError:
                existing = os.lstat(self.path)
            else:
                try:
                    os.fchmod(descriptor, 0o600)
                finally:
                    os.close(descriptor)
                return
        self._validate_database_stat(existing)

    @staticmethod
    def _validate_database_stat(database_stat: os.stat_result) -> None:
        if stat.S_ISLNK(database_stat.st_mode):
            raise ControllerStorageSecurityError(
                "controller database must not be a symlink"
            )
        if not stat.S_ISREG(database_stat.st_mode):
            raise ControllerStorageSecurityError(
                "controller database must be a regular file"
            )
        if database_stat.st_uid != os.geteuid():
            raise ControllerStorageSecurityError(
                "controller database must be owned by the current user"
            )
        if stat.S_IMODE(database_stat.st_mode) != 0o600:
            raise ControllerStorageSecurityError(
                "controller database permissions must be 0600"
            )

    def _validate_database_path(self) -> None:
        try:
            database_stat = os.lstat(self.path)
        except FileNotFoundError as error:
            raise ControllerStorageSecurityError(
                "controller database disappeared"
            ) from error
        self._validate_database_stat(database_stat)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._validate_database_path()
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    target_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL UNIQUE,
                    installation_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    last_seen TEXT,
                    status TEXT NOT NULL CHECK (status IN ('enrolled', 'online')),
                    agent_version TEXT NOT NULL,
                    observed_metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL UNIQUE,
                    installation_id TEXT NOT NULL UNIQUE,
                    credential_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen TEXT,
                    UNIQUE (target_id, agent_id),
                    FOREIGN KEY (target_id) REFERENCES targets(target_id)
                );

                CREATE TABLE IF NOT EXISTS metadata_changes (
                    change_id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    previous_metadata_json TEXT NOT NULL,
                    current_metadata_json TEXT NOT NULL,
                    FOREIGN KEY (target_id) REFERENCES targets(target_id),
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id),
                    FOREIGN KEY (target_id, agent_id)
                        REFERENCES agents(target_id, agent_id)
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    assigned_agent_id TEXT,
                    job_type TEXT NOT NULL CHECK (job_type = 'PROFILE_TARGET'),
                    status TEXT NOT NULL CHECK (
                        status IN ('pending', 'dispatched', 'completed')
                    ),
                    created_at TEXT NOT NULL,
                    dispatched_at TEXT,
                    completed_at TEXT,
                    UNIQUE (target_id, job_id),
                    FOREIGN KEY (target_id) REFERENCES targets(target_id),
                    FOREIGN KEY (assigned_agent_id) REFERENCES agents(agent_id),
                    FOREIGN KEY (target_id, assigned_agent_id)
                        REFERENCES agents(target_id, agent_id)
                );

                CREATE INDEX IF NOT EXISTS jobs_target_status_idx
                    ON jobs(target_id, status, created_at);

                CREATE TABLE IF NOT EXISTS profiles (
                    profile_id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    job_id TEXT NOT NULL UNIQUE,
                    collected_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    profile_sha256 TEXT NOT NULL,
                    profiler_version TEXT,
                    sentra_version TEXT,
                    payload_json TEXT NOT NULL,
                    UNIQUE (target_id, profile_id),
                    FOREIGN KEY (target_id) REFERENCES targets(target_id),
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id),
                    FOREIGN KEY (job_id) REFERENCES jobs(job_id),
                    FOREIGN KEY (target_id, agent_id)
                        REFERENCES agents(target_id, agent_id),
                    FOREIGN KEY (target_id, job_id)
                        REFERENCES jobs(target_id, job_id)
                );

                CREATE INDEX IF NOT EXISTS profiles_target_received_idx
                    ON profiles(target_id, received_at);
                """
            )
            self._initialize_compatibility_reports(connection)
            # SQLite DDL is not implicitly wrapped by the Python driver.  A
            # savepoint makes the two-table M6D addition atomic while also
            # remaining valid if initialization is later called inside a
            # broader migration transaction.
            connection.execute("SAVEPOINT sentra_m6d_validation_schema")
            try:
                self._initialize_validation_storage(connection)
            except BaseException:
                connection.execute(
                    "ROLLBACK TO SAVEPOINT sentra_m6d_validation_schema"
                )
                connection.execute(
                    "RELEASE SAVEPOINT sentra_m6d_validation_schema"
                )
                raise
            else:
                connection.execute(
                    "RELEASE SAVEPOINT sentra_m6d_validation_schema"
                )
            # M6E-A is another strictly additive Controller-side table.  Keep
            # its migration independently atomic so a populated M6D database
            # is preserved byte-for-byte if the new schema is unacceptable.
            connection.execute("SAVEPOINT sentra_m6e_sandbox_schema")
            try:
                self._initialize_sandbox_storage(connection)
            except BaseException:
                connection.execute(
                    "ROLLBACK TO SAVEPOINT sentra_m6e_sandbox_schema"
                )
                connection.execute(
                    "RELEASE SAVEPOINT sentra_m6e_sandbox_schema"
                )
                raise
            else:
                connection.execute(
                    "RELEASE SAVEPOINT sentra_m6e_sandbox_schema"
                )

            connection.execute(
                "SAVEPOINT sentra_m6e_validation_evidence_schema"
            )
            try:
                self._initialize_sandbox_validation_storage(connection)
            except BaseException:
                connection.execute(
                    "ROLLBACK TO SAVEPOINT "
                    "sentra_m6e_validation_evidence_schema"
                )
                connection.execute(
                    "RELEASE SAVEPOINT "
                    "sentra_m6e_validation_evidence_schema"
                )
                raise
            else:
                connection.execute(
                    "RELEASE SAVEPOINT "
                    "sentra_m6e_validation_evidence_schema"
                )
            connection.execute("SAVEPOINT sentra_m7d_enforcement_schema")
            try:
                self._initialize_enforcement_storage(connection)
            except BaseException:
                connection.execute("ROLLBACK TO SAVEPOINT sentra_m7d_enforcement_schema")
                connection.execute("RELEASE SAVEPOINT sentra_m7d_enforcement_schema")
                raise
            else:
                connection.execute("RELEASE SAVEPOINT sentra_m7d_enforcement_schema")
        self._validate_all_enforcement_jobs()

    @staticmethod
    def _initialize_enforcement_storage(connection: sqlite3.Connection) -> None:
        result_tables = {
            item["name"] for item in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name IN ('enforcement_results', 'post_enforcement_verifications')"
            ).fetchall()
        }
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' "
            "AND name = 'enforcement_jobs'"
        ).fetchone()
        new_job_table = row is None
        legacy_job_table = False
        if row is None:
            if result_tables:
                raise ControllerStorageSecurityError("enforcement schema is incomplete")
            connection.execute(_CREATE_ENFORCEMENT_JOBS_M7D_SQL)
        elif isinstance(row["sql"], str) and _normalized_schema_sql(row["sql"]) in {
            _normalized_schema_sql(_CREATE_ENFORCEMENT_JOBS_M7A_SQL),
            _normalized_schema_sql(_CREATE_ENFORCEMENT_JOBS_SQL),
        }:
            legacy_job_table = True
            if result_tables:
                # Older-schema fixture/rollback with new empty child tables:
                # no evidence can be lost, so rebuild only those empty tables.
                if result_tables != {
                    "enforcement_results", "post_enforcement_verifications",
                } or any(
                    connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
                    is not None for table in result_tables
                ):
                    raise ControllerStorageSecurityError(
                        "enforcement migration contains result evidence"
                    )
                connection.execute("DROP TABLE post_enforcement_verifications")
                connection.execute("DROP TABLE enforcement_results")
                result_tables = set()
            # Only exact older schemas are migrated; preserve their rows under
            # a savepoint and reject malformed lineage on the subsequent scan.
            is_m7a = (
                _normalized_schema_sql(row["sql"])
                == _normalized_schema_sql(_CREATE_ENFORCEMENT_JOBS_M7A_SQL)
            )
            connection.execute(
                "ALTER TABLE enforcement_jobs RENAME TO enforcement_jobs_m7_backup"
            )
            connection.execute(_CREATE_ENFORCEMENT_JOBS_M7D_SQL)
            assignment = "NULL" if is_m7a else "assigned_agent_id"
            connection.execute(
                f"""INSERT INTO enforcement_jobs (
                    enforcement_job_id, request_id, target_id, profile_id,
                    compatibility_report_id, sandbox_session_id, control_id,
                    job_type, administrator_enforcement_approval_acknowledged,
                    sandbox_evidence_sha256, status, created_at,
                    assigned_agent_id, dispatched_at, completed_at
                ) SELECT enforcement_job_id, request_id, target_id, profile_id,
                         compatibility_report_id, sandbox_session_id, control_id,
                         job_type, administrator_enforcement_approval_acknowledged,
                         sandbox_evidence_sha256, status, created_at,
                         {assignment}, dispatched_at, completed_at
                  FROM enforcement_jobs_m7_backup"""
            )
            connection.execute("DROP TABLE enforcement_jobs_m7_backup")
        elif (
            not isinstance(row["sql"], str)
            or _normalized_schema_sql(row["sql"])
            != _normalized_schema_sql(_CREATE_ENFORCEMENT_JOBS_M7D_SQL)
        ):
            raise ControllerStorageSecurityError("enforcement schema is not recognized")
        columns = {
            item["name"] for item in connection.execute(
                "PRAGMA table_info(enforcement_jobs)"
            ).fetchall()
        }
        if columns != _ENFORCEMENT_JOB_COLUMNS:
            raise ControllerStorageSecurityError("enforcement columns are not recognized")
        if connection.execute(
            "PRAGMA foreign_key_check(enforcement_jobs)"
        ).fetchall():
            raise ControllerStorageSecurityError("enforcement lineage is invalid")
        expected_tables = {
            "enforcement_results": (
                _CREATE_ENFORCEMENT_RESULTS_SQL, _ENFORCEMENT_RESULT_COLUMNS,
            ),
            "post_enforcement_verifications": (
                _CREATE_POST_ENFORCEMENT_VERIFICATIONS_SQL,
                _POST_ENFORCEMENT_VERIFICATION_COLUMNS,
            ),
        }
        if not result_tables and (new_job_table or legacy_job_table):
            connection.execute(_CREATE_ENFORCEMENT_RESULTS_SQL)
            connection.execute(_CREATE_POST_ENFORCEMENT_VERIFICATIONS_SQL)
        elif result_tables != set(expected_tables):
            raise ControllerStorageSecurityError("enforcement result schema is incomplete")
        for table, (expected_sql, expected_columns) in expected_tables.items():
            schema = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
            columns = {
                item["name"] for item in connection.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            if (
                schema is None or not isinstance(schema["sql"], str)
                or _normalized_schema_sql(schema["sql"])
                != _normalized_schema_sql(expected_sql)
                or columns != expected_columns
                or connection.execute(f"PRAGMA foreign_key_check({table})").fetchall()
            ):
                raise ControllerStorageSecurityError(
                    "enforcement result schema or lineage is invalid"
                )

    def _validate_all_enforcement_jobs(self) -> None:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM enforcement_jobs").fetchall()
            for row in rows:
                try:
                    job = self._enforcement_job_from_row(connection, row)
                    result_row = connection.execute(
                        "SELECT * FROM enforcement_results WHERE enforcement_job_id = ?",
                        (str(job.enforcement_job_id),),
                    ).fetchone()
                    if (job.status is JobStatus.COMPLETED) != (result_row is not None):
                        raise StorageConflictError("enforcement completion lacks evidence")
                    if result_row is not None:
                        result = self._enforcement_result_from_row(connection, result_row)[0]
                        profile_job = connection.execute(
                            "SELECT status FROM jobs WHERE job_id = ?",
                            (str(result.post_enforcement_profile_job_id),),
                        ).fetchone()
                        verification_row = connection.execute(
                            "SELECT * FROM post_enforcement_verifications "
                            "WHERE enforcement_result_id = ?",
                            (str(result.enforcement_result_id),),
                        ).fetchone()
                        if profile_job is None or (
                            profile_job["status"] == JobStatus.COMPLETED.value
                        ) != (verification_row is not None):
                            raise StorageConflictError(
                                "post-enforcement profile completion lacks verification"
                            )
                except (StorageConflictError, StorageNotFoundError) as error:
                    raise ControllerStorageSecurityError(
                        "stored enforcement job is invalid"
                    ) from error
            for row in connection.execute(
                "SELECT * FROM post_enforcement_verifications"
            ).fetchall():
                try:
                    self._post_enforcement_verification_from_row(connection, row)
                except StorageConflictError as error:
                    raise ControllerStorageSecurityError(
                        "stored post-enforcement verification is invalid"
                    ) from error

    @staticmethod
    def _initialize_sandbox_validation_storage(
        connection: sqlite3.Connection,
    ) -> None:
        table_name = "sandbox_validation_executions"
        row = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()

        if row is None:
            connection.execute(
                _CREATE_SANDBOX_VALIDATION_EXECUTIONS_SQL
            )
        else:
            if (
                not isinstance(row["sql"], str)
                or _normalized_schema_sql(row["sql"])
                != _normalized_schema_sql(
                    _CREATE_SANDBOX_VALIDATION_EXECUTIONS_SQL
                )
            ):
                raise ControllerStorageSecurityError(
                    "sandbox validation schema is not recognized"
                )

        columns = {
            item["name"]
            for item in connection.execute(
                "PRAGMA table_info(sandbox_validation_executions)"
            ).fetchall()
        }
        if columns != _SANDBOX_VALIDATION_EXECUTION_COLUMNS:
            raise ControllerStorageSecurityError(
                "sandbox validation columns are not recognized"
            )

        if connection.execute(
            "PRAGMA foreign_key_check(sandbox_validation_executions)"
        ).fetchall():
            raise ControllerStorageSecurityError(
                "sandbox validation lineage is invalid"
            )

    @staticmethod
    def _initialize_compatibility_reports(connection: sqlite3.Connection) -> None:
        """Create M6C report storage or safely upgrade the empty M6A placeholder.

        The old table recorded lineage metadata only.  Existing rows cannot be
        upgraded into complete evidence reports without inventing a payload, so
        startup fails closed if any such row is present.
        """

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(compatibility_reports)"
            ).fetchall()
        }
        if not columns:
            connection.execute(_CREATE_COMPATIBILITY_REPORTS_SQL)
        elif columns == _LEGACY_COMPATIBILITY_REPORT_COLUMNS:
            existing = connection.execute(
                "SELECT COUNT(*) FROM compatibility_reports"
            ).fetchone()[0]
            if existing:
                raise ControllerStorageSecurityError(
                    "legacy compatibility lineage rows cannot be upgraded "
                    "without inventing report evidence"
                )
            connection.execute("DROP TABLE compatibility_reports")
            connection.execute(_CREATE_COMPATIBILITY_REPORTS_SQL)
        elif columns != _COMPATIBILITY_REPORT_COLUMNS:
            raise ControllerStorageSecurityError(
                "controller compatibility-report schema is not recognized"
            )

        schema_row = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'table' AND name = 'compatibility_reports'"
        ).fetchone()
        if (
            schema_row is None
            or not isinstance(schema_row["sql"], str)
            or _normalized_schema_sql(schema_row["sql"])
            != _normalized_schema_sql(_CREATE_COMPATIBILITY_REPORTS_SQL)
        ):
            raise ControllerStorageSecurityError(
                "controller compatibility-report schema constraints are not recognized"
            )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS compatibility_reports_profile_generated_idx
            ON compatibility_reports(
                target_id, profile_id, generated_at, compatibility_report_id
            )
            """
        )

    @staticmethod
    def _initialize_validation_storage(connection: sqlite3.Connection) -> None:
        """Add M6D storage atomically or reject any unrecognized partial schema.

        M6C databases have neither table, so their only truthful migration is
        additive.  Once either M6D table exists, both exact schemas must be
        present; silently completing or reshaping a partial schema could hide
        lost authorization or validation evidence.
        """

        table_rows = connection.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE type = 'table' AND name IN (?, ?)",
            ("validation_jobs", "validation_results"),
        ).fetchall()
        table_sql = {row["name"]: row["sql"] for row in table_rows}
        expected_sql = {
            "validation_jobs": _CREATE_VALIDATION_JOBS_SQL,
            "validation_results": _CREATE_VALIDATION_RESULTS_SQL,
        }
        expected_columns = {
            "validation_jobs": _VALIDATION_JOB_COLUMNS,
            "validation_results": _VALIDATION_RESULT_COLUMNS,
        }

        if not table_sql:
            connection.execute(_CREATE_VALIDATION_JOBS_SQL)
            connection.execute(_CREATE_VALIDATION_RESULTS_SQL)
            table_sql = {
                row["name"]: row["sql"]
                for row in connection.execute(
                    "SELECT name, sql FROM sqlite_master "
                    "WHERE type = 'table' AND name IN (?, ?)",
                    ("validation_jobs", "validation_results"),
                ).fetchall()
            }
        elif set(table_sql) != set(expected_sql):
            raise ControllerStorageSecurityError(
                "controller validation schema is incomplete or not recognized"
            )

        for table_name, create_sql in expected_sql.items():
            columns = {
                row["name"]
                for row in connection.execute(
                    f"PRAGMA table_info({table_name})"
                ).fetchall()
            }
            schema_sql = table_sql.get(table_name)
            if (
                columns != expected_columns[table_name]
                or not isinstance(schema_sql, str)
                or _normalized_schema_sql(schema_sql)
                != _normalized_schema_sql(create_sql)
            ):
                raise ControllerStorageSecurityError(
                    "controller validation schema constraints are not recognized"
                )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS validation_jobs_target_status_idx
            ON validation_jobs(target_id, status, created_at, validation_job_id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS validation_results_lineage_completed_idx
            ON validation_results(
                target_id, profile_id, compatibility_report_id,
                completed_at, validation_result_id
            )
            """
        )
        foreign_key_violations = [
            *connection.execute(
                "PRAGMA foreign_key_check(validation_jobs)"
            ).fetchall(),
            *connection.execute(
                "PRAGMA foreign_key_check(validation_results)"
            ).fetchall(),
        ]
        if foreign_key_violations:
            raise ControllerStorageSecurityError(
                "controller validation storage contains broken lineage"
            )

    @staticmethod
    def _initialize_sandbox_storage(connection: sqlite3.Connection) -> None:
        """Create the exact additive M6E-A schema or fail closed.

        There is no lossy migration path: an absent table is the expected M6D
        starting point, while any existing table must have the complete known
        columns and constraints.
        """

        schema_row = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'table' AND name = 'sandbox_sessions'"
        ).fetchone()
        if schema_row is None:
            connection.execute(_CREATE_SANDBOX_SESSIONS_SQL)
            schema_row = connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'table' AND name = 'sandbox_sessions'"
            ).fetchone()

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(sandbox_sessions)"
            ).fetchall()
        }
        if (
            columns != _SANDBOX_SESSION_COLUMNS
            or schema_row is None
            or not isinstance(schema_row["sql"], str)
            or _normalized_schema_sql(schema_row["sql"])
            != _normalized_schema_sql(_CREATE_SANDBOX_SESSIONS_SQL)
        ):
            raise ControllerStorageSecurityError(
                "controller sandbox-session schema constraints are not recognized"
            )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS sandbox_sessions_lineage_created_idx
            ON sandbox_sessions(
                source_target_id, source_profile_id,
                source_compatibility_report_id, created_at,
                sandbox_session_id
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS sandbox_sessions_status_created_idx
            ON sandbox_sessions(status, created_at, sandbox_session_id)
            """
        )
        if connection.execute(
            "PRAGMA foreign_key_check(sandbox_sessions)"
        ).fetchall():
            raise ControllerStorageSecurityError(
                "controller sandbox-session storage contains broken lineage"
            )

    def enroll(
        self,
        *,
        target_id: UUID,
        agent_id: UUID,
        installation_id: UUID,
        credential_hash: str,
        agent_version: str,
        metadata: ObservedTargetMetadata,
        created_at: datetime,
    ) -> TargetRecord:
        metadata_json = _canonical_json(metadata)
        try:
            with self._connection() as connection, connection:
                connection.execute(
                    """
                    INSERT INTO targets (
                        target_id, agent_id, installation_id, created_at, last_seen,
                        status, agent_version, observed_metadata_json
                    ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?)
                    """,
                    (
                        str(target_id),
                        str(agent_id),
                        str(installation_id),
                        created_at.isoformat(),
                        TargetStatus.ENROLLED.value,
                        agent_version,
                        metadata_json,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO agents (
                        agent_id, target_id, installation_id, credential_hash,
                        created_at, last_seen
                    ) VALUES (?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        str(agent_id),
                        str(target_id),
                        str(installation_id),
                        credential_hash,
                        created_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise StorageConflictError(
                "installation or controller identity is already enrolled"
            ) from error
        target = self.get_target(target_id)
        assert target is not None
        return target

    def get_agent(self, agent_id: UUID) -> StoredAgent | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (str(agent_id),)
            ).fetchone()
        if row is None:
            return None
        return StoredAgent(
            agent_id=UUID(row["agent_id"]),
            target_id=UUID(row["target_id"]),
            installation_id=UUID(row["installation_id"]),
            credential_hash=row["credential_hash"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_seen=_parse_datetime(row["last_seen"]),
        )

    @staticmethod
    def _target_from_row(row: sqlite3.Row) -> TargetRecord:
        return TargetRecord(
            target_id=UUID(row["target_id"]),
            agent_id=UUID(row["agent_id"]),
            installation_id=UUID(row["installation_id"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            last_seen=_parse_datetime(row["last_seen"]),
            status=TargetStatus(row["status"]),
            agent_version=row["agent_version"],
            observed_metadata=ObservedTargetMetadata.model_validate_json(
                row["observed_metadata_json"]
            ),
        )

    def get_target(self, target_id: UUID) -> TargetRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM targets WHERE target_id = ?", (str(target_id),)
            ).fetchone()
        return None if row is None else self._target_from_row(row)

    def list_targets(self) -> list[TargetRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM targets ORDER BY created_at, target_id"
            ).fetchall()
        return [self._target_from_row(row) for row in rows]

    def record_heartbeat(
        self,
        *,
        target_id: UUID,
        agent_id: UUID,
        seen_at: datetime,
        agent_version: str,
        metadata: ObservedTargetMetadata,
        change_id: UUID,
    ) -> MetadataChangeRecord | None:
        metadata_json = _canonical_json(metadata)
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT observed_metadata_json, created_at, last_seen
                FROM targets WHERE target_id = ?
                """,
                (str(target_id),),
            ).fetchone()
            if row is None:
                raise StorageNotFoundError("target does not exist")
            created_at = datetime.fromisoformat(row["created_at"])
            previous_seen = _parse_datetime(row["last_seen"])
            if seen_at < created_at or (
                previous_seen is not None and seen_at < previous_seen
            ):
                raise StorageConflictError(
                    "heartbeat time precedes existing controller state"
                )
            previous_json = row["observed_metadata_json"]
            connection.execute(
                """
                UPDATE targets
                SET last_seen = ?, status = ?, agent_version = ?,
                    observed_metadata_json = ?
                WHERE target_id = ? AND agent_id = ?
                """,
                (
                    seen_at.isoformat(),
                    TargetStatus.ONLINE.value,
                    agent_version,
                    metadata_json,
                    str(target_id),
                    str(agent_id),
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise StorageNotFoundError("target and agent binding does not exist")
            connection.execute(
                "UPDATE agents SET last_seen = ? WHERE agent_id = ? AND target_id = ?",
                (seen_at.isoformat(), str(agent_id), str(target_id)),
            )
            if previous_json == metadata_json:
                return None
            connection.execute(
                """
                INSERT INTO metadata_changes (
                    change_id, target_id, agent_id, observed_at,
                    previous_metadata_json, current_metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(change_id),
                    str(target_id),
                    str(agent_id),
                    seen_at.isoformat(),
                    previous_json,
                    metadata_json,
                ),
            )
        return MetadataChangeRecord(
            change_id=change_id,
            target_id=target_id,
            agent_id=agent_id,
            observed_at=seen_at,
            previous_metadata=ObservedTargetMetadata.model_validate_json(previous_json),
            current_metadata=metadata,
        )

    def list_metadata_changes(self, target_id: UUID) -> list[MetadataChangeRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM metadata_changes
                WHERE target_id = ? ORDER BY observed_at, change_id
                """,
                (str(target_id),),
            ).fetchall()
        return [
            MetadataChangeRecord(
                change_id=UUID(row["change_id"]),
                target_id=UUID(row["target_id"]),
                agent_id=UUID(row["agent_id"]),
                observed_at=datetime.fromisoformat(row["observed_at"]),
                previous_metadata=ObservedTargetMetadata.model_validate_json(
                    row["previous_metadata_json"]
                ),
                current_metadata=ObservedTargetMetadata.model_validate_json(
                    row["current_metadata_json"]
                ),
            )
            for row in rows
        ]

    def create_job(self, job: JobRecord) -> JobRecord:
        try:
            with self._connection() as connection, connection:
                if connection.execute(
                    "SELECT 1 FROM validation_jobs WHERE validation_job_id = ?",
                    (str(job.job_id),),
                ).fetchone() is not None:
                    raise StorageConflictError("controller job ID already exists")
                connection.execute(
                    """
                    INSERT INTO jobs (
                        job_id, target_id, assigned_agent_id, job_type, status,
                        created_at, dispatched_at, completed_at
                    ) VALUES (?, ?, NULL, ?, ?, ?, NULL, NULL)
                    """,
                    (
                        str(job.job_id),
                        str(job.target_id),
                        job.job_type.value,
                        job.status.value,
                        job.created_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise StorageConflictError("job target does not exist or ID conflicts") from error
        return job

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> StoredJob:
        return StoredJob(
            job=JobRecord(
                job_id=UUID(row["job_id"]),
                target_id=UUID(row["target_id"]),
                job_type=JobType(row["job_type"]),
                status=JobStatus(row["status"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                dispatched_at=_parse_datetime(row["dispatched_at"]),
                completed_at=_parse_datetime(row["completed_at"]),
            ),
            assigned_agent_id=(
                UUID(row["assigned_agent_id"])
                if row["assigned_agent_id"] is not None
                else None
            ),
        )

    def get_job(self, job_id: UUID) -> StoredJob | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (str(job_id),)
            ).fetchone()
        return None if row is None else self._job_from_row(row)

    def poll_jobs(
        self,
        *,
        target_id: UUID,
        agent_id: UUID,
        dispatched_at: datetime,
        limit: int,
    ) -> list[JobRecord]:
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            binding = connection.execute(
                """
                SELECT 1 FROM agents WHERE target_id = ? AND agent_id = ?
                """,
                (str(target_id), str(agent_id)),
            ).fetchone()
            if binding is None:
                raise StorageNotFoundError("target and agent binding does not exist")

            existing = connection.execute(
                """
                SELECT * FROM jobs
                WHERE target_id = ? AND assigned_agent_id = ? AND status = ?
                ORDER BY created_at, job_id LIMIT ?
                """,
                (
                    str(target_id),
                    str(agent_id),
                    JobStatus.DISPATCHED.value,
                    limit,
                ),
            ).fetchall()
            remaining = limit - len(existing)
            claimed: list[sqlite3.Row] = []
            if remaining > 0:
                pending = connection.execute(
                    """
                    SELECT job_id, created_at FROM jobs
                    WHERE target_id = ? AND status = ?
                    ORDER BY created_at, job_id LIMIT ?
                    """,
                    (str(target_id), JobStatus.PENDING.value, remaining),
                ).fetchall()
                if any(
                    dispatched_at < datetime.fromisoformat(row["created_at"])
                    for row in pending
                ):
                    raise StorageConflictError(
                        "dispatch time precedes job creation"
                    )
                for row in pending:
                    connection.execute(
                        """
                        UPDATE jobs
                        SET status = ?, assigned_agent_id = ?, dispatched_at = ?
                        WHERE job_id = ? AND status = ?
                        """,
                        (
                            JobStatus.DISPATCHED.value,
                            str(agent_id),
                            dispatched_at.isoformat(),
                            row["job_id"],
                            JobStatus.PENDING.value,
                        ),
                    )
                if pending:
                    placeholders = ",".join("?" for _ in pending)
                    claimed = connection.execute(
                        f"SELECT * FROM jobs WHERE job_id IN ({placeholders}) "
                        "ORDER BY created_at, job_id",
                        tuple(row["job_id"] for row in pending),
                    ).fetchall()
        return [self._job_from_row(row).job for row in [*existing, *claimed]]

    def poll_validation_jobs(
        self,
        *,
        target_id: UUID,
        agent_id: UUID,
        dispatched_at: datetime,
        limit: int,
    ) -> list[ValidationJobRecord]:
        """Return only this target/Agent's strict, allowlisted validation jobs.

        Existing dispatched work is returned without changing its original
        dispatch timestamp.  Pending work is fully reconstructed and its M3/M4
        lineage is revalidated before any row is claimed, so a corrupt record
        rolls the transaction back rather than becoming a mutation request.
        """

        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            binding = connection.execute(
                """
                SELECT 1 FROM agents WHERE target_id = ? AND agent_id = ?
                """,
                (str(target_id), str(agent_id)),
            ).fetchone()
            if binding is None:
                raise StorageNotFoundError("target and agent binding does not exist")

            existing_rows = connection.execute(
                """
                SELECT * FROM validation_jobs
                WHERE target_id = ? AND assigned_agent_id = ? AND status = ?
                ORDER BY created_at, validation_job_id LIMIT ?
                """,
                (
                    str(target_id),
                    str(agent_id),
                    JobStatus.DISPATCHED.value,
                    limit,
                ),
            ).fetchall()
            existing = [
                self._stored_validation_job_from_row(connection, row)
                for row in existing_rows
            ]
            if any(
                stored.job.target_id != target_id
                or stored.assigned_agent_id != agent_id
                for stored in existing
            ):
                raise StorageConflictError(
                    "stored validation job does not belong to the polling Agent"
                )

            remaining = limit - len(existing)
            pending: list[StoredValidationJob] = []
            if remaining > 0:
                pending_rows = connection.execute(
                    """
                    SELECT * FROM validation_jobs
                    WHERE target_id = ? AND status = ?
                      AND NOT EXISTS (
                          SELECT 1 FROM sandbox_validation_executions AS sve
                          WHERE sve.validation_job_id =
                                validation_jobs.validation_job_id
                      )
                    ORDER BY created_at, validation_job_id LIMIT ?
                    """,
                    (str(target_id), JobStatus.PENDING.value, remaining),
                ).fetchall()

                # Strict model and source-lineage validation happen before the
                # first state transition.  Any failure aborts the transaction.
                pending = [
                    self._stored_validation_job_from_row(connection, row)
                    for row in pending_rows
                ]
                if any(
                    stored.job.target_id != target_id
                    or stored.assigned_agent_id is not None
                    for stored in pending
                ):
                    raise StorageConflictError(
                        "pending validation job has an invalid target assignment"
                    )
                if any(
                    dispatched_at < stored.job.created_at for stored in pending
                ):
                    raise StorageConflictError(
                        "dispatch time precedes validation job creation"
                    )

                claimed: list[StoredValidationJob] = []
                for stored in pending:
                    cursor = connection.execute(
                        """
                        UPDATE validation_jobs
                        SET status = ?, assigned_agent_id = ?, dispatched_at = ?
                        WHERE validation_job_id = ? AND target_id = ?
                          AND status = ? AND assigned_agent_id IS NULL
                          AND dispatched_at IS NULL
                        """,
                        (
                            JobStatus.DISPATCHED.value,
                            str(agent_id),
                            dispatched_at.isoformat(),
                            str(stored.job.validation_job_id),
                            str(target_id),
                            JobStatus.PENDING.value,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise StorageConflictError(
                            "validation job changed while it was being dispatched"
                        )
                    claimed_row = connection.execute(
                        """
                        SELECT * FROM validation_jobs
                        WHERE validation_job_id = ?
                        """,
                        (str(stored.job.validation_job_id),),
                    ).fetchone()
                    if claimed_row is None:
                        raise StorageNotFoundError(
                            "claimed validation job does not exist"
                        )
                    claimed_job = self._stored_validation_job_from_row(
                        connection, claimed_row
                    )
                    if (
                        claimed_job.job.target_id != target_id
                        or claimed_job.assigned_agent_id != agent_id
                    ):
                        raise StorageConflictError(
                            "claimed validation job has an invalid Agent binding"
                        )
                    claimed.append(claimed_job)
                pending = claimed

        return [stored.job for stored in [*existing, *pending]]

    def store_profile(self, record: ProfileRecord, payload_json: str) -> ProfileRecord:
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            job = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (str(record.job_id),)
            ).fetchone()
            if job is None:
                raise StorageNotFoundError("profile job does not exist")
            if (
                job["target_id"] != str(record.target_id)
                or job["assigned_agent_id"] != str(record.agent_id)
                or job["job_type"] != JobType.PROFILE_TARGET.value
                or job["status"] != JobStatus.DISPATCHED.value
            ):
                raise StorageConflictError(
                    "profile does not match the dispatched target job"
                )
            dispatched_at = _parse_datetime(job["dispatched_at"])
            if dispatched_at is None or record.received_at < dispatched_at:
                raise StorageConflictError(
                    "profile receipt time precedes job dispatch"
                )
            stored_profile = self._validate_profile_payload(record, payload_json)
            enforcement_row = connection.execute(
                "SELECT * FROM enforcement_results "
                "WHERE post_enforcement_profile_job_id = ?",
                (str(record.job_id),),
            ).fetchone()
            enforcement_result = None
            verification = None
            if enforcement_row is not None:
                enforcement_result = self._enforcement_result_from_row(
                    connection, enforcement_row,
                )[0]
                if (
                    enforcement_result.target_id != record.target_id
                    or enforcement_result.agent_id != record.agent_id
                    or stored_profile.profile.collected_at
                    < enforcement_result.payload.execution_completed_at
                ):
                    raise StorageConflictError(
                        "post-enforcement profile is not fresh or correctly bound"
                    )
                try:
                    observed = observed_passwd_state(stored_profile.profile)
                except (ValueError, ValidationError):
                    observed = None
                verification = PostEnforcementVerificationRecord(
                    enforcement_result_id=enforcement_result.enforcement_result_id,
                    target_id=record.target_id,
                    profile_job_id=record.job_id,
                    profile_id=record.profile_id,
                    profile_sha256=record.profile_sha256,
                    outcome=post_enforcement_outcome(
                        enforcement_result.payload, observed,
                    ),
                    observed_source_state=observed,
                    verified_at=record.received_at,
                )
            try:
                connection.execute(
                    """
                    INSERT INTO profiles (
                        profile_id, target_id, agent_id, job_id, collected_at,
                        received_at, profile_sha256, profiler_version,
                        sentra_version, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(record.profile_id),
                        str(record.target_id),
                        str(record.agent_id),
                        str(record.job_id),
                        record.collected_at.isoformat(),
                        record.received_at.isoformat(),
                        record.profile_sha256,
                        record.profiler_version,
                        record.sentra_version,
                        payload_json,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StorageConflictError(
                    "profile already exists or lineage is invalid"
                ) from error
            connection.execute(
                """
                UPDATE jobs SET status = ?, completed_at = ? WHERE job_id = ?
                """,
                (
                    JobStatus.COMPLETED.value,
                    record.received_at.isoformat(),
                    str(record.job_id),
                ),
            )
            if verification is not None:
                try:
                    connection.execute(
                        """INSERT INTO post_enforcement_verifications (
                            enforcement_result_id, target_id, profile_job_id,
                            profile_id, profile_sha256, outcome,
                            observed_source_state_json, verified_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            str(verification.enforcement_result_id),
                            str(verification.target_id), str(verification.profile_job_id),
                            str(verification.profile_id), verification.profile_sha256,
                            verification.outcome.value,
                            _canonical_json(verification.observed_source_state)
                            if verification.observed_source_state is not None else None,
                            verification.verified_at.isoformat(),
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise StorageConflictError(
                        "post-enforcement verification lineage conflicts"
                    ) from error
        return record

    @staticmethod
    def _profile_record_from_row(row: sqlite3.Row) -> ProfileRecord:
        return ProfileRecord(
            profile_id=UUID(row["profile_id"]),
            target_id=UUID(row["target_id"]),
            agent_id=UUID(row["agent_id"]),
            job_id=UUID(row["job_id"]),
            collected_at=datetime.fromisoformat(row["collected_at"]),
            received_at=datetime.fromisoformat(row["received_at"]),
            profile_sha256=row["profile_sha256"],
            profiler_version=row["profiler_version"],
            sentra_version=row["sentra_version"],
        )

    @staticmethod
    def _validate_profile_payload(
        record: ProfileRecord, payload_json: str
    ) -> StoredProfile:
        try:
            if not isinstance(payload_json, str):
                raise TypeError("profile payload must be text")
            profile = TargetProfile.model_validate_json(payload_json)
            canonical_payload = _canonical_payload_json(profile)
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError(
                "stored profile payload is not valid TargetProfile evidence"
            ) from error
        if payload_json != canonical_payload:
            raise StorageConflictError("stored profile payload is not canonical")
        if _sha256(canonical_payload) != record.profile_sha256:
            raise StorageConflictError(
                "stored profile payload does not match its authoritative hash"
            )
        if profile.collected_at != record.collected_at:
            raise StorageConflictError(
                "stored profile payload does not match profile metadata"
            )
        return StoredProfile(
            record=record,
            profile=profile,
            canonical_payload_json=canonical_payload,
        )

    @classmethod
    def _stored_profile_from_row(cls, row: sqlite3.Row) -> StoredProfile:
        try:
            record = cls._profile_record_from_row(row)
            return cls._validate_profile_payload(record, row["payload_json"])
        except StorageConflictError:
            raise
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError(
                "stored profile metadata is invalid"
            ) from error

    def get_stored_profile(self, profile_id: UUID) -> StoredProfile | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM profiles WHERE profile_id = ?", (str(profile_id),)
            ).fetchone()
        return None if row is None else self._stored_profile_from_row(row)

    def get_profile(self, profile_id: UUID) -> ProfileRecord | None:
        stored = self.get_stored_profile(profile_id)
        return None if stored is None else stored.record

    @staticmethod
    def _validate_compatibility_report_payload(
        record: CompatibilityReportRecord,
        payload_json: str,
    ) -> StoredCompatibilityReport:
        try:
            if not isinstance(payload_json, str):
                raise TypeError("compatibility report payload must be text")
            report = CompatibilityReport.model_validate_json(payload_json)
            canonical_payload = _canonical_payload_json(report)
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError(
                "stored compatibility payload is not a valid report"
            ) from error
        if payload_json != canonical_payload:
            raise StorageConflictError(
                "stored compatibility report payload is not canonical"
            )
        if report != record.report:
            raise StorageConflictError(
                "stored compatibility report does not match its record"
            )
        if _sha256(canonical_payload) != record.report_sha256:
            raise StorageConflictError(
                "stored compatibility report does not match its authoritative hash"
            )
        return StoredCompatibilityReport(
            record=record,
            canonical_payload_json=canonical_payload,
        )

    @classmethod
    def _stored_compatibility_report_from_row(
        cls, row: sqlite3.Row
    ) -> StoredCompatibilityReport:
        try:
            report = CompatibilityReport.model_validate_json(row["payload_json"])
            record = CompatibilityReportRecord(
                compatibility_report_id=UUID(row["compatibility_report_id"]),
                target_id=UUID(row["target_id"]),
                profile_id=UUID(row["profile_id"]),
                benchmark_identity=row["benchmark_identity"],
                benchmark_version=row["benchmark_version"],
                generated_at=datetime.fromisoformat(row["generated_at"]),
                report_version=row["report_version"],
                report_sha256=row["report_sha256"],
                report=report,
            )
            return cls._validate_compatibility_report_payload(
                record, row["payload_json"]
            )
        except StorageConflictError:
            raise
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError(
                "stored compatibility report metadata is invalid"
            ) from error

    @staticmethod
    def _validate_compatibility_report_lineage(
        stored_report: StoredCompatibilityReport,
        stored_profile: StoredProfile,
    ) -> None:
        record = stored_report.record
        report = record.report
        if (
            record.target_id != stored_profile.record.target_id
            or record.profile_id != stored_profile.record.profile_id
        ):
            raise StorageConflictError(
                "compatibility report target/profile lineage is invalid"
            )
        if (
            report.profile_collected_at != stored_profile.profile.collected_at
            or report.target != stored_profile.profile.target
            or report.profile_source
            != f"controller-stored-profile:{record.profile_id}"
        ):
            raise StorageConflictError(
                "compatibility report does not describe its source profile"
            )
        if record.generated_at < stored_profile.record.received_at:
            raise StorageConflictError(
                "compatibility report predates its stored source profile"
            )

    def store_compatibility_report(
        self,
        record: CompatibilityReportRecord,
        payload_json: str,
    ) -> CompatibilityReportRecord:
        validated_report = self._validate_compatibility_report_payload(
            record, payload_json
        )
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            profile_row = connection.execute(
                "SELECT * FROM profiles WHERE profile_id = ?",
                (str(record.profile_id),),
            ).fetchone()
            if profile_row is None:
                raise StorageNotFoundError("profile does not exist")
            stored_profile = self._stored_profile_from_row(profile_row)
            self._validate_compatibility_report_lineage(
                validated_report,
                stored_profile,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO compatibility_reports (
                        compatibility_report_id, target_id, profile_id,
                        benchmark_identity, benchmark_version, generated_at,
                        report_version, report_sha256, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(record.compatibility_report_id),
                        str(record.target_id),
                        str(record.profile_id),
                        record.benchmark_identity,
                        record.benchmark_version,
                        record.generated_at.isoformat(),
                        record.report_version,
                        record.report_sha256,
                        validated_report.canonical_payload_json,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StorageConflictError(
                    "compatibility report ID or lineage conflicts"
                ) from error
        return record

    def get_compatibility_report(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
    ) -> CompatibilityReportRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM compatibility_reports
                WHERE target_id = ? AND profile_id = ?
                  AND compatibility_report_id = ?
                """,
                (str(target_id), str(profile_id), str(compatibility_report_id)),
            ).fetchone()
            profile_row = connection.execute(
                "SELECT * FROM profiles WHERE target_id = ? AND profile_id = ?",
                (str(target_id), str(profile_id)),
            ).fetchone()
        if row is None:
            return None
        if profile_row is None:
            raise StorageConflictError(
                "compatibility report source profile does not exist"
            )
        stored_report = self._stored_compatibility_report_from_row(row)
        self._validate_compatibility_report_lineage(
            stored_report,
            self._stored_profile_from_row(profile_row),
        )
        return stored_report.record

    def list_compatibility_reports(
        self, *, target_id: UUID, profile_id: UUID
    ) -> list[CompatibilityReportRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM compatibility_reports
                WHERE target_id = ? AND profile_id = ?
                ORDER BY generated_at, compatibility_report_id
                """,
                (str(target_id), str(profile_id)),
            ).fetchall()
            profile_row = connection.execute(
                "SELECT * FROM profiles WHERE target_id = ? AND profile_id = ?",
                (str(target_id), str(profile_id)),
            ).fetchone()
        if not rows:
            return []
        if profile_row is None:
            raise StorageConflictError(
                "compatibility report source profile does not exist"
            )
        stored_profile = self._stored_profile_from_row(profile_row)
        records: list[CompatibilityReportRecord] = []
        for row in rows:
            stored_report = self._stored_compatibility_report_from_row(row)
            self._validate_compatibility_report_lineage(
                stored_report,
                stored_profile,
            )
            records.append(stored_report.record)
        return records

    @staticmethod
    def _validation_job_authorization_matches(
        existing: ValidationJobRecord,
        requested: ValidationJobRecord,
    ) -> bool:
        """Compare only the admin-supplied authorization behind an idempotent retry."""

        return (
            existing.request_id == requested.request_id
            and existing.target_id == requested.target_id
            and existing.profile_id == requested.profile_id
            and existing.compatibility_report_id
            == requested.compatibility_report_id
            and existing.control_id == requested.control_id
            and existing.validation_mode is requested.validation_mode
            and existing.execution_mode is requested.execution_mode
            and existing.administrator_approval_acknowledged
            is requested.administrator_approval_acknowledged
            and existing.compatibility_risk_acknowledged
            is requested.compatibility_risk_acknowledged
            and existing.compatibility_override_reason
            == requested.compatibility_override_reason
            and existing.compatibility_reference
            == requested.compatibility_reference
        )

    @staticmethod
    def _compatibility_reference_from_json(
        payload_json: str,
    ) -> CompatibilityReference:
        try:
            if not isinstance(payload_json, str):
                raise TypeError("compatibility reference must be text")
            reference = CompatibilityReference.model_validate_json(payload_json)
            canonical = _canonical_compatibility_reference_json(reference)
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError(
                "stored validation compatibility reference is invalid"
            ) from error
        if payload_json != canonical:
            raise StorageConflictError(
                "stored validation compatibility reference is not canonical"
            )
        return reference

    @classmethod
    def _validate_validation_job_lineage(
        cls,
        connection: sqlite3.Connection,
        job: ValidationJobRecord,
    ) -> None:
        profile_row = connection.execute(
            "SELECT * FROM profiles WHERE target_id = ? AND profile_id = ?",
            (str(job.target_id), str(job.profile_id)),
        ).fetchone()
        if profile_row is None:
            raise StorageNotFoundError("validation source profile does not exist")
        stored_profile = cls._stored_profile_from_row(profile_row)

        report_row = connection.execute(
            """
            SELECT * FROM compatibility_reports
            WHERE target_id = ? AND profile_id = ?
              AND compatibility_report_id = ?
            """,
            (
                str(job.target_id),
                str(job.profile_id),
                str(job.compatibility_report_id),
            ),
        ).fetchone()
        if report_row is None:
            raise StorageNotFoundError(
                "validation compatibility report does not exist"
            )
        stored_report = cls._stored_compatibility_report_from_row(report_row)
        cls._validate_compatibility_report_lineage(stored_report, stored_profile)
        try:
            expected_reference = compatibility_reference_from_record(
                stored_report.record,
                job.control_id,
            )
        except ValueError as error:
            raise StorageConflictError(
                "validation job is not supported by its compatibility report"
            ) from error
        if job.compatibility_reference != expected_reference:
            raise StorageConflictError(
                "validation job changed its compatibility evidence"
            )
        if job.created_at < stored_report.record.generated_at:
            raise StorageConflictError(
                "validation job predates its compatibility report"
            )

    @classmethod
    def _stored_validation_job_from_row(
        cls,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> StoredValidationJob:
        try:
            approval = row["administrator_approval_acknowledged"]
            risk_acknowledged = row["compatibility_risk_acknowledged"]
            if approval not in (0, 1) or risk_acknowledged not in (0, 1):
                raise ValueError(
                    "stored validation acknowledgements must be SQLite booleans"
                )
            reference = cls._compatibility_reference_from_json(
                row["compatibility_reference_json"]
            )
            job = ValidationJobRecord(
                validation_job_id=_canonical_stored_uuid_text(
                    row["validation_job_id"],
                    "validation_job_id",
                ),
                request_id=_canonical_stored_uuid_text(
                    row["request_id"],
                    "request_id",
                ),
                target_id=_canonical_stored_uuid_text(
                    row["target_id"],
                    "validation target_id",
                ),
                profile_id=_canonical_stored_uuid_text(
                    row["profile_id"],
                    "validation profile_id",
                ),
                compatibility_report_id=_canonical_stored_uuid_text(
                    row["compatibility_report_id"],
                    "validation compatibility_report_id",
                ),
                job_type=JobType(row["job_type"]),
                control_id=row["control_id"],
                validation_mode=ValidationMode(row["validation_mode"]),
                execution_mode=ExecutionMode(row["execution_mode"]),
                administrator_approval_acknowledged=bool(
                    approval
                ),
                compatibility_risk_acknowledged=bool(
                    risk_acknowledged
                ),
                compatibility_override_reason=row[
                    "compatibility_override_reason"
                ],
                compatibility_reference=reference,
                status=JobStatus(row["status"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                dispatched_at=_parse_datetime(row["dispatched_at"]),
                completed_at=_parse_datetime(row["completed_at"]),
            )
            assigned_agent_id = (
                _canonical_stored_uuid_text(
                    row["assigned_agent_id"],
                    "validation assigned_agent_id",
                )
                if row["assigned_agent_id"] is not None
                else None
            )
        except StorageConflictError:
            raise
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError(
                "stored validation job metadata is invalid"
            ) from error
        if (job.status is JobStatus.PENDING) != (assigned_agent_id is None):
            raise StorageConflictError(
                "stored validation job assignment does not match its state"
            )
        if assigned_agent_id is not None:
            binding = connection.execute(
                """
                SELECT 1 FROM agents WHERE target_id = ? AND agent_id = ?
                """,
                (str(job.target_id), str(assigned_agent_id)),
            ).fetchone()
            if binding is None:
                raise StorageConflictError(
                    "stored validation job Agent binding is cross-target or missing"
                )
        try:
            cls._validate_validation_job_lineage(connection, job)
        except StorageNotFoundError as error:
            raise StorageConflictError(
                "stored validation job lineage is missing"
            ) from error
        return StoredValidationJob(
            job=job,
            assigned_agent_id=assigned_agent_id,
        )

    def create_validation_job(
        self,
        job: ValidationJobRecord,
    ) -> ValidationJobRecord:
        if job.status is not JobStatus.PENDING:
            raise StorageConflictError("a new validation job must be pending")
        reference_json = _canonical_compatibility_reference_json(
            job.compatibility_reference
        )
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")

            stored_request_id_rows = connection.execute(
                "SELECT request_id FROM validation_jobs"
            ).fetchall()

            for stored_request_id_row in stored_request_id_rows:
                _canonical_stored_uuid_text(
                    stored_request_id_row["request_id"],
                    "request_id",
                )

            existing_row = connection.execute(
                "SELECT * FROM validation_jobs WHERE request_id = ?",
                (str(job.request_id),),
            ).fetchone()
            if existing_row is not None:
                existing = self._stored_validation_job_from_row(
                    connection, existing_row
                ).job
                if not self._validation_job_authorization_matches(existing, job):
                    raise StorageConflictError(
                        "validation request ID conflicts with another authorization"
                    )
                return existing

            if connection.execute(
                "SELECT 1 FROM jobs WHERE job_id = ?",
                (str(job.validation_job_id),),
            ).fetchone() is not None:
                raise StorageConflictError("controller job ID already exists")
            self._validate_validation_job_lineage(connection, job)
            try:
                connection.execute(
                    """
                    INSERT INTO validation_jobs (
                        validation_job_id, request_id, target_id, profile_id,
                        compatibility_report_id, assigned_agent_id, job_type,
                        control_id, validation_mode, execution_mode,
                        administrator_approval_acknowledged,
                        compatibility_risk_acknowledged,
                        compatibility_override_reason,
                        compatibility_reference_json, status, created_at,
                        dispatched_at, completed_at
                    ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                    """,
                    (
                        str(job.validation_job_id),
                        str(job.request_id),
                        str(job.target_id),
                        str(job.profile_id),
                        str(job.compatibility_report_id),
                        job.job_type.value,
                        job.control_id,
                        job.validation_mode.value,
                        job.execution_mode.value,
                        int(job.administrator_approval_acknowledged),
                        int(job.compatibility_risk_acknowledged),
                        job.compatibility_override_reason,
                        reference_json,
                        job.status.value,
                        job.created_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StorageConflictError(
                    "validation job ID, request ID, or lineage conflicts"
                ) from error
        return job


    def dispatch_sandbox_validation_job(
        self,
        *,
        sandbox_session_id: UUID,
        validation_job_id: UUID,
        dispatched_at: datetime,
        pending_job: ValidationJobRecord | None = None,
    ) -> tuple[ValidationJobRecord, SandboxSessionRecord]:
        """Atomically reserve one authorized job for one READY sandbox."""

        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")

            session_row = connection.execute(
                "SELECT * FROM sandbox_sessions WHERE sandbox_session_id = ?",
                (str(sandbox_session_id),),
            ).fetchone()

            job_row = connection.execute(
                "SELECT * FROM validation_jobs WHERE validation_job_id = ?",
                (str(validation_job_id),),
            ).fetchone()

            if session_row is None:
                raise StorageNotFoundError("sandbox session does not exist")

            session = self._stored_sandbox_session_from_row(
                connection, session_row
            )
            if pending_job is None:
                if job_row is None:
                    raise StorageNotFoundError(
                        "validation authorization does not exist"
                    )
                stored = self._stored_validation_job_from_row(
                    connection, job_row
                )
                job = stored.job
                assigned_agent_id = stored.assigned_agent_id
            else:
                # This is the new safe entry point: the validation job does not
                # exist until its sandbox reservation is committed atomically.
                if type(pending_job) is not ValidationJobRecord or job_row is not None:
                    raise StorageConflictError(
                        "new sandbox authorization is invalid or already exists"
                    )
                try:
                    job = ValidationJobRecord.model_validate_json(
                        pending_job.model_dump_json(), strict=True
                    )
                except (TypeError, ValueError, ValidationError) as error:
                    raise StorageConflictError(
                        "new sandbox validation authorization is invalid"
                    ) from error
                if job.validation_job_id != validation_job_id:
                    raise StorageConflictError(
                        "new sandbox validation identity differs from authorization"
                    )
                if connection.execute(
                    "SELECT 1 FROM validation_jobs WHERE request_id = ?",
                    (str(job.request_id),),
                ).fetchone() is not None:
                    raise StorageConflictError(
                        "sandbox validation request has already been used"
                    )
                if connection.execute(
                    "SELECT 1 FROM jobs WHERE job_id = ?",
                    (str(job.validation_job_id),),
                ).fetchone() is not None:
                    raise StorageConflictError("controller job identity conflicts")
                self._validate_validation_job_lineage(connection, job)
                assigned_agent_id = None

            if (
                session.status is not SandboxSessionStatus.READY
                or job.status is not JobStatus.PENDING
                or assigned_agent_id is not None
                or session.ready_at is None
                or dispatched_at < session.ready_at
                or dispatched_at < job.created_at
                or job.target_id != session.source_target_id
                or job.profile_id != session.source_profile_id
                or job.compatibility_report_id
                != session.source_compatibility_report_id
                or job.control_id != session.control_id
                or job.compatibility_reference
                != session.compatibility_reference
            ):
                raise StorageConflictError(
                    "sandbox dispatch authorization or lineage is invalid"
                )

            existing = connection.execute(
                """
                SELECT 1 FROM sandbox_validation_executions
                WHERE sandbox_session_id = ? OR validation_job_id = ?
                """,
                (str(sandbox_session_id), str(validation_job_id)),
            ).fetchone()

            if existing is not None:
                raise StorageConflictError(
                    "sandbox or job has already been reserved"
                )

            dispatched_values = job.model_dump(mode="python")
            dispatched_values["status"] = JobStatus.DISPATCHED
            dispatched_values["dispatched_at"] = dispatched_at

            dispatched_job = ValidationJobRecord.model_validate(
                dispatched_values,
                strict=True,
            )

            session_values = session.model_dump(mode="python")
            session_values["status"] = SandboxSessionStatus.VALIDATING
            session_values["validation_started_at"] = dispatched_at

            validating_session = SandboxSessionRecord.model_validate(
                session_values,
                strict=True,
            )

            job_json = json.dumps(
                dispatched_job.model_dump(mode="json"),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )

            try:
                if pending_job is not None:
                    reference_json = _canonical_compatibility_reference_json(
                        job.compatibility_reference
                    )
                    connection.execute(
                        """
                        INSERT INTO validation_jobs (
                            validation_job_id, request_id, target_id, profile_id,
                            compatibility_report_id, assigned_agent_id, job_type,
                            control_id, validation_mode, execution_mode,
                            administrator_approval_acknowledged,
                            compatibility_risk_acknowledged,
                            compatibility_override_reason,
                            compatibility_reference_json, status, created_at,
                            dispatched_at, completed_at
                        ) VALUES (
                            ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL
                        )
                        """,
                        (
                            str(job.validation_job_id), str(job.request_id),
                            str(job.target_id), str(job.profile_id),
                            str(job.compatibility_report_id), job.job_type.value,
                            job.control_id, job.validation_mode.value,
                            job.execution_mode.value,
                            int(job.administrator_approval_acknowledged),
                            int(job.compatibility_risk_acknowledged),
                            job.compatibility_override_reason, reference_json,
                            JobStatus.PENDING.value, job.created_at.isoformat(),
                        ),
                    )
                changed = connection.execute(
                    """
                    UPDATE sandbox_sessions
                    SET status = 'VALIDATING', validation_started_at = ?
                    WHERE sandbox_session_id = ? AND status = 'READY'
                    """,
                    (dispatched_at.isoformat(), str(sandbox_session_id)),
                )

                if changed.rowcount != 1:
                    raise StorageConflictError(
                        "sandbox changed during reservation"
                    )

                connection.execute(
                    """
                    INSERT INTO sandbox_validation_executions (
                        sandbox_session_id, validation_job_id, request_id,
                        source_target_id, source_profile_id,
                        source_compatibility_report_id,
                        job_json, status, dispatched_at,
                        completed_at, result_sha256, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'DISPATCHED', ?, NULL, NULL, NULL)
                    """,
                    (
                        str(sandbox_session_id),
                        str(validation_job_id),
                        str(job.request_id),
                        str(job.target_id),
                        str(job.profile_id),
                        str(job.compatibility_report_id),
                        job_json,
                        dispatched_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StorageConflictError(
                    "sandbox reservation violates storage lineage"
                ) from error

        return dispatched_job, validating_session



    def complete_sandbox_validation_job(
        self,
        *,
        sandbox_session_id: UUID,
        validation_job_id: UUID,
        payload: ValidationResultPayload,
        completed_at: datetime,
    ) -> SandboxSessionRecord:
        """Atomically save M5 evidence and complete its sandbox session."""
        from src.controller.validation import (
            canonical_validation_payload_json,
            require_payload_matches_job,
        )

        if type(payload) is not ValidationResultPayload:
            raise StorageConflictError("sandbox result payload has invalid type")
        try:
            verified_payload = ValidationResultPayload.model_validate_json(
                payload.model_dump_json(), strict=True
            )
            canonical = canonical_validation_payload_json(verified_payload)
        except (ValueError, TypeError, ValidationError) as error:
            raise StorageConflictError("sandbox result payload is invalid") from error

        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            execution = connection.execute(
                "SELECT * FROM sandbox_validation_executions "
                "WHERE sandbox_session_id = ? AND validation_job_id = ?",
                (str(sandbox_session_id), str(validation_job_id)),
            ).fetchone()
            session_row = connection.execute(
                "SELECT * FROM sandbox_sessions WHERE sandbox_session_id = ?",
                (str(sandbox_session_id),),
            ).fetchone()
            job_row = connection.execute(
                "SELECT * FROM validation_jobs WHERE validation_job_id = ?",
                (str(validation_job_id),),
            ).fetchone()
            if execution is None or session_row is None or job_row is None:
                raise StorageNotFoundError("sandbox validation execution is missing")

            session = self._stored_sandbox_session_from_row(connection, session_row)
            stored = self._stored_validation_job_from_row(connection, job_row)
            try:
                job = ValidationJobRecord.model_validate_json(
                    execution["job_json"], strict=True
                )
            except (TypeError, ValueError, ValidationError) as error:
                raise StorageConflictError(
                    "sandbox dispatched authorization is invalid"
                ) from error

            dispatched_at = _parse_datetime(execution["dispatched_at"])
            if dispatched_at is None:
                raise StorageConflictError("sandbox dispatch timestamp is missing")
            expected_job = stored.job.model_copy(
                update={"status": JobStatus.DISPATCHED, "dispatched_at": dispatched_at}
            )
            if (
                execution["status"] != "DISPATCHED"
                or session.status is not SandboxSessionStatus.VALIDATING
                or stored.job.status is not JobStatus.PENDING
                or stored.assigned_agent_id is not None
                or session.validation_started_at != dispatched_at
                or dispatched_at != job.dispatched_at
                or job != expected_job
                or job.validation_job_id != validation_job_id
                or execution["validation_job_id"] != str(validation_job_id)
                or execution["request_id"] != str(job.request_id)
                or execution["source_target_id"] != str(job.target_id)
                or execution["source_profile_id"] != str(job.profile_id)
                or execution["source_compatibility_report_id"]
                != str(job.compatibility_report_id)
                or job.target_id != session.source_target_id
                or job.profile_id != session.source_profile_id
                or job.compatibility_report_id
                != session.source_compatibility_report_id
                or job.compatibility_reference != session.compatibility_reference
                or completed_at < dispatched_at
            ):
                raise StorageConflictError("sandbox evidence authorization is invalid")
            try:
                require_payload_matches_job(verified_payload, job)
            except ValueError as error:
                raise StorageConflictError("M5 evidence lineage is invalid") from error

            completed_values = session.model_dump(mode="python")
            completed_values["status"] = SandboxSessionStatus.COMPLETED
            completed_values["completed_at"] = completed_at
            completed_session = SandboxSessionRecord.model_validate(
                completed_values, strict=True
            )
            evidence_hash = _sha256(canonical)
            first = connection.execute(
                """UPDATE sandbox_validation_executions
                   SET status = 'COMPLETED', completed_at = ?,
                       result_sha256 = ?, payload_json = ?
                   WHERE sandbox_session_id = ? AND validation_job_id = ?
                     AND status = 'DISPATCHED'""",
                (completed_at.isoformat(), evidence_hash, canonical,
                 str(sandbox_session_id), str(validation_job_id)),
            )
            if first.rowcount != 1:
                raise StorageConflictError("sandbox evidence changed during completion")
            second = connection.execute(
                """UPDATE sandbox_sessions
                   SET status = 'COMPLETED', completed_at = ?
                   WHERE sandbox_session_id = ? AND status = 'VALIDATING'""",
                (completed_at.isoformat(), str(sandbox_session_id)),
            )
            if second.rowcount != 1:
                raise StorageConflictError("sandbox session changed during completion")
        return completed_session

    def get_sandbox_validation_evidence(
        self,
        *,
        sandbox_session_id: UUID,
    ) -> tuple[ValidationResultPayload, str] | None:
        """Read and verify the sealed Controller-owned M5 result and SHA-256."""
        from src.controller.validation import (
            canonical_validation_payload_json,
            require_payload_matches_job,
        )

        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_validation_executions "
                "WHERE sandbox_session_id = ?",
                (str(sandbox_session_id),),
            ).fetchone()
            if row is None or row["status"] != "COMPLETED":
                return None
            session_row = connection.execute(
                "SELECT * FROM sandbox_sessions WHERE sandbox_session_id = ?",
                (str(sandbox_session_id),),
            ).fetchone()
            job_row = connection.execute(
                "SELECT * FROM validation_jobs WHERE validation_job_id = ?",
                (row["validation_job_id"],),
            ).fetchone()
            if session_row is None or job_row is None:
                raise StorageConflictError("sandbox evidence lineage is missing")
            session = self._stored_sandbox_session_from_row(connection, session_row)
            stored = self._stored_validation_job_from_row(connection, job_row)
            try:
                job = ValidationJobRecord.model_validate_json(
                    row["job_json"], strict=True
                )
                payload = ValidationResultPayload.model_validate_json(
                    row["payload_json"], strict=True
                )
                canonical = canonical_validation_payload_json(payload)
                require_payload_matches_job(payload, job)
            except (TypeError, ValueError, ValidationError) as error:
                raise StorageConflictError("stored sandbox M5 evidence is invalid") from error
            dispatched_at = _parse_datetime(row["dispatched_at"])
            if dispatched_at is None:
                raise StorageConflictError("sandbox evidence dispatch time is missing")
            authoritative_job = stored.job.model_copy(
                update={
                    "status": JobStatus.DISPATCHED,
                    "dispatched_at": dispatched_at,
                }
            )
            if (
                job != authoritative_job
                or session.source_target_id != job.target_id
                or session.source_profile_id != job.profile_id
                or session.source_compatibility_report_id
                != job.compatibility_report_id
                or session.validation_started_at != dispatched_at
            ):
                raise StorageConflictError("sandbox M5 job authorization differs from storage")
            if (
                session.status not in (
                    SandboxSessionStatus.COMPLETED, SandboxSessionStatus.CLOSED
                )
                or stored.assigned_agent_id is not None
                or stored.job.status is not JobStatus.PENDING
                or job.status is not JobStatus.DISPATCHED
                or job.validation_job_id != stored.job.validation_job_id
                or job.compatibility_reference != session.compatibility_reference
                or row["validation_job_id"] != str(job.validation_job_id)
                or row["request_id"] != str(job.request_id)
                or row["source_target_id"] != str(job.target_id)
                or row["source_profile_id"] != str(job.profile_id)
                or row["source_compatibility_report_id"]
                != str(job.compatibility_report_id)
                or _parse_datetime(row["dispatched_at"]) != job.dispatched_at
                or _parse_datetime(row["completed_at"]) != session.completed_at
                or row["payload_json"] != canonical
                or _sha256(canonical) != row["result_sha256"]
            ):
                raise StorageConflictError("sandbox M5 evidence integrity check failed")
            return payload, row["result_sha256"]

    def _require_enforcement_evidence(
        self,
        connection: sqlite3.Connection,
        job: EnforcementJobRecord,
    ) -> None:
        session_row = connection.execute(
            "SELECT * FROM sandbox_sessions WHERE sandbox_session_id = ?",
            (str(job.sandbox_session_id),),
        ).fetchone()
        if session_row is None:
            raise StorageNotFoundError("enforcement sandbox session is missing")
        session = self._stored_sandbox_session_from_row(connection, session_row)
        if (
            session.source_target_id != job.target_id
            or session.source_profile_id != job.profile_id
            or session.source_compatibility_report_id != job.compatibility_report_id
            or session.control_id != job.control_id
            or session.status is not SandboxSessionStatus.CLOSED
            or session.failure_reason is not None
            or session.quarantine_reason is not None
            or session.closed_at is None
            or job.created_at < session.closed_at
        ):
            raise StorageConflictError("enforcement sandbox lineage is invalid")
        evidence = self.get_sandbox_validation_evidence(
            sandbox_session_id=job.sandbox_session_id,
        )
        if evidence is None:
            raise StorageConflictError("enforcement sandbox evidence is missing")
        payload, evidence_sha256 = evidence
        if (
            evidence_sha256 != job.sandbox_evidence_sha256
            or payload.target_id != job.target_id
            or payload.profile_id != job.profile_id
            or payload.compatibility_report_id != job.compatibility_report_id
            or payload.control_id != job.control_id
            or payload.execution_mode is not ExecutionMode.EXECUTE
            or payload.report.mode is not ExecutionMode.EXECUTE
            or len(payload.report.control_results) != 1
            or payload.report.control_results[0].control_id != "7.1.1"
            or payload.report.control_results[0].result.value != "validated"
            or payload.report.control_results[0].m4_input
            != session.compatibility_reference
        ):
            raise StorageConflictError("enforcement M6 evidence is invalid")

    def _enforcement_job_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> EnforcementJobRecord:
        try:
            if row["administrator_enforcement_approval_acknowledged"] != 1:
                raise ValueError("enforcement approval is missing")
            job = EnforcementJobRecord(
                enforcement_job_id=_canonical_stored_uuid_text(
                    row["enforcement_job_id"], "enforcement_job_id"
                ),
                request_id=_canonical_stored_uuid_text(
                    row["request_id"], "enforcement request_id"
                ),
                target_id=_canonical_stored_uuid_text(row["target_id"], "target_id"),
                profile_id=_canonical_stored_uuid_text(row["profile_id"], "profile_id"),
                compatibility_report_id=_canonical_stored_uuid_text(
                    row["compatibility_report_id"], "compatibility_report_id"
                ),
                sandbox_session_id=_canonical_stored_uuid_text(
                    row["sandbox_session_id"], "sandbox_session_id"
                ),
                control_id=row["control_id"],
                job_type=JobType(row["job_type"]),
                administrator_enforcement_approval_acknowledged=True,
                sandbox_evidence_sha256=row["sandbox_evidence_sha256"],
                status=JobStatus(row["status"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                assigned_agent_id=(
                    _canonical_stored_uuid_text(row["assigned_agent_id"], "assigned_agent_id")
                    if row["assigned_agent_id"] is not None else None
                ),
                dispatched_at=_parse_datetime(row["dispatched_at"]),
                completed_at=_parse_datetime(row["completed_at"]),
            )
        except StorageConflictError:
            raise
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError("stored enforcement job is invalid") from error
        self._require_enforcement_evidence(connection, job)
        return job

    def create_enforcement_job(
        self,
        job: EnforcementJobRecord,
    ) -> EnforcementJobRecord:
        if type(job) is not EnforcementJobRecord:
            raise StorageConflictError("enforcement job model is invalid")
        try:
            job = EnforcementJobRecord.model_validate(
                job.model_dump(mode="python"), strict=True
            )
        except ValidationError as error:
            raise StorageConflictError("enforcement job model is invalid") from error
        if job.status is not JobStatus.PENDING:
            raise StorageConflictError("only pending enforcement jobs may be created")
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            for row in connection.execute(
                "SELECT request_id FROM enforcement_jobs"
            ).fetchall():
                _canonical_stored_uuid_text(row["request_id"], "enforcement request_id")
            existing_row = connection.execute(
                "SELECT * FROM enforcement_jobs WHERE request_id = ?",
                (str(job.request_id),),
            ).fetchone()
            if existing_row is not None:
                existing = self._enforcement_job_from_row(connection, existing_row)
                fields = (
                    "request_id", "target_id", "profile_id",
                    "compatibility_report_id", "sandbox_session_id", "control_id",
                    "administrator_enforcement_approval_acknowledged",
                    "sandbox_evidence_sha256",
                )
                if any(getattr(existing, field) != getattr(job, field) for field in fields):
                    raise StorageConflictError("enforcement request replay conflicts")
                return existing
            active_rows = connection.execute(
                """SELECT * FROM enforcement_jobs
                   WHERE target_id=? AND profile_id=? AND compatibility_report_id=?
                     AND sandbox_session_id=? AND control_id=?
                     AND status IN ('pending', 'dispatched')""",
                (str(job.target_id), str(job.profile_id),
                 str(job.compatibility_report_id), str(job.sandbox_session_id),
                 job.control_id),
            ).fetchall()
            for active_row in active_rows:
                self._enforcement_job_from_row(connection, active_row)
            if active_rows:
                raise StorageConflictError(
                    "another active enforcement job already owns this lineage"
                )
            self._require_enforcement_evidence(connection, job)
            try:
                connection.execute(
                    """INSERT INTO enforcement_jobs (
                        enforcement_job_id, request_id, target_id, profile_id,
                        compatibility_report_id, sandbox_session_id, control_id,
                        job_type, administrator_enforcement_approval_acknowledged,
                        sandbox_evidence_sha256, status, created_at,
                        assigned_agent_id, dispatched_at, completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(job.enforcement_job_id), str(job.request_id),
                        str(job.target_id), str(job.profile_id),
                        str(job.compatibility_report_id), str(job.sandbox_session_id),
                        job.control_id, job.job_type.value, 1,
                        job.sandbox_evidence_sha256, job.status.value,
                        job.created_at.isoformat(), None, None, None,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StorageConflictError("enforcement job insertion conflicts") from error
            row = connection.execute(
                "SELECT * FROM enforcement_jobs WHERE enforcement_job_id = ?",
                (str(job.enforcement_job_id),),
            ).fetchone()
            if row is None:
                raise StorageConflictError("enforcement job disappeared")
            return self._enforcement_job_from_row(connection, row)

    def poll_enforcement_jobs(
        self,
        *,
        target_id: UUID,
        agent_id: UUID,
        dispatched_at: datetime,
        limit: int,
    ) -> list[EnforcementJobRecord]:
        """Atomically claim fixed enforcement only for this enrolled Agent."""

        if limit < 0:
            raise StorageConflictError("enforcement poll limit is invalid")
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM agents WHERE target_id = ? AND agent_id = ?",
                (str(target_id), str(agent_id)),
            ).fetchone() is None:
                raise StorageNotFoundError("target and agent binding does not exist")
            existing_rows = connection.execute(
                """SELECT * FROM enforcement_jobs
                   WHERE target_id = ? AND assigned_agent_id = ?
                     AND status = 'dispatched'
                   ORDER BY created_at, enforcement_job_id LIMIT ?""",
                (str(target_id), str(agent_id), limit),
            ).fetchall()
            existing = [
                self._enforcement_job_from_row(connection, row)
                for row in existing_rows
            ]
            remaining = limit - len(existing)
            claimed: list[EnforcementJobRecord] = []
            if remaining > 0:
                pending_rows = connection.execute(
                    """SELECT * FROM enforcement_jobs
                       WHERE target_id = ? AND status = 'pending'
                       ORDER BY created_at, enforcement_job_id LIMIT ?""",
                    (str(target_id), remaining),
                ).fetchall()
                pending = [
                    self._enforcement_job_from_row(connection, row)
                    for row in pending_rows
                ]
                if any(
                    job.target_id != target_id or job.assigned_agent_id is not None
                    or dispatched_at < job.created_at
                    for job in pending
                ):
                    raise StorageConflictError("pending enforcement job is invalid")
                for job in pending:
                    cursor = connection.execute(
                        """UPDATE enforcement_jobs
                           SET status = 'dispatched', assigned_agent_id = ?,
                               dispatched_at = ?
                           WHERE enforcement_job_id = ? AND target_id = ?
                             AND status = 'pending' AND assigned_agent_id IS NULL
                             AND dispatched_at IS NULL""",
                        (
                            str(agent_id), dispatched_at.isoformat(),
                            str(job.enforcement_job_id), str(target_id),
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise StorageConflictError("enforcement claim changed")
                    row = connection.execute(
                        "SELECT * FROM enforcement_jobs WHERE enforcement_job_id = ?",
                        (str(job.enforcement_job_id),),
                    ).fetchone()
                    if row is None:
                        raise StorageNotFoundError("claimed enforcement job is missing")
                    claimed_job = self._enforcement_job_from_row(connection, row)
                    if claimed_job.assigned_agent_id != agent_id:
                        raise StorageConflictError("enforcement Agent binding is invalid")
                    claimed.append(claimed_job)
        return [*existing, *claimed]

    def get_enforcement_job(self, enforcement_job_id: UUID) -> EnforcementJobRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM enforcement_jobs WHERE enforcement_job_id = ?",
                (str(enforcement_job_id),),
            ).fetchone()
            return None if row is None else self._enforcement_job_from_row(connection, row)

    def _approved_enforcement_state(
        self, connection: sqlite3.Connection, job: EnforcementJobRecord,
    ):
        profile_row = connection.execute(
            "SELECT * FROM profiles WHERE profile_id = ? AND target_id = ?",
            (str(job.profile_id), str(job.target_id)),
        ).fetchone()
        report_row = connection.execute(
            "SELECT * FROM compatibility_reports WHERE compatibility_report_id = ? "
            "AND profile_id = ? AND target_id = ?",
            (str(job.compatibility_report_id), str(job.profile_id), str(job.target_id)),
        ).fetchone()
        if profile_row is None or report_row is None:
            raise StorageConflictError("enforcement M3/M4 lineage is missing")
        profile = self._stored_profile_from_row(profile_row)
        report = self._stored_compatibility_report_from_row(report_row)
        self._validate_compatibility_report_lineage(report, profile)
        try:
            reference = compatibility_reference_from_record(report.record, "7.1.1")
            return derive_sandbox_context(
                "7.1.1", profile.profile, reference,
            ).source_state
        except (ValueError, ValidationError) as error:
            raise StorageConflictError("approved passwd source state is invalid") from error

    def _enforcement_result_from_row(
        self, connection: sqlite3.Connection, row: sqlite3.Row,
    ) -> tuple[EnforcementResultRecord, str]:
        try:
            payload = EnforcementResultPayload.model_validate_json(
                row["payload_json"], strict=True,
            )
            canonical = canonical_enforcement_payload_json(payload)
            if row["payload_json"] != canonical:
                raise StorageConflictError("enforcement result payload is not canonical")
            record = EnforcementResultRecord(
                enforcement_result_id=_canonical_stored_uuid_text(
                    row["enforcement_result_id"], "enforcement_result_id",
                ),
                enforcement_job_id=_canonical_stored_uuid_text(
                    row["enforcement_job_id"], "enforcement_job_id",
                ),
                target_id=_canonical_stored_uuid_text(row["target_id"], "target_id"),
                agent_id=_canonical_stored_uuid_text(row["agent_id"], "agent_id"),
                outcome=EnforcementOutcome(row["outcome"]),
                result_sha256=row["result_sha256"],
                received_at=datetime.fromisoformat(row["received_at"]),
                post_enforcement_profile_job_id=_canonical_stored_uuid_text(
                    row["post_enforcement_profile_job_id"], "post profile job ID",
                ),
                payload=payload,
            )
            if (
                _sha256(canonical) != record.result_sha256
                or row["control_id"] != "7.1.1"
                or row["m6_evidence_sha256"] != payload.m6_evidence_sha256
            ):
                raise StorageConflictError("enforcement result hash or columns conflict")
        except StorageConflictError:
            raise
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError("stored enforcement result is malformed") from error
        job_row = connection.execute(
            "SELECT * FROM enforcement_jobs WHERE enforcement_job_id = ?",
            (str(record.enforcement_job_id),),
        ).fetchone()
        profile_job_row = connection.execute(
            "SELECT * FROM jobs WHERE job_id = ?",
            (str(record.post_enforcement_profile_job_id),),
        ).fetchone()
        if job_row is None or profile_job_row is None:
            raise StorageConflictError("enforcement result lineage is missing")
        job = self._enforcement_job_from_row(connection, job_row)
        approved = self._approved_enforcement_state(connection, job)
        if (
            job.status is not JobStatus.COMPLETED
            or job.completed_at != record.received_at
            or job.assigned_agent_id != record.agent_id
            or job.target_id != record.target_id
            or job.sandbox_evidence_sha256 != payload.m6_evidence_sha256
            or job.control_id != payload.control_id
            or approved != payload.expected_source_state
            or profile_job_row["target_id"] != str(record.target_id)
            or profile_job_row["job_type"] != JobType.PROFILE_TARGET.value
            or profile_job_row["created_at"] != record.received_at.isoformat()
        ):
            raise StorageConflictError("enforcement result lineage does not match storage")
        return record, canonical

    def store_enforcement_result(
        self, record: EnforcementResultRecord, payload_json: str,
    ) -> EnforcementResultRecord:
        if type(record) is not EnforcementResultRecord:
            raise StorageConflictError("enforcement result record type is invalid")
        try:
            validated = EnforcementResultRecord.model_validate(
                record.model_dump(mode="python"), strict=True,
            )
            canonical = canonical_enforcement_payload_json(validated.payload)
        except (ValueError, ValidationError) as error:
            raise StorageConflictError("enforcement result evidence is invalid") from error
        if payload_json != canonical or _sha256(canonical) != record.result_sha256:
            raise StorageConflictError("enforcement result is not canonical")
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            job_row = connection.execute(
                "SELECT * FROM enforcement_jobs WHERE enforcement_job_id = ?",
                (str(record.enforcement_job_id),),
            ).fetchone()
            if job_row is None:
                raise StorageNotFoundError("enforcement job does not exist")
            job = self._enforcement_job_from_row(connection, job_row)
            existing_row = connection.execute(
                "SELECT * FROM enforcement_results WHERE enforcement_job_id = ?",
                (str(record.enforcement_job_id),),
            ).fetchone()
            if existing_row is not None:
                existing, stored_json = self._enforcement_result_from_row(
                    connection, existing_row,
                )
                if (
                    stored_json != canonical or existing.agent_id != record.agent_id
                    or existing.result_sha256 != record.result_sha256
                ):
                    raise StorageConflictError("enforcement result replay changed")
                return existing
            if (
                job.status is not JobStatus.DISPATCHED
                or job.assigned_agent_id != record.agent_id
                or job.target_id != record.target_id
                or job.control_id != record.payload.control_id
                or job.sandbox_evidence_sha256 != record.payload.m6_evidence_sha256
                or job.administrator_enforcement_approval_acknowledged is not True
                or self._approved_enforcement_state(connection, job)
                != record.payload.expected_source_state
                or job.dispatched_at is None
                or record.payload.execution_completed_at < job.dispatched_at
                or record.received_at < job.dispatched_at
            ):
                raise StorageConflictError("enforcement result conflicts with approved job")
            try:
                connection.execute(
                    """INSERT INTO jobs (
                        job_id, target_id, assigned_agent_id, job_type, status,
                        created_at, dispatched_at, completed_at
                    ) VALUES (?, ?, NULL, 'PROFILE_TARGET', 'pending', ?, NULL, NULL)""",
                    (str(record.post_enforcement_profile_job_id),
                     str(record.target_id), record.received_at.isoformat()),
                )
                connection.execute(
                    """INSERT INTO enforcement_results (
                        enforcement_result_id, enforcement_job_id, target_id,
                        agent_id, control_id, m6_evidence_sha256, outcome,
                        received_at, result_sha256, payload_json,
                        post_enforcement_profile_job_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(record.enforcement_result_id), str(record.enforcement_job_id),
                        str(record.target_id), str(record.agent_id), "7.1.1",
                        record.payload.m6_evidence_sha256, record.outcome.value,
                        record.received_at.isoformat(), record.result_sha256,
                        canonical, str(record.post_enforcement_profile_job_id),
                    ),
                )
                updated = connection.execute(
                    """UPDATE enforcement_jobs SET status = 'completed', completed_at = ?
                       WHERE enforcement_job_id = ? AND target_id = ?
                         AND assigned_agent_id = ? AND status = 'dispatched'""",
                    (
                        record.received_at.isoformat(), str(record.enforcement_job_id),
                        str(record.target_id), str(record.agent_id),
                    ),
                )
                if updated.rowcount != 1:
                    raise StorageConflictError("enforcement job completion changed")
            except sqlite3.IntegrityError as error:
                raise StorageConflictError("enforcement result insertion conflicts") from error
        return record

    def get_enforcement_result_for_job(
        self, enforcement_job_id: UUID,
    ) -> EnforcementResultRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM enforcement_results WHERE enforcement_job_id = ?",
                (str(enforcement_job_id),),
            ).fetchone()
            return None if row is None else self._enforcement_result_from_row(connection, row)[0]

    def _post_enforcement_verification_from_row(
        self, connection: sqlite3.Connection, row: sqlite3.Row,
    ) -> PostEnforcementVerificationRecord:
        from src.sandbox_protocol.models import PasswdSourceState

        try:
            observed_json = row["observed_source_state_json"]
            observed = (
                None if observed_json is None
                else PasswdSourceState.model_validate_json(observed_json, strict=True)
            )
            if observed is not None and _canonical_json(observed) != observed_json:
                raise StorageConflictError("post-enforcement observation is noncanonical")
            record = PostEnforcementVerificationRecord(
                enforcement_result_id=_canonical_stored_uuid_text(
                    row["enforcement_result_id"], "enforcement_result_id",
                ),
                target_id=_canonical_stored_uuid_text(row["target_id"], "target_id"),
                profile_job_id=_canonical_stored_uuid_text(
                    row["profile_job_id"], "profile_job_id",
                ),
                profile_id=_canonical_stored_uuid_text(row["profile_id"], "profile_id"),
                profile_sha256=row["profile_sha256"],
                outcome=PostEnforcementVerificationOutcome(row["outcome"]),
                observed_source_state=observed,
                verified_at=datetime.fromisoformat(row["verified_at"]),
            )
        except StorageConflictError:
            raise
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError("post-enforcement verification is malformed") from error
        result_row = connection.execute(
            "SELECT * FROM enforcement_results WHERE enforcement_result_id = ?",
            (str(record.enforcement_result_id),),
        ).fetchone()
        profile_row = connection.execute(
            "SELECT * FROM profiles WHERE profile_id = ?",
            (str(record.profile_id),),
        ).fetchone()
        if result_row is None or profile_row is None:
            raise StorageConflictError("post-enforcement verification lineage is missing")
        result = self._enforcement_result_from_row(connection, result_row)[0]
        profile = self._stored_profile_from_row(profile_row)
        profile_job_row = connection.execute(
            "SELECT * FROM jobs WHERE job_id = ?",
            (str(record.profile_job_id),),
        ).fetchone()
        try:
            expected_observed = observed_passwd_state(profile.profile)
        except (ValueError, ValidationError):
            expected_observed = None
        if (
            result.target_id != record.target_id
            or result.post_enforcement_profile_job_id != record.profile_job_id
            or profile.record.target_id != record.target_id
            or profile.record.job_id != record.profile_job_id
            or profile.record.profile_sha256 != record.profile_sha256
            or profile.record.received_at != record.verified_at
            or profile_job_row is None
            or profile_job_row["status"] != JobStatus.COMPLETED.value
            or profile.profile.collected_at < result.payload.execution_completed_at
            or expected_observed != record.observed_source_state
            or post_enforcement_outcome(result.payload, expected_observed)
            is not record.outcome
        ):
            raise StorageConflictError("post-enforcement verification evidence changed")
        return record

    def get_post_enforcement_verification(
        self, enforcement_result_id: UUID,
    ) -> PostEnforcementVerificationRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM post_enforcement_verifications "
                "WHERE enforcement_result_id = ?",
                (str(enforcement_result_id),),
            ).fetchone()
            return None if row is None else self._post_enforcement_verification_from_row(
                connection, row,
            )


    def get_validation_job(
        self,
        validation_job_id: UUID,
    ) -> StoredValidationJob | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM validation_jobs WHERE validation_job_id = ?",
                (str(validation_job_id),),
            ).fetchone()
            if row is None:
                return None
            return self._stored_validation_job_from_row(connection, row)

    @staticmethod
    def _validate_validation_result_payload(
        record: ValidationResultRecord,
        payload_json: str,
    ) -> str:
        try:
            if not isinstance(payload_json, str):
                raise TypeError("validation result payload must be text")
            payload = ValidationResultPayload.model_validate_json(payload_json)
            canonical = canonical_validation_payload_json(payload)
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError(
                "stored validation payload is not valid M5 evidence"
            ) from error
        if payload_json != canonical:
            raise StorageConflictError("stored validation payload is not canonical")
        if payload != record.payload:
            raise StorageConflictError(
                "stored validation payload does not match its record"
            )
        if _sha256(canonical) != record.result_sha256:
            raise StorageConflictError(
                "stored validation payload does not match its authoritative hash"
            )
        return canonical

    @staticmethod
    def _require_result_matches_stored_job(
        record: ValidationResultRecord,
        stored_job: StoredValidationJob,
        *,
        completed: bool,
    ) -> None:
        job = stored_job.job
        if stored_job.assigned_agent_id != record.agent_id:
            raise StorageConflictError(
                "validation result Agent does not match the dispatched job"
            )
        if record.created_at != job.created_at or record.dispatched_at != job.dispatched_at:
            raise StorageConflictError(
                "validation result lifecycle does not match the dispatched job"
            )
        if completed:
            if (
                job.status is not JobStatus.COMPLETED
                or job.completed_at != record.completed_at
            ):
                raise StorageConflictError(
                    "validation result does not match the completed job"
                )
        elif job.status is not JobStatus.DISPATCHED:
            raise StorageConflictError(
                "validation job is not awaiting a result"
            )
        try:
            require_payload_matches_job(record.payload, job)
        except ValueError as error:
            raise StorageConflictError(
                "validation result lineage does not match its job"
            ) from error

    @classmethod
    def _stored_validation_result_from_row(
        cls,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> tuple[ValidationResultRecord, str]:
        try:
            payload = ValidationResultPayload.model_validate_json(
                row["payload_json"]
            )
            record = ValidationResultRecord(
                validation_result_id=UUID(row["validation_result_id"]),
                agent_id=UUID(row["agent_id"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                dispatched_at=datetime.fromisoformat(row["dispatched_at"]),
                completed_at=datetime.fromisoformat(row["completed_at"]),
                result_sha256=row["result_sha256"],
                payload=payload,
            )
            canonical = cls._validate_validation_result_payload(
                record, row["payload_json"]
            )
        except StorageConflictError:
            raise
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError(
                "stored validation result metadata is invalid"
            ) from error
        if (
            row["target_id"] != str(payload.target_id)
            or row["profile_id"] != str(payload.profile_id)
            or row["compatibility_report_id"]
            != str(payload.compatibility_report_id)
            or row["validation_job_id"] != str(payload.validation_job_id)
            or row["control_id"] != payload.control_id
            or row["validation_mode"] != payload.validation_mode.value
            or row["execution_mode"] != payload.execution_mode.value
        ):
            raise StorageConflictError(
                "stored validation result columns do not match its payload"
            )
        job_row = connection.execute(
            "SELECT * FROM validation_jobs WHERE validation_job_id = ?",
            (row["validation_job_id"],),
        ).fetchone()
        if job_row is None:
            raise StorageConflictError(
                "stored validation result job does not exist"
            )
        stored_job = cls._stored_validation_job_from_row(connection, job_row)
        cls._require_result_matches_stored_job(
            record,
            stored_job,
            completed=True,
        )
        return record, canonical

    def store_validation_result(
        self,
        record: ValidationResultRecord,
        payload_json: str,
    ) -> ValidationResultRecord:
        canonical = self._validate_validation_result_payload(record, payload_json)
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            job_row = connection.execute(
                "SELECT * FROM validation_jobs WHERE validation_job_id = ?",
                (str(record.payload.validation_job_id),),
            ).fetchone()
            if job_row is None:
                raise StorageNotFoundError("validation job does not exist")
            stored_job = self._stored_validation_job_from_row(connection, job_row)

            existing_row = connection.execute(
                "SELECT * FROM validation_results WHERE validation_job_id = ?",
                (str(record.payload.validation_job_id),),
            ).fetchone()
            if existing_row is not None:
                existing, existing_canonical = self._stored_validation_result_from_row(
                    connection,
                    existing_row,
                )
                if (
                    existing.agent_id != record.agent_id
                    or existing.result_sha256 != record.result_sha256
                    or existing_canonical != canonical
                ):
                    raise StorageConflictError(
                        "validation job already has different result evidence"
                    )
                return existing

            self._require_result_matches_stored_job(
                record,
                stored_job,
                completed=False,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO validation_results (
                        validation_result_id, validation_job_id, target_id,
                        profile_id, compatibility_report_id, agent_id,
                        control_id, validation_mode, execution_mode, created_at,
                        dispatched_at, completed_at, result_sha256, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(record.validation_result_id),
                        str(record.payload.validation_job_id),
                        str(record.payload.target_id),
                        str(record.payload.profile_id),
                        str(record.payload.compatibility_report_id),
                        str(record.agent_id),
                        record.payload.control_id,
                        record.payload.validation_mode.value,
                        record.payload.execution_mode.value,
                        record.created_at.isoformat(),
                        record.dispatched_at.isoformat(),
                        record.completed_at.isoformat(),
                        record.result_sha256,
                        canonical,
                    ),
                )
                connection.execute(
                    """
                    UPDATE validation_jobs
                    SET status = ?, completed_at = ?
                    WHERE validation_job_id = ? AND target_id = ?
                      AND assigned_agent_id = ? AND status = ?
                    """,
                    (
                        JobStatus.COMPLETED.value,
                        record.completed_at.isoformat(),
                        str(record.payload.validation_job_id),
                        str(record.payload.target_id),
                        str(record.agent_id),
                        JobStatus.DISPATCHED.value,
                    ),
                )
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise StorageConflictError(
                        "validation job changed while its result was stored"
                    )
            except sqlite3.IntegrityError as error:
                raise StorageConflictError(
                    "validation result ID or lineage conflicts"
                ) from error
        return record

    def get_validation_result_for_job(
        self,
        validation_job_id: UUID,
    ) -> ValidationResultRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM validation_results WHERE validation_job_id = ?",
                (str(validation_job_id),),
            ).fetchone()
            if row is None:
                return None
            return self._stored_validation_result_from_row(connection, row)[0]

    def get_validation_result(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        validation_result_id: UUID,
    ) -> ValidationResultRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM validation_results
                WHERE target_id = ? AND profile_id = ?
                  AND compatibility_report_id = ?
                  AND validation_result_id = ?
                """,
                (
                    str(target_id),
                    str(profile_id),
                    str(compatibility_report_id),
                    str(validation_result_id),
                ),
            ).fetchone()
            if row is None:
                return None
            return self._stored_validation_result_from_row(connection, row)[0]

    def list_validation_results(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
    ) -> list[ValidationResultRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM validation_results
                WHERE target_id = ? AND profile_id = ?
                  AND compatibility_report_id = ?
                ORDER BY completed_at, validation_result_id
                """,
                (
                    str(target_id),
                    str(profile_id),
                    str(compatibility_report_id),
                ),
            ).fetchall()
            return [
                self._stored_validation_result_from_row(connection, row)[0]
                for row in rows
            ]

    @staticmethod
    def _sandbox_authorization_matches(
        existing: SandboxSessionRecord,
        requested: SandboxSessionRecord,
    ) -> bool:
        """Compare the immutable administrator authorization for idempotency."""

        return (
            existing.request_id == requested.request_id
            and existing.source_target_id == requested.source_target_id
            and existing.source_profile_id == requested.source_profile_id
            and existing.source_compatibility_report_id
            == requested.source_compatibility_report_id
            and existing.control_id == requested.control_id
            and existing.provider_type is requested.provider_type
            and existing.administrator_sandbox_authorization_acknowledged
            is requested.administrator_sandbox_authorization_acknowledged
            and existing.compatibility_reference
            == requested.compatibility_reference
            and existing.compatibility_reference_sha256
            == requested.compatibility_reference_sha256
        )

    @classmethod
    def _validate_sandbox_lineage(
        cls,
        connection: sqlite3.Connection,
        session: SandboxSessionRecord,
    ) -> None:
        profile_row = connection.execute(
            "SELECT * FROM profiles WHERE target_id = ? AND profile_id = ?",
            (
                str(session.source_target_id),
                str(session.source_profile_id),
            ),
        ).fetchone()
        if profile_row is None:
            raise StorageNotFoundError("sandbox source profile does not exist")
        stored_profile = cls._stored_profile_from_row(profile_row)

        report_row = connection.execute(
            """
            SELECT * FROM compatibility_reports
            WHERE target_id = ? AND profile_id = ?
              AND compatibility_report_id = ?
            """,
            (
                str(session.source_target_id),
                str(session.source_profile_id),
                str(session.source_compatibility_report_id),
            ),
        ).fetchone()
        if report_row is None:
            raise StorageNotFoundError(
                "sandbox compatibility report does not exist"
            )
        stored_report = cls._stored_compatibility_report_from_row(report_row)
        cls._validate_compatibility_report_lineage(stored_report, stored_profile)
        try:
            expected_reference = compatibility_reference_from_record(
                stored_report.record,
                session.control_id,
            )
        except ValueError as error:
            raise StorageConflictError(
                "sandbox control is absent from its compatibility report"
            ) from error
        reference_json = _canonical_compatibility_reference_json(
            session.compatibility_reference
        )
        if (
            session.compatibility_reference != expected_reference
            or session.compatibility_reference_sha256 != _sha256(reference_json)
        ):
            raise StorageConflictError(
                "sandbox session changed its M4 authorization evidence"
            )
        if session.created_at < stored_report.record.generated_at:
            raise StorageConflictError(
                "sandbox session predates its compatibility report"
            )

    @classmethod
    def _stored_sandbox_session_from_row(
        cls,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> SandboxSessionRecord:
        try:
            acknowledgment = row[
                "administrator_sandbox_authorization_acknowledged"
            ]
            if acknowledgment != 1:
                raise ValueError(
                    "stored sandbox authorization must be acknowledged"
                )
            reference = cls._compatibility_reference_from_json(
                row["compatibility_reference_json"]
            )
            reference_json = _canonical_compatibility_reference_json(reference)
            if _sha256(reference_json) != row["compatibility_reference_sha256"]:
                raise ValueError(
                    "stored sandbox compatibility reference hash is invalid"
                )
            session = SandboxSessionRecord(
                sandbox_session_id=_canonical_stored_uuid_text(
                    row["sandbox_session_id"], "sandbox_session_id"
                ),
                request_id=_canonical_stored_uuid_text(
                    row["request_id"], "sandbox request_id"
                ),
                source_target_id=_canonical_stored_uuid_text(
                    row["source_target_id"], "sandbox source_target_id"
                ),
                source_profile_id=_canonical_stored_uuid_text(
                    row["source_profile_id"], "sandbox source_profile_id"
                ),
                source_compatibility_report_id=_canonical_stored_uuid_text(
                    row["source_compatibility_report_id"],
                    "sandbox source_compatibility_report_id",
                ),
                control_id=row["control_id"],
                provider_type=SandboxProviderType(row["provider_type"]),
                status=SandboxSessionStatus(row["status"]),
                sandbox_instance_id=row["sandbox_instance_id"],
                administrator_sandbox_authorization_acknowledged=bool(
                    acknowledgment
                ),
                compatibility_reference=reference,
                compatibility_reference_sha256=row[
                    "compatibility_reference_sha256"
                ],
                created_at=datetime.fromisoformat(row["created_at"]),
                provisioning_started_at=_parse_datetime(
                    row["provisioning_started_at"]
                ),
                ready_at=_parse_datetime(row["ready_at"]),
                validation_started_at=_parse_datetime(
                    row["validation_started_at"]
                ),
                completed_at=_parse_datetime(row["completed_at"]),
                closed_at=_parse_datetime(row["closed_at"]),
                failure_reason=row["failure_reason"],
                quarantine_reason=row["quarantine_reason"],
            )
            cls._validate_sandbox_lineage(connection, session)
            return session
        except StorageConflictError:
            raise
        except StorageNotFoundError as error:
            raise StorageConflictError(
                "stored sandbox session lineage is missing"
            ) from error
        except (TypeError, ValueError, ValidationError, UnicodeError) as error:
            raise StorageConflictError(
                "stored sandbox session metadata is invalid"
            ) from error

    def create_sandbox_session(
        self,
        session: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        if session.status is not SandboxSessionStatus.REQUESTED:
            raise StorageConflictError("a new sandbox session must be REQUESTED")
        reference_json = _canonical_compatibility_reference_json(
            session.compatibility_reference
        )
        if _sha256(reference_json) != session.compatibility_reference_sha256:
            raise StorageConflictError(
                "sandbox compatibility reference hash is invalid"
            )

        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            for row in connection.execute(
                "SELECT request_id FROM sandbox_sessions"
            ).fetchall():
                _canonical_stored_uuid_text(
                    row["request_id"], "sandbox request_id"
                )

            existing_row = connection.execute(
                "SELECT * FROM sandbox_sessions WHERE request_id = ?",
                (str(session.request_id),),
            ).fetchone()
            if existing_row is not None:
                existing = self._stored_sandbox_session_from_row(
                    connection, existing_row
                )
                if not self._sandbox_authorization_matches(existing, session):
                    raise StorageConflictError(
                        "sandbox request ID conflicts with another authorization"
                    )
                return existing

            self._validate_sandbox_lineage(connection, session)
            try:
                connection.execute(
                    """
                    INSERT INTO sandbox_sessions (
                        sandbox_session_id, request_id, source_target_id,
                        source_profile_id, source_compatibility_report_id,
                        control_id, provider_type, status,
                        sandbox_instance_id,
                        administrator_sandbox_authorization_acknowledged,
                        compatibility_reference_json,
                        compatibility_reference_sha256, created_at,
                        provisioning_started_at, ready_at,
                        validation_started_at, completed_at, closed_at,
                        failure_reason, quarantine_reason
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?,
                        NULL, NULL, NULL, NULL, NULL, NULL, NULL
                    )
                    """,
                    (
                        str(session.sandbox_session_id),
                        str(session.request_id),
                        str(session.source_target_id),
                        str(session.source_profile_id),
                        str(session.source_compatibility_report_id),
                        session.control_id,
                        session.provider_type.value,
                        session.status.value,
                        int(
                            session.administrator_sandbox_authorization_acknowledged
                        ),
                        reference_json,
                        session.compatibility_reference_sha256,
                        session.created_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StorageConflictError(
                    "sandbox session ID, request ID, instance, or lineage conflicts"
                ) from error
        return session

    def get_sandbox_session(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM sandbox_sessions
                WHERE source_target_id = ? AND source_profile_id = ?
                  AND source_compatibility_report_id = ?
                  AND sandbox_session_id = ?
                """,
                (
                    str(target_id),
                    str(profile_id),
                    str(compatibility_report_id),
                    str(sandbox_session_id),
                ),
            ).fetchone()
            if row is None:
                return None
            return self._stored_sandbox_session_from_row(connection, row)

    def list_sandbox_sessions(
        self,
        *,
        target_id: UUID,
        profile_id: UUID,
        compatibility_report_id: UUID,
    ) -> list[SandboxSessionRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM sandbox_sessions
                WHERE source_target_id = ? AND source_profile_id = ?
                  AND source_compatibility_report_id = ?
                ORDER BY created_at, sandbox_session_id
                """,
                (
                    str(target_id),
                    str(profile_id),
                    str(compatibility_report_id),
                ),
            ).fetchall()
            return [
                self._stored_sandbox_session_from_row(connection, row)
                for row in rows
            ]

    def get_sandbox_session_by_id(
        self,
        sandbox_session_id: UUID,
    ) -> SandboxSessionRecord | None:
        """Trusted internal lookup used only by explicit lifecycle methods."""

        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_sessions WHERE sandbox_session_id = ?",
                (str(sandbox_session_id),),
            ).fetchone()
            if row is None:
                return None
            return self._stored_sandbox_session_from_row(connection, row)

    def _transition_sandbox_session(
        self,
        *,
        expected_statuses: frozenset[SandboxSessionStatus],
        session: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM sandbox_sessions WHERE sandbox_session_id = ?",
                (str(session.sandbox_session_id),),
            ).fetchone()
            if row is None:
                raise StorageNotFoundError("sandbox session does not exist")
            current = self._stored_sandbox_session_from_row(connection, row)
            if current.status not in expected_statuses or (
                session.status not in SANDBOX_SESSION_TRANSITIONS[current.status]
            ):
                raise StorageConflictError(
                    "sandbox session is not in the expected prior state"
                )
            if not self._sandbox_authorization_matches(current, session) or (
                current.sandbox_session_id != session.sandbox_session_id
                or current.created_at != session.created_at
            ):
                raise StorageConflictError(
                    "sandbox transition changed immutable authorization"
                )
            allowed_changes = {
                SandboxSessionStatus.PROVISIONING: {
                    "status",
                    "provisioning_started_at",
                },
                SandboxSessionStatus.READY: {
                    "status",
                    "sandbox_instance_id",
                    "ready_at",
                },
                SandboxSessionStatus.VALIDATING: {
                    "status",
                    "validation_started_at",
                },
                SandboxSessionStatus.COMPLETED: {
                    "status",
                    "completed_at",
                },
                SandboxSessionStatus.FAILED: {
                    "status",
                    "completed_at",
                    "failure_reason",
                },
                SandboxSessionStatus.QUARANTINED: {
                    "status",
                    "completed_at",
                    "quarantine_reason",
                },
                SandboxSessionStatus.CLOSED: {
                    "status",
                    "closed_at",
                },
            }[session.status]
            for field_name in SandboxSessionRecord.model_fields:
                if field_name in allowed_changes:
                    continue
                if getattr(current, field_name) != getattr(session, field_name):
                    raise StorageConflictError(
                        "sandbox transition changed previously recorded state"
                    )
            self._validate_sandbox_lineage(connection, session)
            try:
                connection.execute(
                    """
                    UPDATE sandbox_sessions
                    SET status = ?, sandbox_instance_id = ?,
                        provisioning_started_at = ?, ready_at = ?,
                        validation_started_at = ?, completed_at = ?,
                        closed_at = ?, failure_reason = ?,
                        quarantine_reason = ?
                    WHERE sandbox_session_id = ? AND status = ?
                    """,
                    (
                        session.status.value,
                        session.sandbox_instance_id,
                        session.provisioning_started_at.isoformat()
                        if session.provisioning_started_at is not None
                        else None,
                        session.ready_at.isoformat()
                        if session.ready_at is not None
                        else None,
                        session.validation_started_at.isoformat()
                        if session.validation_started_at is not None
                        else None,
                        session.completed_at.isoformat()
                        if session.completed_at is not None
                        else None,
                        session.closed_at.isoformat()
                        if session.closed_at is not None
                        else None,
                        session.failure_reason,
                        session.quarantine_reason,
                        str(session.sandbox_session_id),
                        current.status.value,
                    ),
                )
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise StorageConflictError(
                        "sandbox session changed during transition"
                    )
            except sqlite3.IntegrityError as error:
                raise StorageConflictError(
                    "sandbox lifecycle or instance identity conflicts"
                ) from error

            updated_row = connection.execute(
                "SELECT * FROM sandbox_sessions WHERE sandbox_session_id = ?",
                (str(session.sandbox_session_id),),
            ).fetchone()
            assert updated_row is not None
            return self._stored_sandbox_session_from_row(connection, updated_row)

    def mark_provisioning(
        self,
        session: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        if session.status is not SandboxSessionStatus.PROVISIONING:
            raise StorageConflictError("sandbox transition must end in PROVISIONING")
        return self._transition_sandbox_session(
            expected_statuses=frozenset({SandboxSessionStatus.REQUESTED}),
            session=session,
        )

    def mark_ready(
        self,
        session: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        if session.status is not SandboxSessionStatus.READY:
            raise StorageConflictError("sandbox transition must end in READY")
        return self._transition_sandbox_session(
            expected_statuses=frozenset({SandboxSessionStatus.PROVISIONING}),
            session=session,
        )

    def mark_validating(
        self,
        session: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        if session.status is not SandboxSessionStatus.VALIDATING:
            raise StorageConflictError("sandbox transition must end in VALIDATING")
        return self._transition_sandbox_session(
            expected_statuses=frozenset({SandboxSessionStatus.READY}),
            session=session,
        )

    def mark_completed(
        self,
        session: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        if session.status is not SandboxSessionStatus.COMPLETED:
            raise StorageConflictError("sandbox transition must end in COMPLETED")
        return self._transition_sandbox_session(
            expected_statuses=frozenset({SandboxSessionStatus.VALIDATING}),
            session=session,
        )

    def mark_failed(
        self,
        session: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        if session.status is not SandboxSessionStatus.FAILED:
            raise StorageConflictError("sandbox transition must end in FAILED")
        return self._transition_sandbox_session(
            expected_statuses=frozenset(
                {
                    SandboxSessionStatus.PROVISIONING,
                    SandboxSessionStatus.READY,
                    SandboxSessionStatus.VALIDATING,
                }
            ),
            session=session,
        )

    def mark_provisioning_failed(
        self,
        session: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        """Race-safe M6E-B failure transition from PROVISIONING only."""

        if session.status is not SandboxSessionStatus.FAILED:
            raise StorageConflictError("sandbox transition must end in FAILED")
        return self._transition_sandbox_session(
            expected_statuses=frozenset(
                {SandboxSessionStatus.PROVISIONING}
            ),
            session=session,
        )

    def mark_quarantined(
        self,
        session: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        if session.status is not SandboxSessionStatus.QUARANTINED:
            raise StorageConflictError("sandbox transition must end in QUARANTINED")
        return self._transition_sandbox_session(
            expected_statuses=frozenset({SandboxSessionStatus.VALIDATING}),
            session=session,
        )

    def close_session(
        self,
        session: SandboxSessionRecord,
    ) -> SandboxSessionRecord:
        if session.status is not SandboxSessionStatus.CLOSED:
            raise StorageConflictError("sandbox transition must end in CLOSED")
        return self._transition_sandbox_session(
            expected_statuses=frozenset(
                {
                    SandboxSessionStatus.COMPLETED,
                    SandboxSessionStatus.FAILED,
                    SandboxSessionStatus.QUARANTINED,
                }
            ),
            session=session,
        )
