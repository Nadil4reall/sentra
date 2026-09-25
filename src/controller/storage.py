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
    JobRecord,
    JobStatus,
    JobType,
    MetadataChangeRecord,
    ObservedTargetMetadata,
    ProfileRecord,
    TargetRecord,
    TargetStatus,
)
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


def _normalized_schema_sql(value: str) -> str:
    """Normalize insignificant SQL whitespace for an exact schema fingerprint."""

    return " ".join(value.strip().rstrip(";").split())


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
            self._validate_profile_payload(record, payload_json)
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
