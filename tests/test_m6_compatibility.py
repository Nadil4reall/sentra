"""M6C Controller service/storage integration with the existing M4 engine."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from uuid import UUID, uuid4

from pydantic import SecretStr
import pytest
import yaml

from src.compatibility_engine.models import CompatibilityDecision
from src.controller.models import (
    AdminAuth,
    AgentAuth,
    CompatibilityAnalysisRequest,
    EnrollmentRequest,
    JobCreateRequest,
    JobPollRequest,
    JobType,
    ObservedTargetMetadata,
    ProfileSubmissionRequest,
)
from src.controller.service import (
    AuthenticationError,
    AuthorizationError,
    ControllerConflictError,
    ControllerNotFoundError,
    ControllerService,
    ControllerSettings,
)
from src.controller.storage import (
    ControllerStorageSecurityError,
    SQLiteControllerRepository,
)
from src.poc_models import DerivationStatus
from src.target_profiler.models import (
    FactResult,
    FactStatus,
    TargetProfile,
    build_collection_summary,
)


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "data" / "profiles" / "target-profile.yaml"
NOW = datetime(2026, 9, 24, 9, 30, tzinfo=timezone.utc)
BOOTSTRAP = SecretStr("m6c-bootstrap-fixture")
ADMIN = SecretStr("m6c-admin-fixture")


def _profile(*, include_error: bool = False) -> TargetProfile:
    profile = TargetProfile.model_validate(
        yaml.safe_load(PROFILE_PATH.read_text(encoding="utf-8"))
    )
    if not include_error:
        return profile

    updated = profile.model_copy(deep=True)
    original = updated.facts["ssh_installed"]
    updated.facts["ssh_installed"] = FactResult(
        name=original.name,
        status=FactStatus.ERROR,
        value=None,
        requested_by=list(original.requested_by),
        reason="synthetic M6C collection-error preservation fixture",
    )
    updated.collection_summary = build_collection_summary(updated.facts)
    return TargetProfile.model_validate(updated.model_dump())


def _controller(
    tmp_path: Path,
) -> tuple[Path, SQLiteControllerRepository, ControllerService]:
    database = tmp_path / "controller.sqlite3"
    repository = SQLiteControllerRepository(database)
    service = ControllerService(
        repository,
        ControllerSettings(
            bootstrap_credential=BOOTSTRAP,
            admin_credential=ADMIN,
        ),
        clock=lambda: NOW,
    )
    return database, repository, service


def _admin() -> AdminAuth:
    return AdminAuth(admin_credential=ADMIN)


def _enroll(service: ControllerService, hostname: str):
    return service.enroll(
        EnrollmentRequest(
            bootstrap_credential=BOOTSTRAP,
            installation_id=uuid4(),
            agent_version="m6c-test",
            observed_metadata=ObservedTargetMetadata(
                hostname=hostname,
                os="Ubuntu",
                os_version="24.04",
                kernel="6.8.0-m6c-test",
                architecture="x86_64",
            ),
        )
    )


def _auth(enrollment) -> AgentAuth:
    return AgentAuth(
        target_id=enrollment.target_id,
        agent_id=enrollment.agent_id,
        agent_credential=enrollment.agent_credential,
    )


def _store_profile(
    service: ControllerService,
    profile: TargetProfile,
    *,
    hostname: str = "m6c-target",
):
    enrollment = _enroll(service, hostname)
    job = service.create_job(
        _admin(),
        JobCreateRequest(
            target_id=enrollment.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )
    jobs = service.poll_jobs(JobPollRequest(auth=_auth(enrollment))).jobs
    assert [item.job_id for item in jobs] == [job.job_id]
    record = service.submit_profile(
        ProfileSubmissionRequest(
            auth=_auth(enrollment),
            job_id=job.job_id,
            profile=profile,
            profiler_version="m3-profile-version-1",
            sentra_version="m6c-test",
        )
    )
    return enrollment, record


def _run_analysis(service: ControllerService, target_id: UUID, profile_id: UUID):
    return service.run_compatibility_analysis(
        _admin(),
        CompatibilityAnalysisRequest(
            target_id=target_id,
            profile_id=profile_id,
        ),
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def test_stored_profile_runs_existing_m4_with_complete_lineage_and_semantics(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    profile = _profile()
    enrollment, stored_profile = _store_profile(service, profile)

    record = _run_analysis(
        service,
        enrollment.target_id,
        stored_profile.profile_id,
    )

    assert record.target_id == enrollment.target_id
    assert record.profile_id == stored_profile.profile_id
    assert record.compatibility_report_id
    assert record.benchmark_identity == (
        "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0"
    )
    assert record.benchmark_version == "v1.0.0"
    assert record.generated_at == NOW == record.report.generated_at
    assert record.report_version == "1" == record.report.report_version
    assert record.report.profile_source == (
        f"controller-stored-profile:{stored_profile.profile_id}"
    )
    assert record.report.profile_collected_at == profile.collected_at
    assert record.report.target == profile.target
    assert len(record.report.control_results) == 10
    assert {item.result for item in record.report.control_results} == set(
        CompatibilityDecision
    )
    serialized_report = record.report.model_dump(mode="json")
    assert {item["result"] for item in serialized_report["control_results"]} == {
        "no_known_conflict",
        "warning",
        "review_required",
        "insufficient_evidence",
    }
    assert '"safe":' not in _canonical_json(serialized_report)
    assert all(item.provisional for item in record.report.control_results)
    assert {
        item.metadata_review_status for item in record.report.control_results
    } == {DerivationStatus.NEEDS_REVIEW}


def test_all_m3_states_survive_stored_profile_analysis(tmp_path: Path) -> None:
    _, _, service = _controller(tmp_path)
    profile = _profile(include_error=True)
    enrollment, stored_profile = _store_profile(service, profile)

    record = _run_analysis(
        service,
        enrollment.target_id,
        stored_profile.profile_id,
    )
    evidence = [
        item
        for result in record.report.control_results
        for item in result.evidence_used
    ]

    assert {item.status for item in evidence} == set(FactStatus)
    error_evidence = [
        item for item in evidence if item.fact == "ssh_installed"
    ]
    assert error_evidence
    assert all(item.status is FactStatus.ERROR for item in error_evidence)
    assert all(
        item.reason == "synthetic M6C collection-error preservation fixture"
        for item in error_evidence
    )


def test_report_hash_is_canonical_deterministic_and_reports_list_and_get(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile = _store_profile(service, _profile())

    first = _run_analysis(service, enrollment.target_id, stored_profile.profile_id)
    second = _run_analysis(service, enrollment.target_id, stored_profile.profile_id)
    canonical = _canonical_json(first.report.model_dump(mode="json"))
    expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    assert first.report == second.report
    assert first.report_sha256 == expected_hash == second.report_sha256
    listed = service.list_compatibility_reports(
        _admin(),
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
    )
    assert {item.compatibility_report_id for item in listed} == {
        first.compatibility_report_id,
        second.compatibility_report_id,
    }
    assert service.get_compatibility_report(
        _admin(),
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
        compatibility_report_id=first.compatibility_report_id,
    ) == first

    with sqlite3.connect(database) as connection:
        stored_payload, stored_hash = connection.execute(
            "SELECT payload_json, report_sha256 FROM compatibility_reports "
            "WHERE compatibility_report_id = ?",
            (str(first.compatibility_report_id),),
        ).fetchone()
    assert stored_payload == canonical
    assert stored_hash == expected_hash

    restarted_repository = SQLiteControllerRepository(database)
    restarted_service = ControllerService(
        restarted_repository,
        ControllerSettings(
            bootstrap_credential=BOOTSTRAP,
            admin_credential=ADMIN,
        ),
        clock=lambda: NOW,
    )
    assert restarted_service.get_compatibility_report(
        _admin(),
        target_id=enrollment.target_id,
        profile_id=stored_profile.profile_id,
        compatibility_report_id=first.compatibility_report_id,
    ) == first

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE compatibility_reports SET report_sha256 = ? "
            "WHERE compatibility_report_id = ?",
            ("0" * 64, str(first.compatibility_report_id)),
        )
    with pytest.raises(
        ControllerConflictError,
        match="stored compatibility report could not be validated",
    ):
        restarted_service.get_compatibility_report(
            _admin(),
            target_id=enrollment.target_id,
            profile_id=stored_profile.profile_id,
            compatibility_report_id=first.compatibility_report_id,
        )


def test_missing_cross_target_and_admin_boundaries_are_enforced(
    tmp_path: Path,
) -> None:
    _, _, service = _controller(tmp_path)
    first, stored_profile = _store_profile(service, _profile(), hostname="first")
    second = _enroll(service, "second")
    missing_profile = uuid4()

    with pytest.raises(ControllerNotFoundError, match="profile does not exist"):
        _run_analysis(service, first.target_id, missing_profile)
    with pytest.raises(AuthorizationError, match="does not belong"):
        _run_analysis(service, second.target_id, stored_profile.profile_id)
    with pytest.raises(AuthorizationError, match="does not belong"):
        service.list_compatibility_reports(
            _admin(),
            target_id=second.target_id,
            profile_id=stored_profile.profile_id,
        )
    with pytest.raises(AuthenticationError):
        service.run_compatibility_analysis(
            AdminAuth(admin_credential=SecretStr("wrong-admin")),
            CompatibilityAnalysisRequest(
                target_id=first.target_id,
                profile_id=stored_profile.profile_id,
            ),
        )


@pytest.mark.parametrize("corruption", ["hash_mismatch", "malformed_payload"])
def test_tampered_or_malformed_stored_profile_is_rejected(
    tmp_path: Path,
    corruption: str,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, stored_profile = _store_profile(service, _profile())

    with sqlite3.connect(database) as connection:
        if corruption == "hash_mismatch":
            raw = connection.execute(
                "SELECT payload_json FROM profiles WHERE profile_id = ?",
                (str(stored_profile.profile_id),),
            ).fetchone()[0]
            payload = json.loads(raw)
            payload["target"]["hostname"] = "tampered-hostname"
            connection.execute(
                "UPDATE profiles SET payload_json = ? WHERE profile_id = ?",
                (_canonical_json(payload), str(stored_profile.profile_id)),
            )
        else:
            malformed = _canonical_json({})
            connection.execute(
                "UPDATE profiles SET payload_json = ?, profile_sha256 = ? "
                "WHERE profile_id = ?",
                (
                    malformed,
                    hashlib.sha256(malformed.encode("utf-8")).hexdigest(),
                    str(stored_profile.profile_id),
                ),
            )

    with pytest.raises(
        ControllerConflictError,
        match="stored profile evidence could not be validated",
    ):
        _run_analysis(service, enrollment.target_id, stored_profile.profile_id)


def test_database_foreign_key_rejects_cross_target_report_lineage(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    first, stored_profile = _store_profile(service, _profile(), hostname="first")
    second = _enroll(service, "second")
    report = _run_analysis(service, first.target_id, stored_profile.profile_id)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        row = connection.execute(
            "SELECT benchmark_identity, benchmark_version, generated_at, "
            "report_version, report_sha256, payload_json "
            "FROM compatibility_reports WHERE compatibility_report_id = ?",
            (str(report.compatibility_report_id),),
        ).fetchone()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO compatibility_reports ("
                "compatibility_report_id, target_id, profile_id, "
                "benchmark_identity, benchmark_version, generated_at, "
                "report_version, report_sha256, payload_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    str(second.target_id),
                    str(stored_profile.profile_id),
                    *row,
                ),
            )


def test_retrieval_rejects_same_target_report_profile_rebinding(
    tmp_path: Path,
) -> None:
    database, _, service = _controller(tmp_path)
    enrollment, first_profile = _store_profile(service, _profile())
    second_job = service.create_job(
        _admin(),
        JobCreateRequest(
            target_id=enrollment.target_id,
            job_type=JobType.PROFILE_TARGET,
        ),
    )
    service.poll_jobs(JobPollRequest(auth=_auth(enrollment)))
    second_profile = service.submit_profile(
        ProfileSubmissionRequest(
            auth=_auth(enrollment),
            job_id=second_job.job_id,
            profile=_profile(include_error=True),
        )
    )
    report = _run_analysis(
        service,
        enrollment.target_id,
        first_profile.profile_id,
    )

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE compatibility_reports SET profile_id = ? "
            "WHERE compatibility_report_id = ?",
            (str(second_profile.profile_id), str(report.compatibility_report_id)),
        )

    with pytest.raises(
        ControllerConflictError,
        match="stored compatibility report could not be validated",
    ):
        service.get_compatibility_report(
            _admin(),
            target_id=enrollment.target_id,
            profile_id=second_profile.profile_id,
            compatibility_report_id=report.compatibility_report_id,
        )


def _create_legacy_database(path: Path, *, populated: bool) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE compatibility_reports (
                compatibility_report_id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                benchmark_identity TEXT NOT NULL,
                benchmark_version TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                report_sha256 TEXT NOT NULL
            )
            """
        )
        if populated:
            connection.execute(
                "INSERT INTO compatibility_reports VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    str(uuid4()),
                    str(uuid4()),
                    "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0",
                    "v1.0.0",
                    NOW.isoformat(),
                    "0" * 64,
                ),
            )
    os.chmod(path, 0o600)


def test_empty_legacy_compatibility_table_is_safely_upgraded(
    tmp_path: Path,
) -> None:
    database = tmp_path / "empty-legacy.sqlite3"
    _create_legacy_database(database, populated=False)

    SQLiteControllerRepository(database)

    with sqlite3.connect(database) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(compatibility_reports)"
            )
        }
    assert {"report_version", "payload_json"} <= columns


def test_nonempty_legacy_compatibility_table_fails_closed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "nonempty-legacy.sqlite3"
    _create_legacy_database(database, populated=True)

    with pytest.raises(
        ControllerStorageSecurityError,
        match="cannot be upgraded without inventing report evidence",
    ):
        SQLiteControllerRepository(database)


def test_same_columns_without_m6c_constraints_fail_closed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "false-current-schema.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE compatibility_reports (
                compatibility_report_id TEXT,
                target_id TEXT,
                profile_id TEXT,
                benchmark_identity TEXT,
                benchmark_version TEXT,
                generated_at TEXT,
                report_version TEXT,
                report_sha256 TEXT,
                payload_json TEXT
            )
            """
        )
    os.chmod(database, 0o600)

    with pytest.raises(
        ControllerStorageSecurityError,
        match="schema constraints are not recognized",
    ):
        SQLiteControllerRepository(database)
