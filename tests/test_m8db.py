"""M8 foundation tests use disposable SQLite files and existing M7 fixtures."""

from __future__ import annotations

from contextlib import closing
import json
import sqlite3
from uuid import uuid4

import pytest

from src.m8db.cli import main
from src.m8db.migrations import MigrationError, apply_migrations, check_db, open_db
from src.m8db.repository import M8DataError, M8Repository
from src.controller.storage import ControllerStorageSecurityError, StorageConflictError

from test_m6_validation import _enroll
from test_m7_enforcement import _case
from test_m7_enforcement_result import _complete_reprofile, _terminal


BENCHMARK = "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0"


@pytest.fixture
def db(tmp_path):
    return tmp_path / "controller.sqlite3"


def _benchmark(repo: M8Repository):
    return repo.create_benchmark(
        identity=BENCHMARK, version="v1.0.0", platform="Ubuntu 24.04 LTS",
        source_reference="CIS Ubuntu 24.04 LTS Benchmark v1.0.0",
    )


def _assessment_for_case(repo, case):
    benchmark = _benchmark(repo)
    repo.create_control(
        benchmark_id=benchmark["benchmark_id"], control_id="7.1.1",
        title="Ensure permissions on /etc/passwd are configured",
        required_facts=["passwd_file_mode", "passwd_file_owner_uid",
                        "passwd_file_group_gid"], adapter_capability="full",
    )
    repo.activate_benchmark(benchmark["benchmark_id"])
    assessment = repo.create_assessment(
        target_id=case.enrollment.target_id, profile_id=case.profile_id,
        benchmark_id=benchmark["benchmark_id"],
    )
    repo.start_assessment(assessment["assessment_id"])
    profile = case.repository.get_stored_profile(case.profile_id)
    evidence_id = repo.create_evidence(
        evidence_type="m3_profile", producer="target_profiler",
        related_type="profile", related_id=case.profile_id,
        storage_reference=f"controller:profiles/{case.profile_id}",
        target_id=case.enrollment.target_id, control_id="7.1.1",
        sha256=profile.record.profile_sha256,
    )
    result = repo.record_assessment_result(
        assessment_id=assessment["assessment_id"], control_id="7.1.1",
        state="needs_review", reason="m2_metadata_needs_review",
        observed_facts={"passwd_file_mode": "0644"}, evidence_id=evidence_id,
    )
    repo.complete_assessment(assessment["assessment_id"])
    repo.link_compatibility_report(
        assessment_id=assessment["assessment_id"],
        compatibility_report_id=case.report_id,
    )
    return benchmark, assessment, result, evidence_id


def test_empty_initialization_is_one_controller_database_without_fake_records(db):
    assert apply_migrations(db) == [1]
    report = check_db(db)
    assert report["ok"] and report["sqlite_integrity"] == "ok"
    assert report["foreign_key_violations"] == 0
    assert {"targets", "agents", "profiles", "compatibility_reports",
            "sandbox_sessions", "enforcement_jobs", "enforcement_results",
            "post_enforcement_verifications"}.issubset(report["tables"])
    assert not {"m8_targets", "m8_agents", "m8_profiles", "m8_sandbox_sessions",
                "m8_validation_results", "m8_verifications"}.intersection(report["tables"])
    assert report["missing_views"] == []
    with open_db(db) as connection:
        for table in ("targets", "agents", "profiles", "m8_benchmarks",
                      "m8_users", "m8_assessments", "m8_audit_events"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
        assert {row[0] for row in connection.execute(
            "SELECT role_name FROM m8_roles"
        )} == {"admin", "viewer"}


def test_migration_idempotency_and_status(db):
    assert apply_migrations(db) == [1]
    assert apply_migrations(db) == []
    assert check_db(db)["migration_versions"] == [1]


def test_migration_rejects_conflicting_schema_atomically(db):
    from src.controller.storage import SQLiteControllerRepository

    SQLiteControllerRepository(db)
    with closing(sqlite3.connect(db)) as connection, connection:
        connection.execute("CREATE TABLE m8_users (wrong TEXT)")
    with pytest.raises(MigrationError):
        apply_migrations(db)
    with closing(sqlite3.connect(db)) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='m8_benchmarks'"
        ).fetchone() is None
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='m8_schema_migrations'"
        ).fetchone() is None


def test_migration_checksum_tampering_fails_closed(db):
    apply_migrations(db)
    with open_db(db) as connection:
        connection.execute(
            "UPDATE m8_schema_migrations SET checksum = ? WHERE version = 1",
            ("0" * 64,),
        )
    assert not check_db(db)["ok"]
    with pytest.raises(MigrationError):
        apply_migrations(db)


def test_missing_append_only_trigger_fails_integrity_and_repository_start(db):
    apply_migrations(db)
    with open_db(db) as connection:
        connection.execute("DROP TRIGGER m8_audit_no_update")
    assert "m8_audit_no_update" in check_db(db)["missing_triggers"]
    with pytest.raises(MigrationError):
        M8Repository(db)


def test_foreign_keys_and_orphans_rejected(db):
    apply_migrations(db)
    with open_db(db) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO m8_assessments (assessment_id,target_id,profile_id,"
                "benchmark_id,state,created_at) VALUES (?,?,?,?,'pending',?)",
                tuple(str(uuid4()) for _ in range(5)),
            )


def test_benchmark_active_scope_and_control_relationship(db):
    repo = M8Repository(db)
    first = _benchmark(repo)
    second = repo.create_benchmark(
        identity="Other Ubuntu benchmark", version="v2", platform="Ubuntu 24.04 LTS",
        source_reference="test-only reference",
    )
    third = repo.create_benchmark(
        identity="Other platform benchmark", version="v1", platform="Other Linux",
        source_reference="test-only reference",
    )
    repo.activate_benchmark(first["benchmark_id"])
    repo.activate_benchmark(third["benchmark_id"])
    repo.activate_benchmark(second["benchmark_id"])
    assert repo.get_benchmark(first["benchmark_id"])["active"] == 0
    assert repo.get_benchmark(second["benchmark_id"])["active"] == 1
    assert repo.get_benchmark(third["benchmark_id"])["active"] == 1
    repo.create_control(
        benchmark_id=first["benchmark_id"], control_id="7.1.1", title="passwd",
        required_facts=["passwd_file_mode"], adapter_capability="full",
    )
    with open_db(db) as connection:
        assert connection.execute(
            "SELECT review_state FROM m8_controls WHERE benchmark_id = ?",
            (first["benchmark_id"],),
        ).fetchone()[0] == "needs_review"
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO m8_controls (benchmark_id,control_id,title,selected,"
                "review_state,required_facts_json,adapter_capability,metadata_json) "
                "VALUES (?,?,?,1,'needs_review','[]','full','{}')",
                (str(uuid4()), "7.1.1", "orphan"),
            )


def test_user_password_hash_roles_and_no_plaintext(db):
    repo = M8Repository(db)
    user = repo.create_user(username="research-admin", password="correct horse battery")
    repo.assign_role(user_id=user["user_id"], role_name="admin")
    with open_db(db) as connection:
        stored = connection.execute(
            "SELECT password_hash FROM m8_users WHERE user_id = ?", (user["user_id"],),
        ).fetchone()[0]
        assert stored.startswith("scrypt$")
        assert "correct horse battery" not in stored
        assert connection.execute(
            "SELECT role_name FROM m8_user_roles WHERE user_id = ?",
            (user["user_id"],),
        ).fetchone()[0] == "admin"
    assert "password" not in user
    with pytest.raises(M8DataError):
        repo.create_user(username="weak", password="plaintext")


def test_existing_target_agent_profile_history_is_reused(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    assert repo.get_target(case.enrollment.target_id).target_id == case.enrollment.target_id
    agent = repo.get_agent(case.enrollment.agent_id)
    assert agent["agent_id"] == case.enrollment.agent_id
    assert "credential_hash" not in agent
    assert [item["profile_id"] for item in repo.list_profile_history(
        case.enrollment.target_id,
    )] == [str(case.profile_id)]


def test_cross_target_assessment_profile_is_rejected(tmp_path):
    case = _case(tmp_path)
    foreign = _enroll(case.service, "second-m8-target")
    repo = M8Repository(case.database)
    benchmark = _benchmark(repo)
    with pytest.raises(sqlite3.IntegrityError):
        repo.create_assessment(
            target_id=foreign.target_id, profile_id=case.profile_id,
            benchmark_id=benchmark["benchmark_id"],
        )


def test_assessment_cannot_attach_foreign_target_evidence(tmp_path):
    case = _case(tmp_path)
    foreign = _enroll(case.service, "foreign-evidence-target")
    repo = M8Repository(case.database)
    benchmark = _benchmark(repo)
    repo.create_control(
        benchmark_id=benchmark["benchmark_id"], control_id="7.1.1",
        title="passwd", required_facts=[], adapter_capability="full",
    )
    assessment = repo.create_assessment(
        target_id=case.enrollment.target_id, profile_id=case.profile_id,
        benchmark_id=benchmark["benchmark_id"],
    )
    repo.start_assessment(assessment["assessment_id"])
    foreign_evidence = repo.create_evidence(
        evidence_type="target_metadata", producer="test", related_type="target",
        related_id=foreign.target_id, target_id=foreign.target_id,
        control_id="7.1.1", storage_reference="controller:foreign-target",
    )
    with pytest.raises(M8DataError):
        repo.record_assessment_result(
            assessment_id=assessment["assessment_id"], control_id="7.1.1",
            state="fail", reason="should_reject", observed_facts={},
            evidence_id=foreign_evidence,
        )


def test_assessment_control_states_and_report_link_use_real_m4(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    benchmark, assessment, result, _ = _assessment_for_case(repo, case)
    assert result["state"] == "needs_review"
    assert assessment["profile_id"] == str(case.profile_id)
    with open_db(case.database) as connection:
        assert connection.execute(
            "SELECT state FROM m8_assessments WHERE assessment_id = ?",
            (assessment["assessment_id"],),
        ).fetchone()[0] == "completed"
        assert connection.execute(
            "SELECT compatibility_report_id FROM m8_assessment_report_links",
        ).fetchone()[0] == str(case.report_id)
    history = repo.target_control_history(
        target_id=case.enrollment.target_id, control_id="7.1.1",
    )
    assert history["compatibility_reports"][0]["decision"] == "review_required"
    assert history["compatibility_reports"][0]["provisional"] is True
    assert history["assessment_results"][0]["benchmark_id"] == benchmark["benchmark_id"]
    with open_db(case.database) as connection:
        assert connection.execute(
            "SELECT decision FROM m8_compatibility_decisions "
            "WHERE assessment_result_id = ?",
            (result["assessment_result_id"],),
        ).fetchone()[0] == "review_required"


def test_history_preserves_existing_m4_no_known_conflict_without_safety_label(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    history = repo.target_control_history(
        target_id=case.enrollment.target_id, control_id="1.1.1.6",
    )
    assert history["compatibility_reports"][0]["decision"] == "no_known_conflict"
    assert "safe" not in json.dumps(history)


def test_history_and_evidence_reference_fail_closed_on_wrong_source_hash(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    with pytest.raises(M8DataError):
        repo.create_evidence(
            evidence_type="m3_profile", producer="target_profiler",
            related_type="profile", related_id=case.profile_id,
            storage_reference="controller:profiles", target_id=case.enrollment.target_id,
            control_id="7.1.1", sha256="0" * 64,
        )
    with open_db(case.database) as connection:
        connection.execute(
            "UPDATE compatibility_reports SET report_sha256 = ? "
            "WHERE compatibility_report_id = ?",
            ("0" * 64, str(case.report_id)),
        )
    with pytest.raises((ControllerStorageSecurityError, StorageConflictError)):
        repo.target_control_history(
            target_id=case.enrollment.target_id, control_id="7.1.1",
        )


def test_history_includes_legacy_m7_job_without_m8_request(tmp_path):
    case, delivery, _, _, _ = _terminal(tmp_path)
    repo = M8Repository(case.database)
    history = repo.target_control_history(
        target_id=case.enrollment.target_id, control_id="7.1.1",
    )
    assert history["deployments"] == []
    assert history["enforcement_jobs"][0]["enforcement_job_id"] \
        == str(delivery.enforcement_job_id)


@pytest.mark.parametrize("state", [
    "pass", "fail", "needs_review", "not_tested", "insufficient_evidence",
    "not_applicable", "error",
])
def test_assessment_result_state_enum_accepts_only_explicit_test_evidence(tmp_path, state):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    benchmark = _benchmark(repo)
    repo.create_control(
        benchmark_id=benchmark["benchmark_id"], control_id="7.1.1", title="passwd",
        required_facts=["passwd_file_mode"], adapter_capability="full",
    )
    assessment = repo.create_assessment(
        target_id=case.enrollment.target_id, profile_id=case.profile_id,
        benchmark_id=benchmark["benchmark_id"],
    )
    repo.start_assessment(assessment["assessment_id"])
    evidence = repo.create_evidence(
        evidence_type="test_case", producer="pytest", related_type="profile",
        related_id=case.profile_id, storage_reference="test:in-memory-fixture",
        target_id=case.enrollment.target_id, control_id="7.1.1",
    )
    record = repo.record_assessment_result(
        assessment_id=assessment["assessment_id"], control_id="7.1.1",
        state=state, reason="explicit_test_assertion", observed_facts={},
        evidence_id=evidence,
    )
    assert record["state"] == state
    repo.complete_assessment(assessment["assessment_id"])


def test_assessment_rejects_unselected_or_unknown_result(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    benchmark = _benchmark(repo)
    repo.create_control(
        benchmark_id=benchmark["benchmark_id"], control_id="7.1.1", title="passwd",
        required_facts=[], adapter_capability="full", selected=False,
    )
    assessment = repo.create_assessment(
        target_id=case.enrollment.target_id, profile_id=case.profile_id,
        benchmark_id=benchmark["benchmark_id"],
    )
    repo.start_assessment(assessment["assessment_id"])
    with pytest.raises(M8DataError):
        repo.record_assessment_result(
            assessment_id=assessment["assessment_id"], control_id="7.1.1",
            state="pass", reason="test", observed_facts={},
        )
    with pytest.raises(M8DataError):
        repo.record_assessment_result(
            assessment_id=assessment["assessment_id"], control_id="7.1.1",
            state="needs_review", reason="test", observed_facts={},
        )
    with pytest.raises(M8DataError):
        repo.complete_assessment(assessment["assessment_id"])


def test_full_existing_lineage_through_approval_and_verification(tmp_path):
    case, delivery, _, _, submission = _terminal(tmp_path)
    result = case.service.submit_enforcement_result(submission)
    verification = _complete_reprofile(case, result)
    repo = M8Repository(case.database)
    _, _, assessment_result, evidence_id = _assessment_for_case(repo, case)
    deployment = repo.create_deployment_request(
        assessment_result_id=assessment_result["assessment_result_id"],
        sandbox_session_id=case.session_id,
    )
    admin = repo.create_user(username="researcher", password="long local passphrase")
    repo.assign_role(user_id=admin["user_id"], role_name="admin")
    approval = repo.record_approval(
        deployment_id=deployment["deployment_id"], user_id=admin["user_id"],
        decision="approved", reason="reviewed_m6_evidence",
    )
    repo.link_enforcement_job(
        deployment_id=deployment["deployment_id"],
        enforcement_job_id=delivery.enforcement_job_id,
    )
    repo.append_audit_event(
        actor_type="user", actor_user_id=admin["user_id"],
        event_type="deployment_approved", related_type="deployment",
        related_id=deployment["deployment_id"], outcome="approved",
        reason_code="reviewed_m6_evidence", target_id=case.enrollment.target_id,
        control_id="7.1.1", evidence_id=evidence_id,
    )
    history = repo.target_control_history(
        target_id=case.enrollment.target_id, control_id="7.1.1",
    )
    assert history["profiles"] and history["assessment_results"]
    assert history["compatibility_reports"][0]["decision"] == "review_required"
    assert history["sandbox_sessions"][0]["sandbox_session_id"] == str(case.session_id)
    assert history["validation_results"][0]["result_sha256"] \
        == approval["validation_evidence_sha256"]
    assert history["deployments"][0]["enforcement_job_id"] \
        == str(delivery.enforcement_job_id)
    assert history["deployments"][0]["deployment_state"] == "verified"
    assert history["enforcement_results"][0]["result_sha256"] == result.result_sha256
    assert history["verifications"][0]["profile_id"] == str(verification.profile_id)
    assert history["audit"][0]["event_type"] == "deployment_approved"
    with open_db(case.database) as connection:
        assert connection.execute(
            "SELECT result FROM m8_validation_outcomes WHERE sandbox_session_id = ?",
            (str(case.session_id),),
        ).fetchone()[0] == "validated"
        assert connection.execute(
            "SELECT outcome FROM m8_verifications WHERE deployment_id = ?",
            (deployment["deployment_id"],),
        ).fetchone()[0] == "VERIFIED"


def test_review_required_without_valid_m6_cannot_become_deployment(tmp_path):
    case = _case(tmp_path, validated=False)
    repo = M8Repository(case.database)
    _, _, assessment_result, _ = _assessment_for_case(repo, case)
    assert repo.target_control_history(
        target_id=case.enrollment.target_id, control_id="7.1.1",
    )["compatibility_reports"][0]["decision"] == "review_required"
    with pytest.raises(M8DataError):
        repo.create_deployment_request(
            assessment_result_id=assessment_result["assessment_result_id"],
            sandbox_session_id=case.session_id,
        )
    with open_db(case.database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m8_deployment_requests",
        ).fetchone()[0] == 0


def test_approval_requires_active_admin_and_is_historical(tmp_path):
    case = _case(tmp_path)
    repo = M8Repository(case.database)
    _, _, result, _ = _assessment_for_case(repo, case)
    deployment = repo.create_deployment_request(
        assessment_result_id=result["assessment_result_id"],
        sandbox_session_id=case.session_id,
    )
    viewer = repo.create_user(username="viewer", password="long viewer password")
    repo.assign_role(user_id=viewer["user_id"], role_name="viewer")
    with pytest.raises(M8DataError):
        repo.record_approval(
            deployment_id=deployment["deployment_id"], user_id=viewer["user_id"],
            decision="approved", reason="not an admin",
        )
    admin = repo.create_user(username="admin", password="long admin password")
    repo.assign_role(user_id=admin["user_id"], role_name="admin")
    approval = repo.record_approval(
        deployment_id=deployment["deployment_id"], user_id=admin["user_id"],
        decision="rejected", reason="operator rejected",
    )
    with open_db(case.database) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE m8_approvals SET decision='approved' WHERE approval_id=?",
                (approval["approval_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM m8_approvals WHERE approval_id=?",
                (approval["approval_id"],),
            )


def test_evidence_and_audit_append_only_and_no_secret_reason(db):
    repo = M8Repository(db)
    benchmark_id = _benchmark(repo)["benchmark_id"]
    item = repo.create_evidence(
        evidence_type="benchmark_reference", producer="test", related_type="benchmark",
        related_id=benchmark_id, storage_reference="local:reference",
    )
    event = repo.append_audit_event(
        actor_type="controller", event_type="benchmark_imported",
        related_type="benchmark", related_id=benchmark_id, outcome="recorded",
        reason_code="metadata_imported", evidence_id=item,
    )
    with open_db(db) as connection:
        for table, key, identifier in (
            ("m8_evidence_records", "evidence_id", item),
            ("m8_audit_events", "event_id", event),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    f"UPDATE {table} SET {key}=? WHERE {key}=?",
                    (str(uuid4()), identifier),
                )
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(f"DELETE FROM {table} WHERE {key}=?", (identifier,))
    with pytest.raises(M8DataError):
        repo.append_audit_event(
            actor_type="controller", event_type="test", related_type="benchmark",
            related_id=benchmark_id, outcome="recorded",
            reason_code="password=hunter2",
        )
    with pytest.raises(M8DataError):
        repo.create_evidence(
            evidence_type="orphan", producer="test", related_type="profile",
            related_id=uuid4(), storage_reference="none", target_id=None,
        )


def test_cli_init_check_migrations_use_explicit_controller_path(db, capsys):
    assert main(["--database", str(db), "init"]) == 0
    assert main(["--database", str(db), "check"]) == 0
    assert main(["--database", str(db), "migrations"]) == 0
    output = capsys.readouterr().out.splitlines()
    assert json.loads(output[0])["applied_migrations"] == [1]
    assert json.loads(output[-1])["migration_versions"] == [1]


def test_database_connections_are_closed_after_context(db):
    apply_migrations(db)
    with open_db(db) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
