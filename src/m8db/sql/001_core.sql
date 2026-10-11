-- M8 extends the *same* Controller SQLite file. Existing M6/M7 tables remain
-- authoritative for targets, agents, profiles, reports, sandboxes, validation,
-- enforcement and fresh post-enforcement verification. No shadow copies.
CREATE TABLE m8_schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE,
    checksum TEXT NOT NULL CHECK (length(checksum) = 64 AND checksum NOT GLOB '*[^0-9a-f]*'),
    applied_at TEXT NOT NULL
);

CREATE TABLE m8_benchmarks (
    benchmark_id TEXT PRIMARY KEY,
    identity TEXT NOT NULL,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
    UNIQUE (identity, version, platform)
);
CREATE UNIQUE INDEX m8_one_active_benchmark_per_platform
    ON m8_benchmarks(platform COLLATE NOCASE) WHERE active = 1;

CREATE TABLE m8_controls (
    benchmark_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    profile_level TEXT NOT NULL DEFAULT '',
    assessment_type TEXT NOT NULL DEFAULT '',
    selected INTEGER NOT NULL CHECK (selected IN (0, 1)),
    review_state TEXT NOT NULL CHECK (review_state IN ('needs_review', 'reviewed')),
    required_facts_json TEXT NOT NULL CHECK (json_valid(required_facts_json)),
    adapter_capability TEXT NOT NULL,
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    PRIMARY KEY (benchmark_id, control_id),
    FOREIGN KEY (benchmark_id) REFERENCES m8_benchmarks(benchmark_id) ON DELETE RESTRICT
);

CREATE TABLE m8_users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL CHECK (password_hash LIKE 'scrypt$%' AND length(password_hash) >= 80),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login_at TEXT
);
CREATE TABLE m8_roles (
    role_name TEXT PRIMARY KEY CHECK (role_name IN ('admin', 'viewer'))
);
INSERT INTO m8_roles (role_name) VALUES ('admin'), ('viewer');
CREATE TABLE m8_user_roles (
    user_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    PRIMARY KEY (user_id, role_name),
    FOREIGN KEY (user_id) REFERENCES m8_users(user_id) ON DELETE RESTRICT,
    FOREIGN KEY (role_name) REFERENCES m8_roles(role_name) ON DELETE RESTRICT
);

CREATE TABLE m8_assessments (
    assessment_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    benchmark_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'completed', 'error')),
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    CHECK (
        (state = 'pending' AND started_at IS NULL AND completed_at IS NULL)
        OR (state = 'running' AND started_at IS NOT NULL AND completed_at IS NULL)
        OR (state IN ('completed', 'error') AND started_at IS NOT NULL AND completed_at IS NOT NULL)
    ),
    UNIQUE (assessment_id, target_id, profile_id, benchmark_id),
    UNIQUE (assessment_id, target_id, benchmark_id),
    FOREIGN KEY (target_id, profile_id) REFERENCES profiles(target_id, profile_id) ON DELETE RESTRICT,
    FOREIGN KEY (benchmark_id) REFERENCES m8_benchmarks(benchmark_id) ON DELETE RESTRICT
);
CREATE INDEX m8_assessments_target_history ON m8_assessments(target_id, created_at DESC);

CREATE TABLE m8_assessment_results (
    assessment_result_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    benchmark_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'pass', 'fail', 'needs_review', 'not_tested',
        'insufficient_evidence', 'not_applicable', 'error'
    )),
    reason TEXT NOT NULL,
    observed_facts_json TEXT NOT NULL CHECK (json_valid(observed_facts_json)),
    evidence_id TEXT,
    observed_at TEXT NOT NULL,
    CHECK (state NOT IN ('pass', 'fail') OR evidence_id IS NOT NULL),
    UNIQUE (assessment_id, control_id),
    UNIQUE (assessment_result_id, target_id, control_id),
    FOREIGN KEY (assessment_id, target_id, benchmark_id)
        REFERENCES m8_assessments(assessment_id, target_id, benchmark_id) ON DELETE RESTRICT,
    FOREIGN KEY (benchmark_id, control_id)
        REFERENCES m8_controls(benchmark_id, control_id) ON DELETE RESTRICT,
    FOREIGN KEY (evidence_id, target_id, control_id)
        REFERENCES m8_evidence_records(evidence_id, target_id, control_id) ON DELETE RESTRICT
);
CREATE INDEX m8_results_target_control ON m8_assessment_results(target_id, control_id, observed_at DESC);

-- A link, not a duplicate M4 report. Individual decisions stay in the
-- canonical compatibility_reports.payload_json written by M4/M6C.
CREATE TABLE m8_assessment_report_links (
    assessment_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    benchmark_id TEXT NOT NULL,
    compatibility_report_id TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    FOREIGN KEY (assessment_id, target_id, profile_id, benchmark_id)
        REFERENCES m8_assessments(assessment_id, target_id, profile_id, benchmark_id) ON DELETE RESTRICT,
    FOREIGN KEY (target_id, profile_id, compatibility_report_id)
        REFERENCES compatibility_reports(target_id, profile_id, compatibility_report_id) ON DELETE RESTRICT
);

-- A pre-enforcement administrative request, never an alternate M7 executor.
-- Operational execution and outcome remain enforcement_jobs/results.
CREATE TABLE m8_deployment_requests (
    deployment_id TEXT PRIMARY KEY,
    assessment_result_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    sandbox_session_id TEXT NOT NULL,
    enforcement_job_id TEXT UNIQUE,
    state TEXT NOT NULL CHECK (state IN (
        'awaiting_approval', 'approved', 'rejected', 'precondition_failed'
    )),
    requested_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    UNIQUE (deployment_id, target_id, control_id),
    FOREIGN KEY (assessment_result_id, target_id, control_id)
        REFERENCES m8_assessment_results(assessment_result_id, target_id, control_id) ON DELETE RESTRICT,
    FOREIGN KEY (sandbox_session_id) REFERENCES sandbox_validation_executions(sandbox_session_id) ON DELETE RESTRICT,
    FOREIGN KEY (enforcement_job_id) REFERENCES enforcement_jobs(enforcement_job_id) ON DELETE RESTRICT
);
CREATE INDEX m8_deployment_target_history ON m8_deployment_requests(target_id, control_id, requested_at DESC);

-- Read-only projections; no second compatibility/validation/deployment authority.
CREATE VIEW m8_compatibility_decisions AS
    SELECT ar.assessment_result_id, ar.target_id, ar.control_id,
           l.compatibility_report_id, r.report_sha256, r.generated_at,
           json_extract(c.value, '$.result') AS decision,
           json_extract(c.value, '$.explanation') AS reason,
           json_extract(c.value, '$.provisional') AS provisional,
           json_extract(c.value, '$.metadata_review_status') AS metadata_review_status
    FROM m8_assessment_results AS ar
    JOIN m8_assessment_report_links AS l ON l.assessment_id = ar.assessment_id
    JOIN compatibility_reports AS r
      ON r.compatibility_report_id = l.compatibility_report_id
    JOIN json_each(r.payload_json, '$.control_results') AS c
    WHERE json_extract(c.value, '$.control_id') = ar.control_id;

CREATE VIEW m8_validation_outcomes AS
    SELECT x.sandbox_session_id, x.validation_job_id, x.source_target_id AS target_id,
           s.control_id, x.status, x.result_sha256, x.completed_at,
           json_extract(x.payload_json, '$.report.control_results[0].result') AS result
    FROM sandbox_validation_executions AS x
    JOIN sandbox_sessions AS s ON s.sandbox_session_id = x.sandbox_session_id;

CREATE VIEW m8_deployments AS
    SELECT d.deployment_id, d.target_id, d.control_id, d.assessment_result_id,
           d.sandbox_session_id, d.enforcement_job_id, d.requested_at,
           d.updated_at,
           CASE
             WHEN d.enforcement_job_id IS NULL THEN d.state
             WHEN j.status = 'pending' THEN 'approved'
             WHEN j.status = 'dispatched' THEN 'running'
             WHEN e.outcome = 'SUCCEEDED' AND v.outcome = 'VERIFIED' THEN 'verified'
             WHEN e.outcome = 'SUCCEEDED' AND v.outcome = 'DRIFT_DETECTED' THEN 'verification_failed'
             WHEN e.outcome = 'SUCCEEDED' THEN 'applied'
             WHEN e.outcome = 'BLOCKED_DRIFT' THEN 'precondition_failed'
             WHEN e.outcome = 'ROLLED_BACK' THEN 'rolled_back'
             WHEN e.outcome = 'ROLLBACK_FAILED' THEN 'recovery_required'
             WHEN e.outcome = 'FAILED' THEN 'failed'
             ELSE d.state
           END AS deployment_state
    FROM m8_deployment_requests AS d
    LEFT JOIN enforcement_jobs AS j ON j.enforcement_job_id = d.enforcement_job_id
    LEFT JOIN enforcement_results AS e ON e.enforcement_job_id = j.enforcement_job_id
    LEFT JOIN post_enforcement_verifications AS v
      ON v.enforcement_result_id = e.enforcement_result_id;

CREATE VIEW m8_verifications AS
    SELECT d.deployment_id, d.target_id, d.control_id,
           v.enforcement_result_id, v.profile_id, v.profile_sha256,
           v.outcome, v.verified_at
    FROM m8_deployment_requests AS d
    JOIN enforcement_results AS e ON e.enforcement_job_id = d.enforcement_job_id
    JOIN post_enforcement_verifications AS v
      ON v.enforcement_result_id = e.enforcement_result_id;

CREATE TABLE m8_approvals (
    approval_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reason TEXT NOT NULL,
    validation_evidence_sha256 TEXT NOT NULL CHECK (
        length(validation_evidence_sha256) = 64
        AND validation_evidence_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    decided_at TEXT NOT NULL,
    FOREIGN KEY (deployment_id, target_id, control_id)
        REFERENCES m8_deployment_requests(deployment_id, target_id, control_id) ON DELETE RESTRICT,
    FOREIGN KEY (user_id) REFERENCES m8_users(user_id) ON DELETE RESTRICT
);
CREATE INDEX m8_approvals_history ON m8_approvals(deployment_id, decided_at DESC);

CREATE TABLE m8_evidence_records (
    evidence_id TEXT PRIMARY KEY,
    evidence_type TEXT NOT NULL,
    producer TEXT NOT NULL,
    target_id TEXT,
    control_id TEXT,
    related_type TEXT NOT NULL,
    related_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    storage_reference TEXT NOT NULL,
    sha256 TEXT CHECK (sha256 IS NULL OR (
        length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'
    )),
    FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE RESTRICT,
    UNIQUE (evidence_id, target_id, control_id)
);
CREATE INDEX m8_evidence_history ON m8_evidence_records(target_id, control_id, created_at DESC);
CREATE INDEX m8_evidence_source ON m8_evidence_records(producer, related_type, related_id);

CREATE TABLE m8_audit_events (
    event_id TEXT PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'agent', 'controller', 'system')),
    actor_user_id TEXT,
    event_type TEXT NOT NULL,
    target_id TEXT,
    control_id TEXT,
    related_type TEXT NOT NULL,
    related_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    evidence_id TEXT,
    FOREIGN KEY (actor_user_id) REFERENCES m8_users(user_id) ON DELETE RESTRICT,
    FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE RESTRICT,
    FOREIGN KEY (evidence_id) REFERENCES m8_evidence_records(evidence_id) ON DELETE RESTRICT,
    CHECK ((actor_type = 'user') = (actor_user_id IS NOT NULL))
);
CREATE INDEX m8_audit_history ON m8_audit_events(target_id, control_id, occurred_at DESC);

CREATE TRIGGER m8_evidence_no_update BEFORE UPDATE ON m8_evidence_records
    BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER m8_evidence_no_delete BEFORE DELETE ON m8_evidence_records
    BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER m8_audit_no_update BEFORE UPDATE ON m8_audit_events
    BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER m8_audit_no_delete BEFORE DELETE ON m8_audit_events
    BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER m8_approval_no_update BEFORE UPDATE ON m8_approvals
    BEGIN SELECT RAISE(ABORT, 'approvals are append-only'); END;
CREATE TRIGGER m8_approval_no_delete BEFORE DELETE ON m8_approvals
    BEGIN SELECT RAISE(ABORT, 'approvals are append-only'); END;
CREATE TRIGGER m8_assessment_result_no_update BEFORE UPDATE ON m8_assessment_results
    BEGIN SELECT RAISE(ABORT, 'assessment results are historical'); END;
CREATE TRIGGER m8_assessment_result_no_delete BEFORE DELETE ON m8_assessment_results
    BEGIN SELECT RAISE(ABORT, 'assessment results are historical'); END;
CREATE TRIGGER m8_report_link_no_update BEFORE UPDATE ON m8_assessment_report_links
    BEGIN SELECT RAISE(ABORT, 'M4 report links are historical'); END;
CREATE TRIGGER m8_report_link_no_delete BEFORE DELETE ON m8_assessment_report_links
    BEGIN SELECT RAISE(ABORT, 'M4 report links are historical'); END;
