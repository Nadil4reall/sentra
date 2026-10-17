-- An explicit pre-profile boundary is necessary because m8_assessments requires
-- an existing Controller profile and is populated only after M4 analysis.
-- This row has no independent workflow status: Controller evidence determines it.
-- Its run_id becomes m8_assessments.assessment_id once M4 is linked.
CREATE TABLE m8_run_starts (
    run_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    benchmark_id TEXT NOT NULL,
    selected_controls_json TEXT NOT NULL CHECK (
        json_valid(selected_controls_json) AND json_type(selected_controls_json) = 'array'
    ),
    created_by_user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    profile_job_id TEXT UNIQUE,
    profile_job_linked_at TEXT,
    CHECK ((profile_job_id IS NULL AND profile_job_linked_at IS NULL)
        OR (profile_job_id IS NOT NULL AND profile_job_linked_at IS NOT NULL)),
    FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE RESTRICT,
    FOREIGN KEY (benchmark_id) REFERENCES m8_benchmarks(benchmark_id) ON DELETE RESTRICT,
    FOREIGN KEY (created_by_user_id) REFERENCES m8_users(user_id) ON DELETE RESTRICT,
    FOREIGN KEY (target_id, profile_job_id) REFERENCES jobs(target_id, job_id) ON DELETE RESTRICT
);
CREATE INDEX m8_run_starts_target_history
    ON m8_run_starts(target_id, created_at DESC);

CREATE TRIGGER m8_run_start_no_delete BEFORE DELETE ON m8_run_starts
BEGIN SELECT RAISE(ABORT, 'hardening run history is immutable'); END;
CREATE TRIGGER m8_run_start_no_rebind BEFORE UPDATE ON m8_run_starts
WHEN NEW.run_id != OLD.run_id OR NEW.target_id != OLD.target_id
  OR NEW.benchmark_id != OLD.benchmark_id
  OR NEW.selected_controls_json != OLD.selected_controls_json
  OR NEW.created_by_user_id != OLD.created_by_user_id
  OR NEW.created_at != OLD.created_at
  OR OLD.profile_job_id IS NOT NULL
  OR NEW.profile_job_id IS NULL
BEGIN SELECT RAISE(ABORT, 'hardening run lineage cannot be rebound'); END;
