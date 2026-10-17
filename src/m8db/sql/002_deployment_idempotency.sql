-- Preserve historical duplicate rows, but reject any new duplicate lineage.
CREATE INDEX m8_deployment_exact_lineage
    ON m8_deployment_requests(
        assessment_result_id, target_id, control_id, sandbox_session_id
    );

CREATE TRIGGER m8_deployment_no_duplicate_lineage
BEFORE INSERT ON m8_deployment_requests
WHEN EXISTS (
    SELECT 1 FROM m8_deployment_requests AS existing
    WHERE existing.assessment_result_id = NEW.assessment_result_id
      AND existing.target_id = NEW.target_id
      AND existing.control_id = NEW.control_id
      AND existing.sandbox_session_id = NEW.sandbox_session_id
)
BEGIN
    SELECT RAISE(ABORT, 'deployment lineage already requested');
END;

-- Approval history stays append-only; an old duplicate is not rewritten.
CREATE TRIGGER m8_approval_no_second_decision
BEFORE INSERT ON m8_approvals
WHEN EXISTS (
    SELECT 1 FROM m8_approvals AS existing
    WHERE existing.deployment_id = NEW.deployment_id
)
BEGIN
    SELECT RAISE(ABORT, 'deployment decision already recorded');
END;
