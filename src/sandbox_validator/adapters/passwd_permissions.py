"""Fixed-path adapter for control 7.1.1 (/etc/passwd metadata)."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from src.poc_models import Category

from ..audit import audit_passwd, evidence_by_name
from ..command_runner import MutationAuthorization
from ..health import check_passwd_health, check_passwd_readability_mode
from ..models import (
    ActionStatus,
    AuditEvidence,
    BackupInformation,
    EvidenceStatus,
    HealthCheck,
    HealthStatus,
    RemediationAction,
    RemediationResult,
    RollbackResult,
    ValidationDecision,
)
from .base import AdapterContext, AdapterOutcome, ControlAdapter, FileSnapshot


@dataclass(slots=True)
class _PasswdExecutionState:
    actions: list[RemediationAction] = field(default_factory=list)
    backups: list[BackupInformation] = field(default_factory=list)
    original: FileSnapshot | None = None
    target_mutation_started: bool = False
    post_audit: list[AuditEvidence] = field(default_factory=list)
    health_checks: list[HealthCheck] = field(default_factory=list)


class PasswdPermissionsAdapter(ControlAdapter):
    control_id = "7.1.1"
    title = "Ensure permissions on /etc/passwd are configured"
    category = Category.FILE_PERMISSIONS
    mutation_supported = True
    target = "/etc/passwd"

    def pre_audit(self, context: AdapterContext):
        return audit_passwd(context)

    def plan(self, pre_audit):
        return [
            RemediationAction(
                action_id="backup-passwd",
                description="Create a private local backup before changing metadata.",
                mutating=True,
                target=self.target,
                planned_effect="Preserve the current file content and metadata locally.",
                status=ActionStatus.PLANNED,
            ),
            RemediationAction(
                action_id="apply-passwd-metadata",
                description="Set root ownership and remove permissions outside 0644.",
                mutating=True,
                target=self.target,
                planned_effect=(
                    "Set UID/GID to 0 and mode to the current mode masked by 0644."
                ),
                status=ActionStatus.PLANNED,
            ),
            RemediationAction(
                action_id="verify-passwd-state",
                description="Re-audit metadata and run narrow account database checks.",
                mutating=False,
                target=self.target,
                planned_effect="Confirm expected state without recording account contents.",
                status=ActionStatus.PLANNED,
            ),
        ]

    @staticmethod
    def _metadata_matches(audit, *, mode: int, uid: int, gid: int) -> bool:
        by_name = evidence_by_name(audit)
        try:
            return (
                by_name["passwd_file_mode"].status is EvidenceStatus.COLLECTED
                and int(str(by_name["passwd_file_mode"].value), 8) == mode
                and by_name["passwd_file_owner_uid"].status
                is EvidenceStatus.COLLECTED
                and by_name["passwd_file_owner_uid"].value == uid
                and by_name["passwd_file_group_gid"].status
                is EvidenceStatus.COLLECTED
                and by_name["passwd_file_group_gid"].value == gid
            )
        except (KeyError, TypeError, ValueError):
            return False

    def _rollback(
        self,
        context: AdapterContext,
        original: FileSnapshot,
    ) -> RollbackResult:
        path = context.resolve(self.target)
        action = RemediationAction(
            action_id="restore-passwd-metadata",
            description="Restore the captured original owner, group, and mode.",
            mutating=True,
            target=self.target,
            planned_effect="Restore only the original /etc/passwd metadata.",
            status=ActionStatus.PLANNED,
        )
        try:
            current = context.files.snapshot(path)
            context.files.set_metadata(
                path,
                current,
                uid=original.uid,
                gid=original.gid,
                mode=original.mode,
            )
            restored = self._metadata_matches(
                audit_passwd(context),
                mode=original.mode,
                uid=original.uid,
                gid=original.gid,
            )
            completed = action.model_copy(
                update={
                    "status": ActionStatus.APPLIED if restored else ActionStatus.FAILED,
                    "error": None if restored else "restored metadata did not verify",
                }
            )
            return RollbackResult(
                supported=True,
                attempted=True,
                succeeded=restored,
                actions=[completed],
                explanation=(
                    "Original /etc/passwd metadata was restored and verified."
                    if restored
                    else "Rollback ran but original /etc/passwd metadata did not verify."
                ),
            )
        except (OSError, ValueError) as exc:
            failed = action.model_copy(
                update={"status": ActionStatus.FAILED, "error": type(exc).__name__}
            )
            return RollbackResult(
                supported=True,
                attempted=True,
                succeeded=False,
                actions=[failed],
                explanation="Rollback could not restore the captured metadata.",
            )

    @staticmethod
    def _exception_label(exc: Exception) -> str:
        message = " ".join(str(exc).split())
        return f"{type(exc).__name__}: {message}" if message else type(exc).__name__

    def _safe_rollback(
        self,
        context: AdapterContext,
        original: FileSnapshot,
    ) -> tuple[RollbackResult, str | None]:
        try:
            rollback = self._rollback(context, original)
        except Exception as exc:  # containment boundary for emergency rollback
            error = self._exception_label(exc)
            return (
                RollbackResult(
                    supported=True,
                    attempted=True,
                    succeeded=False,
                    actions=[
                        RemediationAction(
                            action_id="passwd-emergency-rollback-failure",
                            description="Record that emergency metadata rollback failed.",
                            mutating=False,
                            target=self.target,
                            planned_effect="Retain the rollback failure for manual recovery.",
                            status=ActionStatus.FAILED,
                            error=error,
                        )
                    ],
                    explanation="Emergency rollback raised an unexpected contained error.",
                ),
                error,
            )
        error = next(
            (action.error for action in rollback.actions if action.error is not None),
            None,
        )
        return rollback, error

    @staticmethod
    def _record_unexpected_action(
        actions: list[RemediationAction], error: str
    ) -> list[RemediationAction]:
        recorded = list(actions)
        for index, action in enumerate(recorded):
            if action.status is ActionStatus.PLANNED:
                recorded[index] = action.model_copy(
                    update={"status": ActionStatus.FAILED, "error": error}
                )
                for remaining in range(index + 1, len(recorded)):
                    if recorded[remaining].status is ActionStatus.PLANNED:
                        recorded[remaining] = recorded[remaining].model_copy(
                            update={"status": ActionStatus.SKIPPED}
                        )
                return recorded
        recorded.append(
            RemediationAction(
                action_id="record-unexpected-passwd-failure",
                description="Record an unexpected failure after metadata mutation began.",
                mutating=False,
                target=PasswdPermissionsAdapter.target,
                planned_effect="Preserve the original execution error for review.",
                status=ActionStatus.FAILED,
                error=error,
            )
        )
        return recorded

    def _unexpected_failure(
        self,
        context: AdapterContext,
        state: _PasswdExecutionState,
        exc: Exception,
    ) -> AdapterOutcome:
        error = self._exception_label(exc)
        if not state.target_mutation_started or state.original is None:
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=False,
                    changed=False,
                    succeeded=None,
                    actions=state.actions,
                    backups=state.backups,
                    reason="Execution stopped after an unexpected failure before target mutation.",
                ),
                post_audit=state.post_audit,
                health_checks=state.health_checks,
                rollback=RollbackResult(
                    supported=True,
                    attempted=False,
                    succeeded=None,
                    actions=[],
                    explanation="Rollback was not required because target mutation did not start.",
                ),
                decision=ValidationDecision.NOT_TESTED,
                explanation="The passwd experiment stopped safely before target mutation.",
                warnings=[],
                errors=[error],
            )

        actions = self._record_unexpected_action(state.actions, error)
        rollback, rollback_error = self._safe_rollback(context, state.original)
        errors = [error]
        if rollback.succeeded is not True:
            errors.append(
                f"rollback_error: {rollback_error or 'passwd rollback did not succeed'}"
            )
        return AdapterOutcome(
            remediation=RemediationResult(
                supported=True,
                attempted=True,
                changed=True,
                succeeded=False,
                actions=actions,
                backups=state.backups,
                reason="An unexpected failure occurred after target mutation began.",
            ),
            post_audit=state.post_audit,
            health_checks=state.health_checks,
            rollback=rollback,
            decision=ValidationDecision.FAILED,
            explanation="The passwd experiment failed unexpectedly and rollback was attempted.",
            warnings=[],
            errors=errors,
        )

    def execute(self, context, pre_audit, authorization):
        state = _PasswdExecutionState()
        try:
            state.actions = self.plan(pre_audit)
            return self._execute(context, pre_audit, authorization, state)
        except Exception as exc:  # fail closed while retaining mutation state
            return self._unexpected_failure(context, state, exc)

    def _execute(self, context, pre_audit, authorization, state):
        if authorization.control_id != self.control_id:
            raise ValueError("mutation authorization does not match control 7.1.1")
        path = context.resolve(self.target)
        actions = state.actions
        backups = state.backups
        no_rollback = RollbackResult(
            supported=True,
            attempted=False,
            succeeded=None,
            actions=[],
            explanation="Rollback was not required.",
        )

        try:
            original = context.files.snapshot(path)
            state.original = original
        except (OSError, ValueError) as exc:
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=False,
                    changed=False,
                    succeeded=None,
                    actions=actions,
                    backups=[],
                    reason="Fresh target metadata could not be captured safely.",
                ),
                post_audit=[],
                health_checks=[],
                rollback=no_rollback,
                decision=ValidationDecision.NOT_TESTED,
                explanation="The candidate was not applied because fresh metadata was unavailable.",
                warnings=[],
                errors=[type(exc).__name__],
            )

        if not self._metadata_matches(
            pre_audit, mode=original.mode, uid=original.uid, gid=original.gid
        ):
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=False,
                    changed=False,
                    succeeded=None,
                    actions=actions,
                    backups=[],
                    reason="The target changed between pre-audit and execution.",
                ),
                post_audit=[],
                health_checks=[],
                rollback=no_rollback,
                decision=ValidationDecision.NOT_TESTED,
                explanation="Execution stopped because the pre-audit was no longer current.",
                warnings=[],
                errors=["pre_audit_state_changed"],
            )

        desired_mode = original.mode & 0o644
        change_needed = not (
            original.mode == desired_mode and original.uid == 0 and original.gid == 0
        )
        if not change_needed:
            completed_actions = [
                item.model_copy(update={"status": ActionStatus.SKIPPED})
                if item.mutating
                else item.model_copy(update={"status": ActionStatus.APPLIED})
                for item in actions
            ]
            post = audit_passwd(context)
            state.post_audit = post
            health = [
                *check_passwd_health(context),
                check_passwd_readability_mode(post),
            ]
            state.health_checks = health
            required_failed = any(
                item.required and item.status is not HealthStatus.PASSED
                for item in health
            )
            optional_concern = any(
                not item.required
                and item.status in {HealthStatus.WARNING, HealthStatus.UNAVAILABLE}
                for item in health
            )
            decision = (
                ValidationDecision.FAILED
                if required_failed
                else ValidationDecision.WARNING
                if optional_concern
                else ValidationDecision.VALIDATED
            )
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=True,
                    changed=False,
                    succeeded=not required_failed,
                    actions=completed_actions,
                    backups=[],
                    reason="The fixed target already matched the required metadata state.",
                ),
                post_audit=post,
                health_checks=health,
                rollback=no_rollback,
                decision=decision,
                explanation="The already-matching state was audited and health checked.",
                warnings=(
                    ["ordinary-user readability remains uncertain"]
                    if optional_concern
                    else []
                ),
                errors=["required health check failed"] if required_failed else [],
            )

        backup_directory = context.backup_directory(self.control_id)
        backup_path = backup_directory / (
            f"passwd-{context.clock().strftime('%Y%m%dT%H%M%S%fZ')}-"
            f"{secrets.token_hex(4)}.bak"
        )
        try:
            context.files.make_private_directory(backup_directory)
            context.files.backup_file(path, backup_path, original)
            backups.append(
                BackupInformation(
                    target=self.target,
                    original_existed=True,
                    created=True,
                    path="/" + backup_path.relative_to(context.root).as_posix(),
                    metadata_preserved=True,
                )
            )
            actions[0] = actions[0].model_copy(update={"status": ActionStatus.APPLIED})
        except (OSError, ValueError) as exc:
            actions[0] = actions[0].model_copy(
                update={"status": ActionStatus.FAILED, "error": type(exc).__name__}
            )
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=False,
                    changed=False,
                    succeeded=None,
                    actions=actions,
                    backups=backups,
                    reason="A private backup could not be created; no target change ran.",
                ),
                post_audit=[],
                health_checks=[],
                rollback=no_rollback,
                decision=ValidationDecision.NOT_TESTED,
                explanation="Execution was refused before mutation because backup failed.",
                warnings=[],
                errors=[type(exc).__name__],
            )

        mutation_error: str | None = None
        try:
            state.target_mutation_started = True
            context.files.set_metadata(
                path, original, uid=0, gid=0, mode=desired_mode
            )
            actions[1] = actions[1].model_copy(update={"status": ActionStatus.APPLIED})
        except (OSError, ValueError) as exc:
            mutation_error = type(exc).__name__
            actions[1] = actions[1].model_copy(
                update={"status": ActionStatus.FAILED, "error": mutation_error}
            )

        post = audit_passwd(context)
        state.post_audit = post
        actions[2] = actions[2].model_copy(update={"status": ActionStatus.APPLIED})
        expected = self._metadata_matches(post, mode=desired_mode, uid=0, gid=0)
        health = [*check_passwd_health(context), check_passwd_readability_mode(post)]
        state.health_checks = health
        required_failed = any(
            item.required and item.status is not HealthStatus.PASSED for item in health
        )
        if mutation_error or not expected or required_failed:
            rollback, rollback_error = self._safe_rollback(context, original)
            errors = [item for item in [mutation_error] if item]
            if not expected:
                errors.append("required post-state was not observed")
            if required_failed:
                errors.append("required health check failed")
            if rollback.succeeded is False:
                errors.append(
                    f"rollback_error: {rollback_error or 'passwd rollback did not succeed'}"
                )
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=True,
                    changed=True,
                    succeeded=False,
                    actions=actions,
                    backups=backups,
                    reason="The candidate change or a required verification failed.",
                ),
                post_audit=post,
                health_checks=health,
                rollback=rollback,
                decision=ValidationDecision.FAILED,
                explanation="The experiment failed and adapter-specific rollback was attempted.",
                warnings=[],
                errors=errors,
            )

        optional_concern = any(
            not item.required
            and item.status in {HealthStatus.WARNING, HealthStatus.UNAVAILABLE}
            for item in health
        )
        return AdapterOutcome(
            remediation=RemediationResult(
                supported=True,
                attempted=True,
                changed=True,
                succeeded=True,
                actions=actions,
                backups=backups,
                reason="The fixed metadata change and required checks completed.",
            ),
            post_audit=post,
            health_checks=health,
            rollback=no_rollback,
            decision=(
                ValidationDecision.WARNING
                if optional_concern
                else ValidationDecision.VALIDATED
            ),
            explanation=(
                "The expected state was observed with a non-fatal readability concern."
                if optional_concern
                else "The expected state and all required health checks were observed."
            ),
            warnings=(
                ["ordinary-user readability remains uncertain"]
                if optional_concern
                else []
            ),
            errors=[],
        )
