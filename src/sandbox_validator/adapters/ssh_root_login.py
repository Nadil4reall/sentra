"""Conservative dedicated-drop-in adapter for SSH PermitRootLogin."""

from __future__ import annotations

import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path

from src.poc_models import Category

from ..audit import audit_ssh, evidence_by_name
from ..command_runner import (
    CommandNotAllowedError,
    MutationAction,
    MutationAuthorization,
)
from ..health import check_ssh_health
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


_OWNERSHIP_MARKER = "# Managed by SENTRA Milestone 5 (control 5.1.20)."
_DROPIN_CONTENT = f"{_OWNERSHIP_MARKER}\nPermitRootLogin no\n"


@dataclass(slots=True)
class _SshExecutionState:
    actions: list[RemediationAction] = field(default_factory=list)
    backups: list[BackupInformation] = field(default_factory=list)
    original: FileSnapshot | None = None
    backup_path: Path | None = None
    target_mutation_started: bool = False
    runtime_reload_attempted: bool = False
    post_audit: list[AuditEvidence] = field(default_factory=list)
    health_checks: list[HealthCheck] = field(default_factory=list)


class SshRootLoginAdapter(ControlAdapter):
    control_id = "5.1.20"
    title = "Ensure sshd PermitRootLogin is disabled"
    category = Category.SSH
    mutation_supported = True
    target = "/etc/ssh/sshd_config.d/00-sentra-5-1-20.conf"

    def pre_audit(self, context: AdapterContext):
        return audit_ssh(context)

    def plan(self, pre_audit):
        return [
            RemediationAction(
                action_id="backup-sentra-ssh-dropin",
                description="Back up an existing SENTRA-owned SSH drop-in.",
                mutating=True,
                target=self.target,
                planned_effect="Preserve the existing SENTRA-owned file before replacement.",
                status=ActionStatus.PLANNED,
            ),
            RemediationAction(
                action_id="write-sentra-ssh-dropin",
                description="Atomically write the fixed PermitRootLogin drop-in.",
                mutating=True,
                target=self.target,
                planned_effect="Set the global candidate value to PermitRootLogin no.",
                status=ActionStatus.PLANNED,
            ),
            RemediationAction(
                action_id="validate-sshd-syntax",
                description="Run the fixed sshd syntax validation action.",
                mutating=False,
                target=self.target,
                planned_effect="Prevent reload when the candidate syntax is invalid.",
                status=ActionStatus.PLANNED,
            ),
            RemediationAction(
                action_id="verify-sshd-effective-value",
                description="Read the effective PermitRootLogin value with sshd -T.",
                mutating=False,
                target=self.target,
                planned_effect="Require an effective value of no before reload.",
                status=ActionStatus.PLANNED,
            ),
            RemediationAction(
                action_id="reload-ssh-service",
                description="Reload, never restart, the fixed ssh.service unit.",
                mutating=True,
                target="ssh.service",
                planned_effect="Ask the active service to load the validated configuration.",
                status=ActionStatus.PLANNED,
            ),
            RemediationAction(
                action_id="post-audit-ssh",
                description="Repeat effective, syntax, service, and context checks.",
                mutating=False,
                target=self.target,
                planned_effect="Collect post-change evidence without claiming access continuity.",
                status=ActionStatus.PLANNED,
            ),
        ]

    @staticmethod
    def _collected_value(evidence, name):
        item = evidence_by_name(evidence).get(name)
        if item is None or item.status is not EvidenceStatus.COLLECTED:
            return None
        return item.value

    def _precondition_failures(self, evidence) -> list[str]:
        expected = {
            "ssh_installed": True,
            "ssh_service_status": "active",
            "ssh_service_reload_supported": True,
            "sshd_config_syntax_valid": True,
            "sshd_match_directives_present": False,
            "sshd_include_precedence_supported": True,
            "remote_session_context": True,
        }
        failures: list[str] = []
        for name, required in expected.items():
            value = self._collected_value(evidence, name)
            if isinstance(required, str):
                matches = isinstance(value, str) and value.casefold() == required
            else:
                matches = value is required
            if not matches:
                failures.append(f"{name} did not establish the required safe condition")
        return failures

    @staticmethod
    def _syntax_and_effective(evidence) -> tuple[bool, bool]:
        by_name = evidence_by_name(evidence)
        syntax = by_name.get("sshd_config_syntax_valid")
        effective = by_name.get("sshd_permit_root_login_effective")
        syntax_ok = (
            syntax is not None
            and syntax.status is EvidenceStatus.COLLECTED
            and syntax.value is True
        )
        effective_ok = (
            effective is not None
            and effective.status is EvidenceStatus.COLLECTED
            and str(effective.value).casefold() == "no"
        )
        return syntax_ok, effective_ok

    def _rollback_dropin(
        self,
        context: AdapterContext,
        *,
        original: FileSnapshot | None,
        backup_path,
        runtime_reload_attempted: bool,
        authorization: MutationAuthorization,
    ) -> RollbackResult:
        target = context.resolve(self.target)
        actions: list[RemediationAction] = []
        try:
            if original is None:
                context.files.remove_file(target)
                actions.append(
                    RemediationAction(
                        action_id="remove-candidate-ssh-dropin",
                        description="Remove the newly created SENTRA drop-in.",
                        mutating=True,
                        target=self.target,
                        planned_effect="Restore the prior absence of the candidate file.",
                        status=ActionStatus.APPLIED,
                    )
                )
            else:
                if backup_path is None:
                    raise OSError("existing drop-in backup is unavailable")
                previous = context.files.read_text(backup_path, max_bytes=1024 * 1024)
                context.files.atomic_write_text(
                    target,
                    previous,
                    uid=original.uid,
                    gid=original.gid,
                    mode=original.mode,
                )
                actions.append(
                    RemediationAction(
                        action_id="restore-sentra-ssh-dropin",
                        description="Restore the backed-up SENTRA-owned drop-in.",
                        mutating=True,
                        target=self.target,
                        planned_effect="Restore the complete prior dedicated file.",
                        status=ActionStatus.APPLIED,
                    )
                )

            restored_audit = audit_ssh(context)
            restored_syntax = self._collected_value(
                restored_audit, "sshd_config_syntax_valid"
            )
            if restored_syntax is not True:
                raise OSError("restored SSH configuration did not pass syntax validation")

            if runtime_reload_attempted:
                restored_failures = self._precondition_failures(restored_audit)
                if restored_failures:
                    raise OSError(
                        "restored SSH reload preconditions were not re-established"
                    )
                reload_result = context.runner.run_mutation(
                    MutationAction.SSH_SERVICE_RELOAD, authorization
                )
                actions.append(
                    RemediationAction(
                        action_id="reload-restored-ssh-service",
                        description="Reload the syntax-validated restored SSH configuration.",
                        mutating=True,
                        target="ssh.service",
                        planned_effect="Restore the previously configured runtime state.",
                        status=(
                            ActionStatus.APPLIED
                            if reload_result.succeeded
                            else ActionStatus.FAILED
                        ),
                        error=(
                            None
                            if reload_result.succeeded
                            else reload_result.reason or "reload_failed"
                        ),
                    )
                )
                if not reload_result.succeeded:
                    raise OSError("restored SSH configuration could not be reloaded")

            return RollbackResult(
                supported=True,
                attempted=True,
                succeeded=True,
                actions=actions,
                explanation="The dedicated SSH candidate was restored or removed safely.",
            )
        except (OSError, ValueError, CommandNotAllowedError) as exc:
            actions.append(
                RemediationAction(
                    action_id="ssh-rollback-failure",
                    description="Record that SSH rollback did not complete.",
                    mutating=False,
                    target=self.target,
                    planned_effect="Retain the rollback failure for operator review.",
                    status=ActionStatus.FAILED,
                    error=type(exc).__name__,
                )
            )
            return RollbackResult(
                supported=True,
                attempted=True,
                succeeded=False,
                actions=actions,
                explanation="The dedicated SSH candidate could not be fully rolled back.",
            )

    def _not_tested(self, actions, reason, errors=None):
        return AdapterOutcome(
            remediation=RemediationResult(
                supported=True,
                attempted=False,
                changed=False,
                succeeded=None,
                actions=actions,
                backups=[],
                reason=reason,
            ),
            post_audit=[],
            health_checks=[],
            rollback=RollbackResult(
                supported=True,
                attempted=False,
                succeeded=None,
                actions=[],
                explanation="Rollback was not required because mutation did not start.",
            ),
            decision=ValidationDecision.NOT_TESTED,
            explanation=reason,
            warnings=[],
            errors=errors or [],
        )

    @staticmethod
    def _exception_label(exc: Exception) -> str:
        message = " ".join(str(exc).split())
        return f"{type(exc).__name__}: {message}" if message else type(exc).__name__

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
                action_id="record-unexpected-ssh-failure",
                description="Record an unexpected failure after SSH mutation began.",
                mutating=False,
                target=SshRootLoginAdapter.target,
                planned_effect="Preserve the original execution error for review.",
                status=ActionStatus.FAILED,
                error=error,
            )
        )
        return recorded

    def _safe_rollback_dropin(
        self,
        context: AdapterContext,
        *,
        state: _SshExecutionState,
        authorization: MutationAuthorization,
    ) -> tuple[RollbackResult, str | None]:
        try:
            rollback = self._rollback_dropin(
                context,
                original=state.original,
                backup_path=state.backup_path,
                runtime_reload_attempted=state.runtime_reload_attempted,
                authorization=authorization,
            )
        except Exception as exc:  # containment boundary for emergency rollback
            error = self._exception_label(exc)
            return (
                RollbackResult(
                    supported=True,
                    attempted=True,
                    succeeded=False,
                    actions=[
                        RemediationAction(
                            action_id="ssh-emergency-rollback-failure",
                            description="Record that emergency SSH rollback failed.",
                            mutating=False,
                            target=self.target,
                            planned_effect="Retain the rollback failure for manual recovery.",
                            status=ActionStatus.FAILED,
                            error=error,
                        )
                    ],
                    explanation="Emergency SSH rollback raised an unexpected contained error.",
                ),
                error,
            )
        error = next(
            (action.error for action in rollback.actions if action.error is not None),
            None,
        )
        return rollback, error

    def _unexpected_failure(
        self,
        context: AdapterContext,
        authorization: MutationAuthorization,
        state: _SshExecutionState,
        exc: Exception,
    ) -> AdapterOutcome:
        error = self._exception_label(exc)
        if not state.target_mutation_started:
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=False,
                    changed=False,
                    succeeded=None,
                    actions=state.actions,
                    backups=state.backups,
                    reason="SSH execution stopped after an unexpected failure before target mutation.",
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
                explanation="The SSH experiment stopped safely before target mutation.",
                warnings=[],
                errors=[error],
            )

        actions = self._record_unexpected_action(state.actions, error)
        rollback, rollback_error = self._safe_rollback_dropin(
            context,
            state=state,
            authorization=authorization,
        )
        errors = [error]
        if rollback.succeeded is not True:
            errors.append(
                f"rollback_error: {rollback_error or 'SSH rollback did not succeed'}"
            )
        return AdapterOutcome(
            remediation=RemediationResult(
                supported=True,
                attempted=True,
                changed=True,
                succeeded=False,
                actions=actions,
                backups=state.backups,
                reason="An unexpected failure occurred after SSH target mutation began.",
            ),
            post_audit=state.post_audit,
            health_checks=state.health_checks,
            rollback=rollback,
            decision=ValidationDecision.FAILED,
            explanation="The SSH experiment failed unexpectedly and rollback was attempted.",
            warnings=[],
            errors=errors,
        )

    def execute(self, context, pre_audit, authorization):
        state = _SshExecutionState()
        try:
            state.actions = self.plan(pre_audit)
            return self._execute(context, pre_audit, authorization, state)
        except Exception as exc:  # fail closed while retaining mutation state
            return self._unexpected_failure(context, authorization, state, exc)

    def _execute(self, context, pre_audit, authorization, state):
        if authorization.control_id != self.control_id:
            raise ValueError("mutation authorization does not match control 5.1.20")
        actions = state.actions
        failures = self._precondition_failures(pre_audit)
        if failures:
            return self._not_tested(
                actions,
                "SSH mutation was refused because strict preconditions were not proven.",
                failures,
            )

        effective_before = self._collected_value(
            pre_audit, "sshd_permit_root_login_effective"
        )
        if isinstance(effective_before, str) and effective_before.casefold() == "no":
            post = audit_ssh(context)
            state.post_audit = post
            health = check_ssh_health(post)
            state.health_checks = health
            required_failed = any(
                item.required and item.status is not HealthStatus.PASSED
                for item in health
            )
            completed = [
                item.model_copy(
                    update={
                        "status": (
                            ActionStatus.SKIPPED if item.mutating else ActionStatus.APPLIED
                        )
                    }
                )
                for item in actions
            ]
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=True,
                    changed=False,
                    succeeded=not required_failed,
                    actions=completed,
                    backups=[],
                    reason="Effective PermitRootLogin was already no; no file was changed.",
                ),
                post_audit=post,
                health_checks=health,
                rollback=RollbackResult(
                    supported=True,
                    attempted=False,
                    succeeded=None,
                    actions=[],
                    explanation="Rollback was not required.",
                ),
                decision=(
                    ValidationDecision.FAILED
                    if required_failed
                    else ValidationDecision.WARNING
                ),
                explanation=(
                    "The expected effective state was observed, but remote-access "
                    "continuity remains an administrator concern."
                    if not required_failed
                    else "A required SSH health check failed."
                ),
                warnings=(
                    ["remote-access continuity was not proven"]
                    if not required_failed
                    else []
                ),
                errors=["required SSH health check failed"] if required_failed else [],
            )

        target = context.resolve(self.target)
        try:
            parent_metadata = target.parent.lstat()
            if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
                parent_metadata.st_mode
            ):
                raise OSError("SSH drop-in parent is not a real directory")
        except OSError as exc:
            return self._not_tested(
                actions,
                "The fixed SSH drop-in directory could not be validated safely.",
                [type(exc).__name__],
            )
        original: FileSnapshot | None = None
        original_text: str | None = None
        try:
            original = context.files.snapshot(target)
            original_text = context.files.read_text(target, max_bytes=1024 * 1024)
        except FileNotFoundError:
            original = None
        except (OSError, ValueError) as exc:
            return self._not_tested(
                actions,
                "The dedicated SSH drop-in path could not be inspected safely.",
                [type(exc).__name__],
            )
        state.original = original
        if original_text is not None and not original_text.startswith(_OWNERSHIP_MARKER):
            return self._not_tested(
                actions,
                "An existing drop-in is not SENTRA-owned; collision was refused.",
                ["unmanaged_dropin_collision"],
            )

        backup_path = None
        backups = state.backups
        if original is not None:
            backup_directory = context.backup_directory(self.control_id)
            backup_path = backup_directory / (
                f"ssh-dropin-{context.clock().strftime('%Y%m%dT%H%M%S%fZ')}-"
                f"{secrets.token_hex(4)}.bak"
            )
            state.backup_path = backup_path
            try:
                context.files.make_private_directory(backup_directory)
                context.files.backup_file(target, backup_path, original)
                backups.append(
                    BackupInformation(
                        target=self.target,
                        original_existed=True,
                        created=True,
                        path="/" + backup_path.relative_to(context.root).as_posix(),
                        metadata_preserved=True,
                    )
                )
                actions[0] = actions[0].model_copy(
                    update={"status": ActionStatus.APPLIED}
                )
            except (OSError, ValueError) as exc:
                actions[0] = actions[0].model_copy(
                    update={"status": ActionStatus.FAILED, "error": type(exc).__name__}
                )
                return self._not_tested(
                    actions,
                    "The existing SENTRA-owned drop-in could not be backed up.",
                    [type(exc).__name__],
                )
        else:
            actions[0] = actions[0].model_copy(update={"status": ActionStatus.SKIPPED})
            backups.append(
                BackupInformation(
                    target=self.target,
                    original_existed=False,
                    created=False,
                    path=None,
                    metadata_preserved=False,
                    reason="No existing file required backup before creation.",
                )
            )

        try:
            state.target_mutation_started = True
            context.files.atomic_write_text(
                target, _DROPIN_CONTENT, uid=0, gid=0, mode=0o644
            )
            actions[1] = actions[1].model_copy(update={"status": ActionStatus.APPLIED})
        except (OSError, ValueError) as exc:
            actions[1] = actions[1].model_copy(
                update={"status": ActionStatus.FAILED, "error": type(exc).__name__}
            )
            rollback, rollback_error = self._safe_rollback_dropin(
                context,
                state=state,
                authorization=authorization,
            )
            errors = [self._exception_label(exc)]
            if rollback.succeeded is not True:
                errors.append(
                    f"rollback_error: {rollback_error or 'SSH rollback did not succeed'}"
                )
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=True,
                    changed=True,
                    succeeded=False,
                    actions=actions,
                    backups=backups,
                    reason="Writing the fixed SSH candidate failed.",
                ),
                post_audit=[],
                health_checks=[],
                rollback=rollback,
                decision=ValidationDecision.FAILED,
                explanation="The SSH candidate write failed and rollback was attempted.",
                warnings=[],
                errors=errors,
            )

        candidate_audit = audit_ssh(context)
        state.post_audit = candidate_audit
        syntax_ok, effective_ok = self._syntax_and_effective(candidate_audit)
        candidate_precondition_failures = self._precondition_failures(candidate_audit)
        actions[2] = actions[2].model_copy(
            update={
                "status": ActionStatus.APPLIED if syntax_ok else ActionStatus.FAILED,
                "error": None if syntax_ok else "sshd_syntax_validation_failed",
            }
        )
        actions[3] = actions[3].model_copy(
            update={
                "status": ActionStatus.APPLIED if effective_ok else ActionStatus.FAILED,
                "error": None if effective_ok else "effective_value_not_no",
            }
        )
        if not syntax_ok or not effective_ok or candidate_precondition_failures:
            actions[4] = actions[4].model_copy(update={"status": ActionStatus.SKIPPED})
            rollback, rollback_error = self._safe_rollback_dropin(
                context,
                state=state,
                authorization=authorization,
            )
            errors = []
            if not syntax_ok:
                errors.append("sshd syntax validation failed; reload was not attempted")
            if not effective_ok:
                errors.append("effective PermitRootLogin was not no; reload was not attempted")
            errors.extend(
                f"{failure}; reload was not attempted"
                for failure in candidate_precondition_failures
            )
            if rollback.succeeded is not True:
                errors.append(
                    f"rollback_error: {rollback_error or 'SSH rollback did not succeed'}"
                )
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=True,
                    changed=True,
                    succeeded=False,
                    actions=actions,
                    backups=backups,
                    reason="The candidate failed validation before service reload.",
                ),
                post_audit=candidate_audit,
                health_checks=[],
                rollback=rollback,
                decision=ValidationDecision.FAILED,
                explanation="Pre-reload SSH validation failed; rollback ran without reload.",
                warnings=[],
                errors=errors,
            )

        try:
            state.runtime_reload_attempted = True
            reload_result = context.runner.run_mutation(
                MutationAction.SSH_SERVICE_RELOAD, authorization
            )
        except CommandNotAllowedError as exc:
            reload_result = None
            reload_error = type(exc).__name__
        else:
            reload_error = reload_result.reason if not reload_result.succeeded else None
        actions[4] = actions[4].model_copy(
            update={
                "status": (
                    ActionStatus.APPLIED
                    if reload_result is not None and reload_result.succeeded
                    else ActionStatus.FAILED
                ),
                "error": reload_error,
            }
        )
        if reload_result is None or not reload_result.succeeded:
            rollback, rollback_error = self._safe_rollback_dropin(
                context,
                state=state,
                authorization=authorization,
            )
            errors = [reload_error or "ssh_reload_failed"]
            if rollback.succeeded is not True:
                errors.append(
                    f"rollback_error: {rollback_error or 'SSH rollback did not succeed'}"
                )
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=True,
                    changed=True,
                    succeeded=False,
                    actions=actions,
                    backups=backups,
                    reason="The validated candidate could not be reloaded.",
                ),
                post_audit=candidate_audit,
                health_checks=[],
                rollback=rollback,
                decision=ValidationDecision.FAILED,
                explanation="SSH reload failed and the dedicated file was rolled back.",
                warnings=[],
                errors=errors,
            )

        post = audit_ssh(context)
        state.post_audit = post
        post.append(
            AuditEvidence(
                name="ssh_configuration_files_touched",
                status=EvidenceStatus.COLLECTED,
                value=[self.target],
                source="adapter:5.1.20",
            )
        )
        actions[5] = actions[5].model_copy(update={"status": ActionStatus.APPLIED})
        post_syntax, post_effective = self._syntax_and_effective(post)
        health = check_ssh_health(post)
        state.health_checks = health
        required_failed = any(
            item.required and item.status is not HealthStatus.PASSED for item in health
        )
        if not post_syntax or not post_effective or required_failed:
            rollback, rollback_error = self._safe_rollback_dropin(
                context,
                state=state,
                authorization=authorization,
            )
            errors = ["required SSH post-state or health check failed"]
            if rollback.succeeded is not True:
                errors.append(
                    f"rollback_error: {rollback_error or 'SSH rollback did not succeed'}"
                )
            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=True,
                    changed=True,
                    succeeded=False,
                    actions=actions,
                    backups=backups,
                    reason="Post-reload state or required SSH health did not validate.",
                ),
                post_audit=post,
                health_checks=health,
                rollback=rollback,
                decision=ValidationDecision.FAILED,
                explanation="The SSH experiment failed after reload and rollback was attempted.",
                warnings=[],
                errors=errors,
            )

        return AdapterOutcome(
            remediation=RemediationResult(
                supported=True,
                attempted=True,
                changed=True,
                succeeded=True,
                actions=actions,
                backups=backups,
                reason="The fixed candidate, syntax test, effective check, and reload succeeded.",
            ),
            post_audit=post,
            health_checks=health,
            rollback=RollbackResult(
                supported=True,
                attempted=False,
                succeeded=None,
                actions=[],
                explanation="Rollback was not required.",
            ),
            decision=ValidationDecision.WARNING,
            explanation=(
                "The expected SSH state was observed, but future remote-access "
                "continuity was not proven."
            ),
            warnings=["remote-access continuity was not proven"],
            errors=[],
        )
