"""Controlled M5 adapter for CIS 3.3.1 IP forwarding."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import stat

from src.poc_models import Category
from src.target_profiler.collectors import (
    CollectionContext,
    ipv6_enabled,
    sysctl_parameter_sources,
)
from src.target_profiler.models import FactStatus

from ..command_runner import (
    CommandResult,
    MutationAction,
    MutationAuthorization,
    ReadAction,
)
from ..models import (
    ActionStatus,
    AuditEvidence,
    EvidenceStatus,
    HealthCheck,
    HealthStatus,
    RemediationAction,
    RemediationResult,
    RollbackResult,
    ValidationDecision,
)
from .base import (
    AdapterContext,
    AdapterOutcome,
    ControlAdapter,
    FileSnapshot,
    UnsafePathError,
)


_MANAGED_PATH = "/etc/sysctl.d/99-sentra-3.3.1.conf"
_OWNERSHIP_MARKER = "# Managed by SENTRA Milestone 5 (control 3.3.1)."
_MANAGED_CONTENT_IPV4 = (
    f"{_OWNERSHIP_MARKER}\n"
    "net.ipv4.ip_forward = 0\n"
)
_MANAGED_CONTENT_DUAL = (
    _MANAGED_CONTENT_IPV4 + "net.ipv6.conf.all.forwarding = 0\n"
)
_FORWARDING_KEYS = frozenset(
    {"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"}
)
_MAX_SYSCTL_SOURCES = 256


@dataclass(slots=True)
class _ExecutionState:
    actions: list[RemediationAction] = field(default_factory=list)
    file_created: bool = False
    created_file_snapshot: FileSnapshot | None = None
    created_file_content: str | None = None
    ipv4_original: int | None = None
    ipv6_original: int | None = None
    ipv4_changed: bool = False
    ipv6_changed: bool = False


def _collected(name: str, value, source: str) -> AuditEvidence:
    return AuditEvidence(
        name=name,
        status=EvidenceStatus.COLLECTED,
        value=value,
        source=source,
    )


def _missing(
    name: str,
    status: EvidenceStatus,
    reason: str,
    source: str,
) -> AuditEvidence:
    return AuditEvidence(
        name=name,
        status=status,
        value=None,
        source=source,
        reason=reason,
    )


def _command_evidence(
    name: str,
    result: CommandResult,
) -> AuditEvidence:
    if result.succeeded:
        value = result.stdout.strip()
        if value in {"0", "1"}:
            return _collected(
                name,
                int(value),
                f"command:{result.action}",
            )

        return _missing(
            name,
            EvidenceStatus.ERROR,
            "sysctl returned an unexpected forwarding value",
            f"command:{result.action}",
        )

    status = (
        EvidenceStatus.UNAVAILABLE
        if result.error_kind in {"permission_denied", "not_found"}
        else EvidenceStatus.ERROR
    )
    return _missing(
        name,
        status,
        result.reason or "unable to read forwarding state",
        f"command:{result.action}",
    )


def _ipv6_enabled_evidence(context: AdapterContext) -> AuditEvidence:
    observation = ipv6_enabled(CollectionContext(root=context.root))
    if observation.status is FactStatus.COLLECTED and type(observation.value) is bool:
        return _collected("ipv6_enabled", observation.value, "python:ipv6-state")
    status = EvidenceStatus(observation.status.value)
    return _missing(
        "ipv6_enabled",
        status,
        observation.reason or "IPv6 enablement could not be established",
        "python:ipv6-state",
    )


def _persistent_sources_evidence(context: AdapterContext) -> AuditEvidence:
    """Refuse to assert persistence if another source assigns either key.

    The M3 source collector resolves the standard Ubuntu sysctl locations and
    same-basename masking. Reading their assignments is local sandbox evidence;
    the M3 target profile's path list alone is not enough for this conclusion.
    """

    observation = sysctl_parameter_sources(CollectionContext(root=context.root))
    if observation.status is not FactStatus.COLLECTED:
        return _missing(
            "ip_forwarding_sources_uncontested",
            EvidenceStatus(observation.status.value),
            observation.reason or "sysctl sources could not be enumerated",
            "python:sysctl-sources",
        )
    paths = observation.value
    if (
        not isinstance(paths, list)
        or len(paths) > _MAX_SYSCTL_SOURCES
        or any(type(path) is not str or not path.startswith("/") for path in paths)
    ):
        return _missing(
            "ip_forwarding_sources_uncontested",
            EvidenceStatus.ERROR,
            "sysctl source enumeration exceeded the fixed review boundary",
            "python:sysctl-sources",
        )

    competing: list[str] = []
    try:
        selected_paths = {context.resolve(source) for source in paths}
        for source in paths:
            if source == _MANAGED_PATH:
                continue
            source_path = context.resolve(source)
            if stat.S_ISLNK(source_path.lstat().st_mode):
                # Ubuntu may alias a drop-in to /etc/sysctl.conf. Scan the
                # separately enumerated real file, never the link itself.
                resolved = source_path.resolve(strict=True)
                if resolved not in selected_paths or not resolved.is_relative_to(
                    context.root.resolve(strict=True)
                ):
                    raise UnsafePathError("sysctl source link is not separately inspected")
                continue
            text = context.files.read_text(source_path, max_bytes=64 * 1024)
            for line in text.splitlines():
                assignment = re.split(r"[#;]", line, maxsplit=1)[0].strip()
                if not assignment:
                    continue
                key = re.split(r"[\s=]+", assignment.lstrip("-"), maxsplit=1)[0]
                if key.replace("/", ".") in _FORWARDING_KEYS:
                    competing.append(source)
                    break
    except (OSError, UnsafePathError, ValueError) as exc:
        return _missing(
            "ip_forwarding_sources_uncontested",
            EvidenceStatus.ERROR,
            f"sysctl source could not be read safely: {type(exc).__name__}",
            "python:sysctl-sources",
        )

    return _collected(
        "ip_forwarding_sources_uncontested",
        not competing,
        "python:sysctl-sources",
    )


def audit_ip_forwarding(context: AdapterContext) -> list[AuditEvidence]:
    """Collect fresh runtime and SENTRA-managed persistent-state evidence."""

    ipv4 = context.runner.run_read(ReadAction.IPV4_FORWARDING_STATUS)
    enabled = _ipv6_enabled_evidence(context)

    evidence = [
        _command_evidence("ipv4_forwarding_runtime", ipv4),
        enabled,
        _persistent_sources_evidence(context),
    ]
    if enabled.status is EvidenceStatus.COLLECTED and enabled.value is True:
        evidence.append(
            _command_evidence(
                "ipv6_forwarding_runtime",
                context.runner.run_read(ReadAction.IPV6_FORWARDING_STATUS),
            )
        )
    else:
        evidence.append(
            _missing(
                "ipv6_forwarding_runtime",
                EvidenceStatus.UNSUPPORTED,
                "IPv6 forwarding is not applicable or enablement is unknown",
                "python:ipv6-state",
            )
        )

    path = context.resolve(_MANAGED_PATH)

    try:
        snapshot = context.files.snapshot(path)
    except FileNotFoundError:
        evidence.extend(
            [
                _collected(
                    "ip_forwarding_managed_file_present",
                    False,
                    "python:lstat",
                ),
                _collected(
                    "ip_forwarding_managed_file_owned",
                    False,
                    "adapter:3.3.1",
                ),
                _collected(
                    "ip_forwarding_managed_file_exact",
                    False,
                    "adapter:3.3.1",
                ),
            ]
        )
        return evidence
    except (OSError, UnsafePathError, ValueError) as exc:
        reason = f"unable to inspect managed sysctl path: {type(exc).__name__}"
        evidence.extend(
            [
                _missing(
                    "ip_forwarding_managed_file_present",
                    EvidenceStatus.ERROR,
                    reason,
                    "python:lstat",
                ),
                _missing(
                    "ip_forwarding_managed_file_owned",
                    EvidenceStatus.ERROR,
                    reason,
                    "adapter:3.3.1",
                ),
                _missing(
                    "ip_forwarding_managed_file_exact",
                    EvidenceStatus.ERROR,
                    reason,
                    "adapter:3.3.1",
                ),
            ]
        )
        return evidence

    try:
        text = context.files.read_text(path, max_bytes=64 * 1024)
    except (OSError, UnsafePathError, ValueError) as exc:
        reason = f"unable to read managed sysctl path: {type(exc).__name__}"
        evidence.extend(
            [
                _collected(
                    "ip_forwarding_managed_file_present",
                    True,
                    "python:lstat",
                ),
                _missing(
                    "ip_forwarding_managed_file_owned",
                    EvidenceStatus.ERROR,
                    reason,
                    "adapter:3.3.1",
                ),
                _missing(
                    "ip_forwarding_managed_file_exact",
                    EvidenceStatus.ERROR,
                    reason,
                    "adapter:3.3.1",
                ),
            ]
        )
        return evidence

    owned = text.startswith(_OWNERSHIP_MARKER + "\n")
    expected_content = (
        _MANAGED_CONTENT_DUAL
        if enabled.status is EvidenceStatus.COLLECTED and enabled.value is True
        else _MANAGED_CONTENT_IPV4
        if enabled.status is EvidenceStatus.COLLECTED and enabled.value is False
        else None
    )
    exact = (
        expected_content is not None
        and text == expected_content
        and snapshot.mode == 0o644
        and snapshot.uid == 0
        and snapshot.gid == 0
    )

    evidence.extend(
        [
            _collected(
                "ip_forwarding_managed_file_present",
                True,
                "python:lstat",
            ),
            _collected(
                "ip_forwarding_managed_file_owned",
                owned,
                "adapter:3.3.1",
            ),
            _collected(
                "ip_forwarding_managed_file_exact",
                exact,
                "adapter:3.3.1",
            ),
        ]
    )

    return evidence


def _by_name(evidence: list[AuditEvidence]) -> dict[str, AuditEvidence]:
    return {item.name: item for item in evidence}


def _integer_value(
    evidence: list[AuditEvidence],
    name: str,
) -> int | None:
    item = _by_name(evidence).get(name)
    if (
        item is not None
        and item.status is EvidenceStatus.COLLECTED
        and type(item.value) is int
        and item.value in {0, 1}
    ):
        return item.value
    return None


def _boolean_value(
    evidence: list[AuditEvidence],
    name: str,
) -> bool | None:
    item = _by_name(evidence).get(name)
    if (
        item is not None
        and item.status is EvidenceStatus.COLLECTED
        and type(item.value) is bool
    ):
        return item.value
    return None


def _health_checks(post_audit: list[AuditEvidence]) -> list[HealthCheck]:
    ipv4 = _integer_value(post_audit, "ipv4_forwarding_runtime")
    ipv6 = _integer_value(post_audit, "ipv6_forwarding_runtime")
    enabled = _boolean_value(post_audit, "ipv6_enabled")
    persistent = _boolean_value(
        post_audit,
        "ip_forwarding_managed_file_exact",
    )
    sources_uncontested = _boolean_value(
        post_audit,
        "ip_forwarding_sources_uncontested",
    )

    return [
        HealthCheck(
            check_id="ipv4-forwarding-disabled",
            description="IPv4 packet forwarding is disabled in the running kernel.",
            required=True,
            status=(
                HealthStatus.PASSED
                if ipv4 == 0
                else HealthStatus.FAILED
                if ipv4 is not None
                else HealthStatus.UNAVAILABLE
            ),
            explanation=(
                "The running IPv4 forwarding value is 0."
                if ipv4 == 0
                else "The running IPv4 forwarding value was not verified as 0."
            ),
        ),
        HealthCheck(
            check_id="ipv6-forwarding-disabled",
            description="IPv6 packet forwarding is disabled in the running kernel.",
            required=True,
            status=(
                HealthStatus.PASSED
                if enabled is False or (enabled is True and ipv6 == 0)
                else HealthStatus.FAILED
                if enabled is True and ipv6 is not None
                else HealthStatus.UNAVAILABLE
            ),
            explanation=(
                "IPv6 is disabled on this sandbox."
                if enabled is False
                else "The running IPv6 forwarding value is 0."
                if enabled is True and ipv6 == 0
                else "The running IPv6 forwarding value was not verified as 0."
            ),
        ),
        HealthCheck(
            check_id="ip-forwarding-persistent-file",
            description="The fixed SENTRA sysctl drop-in contains the expected settings.",
            required=True,
            status=(
                HealthStatus.PASSED
                if persistent is True
                else HealthStatus.FAILED
                if persistent is False
                else HealthStatus.UNAVAILABLE
            ),
            explanation=(
                "The SENTRA-owned persistent sysctl drop-in matches the expected content."
                if persistent is True
                else "The SENTRA-owned persistent sysctl drop-in was not verified."
            ),
        ),
        HealthCheck(
            check_id="ip-forwarding-sources-uncontested",
            description="No other inspected sysctl source assigns forwarding parameters.",
            required=True,
            status=(
                HealthStatus.PASSED
                if sources_uncontested is True
                else HealthStatus.FAILED
                if sources_uncontested is False
                else HealthStatus.UNAVAILABLE
            ),
            explanation=(
                "No competing forwarding assignment was found in the inspected sources."
                if sources_uncontested is True
                else "Persistent forwarding precedence could not be established."
            ),
        ),
    ]


class IpForwardingAdapter(ControlAdapter):
    """Fixed, fail-closed adapter for CIS control 3.3.1."""

    control_id = "3.3.1"
    title = "Ensure ip forwarding is disabled"
    category = Category.NETWORK
    mutation_supported = True
    target = _MANAGED_PATH

    def pre_audit(self, context: AdapterContext) -> list[AuditEvidence]:
        return audit_ip_forwarding(context)

    def plan(self, pre_audit: list[AuditEvidence]) -> list[RemediationAction]:
        enabled = _boolean_value(pre_audit, "ipv6_enabled")
        actions = [
            RemediationAction(
                action_id="write-ip-forwarding-sysctl",
                description="Create the fixed SENTRA-owned sysctl drop-in.",
                mutating=True,
                target=self.target,
                planned_effect=(
                    "Persist applicable forwarding values as 0 without "
                    "modifying unrelated sysctl files."
                ),
                status=ActionStatus.PLANNED,
            ),
            RemediationAction(
                action_id="disable-ipv4-forwarding",
                description="Disable IPv4 packet forwarding in the running kernel.",
                mutating=True,
                target="net.ipv4.ip_forward",
                planned_effect="Set the fixed runtime value to 0.",
                status=ActionStatus.PLANNED,
            ),
            RemediationAction(
                action_id="flush-ipv4-route-cache",
                description="Flush IPv4 route state after changing forwarding.",
                mutating=True,
                target="net.ipv4.route.flush",
                planned_effect="Apply the CIS remediation route flush.",
                status=ActionStatus.PLANNED,
            ),
        ]
        if enabled is True:
            actions.extend([
                RemediationAction(
                    action_id="disable-ipv6-forwarding",
                    description="Disable IPv6 packet forwarding in the running kernel.",
                    mutating=True,
                    target="net.ipv6.conf.all.forwarding",
                    planned_effect="Set the fixed runtime value to 0.",
                    status=ActionStatus.PLANNED,
                ),
                RemediationAction(
                    action_id="flush-ipv6-route-cache",
                    description="Flush IPv6 route state after changing forwarding.",
                    mutating=True,
                    target="net.ipv6.route.flush",
                    planned_effect="Apply the CIS remediation route flush.",
                    status=ActionStatus.PLANNED,
                ),
            ])
        actions.append(
            RemediationAction(
                action_id="verify-ip-forwarding-state",
                description="Re-audit runtime and persistent forwarding state.",
                mutating=False,
                target=self.target,
                planned_effect=(
                    "Confirm the sandbox candidate state without claiming "
                    "full CIS compliance."
                ),
                status=ActionStatus.PLANNED,
            )
        )
        return actions

    @staticmethod
    def _set_status(
        actions: list[RemediationAction],
        action_id: str,
        status: ActionStatus,
        error: str | None = None,
    ) -> None:
        for index, action in enumerate(actions):
            if action.action_id == action_id:
                actions[index] = action.model_copy(
                    update={
                        "status": status,
                        "error": error,
                    }
                )
                return
        raise ValueError(f"unknown adapter action: {action_id}")

    @staticmethod
    def _not_tested(
        actions: list[RemediationAction],
        reason: str,
        errors: list[str],
    ) -> AdapterOutcome:
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
            errors=errors,
        )

    @staticmethod
    def _run(
        context: AdapterContext,
        action: MutationAction,
        authorization: MutationAuthorization,
    ) -> CommandResult:
        return context.runner.run_mutation(action, authorization)

    def _rollback(
        self,
        context: AdapterContext,
        authorization: MutationAuthorization,
        state: _ExecutionState,
    ) -> RollbackResult:
        actions: list[RemediationAction] = []
        succeeded = True

        if state.ipv6_changed and state.ipv6_original is not None:
            action = RemediationAction(
                action_id="restore-ipv6-forwarding",
                description="Restore the original IPv6 forwarding runtime value.",
                mutating=True,
                target="net.ipv6.conf.all.forwarding",
                planned_effect="Restore the captured pre-remediation value.",
                status=ActionStatus.PLANNED,
            )
            restore_action = (
                MutationAction.IPV6_FORWARDING_ENABLE
                if state.ipv6_original == 1
                else MutationAction.IPV6_FORWARDING_DISABLE
            )
            result = self._run(context, restore_action, authorization)
            if result.succeeded:
                flush = self._run(
                    context,
                    MutationAction.IPV6_ROUTE_FLUSH,
                    authorization,
                )
                ok = flush.succeeded
            else:
                ok = False

            action = action.model_copy(
                update={
                    "status": ActionStatus.APPLIED if ok else ActionStatus.FAILED,
                    "error": None if ok else (result.reason or "ipv6 rollback failed"),
                }
            )
            actions.append(action)
            succeeded = succeeded and ok

        if state.ipv4_changed and state.ipv4_original is not None:
            action = RemediationAction(
                action_id="restore-ipv4-forwarding",
                description="Restore the original IPv4 forwarding runtime value.",
                mutating=True,
                target="net.ipv4.ip_forward",
                planned_effect="Restore the captured pre-remediation value.",
                status=ActionStatus.PLANNED,
            )
            restore_action = (
                MutationAction.IPV4_FORWARDING_ENABLE
                if state.ipv4_original == 1
                else MutationAction.IPV4_FORWARDING_DISABLE
            )
            result = self._run(context, restore_action, authorization)
            if result.succeeded:
                flush = self._run(
                    context,
                    MutationAction.IPV4_ROUTE_FLUSH,
                    authorization,
                )
                ok = flush.succeeded
            else:
                ok = False

            action = action.model_copy(
                update={
                    "status": ActionStatus.APPLIED if ok else ActionStatus.FAILED,
                    "error": None if ok else (result.reason or "ipv4 rollback failed"),
                }
            )
            actions.append(action)
            succeeded = succeeded and ok

        if state.file_created:
            action = RemediationAction(
                action_id="remove-ip-forwarding-sysctl",
                description="Remove the sysctl drop-in created by this attempt.",
                mutating=True,
                target=self.target,
                planned_effect="Restore the original absence of the SENTRA file.",
                status=ActionStatus.PLANNED,
            )
            try:
                path = context.resolve(self.target)
                current = context.files.snapshot(path)
                original = state.created_file_snapshot
                if (
                    original is None
                    or (current.device, current.inode)
                    != (original.device, original.inode)
                    or current.mode != 0o644
                    or current.uid != 0
                    or current.gid != 0
                    or context.files.read_text(path, max_bytes=64 * 1024)
                    != state.created_file_content
                ):
                    raise UnsafePathError("created sysctl file changed before rollback")
                context.files.remove_file(path)
            except (OSError, UnsafePathError, ValueError) as exc:
                ok = False
                error = type(exc).__name__
            else:
                ok = True
                error = None

            actions.append(
                action.model_copy(
                    update={
                        "status": ActionStatus.APPLIED if ok else ActionStatus.FAILED,
                        "error": error,
                    }
                )
            )
            succeeded = succeeded and ok

        return RollbackResult(
            supported=True,
            attempted=bool(actions),
            succeeded=succeeded if actions else None,
            actions=actions,
            explanation=(
                "The original forwarding runtime state and newly created "
                "SENTRA file were restored."
                if actions and succeeded
                else "Rollback was attempted but one or more restoration steps failed."
                if actions
                else "Rollback was not required."
            ),
        )

    def execute(
        self,
        context: AdapterContext,
        pre_audit: list[AuditEvidence],
        authorization: MutationAuthorization,
    ) -> AdapterOutcome:
        if authorization.control_id != self.control_id:
            raise ValueError(
                "mutation authorization does not match control 3.3.1"
            )

        state = _ExecutionState(actions=self.plan(pre_audit))
        state.ipv4_original = _integer_value(
            pre_audit,
            "ipv4_forwarding_runtime",
        )
        state.ipv6_original = _integer_value(
            pre_audit,
            "ipv6_forwarding_runtime",
        )
        enabled = _boolean_value(pre_audit, "ipv6_enabled")

        if (
            state.ipv4_original is None
            or enabled is None
            or (enabled and state.ipv6_original is None)
        ):
            return self._not_tested(
                state.actions,
                "Fresh forwarding runtime evidence was incomplete.",
                ["forwarding_runtime_evidence_unavailable"],
            )

        if _boolean_value(pre_audit, "ip_forwarding_sources_uncontested") is not True:
            return self._not_tested(
                state.actions,
                "Persistent sysctl sources may override the fixed candidate.",
                ["persistent_sysctl_precedence_unresolved"],
            )

        present = _boolean_value(
            pre_audit,
            "ip_forwarding_managed_file_present",
        )
        owned = _boolean_value(
            pre_audit,
            "ip_forwarding_managed_file_owned",
        )
        exact = _boolean_value(
            pre_audit,
            "ip_forwarding_managed_file_exact",
        )

        if present is None or owned is None or exact is None:
            return self._not_tested(
                state.actions,
                "The fixed persistent sysctl path could not be verified safely.",
                ["persistent_sysctl_evidence_unavailable"],
            )

        if present and not exact:
            return self._not_tested(
                state.actions,
                (
                    "The fixed SENTRA sysctl path already exists with unexpected "
                    "content; collision or drift was refused."
                ),
                [
                    "unmanaged_sysctl_collision"
                    if not owned
                    else "sentra_sysctl_drift"
                ],
            )

        changed = False

        try:
            if exact:
                self._set_status(
                    state.actions,
                    "write-ip-forwarding-sysctl",
                    ActionStatus.SKIPPED,
                )
            else:
                content = _MANAGED_CONTENT_DUAL if enabled else _MANAGED_CONTENT_IPV4
                context.files.create_exclusive_text(
                    context.resolve(self.target),
                    content,
                    uid=0,
                    gid=0,
                    mode=0o644,
                )
                state.file_created = True
                state.created_file_content = content
                state.created_file_snapshot = context.files.snapshot(
                    context.resolve(self.target)
                )
                changed = True
                self._set_status(
                    state.actions,
                    "write-ip-forwarding-sysctl",
                    ActionStatus.APPLIED,
                )

            if state.ipv4_original == 1:
                state.ipv4_changed = True
                result = self._run(
                    context,
                    MutationAction.IPV4_FORWARDING_DISABLE,
                    authorization,
                )
                if not result.succeeded:
                    raise RuntimeError(
                        result.reason or "ipv4 forwarding mutation failed"
                    )
                changed = True
                self._set_status(
                    state.actions,
                    "disable-ipv4-forwarding",
                    ActionStatus.APPLIED,
                )

                result = self._run(
                    context,
                    MutationAction.IPV4_ROUTE_FLUSH,
                    authorization,
                )
                if not result.succeeded:
                    raise RuntimeError(
                        result.reason or "ipv4 route flush failed"
                    )
                self._set_status(
                    state.actions,
                    "flush-ipv4-route-cache",
                    ActionStatus.APPLIED,
                )
            else:
                self._set_status(
                    state.actions,
                    "disable-ipv4-forwarding",
                    ActionStatus.SKIPPED,
                )
                self._set_status(
                    state.actions,
                    "flush-ipv4-route-cache",
                    ActionStatus.SKIPPED,
                )

            if enabled and state.ipv6_original == 1:
                state.ipv6_changed = True
                result = self._run(
                    context,
                    MutationAction.IPV6_FORWARDING_DISABLE,
                    authorization,
                )
                if not result.succeeded:
                    raise RuntimeError(
                        result.reason or "ipv6 forwarding mutation failed"
                    )
                changed = True
                self._set_status(
                    state.actions,
                    "disable-ipv6-forwarding",
                    ActionStatus.APPLIED,
                )

                result = self._run(
                    context,
                    MutationAction.IPV6_ROUTE_FLUSH,
                    authorization,
                )
                if not result.succeeded:
                    raise RuntimeError(
                        result.reason or "ipv6 route flush failed"
                    )
                self._set_status(
                    state.actions,
                    "flush-ipv6-route-cache",
                    ActionStatus.APPLIED,
                )
            elif enabled:
                self._set_status(
                    state.actions,
                    "disable-ipv6-forwarding",
                    ActionStatus.SKIPPED,
                )
                self._set_status(
                    state.actions,
                    "flush-ipv6-route-cache",
                    ActionStatus.SKIPPED,
                )

            post = audit_ip_forwarding(context)
            health = _health_checks(post)

            required_failed = any(
                item.required and item.status is not HealthStatus.PASSED
                for item in health
            )

            if required_failed:
                rollback = self._rollback(context, authorization, state)
                self._set_status(
                    state.actions,
                    "verify-ip-forwarding-state",
                    ActionStatus.FAILED,
                    "post-remediation verification failed",
                )
                return AdapterOutcome(
                    remediation=RemediationResult(
                        supported=True,
                        attempted=True,
                        changed=changed,
                        succeeded=False,
                        actions=state.actions,
                        backups=[],
                        reason="Post-remediation forwarding verification failed.",
                    ),
                    post_audit=post,
                    health_checks=health,
                    rollback=rollback,
                    decision=ValidationDecision.FAILED,
                    explanation=(
                        "The 3.3.1 candidate did not pass required sandbox "
                        "verification and rollback was attempted."
                    ),
                    warnings=[],
                    errors=["required_ip_forwarding_health_check_failed"],
                )

            self._set_status(
                state.actions,
                "verify-ip-forwarding-state",
                ActionStatus.APPLIED,
            )

            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=True,
                    changed=changed,
                    succeeded=True,
                    actions=state.actions,
                    backups=[],
                    reason=(
                        "The fixed IP-forwarding candidate was applied and "
                        "verified in the sandbox."
                        if changed
                        else "The sandbox already matched the fixed candidate state."
                    ),
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
                decision=ValidationDecision.VALIDATED,
                explanation=(
                    "Runtime forwarding values and the SENTRA-owned persistent "
                    "drop-in were verified in the isolated sandbox."
                ),
                warnings=[
                    (
                        "M4 deployment-role and sysctl-source review remains "
                        "authoritative; sandbox validation is not a CIS "
                        "compliance verdict."
                    )
                ],
                errors=[],
            )

        except Exception as exc:
            rollback = self._rollback(context, authorization, state)

            for action in state.actions:
                if action.status is ActionStatus.PLANNED:
                    self._set_status(
                        state.actions,
                        action.action_id,
                        ActionStatus.FAILED,
                        type(exc).__name__,
                    )
                    break

            for action in list(state.actions):
                if action.status is ActionStatus.PLANNED:
                    self._set_status(
                        state.actions,
                        action.action_id,
                        ActionStatus.SKIPPED,
                    )

            return AdapterOutcome(
                remediation=RemediationResult(
                    supported=True,
                    attempted=True,
                    changed=(
                        state.file_created
                        or state.ipv4_changed
                        or state.ipv6_changed
                    ),
                    succeeded=False,
                    actions=state.actions,
                    backups=[],
                    reason="The controlled 3.3.1 candidate stopped after a failure.",
                ),
                post_audit=[],
                health_checks=[],
                rollback=rollback,
                decision=ValidationDecision.FAILED,
                explanation=(
                    "The IP-forwarding experiment failed closed and rollback "
                    "was attempted where required."
                ),
                warnings=[],
                errors=[type(exc).__name__],
            )


__all__ = [
    "IpForwardingAdapter",
    "audit_ip_forwarding",
]
