"""Persistent local identity for the lightweight SENTRA agent.

The state path is supplied by the caller.  This module deliberately has no
knowledge of operating-system account names, home directories, hostnames, or
network addresses.
"""

from __future__ import annotations

import errno
import json
import os
import stat
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from src.controller.models import EnrollmentResponse


_MAX_STATE_BYTES = 1024 * 1024


class AgentStateError(RuntimeError):
    """Base error for invalid or unavailable local agent state."""


class AgentStateSecurityError(AgentStateError):
    """The requested state path does not meet the local safety contract."""


class AgentEnrollmentError(AgentStateError):
    """The persisted enrollment cannot safely be created or replaced."""


class AgentState(BaseModel):
    """Installation identity and the optional controller-issued enrollment."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    schema_version: Literal[1] = 1
    installation_id: UUID = Field(default_factory=uuid4)
    target_id: UUID | None = None
    agent_id: UUID | None = None
    agent_credential: SecretStr | None = None
    polling_interval_seconds: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_complete_enrollment(self) -> "AgentState":
        enrollment_values = (
            self.target_id,
            self.agent_id,
            self.agent_credential,
            self.polling_interval_seconds,
        )
        populated = tuple(value is not None for value in enrollment_values)
        if any(populated) and not all(populated):
            raise ValueError("agent enrollment must be complete or absent")
        if self.agent_credential is not None:
            if not self.agent_credential.get_secret_value():
                raise ValueError("agent credential must not be empty")
        return self

    @property
    def is_enrolled(self) -> bool:
        """Whether a complete controller-issued enrollment is persisted."""

        return self.target_id is not None


class AgentStateStore:
    """Atomically persist one agent installation's state as mode-0600 JSON."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        supplied = Path(path)
        if supplied.name in {"", ".", ".."}:
            raise AgentStateSecurityError("agent state path must name a file")
        # abspath is lexical: unlike resolve(), it does not follow a caller's
        # symlinks before this class has a chance to reject them.
        self.path = Path(os.path.abspath(os.fspath(supplied)))

    def load_or_create(self) -> AgentState:
        """Load existing state or create a new persistent installation UUID."""

        self._ensure_safe_parent()
        existing = self._lstat_destination()
        if existing is not None:
            return self._load(existing)

        new_state = AgentState()
        try:
            self._atomic_write(new_state, create_only=True)
        except FileExistsError:
            # Another process initialized this path first.  Its complete,
            # permission-checked state is authoritative.
            existing = self._lstat_destination()
            if existing is None:  # pragma: no cover - pathological race
                raise AgentStateError("agent state disappeared during creation")
            return self._load(existing)
        return new_state

    def save_enrollment(self, response: EnrollmentResponse) -> AgentState:
        """Persist a controller-issued enrollment without permitting rebinding."""

        current = self.load_or_create()
        candidate = AgentState(
            installation_id=current.installation_id,
            target_id=response.target_id,
            agent_id=response.agent_id,
            agent_credential=response.agent_credential,
            polling_interval_seconds=response.polling_interval_seconds,
        )

        if current.is_enrolled:
            same_enrollment = (
                current.target_id == candidate.target_id
                and current.agent_id == candidate.agent_id
                and current.agent_credential is not None
                and candidate.agent_credential is not None
                and current.agent_credential.get_secret_value()
                == candidate.agent_credential.get_secret_value()
            )
            if not same_enrollment:
                raise AgentEnrollmentError(
                    "refusing to replace an existing agent enrollment"
                )

        self._atomic_write(candidate, create_only=False)
        return candidate

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
                raise AgentStateSecurityError(
                    "agent state parent must not contain symlinks"
                )
            if not stat.S_ISDIR(item_stat.st_mode):
                raise AgentStateSecurityError(
                    "agent state parent must contain only directories"
                )

    def _lstat_destination(self) -> os.stat_result | None:
        try:
            destination_stat = os.lstat(self.path)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(destination_stat.st_mode):
            raise AgentStateSecurityError("agent state must not be a symlink")
        if not stat.S_ISREG(destination_stat.st_mode):
            raise AgentStateSecurityError("agent state must be a regular file")
        if stat.S_IMODE(destination_stat.st_mode) != 0o600:
            raise AgentStateSecurityError("agent state permissions must be 0600")
        return destination_stat

    def _load(self, expected_stat: os.stat_result) -> AgentState:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise AgentStateSecurityError(
                    "agent state must not be a symlink"
                ) from None
            raise AgentStateError("unable to open agent state") from None

        try:
            opened_stat = os.fstat(descriptor)
            if not stat.S_ISREG(opened_stat.st_mode):
                raise AgentStateSecurityError("agent state must be a regular file")
            if stat.S_IMODE(opened_stat.st_mode) != 0o600:
                raise AgentStateSecurityError("agent state permissions must be 0600")
            if (
                opened_stat.st_dev != expected_stat.st_dev
                or opened_stat.st_ino != expected_stat.st_ino
            ):
                raise AgentStateSecurityError("agent state changed while opening")
            raw = os.read(descriptor, _MAX_STATE_BYTES + 1)
        finally:
            os.close(descriptor)

        if len(raw) > _MAX_STATE_BYTES:
            raise AgentStateError("agent state exceeds the size limit")
        try:
            payload = json.loads(raw.decode("utf-8"))
            return AgentState.model_validate(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            # Do not attach parser/validation details: malformed state may
            # contain a plaintext credential that must not enter logs.
            raise AgentStateError("agent state is invalid") from None

    def _atomic_write(self, state: AgentState, *, create_only: bool) -> None:
        self._ensure_safe_parent()
        existing = self._lstat_destination()
        if create_only and existing is not None:
            raise FileExistsError(os.fspath(self.path))
        if not create_only and existing is None:
            raise AgentStateError("agent state must exist before it can be updated")

        payload = self._serialized(state)
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        directory_fd = os.open(self.path.parent, directory_flags)
        temporary_name = f".{self.path.name}.{uuid4().hex}.tmp"
        temporary_fd: int | None = None

        try:
            file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            temporary_fd = os.open(
                temporary_name,
                file_flags,
                0o600,
                dir_fd=directory_fd,
            )
            os.fchmod(temporary_fd, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(temporary_fd, view)
                view = view[written:]
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None

            if create_only:
                os.link(
                    temporary_name,
                    self.path.name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                os.unlink(temporary_name, dir_fd=directory_fd)
            else:
                # Replacement is confined to the already-open directory.  A
                # destination symlink is replaced as an entry, never followed.
                os.replace(
                    temporary_name,
                    self.path.name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
            try:
                os.fsync(directory_fd)
            except OSError:  # pragma: no cover - filesystem-specific
                pass
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.close(directory_fd)

    @staticmethod
    def _serialized(state: AgentState) -> bytes:
        credential = (
            state.agent_credential.get_secret_value()
            if state.agent_credential is not None
            else None
        )
        payload = {
            "schema_version": state.schema_version,
            "installation_id": str(state.installation_id),
            "target_id": str(state.target_id) if state.target_id is not None else None,
            "agent_id": str(state.agent_id) if state.agent_id is not None else None,
            "agent_credential": credential,
            "polling_interval_seconds": state.polling_interval_seconds,
        }
        return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
