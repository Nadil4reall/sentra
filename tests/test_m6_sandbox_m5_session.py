"""Bounded in-memory tests for the two-phase sandbox M5 session."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from src import sandbox_m5_validation
from src.controller.models import JobStatus, ValidationJobRecord, ValidationResultPayload
from src.controller.sandbox_m5 import (
    SandboxM5ControllerError,
    build_sandbox_m5_authorization,
    run_sandbox_m5_controller_transaction,
    sandbox_m5_result_to_validation_payload,
)
from src.sandbox_m5_protocol.context import sandbox_context_sha256
from src.sandbox_m5_protocol import context as context_binding
from src.poc_models import DerivationStatus
from src.sandbox_m5_session import SandboxM5SessionError, run_sandbox_m5_session
from src.sandbox_protocol import (
    MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES,
    SandboxContextAcknowledgement,
    SandboxContextManifest,
    SandboxContextRejectionCode,
    decode_sandbox_acknowledgement_frame,
    encode_sandbox_acknowledgement_frame,
    encode_sandbox_context_frame,
)
from src.sandbox_m5_protocol.models import (
    SandboxM5ControllerAuthorization,
    SandboxM5SessionResult,
)
from src.sandbox_m5_protocol.transport import (
    MAX_SANDBOX_M5_PAYLOAD_BYTES,
    SandboxM5TransportError,
    decode_sandbox_m5_authorization_frame,
    decode_sandbox_m5_result_frame,
    encode_sandbox_m5_authorization_frame,
    encode_sandbox_m5_result_frame,
)
from src.sandbox_runtime import reproduction
from src.sandbox_runtime.reproduction import SandboxPasswdReproductionResult
from src.sandbox_validator.adapters.base import AdapterContext, FileSnapshot
from src.sandbox_validator.adapters.passwd_permissions import PasswdPermissionsAdapter
from src.sandbox_validator.models import (
    CompatibilityReference,
    ExecutionMode,
    SandboxIdentity,
    ValidationDecision,
    ValidationReport,
)
from src.sandbox_validator.validator import SandboxValidator as RealSandboxValidator
from src.target_profiler.models import TargetInfo


_NOW = datetime(2026, 10, 8, 9, 0, tzinfo=UTC)
_PROFILE_ID = UUID("949f950f-747c-4711-9684-95b186899013")
_REPORT_ID = UUID("8d6136f4-621c-410b-b3c4-d87ce2220268")
_JOB_ID = UUID("87a5e976-b05b-4c27-8c00-ceb024acb9b4")
_TARGET_ID = UUID("d16ab6b4-45ff-4031-8223-1c90e27c22ec")
_PASSWD_TEXT = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
)


class _MemoryDuplex:
    def __init__(self, incoming: bytes = b"", *, read_limit: int = 11, write_limit: int = 13):
        self.incoming = bytearray(incoming)
        self.offset = 0
        self.outgoing = bytearray()
        self.read_limit = read_limit
        self.write_limit = write_limit
        self.read_calls = 0

    def read(self, size: int) -> bytes:
        self.read_calls += 1
        if self.offset == len(self.incoming):
            return b""
        count = min(size, self.read_limit, len(self.incoming) - self.offset)
        value = bytes(self.incoming[self.offset : self.offset + count])
        self.offset += count
        return value

    def write(self, value: bytes) -> int:
        count = min(len(value), self.write_limit)
        self.outgoing.extend(value[:count])
        return count


class _MemoryReproductionFilesystem:
    def __init__(self) -> None:
        self.mode = 0o600
        self.uid = 1001
        self.gid = 1002
        self.opens: list[tuple[str, int]] = []

    def open(self, path: str, flags: int) -> int:
        self.opens.append((path, flags))
        assert path == "/etc/passwd"
        return 17

    def fstat(self, _descriptor: int) -> Any:
        return type(
            "Stat",
            (),
            {
                "st_mode": stat.S_IFREG | self.mode,
                "st_uid": self.uid,
                "st_gid": self.gid,
            },
        )()

    def fchown(self, _descriptor: int, uid: int, gid: int) -> None:
        self.uid, self.gid = uid, gid

    def fchmod(self, _descriptor: int, mode: int) -> None:
        self.mode = mode

    def close(self, _descriptor: int) -> None:
        return None


class _MemoryM5Files:
    """M5 filesystem constrained to one temporary /etc/passwd path."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.entries: dict[Path, tuple[str, int, int, int, int]] = {}
        self.operations: list[str] = []
        self._inode = 100
        self.add(root / "etc" / "passwd", _PASSWD_TEXT, 0o664, 0, 0)

    def _check(self, path: Path) -> Path:
        path = Path(path)
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise AssertionError("test M5 filesystem refused a path outside tmp_path") from exc
        return path

    def add(self, path: Path, text: str, mode: int, uid: int, gid: int) -> None:
        path = self._check(path)
        self._inode += 1
        self.entries[path] = (text, mode, uid, gid, self._inode)

    def snapshot(self, path: Path) -> FileSnapshot:
        path = self._check(path)
        self.operations.append("snapshot")
        text, mode, uid, gid, inode = self.entries[path]
        return FileSnapshot(mode, uid, gid, 23, inode, len(text.encode("utf-8")))

    def read_text(self, path: Path, *, max_bytes: int) -> str:
        path = self._check(path)
        self.operations.append("read_text")
        text = self.entries[path][0]
        if len(text.encode("utf-8")) > max_bytes:
            raise OSError("temporary fixture exceeds read bound")
        return text

    def make_private_directory(self, path: Path) -> None:
        self._check(path)
        self.operations.append("make_private_directory")

    def backup_file(self, source: Path, destination: Path, expected: FileSnapshot) -> None:
        source, destination = self._check(source), self._check(destination)
        current = self.snapshot(source)
        if current != expected:
            raise OSError("temporary fixture identity changed")
        text, mode, uid, gid, _inode = self.entries[source]
        self.add(destination, text, mode, uid, gid)
        self.operations.append("backup_file")

    def set_metadata(
        self,
        path: Path,
        expected: FileSnapshot,
        *,
        uid: int,
        gid: int,
        mode: int,
    ) -> None:
        path = self._check(path)
        if self.snapshot(path) != expected:
            raise OSError("temporary fixture identity changed")
        text, _old_mode, _old_uid, _old_gid, inode = self.entries[path]
        self.entries[path] = (text, mode, uid, gid, inode)
        self.operations.append("set_metadata")

    def atomic_write_text(
        self, path: Path, content: str, *, uid: int, gid: int, mode: int
    ) -> None:
        self.add(path, content, mode, uid, gid)
        self.operations.append("atomic_write_text")

    def remove_file(self, path: Path) -> None:
        self.entries.pop(self._check(path), None)
        self.operations.append("remove_file")


class _NoCommandRunner:
    def run_read(self, *_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("fixed 7.1.1 M5 adapter must not run commands")

    def run_mutation(self, *_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("fixed 7.1.1 M5 adapter must not run commands")


def _manifest(*, mode: str = "0664", uid: int = 0, gid: int = 0) -> SandboxContextManifest:
    return SandboxContextManifest.model_validate(
        {
            "context_version": "1",
            "control_id": "7.1.1",
            "source_state": {
                "passwd_file_mode": mode,
                "passwd_file_owner_uid": uid,
                "passwd_file_group_gid": gid,
            },
        }
    )


def _compatibility() -> CompatibilityReference:
    return CompatibilityReference(
        control_id="7.1.1",
        report_source=f"controller-stored-compatibility-report:{_REPORT_ID}",
        report_sha256="a" * 64,
        report_version="1",
        report_generated_at=_NOW - timedelta(minutes=5),
        profile_source=f"controller-stored-profile:{_PROFILE_ID}",
        profile_collected_at=_NOW - timedelta(minutes=10),
        profile_target=TargetInfo(
            hostname="lab-ubuntu",
            os="Ubuntu",
            os_version="24.04",
            kernel="6.8.0-test",
            architecture="aarch64",
            supported=True,
        ),
        result="no_known_conflict",
        provisional=True,
        metadata_review_status=DerivationStatus.NEEDS_REVIEW,
        explanation="Stored M4 reference for the fixed 7.1.1 session test.",
    )


def _job() -> ValidationJobRecord:
    return ValidationJobRecord(
        validation_job_id=_JOB_ID,
        request_id=uuid4(),
        target_id=_TARGET_ID,
        profile_id=_PROFILE_ID,
        compatibility_report_id=_REPORT_ID,
        control_id="7.1.1",
        administrator_approval_acknowledged=True,
        compatibility_risk_acknowledged=False,
        compatibility_override_reason=None,
        compatibility_reference=_compatibility(),
        status=JobStatus.DISPATCHED,
        created_at=_NOW - timedelta(minutes=2),
        dispatched_at=_NOW - timedelta(minutes=1),
    )


def _identity() -> SandboxIdentity:
    return SandboxIdentity(
        hostname="temporary-sandbox",
        os="Ubuntu",
        version="24.04",
        kernel="6.8.0-test",
        architecture="x86_64",
        architecture_supported=True,
        effective_uid=0,
        privileged=True,
        supported=True,
    )


def _install_safe_m5_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    files = _MemoryM5Files(tmp_path)
    observed: dict[str, Any] = {}

    class TemporaryContextValidator:
        def __init__(self, *, context: AdapterContext) -> None:
            assert context.root == Path("/")
            observed["production_root"] = context.root
            self.delegate = RealSandboxValidator(
                context=AdapterContext(
                    root=tmp_path,
                    files=files,  # type: ignore[arg-type]
                    runner=_NoCommandRunner(),  # type: ignore[arg-type]
                    clock=lambda: _NOW,
                ),
                identity_provider=_identity,
            )
            observed["validator"] = self.delegate

        def validate(self, inputs: Any, request: Any) -> ValidationReport:
            observed["inputs"] = inputs
            observed["request"] = request
            return self.delegate.validate(inputs, request)

    monkeypatch.setattr(
        sandbox_m5_validation, "SandboxValidator", TemporaryContextValidator
    )
    return observed, files


def _run_guest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    sandbox_operator_acknowledged: bool,
    authorization: SandboxM5ControllerAuthorization | None = None,
    manifest_frame: bytes | None = None,
):
    reproduction_fs = _MemoryReproductionFilesystem()
    monkeypatch.setattr(reproduction, "_FILESYSTEM", reproduction_fs)
    observed, m5_files = _install_safe_m5_context(monkeypatch, tmp_path)
    manifest = _manifest()
    authorization = authorization or build_sandbox_m5_authorization(_job(), manifest)
    incoming = manifest_frame or encode_sandbox_context_frame(manifest)
    incoming += encode_sandbox_m5_authorization_frame(authorization)
    stream = _MemoryDuplex(incoming)
    result = run_sandbox_m5_session(
        stream,
        sandbox_operator_acknowledged=sandbox_operator_acknowledged,
    )
    return result, stream, observed, m5_files, reproduction_fs


def _frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def _split_frame(data: bytes) -> tuple[bytes, bytes]:
    size = struct.unpack("!I", data[:4])[0]
    return data[: 4 + size], data[4 + size :]


def test_context_and_ack_wire_bytes_remain_the_existing_protocol() -> None:
    accepted = encode_sandbox_acknowledgement_frame(
        SandboxContextAcknowledgement(protocol_version="1", status="accepted")
    )
    assert accepted == b'\x00\x00\x00,{"protocol_version":"1","status":"accepted"}'
    decoded = decode_sandbox_acknowledgement_frame(accepted)
    assert decoded.status == "accepted"
    assert encode_sandbox_context_frame(_manifest()) == (
        b'\x00\x00\x00\x8b{"context_version":"1","control_id":"7.1.1",'
        b'"source_state":{"passwd_file_group_gid":0,"passwd_file_mode":"0664",'
        b'"passwd_file_owner_uid":0}}'
    )
    assert MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES == 4096


def test_context_fingerprint_hashes_only_the_existing_canonical_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    canonical_frame = encode_sandbox_context_frame(manifest)
    calls: list[bytes] = []
    original_encoder = context_binding.encode_sandbox_context_frame

    def record_encoder(value: SandboxContextManifest) -> bytes:
        encoded = original_encoder(value)
        calls.append(encoded)
        return encoded

    monkeypatch.setattr(context_binding, "encode_sandbox_context_frame", record_encoder)
    import inspect

    assert list(inspect.signature(sandbox_context_sha256).parameters) == ["manifest"]
    assert sandbox_context_sha256(manifest) == hashlib.sha256(canonical_frame).hexdigest()
    assert calls == [canonical_frame]
    assert _PASSWD_TEXT.encode() not in canonical_frame


@pytest.mark.parametrize(
    "changed",
    [
        _manifest(mode="0600"),
        _manifest(uid=1001),
        _manifest(gid=1002),
    ],
    ids=["mode", "uid", "gid"],
)
def test_context_fingerprint_changes_for_each_source_state_field(
    changed: SandboxContextManifest,
) -> None:
    assert sandbox_context_sha256(changed) != sandbox_context_sha256(_manifest())


def test_authorization_model_has_only_controller_owned_fields_and_fixed_lineage() -> None:
    job = _job()
    authorization = build_sandbox_m5_authorization(job, _manifest())
    assert set(SandboxM5ControllerAuthorization.model_fields) == {
        "protocol_version",
        "validation_job_id",
        "profile_id",
        "compatibility_report_id",
        "context_sha256",
        "control_id",
        "administrator_approval_acknowledged",
        "compatibility_risk_acknowledged",
        "compatibility_override_reason",
        "compatibility_reference",
    }
    assert "sandbox_operator_acknowledged" not in SandboxM5ControllerAuthorization.model_fields
    assert authorization.validation_job_id == job.validation_job_id
    assert authorization.profile_id == job.profile_id
    assert authorization.compatibility_report_id == job.compatibility_report_id
    assert authorization.compatibility_reference == job.compatibility_reference
    assert authorization.model_config["frozen"] is True
    assert authorization.context_sha256 == sandbox_context_sha256(_manifest())


def test_controller_builder_requires_and_validates_both_job_and_manifest() -> None:
    import inspect

    signature = inspect.signature(build_sandbox_m5_authorization)
    assert list(signature.parameters) == ["job", "manifest"]
    assert all(
        parameter.default is inspect.Parameter.empty
        for parameter in signature.parameters.values()
    )
    valid_manifest = _manifest()
    invalid_manifest = SandboxContextManifest.model_construct(
        context_version="1",
        control_id="7.1.1",
        source_state=valid_manifest.source_state.model_copy(
            update={"passwd_file_owner_uid": -1}
        ),
    )
    with pytest.raises(SandboxM5ControllerError):
        build_sandbox_m5_authorization(_job(), invalid_manifest)


def test_authorization_requires_lowercase_sha256_context_fingerprint() -> None:
    values = build_sandbox_m5_authorization(_job(), _manifest()).model_dump(mode="json")
    values["context_sha256"] = "A" * 64
    with pytest.raises(ValidationError):
        SandboxM5ControllerAuthorization.model_validate(values)
    values["context_sha256"] = "a" * 63
    with pytest.raises(ValidationError):
        SandboxM5ControllerAuthorization.model_validate(values)


@pytest.mark.parametrize(
    "change",
    [
        {"control_id": "5.1.20"},
        {"compatibility_reference": {**_compatibility().model_dump(mode="json"), "control_id": "5.1.20"}},
        {"sandbox_operator_acknowledged": True},
        {"path": "/etc/passwd"},
        {"command": "anything"},
        {"argv": ["anything"]},
        {"adapter": "anything"},
        {"service": "ssh"},
        {"root": "/"},
    ],
)
def test_authorization_wire_model_rejects_unapproved_fields_and_controls(
    change: dict[str, object],
) -> None:
    values = build_sandbox_m5_authorization(_job(), _manifest()).model_dump(mode="json")
    values.update(change)
    with pytest.raises(ValidationError):
        SandboxM5ControllerAuthorization.model_validate(values)


def test_controller_builder_copies_only_the_dispatched_validation_job() -> None:
    job = _job()
    authorization = build_sandbox_m5_authorization(job, _manifest())
    assert authorization.administrator_approval_acknowledged is True
    assert authorization.compatibility_risk_acknowledged is False
    assert authorization.compatibility_override_reason is None
    pending = job.model_copy(update={"status": JobStatus.PENDING, "dispatched_at": None})
    with pytest.raises(SandboxM5ControllerError):
        build_sandbox_m5_authorization(pending, _manifest())


def test_guest_session_local_operator_false_reaches_m5_without_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, stream, observed, files, reproduction_fs = _run_guest(
        monkeypatch,
        tmp_path,
        sandbox_operator_acknowledged=False,
    )
    control = result.report.control_results[0]
    assert type(result.report) is ValidationReport
    assert control.result is ValidationDecision.NOT_TESTED
    assert control.precheck.sandbox_operator_acknowledged is False
    assert control.remediation.attempted is False
    assert "set_metadata" not in files.operations
    assert observed["request"].sandbox_operator_acknowledged is False
    assert reproduction_fs.opens[0][0] == "/etc/passwd"
    assert reproduction_fs.opens[0][1] & os.O_NOFOLLOW
    assert len(stream.outgoing) > 0
    ack_frame, result_frame = _split_frame(bytes(stream.outgoing))
    assert decode_sandbox_acknowledgement_frame(ack_frame).status == "accepted"
    decoded = decode_sandbox_m5_result_frame(result_frame)
    assert decoded.report == result.report


def test_guest_session_local_operator_true_runs_existing_passwd_adapter_in_tmp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, stream, observed, files, _reproduction_fs = _run_guest(
        monkeypatch,
        tmp_path,
        sandbox_operator_acknowledged=True,
    )
    control = result.report.control_results[0]
    assert control.result is ValidationDecision.VALIDATED
    assert control.precheck.sandbox_operator_acknowledged is True
    assert control.remediation.attempted is True
    assert control.remediation.backups[0].created is True
    assert control.post_audit[0].value == "0644"
    assert all(check.status.value == "passed" for check in control.health_checks if check.required)
    assert isinstance(observed["validator"].adapters["7.1.1"], PasswdPermissionsAdapter)
    assert files.entries[tmp_path / "etc" / "passwd"][1:4] == (0o644, 0, 0)
    assert observed["request"].administrator_approval_acknowledged is True
    assert observed["inputs"].compatibility == _compatibility()
    assert result.reproduction.target_path == "/etc/passwd"
    assert result.reproduction.reproduced is True
    assert _PASSWD_TEXT.encode() not in encode_sandbox_m5_result_frame(result)
    ack_frame, result_frame = _split_frame(bytes(stream.outgoing))
    assert decode_sandbox_acknowledgement_frame(ack_frame).status == "accepted"
    assert decode_sandbox_m5_result_frame(result_frame) == result


def test_rejected_context_stops_before_authorization_reproduction_and_m5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reproduction_calls: list[object] = []
    monkeypatch.setattr(
        "src.sandbox_m5_session.reproduce_passwd_source_state",
        lambda value: reproduction_calls.append(value),
    )
    stream = _MemoryDuplex(b"\x00\x00\x00\x00" + b"authorization-must-remain-unread")
    with pytest.raises(SandboxM5SessionError):
        run_sandbox_m5_session(stream, sandbox_operator_acknowledged=True)
    assert reproduction_calls == []
    assert stream.offset == 4
    ack = decode_sandbox_acknowledgement_frame(bytes(stream.outgoing))
    assert ack.status == "rejected"
    assert ack.reason_code == SandboxContextRejectionCode.INVALID_FRAME


def test_malformed_authorization_stops_before_reproduction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[object] = []
    monkeypatch.setattr(
        "src.sandbox_m5_session.reproduce_passwd_source_state",
        lambda value: called.append(value),
    )
    values = build_sandbox_m5_authorization(_job(), _manifest()).model_dump(mode="json")
    values["profile_id"] = str(uuid4())
    authorization_frame = _frame(
        json.dumps(values, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    )
    stream = _MemoryDuplex(encode_sandbox_context_frame(_manifest()) + authorization_frame)
    with pytest.raises(SandboxM5SessionError):
        run_sandbox_m5_session(stream, sandbox_operator_acknowledged=True)
    assert called == []


def test_authorization_for_manifest_a_rejects_manifest_b_before_reproduction_or_m5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_a = _manifest()
    manifest_b = _manifest(mode="0600")
    authorization_a = build_sandbox_m5_authorization(_job(), manifest_a)
    reproduction_fs = _MemoryReproductionFilesystem()
    monkeypatch.setattr(reproduction, "_FILESYSTEM", reproduction_fs)
    monkeypatch.setattr(
        sandbox_m5_validation,
        "SandboxValidator",
        lambda **_kwargs: pytest.fail("context mismatch reached M5"),
    )
    stream = _MemoryDuplex(
        encode_sandbox_context_frame(manifest_b)
        + encode_sandbox_m5_authorization_frame(authorization_a)
    )

    with pytest.raises(SandboxM5SessionError):
        run_sandbox_m5_session(stream, sandbox_operator_acknowledged=True)

    assert reproduction_fs.opens == []
    ack_frame, remainder = _split_frame(bytes(stream.outgoing))
    assert decode_sandbox_acknowledgement_frame(ack_frame).status == "accepted"
    assert remainder == b""


def test_local_operator_ack_argument_is_mandatory_and_strict() -> None:
    import inspect

    parameter = inspect.signature(run_sandbox_m5_session).parameters[
        "sandbox_operator_acknowledged"
    ]
    assert parameter.default is inspect.Parameter.empty
    with pytest.raises(SandboxM5SessionError):
        run_sandbox_m5_session(_MemoryDuplex(), sandbox_operator_acknowledged=1)  # type: ignore[arg-type]


def test_controller_transaction_validates_guest_result_and_returns_existing_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, guest_stream, _observed, _files, _rep_fs = _run_guest(
        monkeypatch,
        tmp_path,
        sandbox_operator_acknowledged=True,
    )
    controller_stream = _MemoryDuplex(bytes(guest_stream.outgoing))
    payload = run_sandbox_m5_controller_transaction(
        controller_stream,
        manifest=_manifest(),
        job=_job(),
    )
    assert type(payload) is ValidationResultPayload
    assert payload.validation_job_id == _JOB_ID
    assert payload.profile_id == _PROFILE_ID
    assert payload.compatibility_report_id == _REPORT_ID
    assert payload.report == result.report
    assert result.context_sha256 == sandbox_context_sha256(_manifest())
    context_frame, remainder = _split_frame(bytes(controller_stream.outgoing))
    assert context_frame == encode_sandbox_context_frame(_manifest())
    assert decode_sandbox_m5_authorization_frame(remainder).validation_job_id == _JOB_ID


def test_controller_rejects_context_ack_before_sending_authorization() -> None:
    rejected = encode_sandbox_acknowledgement_frame(
        SandboxContextAcknowledgement(
            protocol_version="1",
            status="rejected",
            reason_code=SandboxContextRejectionCode.INVALID_CONTEXT,
        )
    )
    stream = _MemoryDuplex(rejected)
    with pytest.raises(SandboxM5ControllerError):
        run_sandbox_m5_controller_transaction(stream, manifest=_manifest(), job=_job())
    assert bytes(stream.outgoing) == encode_sandbox_context_frame(_manifest())


@pytest.mark.parametrize(
    "field",
    ["validation_job_id", "profile_id", "compatibility_report_id", "control_id"],
)
def test_controller_result_validation_rejects_mismatched_lineage(
    field: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result, _stream, _observed, _files, _rep_fs = _run_guest(
        monkeypatch,
        tmp_path,
        sandbox_operator_acknowledged=False,
    )
    updates: dict[str, object] = {field: "5.1.20" if field == "control_id" else uuid4()}
    forged_values = {
        "protocol_version": result.protocol_version,
        "validation_job_id": result.validation_job_id,
        "profile_id": result.profile_id,
        "compatibility_report_id": result.compatibility_report_id,
        "context_sha256": result.context_sha256,
        "control_id": result.control_id,
        "reproduction": result.reproduction,
        "report": result.report,
    }
    forged_values.update(updates)
    forged = SandboxM5SessionResult.model_construct(**forged_values)
    with pytest.raises(SandboxM5ControllerError):
        sandbox_m5_result_to_validation_payload(_job(), forged, _manifest())


def test_controller_rejects_result_with_wrong_context_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result, _stream, _observed, _files, _rep_fs = _run_guest(
        monkeypatch,
        tmp_path,
        sandbox_operator_acknowledged=False,
    )
    forged = SandboxM5SessionResult.model_construct(
        protocol_version=result.protocol_version,
        validation_job_id=result.validation_job_id,
        profile_id=result.profile_id,
        compatibility_report_id=result.compatibility_report_id,
        context_sha256="0" * 64,
        control_id=result.control_id,
        reproduction=result.reproduction,
        report=result.report,
    )
    with pytest.raises(SandboxM5ControllerError):
        sandbox_m5_result_to_validation_payload(_job(), forged, _manifest())


def test_result_envelope_requires_execute_single_control_and_matching_m4_lineage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, _stream, _observed, _files, _rep_fs = _run_guest(
        monkeypatch,
        tmp_path,
        sandbox_operator_acknowledged=False,
    )
    assert result.report.mode is ExecutionMode.EXECUTE
    assert len(result.report.control_results) == 1
    assert result.report.control_results[0].m4_input == _compatibility()
    assert result.report.control_results[0].m3_profile_source == _compatibility().profile_source


def test_valid_result_is_below_the_fixed_m5_frame_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, _stream, _observed, _files, _rep_fs = _run_guest(
        monkeypatch,
        tmp_path,
        sandbox_operator_acknowledged=False,
    )
    frame = encode_sandbox_m5_result_frame(result)
    assert len(frame) - 4 <= MAX_SANDBOX_M5_PAYLOAD_BYTES
    assert frame[:4] == struct.pack("!I", len(frame) - 4)


@pytest.mark.parametrize(
    "bad_frame",
    [
        b"\x00\x00\x00\x00",
        struct.pack("!I", MAX_SANDBOX_M5_PAYLOAD_BYTES + 1),
        b"\x00\x00",
        struct.pack("!I", 5) + b"x",
        _frame(b"\xff"),
        _frame(b"[]"),
        _frame(b'{"same":1,"same":2}'),
        _frame(b'{"x":NaN}'),
    ],
    ids=["zero", "oversized", "short-header", "truncated", "invalid-utf8", "non-object", "duplicate-key", "non-json-constant"],
)
def test_m5_authorization_decoder_rejects_invalid_frames(bad_frame: bytes) -> None:
    with pytest.raises(SandboxM5TransportError):
        decode_sandbox_m5_authorization_frame(bad_frame)


def test_m5_authorization_decoder_rejects_noncanonical_trailing_and_extra_fields() -> None:
    valid = encode_sandbox_m5_authorization_frame(
        build_sandbox_m5_authorization(_job(), _manifest())
    )
    payload = valid[4:]
    pretty = _frame(json.dumps(json.loads(payload), indent=2, sort_keys=True).encode())
    trailing = valid + b"x"
    values = json.loads(payload)
    values["sandbox_operator_acknowledged"] = True
    extra = _frame(
        json.dumps(values, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    )
    for candidate in (pretty, trailing, extra):
        with pytest.raises(SandboxM5TransportError):
            decode_sandbox_m5_authorization_frame(candidate)


def test_m5_result_decoder_rejects_oversized_or_trailing_frames(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, _stream, _observed, _files, _rep_fs = _run_guest(
        monkeypatch,
        tmp_path,
        sandbox_operator_acknowledged=False,
    )
    frame = encode_sandbox_m5_result_frame(result)
    with pytest.raises(SandboxM5TransportError):
        decode_sandbox_m5_result_frame(frame + b"extra")
    with pytest.raises(SandboxM5TransportError):
        decode_sandbox_m5_result_frame(struct.pack("!I", MAX_SANDBOX_M5_PAYLOAD_BYTES + 1))


@pytest.mark.parametrize(
    "payload",
    [
        b"{",
        b"[]",
        b'{"same":1,"same":2}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b"\xff",
        b'{"protocol_version":"1","unexpected":true}',
    ],
    ids=["malformed-json", "non-object", "duplicate-key", "nan", "infinity", "invalid-utf8", "extra-field"],
)
def test_malformed_m5_result_payloads_are_rejected(payload: bytes) -> None:
    with pytest.raises(SandboxM5TransportError):
        decode_sandbox_m5_result_frame(_frame(payload))


def test_transport_reads_partial_frames_and_controller_lineage_is_strict(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, guest_stream, _observed, _files, _rep_fs = _run_guest(
        monkeypatch,
        tmp_path,
        sandbox_operator_acknowledged=False,
    )
    stream = _MemoryDuplex(bytes(guest_stream.outgoing), read_limit=1, write_limit=2)
    payload = run_sandbox_m5_controller_transaction(stream, manifest=_manifest(), job=_job())
    assert payload.report == result.report
    assert payload.validation_job_id == _JOB_ID


def test_session_uses_one_context_and_no_agent_or_generic_execution_surface() -> None:
    source_paths = (
        Path("src/sandbox_m5_session.py"),
        Path("src/controller/sandbox_m5.py"),
        Path("src/sandbox_m5_protocol/context.py"),
        Path("src/sandbox_m5_protocol/models.py"),
        Path("src/sandbox_m5_protocol/transport.py"),
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in source_paths)
    lowered = source.casefold()
    for forbidden in (
        "subprocess",
        "paramiko",
        "os.system",
        "shell=true",
        "eval(",
        "exec(",
        "agentruntime",
        "heartbeat",
        "poll_jobs",
        "qemu guest agent",
        "socket listener",
    ):
        assert forbidden not in lowered
    assert "reproduce_passwd_source_state" in source
    assert "run_m5_validation_after_reproduction" in source
    assert "run_sandbox_m5_session" in source
    assert "libvirt" not in lowered


def test_m5_wire_size_is_independent_of_context_frame_limit() -> None:
    assert MAX_SANDBOX_M5_PAYLOAD_BYTES == 65536
    assert MAX_SANDBOX_M5_PAYLOAD_BYTES > MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES
