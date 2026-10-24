from __future__ import annotations

import ast
import json
import re
import struct
from pathlib import Path
from typing import Any

import pytest

from src.controller.sandbox_context import (
    PasswdSourceState as ControllerPasswdSourceState,
    SandboxContextManifest as ControllerSandboxContextManifest,
)
from src.controller.sandbox_transport import (
    SandboxContextAcknowledgement as ControllerSandboxContextAcknowledgement,
    encode_sandbox_context_frame,
)
from src.controller.sandbox_transport import (
    decode_sandbox_context_frame as ControllerDecodeSandboxContext,
)
from src.sandbox_protocol import (
    SENTRA_VALIDATION_CHANNEL_NAME,
    PasswdSourceState,
    SandboxContextAcknowledgement,
    SandboxContextManifest,
    SandboxContextRejectionCode,
    decode_sandbox_acknowledgement_frame,
)
from src.sandbox_runtime import receiver as receiver_module
from src.sandbox_runtime.receiver import (
    SENTRA_VALIDATION_DEVICE_PATH,
    SandboxContextReceiveResult,
    SandboxReceiverIOError,
    open_fixed_validation_channel_and_receive,
    receive_one_context,
)


_HEADER_BYTES = 4
_MAX_PAYLOAD_BYTES = 4096
_REPO_ROOT = Path(__file__).resolve().parents[1]


class ChunkedDuplex:
    """Controlled binary stream that can fragment reads and writes."""

    def __init__(
        self,
        incoming: bytes,
        *,
        read_limit: int = 65536,
        write_limit: int = 65536,
    ) -> None:
        self.incoming = bytearray(incoming)
        self.read_limit = read_limit
        self.write_limit = write_limit
        self.read_sizes: list[int] = []
        self.bytes_read = 0
        self.written = bytearray()
        self.write_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if not self.incoming:
            return b""
        requested = len(self.incoming) if size < 0 else size
        count = min(requested, self.read_limit, len(self.incoming))
        chunk = bytes(self.incoming[:count])
        del self.incoming[:count]
        self.bytes_read += count
        return chunk

    def write(self, data: bytes) -> int:
        count = min(len(data), self.write_limit)
        self.write_sizes.append(count)
        self.written.extend(data[:count])
        return count


class InitialEmptyReads(ChunkedDuplex):
    """Return a fixed number of pre-connection empty reads before frame bytes."""

    def __init__(
        self,
        incoming: bytes,
        *,
        initial_empty_reads: int,
        **kwargs: Any,
    ) -> None:
        super().__init__(incoming, **kwargs)
        self.initial_empty_reads = initial_empty_reads

    def read(self, size: int = -1) -> bytes:
        if self.initial_empty_reads:
            self.initial_empty_reads -= 1
            self.read_sizes.append(size)
            return b""
        return super().read(size)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.delays: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.delays.append(seconds)
        self.now += seconds


def _manifest() -> SandboxContextManifest:
    return SandboxContextManifest(
        context_version="1",
        control_id="7.1.1",
        source_state=PasswdSourceState(
            passwd_file_mode="0666",
            passwd_file_owner_uid=42,
            passwd_file_group_gid=43,
        ),
    )


def _frame_payload(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def _json_frame(payload: Any) -> bytes:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _frame_payload(encoded)


def _raw_manifest_payload() -> dict[str, Any]:
    return {
        "context_version": "1",
        "control_id": "7.1.1",
        "source_state": {
            "passwd_file_mode": "0666",
            "passwd_file_owner_uid": 42,
            "passwd_file_group_gid": 43,
        },
    }


def _assert_ack(
    stream: ChunkedDuplex,
    *,
    status: str,
    reason_code: SandboxContextRejectionCode | None = None,
) -> SandboxContextAcknowledgement:
    ack = decode_sandbox_acknowledgement_frame(bytes(stream.written))
    expected = {"protocol_version": "1", "status": status}
    if reason_code is not None:
        expected["reason_code"] = reason_code.value
    assert ack.model_dump(mode="json", exclude_none=True) == expected
    return ack


def test_valid_manifest_is_accepted_and_returned_unchanged() -> None:
    manifest = _manifest()
    stream = ChunkedDuplex(encode_sandbox_context_frame(manifest))

    result = receive_one_context(stream)

    assert isinstance(result, SandboxContextReceiveResult)
    assert result.manifest == manifest
    _assert_ack(stream, status="accepted")


def test_receiver_diagnostics_identify_frame_and_ack_stages_without_payload(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stream = ChunkedDuplex(encode_sandbox_context_frame(_manifest()))

    result = receive_one_context(stream)

    assert result.acknowledgement.status == "accepted"
    messages = [record.getMessage() for record in caplog.records]
    for stage in (
        "header_wait",
        "first_byte_received",
        "header_complete",
        "payload_read_start",
        "payload_complete",
        "context_decoded",
        "ack_write_start",
        "ack_write_complete",
    ):
        assert any(f"guest {stage}" in message for message in messages)
    assert "0666" not in " ".join(messages)
    assert "passwd_file_mode" not in " ".join(messages)
    assert "source_state" not in " ".join(messages)
    assert all(re.match(r"^\d{4}-\d\d-\d\dT.*Z guest ", message) for message in messages)


def test_initial_empty_reads_before_first_header_byte_are_tolerated() -> None:
    stream = InitialEmptyReads(
        encode_sandbox_context_frame(_manifest()), initial_empty_reads=2
    )

    result = receive_one_context(stream)

    assert result.manifest == _manifest()
    assert stream.read_sizes[:2] == [_HEADER_BYTES, _HEADER_BYTES]
    _assert_ack(stream, status="accepted")


def test_initial_empty_reads_then_fragmented_header_and_payload_are_accepted() -> None:
    stream = InitialEmptyReads(
        encode_sandbox_context_frame(_manifest()),
        initial_empty_reads=4,
        read_limit=1,
    )

    result = receive_one_context(stream)

    assert result.manifest == _manifest()
    assert stream.read_sizes[:4] == [_HEADER_BYTES] * 4
    assert stream.read_sizes[4:8] == [
        _HEADER_BYTES,
        _HEADER_BYTES - 1,
        _HEADER_BYTES - 2,
        _HEADER_BYTES - 3,
    ]
    _assert_ack(stream, status="accepted")


def test_startup_timeout_fails_as_io_without_invalid_frame_ack(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = FakeClock()
    monkeypatch.setattr(receiver_module, "_monotonic", clock.monotonic)
    monkeypatch.setattr(receiver_module, "_sleep", clock.sleep)
    stream = ChunkedDuplex(b"")

    with pytest.raises(SandboxReceiverIOError, match="timed out"):
        receive_one_context(stream)

    assert stream.written == b""
    assert any(
        "guest first_byte_timeout" in record.getMessage()
        for record in caplog.records
    )
    assert any(
        "guest failure=SandboxReceiverIOError" in record.getMessage()
        for record in caplog.records
    )
    assert clock.now == receiver_module._FIRST_FRAME_STARTUP_TIMEOUT_SECONDS
    assert len(stream.read_sizes) <= (
        receiver_module._FIRST_FRAME_STARTUP_TIMEOUT_SECONDS
        / receiver_module._FIRST_FRAME_RETRY_INTERVAL_SECONDS
    ) + 1
    assert clock.delays
    assert all(
        delay <= receiver_module._FIRST_FRAME_RETRY_INTERVAL_SECONDS
        for delay in clock.delays
    )


def test_eof_after_first_header_byte_is_immediately_invalid_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = ChunkedDuplex(b"\x00", read_limit=1)
    monkeypatch.setattr(
        receiver_module,
        "_sleep",
        lambda _seconds: pytest.fail("mid-header EOF must not be retried"),
    )

    result = receive_one_context(stream)

    assert result.manifest is None
    _assert_ack(
        stream,
        status="rejected",
        reason_code=SandboxContextRejectionCode.INVALID_FRAME,
    )


def test_partial_header_reads_are_handled() -> None:
    frame = encode_sandbox_context_frame(_manifest())
    stream = ChunkedDuplex(frame, read_limit=1)

    result = receive_one_context(stream)

    assert result.manifest == _manifest()
    assert stream.read_sizes[:4] == [4, 3, 2, 1]


def test_partial_payload_reads_are_handled() -> None:
    frame = encode_sandbox_context_frame(_manifest())
    stream = ChunkedDuplex(frame, read_limit=2)

    result = receive_one_context(stream)

    assert result.manifest == _manifest()
    assert len(stream.read_sizes) > 2
    _assert_ack(stream, status="accepted")


def test_partial_acknowledgement_writes_are_completed() -> None:
    stream = ChunkedDuplex(encode_sandbox_context_frame(_manifest()), write_limit=3)

    result = receive_one_context(stream)

    assert result.acknowledgement.status == "accepted"
    assert len(stream.write_sizes) > 1
    _assert_ack(stream, status="accepted")


def test_eof_during_header_fails_closed_with_invalid_frame_ack(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stream = ChunkedDuplex(b"\x00\x00", read_limit=1)

    result = receive_one_context(stream)

    assert result.manifest is None
    _assert_ack(
        stream,
        status="rejected",
        reason_code=SandboxContextRejectionCode.INVALID_FRAME,
    )
    assert any(
        "guest header_incomplete" in record.getMessage()
        for record in caplog.records
    )


def test_eof_during_payload_fails_closed_with_invalid_frame_ack(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stream = ChunkedDuplex(struct.pack("!I", 8) + b"{}")

    result = receive_one_context(stream)

    assert result.manifest is None
    _assert_ack(
        stream,
        status="rejected",
        reason_code=SandboxContextRejectionCode.INVALID_FRAME,
    )
    assert any(
        "guest payload_incomplete" in record.getMessage()
        for record in caplog.records
    )


@pytest.mark.parametrize(
    "incoming",
    [
        struct.pack("!I", 0),
        struct.pack("!I", _MAX_PAYLOAD_BYTES + 1),
    ],
    ids=["zero-length", "oversized"],
)
def test_invalid_length_is_rejected_before_reading_payload(incoming: bytes) -> None:
    stream = ChunkedDuplex(incoming + b"unread-payload")

    result = receive_one_context(stream)

    assert result.manifest is None
    assert stream.bytes_read == _HEADER_BYTES
    assert stream.read_sizes == [_HEADER_BYTES]
    _assert_ack(
        stream,
        status="rejected",
        reason_code=SandboxContextRejectionCode.INVALID_FRAME,
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b"{not-json}",
        b"[]",
    ],
    ids=["invalid-utf8", "invalid-json", "non-object"],
)
def test_invalid_payload_encoding_is_rejected_as_invalid_context(
    payload: bytes,
) -> None:
    stream = ChunkedDuplex(_frame_payload(payload))

    result = receive_one_context(stream)

    assert result.manifest is None
    _assert_ack(
        stream,
        status="rejected",
        reason_code=SandboxContextRejectionCode.INVALID_CONTEXT,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_manifest_field",
        "extra_source_state_field",
        "wrong_control",
        "wrong_version",
        "malformed_mode",
        "uid_string",
        "gid_string",
        "uid_bool",
        "gid_bool",
        "uid_negative",
        "gid_negative",
    ],
)
def test_invalid_context_schema_is_rejected_without_diagnostics(
    mutation: str,
) -> None:
    payload = _raw_manifest_payload()
    source_state = payload["source_state"]
    if mutation == "extra_manifest_field":
        payload["hostname"] = "sensitive-hostname"
    elif mutation == "extra_source_state_field":
        source_state["arbitrary"] = {"nested": "not allowed"}
    elif mutation == "wrong_control":
        payload["control_id"] = "5.1.20"
    elif mutation == "wrong_version":
        payload["context_version"] = "2"
    elif mutation == "malformed_mode":
        source_state["passwd_file_mode"] = "0o666"
    elif mutation == "uid_string":
        source_state["passwd_file_owner_uid"] = "42"
    elif mutation == "gid_string":
        source_state["passwd_file_group_gid"] = "43"
    elif mutation == "uid_bool":
        source_state["passwd_file_owner_uid"] = True
    elif mutation == "gid_bool":
        source_state["passwd_file_group_gid"] = True
    elif mutation == "uid_negative":
        source_state["passwd_file_owner_uid"] = -1
    else:
        source_state["passwd_file_group_gid"] = -1
    stream = ChunkedDuplex(_json_frame(payload))

    result = receive_one_context(stream)

    assert result.manifest is None
    acknowledgement = _assert_ack(
        stream,
        status="rejected",
        reason_code=SandboxContextRejectionCode.INVALID_CONTEXT,
    )
    assert acknowledgement.model_dump(mode="json", exclude_none=True) == {
        "protocol_version": "1",
        "reason_code": "invalid_context",
        "status": "rejected",
    }


def test_duplicate_json_key_is_rejected_as_invalid_context() -> None:
    payload = (
        b'{"context_version":"1","context_version":"1",'
        b'"control_id":"7.1.1","source_state":{}}'
    )
    stream = ChunkedDuplex(_frame_payload(payload))

    result = receive_one_context(stream)

    assert result.manifest is None
    _assert_ack(
        stream,
        status="rejected",
        reason_code=SandboxContextRejectionCode.INVALID_CONTEXT,
    )


def test_noncanonical_json_is_rejected_as_invalid_context() -> None:
    payload = json.dumps(_raw_manifest_payload(), indent=2).encode("utf-8")
    stream = ChunkedDuplex(_frame_payload(payload))

    result = receive_one_context(stream)

    assert result.manifest is None
    _assert_ack(
        stream,
        status="rejected",
        reason_code=SandboxContextRejectionCode.INVALID_CONTEXT,
    )


def test_one_receive_leaves_second_message_unread_without_probe() -> None:
    first_frame = encode_sandbox_context_frame(_manifest())
    second_frame = encode_sandbox_context_frame(_manifest())
    stream = ChunkedDuplex(first_frame + second_frame)

    result = receive_one_context(stream)

    assert result.manifest == _manifest()
    assert stream.bytes_read == len(first_frame)
    assert bytes(stream.incoming) == second_frame


def test_acknowledgement_does_not_echo_manifest_data() -> None:
    stream = ChunkedDuplex(
        _frame_payload(b'{"context_version":"1","control_id":"bad"}')
    )

    receive_one_context(stream)

    ack_payload = bytes(stream.written)[_HEADER_BYTES:]
    assert b"passwd_file_mode" not in ack_payload
    assert b"0666" not in ack_payload
    assert b"sensitive-hostname" not in ack_payload


def test_receiver_fixed_device_path_and_entrypoint_have_no_path_argument() -> None:
    assert SENTRA_VALIDATION_DEVICE_PATH == (
        "/dev/virtio-ports/org.sentra.validation.0"
    )
    assert SENTRA_VALIDATION_DEVICE_PATH.endswith(SENTRA_VALIDATION_CHANNEL_NAME)
    assert not open_fixed_validation_channel_and_receive.__code__.co_argcount
    with pytest.raises(TypeError):
        open_fixed_validation_channel_and_receive(  # type: ignore[call-arg]
            "/tmp/other-channel"
        )


def test_controller_compatibility_imports_reexport_shared_schema_authority() -> None:
    from src.sandbox_protocol.transport import (
        decode_sandbox_acknowledgement_frame as shared_decode_ack,
        decode_sandbox_context_frame as shared_decode_context,
    )
    from src.controller.sandbox_transport import (
        decode_sandbox_acknowledgement_frame as controller_decode_ack,
    )

    assert ControllerPasswdSourceState is PasswdSourceState
    assert ControllerSandboxContextManifest is SandboxContextManifest
    assert ControllerSandboxContextAcknowledgement is SandboxContextAcknowledgement
    assert controller_decode_ack is shared_decode_ack
    assert ControllerDecodeSandboxContext is shared_decode_context


def _imports_from_python_file(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


def _has_forbidden_execution_calls(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                return True
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "system"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
            ):
                return True
        if isinstance(node, ast.keyword) and node.arg == "shell":
            if isinstance(node.value, ast.Constant) and node.value.value is True:
                return True
    return False


def _python_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.py"))


def test_shared_protocol_imports_no_controller_or_runtime_services() -> None:
    protocol_dir = _REPO_ROOT / "src" / "sandbox_protocol"
    imported = set().union(
        *(_imports_from_python_file(path) for path in _python_files(protocol_dir))
    )
    forbidden_prefixes = (
        "src.controller",
        "src.sandbox_runtime",
        "src.sandbox_validator",
        "src.target_profiler",
        "libvirt",
        "subprocess",
        "socket",
        "paramiko",
    )

    assert not any(
        name == prefix or name.startswith(prefix + ".")
        for name in imported
        for prefix in forbidden_prefixes
    )


def test_sandbox_runtime_imports_no_generic_execution_modules() -> None:
    runtime_dir = _REPO_ROOT / "src" / "sandbox_runtime"
    imported = set().union(
        *(_imports_from_python_file(path) for path in _python_files(runtime_dir))
    )
    forbidden_prefixes = (
        "subprocess",
        "socket",
        "paramiko",
        "libvirt",
        "src.agent",
        "src.controller",
        "src.sandbox_validator",
    )

    assert not any(
        name == prefix or name.startswith(prefix + ".")
        for name in imported
        for prefix in forbidden_prefixes
    )
    assert not any(
        _has_forbidden_execution_calls(path) for path in _python_files(runtime_dir)
    )


def test_shared_protocol_and_runtime_have_no_exec_eval_or_shell_true() -> None:
    checked_directories = (
        _REPO_ROOT / "src" / "sandbox_protocol",
        _REPO_ROOT / "src" / "sandbox_runtime",
    )

    assert not any(
        _has_forbidden_execution_calls(path)
        for directory in checked_directories
        for path in _python_files(directory)
    )


def test_partial_ack_write_failure_fails_closed() -> None:
    class BrokenWriter(ChunkedDuplex):
        def write(self, data: bytes) -> int:
            return 0

    stream = BrokenWriter(encode_sandbox_context_frame(_manifest()))

    with pytest.raises(SandboxReceiverIOError, match="write"):
        receive_one_context(stream)
