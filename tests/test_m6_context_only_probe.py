"""Offline tests for the one-shot context-only Ubuntu diagnostic."""

from __future__ import annotations

import ast
import hashlib
import logging
from pathlib import Path
import re
import sqlite3
import stat
from types import SimpleNamespace
from uuid import uuid4

import pytest

from scripts import m6_context_only_probe as probe
from src.sandbox_protocol import (
    PasswdSourceState,
    SandboxContextAcknowledgement,
    SandboxContextManifest,
    encode_sandbox_acknowledgement_frame,
    encode_sandbox_context_frame,
)


class FakeStream:
    def __init__(self, incoming: bytes, *, read_limit: int = 65536) -> None:
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.read_limit = read_limit

    def write(self, data: bytes) -> int:
        count = min(3, len(data))
        self.sent.extend(data[:count])
        return count

    def read(self, size: int) -> bytes:
        count = min(size, self.read_limit, len(self.incoming))
        chunk = bytes(self.incoming[:count])
        del self.incoming[:count]
        return chunk


def _manifest() -> SandboxContextManifest:
    return SandboxContextManifest(
        context_version="1",
        control_id="7.1.1",
        source_state=PasswdSourceState(
            passwd_file_mode="0644",
            passwd_file_owner_uid=0,
            passwd_file_group_gid=0,
        ),
    )


def _ack(status: str) -> bytes:
    if status == "accepted":
        model = SandboxContextAcknowledgement(
            protocol_version="1", status="accepted"
        )
    else:
        from src.sandbox_protocol import SandboxContextRejectionCode

        model = SandboxContextAcknowledgement(
            protocol_version="1",
            status="rejected",
            reason_code=SandboxContextRejectionCode.INVALID_CONTEXT,
        )
    return encode_sandbox_acknowledgement_frame(model)


def test_context_only_probe_sends_exact_canonical_frame_then_stops(
    capsys: pytest.CaptureFixture[str],
) -> None:
    stream = FakeStream(_ack("accepted"), read_limit=1)

    acknowledgement = probe._context_only_exchange(stream, _manifest())

    assert acknowledgement.status == "accepted"
    assert bytes(stream.sent) == encode_sandbox_context_frame(_manifest())
    assert stream.incoming == b""
    lines = capsys.readouterr().out.splitlines()
    assert [line.split(" controller ", 1)[1] for line in lines] == [
        "context_write_start",
        "context_write_complete",
        "ack_header_wait",
        "ack_header_complete",
        "ack_payload_complete",
        "ack_accepted",
    ]
    assert "source_state" not in "\n".join(lines)
    assert all(re.match(r"^\d{4}-\d\d-\d\dT.*Z controller ", line) for line in lines)


def test_context_only_probe_reports_rejection_without_followup_write(
    capsys: pytest.CaptureFixture[str],
) -> None:
    stream = FakeStream(_ack("rejected"))

    acknowledgement = probe._context_only_exchange(stream, _manifest())

    assert acknowledgement.status == "rejected"
    assert bytes(stream.sent) == encode_sandbox_context_frame(_manifest())
    assert "controller ack_rejected" in capsys.readouterr().out


def test_context_only_probe_missing_ack_fails_before_any_followup_frame(
    capsys: pytest.CaptureFixture[str],
) -> None:
    stream = FakeStream(b"")

    with pytest.raises(probe.ProbeRefused):
        probe._context_only_exchange(stream, _manifest())

    assert bytes(stream.sent) == encode_sandbox_context_frame(_manifest())
    output = capsys.readouterr().out
    assert "controller ack_header_wait" in output
    assert "controller ack_header_complete" not in output


def test_diagnostic_source_has_no_m5_authorization_or_validation_call() -> None:
    source = Path(probe.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "src.controller.sandbox_m5" not in imports
    assert "src.sandbox_m5_protocol.transport" not in imports
    for forbidden in (
        "SandboxM5ControllerAuthorization",
        "write_sandbox_m5_authorization",
        "run_controller_owned_sandbox_validation",
        "run_m5_validation_after_reproduction",
        "ValidationJobCreateRequest",
        "create_and_dispatch_sandbox_validation_job",
    ):
        assert forbidden not in source.split("def _parser()", 1)[1]


def test_reviewed_guest_hashes_match_the_instrumented_source() -> None:
    for name, expected in probe.GUEST_FILE_SHA256.items():
        path = probe.REPOSITORY_ROOT / "src" / "sandbox_runtime" / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected


def test_probe_pins_the_recorded_sealed_v3_base() -> None:
    assert str(probe.SEALED_BASE) == (
        "/var/lib/sentra/base/sentra-sandbox-appliance-v3.qcow2"
    )
    assert probe.SEALED_BASE_SHA256 == (
        "65cee52d702871c9ba2174d680ae9eadd94fdf6fac71cedf611300c09048590a"
    )


def test_explicit_admin_approval_is_required_before_base_or_vm_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        probe,
        "_verify_sealed_base",
        lambda: pytest.fail("base must not be opened without approval"),
    )
    args = SimpleNamespace(administrator_sandbox_approval_acknowledged=False)
    with pytest.raises(probe.ProbeRefused):
        probe.run(args)


def test_timeout_output_has_only_timestamp_stage_and_exception_type(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_args: object) -> bool:
        raise TimeoutError("manifest and credential must not appear")

    parser = SimpleNamespace(parse_args=lambda _argv: object())
    monkeypatch.setattr(probe, "run", fail)
    monkeypatch.setattr(probe, "_parser", lambda: parser)
    transport_logger = logging.getLogger("src.controller.sandbox")
    was_disabled = transport_logger.disabled

    assert probe.main([]) == 2
    assert transport_logger.disabled is was_disabled

    output = capsys.readouterr()
    assert output.err == ""
    lines = output.out.splitlines()
    assert len(lines) == 2
    assert lines[0].endswith(" controller stream_read_timeout")
    assert lines[1].endswith(" controller failure=TimeoutError")
    assert all("manifest" not in line and "credential" not in line for line in lines)


def test_saved_database_is_backed_up_into_isolated_protected_file(
    tmp_path: Path,
) -> None:
    source = tmp_path / "saved.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE evidence (value TEXT NOT NULL)")
        connection.execute("INSERT INTO evidence (value) VALUES ('saved')")
    source.chmod(0o600)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    proof = tmp_path / "proof"
    proof.mkdir(mode=0o700)

    snapshot = probe._snapshot_database(source, proof)

    assert snapshot != source
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600
    with sqlite3.connect(snapshot) as connection:
        assert connection.execute("SELECT value FROM evidence").fetchone() == ("saved",)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


def test_saved_database_with_wal_sidecar_is_refused_without_write(
    tmp_path: Path,
) -> None:
    source = tmp_path / "saved.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE evidence (value TEXT NOT NULL)")
    source.chmod(0o600)
    sidecar = tmp_path / "saved.sqlite3-wal"
    sidecar.write_bytes(b"offline-test-sidecar")
    proof = tmp_path / "proof"
    proof.mkdir(mode=0o700)
    before = source.read_bytes()

    with pytest.raises(probe.ProbeRefused):
        probe._snapshot_database(source, proof)

    assert source.read_bytes() == before
    assert sidecar.read_bytes() == b"offline-test-sidecar"
    assert not (proof / "controller-isolated.sqlite3").exists()


def test_guest_sources_are_frozen_with_reviewed_hashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_dir = tmp_path / "repo" / "src" / "sandbox_runtime"
    source_dir.mkdir(parents=True)
    files = {"receiver.py": b"receiver", "session_channel.py": b"channel", "__main__.py": b"main"}
    for name, data in files.items():
        (source_dir / name).write_bytes(data)
    monkeypatch.setattr(probe, "REPOSITORY_ROOT", tmp_path / "repo")
    monkeypatch.setattr(
        probe,
        "GUEST_FILE_SHA256",
        {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    )
    proof = tmp_path / "proof"
    proof.mkdir()

    snapshots = probe._snapshot_guest_files(proof)

    assert {path.name: path.read_bytes() for path in snapshots} == files
    assert all(path.parent == proof / "guest-files" for path in snapshots)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in snapshots)


def test_overlay_staging_uses_only_fresh_undefined_session_volume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeBackend:
        pool: object | None = None
        domain: object | None = None
        validations = 0

        def _expect_libvirt_plan(self, _plan: object) -> None:
            pass

        def _open(self, _plan: object) -> tuple[object, object]:
            return object(), object()

        def _close(self, _connection: object) -> None:
            pass

        def _lookup_domain(self, _connection: object, _libvirt: object, _plan: object):
            return self.domain

        def _lookup_pool(self, _connection: object, _libvirt: object, _plan: object):
            return self.pool

        def _ensure_pool(self, _connection: object, _libvirt: object, _plan: object):
            self.pool = object()
            return self.pool

        def _create_or_reconcile_volume(self, _pool: object, _libvirt: object, _plan: object):
            return object()

        def _lookup_volume(self, _pool: object, _libvirt: object):
            return object()

        def _validate_volume(self, _volume: object, _plan: object) -> None:
            self.validations += 1

    backend = FakeBackend()
    overlay = tmp_path / "new-session" / "root.qcow2"
    plan = SimpleNamespace(overlay_path=overlay)
    probe._prepare_fresh_overlay(backend, plan)
    assert backend.pool is not None
    assert backend.domain is None

    reviewed = tmp_path / "receiver.py"
    reviewed.write_bytes(b"reviewed")
    monkeypatch.setattr(
        probe,
        "GUEST_FILE_SHA256",
        {"receiver.py": hashlib.sha256(b"reviewed").hexdigest()},
    )
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        return SimpleNamespace(stdout=b"reviewed" if argv[0] == probe._VIRT_CAT else b"")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    probe._stage_in_stopped_overlay(backend, plan, [reviewed])

    assert backend.domain is None
    assert backend.validations == 3
    assert calls[0] == [
        probe._VIRT_COPY_IN,
        "--format=qcow2",
        "-a",
        str(overlay),
        str(reviewed),
        probe.GUEST_DESTINATION,
    ]
    assert calls[1][0] == probe._VIRT_CAT
    assert str(overlay) in calls[1]


def test_existing_session_resource_is_rejected_before_pool_creation(
    tmp_path: Path,
) -> None:
    class ExistingBackend:
        def _expect_libvirt_plan(self, _plan: object) -> None:
            pass

        def _open(self, _plan: object) -> tuple[object, object]:
            return object(), object()

        def _close(self, _connection: object) -> None:
            pass

        def _lookup_domain(self, _connection: object, _libvirt: object, _plan: object):
            return object()

        def _ensure_pool(self, *_args: object) -> None:
            pytest.fail("must not touch a pre-existing resource")

    plan = SimpleNamespace(overlay_path=tmp_path / "session" / "root.qcow2")
    with pytest.raises(probe.ProbeRefused):
        probe._prepare_fresh_overlay(ExistingBackend(), plan)


def test_staging_refuses_any_already_defined_guest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DefinedBackend:
        def _open(self, _plan: object) -> tuple[object, object]:
            return object(), object()

        def _close(self, _connection: object) -> None:
            pass

        def _lookup_domain(self, _connection: object, _libvirt: object, _plan: object):
            return object()

    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("staging must precede domain definition"),
    )
    plan = SimpleNamespace(overlay_path=tmp_path / "new" / "root.qcow2")
    with pytest.raises(probe.ProbeRefused):
        probe._stage_in_stopped_overlay(DefinedBackend(), plan, [])
