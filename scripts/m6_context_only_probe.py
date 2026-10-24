"""One-off, context-only probe for a fresh disposable SENTRA sandbox.

This diagnostic deliberately stops after the existing context ACK.  It does
not create a validation job, send M5 authorization, or execute M5.
Run only after operator review on the Ubuntu Controller, never on a target.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import logging
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import subprocess
from typing import BinaryIO, Sequence
from uuid import UUID, uuid4

from pydantic import SecretStr

from src.controller.models import (
    AdminAuth,
    CompatibilityAnalysisRequest,
    SandboxSessionCreateRequest,
    SandboxSessionStatus,
)
from src.controller.sandbox import (
    LibvirtBackend,
    LocalNestedVmConfig,
    LocalNestedVmPlan,
    LocalNestedVmProvider,
    SandboxManager,
    SandboxRuntimeState,
    SandboxStorageMode,
    _require_trusted_ancestry,
    _stat_trusted_base_image,
)
from src.controller.sandbox_context import derive_sandbox_context
from src.controller.service import ControllerService, ControllerSettings
from src.controller.storage import SQLiteControllerRepository
from src.controller.validation import compatibility_reference_from_record
from src.sandbox_protocol import (
    MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES,
    SandboxContextAcknowledgement,
    SandboxContextManifest,
    decode_sandbox_acknowledgement_frame,
    encode_sandbox_context_frame,
)


SEALED_BASE = Path("/var/lib/sentra/base/sentra-sandbox-appliance-v3.qcow2")
SEALED_BASE_SHA256 = "65cee52d702871c9ba2174d680ae9eadd94fdf6fac71cedf611300c09048590a"
GUEST_DESTINATION = "/opt/sentra/src/sandbox_runtime"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GUEST_FILE_SHA256 = {
    "receiver.py": "58c9438f2458b6f3f49ecb0b22c52e5be1f8bf126abeb2abf70e56c65a2acc5f",
    "session_channel.py": "fecfdc46a5c1742d2eba9f6473fce1085448234652fed1796b15b252bb0383c6",
    "__main__.py": "0ec42b415c473682f26156cf486d2e6ea600cc8bc4001904f6fdfed493cb2f6b",
}
_VIRT_COPY_IN = "/usr/bin/virt-copy-in"
_VIRT_CAT = "/usr/bin/virt-cat"


class ProbeRefused(RuntimeError):
    """Fixed, non-sensitive refusal for an unsafe diagnostic input."""


class _QuietParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ProbeRefused("invalid diagnostic arguments")


def _stage(event: str) -> None:
    """Emit only a timestamp and one fixed-stage token."""

    timestamp = datetime.now(UTC).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
    print(f"{timestamp} controller {event}", flush=True)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _verify_sealed_base() -> None:
    """Reject any deviation from the recorded immutable backing-file seal."""

    value = _stat_trusted_base_image(SEALED_BASE)
    if (
        value.st_uid != 0
        or value.st_gid != 0
        or stat.S_IMODE(value.st_mode) != 0o444
    ):
        raise ProbeRefused("sealed base metadata changed")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(SEALED_BASE, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (value.st_dev, value.st_ino):
            raise ProbeRefused("sealed base identity changed")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        finished = os.fstat(descriptor)
        if (
            digest.hexdigest() != SEALED_BASE_SHA256
            or (
                finished.st_dev,
                finished.st_ino,
                finished.st_size,
                finished.st_mtime_ns,
                finished.st_uid,
                finished.st_gid,
                stat.S_IMODE(finished.st_mode),
            )
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                0,
                0,
                0o444,
            )
        ):
            raise ProbeRefused("sealed base hash or identity changed")
    finally:
        os.close(descriptor)


def _new_proof_directory(parent: Path, sandbox_session_id: UUID) -> Path:
    if not parent.is_absolute() or ".." in parent.parts:
        raise ProbeRefused("proof parent is not canonical")
    _require_trusted_ancestry(parent)
    value = os.lstat(parent)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.geteuid()
        or value.st_gid != os.getegid()
        or stat.S_IMODE(value.st_mode) != 0o700
    ):
        raise ProbeRefused("proof parent is not protected")
    directory = parent / f"sentra-context-probe-{sandbox_session_id}"
    directory.mkdir(mode=0o700, exist_ok=False)
    created = os.lstat(directory)
    if (
        not stat.S_ISDIR(created.st_mode)
        or created.st_uid != os.geteuid()
        or created.st_gid != os.getegid()
        or stat.S_IMODE(created.st_mode) != 0o700
    ):
        raise ProbeRefused("proof directory is not protected")
    return directory


def _snapshot_database(source: Path, proof_directory: Path) -> Path:
    """Read the saved Controller DB in read-only mode into isolated storage."""

    if not source.is_absolute() or ".." in source.parts:
        raise ProbeRefused("source database path is not canonical")
    source_stat = os.lstat(source)
    if (
        not stat.S_ISREG(source_stat.st_mode)
        or source_stat.st_nlink != 1
        or stat.S_IMODE(source_stat.st_mode) & 0o077
    ):
        raise ProbeRefused("source database is not a protected regular file")
    # The input must be an offline saved DB, not a live WAL database.  SQLite's
    # immutable read mode then cannot create sidecars beside operator evidence.
    if any(os.path.lexists(f"{source}{suffix}") for suffix in ("-wal", "-shm", "-journal")):
        raise ProbeRefused("source database has live or stale SQLite sidecars")
    destination = proof_directory / "controller-isolated.sqlite3"
    descriptor = os.open(
        destination,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    os.close(descriptor)
    with sqlite3.connect(f"{source.as_uri()}?mode=ro&immutable=1", uri=True) as original:
        with sqlite3.connect(destination) as isolated:
            original.backup(isolated)
    source_after = os.lstat(source)
    if (
        source_after.st_dev,
        source_after.st_ino,
        source_after.st_size,
        source_after.st_mtime_ns,
    ) != (
        source_stat.st_dev,
        source_stat.st_ino,
        source_stat.st_size,
        source_stat.st_mtime_ns,
    ):
        raise ProbeRefused("saved database changed during snapshot")
    if stat.S_IMODE(os.lstat(destination).st_mode) != 0o600:
        raise ProbeRefused("isolated database permissions are not protected")
    return destination


def _snapshot_guest_files(proof_directory: Path) -> list[Path]:
    """Freeze the reviewed bytes under 0700 proof storage before copy-in."""

    snapshots = proof_directory / "guest-files"
    snapshots.mkdir(mode=0o700, exist_ok=False)
    paths: list[Path] = []
    for name, expected_sha256 in GUEST_FILE_SHA256.items():
        path = REPOSITORY_ROOT / "src" / "sandbox_runtime" / name
        value = os.lstat(path)
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise ProbeRefused("guest instrumentation source is not regular")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (
                (opened.st_dev, opened.st_ino) != (value.st_dev, value.st_ino)
                or opened.st_size > 256 * 1024
            ):
                raise ProbeRefused("guest instrumentation source changed")
            chunks = bytearray()
            while chunk := os.read(descriptor, 64 * 1024):
                chunks.extend(chunk)
                if len(chunks) > 256 * 1024:
                    raise ProbeRefused("guest instrumentation source is oversized")
            if (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) != (
                value.st_dev,
                value.st_ino,
            ):
                raise ProbeRefused("guest instrumentation source changed")
        finally:
            os.close(descriptor)
        data = bytes(chunks)
        if _sha256(data) != expected_sha256:
            raise ProbeRefused("guest instrumentation source differs from review")
        snapshot = snapshots / name
        output = os.open(
            snapshot,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(output, data[offset:])
        finally:
            os.close(output)
        paths.append(snapshot)
    return paths


def _require_offline_tools() -> None:
    for tool in (_VIRT_COPY_IN, _VIRT_CAT):
        _require_trusted_ancestry(Path(tool))
        value = os.lstat(tool)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != 0
            or stat.S_IMODE(value.st_mode) & 0o022
            or not stat.S_IMODE(value.st_mode) & 0o111
        ):
            raise ProbeRefused("offline overlay tool is not trusted")


def _prepare_fresh_overlay(backend: LibvirtBackend, plan: LocalNestedVmPlan) -> None:
    """Create only a new pool/overlay; do not define or boot a domain yet."""

    backend._expect_libvirt_plan(plan)
    libvirt, connection = backend._open(plan)
    try:
        if (
            backend._lookup_domain(connection, libvirt, plan) is not None
            or backend._lookup_pool(connection, libvirt, plan) is not None
            or os.path.lexists(plan.overlay_path.parent)
        ):
            raise ProbeRefused("sandbox session resource already exists")
        pool = backend._ensure_pool(connection, libvirt, plan)
        volume = backend._create_or_reconcile_volume(pool, libvirt, plan)
        backend._validate_volume(volume, plan)
    finally:
        backend._close(connection)


def _stage_in_stopped_overlay(
    backend: LibvirtBackend,
    plan: LocalNestedVmPlan,
    sources: list[Path],
) -> None:
    """Copy and byte-verify only the three fixed files in the fresh overlay."""

    libvirt, connection = backend._open(plan)
    try:
        if backend._lookup_domain(connection, libvirt, plan) is not None:
            raise ProbeRefused("guest was defined before instrumentation")
        pool = backend._lookup_pool(connection, libvirt, plan)
        if pool is None:
            raise ProbeRefused("fresh storage pool disappeared")
        volume = backend._lookup_volume(pool, libvirt)
        if volume is None:
            raise ProbeRefused("fresh overlay disappeared")
        backend._validate_volume(volume, plan)
    finally:
        backend._close(connection)

    subprocess.run(
        [
            _VIRT_COPY_IN,
            "--format=qcow2",
            "-a",
            os.fspath(plan.overlay_path),
            *(os.fspath(path) for path in sources),
            GUEST_DESTINATION,
        ],
        check=True,
        capture_output=True,
        timeout=300,
    )
    for path in sources:
        observed = subprocess.run(
            [
                _VIRT_CAT,
                "--format=qcow2",
                "-a",
                os.fspath(plan.overlay_path),
                f"{GUEST_DESTINATION}/{path.name}",
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
        if _sha256(observed.stdout) != GUEST_FILE_SHA256[path.name]:
            raise ProbeRefused("guest instrumentation verification failed")

    libvirt, connection = backend._open(plan)
    try:
        pool = backend._lookup_pool(connection, libvirt, plan)
        volume = None if pool is None else backend._lookup_volume(pool, libvirt)
        if volume is None or backend._lookup_domain(connection, libvirt, plan) is not None:
            raise ProbeRefused("guest identity changed during staging")
        backend._validate_volume(volume, plan)
    finally:
        backend._close(connection)


def _write_all(stream: BinaryIO, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        count = stream.write(data[offset:])
        if type(count) is not int or count <= 0 or count > len(data) - offset:
            raise ProbeRefused("context write was incomplete")
        offset += count


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if type(chunk) is not bytes or not chunk or len(chunk) > size - len(result):
            raise ProbeRefused("context acknowledgement was incomplete")
        result.extend(chunk)
    return bytes(result)


def _context_only_exchange(
    stream: BinaryIO,
    manifest: SandboxContextManifest,
) -> SandboxContextAcknowledgement:
    """Send one canonical context and read one ACK. Nothing follows the ACK."""

    frame = encode_sandbox_context_frame(manifest)
    _stage("context_write_start")
    _write_all(stream, frame)
    _stage("context_write_complete")
    _stage("ack_header_wait")
    header = _read_exact(stream, 4)
    _stage("ack_header_complete")
    payload_size = int.from_bytes(header, "big")
    if payload_size == 0 or payload_size > MAX_SANDBOX_CONTEXT_PAYLOAD_BYTES:
        raise ProbeRefused("context acknowledgement length was rejected")
    payload = _read_exact(stream, payload_size)
    _stage("ack_payload_complete")
    acknowledgement = decode_sandbox_acknowledgement_frame(header + payload)
    _stage("ack_accepted" if acknowledgement.status == "accepted" else "ack_rejected")
    return acknowledgement


def _parser() -> argparse.ArgumentParser:
    parser = _QuietParser(description="One disposable SENTRA context-only probe")
    parser.add_argument("--saved-database", type=Path, required=True)
    parser.add_argument("--proof-root", type=Path, required=True)
    parser.add_argument("--sandbox-storage-root", type=Path, required=True)
    parser.add_argument("--libvirt-qemu-uid", type=int, required=True)
    parser.add_argument("--libvirt-qemu-gid", type=int, required=True)
    parser.add_argument("--target-id", type=UUID, required=True)
    parser.add_argument("--profile-id", type=UUID, required=True)
    parser.add_argument(
        "--administrator-sandbox-approval-acknowledged",
        action="store_true",
        help="explicit approval to create exactly one disposable sandbox",
    )
    return parser


def run(args: argparse.Namespace) -> bool:
    if os.geteuid() != 0:
        raise ProbeRefused("diagnostic requires local administrator")
    if args.administrator_sandbox_approval_acknowledged is not True:
        raise ProbeRefused("administrator sandbox approval is required")
    _verify_sealed_base()
    _stage("base_verified_before")
    try:
        sandbox_session_id = uuid4()
        compatibility_report_id = uuid4()
        if compatibility_report_id == sandbox_session_id:
            raise ProbeRefused("diagnostic identity collision")
        issued_ids = iter((compatibility_report_id, sandbox_session_id))
        proof_directory = _new_proof_directory(args.proof_root, sandbox_session_id)
        _stage("proof_directory_created")
        _require_offline_tools()
        guest_sources = _snapshot_guest_files(proof_directory)
        _stage("guest_files_reviewed")
        database = _snapshot_database(args.saved_database, proof_directory)
        _stage("isolated_database_created")

        repository = SQLiteControllerRepository(database)
        # ControllerService admin credentials are process-local settings, not
        # read from the saved SQLite database.  Use a fresh, unprinted secret
        # solely for this isolated diagnostic service instance.
        admin_secret = SecretStr(secrets.token_urlsafe(32))
        service = ControllerService(
            repository,
            ControllerSettings(
                bootstrap_credential=SecretStr(secrets.token_urlsafe(32)),
                admin_credential=admin_secret,
            ),
            id_factory=lambda: next(issued_ids),
        )
        auth = AdminAuth(admin_credential=admin_secret)
        stored_profile = repository.get_stored_profile(args.profile_id)
        if stored_profile is None or stored_profile.record.target_id != args.target_id:
            raise ProbeRefused("saved profile lineage is unavailable")
        report = service.run_compatibility_analysis(
            auth,
            CompatibilityAnalysisRequest(
                target_id=args.target_id,
                profile_id=args.profile_id,
            ),
        )
        if report.compatibility_report_id != compatibility_report_id:
            raise ProbeRefused("new compatibility report identity changed")
        reference = compatibility_reference_from_record(report, "7.1.1")
        if (
            reference.result.value != "review_required"
            or reference.provisional is not True
            or reference.metadata_review_status != "needs_review"
        ):
            raise ProbeRefused("saved profile M4 result differs from the reviewed case")
        manifest = derive_sandbox_context(
            "7.1.1", stored_profile.profile, reference
        )
        if (
            manifest.source_state.passwd_file_mode != "0644"
            or manifest.source_state.passwd_file_owner_uid != 0
            or manifest.source_state.passwd_file_group_gid != 0
        ):
            raise ProbeRefused("saved source state differs from the reviewed case")
        _stage("source_context_validated")

        session = service.create_sandbox_session(
            auth,
            target_id=args.target_id,
            profile_id=args.profile_id,
            compatibility_report_id=report.compatibility_report_id,
            request=SandboxSessionCreateRequest(
                request_id=uuid4(),
                control_id="7.1.1",
                administrator_sandbox_authorization_acknowledged=True,
            ),
        )
        if session.sandbox_session_id != sandbox_session_id:
            raise ProbeRefused("new sandbox session identity changed")

        backend = LibvirtBackend()
        provider = LocalNestedVmProvider(
            LocalNestedVmConfig(
                sandbox_root=args.sandbox_storage_root,
                base_image=SEALED_BASE,
                storage_mode=SandboxStorageMode.LIBVIRT_POOL,
                libvirt_qemu_uid=args.libvirt_qemu_uid,
                libvirt_qemu_gid=args.libvirt_qemu_gid,
            ),
            backend,
        )
        plan = provider._plan(sandbox_session_id, prepare_directory=False)
        _prepare_fresh_overlay(backend, plan)
        _stage("overlay_created_stopped")
        _verify_sealed_base()
        _stage("base_verified_after_overlay")
        _stage_in_stopped_overlay(backend, plan, guest_sources)
        _stage("overlay_instrumented_stopped")
        _verify_sealed_base()
        _stage("base_verified_after_staging")

        manager = SandboxManager(service, provider)
        ready = manager.provision(
            auth,
            target_id=args.target_id,
            profile_id=args.profile_id,
            compatibility_report_id=report.compatibility_report_id,
            sandbox_session_id=sandbox_session_id,
        )
        if ready.status is not SandboxSessionStatus.READY:
            raise ProbeRefused("fresh sandbox was not ready")
        if provider.inspect(sandbox_session_id).runtime_state is not SandboxRuntimeState.RUNNING:
            raise ProbeRefused("fresh sandbox was not running")
        _stage("guest_started")

        channel = provider.open_validation_channel(sandbox_session_id)
        _stage("channel_open")
        try:
            acknowledgement = _context_only_exchange(channel, manifest)
        finally:
            channel.abort()
        return acknowledgement.status == "accepted"
    finally:
        _verify_sealed_base()
        _stage("base_verified_after")


def main(argv: Sequence[str] | None = None) -> int:
    # This one-off command emits its own fixed, timestamped stages.  Suppress
    # the library's duplicate transport warnings in this process only.
    transport_logger = logging.getLogger("src.controller.sandbox")
    was_disabled = transport_logger.disabled
    transport_logger.disabled = True
    try:
        try:
            accepted = run(_parser().parse_args(argv))
        except Exception as error:
            if isinstance(error, TimeoutError):
                _stage("stream_read_timeout")
            _stage(f"failure={type(error).__name__}")
            return 2
    finally:
        transport_logger.disabled = was_disabled
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
