"""Local-only CLI for Milestone 5 planning and sandbox experiments."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import stat

import yaml

from src.compatibility_engine.loaders import DEFAULT_MANIFEST_PATH
from src.poc_models import enrichment_filename

from .adapters.base import AdapterContext
from .loaders import load_validation_inputs
from .models import ExecutionMode, ValidationReport
from .report import report_to_yaml
from .validator import SandboxValidator, ValidationRequest


_CONTROL_CATALOG = (
    {
        "control_id": "7.1.1",
        "title": "Ensure permissions on /etc/passwd are configured",
        "capability": "full",
        "mutation": "fixed-path metadata change with backup and rollback",
    },
    {
        "control_id": "5.1.20",
        "title": "Ensure sshd PermitRootLogin is disabled",
        "capability": "conditional",
        "mutation": "dedicated SENTRA drop-in, validation, and reload only",
    },
    {
        "control_id": "4.2.3",
        "title": "Ensure ufw service is enabled",
        "capability": "audit_plan_only",
        "mutation": "not implemented in the initial M5 safety boundary",
    },
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_OUTPUT_DIRECTORY = PROJECT_ROOT / "data" / "sandbox"
_REPORT_RESERVATION_NOTICE = (
    b"# SENTRA M5 REPORT RESERVATION - NOT A COMPLETED VALIDATION REPORT\n"
    b"sentra_m5_report_reservation:\n"
    b"  complete: false\n"
    b"  notice: A final report was not written; inspect the sandbox before retrying.\n"
)
_MAX_EXISTING_REPORT_BYTES = 16 * 1024 * 1024


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError("report write made no progress")
        offset += written


def _identity(file_stat: os.stat_result) -> tuple[int, int]:
    return (file_stat.st_dev, file_stat.st_ino)


def _same_identity(
    file_stat: os.stat_result, expected: tuple[int, int]
) -> bool:
    return _identity(file_stat) == expected


def _anchored_stat(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


@dataclass(slots=True)
class _PreparedReportDestination:
    """A same-directory, descriptor-anchored report reservation."""

    path: Path
    overwrite: bool
    directory_fd: int
    target_name: str
    target_identity: tuple[int, int]
    reservation_created: bool
    pending_fd: int
    pending_name: str
    pending_identity: tuple[int, int]
    finalized: bool = False

    def finalize(self, rendered: str) -> None:
        content = rendered.encode("utf-8")
        os.lseek(self.pending_fd, 0, os.SEEK_SET)
        os.ftruncate(self.pending_fd, 0)
        _write_all(self.pending_fd, content)
        os.fchmod(self.pending_fd, 0o600)
        os.fsync(self.pending_fd)

        current_pending = _anchored_stat(self.directory_fd, self.pending_name)
        if current_pending is None or not _same_identity(
            current_pending, self.pending_identity
        ):
            raise OSError("prepared report staging file changed unexpectedly")
        current_target = _anchored_stat(self.directory_fd, self.target_name)
        if current_target is None or not _same_identity(
            current_target, self.target_identity
        ):
            raise OSError("prepared report destination changed unexpectedly")
        if not stat.S_ISREG(current_target.st_mode):
            raise OSError("prepared report destination is no longer a regular file")

        os.close(self.pending_fd)
        self.pending_fd = -1
        os.replace(
            self.pending_name,
            self.target_name,
            src_dir_fd=self.directory_fd,
            dst_dir_fd=self.directory_fd,
        )
        self.pending_name = ""
        self.finalized = True
        os.fsync(self.directory_fd)

    def close(self, *, preserve_incomplete_reservation: bool = False) -> None:
        if self.pending_fd >= 0:
            os.close(self.pending_fd)
            self.pending_fd = -1
        if self.pending_name:
            current_pending = _anchored_stat(self.directory_fd, self.pending_name)
            if current_pending is not None and _same_identity(
                current_pending, self.pending_identity
            ):
                os.unlink(self.pending_name, dir_fd=self.directory_fd)
            self.pending_name = ""
        if (
            self.reservation_created
            and not self.finalized
            and not preserve_incomplete_reservation
        ):
            current_target = _anchored_stat(self.directory_fd, self.target_name)
            if current_target is not None and _same_identity(
                current_target, self.target_identity
            ):
                os.unlink(self.target_name, dir_fd=self.directory_fd)
                os.fsync(self.directory_fd)
        os.close(self.directory_fd)
        self.directory_fd = -1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Plan or run one hand-authored SENTRA control experiment locally "
            "inside an acknowledged Ubuntu 24.04 sandbox"
        )
    )
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--list-controls",
        action="store_true",
        help="list M5 adapters without inspecting the local host",
    )
    selection.add_argument("--control", help="control ID to audit or validate")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--plan",
        action="store_true",
        help="run read-only precheck and audit (the default)",
    )
    mode.add_argument(
        "--execute",
        action="store_true",
        help="request the selected adapter's controlled sandbox mutation",
    )
    parser.add_argument(
        "--compatibility-report",
        type=Path,
        help="explicit M4 compatibility report containing the selected control",
    )
    parser.add_argument(
        "--target-profile",
        type=Path,
        help="optional explicit M3 profile for lineage cross-checking",
    )
    parser.add_argument(
        "--sandbox-ack",
        action="store_true",
        help="authoritatively acknowledge that the local host is the disposable sandbox",
    )
    parser.add_argument(
        "--administrator-approval",
        action="store_true",
        help="record explicit administrator approval for the selected mutation",
    )
    parser.add_argument(
        "--ssh-recovery-access-ack",
        dest="ssh_recovery_access_acknowledged",
        action="store_true",
        help=(
            "for control 5.1.20 execute only, acknowledge that VM console and "
            "snapshot recovery access are available"
        ),
    )
    parser.add_argument(
        "--ssh-non-root-admin-sudo-access-verified",
        action="store_true",
        help=(
            "for control 5.1.20 execute only, attest that a working non-root "
            "administrator login and sudo path were tested"
        ),
    )
    parser.add_argument(
        "--ssh-lockout-risk-ack",
        dest="ssh_lockout_risk_acknowledged",
        action="store_true",
        help=(
            "for control 5.1.20 execute only, explicitly acknowledge SSH "
            "lockout risk"
        ),
    )
    parser.add_argument(
        "--compatibility-ack",
        action="store_true",
        help="acknowledge an M4 warning/review/insufficient-evidence result",
    )
    parser.add_argument(
        "--override-insufficient-evidence",
        metavar="REASON",
        help="record the research reason for proceeding with insufficient M4 evidence",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the validated YAML report to this explicit path",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing output report atomically",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help=argparse.SUPPRESS,
    )
    return parser


def _catalog_yaml() -> str:
    return yaml.safe_dump(
        {"controls": list(_CONTROL_CATALOG)}, sort_keys=False, allow_unicode=True
    )


def _protected_inputs(args: argparse.Namespace) -> set[Path]:
    protected = {Path(args.manifest).resolve()}
    if args.control:
        protected.add(
            Path(args.manifest).resolve().parent
            / "enriched"
            / enrichment_filename(args.control)
        )
    if args.compatibility_report is not None:
        protected.add(args.compatibility_report.resolve())
    if args.target_profile is not None:
        protected.add(args.target_profile.resolve())
    return protected


def _preflight_output(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> Path | None:
    output = args.output
    if args.overwrite and output is None:
        parser.error("--overwrite requires --output")
    if args.execute and output is None:
        parser.error("--execute requires an explicit --output audit report path")
    if output is None:
        return None
    if ".." in output.parts:
        parser.error("--output must not contain parent-directory traversal")

    allowed = Path(os.path.abspath(os.fspath(REPORT_OUTPUT_DIRECTORY)))
    try:
        allowed_stat = allowed.lstat()
    except FileNotFoundError:
        parser.error(f"M5 report directory does not exist: {allowed}")
    if stat.S_ISLNK(allowed_stat.st_mode) or not stat.S_ISDIR(allowed_stat.st_mode):
        parser.error("M5 report directory must be a real directory, not a symlink")
    allowed_resolved = allowed.resolve(strict=True)

    lexical = Path(os.path.abspath(os.fspath(output)))
    try:
        relative = lexical.relative_to(allowed)
    except ValueError:
        parser.error(f"--output must be beneath {allowed}")
    if not relative.parts:
        parser.error("--output must name a report file inside data/sandbox")

    current = allowed
    for component in relative.parts[:-1]:
        current /= component
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            parser.error("--output parent directory must already exist")
        if stat.S_ISLNK(current_stat.st_mode):
            parser.error("--output must not traverse a symlink directory")
        if not stat.S_ISDIR(current_stat.st_mode):
            parser.error("--output parent must be a regular directory")

    try:
        output_stat = lexical.lstat()
    except FileNotFoundError:
        output_stat = None
    if output_stat is not None:
        if stat.S_ISLNK(output_stat.st_mode):
            parser.error("--output must not be a symlink")
        if not stat.S_ISREG(output_stat.st_mode):
            parser.error("--output existing target must be a regular file")

    resolved = lexical.resolve(strict=False)
    try:
        resolved.relative_to(allowed_resolved)
    except ValueError:
        parser.error(f"--output must resolve beneath {allowed_resolved}")
    if resolved in _protected_inputs(args):
        parser.error("--output must not overwrite an M2, M3, or M4 input")
    if output_stat is not None and not args.overwrite:
        parser.error("output already exists; use --overwrite to replace it explicitly")
    if output_stat is None and args.overwrite:
        parser.error("--overwrite requires an existing valid M5 report")
    return resolved


def _validate_existing_report(
    directory_fd: int,
    target_name: str,
    expected: os.stat_result,
) -> None:
    if expected.st_nlink != 1:
        raise ValueError("existing output report must not have multiple hard links")
    if expected.st_size > _MAX_EXISTING_REPORT_BYTES:
        raise ValueError("existing output is too large to be an M5 report")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target_name, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_identity(
            opened, _identity(expected)
        ):
            raise ValueError("existing output changed during validation")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            document = yaml.safe_load(stream)
        ValidationReport.model_validate(document)
    except (UnicodeError, ValueError, yaml.YAMLError) as exc:
        raise ValueError("--overwrite target is not a valid existing M5 report") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _create_pending_file(
    directory_fd: int, target_name: str
) -> tuple[int, str, tuple[int, int]]:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _attempt in range(32):
        pending_name = f".{target_name}.{secrets.token_hex(12)}.pending"
        try:
            descriptor = os.open(pending_name, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError:
            continue
        try:
            _write_all(descriptor, _REPORT_RESERVATION_NOTICE)
            os.fsync(descriptor)
            pending_stat = os.fstat(descriptor)
            return descriptor, pending_name, _identity(pending_stat)
        except BaseException:
            os.close(descriptor)
            os.unlink(pending_name, dir_fd=directory_fd)
            raise
    raise FileExistsError("could not allocate a unique report staging file")


def _prepare_report_destination(
    path: Path, *, overwrite: bool
) -> _PreparedReportDestination:
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(path.parent, directory_flags)
    target_identity: tuple[int, int] | None = None
    reservation_created = False
    pending_fd = -1
    pending_name = ""
    pending_identity = (0, 0)
    try:
        parent_stat = os.fstat(directory_fd)
        expected_parent = path.parent.stat()
        if not stat.S_ISDIR(parent_stat.st_mode) or not _same_identity(
            parent_stat, _identity(expected_parent)
        ):
            raise OSError("report parent directory changed during preparation")

        current = _anchored_stat(directory_fd, path.name)
        if current is None:
            if overwrite:
                raise FileNotFoundError(
                    "--overwrite target disappeared during report preparation"
                )
            target_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
            )
            target_fd = os.open(path.name, target_flags, 0o600, dir_fd=directory_fd)
            reservation_created = True
            current = os.fstat(target_fd)
            target_identity = _identity(current)
            try:
                _write_all(target_fd, _REPORT_RESERVATION_NOTICE)
                os.fsync(target_fd)
            finally:
                os.close(target_fd)
            os.fsync(directory_fd)
        else:
            if not overwrite:
                raise FileExistsError(
                    "output appeared during report preparation; refusing to overwrite it"
                )
            if not stat.S_ISREG(current.st_mode):
                raise ValueError("existing output target must be a regular file")
            original_identity = _identity(current)
            _validate_existing_report(directory_fd, path.name, current)
            current = _anchored_stat(directory_fd, path.name)
            if (
                current is None
                or not stat.S_ISREG(current.st_mode)
                or not _same_identity(current, original_identity)
            ):
                raise OSError("existing output changed during report preparation")

        target_identity = _identity(current)
        pending_fd, pending_name, pending_identity = _create_pending_file(
            directory_fd, path.name
        )
        return _PreparedReportDestination(
            path=path,
            overwrite=overwrite,
            directory_fd=directory_fd,
            target_name=path.name,
            target_identity=target_identity,
            reservation_created=reservation_created,
            pending_fd=pending_fd,
            pending_name=pending_name,
            pending_identity=pending_identity,
        )
    except BaseException:
        if pending_fd >= 0:
            os.close(pending_fd)
        if pending_name:
            pending_stat = _anchored_stat(directory_fd, pending_name)
            if pending_stat is not None and _same_identity(
                pending_stat, pending_identity
            ):
                os.unlink(pending_name, dir_fd=directory_fd)
        if reservation_created and target_identity is not None:
            target_stat = _anchored_stat(directory_fd, path.name)
            if target_stat is not None and _same_identity(
                target_stat, target_identity
            ):
                os.unlink(path.name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        os.close(directory_fd)
        raise


def _write_private_report(
    destination: _PreparedReportDestination, rendered: str
) -> None:
    destination.finalize(rendered)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_controls:
        incompatible = any(
            (
                args.execute,
                args.plan,
                args.compatibility_report is not None,
                args.target_profile is not None,
                args.sandbox_ack,
                args.administrator_approval,
                args.ssh_recovery_access_acknowledged,
                args.ssh_non_root_admin_sudo_access_verified,
                args.ssh_lockout_risk_acknowledged,
                args.compatibility_ack,
                args.override_insufficient_evidence is not None,
                args.output is not None,
                args.overwrite,
            )
        )
        if incompatible:
            parser.error("--list-controls cannot be combined with validation options")
        print(_catalog_yaml(), end="")
        return 0

    destination: _PreparedReportDestination | None = None
    validation_started = False
    try:
        output_path = _preflight_output(parser, args)
        if output_path is not None:
            destination = _prepare_report_destination(
                output_path, overwrite=args.overwrite
            )
        inputs = load_validation_inputs(
            args.control,
            compatibility_report=args.compatibility_report,
            target_profile=args.target_profile,
            manifest_path=args.manifest,
        )
        environment = {
            key: os.environ[key]
            for key in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")
            if key in os.environ
        }
        context = AdapterContext(environment=environment)
        validation_started = True
        report = SandboxValidator(context=context).validate(
            inputs,
            ValidationRequest(
                control_id=args.control,
                mode=(ExecutionMode.EXECUTE if args.execute else ExecutionMode.PLAN),
                sandbox_operator_acknowledged=args.sandbox_ack,
                administrator_approval_acknowledged=args.administrator_approval,
                compatibility_risk_acknowledged=args.compatibility_ack,
                compatibility_override_reason=args.override_insufficient_evidence,
                ssh_recovery_access_acknowledged=(
                    args.ssh_recovery_access_acknowledged
                ),
                ssh_non_root_admin_sudo_access_verified=(
                    args.ssh_non_root_admin_sudo_access_verified
                ),
                ssh_lockout_risk_acknowledged=(
                    args.ssh_lockout_risk_acknowledged
                ),
            ),
        )
        rendered = report_to_yaml(report)
        if args.output is None:
            print(rendered, end="")
        else:
            if destination is None:  # defensive invariant
                raise RuntimeError("report destination was not prepared")
            _write_private_report(destination, rendered)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    finally:
        if destination is not None:
            destination.close(
                preserve_incomplete_reservation=(
                    args.execute
                    and validation_started
                    and not destination.finalized
                )
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
