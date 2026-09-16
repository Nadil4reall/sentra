"""Command-line entry point for the local read-only target profiler."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import tempfile

import yaml

from .fact_loader import DEFAULT_MANIFEST_PATH, load_required_facts
from .profiler import collect_local_profile, profile_to_yaml


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect a read-only SENTRA profile of this local Ubuntu host"
    )
    parser.add_argument(
        "--list-required-facts",
        action="store_true",
        help="list enrichment-derived facts without profiling this host",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the YAML profile to this path instead of standard output",
    )
    parser.add_argument(
        "--format",
        choices=("yaml",),
        default="yaml",
        help="profile output format (default: yaml)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help=argparse.SUPPRESS,
    )
    return parser


def _required_facts_yaml(manifest_path: Path) -> str:
    required = load_required_facts(manifest_path)
    document = {
        "required_target_facts": {
            fact.name: {"requested_by": fact.requested_by} for fact in required
        }
    }
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True)


def _write_private_profile(path: Path, rendered: str) -> None:
    """Atomically write a profile using owner-only permissions."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.chmod(0o600)
        os.replace(temporary_path, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_required_facts:
        if args.output is not None:
            parser.error("--output cannot be used with --list-required-facts")
        print(_required_facts_yaml(args.manifest), end="")
        return 0

    profile = collect_local_profile(args.manifest)
    rendered = profile_to_yaml(profile)
    if args.output is None:
        print(rendered, end="")
    else:
        _write_private_profile(args.output, rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
