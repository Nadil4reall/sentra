"""Command-line entry point for data-only compatibility analysis."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import tempfile

import yaml

from src.poc_models import enrichment_filename

from .engine import evaluate_compatibility
from .loaders import (
    DEFAULT_MANIFEST_PATH,
    CompatibilityInputs,
    load_compatibility_inputs,
)
from .report import report_to_yaml
from .rules import list_rule_descriptions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare a supplied SENTRA target profile with deterministic PoC "
            "compatibility rules"
        )
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--profile",
        type=Path,
        help="Milestone 3 target profile YAML to evaluate",
    )
    action.add_argument(
        "--list-rules",
        action="store_true",
        help="list deterministic PoC rules without evaluating a profile",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the YAML report to this path instead of standard output",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help=argparse.SUPPRESS,
    )
    return parser


def _rules_yaml() -> str:
    document = {
        "rules": [
            item.model_dump(mode="json") for item in list_rule_descriptions()
        ]
    }
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True)


def _write_private_report(path: Path, rendered: str) -> None:
    """Atomically write only the explicitly requested report output."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(
            descriptor, "w", encoding="utf-8", newline="\n"
        ) as stream:
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


def _reject_input_overwrite(
    parser: argparse.ArgumentParser,
    output: Path | None,
    inputs: CompatibilityInputs,
) -> None:
    if output is None:
        return
    profile_path = inputs.profile_path
    manifest_path = inputs.manifest_path
    enrichments = inputs.enrichments
    protected = {profile_path, manifest_path}
    protected.update(
        manifest_path.parent
        / "enriched"
        / enrichment_filename(item.control_id)
        for item in enrichments
    )
    if output.resolve() in protected:
        parser.error("--output must not overwrite a Milestone 2 or 3 input file")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        if args.output is not None:
            parser.error("--output cannot be used with --list-rules")
        print(_rules_yaml(), end="")
        return 0

    try:
        inputs = load_compatibility_inputs(args.profile, args.manifest)
        _reject_input_overwrite(parser, args.output, inputs)
        rendered = report_to_yaml(evaluate_compatibility(inputs))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    if args.output is None:
        print(rendered, end="")
    else:
        _write_private_report(args.output, rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
