"""Read-only summary command for the SENTRA Milestone 2 PoC dataset."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from .poc_models import Category, DerivationStatus, validate_poc_dataset


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "data" / "poc" / "poc_controls.yaml"
CATEGORY_LABELS = (
    (Category.KERNEL, "Kernel"),
    (Category.NETWORK, "Network"),
    (Category.FIREWALL, "Firewall"),
    (Category.SSH, "SSH"),
    (Category.AUDITING, "Auditing"),
    (Category.FILE_PERMISSIONS, "File Permissions"),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize the read-only SENTRA PoC metadata")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="PoC manifest path",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    dataset = validate_poc_dataset(args.manifest)
    category_counts = Counter(item.sentra.category for item in dataset.enrichments)
    review_count = sum(
        item.sentra.evidence.derivation_status == DerivationStatus.NEEDS_REVIEW
        for item in dataset.enrichments
    )

    print("SENTRA PoC Control Set")
    print()
    print(f"Selected controls: {dataset.manifest.poc.total_controls}")
    print()
    for category, label in CATEGORY_LABELS:
        print(f"{label + ':':<20}{category_counts[category]}")
    print()
    print(f"Needs review: {review_count}")
    print()
    print("Controls executed: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
