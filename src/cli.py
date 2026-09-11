"""Command-line entry point for SENTRA Milestone 1."""

from __future__ import annotations

import argparse
from pathlib import Path

from .control_detector import DetectedControl, detect_controls, raw_text_for_control
from .control_parser import parse_control
from .models import Catalog, CatalogEntry, SourceLocation, benchmark_metadata
from .pdf_extractor import extract_pages, extract_tables_for_pages
from .yaml_writer import control_filename, write_catalog, write_control


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("--limit must be at least 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert CIS Benchmark recommendations to traceable YAML data."
    )
    parser.add_argument("pdf", type=Path, help="Local CIS Benchmark PDF (read-only input)")
    parser.add_argument(
        "--limit",
        type=positive_integer,
        default=None,
        help="Generate only the first N recommendations (Milestone 1 uses 5)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data"),
        help="Output directory (default: data)",
    )
    return parser


def _source_location(control: DetectedControl) -> SourceLocation:
    return SourceLocation(
        pdf_page_start=control.pdf_page_start,
        pdf_page_end=control.pdf_page_end,
        benchmark_page_start=control.benchmark_page_start,
        benchmark_page_end=control.benchmark_page_end,
    )


def convert(pdf_path: Path, output_directory: Path, limit: int | None) -> Catalog:
    pages = extract_pages(pdf_path)
    detected = detect_controls(pages)
    selected = detected[:limit] if limit is not None else detected

    selected_page_numbers = {
        number
        for control in selected
        for number in range(control.pdf_page_start, control.pdf_page_end + 1)
    }
    tables_by_page = extract_tables_for_pages(pdf_path, selected_page_numbers)

    generated_ids: set[str] = set()
    for control in selected:
        tables = [
            table
            for page_number in range(control.pdf_page_start, control.pdf_page_end + 1)
            for table in tables_by_page.get(page_number, [])
        ]
        document = parse_control(control, raw_text_for_control(control, pages), tables)
        write_control(output_directory, document)
        generated_ids.add(control.heading.control_id)

    entries: list[CatalogEntry] = []
    for control in detected:
        generated = control.heading.control_id in generated_ids
        entries.append(
            CatalogEntry(
                id=control.heading.control_id,
                title=control.heading.title,
                assessment_status=control.heading.assessment_status,
                source=_source_location(control),
                generated=generated,
                output_file=(
                    f"controls/{control_filename(control.heading.control_id)}" if generated else None
                ),
            )
        )

    catalog = Catalog(
        benchmark=benchmark_metadata(),
        source_pdf=pdf_path.name,
        detected_recommendations=len(detected),
        generated_recommendations=len(selected),
        controls=entries,
    )
    write_catalog(output_directory, catalog)
    return catalog


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    catalog = convert(args.pdf, args.output_dir, args.limit)
    print(f"Detected recommendations: {catalog.detected_recommendations}")
    print(f"Generated controls: {catalog.generated_recommendations}")
    print(f"Catalog: {args.output_dir / 'catalog.yaml'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

