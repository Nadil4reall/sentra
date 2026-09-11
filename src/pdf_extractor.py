"""Read-only PDF text and table extraction.

This module never evaluates or executes text extracted from the benchmark.
"""

from __future__ import annotations

import contextlib
import io
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pymupdf


PRINTED_PAGE_RE = re.compile(r"^\s*Page\s+(\d+)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class TextBlock:
    text: str
    y0: float
    max_font_size: float
    fonts: tuple[str, ...]


@dataclass(frozen=True)
class ExtractedPage:
    pdf_page: int
    benchmark_page: int | None
    text: str
    top_blocks: tuple[TextBlock, ...]


@dataclass(frozen=True)
class StyledLine:
    text: str
    max_font_size: float


@dataclass(frozen=True)
class ExtractedCell:
    text: str
    lines: tuple[StyledLine, ...]


@dataclass(frozen=True)
class ExtractedTable:
    rows: tuple[tuple[ExtractedCell | None, ...], ...]


def extract_printed_page_number(text: str) -> int | None:
    """Return the final printed ``Page N`` footer from extracted page text."""

    matches = PRINTED_PAGE_RE.findall(text)
    return int(matches[-1]) if matches else None


def remove_printed_page_footer(text: str) -> str:
    """Remove only the terminal printed-page footer, not recommendation content."""

    lines = text.rstrip().splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and re.fullmatch(r"Page\s+\d+", lines[-1].strip()):
        lines.pop()
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines).rstrip()


def _text_blocks(page: pymupdf.Page) -> tuple[TextBlock, ...]:
    blocks: list[TextBlock] = []
    page_dict = page.get_text("dict", sort=True)
    for raw_block in page_dict.get("blocks", []):
        if "lines" not in raw_block:
            continue
        line_texts: list[str] = []
        font_sizes: list[float] = []
        fonts: list[str] = []
        for line in raw_block["lines"]:
            spans = line.get("spans", [])
            line_text = "".join(span.get("text", "") for span in spans).strip()
            if line_text:
                line_texts.append(line_text)
            for span in spans:
                if span.get("text", "").strip():
                    font_sizes.append(float(span.get("size", 0.0)))
                    fonts.append(str(span.get("font", "")))
        text = " ".join(line_texts).strip()
        if not text:
            continue
        blocks.append(
            TextBlock(
                text=text,
                y0=float(raw_block["bbox"][1]),
                max_font_size=max(font_sizes, default=0.0),
                fonts=tuple(fonts),
            )
        )
    return tuple(blocks)


def extract_pages(pdf_path: str | Path) -> list[ExtractedPage]:
    """Extract every page while opening the source PDF strictly read-only."""

    path = Path(pdf_path)
    if not path.is_file():
        raise FileNotFoundError(f"Benchmark PDF not found: {path}")
    if path.suffix.lower() != ".pdf":
        raise ValueError(f"Expected a PDF input, got: {path}")

    pages: list[ExtractedPage] = []
    with pymupdf.open(path) as document:
        for page_index, page in enumerate(document):
            raw_text = page.get_text("text", sort=True)
            pages.append(
                ExtractedPage(
                    pdf_page=page_index + 1,
                    benchmark_page=extract_printed_page_number(raw_text),
                    text=remove_printed_page_footer(raw_text),
                    top_blocks=_text_blocks(page),
                )
            )
    return pages


def _styled_lines(page: pymupdf.Page, rectangle: tuple[float, ...]) -> tuple[StyledLine, ...]:
    lines: list[StyledLine] = []
    cell_dict = page.get_text("dict", clip=rectangle, sort=True)
    for block in cell_dict.get("blocks", []):
        for line in block.get("lines", []):
            spans = [span for span in line.get("spans", []) if span.get("text", "").strip()]
            text = "".join(span.get("text", "") for span in spans).strip()
            if text:
                lines.append(
                    StyledLine(
                        text=text,
                        max_font_size=max(float(span.get("size", 0.0)) for span in spans),
                    )
                )
    return tuple(lines)


def _extract_page_tables(page: pymupdf.Page) -> list[ExtractedTable]:
    tables: list[ExtractedTable] = []
    # PyMuPDF currently prints an optional layout-package hint. It is irrelevant to
    # deterministic extraction, so keep CLI output focused on conversion results.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        finder = page.find_tables()
    for table in finder.tables:
        plain_rows = table.extract()
        extracted_rows: list[tuple[ExtractedCell | None, ...]] = []
        for row_index, row in enumerate(table.rows):
            cells: list[ExtractedCell | None] = []
            for column_index, rectangle in enumerate(row.cells):
                if rectangle is None:
                    cells.append(None)
                    continue
                plain_text = ""
                if row_index < len(plain_rows) and column_index < len(plain_rows[row_index]):
                    plain_text = plain_rows[row_index][column_index] or ""
                cells.append(
                    ExtractedCell(
                        text=plain_text.strip(),
                        lines=_styled_lines(page, rectangle),
                    )
                )
            extracted_rows.append(tuple(cells))
        tables.append(ExtractedTable(rows=tuple(extracted_rows)))
    return tables


def extract_tables_for_pages(
    pdf_path: str | Path, pdf_page_numbers: Iterable[int]
) -> dict[int, list[ExtractedTable]]:
    """Extract tables only from selected one-based physical PDF pages.

    Table extraction failures safely produce no structured rows. The full table text
    remains present in ``raw_source_text`` for later human review.
    """

    selected = sorted(set(pdf_page_numbers))
    results: dict[int, list[ExtractedTable]] = {number: [] for number in selected}
    if not selected:
        return results

    path = Path(pdf_path)
    with pymupdf.open(path) as document:
        for number in selected:
            if not 1 <= number <= document.page_count:
                continue
            try:
                results[number] = _extract_page_tables(document[number - 1])
            except (RuntimeError, ValueError, TypeError):
                results[number] = []
    return results

