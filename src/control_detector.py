"""Detect CIS recommendation headings and their multi-page boundaries."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .pdf_extractor import ExtractedPage, TextBlock


HEADING_RE = re.compile(
    r"^(?P<id>\d+(?:\.\d+){2,})\s+"
    r"(?P<title>Ensure\s+.+?)\s+"
    r"\((?P<status>Automated|Manual)\)\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Heading:
    control_id: str
    title: str
    assessment_status: str


@dataclass(frozen=True)
class DetectedControl:
    heading: Heading
    start_page_index: int
    end_page_index: int
    pdf_page_start: int
    pdf_page_end: int
    benchmark_page_start: int | None
    benchmark_page_end: int | None


def parse_heading_text(text: str) -> Heading | None:
    """Parse a complete recommendation heading after collapsing visual wrapping."""

    normalized = re.sub(r"\s+", " ", text).strip()
    match = HEADING_RE.fullmatch(normalized)
    if not match:
        return None
    status = match.group("status").capitalize()
    return Heading(
        control_id=match.group("id"),
        title=match.group("title").strip(),
        assessment_status=status,
    )


def is_recommendation_heading_block(block: TextBlock) -> bool:
    """Distinguish styled recommendation headings from section/TOC entries."""

    italic = any("italic" in font.lower() or "oblique" in font.lower() for font in block.fonts)
    return block.y0 <= 130.0 and block.max_font_size >= 15.0 and italic


def detect_heading(page: ExtractedPage) -> Heading | None:
    for block in page.top_blocks:
        if is_recommendation_heading_block(block):
            heading = parse_heading_text(block.text)
            if heading is not None:
                return heading
    return None


def _is_appendix_boundary(page: ExtractedPage) -> bool:
    for block in page.top_blocks:
        if block.y0 <= 140.0 and block.max_font_size >= 13.0:
            if re.match(r"^Appendix(?:\s|:)", block.text, re.IGNORECASE):
                return True
    return False


def _is_numbered_section_boundary(page: ExtractedPage) -> bool:
    """Recognize styled chapter/section headings without treating TOC rows as content."""

    for block in page.top_blocks:
        if block.y0 > 140.0 or block.max_font_size < 13.0:
            continue
        normalized = re.sub(r"\s+", " ", block.text).strip()
        if parse_heading_text(normalized) is not None:
            return True
        bold = any("bold" in font.lower() for font in block.fonts)
        if bold and re.match(r"^\d+(?:\.\d+)*\s+\S", normalized):
            return True
    return False


def _is_structural_boundary(page: ExtractedPage) -> bool:
    return _is_appendix_boundary(page) or _is_numbered_section_boundary(page)


def detect_controls(pages: list[ExtractedPage]) -> list[DetectedControl]:
    """Detect recommendations and stop before the next structural heading.

    A numbered section introduction can occur between two recommendations. Treating
    only the next recommendation as a boundary would incorrectly attach that section
    prose to the preceding control.
    """

    starts: list[tuple[int, Heading]] = []
    for index, page in enumerate(pages):
        heading = detect_heading(page)
        if heading is not None:
            starts.append((index, heading))

    controls: list[DetectedControl] = []
    for start_index, heading in starts:
        end_index = len(pages) - 1
        for possible_end in range(start_index + 1, len(pages)):
            if _is_structural_boundary(pages[possible_end]):
                end_index = possible_end - 1
                break
        controls.append(
            DetectedControl(
                heading=heading,
                start_page_index=start_index,
                end_page_index=end_index,
                pdf_page_start=pages[start_index].pdf_page,
                pdf_page_end=pages[end_index].pdf_page,
                benchmark_page_start=pages[start_index].benchmark_page,
                benchmark_page_end=pages[end_index].benchmark_page,
            )
        )
    return controls


def raw_text_for_control(control: DetectedControl, pages: list[ExtractedPage]) -> str:
    """Return all extracted recommendation text, excluding only page footers."""

    return "\n\n".join(
        page.text for page in pages[control.start_page_index : control.end_page_index + 1]
    ).strip()
