"""Parse recommendation sections without interpreting embedded commands."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .control_detector import DetectedControl
from .models import (
    CISControlMapping,
    ControlData,
    ControlDocument,
    MitreAttackMappings,
    SourceLocation,
    Verification,
    benchmark_metadata,
)
from .pdf_extractor import ExtractedCell, ExtractedTable


SECTION_NAMES = (
    "Profile Applicability",
    "Description",
    "Rationale",
    "Impact",
    "Audit",
    "Remediation",
    "Default Value",
    "References",
    "Additional Information",
    "CIS Controls",
    "MITRE ATT&CK Mappings",
)
SECTION_RE = re.compile(
    r"^(?P<name>" + "|".join(re.escape(name) for name in SECTION_NAMES) + r"):?[ \t]*$",
    re.MULTILINE,
)


def split_sections(raw_text: str) -> dict[str, str]:
    """Split exact, standalone CIS section labels from their source content."""

    matches = list(SECTION_RE.finditer(raw_text))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(raw_text)
        sections[match.group("name")] = raw_text[start:end].strip()
    return sections


def _optional_text(sections: dict[str, str], name: str) -> str | None:
    value = sections.get(name, "").strip()
    return value or None


def parse_profile_applicability(text: str | None) -> list[str]:
    if not text:
        return []
    profiles: list[str] = []
    for line in text.splitlines():
        value = re.sub(r"^[\s•*-]+", "", line).strip()
        if re.match(r"^Level\s+\d+\s*-\s*\S", value, re.IGNORECASE):
            profiles.append(value)
    return list(dict.fromkeys(profiles))


def parse_references(text: str | None) -> list[str]:
    if not text:
        return []
    starts = list(re.finditer(r"(?m)^\s*\d+\.\s+", text))
    if starts:
        references: list[str] = []
        for index, start in enumerate(starts):
            end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
            value = text[start.end() : end].strip()
            if value:
                references.append(re.sub(r"\s+", " ", value))
        return references

    fallback: list[str] = []
    for line in text.splitlines():
        value = re.sub(r"^[\s•*-]+", "", line).strip()
        if value:
            fallback.append(value)
    return fallback


def _cell_text(cell: ExtractedCell | None) -> str:
    return cell.text.strip() if cell is not None else ""


def _parse_cis_row(row: tuple[ExtractedCell | None, ...]) -> CISControlMapping | None:
    if len(row) < 2:
        return None
    version = _cell_text(row[0])
    control_cell = row[1]
    if not re.fullmatch(r"v\d+", version, re.IGNORECASE) or control_cell is None:
        return None

    # The benchmark distinguishes linked control titles (12 pt) from descriptions
    # (8.52 pt). If that evidence is missing, skip the row rather than guessing.
    title_lines = [line.text for line in control_cell.lines if line.max_font_size >= 10.0]
    description_lines = [line.text for line in control_cell.lines if line.max_font_size < 10.0]
    title_text = re.sub(r"\s+", " ", " ".join(title_lines)).strip()
    match = re.fullmatch(r"(?P<id>\d+(?:\.\d+)*)\s+(?P<title>.+)", title_text)
    if not match:
        return None

    groups: list[str] = []
    for column, group in ((2, "IG 1"), (3, "IG 2"), (4, "IG 3")):
        if column < len(row) and _cell_text(row[column]):
            groups.append(group)

    description = re.sub(r"\s+", " ", " ".join(description_lines)).strip() or None
    return CISControlMapping(
        version=version,
        control_id=match.group("id"),
        title=match.group("title").strip(),
        description=description,
        implementation_groups=groups,
    )


def parse_cis_controls(tables: Iterable[ExtractedTable]) -> list[CISControlMapping]:
    """Parse only confidently structured CIS Controls rows from detected tables."""

    mappings: list[CISControlMapping] = []
    seen: set[tuple[str, str]] = set()
    for table in tables:
        for row in table.rows:
            mapping = _parse_cis_row(row)
            if mapping is None:
                continue
            key = (mapping.version.lower(), mapping.control_id)
            if key not in seen:
                mappings.append(mapping)
                seen.add(key)
    return mappings


def _unique_matches(pattern: str, text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(pattern, text, flags=re.IGNORECASE)))


def parse_mitre_attack(text: str | None) -> MitreAttackMappings:
    source = text or ""
    return MitreAttackMappings(
        techniques=_unique_matches(r"\bT\d{4}(?:\.\d{3})?\b", source),
        tactics=_unique_matches(r"\bTA\d{4}\b", source),
        mitigations=_unique_matches(r"\bM\d{4}\b", source),
    )


def parse_control(
    detected: DetectedControl,
    raw_source_text: str,
    tables: Iterable[ExtractedTable] = (),
) -> ControlDocument:
    """Build a validated control document from extracted data only."""

    sections = split_sections(raw_source_text)
    return ControlDocument(
        benchmark=benchmark_metadata(),
        control=ControlData(
            id=detected.heading.control_id,
            title=detected.heading.title,
            assessment_status=detected.heading.assessment_status,
            profile_applicability=parse_profile_applicability(
                _optional_text(sections, "Profile Applicability")
            ),
            description=_optional_text(sections, "Description"),
            rationale=_optional_text(sections, "Rationale"),
            impact=_optional_text(sections, "Impact"),
            audit=_optional_text(sections, "Audit"),
            remediation=_optional_text(sections, "Remediation"),
            default_value=_optional_text(sections, "Default Value"),
            references=parse_references(_optional_text(sections, "References")),
            additional_information=_optional_text(sections, "Additional Information"),
            cis_controls=parse_cis_controls(tables),
            mitre_attack=parse_mitre_attack(
                _optional_text(sections, "MITRE ATT&CK Mappings")
            ),
        ),
        source=SourceLocation(
            pdf_page_start=detected.pdf_page_start,
            pdf_page_end=detected.pdf_page_end,
            benchmark_page_start=detected.benchmark_page_start,
            benchmark_page_end=detected.benchmark_page_end,
        ),
        # PDF line wrapping can alter shell syntax. All extracted code therefore
        # remains explicitly unverified and requires human integrity review.
        verification=Verification(status="unverified", code_integrity="needs_review"),
        raw_source_text=raw_source_text,
    )

