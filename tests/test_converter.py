from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.control_detector import (
    DetectedControl,
    Heading,
    detect_controls,
    detect_heading,
    parse_heading_text,
    raw_text_for_control,
)
from src.control_parser import parse_cis_controls, parse_control, parse_mitre_attack
from src.pdf_extractor import (
    ExtractedCell,
    ExtractedPage,
    ExtractedTable,
    StyledLine,
    TextBlock,
    extract_pages,
    extract_printed_page_number,
    remove_printed_page_footer,
)
from src.yaml_writer import control_filename, serialize_yaml


ROOT = Path(__file__).resolve().parents[1]
LOCAL_BENCHMARK = ROOT / "benchmark" / "CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.pdf"


def heading_block(text: str) -> TextBlock:
    return TextBlock(
        text=text,
        y0=72.0,
        max_font_size=16.0,
        fonts=("Arial-ItalicMT",),
    )


def section_block(text: str) -> TextBlock:
    return TextBlock(
        text=text,
        y0=72.0,
        max_font_size=14.0,
        fonts=("Arial-BoldMT",),
    )


def page(
    pdf_page: int,
    benchmark_page: int | None,
    text: str,
    *blocks: TextBlock,
) -> ExtractedPage:
    return ExtractedPage(
        pdf_page=pdf_page,
        benchmark_page=benchmark_page,
        text=text,
        top_blocks=tuple(blocks),
    )


def detected_control(status: str = "Automated") -> DetectedControl:
    return DetectedControl(
        heading=Heading("1.1.1.1", "Ensure example is configured", status),
        start_page_index=0,
        end_page_index=1,
        pdf_page_start=24,
        pdf_page_end=25,
        benchmark_page_start=23,
        benchmark_page_end=24,
    )


def cell(text: str, *lines: tuple[str, float]) -> ExtractedCell:
    return ExtractedCell(
        text=text,
        lines=tuple(StyledLine(line_text, size) for line_text, size in lines),
    )


def test_recommendation_heading_detection_rejects_section_headings() -> None:
    recommendation = page(
        24,
        23,
        "source",
        heading_block("1.1.1.1 Ensure cramfs kernel module is not available (Automated)"),
    )
    section = page(
        23,
        22,
        "source",
        section_block("1.1.1 Configure Filesystem Kernel Modules"),
    )

    assert detect_heading(recommendation) == Heading(
        "1.1.1.1", "Ensure cramfs kernel module is not available", "Automated"
    )
    assert detect_heading(section) is None


@pytest.mark.parametrize(
    ("source", "control_id", "status"),
    [
        (
            "1.1.1.2 Ensure freevxfs kernel module is not available\n(Automated)",
            "1.1.1.2",
            "Automated",
        ),
        (
            "1.1.1.10 Ensure unused filesystems kernel modules are not available (Manual)",
            "1.1.1.10",
            "Manual",
        ),
        ("3.3.1 Ensure ip forwarding is disabled (Automated)", "3.3.1", "Automated"),
    ],
)
def test_control_id_and_assessment_status_extraction(
    source: str, control_id: str, status: str
) -> None:
    heading = parse_heading_text(source)
    assert heading is not None
    assert heading.control_id == control_id
    assert heading.assessment_status == status


def test_multi_page_boundaries_and_both_page_number_systems() -> None:
    pages = [
        page(
            24,
            23,
            "first heading",
            heading_block("1.1.1.1 Ensure first control is configured (Automated)"),
        ),
        page(25, 24, "first continuation"),
        page(
            26,
            25,
            "second heading",
            heading_block("1.1.1.2 Ensure second control is configured (Manual)"),
        ),
        page(27, 26, "second continuation"),
        page(28, 27, "Appendix: Summary", section_block("Appendix: Summary Table")),
    ]

    controls = detect_controls(pages)

    assert len(controls) == 2
    assert (controls[0].pdf_page_start, controls[0].pdf_page_end) == (24, 25)
    assert (controls[0].benchmark_page_start, controls[0].benchmark_page_end) == (23, 24)
    assert (controls[1].pdf_page_start, controls[1].pdf_page_end) == (26, 27)
    assert raw_text_for_control(controls[0], pages) == "first heading\n\nfirst continuation"


def test_printed_page_tracking_and_footer_removal() -> None:
    text = "Recommendation data\n\nPage 23\n"
    assert extract_printed_page_number(text) == 23
    assert remove_printed_page_footer(text) == "Recommendation data"
    assert remove_printed_page_footer("The phrase Page 23 is content") == (
        "The phrase Page 23 is content"
    )


def test_missing_fields_use_null_or_empty_lists() -> None:
    raw = """1.1.1.1 Ensure example is configured (Automated)

Description:
Only a description is present.
"""
    document = parse_control(detected_control(), raw)

    assert document.control.description == "Only a description is present."
    assert document.control.rationale is None
    assert document.control.impact is None
    assert document.control.audit is None
    assert document.control.remediation is None
    assert document.control.default_value is None
    assert document.control.references == []
    assert document.control.profile_applicability == []
    assert document.control.cis_controls == []


def test_yaml_serialization_preserves_raw_text_and_nulls() -> None:
    raw = """1.1.1.1 Ensure example is configured (Automated)

Audit:
#!/usr/bin/env bash
printf '%s\\n' "data only"
"""
    document = parse_control(detected_control(), raw)

    serialized = serialize_yaml(document)
    loaded = yaml.safe_load(serialized)

    assert "raw_source_text: |" in serialized
    assert loaded["raw_source_text"] == raw
    assert loaded["control"]["impact"] is None
    assert loaded["verification"] == {
        "status": "unverified",
        "code_integrity": "needs_review",
    }


def test_structured_cis_controls_parsing() -> None:
    table = ExtractedTable(
        rows=(
            (
                cell("v8", ("v8", 12.0)),
                cell(
                    "4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
                    ("4.8 Uninstall or Disable Unnecessary Services on", 12.0),
                    ("Enterprise Assets and Software", 12.0),
                    ("Uninstall or disable unnecessary services on enterprise assets.", 8.52),
                ),
                cell("", ("", 8.52)),
                cell("●", ("●", 8.52)),
                cell("●", ("●", 8.52)),
            ),
        )
    )

    mappings = parse_cis_controls([table])

    assert len(mappings) == 1
    assert mappings[0].version == "v8"
    assert mappings[0].control_id == "4.8"
    assert mappings[0].title == (
        "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software"
    )
    assert mappings[0].implementation_groups == ["IG 2", "IG 3"]
    assert mappings[0].description == (
        "Uninstall or disable unnecessary services on enterprise assets."
    )


def test_unreliable_cis_table_falls_back_without_guessing() -> None:
    malformed = ExtractedTable(
        rows=((cell("v8", ("v8", 12.0)), cell("4.8 visually ambiguous")),)
    )
    assert parse_cis_controls([malformed]) == []


def test_mitre_attack_mappings_are_structured_and_deduplicated() -> None:
    mappings = parse_mitre_attack(
        "Techniques T1005, T1005.000, T1005; Tactics TA0005; Mitigations M1050"
    )
    assert mappings.techniques == ["T1005", "T1005.000"]
    assert mappings.tactics == ["TA0005"]
    assert mappings.mitigations == ["M1050"]


def test_control_filename() -> None:
    assert control_filename("1.1.1.1") == "1_1_1_1.yaml"


@pytest.mark.skipif(not LOCAL_BENCHMARK.exists(), reason="licensed local benchmark not present")
def test_local_benchmark_detects_expected_catalog_and_first_five_boundaries() -> None:
    pages = extract_pages(LOCAL_BENCHMARK)
    controls = detect_controls(pages)

    assert len(controls) == 312
    assert [control.heading.control_id for control in controls[:5]] == [
        "1.1.1.1",
        "1.1.1.2",
        "1.1.1.3",
        "1.1.1.4",
        "1.1.1.5",
    ]
    assert [
        (control.pdf_page_start, control.pdf_page_end) for control in controls[:5]
    ] == [(24, 28), (29, 33), (34, 38), (39, 43), (44, 48)]
    assert [
        (control.benchmark_page_start, control.benchmark_page_end)
        for control in controls[:5]
    ] == [(23, 27), (28, 32), (33, 37), (38, 42), (43, 47)]
