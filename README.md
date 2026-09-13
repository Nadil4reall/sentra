# SENTRA - Milestone 1

SENTRA Milestone 1 is a proof-of-concept, read-only converter for the **CIS Ubuntu
Linux 24.04 LTS Benchmark v1.0.0**. It detects CIS recommendation headings in the
local benchmark PDF and writes traceable, validated YAML records.

This milestone does **not** implement sandboxing, Terraform, target agents, Ansible,
dependency analysis, remediation execution, APIs, deployment, a dashboard, or LLM
integration.

## Safety boundary

- The benchmark PDF is opened read-only and is never copied, changed, uploaded, or
  included in version control.
- Audit and Remediation commands are extracted as plain text data only. They are never
  evaluated, invoked, validated, or repaired.
- Every control is emitted with `verification.status: unverified` and
  `verification.code_integrity: needs_review`.
- The complete extracted recommendation text is retained in `raw_source_text` so a
  reviewer can compare YAML fields with the licensed local source.

## Requirements

- Python 3.11 or newer
- PyMuPDF
- PyYAML
- Pydantic
- pytest

Create an environment and install the pinned dependency ranges:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Place the licensed benchmark at this local-only path:

```text
benchmark/CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.pdf
```

The `.gitignore` excludes all PDFs in `benchmark/` to reduce redistribution risk.

## Convert the first five recommendations

```bash
.venv/bin/python -m src.cli \
  benchmark/CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.pdf \
  --limit 5
```

This writes one record per selected recommendation under `data/controls/` and a full
detection index to `data/catalog.yaml`. The catalog distinguishes all detected
recommendations from the subset generated during the limited development run.

The CLI also accepts `--output-dir`. Omitting `--limit` is implemented for a later
full-catalog milestone, but it is deliberately not used in the Milestone 1 run.

## Design

```text
src/pdf_extractor.py   read-only page text, printed-page footers, and tables
src/control_detector.py styled heading detection and multi-page boundaries
src/control_parser.py  named sections plus conservative CIS/MITRE mappings
src/models.py          strict Pydantic output contracts
src/yaml_writer.py     safe, deterministic YAML serialization
src/cli.py             conversion orchestration
```

Recommendation detection requires all of the following evidence:

1. A dotted numeric control ID with at least three numeric components.
2. A title beginning with `Ensure` and ending in `(Automated)` or `(Manual)`.
3. The benchmark's recommendation-heading presentation: italic text of at least 15 pt
   in the top page band.

These constraints prevent numbered section headings and table-of-contents entries from
being mistaken for recommendations. A control extends through the page before the next
recommendation heading; the final control stops before the appendix.

## Known parser limitations

- PDF extraction preserves visual line wraps. In shell snippets, those wraps can split
  tokens and make copied commands invalid; the converter never repairs them.
- CIS Controls table rows are structured only when font-size and cell evidence clearly
  distinguish the control title from its description. Ambiguous rows remain available
  in `raw_source_text` and produce an empty structured list rather than guessed data.
- MITRE ATT&CK mappings are limited to explicit `T####`, `TA####`, and `M####` values in
  the recommendation's mapping section.
- Repeated headers/footers other than the terminal `Page N` footer are not heuristically
  deleted, because preserving source text is safer than silently dropping content.

## Tests

```bash
.venv/bin/python -m pytest -q
```

The suite covers heading and status detection, multi-page boundaries, both page-number
systems, missing fields, YAML round trips, raw-text preservation, verification warnings,
structured CIS/MITRE mappings, malformed-table fallback, and the local benchmark's
first-five integration boundaries.

## Milestone 2 — PoC Control Selection

Milestone 2 selects ten representative controls across kernel modules, networking,
firewalls, SSH, auditing, and file permissions. This deliberately small set keeps later
proof-of-concept execution and validation focused while the complete 312-control
CIS-derived catalog continues to exist locally under `data/controls/`.

CIS source records are not rewritten. The PoC index is stored in
`data/poc/poc_controls.yaml`, while SENTRA-derived target facts, compatibility evidence,
sandbox requirements, and review state are kept separately under `data/poc/enriched/`.
Every enrichment remains `needs_review`.

This milestone performs data preparation and read-only validation only. It does not run
Audit or Remediation commands, create a sandbox, connect to a host, or modify a system.

Display the validated control-set summary with:

```bash
.venv/bin/python -m src.poc_summary
```
