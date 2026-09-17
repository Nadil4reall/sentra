# SENTRA

## A Layered Framework for Automated CIS Security Control Enforcement on Linux Systems

SENTRA is a university cybersecurity research Proof of Concept. It converts CIS
recommendations into structured records, adds reviewable SENTRA knowledge, profiles an
Ubuntu target without changing it, and evaluates dependency and compatibility evidence.

**Milestones 1–4 are implemented. Milestone 5 sandbox validation is next.** SENTRA is
not a production hardening platform, a CIS compliance scanner, or a claim of complete
CIS enforcement. No selected control has been applied by Milestones 1–4.

## The research story

```text
M1  What does CIS say?
                ↓
M2  What should SENTRA check?
                ↓
M3  What is actually on Ubuntu?
                ↓
M4  Do the control requirements and target evidence conflict?
                ↓
M5  Test the candidate control in a sandbox.                 NEXT
```

## Project status

| Milestone | Output | Status |
|---|---|---|
| M1 — benchmark ingestion | Machine-readable CIS control catalog | ✅ Implemented |
| M2 — control enrichment | Ten PoC knowledge records | ✅ Implemented; metadata remains `needs_review` |
| M3 — target profiling | Read-only Ubuntu 24.04 target profile | ✅ Implemented and validated on one real target |
| M4 — compatibility analysis | Evidence-traceable compatibility report | ✅ Implemented and tested with synthetic fixtures; real-profile run pending |
| M5 — sandbox validation | Isolated control experiment | 🔜 Next |
| M6–M8 | Controller/agent, deployment verification, dashboard/audit trail | Planned |

### Verified results at a glance

| Layer | Result |
|---|---:|
| M1 source pages processed | 1,078 |
| M1 recommendations detected | 312: 291 Automated, 21 Manual |
| M1 YAML controls valid | 312 / 312 |
| M2 representative PoC controls | 10 across six security areas |
| M3 fact requests | 51 requests, 47 unique facts |
| M4 deterministic rules | 19 across all ten PoC controls |
| M4 automated tests | 65 passed |
| Full M1–M4 suite | 187 passed, 0 failed |

Automated tests establish software behavior. The recorded Ubuntu experiment establishes
representative M3 host evidence. It does **not** establish a real-host M4 result.

## Main architecture

```text
Licensed CIS benchmark
          │
          ▼
┌──────────────────────────────┐
│ M1  Parse + validate controls│  Audit/Remediation text stays data
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ M2  Add SENTRA enrichment    │  required facts, conflicts, prerequisites
└──────────────┬───────────────┘
               │ knowledge                         target evidence
               │                                      ▲
               │             ┌────────────────────────┴─────┐
               │             │ M3  Read-only Ubuntu profiler│
               │             └──────────────────────────────┘
               ▼                                      │
┌─────────────────────────────────────────────────────┴─────┐
│ M4  Deterministic dependency + compatibility analysis     │
└───────────────────────────┬───────────────────────────────┘
                            ▼
          Structured, provisional compatibility report
                            │
                            ▼
                 M5 sandbox validation — next
```

## Milestone 1 — CIS benchmark ingestion

> **Question:** What does CIS say?

```text
CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0
                    ↓
        PyMuPDF page/table extraction
                    ↓
    Recommendation detection + field parsing
                    ↓
        Pydantic validation + YAML output
```

| Result | Value |
|---|---:|
| PDF pages | 1,078 |
| Recommendations | 312 |
| Automated / Manual | 291 / 21 |
| Valid YAML | 312 / 312 |
| M1 tests | 13 passed |

Recommendation detection combines dotted numeric IDs, `Ensure` titles, assessment
labels, and heading-layout evidence. CIS Audit and Remediation content is retained for
traceability but is not executed. The licensed PDF and full generated catalog remain
local and are Git-ignored.

## Milestone 2 — PoC selection and SENTRA enrichment

> **Question:** What should SENTRA check?

Ten controls cover kernel, network, firewall, SSH, auditing, and file permissions.
Their separate enrichment records:

- required target facts;
- explicit prerequisites and possible conflicts;
- affected services, files, and packages where supported by the source;
- sandbox and validation requirements; and
- administrator-approval requirements.

```text
data/controls/       CIS-derived records; unchanged by enrichment
data/poc/enriched/   SENTRA-specific knowledge
```

Every enrichment remains `derivation_status: needs_review`. M4 preserves that state;
it never silently treats generated or inferred metadata as human-reviewed.

## Milestone 3 — read-only Ubuntu target profiler

> **Question:** What is actually on Ubuntu?

```text
M2 required_target_facts
            ↓
Deduplicate 51 requests into 47 facts
            ↓
Allowlisted read-only collectors
            ↓
Validated YAML target profile
```

The profiler runs locally on the host being examined. It does not require an address
or provide remote execution. Facts preserve one of four states:

| Fact state | Meaning |
|---|---|
| `collected` | Reliable evidence was obtained |
| `unavailable` | A collector exists, but evidence could not be obtained in this run |
| `unsupported` | The fact cannot be determined safely from local technical evidence |
| `error` | An unexpected collection failure occurred |

Non-collected evidence is never converted to `false`.

### Recorded M3 Ubuntu experiment

| Property | Recorded value |
|---|---|
| Operating system | Ubuntu 24.04.5 LTS |
| Kernel | `6.8.0-139-generic` |
| Architecture | `aarch64` |

| Run | Requested | Collected | Unavailable | Unsupported | Errors |
|---|---:|---:|---:|---:|---:|
| Normal user | 47 | 36 | 6 | 5 | 0 |
| Elevated, read-only | 47 | 40 | 0 | 7 | 0 |

Representative manual checks matched the generated profile. This is one target
experiment, not certification across every Ubuntu installation or architecture.

## Milestone 4 — dependency and compatibility analysis

> **Question:** Does SENTRA knowledge for a selected control, compared with supplied
> target facts, indicate a dependency, compatibility concern, missing evidence, or a
> need for administrator review?

M4 is a **data analysis and decision layer**. It is not a CIS compliance scanner and
does not use generic PASS/FAIL labels.

### Inputs and output

```text
M2 PoC manifest + matching enrichment       Explicit M3 profile path
data/poc/poc_controls.yaml                  data/profiles/*.yaml
data/poc/enriched/*.yaml                              │
                    └──────────────┬──────────────────┘
                                   ▼
                   Validate relationships + resolve evidence
                                   ▼
                       Evaluate 19 static Python rules
                                   ▼
             YAML report in data/compatibility/ when requested
```

The profile path is explicit. M4 never starts M3, discovers a host, requests an IP
address, or connects to Ubuntu.

### Compatibility result states

| State | Meaning |
|---|---|
| `no_known_conflict` | Available evidence triggered no currently defined compatibility concern |
| `warning` | Collected evidence matches a documented or defined compatibility risk |
| `review_required` | Deployment context or an administrator decision is required |
| `insufficient_evidence` | Necessary technical evidence is unavailable or erroneous |

`no_known_conflict` is limited to the current evidence and rule catalog. It is not a
safety, compliance, or deployment verdict.

### Provisional metadata

Each control result retains:

| Field | Current value / purpose |
|---|---|
| `metadata_review_status` | `needs_review`, copied from M2 enrichment |
| `provisional` | `true` while enrichment has not been reviewed |
| `evidence_used` | Fact name, state, value, requester traceability, and reason |
| `triggered_rules` | Stable rule ID, result, explanation, and evidence facts |
| `missing_or_contextual_evidence` | Uncertainty requiring evidence or human context |

A provisional decision can support development and review without silently approving
the underlying metadata.

### Components

```text
loaders ──► evidence ──► rules ──► engine ──► report
   │                       ▲          │           │
   └──────── models ───────┴──────────┘           └── YAML
                                      ▲
                                     CLI
```

| File | Responsibility |
|---|---|
| `models.py` | Strict schemas for states, evidence, results, rules, and report summaries |
| `loaders.py` | Load and cross-check the M2 manifest/enrichments and supplied M3 profile |
| `evidence.py` | Resolve facts without collapsing unavailable, unsupported, or error states |
| `rules.py` | Hold the explicit, deterministic, traceable PoC rules |
| `engine.py` | Coordinate per-control evaluation and preserve uncertainty |
| `report.py` | Serialize the structured report as YAML |
| `cli.py` | List rules or evaluate an explicitly supplied profile |

### Implemented rule catalog

The 19 rules come only from M2 `possible_conflicts`, `prerequisites`,
`required_target_facts`, and `evidence.notes`. They do not interpret CIS audit values as
compliance results or invent new dependencies.

| Control | Rule ID | M2 source basis |
|---|---|---|
| <code>1.1.1&#46;1</code> | `cramfs-required-workload` | `possible_conflicts`: target workload requires cramfs |
| <code>1.1.1&#46;6</code> | `overlayfs-container-workload` | `possible_conflicts` + `evidence.notes`: container disruption concern |
| `3.3.1` | `ip-forwarding-deployment-role` | `possible_conflicts`: router and CSP deployment roles |
| `3.3.1` | `ip-forwarding-source-precedence-review` | `possible_conflicts` + `evidence.notes`: sysctl precedence and IPv6 context |
| `4.2.1` | `ufw-iptables-prerequisite` | `prerequisites`: UFW depends on iptables |
| `4.2.1` | `ufw-other-firewall-utility` | `possible_conflicts` + `evidence.notes`: another firewall utility |
| `4.2.3` | `ufw-service-state-evidence` | `required_target_facts` + `evidence.notes`: UFW service/status evidence |
| `4.2.3` | `ufw-live-remote-session` | `possible_conflicts`: connection-loss and lockout risk |
| `4.2.3` | `ufw-ssh-22-safeguard` | `prerequisites` + `evidence.notes`: documented TCP/22 safeguard and alternate-port review |
| `5.1.19` | `ssh-empty-passwords-effective-evidence` | `required_target_facts`: effective SSH setting |
| `5.1.19` | `ssh-empty-passwords-match-context` | `possible_conflicts`: connection-specific `Match` behavior |
| `5.1.19` | `ssh-empty-passwords-include-precedence` | `possible_conflicts`: `Include` ordering and first occurrence |
| `5.1.20` | `ssh-root-login-effective-evidence` | `required_target_facts`: effective SSH setting |
| `5.1.20` | `ssh-root-login-match-context` | `possible_conflicts`: connection-specific `Match` behavior |
| `5.1.20` | `ssh-root-login-include-precedence` | `possible_conflicts`: `Include` ordering and first occurrence |
| `5.1.20` | `ssh-root-login-administrator-path` | `evidence.notes`: individual-admin and root-escalation path |
| <code>6.2.1&#46;2</code> | `auditd-required-evidence` | `required_target_facts`: auditd service evidence; no invented conflict |
| `7.1.1` | `passwd-readability-preservation-review` | `possible_conflicts`: `/etc/passwd` must remain readable |
| `7.1.5` | `shadow-required-evidence` | `required_target_facts`: file and target shadow-group evidence; no invented conflict |

Examples of conservative behavior:

- a non-empty container-application list triggers the documented OverlayFS warning;
- unknown router or CSP deployment context requires review—forwarding value `0` alone
  is not treated as a conclusion;
- live remote-management evidence preserves the documented UFW lockout concern;
- SSH TCP/22 evidence is not used to assume every SSH session uses that port;
- unsupported administrator fallback/escalation context requires review; and
- controls without an explicit conflict still require their named evidence, but do not
  become compliance checks.

### How M1–M4 connect

The OverlayFS PoC path illustrates the separation of responsibilities:

```text
M1  Preserve the benchmark recommendation as structured YAML
                              ↓
M2  Record the documented container-workload compatibility concern
                              ↓
M3  Collect container_applications_in_use and module evidence
                              ↓
M4  Compare the supplied evidence with the explicit rule
       ├── non-empty list ─────────► warning
       ├── empty list ─────────────► no container rule triggered
       └── unavailable / error ────► insufficient_evidence
```

All outcomes remain provisional while the M2 enrichment is `needs_review`.

### Report shape

| Level | Included fields |
|---|---|
| Report | `report_version`, `generated_at`, profile source, target summary |
| Per control | ID, category, result, provisional/review status, evidence, rules, explanation |
| Overall | controls evaluated and counts for all four result states plus provisional count |

There is deliberately no global “system safe” field.

### M4 safety boundary

| M4 may | M4 must not |
|---|---|
| Read the M2 manifest and enrichment | Invoke the target profiler or SSH |
| Read one explicitly supplied M3 YAML profile | Require or use an IP address |
| Evaluate fixed, ordinary Python rules | Execute subprocesses, `systemctl`, UFW, SSHD, or `modprobe` |
| Print YAML or write one requested report | Execute CIS Audit or Remediation content |
| Reject unsupported/non-Ubuntu profiles | Install packages, change services/files, or apply a control |

The rule layer contains no AI/LLM calls, `eval()`, `exec()`, or user-defined expression
language. Identical evidence produces the same compatibility decision.

### M4 validation status

| Validation | Status |
|---|---|
| Core, rule, acceptance, determinism, serialization, and safety tests | 65 passed |
| Full M1–M4 regression suite | 187 passed, 0 failed |
| Real M3-profile evaluation by M4 | **Not yet run or manually reviewed** |

Synthetic fixtures are test evidence, not real-Ubuntu validation. A real M4 result must
not be claimed until the following command is run against a real M3 profile available
locally and its report is manually reviewed:

```bash
python -m src.compatibility_engine.cli \
  --profile data/profiles/target-profile.yaml \
  --output data/compatibility/target-profile-compatibility.yaml
```

List the auditable rule catalog without loading a profile:

```bash
python -m src.compatibility_engine.cli --list-rules
```

## Current research boundary

### Implemented

- one-version CIS Ubuntu benchmark ingestion;
- ten-control PoC enrichment with explicit review status;
- local read-only Ubuntu 24.04 profiling;
- deterministic dependency and compatibility analysis; and
- structured, evidence-traceable YAML reports.

### Not implemented

- M5 sandbox execution or validation;
- CIS Audit or Remediation execution;
- automatic deployment or post-deployment verification;
- controller, target agent, centralized database, dashboard, or approval workflow.

### Limitations

- Benchmark ingestion is validated against one benchmark and version.
- Only ten of 312 recommendations have PoC enrichment and M4 rules.
- All current enrichment is still `needs_review`; therefore all M4 results are
  provisional.
- M3 real-host evidence represents one Ubuntu target and varies with permissions and
  execution context.
- Operational context that cannot be determined technically remains explicit rather
  than being guessed.
- M4 has not yet been run against and manually reviewed with a real M3 profile.

## Data storage

| Milestone | Path | Repository policy |
|---|---|---|
| M1 | `data/controls/*.yaml` | Full local conversion ignored; development sample tracked |
| M2 | `data/poc/poc_controls.yaml`, `data/poc/enriched/*.yaml` | Tracked |
| M3 | `data/profiles/*.yaml` | Generated profiles ignored |
| M4 | `data/compatibility/*.yaml` | Generated reports ignored; `.gitkeep` tracked |

## Project structure

```text
data/
├── controls/                    M1 CIS-derived records
├── poc/                         M2 manifest + enrichment
├── profiles/                    M3 generated profiles; Git-ignored
└── compatibility/              M4 generated reports; Git-ignored

src/
├── pdf_extractor.py             M1 extraction
├── control_detector.py          M1 recommendation detection
├── control_parser.py            M1 field parsing
├── poc_models.py                M2 validation
├── target_profiler/             M3 read-only profiler
└── compatibility_engine/        M4 analysis package
    ├── __init__.py
    ├── models.py
    ├── loaders.py
    ├── evidence.py
    ├── rules.py
    ├── engine.py
    ├── report.py
    └── cli.py

tests/
├── test_compatibility_engine.py
├── test_compatibility_engine_rules.py
└── test_compatibility_engine_acceptance.py
```

## Technical usage

Requirements: Python 3.11+, PyMuPDF, PyYAML, Pydantic, and pytest.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
```

Generate an M3 profile locally on the Ubuntu 24.04 host:

```bash
python -m src.target_profiler.cli \
  --format yaml \
  --output data/profiles/target-profile.yaml
```

The benchmark converter requires the licensed PDF to be supplied locally. The PDF,
full generated catalog, host profiles, and compatibility reports must not be
redistributed as normal repository content.

## Next — Milestone 5 sandbox validation

M5 will test candidate controls in an isolated environment and collect pre-change,
post-change, service-health, and rollback evidence. M4 does not start that work or use
its absence as permission to deploy.

## Research and licensing note

Results are specific to the named CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0, the ten
PoC enrichments, the implemented profiler and compatibility rules, and the recorded
experiment. The CIS benchmark is licensed source material and is not distributed with
this project.
