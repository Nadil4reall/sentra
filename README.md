# SENTRA

## A Layered Framework for Automated CIS Security Control Enforcement on Linux Systems

SENTRA is a cybersecurity research Proof of Concept investigating how CIS security
controls could be applied more safely to Linux systems. The project is developing a
layered workflow that gathers and preserves evidence before any future remediation or
deployment decision is made.

The current implementation has completed Milestones 1–3: benchmark ingestion,
control enrichment, and read-only Ubuntu target profiling. It does **not** yet make
compatibility decisions, validate controls in a sandbox, execute remediation, deploy
changes, or provide a controller, agent, database, or dashboard.

## Project overview

Automated hardening can create operational risk when a recommendation is applied
without enough knowledge of the target system. Relevant information may include:

- the current operating-system configuration;
- installed packages and active services;
- technical and operational dependencies;
- existing workloads and administrative requirements; and
- possible conflicts between a security change and normal system use.

Ignoring this context can disrupt services or introduce compatibility problems.
SENTRA therefore separates understanding a control, understanding a target, deciding
compatibility, validating safely, and deploying with approval.

This is a research prototype, not a production-ready hardening platform and not a
claim of complete CIS enforcement.

## Research idea

Instead of directly applying CIS hardening recommendations to a target, SENTRA first
converts the recommendations into machine-readable controls, identifies the evidence
needed to reason about them, and profiles the target host. Later milestones will use
that evidence for compatibility analysis and sandbox validation before any approved
deployment.

The milestone questions provide a concise explanation of the research:

- **Milestone 1:** “What does CIS say?”
- **Milestone 2:** “What should SENTRA know before using the control?”
- **Milestone 3:** “What is actually present on this Ubuntu machine?”
- **Milestone 4:** “Does the selected control conflict with this target?”

## Layered research workflow

The complete research direction is shown below. The labels distinguish implemented
work from future work.

```text
IMPLEMENTED — MILESTONES 1–3

CIS Benchmark
      ↓
Machine-readable controls
      ↓
Control enrichment
      ↓
Target profiling

NEXT — MILESTONE 4

Dependency / compatibility analysis

PLANNED — MILESTONES 5–8

Sandbox validation
      ↓
Administrator approval
      ↓
Deployment
      ↓
Post-deployment verification
      ↓
Dashboard and audit trail
```

## Current project status

| Milestone | Main question / purpose | Status |
|---|---|---|
| Milestone 1 | CIS Benchmark → machine-readable control catalog | ✅ Complete |
| Milestone 2 | PoC control selection and SENTRA enrichment | ✅ Complete |
| Milestone 3 | Ubuntu 24.04 target profiling | ✅ Implemented and validated on one target |
| Milestone 4 | Dependency and compatibility analysis | 🔜 Next |
| Milestone 5 | Sandbox validation | 📝 Planned |
| Milestone 6 | Controller and target agent | 📝 Planned |
| Milestone 7 | Deployment and post-deployment verification | 📝 Planned |
| Milestone 8 | Dashboard and audit trail | 📝 Planned |

## Evidence at a glance

| Area | Verified result |
|---|---|
| Benchmark ingestion | 1,078 PDF pages processed and 312 recommendations detected |
| Machine-readable catalog | 312 YAML controls generated and schema-valid |
| PoC selection | 10 representative controls across six security areas |
| Fact discovery | 51 fact requests deduplicated into 47 unique facts |
| Software verification | 122 tests passed with 0 failures |
| Host experiment | Read-only profiling executed on one Ubuntu 24.04.5 LTS, `aarch64` target |
| Manual comparison | Representative profile values matched manual Ubuntu checks |

These are different forms of evidence. Automated tests validate software behavior,
while the Ubuntu experiment and manual comparisons provide representative host-level
evidence. One target experiment does not establish universal behavior across every
Ubuntu installation or architecture.

## Milestone 1 — CIS Benchmark Ingestion

> **Main question:** “What does CIS say?”

Milestone 1 is validated against the **CIS Ubuntu Linux 24.04 LTS Benchmark
v1.0.0**. It converts the licensed local PDF into structured YAML controls.

### Ingestion pipeline

```text
CIS Benchmark PDF
        ↓
PyMuPDF extraction
        ↓
Recommendation detection
Python + regular expressions + layout evidence
        ↓
Control parser
        ↓
Pydantic validation
        ↓
PyYAML serialization
        ↓
Machine-readable YAML controls
```

- **PyMuPDF** extracts text and tables page by page while preserving PDF and printed
  page information. It does not itself understand CIS recommendations.
- The **recommendation detector** uses custom Python, regular expressions, and heading
  presentation evidence. It does not contain a hard-coded list of all controls.
- The **parser** separates profile applicability, description, rationale, impact,
  Audit, Remediation, references, CIS Controls, and explicit MITRE mappings.
- **Pydantic** checks the parsed structure and accepted data types against SENTRA’s
  schema. Schema validity does not independently prove that extracted CIS content is
  semantically correct.
- **PyYAML** serializes validated records into readable YAML.

Recommendation detection requires a dotted numeric control ID, an `Ensure` title with
an `(Automated)` or `(Manual)` assessment label, and matching heading-layout evidence.
This avoids treating ordinary numbered sections or table-of-contents entries as
recommendations.

Audit and Remediation commands are retained as **data only** for traceability. Nothing
from the benchmark is executed in Milestone 1.

Each locally generated record also retains its extracted raw source text so that a
reviewer can compare parsed fields with the licensed source.

### Milestone 1 results

| Measure | Result |
|---|---:|
| CIS PDF pages processed | 1,078 |
| Recommendations detected | 312 |
| Automated recommendations | 291 |
| Manual recommendations | 21 |
| Generated YAML files | 312 |
| Valid YAML files | 312 |
| Invalid YAML files | 0 |
| Milestone 1 tests | 13 passed |

Milestone 1 successfully created a machine-readable representation of all 312
recommendations in the selected benchmark. This result applies to the named Ubuntu
24.04 benchmark and does not claim universal support for other CIS benchmarks or
versions.

The licensed PDF, complete 312-control output, and full catalog remain local and are
excluded from normal Git distribution. The tracked repository retains the converter
and a five-record development sample so the parsing design can be reviewed without
redistributing the full licensed material.

## Milestone 2 — PoC Control Selection and SENTRA Enrichment

> **Main question:** “What should SENTRA know before safely working with a CIS control?”

Milestone 2 does not apply controls. It selects ten representative recommendations
for the Proof of Concept and stores separate SENTRA metadata describing the evidence
and safety conditions that later milestones may need.

### Selected PoC controls

| Control | Area | PoC focus |
|---|---|---|
| `1.1.1.1` | Kernel | cramfs |
| `1.1.1.6` | Kernel | OverlayFS |
| `3.3.1` | Network | IP forwarding |
| `4.2.1` | Firewall | UFW installation |
| `4.2.3` | Firewall | UFW service |
| `5.1.19` | SSH | Empty passwords |
| `5.1.20` | SSH | Root login |
| `6.2.1.2` | Auditing | auditd |
| `7.1.1` | File permissions | `/etc/passwd` |
| `7.1.5` | File permissions | `/etc/shadow` |

The sample deliberately covers kernel, network, firewall, SSH, auditing, and file
permission behavior. This creates varied evidence and compatibility questions without
claiming that all 312 recommendations have been experimentally enforced.

### What enrichment means

SENTRA enrichment records metadata such as:

- affected services and files;
- affected packages where they are explicit;
- required target facts;
- prerequisites and possible conflicts;
- sandbox and validation requirements; and
- the requirement for administrator approval.

CIS-derived source data and SENTRA-specific knowledge remain separate:

```text
data/controls/       CIS-derived source records
data/poc/enriched/   SENTRA-specific metadata
```

Every enrichment initially uses `derivation_status: needs_review`. Generated or
inferred metadata is therefore not automatically treated as human-approved.

### OverlayFS example

Control `1.1.1.6` concerns disabling OverlayFS. Its Impact information warns that
doing so may disrupt container technologies such as Docker, Kubernetes, Podman, and
LXC. SENTRA therefore records that container use must be checked before a future
compatibility decision.

Milestone 2 says: **“Container use should be checked.”** It does not yet ask the
Ubuntu target for the answer and does not decide whether the control is safe.

### Milestone 2 results

| Measure | Result |
|---|---:|
| Selected PoC controls | 10 |
| Kernel | 2 |
| Network | 1 |
| Firewall | 2 |
| SSH | 2 |
| Auditing | 1 |
| File permissions | 2 |
| Controls executed | 0 |
| Full test count after Milestone 2 | 26 passed |

## Milestone 3 — Ubuntu 24.04 Target Profiler

> **Main question:** “What is actually present and configured on this Ubuntu machine?”

Milestone 3 reads the facts requested by Milestone 2 and collects local, read-only
evidence from an Ubuntu 24.04 target.

```text
Milestone 2 enrichment
        ↓
required_target_facts
        ↓
Milestone 3 fact loader
        ↓
Ubuntu fact collectors
        ↓
Validated target profile
```

The profiler runs on the host it inspects. It does not require a fixed target address,
use an address as target identity, or implement remote execution. An administrator may
use SSH to reach a server, but the profiler itself examines the local operating system,
hostname, architecture, kernel, packages, services, configuration, and file metadata.

Only Ubuntu 24.04 is treated as a supported profiling target. Development tests can
run on other operating systems, but those systems retain their actual identity and are
not reported as Ubuntu.

### Milestone 3 components

```text
src/target_profiler/
├── __init__.py
├── models.py
├── fact_loader.py
├── command_runner.py
├── collectors.py
├── profiler.py
└── cli.py
```

| Component | Responsibility |
|---|---|
| `fact_loader.py` | Reads all ten enrichments, deduplicates `required_target_facts`, and preserves `requested_by` traceability |
| `command_runner.py` | Allows only exact read-only commands, uses `shell=False`, a timeout and fixed environment, and rejects modifying commands |
| `collectors.py` | Implements explicit collectors for the facts requested by the current PoC controls |
| `profiler.py` | Detects the target OS, enforces Ubuntu 24.04 support, coordinates collection, summarizes results, and serializes YAML |
| `models.py` | Defines strict Pydantic schemas for targets, facts, states, traceability, and profiles |
| `cli.py` | Lists required facts without profiling or generates a local YAML profile |

The command allowlist is a narrow process-execution boundary, not an operating-system
sandbox. Commands outside the approved argument patterns are rejected before launch.

### Required fact discovery

The ten enrichments contain **51 total requests** for **47 unique facts**. The totals
differ because more than one control may request the same evidence.

For example, `ssh_service_status` is requested by controls `5.1.19` and `5.1.20`.
SENTRA collects the fact once while preserving traceability to both controls.

### Fact result states

| State | Meaning |
|---|---|
| `collected` | SENTRA obtained reliable evidence for the fact |
| `unavailable` | A collector exists, but the evidence could not be obtained in this run—for example because of permissions or unavailable local metadata |
| `unsupported` | The fact cannot be determined safely from the available local technical evidence |
| `error` | An unexpected collection failure occurred |

SENTRA does not convert unavailable or unsupported evidence into `false`. It preserves
uncertainty instead of guessing.

## Real Ubuntu validation

Milestone 3 was executed against one real Ubuntu system:

| Property | Value |
|---|---|
| Operating system | Ubuntu 24.04.5 LTS |
| Kernel | `6.8.0-139-generic` |
| Architecture | `aarch64` |

No address, username, hostname, or other target identifier is included here.
These values document the project’s recorded experimental validation run. The
machine-generated target profile is intentionally not committed to the repository.

### Normal-user run

| Requested | Collected | Unavailable | Unsupported | Errors |
|---:|---:|---:|---:|---:|
| 47 | 36 | 6 | 5 | 0 |

### Elevated read-only run

| Requested | Collected | Unavailable | Unsupported | Errors |
|---:|---:|---:|---:|---:|
| 47 | 40 | 0 | 7 | 0 |

The elevated run made additional protected UFW and OpenSSH evidence visible. At the
same time, two SSH/session-context facts became unsupported because this run’s `sudo`
execution context changed. This is a useful research observation: privilege level can
change both evidence visibility and the meaning of process-context signals. Environment
preservation under `sudo` can vary, so this observation is specific to the recorded run.

### Representative manual verification

| Fact | SENTRA result | Manual Ubuntu check |
|---|---|---|
| Kernel | `6.8.0-139-generic` | `6.8.0-139-generic` |
| Architecture | `aarch64` | `aarch64` |
| IPv4 forwarding | `0` | `0` |
| IPv6 forwarding | `0` | `0` |
| SSH service | `active` | `active` |
| UFW package | installed | installed |
| iptables package | installed | installed |
| nftables in `installed_firewall_utilities` | installed | installed |
| auditd | not present | service not found |
| `/etc/passwd` permissions | `0644`, UID `0`, GID `0` | `644`, `0`, `0` |
| `/etc/shadow` permissions | `0640`, UID `0`, GID `42` | `640`, `0`, `42` |
| cramfs loaded | `false` | not present in `/proc/modules` |
| OverlayFS loaded | `false` | not present in `/proc/modules` |

The representative manual checks matched the SENTRA-generated target profile. This is
a focused comparison on one target, not exhaustive independent certification of all
collectors or all Ubuntu systems.

## Test results

| Test scope | Result |
|---|---:|
| Milestones 1–2 | 26 passed |
| Milestone 3 | 96 passed |
| Full suite | 122 passed |
| Failures | 0 |

The existing PyMuPDF/SWIG deprecation messages are warnings only and do not represent
test failures.

## How Milestones 1–3 connect

Control `1.1.1.6` demonstrates why the layers are separate:

1. **Milestone 1:** the recommendation is converted from the PDF into structured YAML.
2. **Milestone 2:** SENTRA records that container use is relevant because disabling
   OverlayFS may disrupt container workloads.
3. **Milestone 3:** SENTRA inspects the Ubuntu host and collects OverlayFS module state
   and container applications in use.
4. **Milestone 4:** the future compatibility layer will compare Milestone 2 knowledge
   with Milestone 3 evidence and produce a compatibility result.

Milestone 4 has **not** been implemented. Milestone 3 reports evidence but does not
label the control safe, unsafe, compatible, or conflicting.

## Current research boundary

### Currently implemented

- CIS benchmark ingestion for the selected Ubuntu benchmark;
- machine-readable YAML control generation;
- representative PoC control enrichment;
- required-target-fact discovery and traceability;
- local read-only Ubuntu 24.04 target profiling;
- automated tests;
- one real Ubuntu target experiment; and
- representative manual comparison.

### Not yet implemented

- automatic dependency or compatibility decisions;
- sandbox execution or validation;
- CIS Audit or Remediation execution;
- automatic deployment;
- a target agent or controller/API;
- a centralized database;
- a dashboard or audit-trail interface;
- an administrator approval workflow; and
- post-deployment verification.

### Current limitations

- Benchmark ingestion is validated against one benchmark and version only.
- All 312 recommendations were parsed, but only ten representative controls were
  enriched for the PoC and none were enforced.
- Real-host evaluation currently represents one Ubuntu target.
- Some facts depend on permissions and execution context.
- Some operational facts cannot be inferred safely from local technical evidence.
- Enrichment remains `needs_review` until human review.
- PDF visual line wrapping can split tokens in stored shell text; SENTRA does not repair
  or execute that text.
- Ambiguous CIS Controls tables and mappings are kept conservative rather than guessed.

## Next — Milestone 4: Dependency and Compatibility Analysis

Milestone 4 will combine enriched control knowledge with target evidence:

```text
Milestone 2 knowledge
        +
Milestone 3 target facts
        ↓
Future compatibility / dependency result
```

Possible future result concepts may include `compatible`, `warning`, `review required`,
or `insufficient evidence`. These states are design directions only; the compatibility
engine and its results do not yet exist.

## Read-only safety boundary

Milestone 3 may:

- read operating-system and kernel information;
- read service and package state;
- inspect firewall and SSH state;
- inspect kernel/module state; and
- inspect file ownership and permission metadata.

Milestone 3 may not:

- apply CIS remediation;
- run `apt install`, `apt remove`, or `apt update`;
- run `systemctl start`, `stop`, `restart`, `enable`, or `disable`;
- restart services through the `service` command;
- run `chmod` or `chown`;
- unload modules with `modprobe -r` or `rmmod`;
- write kernel settings with `sysctl -w`;
- enable or disable UFW;
- modify iptables or nftables;
- reboot or shut down the target; or
- execute commands copied from CIS YAML.

CIS Audit and Remediation text remains data only throughout Milestone 3. Permission or
command failures retain null values and an explicit state instead of becoming false.

## Current data storage

| Milestone | Current PoC storage |
|---|---|
| Milestone 1 | `data/controls/*.yaml` |
| Milestone 2 | `data/poc/poc_controls.yaml` and `data/poc/enriched/*.yaml` |
| Milestone 3 | `data/profiles/*.yaml` when explicitly requested with `--output` |

Generated target profiles are Git-ignored and are not stored automatically. The
licensed benchmark PDF and full local CIS-derived catalog are also excluded from
normal Git distribution.

A centralized database is planned for later research stages. It may eventually store
targets, profiles, compatibility results, sandbox evidence, administrator approvals,
deployments, post-deployment verification, and audit history. No such database exists
in the current implementation.

## Technical usage

### Requirements

- Python 3.11 or newer
- PyMuPDF
- PyYAML
- Pydantic
- pytest

### Create the environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Run the tests

```bash
python -m pytest -q
```

### List Milestone 3 required facts

This command reads enrichment metadata but does not profile the current host:

```bash
python -m src.target_profiler.cli --list-required-facts
```

### Generate a local target profile

Run this on the Ubuntu 24.04 host being inspected:

```bash
python -m src.target_profiler.cli \
  --format yaml \
  --output data/profiles/target-profile.yaml
```

Profile files are written atomically with owner-only (`0600`) permissions. Begin with
a normal-user run. If protected facts are unavailable, an administrator may deliberately
repeat the read-only experiment with elevation; the execution context and session facts
must then be interpreted accordingly.

### Display the Milestone 2 PoC summary

```bash
python -m src.poc_summary
```

### Run the Milestone 1 converter

The benchmark is licensed and must be supplied locally at:

```text
benchmark/CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.pdf
```

Run the converter against that local read-only input:

```bash
python -m src.cli \
  benchmark/CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.pdf \
  --output-dir data
```

The benchmark PDF is Git-ignored and must not be redistributed.

## Project structure

```text
data/
├── controls/                 Milestone 1 CIS-derived YAML records
├── poc/
│   ├── poc_controls.yaml     Milestone 2 PoC manifest
│   └── enriched/             SENTRA-specific enrichment
└── profiles/                 Milestone 3 output; generated and Git-ignored

src/
├── pdf_extractor.py          PDF text, page and table extraction
├── control_detector.py       Recommendation-boundary detection
├── control_parser.py         Structured CIS field parsing
├── models.py                 Milestone 1 schemas
├── yaml_writer.py            Deterministic YAML output
├── cli.py                    Milestone 1 converter CLI
├── poc_models.py             Milestone 2 schemas and validation
├── poc_summary.py            Milestone 2 summary CLI
└── target_profiler/          Milestone 3 profiler package

tests/                        Milestones 1–3 automated tests
```

## Research and licensing note

This repository supports a university cybersecurity research project. The CIS
benchmark is licensed source material and is not distributed with the project. The
current results are specific to the stated benchmark, PoC control set, profiler
implementation, and recorded Ubuntu experiment.
