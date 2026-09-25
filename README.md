# SENTRA

## A Layered Framework for Automated CIS Security Control Enforcement on Linux Systems

SENTRA is a university cybersecurity research Proof of Concept. It converts CIS
recommendations into structured records, adds reviewable SENTRA knowledge, profiles an
Ubuntu target without changing it, evaluates dependency and compatibility evidence, and
runs tightly bounded control experiments in an acknowledged Ubuntu sandbox.

**Milestones 1–5 are implemented at PoC scope, the initial three-control M5 sandbox
validation scope is complete, M6A provides the Controller/Agent protocol and storage
core, M6B implements its TLS-only HTTPS transport and one-cycle M3 Agent, and M6C runs
the existing M4 engine against validated Controller-stored profiles.** SENTRA is not a
production hardening platform, a CIS compliance scanner, or a claim of complete CIS
enforcement. M1–M4 remain non-mutating. M5's intended mutation surface is limited to
explicit adapters and approval gates; its two controlled executions and one deliberately
non-mutating audit/plan are documented below. M6B/M6C add no remediation or arbitrary
remote-command capability. M6B's scoped Mac-to-Ubuntu profiling workflow has completed
real-lab validation, and M6C has completed a real Controller-stored-profile lab using a
protected copy of that M6B evidence. This does not imply production readiness or
completion of all M6 work.

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
M5  What happens when the candidate runs in a sandbox?       INITIAL VALIDATION
                ↓
M6A How are Agent identity, jobs, storage, and lineage bound? PROTOCOL CORE
                ↓
M6B Can one TLS-verified Agent run M3 and submit evidence?    SCOPED LAB VALIDATED
                ↓
M6C Can the Controller run existing M4 on that evidence?     STORED-PROFILE LAB VALIDATED
```

## Project status

| Milestone | Output | Status |
|---|---|---|
| M1 — benchmark ingestion | Machine-readable CIS control catalog | ✅ Implemented |
| M2 — control enrichment | Ten PoC knowledge records | ✅ Implemented; metadata remains `needs_review` |
| M3 — target profiling | Read-only Ubuntu 24.04 target profile | ✅ Implemented and validated on one real target |
| M4 — compatibility analysis | Evidence-traceable compatibility report | ✅ Implemented; normal and elevated real-profile reports rerun and reviewed |
| M5 — sandbox validation | Isolated, evidence-traceable control experiment | ✅ Three initial adapters empirically exercised within their designed capabilities |
| M6A — controller/agent core | Identity, enrollment, heartbeat, target-isolated profile jobs, persistence, and evidence lineage | ✅ Implemented and committed |
| M6B — HTTPS + M3 Agent | TLS-only Controller/Agent transport and deterministic local `PROFILE_TARGET` cycle | ✅ Scoped real-lab validation complete; not production-ready |
| M6C — Controller-side M4 | Admin-only analysis of validated stored profiles with canonical report persistence and lineage | ✅ Implemented, automated-test validated, and real stored-profile lab validated; not production-ready |
| M6D–M8 | Deployment/approval, sandbox manager, dashboard/audit trail | Planned |

### Verified results at a glance

| Layer | Result |
|---|---:|
| M1 source pages processed | 1,078 |
| M1 recommendations detected | 312: 291 Automated, 21 Manual |
| M1 YAML controls valid | 312 / 312 |
| M2 representative PoC controls | 10 across six security areas |
| M3 fact requests | 51 requests, 47 unique facts |
| M4 deterministic rules | 19 across all ten PoC controls |
| M4 automated tests | 68 passed |
| M5 initial adapters | 3: one full, one conditional, one audit/plan-only |
| M5 real sandbox experiments | 3: `7.1.1` validated; `5.1.20` warning; `4.2.3` intentionally `not_tested` |
| M5 automated tests | 122 passed |
| Full M1–M5 suite | 309 passed, 0 failed |
| M6 boundary | Agent-initiated HTTPS; `PROFILE_TARGET` is the only operational job type |
| M6B real-lab workflow | Development-CA-verified HTTPS; one enrollment reused; one `PROFILE_TARGET` job/profile completed |
| M6C real-lab workflow | Protected M6B database copy; admin POST/list/item retrieval matched; SQL lineage `MATCH` |
| Focused M6/M4 validation | 123 passed |
| M6 automated tests | 100 passed |
| Full regression suite after M6C | 412 passed, 0 failed; 5 existing warnings |

Automated tests establish software behavior. The recorded experiments now include
normal and elevated M4 reports from one target, three initial M5 sandbox reports, and
one operator-observed M6B Mac-to-Ubuntu profiling workflow. A separate M6C lab reused a
protected copy of that Controller database and verified central M4 analysis, report
persistence, retrieval, and SQL lineage for the stored real profile. Automated results
and operator observations are separate evidence sources; none is universal Ubuntu or
production validation.

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
                 M5 sandbox validation
                            │
                            ▼
          pre-audit → candidate → post-audit → health/rollback
```

M6A–M6C add a centralization boundary without changing those layers:

```text
Ubuntu Agent -- outbound CA-verified HTTPS /api/v1 --> Controller
     |                                              |
     +-- existing read-only M3 profiler             +-- SQLite repository
             for PROFILE_TARGET                             |
                                                validated TargetProfile
                                                            |
                                                existing M4 engine (read-only)
                                                            |
                                             canonical compatibility report
```

`target_id` and `agent_id` are opaque Controller-issued identities.
`installation_id` is generated and persisted locally by the Agent. Observed host
metadata is non-authoritative, and current Mac/VM addresses, hostnames, and usernames
are lab details only. The Controller does not SSH into targets, and the protocol has no
generic command, shell, remediation, or deployment job. See
[`docs/m6a-architecture.md`](docs/m6a-architecture.md) for the committed protocol core
and [`docs/m6b-architecture.md`](docs/m6b-architecture.md) for the HTTPS transport,
one-cycle Agent, configuration, lab procedure, and remaining limitations. The separate
M6C Controller-side design and stored-profile lab record are in
[`docs/m6c-architecture.md`](docs/m6c-architecture.md).

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
| `3.3.1` | `ip-forwarding-source-precedence-review` | Candidate paths are validated as evidence but do not prove forwarding assignments or precedence |
| `4.2.1` | `ufw-iptables-prerequisite` | `prerequisites`: UFW depends on iptables |
| `4.2.1` | `ufw-other-firewall-utility` | Additional package presence requires review; it does not prove an active/configured competitor |
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
- multiple candidate sysctl paths do not imply relevant assignments, conflicts, or an
  effective forwarding override; exact assignment evidence is a future enhancement;
- installed `nftables` does not trigger a warning by itself; package-only evidence
  requires review because independent configuration is not established;
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
| Real normal-profile report | 3 `no_known_conflict`, 1 `warning`, 4 `review_required`, 2 `insufficient_evidence` |
| Real elevated-profile report | 3 `no_known_conflict`, 0 `warning`, 7 `review_required`, 0 `insufficient_evidence` |
| Manual semantic review | Completed for both reports; all 10 results in each remain provisional |

Synthetic fixtures remain distinct from real-target evidence. The two real reports
come from the same recorded Ubuntu target under normal and elevated execution contexts;
they do not establish broader compatibility across Ubuntu systems. Reproduce the normal
report with:

```bash
python -m src.compatibility_engine.cli \
  --profile data/profiles/target-profile.yaml \
  --output data/compatibility/target-profile-compatibility.yaml
```

Reproduce the elevated-profile report from its already collected YAML data with:

```bash
python -m src.compatibility_engine.cli \
  --profile data/profiles/target-profile-elevated.yaml \
  --output data/compatibility/target-profile-elevated-compatibility.yaml
```

List the auditable rule catalog without loading a profile:

```bash
python -m src.compatibility_engine.cli --list-rules
```

## Milestone 5 — sandbox validation

> **Question:** What actually happens when a hand-authored candidate control is applied
> inside a representative Ubuntu sandbox?

M5 is an empirical validation layer, not another M4 decision state and not a CIS
compliance scanner.

```text
M2 structured metadata     Explicit M3/M4 evidence       Local sandbox identity
          └───────────────────────┬──────────────────────────────┘
                                  ▼
             sandbox precheck + operator acknowledgements
                                  ▼
 pre-audit → fixed adapter action → post-audit → health checks
                                  │
                                  └── adapter-specific rollback on failure
                                  ▼
                validated | warning | failed | not_tested
```

| M4 answers | M5 answers |
|---|---|
| Whether current evidence triggers a defined compatibility concern | What the candidate actually did in this sandbox run |
| Uses `no_known_conflict`, `warning`, `review_required`, `insufficient_evidence` | Uses `validated`, `warning`, `failed`, `not_tested` |
| Never mutates a host | May mutate only through an explicitly supported adapter |
| A result is input evidence, never deployment permission | Every mutation still requires sandbox acknowledgement and administrator approval |

Neither layer emits CIS PASS/FAIL. `no_known_conflict` never becomes an implicit M5
authorization.

The M3/M4 inputs retained in an M5 report are target-lineage context only. They are not
reused as sandbox state: M5 collects the local sandbox identity and pre/post evidence
freshly and stores them in separate report fields.

### Implemented initial adapters

| Control | Capability | Current behavior |
|---|---|---|
| `7.1.1` — `/etc/passwd` permissions | **Full initial experiment; empirically validated** | Fresh fixed-path audit; private exclusive backup; UID/GID `0`; current mode masked by `0644` without widening access; post-audit; non-secret account-database checks; metadata rollback on failure |
| `5.1.20` — SSH `PermitRootLogin` | **Conditional, execute-gated; empirically exercised** | Strict Include/Match/service prerequisites; one SENTRA-owned drop-in; validation before the only allowed reload; real execution reached the intended technical state but returned `warning` because automated evidence cannot prove future remote access |
| `4.2.3` — UFW service | **Audit and plan only; empirically exercised** | Records mask/enabled/active/status, session context, TCP/22 evidence, and alternate-port uncertainty; automatic firewall mutation is deliberately not implemented |

All other controls produce `not_tested` because no hand-authored M5 adapter exists.
M5 never turns CIS Audit or Remediation prose into a command.

### Mutation gates and safety boundary

Actual mutation requires all applicable gates:

- `--execute` and `--sandbox-ack`;
- Ubuntu `24.04` identity on a supported recorded architecture;
- effective UID `0`;
- explicit `--administrator-approval`;
- an explicit M4 report for the selected control;
- `--compatibility-ack` for M4 `warning`, `review_required`, or
  `insufficient_evidence`; and
- a non-empty research reason when overriding `insufficient_evidence`.

Control `5.1.20` execution additionally requires all three SSH-specific attestations:
`--ssh-recovery-access-ack`, `--ssh-non-root-admin-sudo-access-verified`, and
`--ssh-lockout-risk-ack`. These execute-only gates are not required for a plan, control
`7.1.1`, or the audit/plan-only UFW adapter.

The acknowledgement is recorded as `sandbox_operator_acknowledged: true`. M5 does not
claim that it technically verified a disposable VM. It records that an external VM
snapshot is expected, but it neither creates nor restores snapshots.

The command boundary accepts named actions rather than arbitrary argv. Every subprocess
uses an absolute allowlisted executable, fixed arguments, a fixed environment, a
timeout, and `shell=False`. The only initial mutating subprocess is a control-bound
`systemctl reload ssh.service`; there is no SSH restart/start and no UFW mutation.
`/etc/passwd` changes use no-follow, inode-checked Python file operations against the
adapter's exact path. There is no generic command-from-YAML, package installation,
reboot, shutdown, remote connection, controller/agent transport, or central database.

### M5 report and audit trail

Each YAML report retains:

- sandbox OS/version, hostname, kernel, architecture, effective UID, and operator gates;
- M2 metadata source plus optional M3 source and exact M4 result/provisional lineage;
- pre- and post-audit evidence with `collected`, `unavailable`, `unsupported`, or
  `error` states;
- planned/attempted actions, backups, health checks, rollback outcome, errors, and
  warnings; and
- ordered events for precheck, audit, remediation, health, rollback, and final result.

Reports contain normalized evidence, not `/etc/passwd` contents, password hashes, SSH
keys, or raw configuration bodies. Generated reports live under `data/sandbox/` and
are ignored by Git.

### M5 validation status

The implementation is unit/acceptance tested with temporary files and injected fake
system boundaries: 122 M5 tests pass, and the complete M1–M5 suite is 309 passed with no
failures.

### Real sandbox evidence

The initial M5 PoC validation scope is complete: one full file-metadata execution, one
conditional SSH execution, and one deliberately non-mutating firewall audit/plan were
run in a dedicated Ubuntu 24.04 sandbox.

#### Control `7.1.1` — `/etc/passwd` permissions

The sandbox `/etc/passwd` mode was deliberately set to `0664`. M5 detected that state
and its controlled remediation restored `0644 root:root`. The run exercised backup,
remediation, post-audit verification, and all required health checks; those health
checks passed and the final automated result was `validated`.

Local evidence: `data/sandbox/7_1_1-repro-20260920T153703Z.yaml`. This generated report
is Git-ignored and must not be committed.

#### Control `5.1.20` — SSH `PermitRootLogin`

The M5 pre-audit collected an effective `PermitRootLogin without-password`, an active
and reload-capable `ssh.service`, valid `sshd` syntax, supported Include ordering, and
no detected `Match` directives. The controlled execution created the dedicated
`/etc/ssh/sshd_config.d/00-sentra-5-1-20.conf` drop-in, verified an effective
`PermitRootLogin no`, revalidated syntax, successfully reloaded the service, and found
`ssh.service` still active. Remediation recorded `attempted=true`, `changed=true`, and
`succeeded=true`; rollback was not required.

The automated M5 result was `warning`, **not `validated`**, because internal service,
configuration, and current-session evidence cannot prove future remote-access
continuity. Separate live inspection confirmed the new drop-in was `root:root` mode
`0644`. Separately from SENTRA's automated result, a brand-new post-change SSH session
was successfully established and non-root administrator plus `sudo` access were
independently confirmed. Those external checks do not change the automated `warning`.

- Local evidence: `data/sandbox/5_1_20-validation-20260922T153043Z.yaml`
- SHA-256: `b23b751aff3cd8ca94dc11d56f013e95a79ed3a935c456dd86f9b71dbe431996`

#### Control `4.2.3` — UFW service

The adapter remains `audit_plan_only`. The sandbox had the UFW package installed; the
M5 report independently recorded `ufw.service` as enabled and active, while
`ufw status verbose` reported `inactive`. It found no TCP/22 UFW rule. Alternate
SSH-port context was unavailable, and remote-session context was unsupported in this
run because marker absence cannot be proven after privilege escalation.

Remediation recorded `supported=false`, `attempted=false`, and `changed=false`. SENTRA
explicitly planned a remote-access safety review and deferred firewall mutation. The
final result was `not_tested`: this is the intended safety boundary, not a failed
experiment.

- Local evidence: `data/sandbox/4_2_3-plan-20260922T154200Z.yaml`
- SHA-256: `7e0a3d40adc725c038c7be09fc1434438fa58d617bf36b51a66b5d8d19668f67`

These are sandbox experiments, not production deployment, full CIS automation, or CIS
compliance verdicts. M2 metadata remains `needs_review`, and M4 results remain
provisional. The retained target profile is Ubuntu 24.04 `aarch64`, while the M5
sandbox is Ubuntu 24.04 `x86_64`; that difference limits broader representativeness.
External VM snapshot and console recovery remain operator responsibilities. Generated
M5 reports are local evidence, are Git-ignored, and must not be committed. SENTRA does
not provide automated proof of future SSH access continuity; the successful new session
and administrator/`sudo` checks above are explicitly separate external verification.
Broader control coverage and an automated controller-agent/sandbox-manager lifecycle
remain future work.

## Current research boundary

### Implemented

- one-version CIS Ubuntu benchmark ingestion;
- ten-control PoC enrichment with explicit review status;
- local read-only Ubuntu 24.04 profiling;
- deterministic dependency and compatibility analysis;
- the local M5 sandbox framework and three initial adapters; and
- structured, evidence-traceable M4 and M5 YAML reports, including the three initial
  real-sandbox M5 experiment reports retained as local generated artifacts; and
- the M6A in-process Controller/Agent protocol skeleton with persistent identities,
  enrollment, authenticated heartbeat, target-isolated `PROFILE_TARGET` jobs, local
  SQLite persistence, and profile-evidence lineage; and
- the M6B TLS-only HTTPS listener/client, protected configuration boundaries,
  deterministic one-cycle Agent, and narrow reuse of the existing read-only M3
  profiler for strict profile submission, exercised in the controlled Mac-to-Ubuntu
  lab workflow; and
- the M6C admin-only Controller adapter that revalidates stored M3 evidence, invokes
  the existing ten-control M4 engine, and stores canonical compatibility reports with
  `target_id → profile_id → compatibility_report_id` lineage and Controller-computed
  hashes, exercised against a protected copy of the real M6B Controller database.

### Not implemented

- broader M5 control coverage and automated sandbox lifecycle management;
- arbitrary CIS Audit or Remediation execution;
- automatic deployment or post-deployment verification;
- production certificate lifecycle automation and broader M6 deployment validation;
  and
- deployment/approval workflows, sandbox manager, production database, or dashboard.

### Limitations

- Benchmark ingestion is validated against one benchmark and version.
- Only ten of 312 recommendations have PoC enrichment and M4 rules.
- All current enrichment is still `needs_review`; therefore all M4 results are
  provisional.
- M3 real-host evidence represents one Ubuntu target and varies with permissions and
  execution context.
- Operational context that cannot be determined technically remains explicit rather
  than being guessed.
- M4 real-profile validation currently covers one Ubuntu target under normal and
  elevated execution contexts.
- M5 currently covers three controls: `7.1.1` completed with `validated`, conditional
  SSH control `5.1.20` completed with `warning`, and audit/plan-only UFW control `4.2.3`
  completed with the intentional result `not_tested`.
- The completed `7.1.1` run used an `x86_64` sandbox while its recorded target lineage
  was `aarch64`; that fixed metadata experiment is not architecture-sensitive, but it
  does not establish architecture-wide equivalence.
- VM identity and operator acknowledgement do not prove disposability; snapshot
  handling remains an external operator responsibility.
- M6B real-lab evidence covers one MacBook Controller, one Ubuntu 24.04 LTS `aarch64`
  Agent, one lab-only development CA, and one `PROFILE_TARGET` workflow. It does not
  establish production or multi-environment readiness. Production certificate
  lifecycle, replay protection, rate limiting, credential rotation/revocation,
  enrollment response-loss recovery, Agent daemon/service operation, deployment, and a
  production administration boundary remain future work.
- M6C is an on-demand, administrator-authenticated PoC over the existing SQLite backend.
  It covers only the current ten M4 controls and has no scheduler, idempotency framework,
  production concurrency model, remediation/deployment step, M5 orchestration, or UI.
  Its real-lab evidence covers one protected database copy, one stored profile, one
  generated report, and one lab-only certificate chain.

## Data storage

| Milestone | Path | Repository policy |
|---|---|---|
| M1 | `data/controls/*.yaml` | Full local conversion ignored; development sample tracked |
| M2 | `data/poc/poc_controls.yaml`, `data/poc/enriched/*.yaml` | Tracked |
| M3 | `data/profiles/*.yaml` | Generated profiles ignored |
| M4 | `data/compatibility/*.yaml` | Generated reports ignored; `.gitkeep` tracked |
| M5 | `data/sandbox/*.yaml` | Generated sandbox reports ignored; `.gitkeep` tracked |
| M6A–M6C | `data/controller/*`, `data/agent/*` | Generated databases, credentials, runtime state, and stored reports ignored; `.gitkeep` files tracked |

## Project structure

```text
data/
├── controls/                    M1 CIS-derived records
├── poc/                         M2 manifest + enrichment
├── profiles/                    M3 generated profiles; Git-ignored
├── compatibility/              M4 generated reports; Git-ignored
├── sandbox/                     M5 generated reports; Git-ignored
├── controller/                  M6 Controller database/runtime state; Git-ignored
└── agent/                       M6 Agent identity/credential state; Git-ignored

docs/
├── m6a-architecture.md          M6A trust, protocol, storage, and lineage baseline
├── m6b-architecture.md          M6B completed lab record, reproduction, and limitations
└── m6c-architecture.md          M6C design, stored-profile lab record, and limitations

src/
├── pdf_extractor.py             M1 extraction
├── control_detector.py          M1 recommendation detection
├── control_parser.py            M1 field parsing
├── poc_models.py                M2 validation
├── target_profiler/             M3 read-only profiler
├── compatibility_engine/        M4 analysis package
├── sandbox_validator/           M5 sandbox package
    ├── models.py                strict reports and result states
    ├── loaders.py               inert M2/M3/M4 inputs
    ├── command_runner.py        named, fixed subprocess actions
    ├── precheck.py              identity and authorization gates
    ├── audit.py                 normalized fresh evidence
    ├── health.py                narrow post-change checks
    ├── adapters/                three hand-authored control adapters
    ├── validator.py             fail-stop orchestration
    ├── report.py                YAML output
    └── cli.py                   local plan/execute entry point
├── controller/                  M6 protocol/service/storage + HTTPS + M4 adapter
└── agent/                       persistent identity + HTTPS client + M3 one-cycle runtime

tests/
├── test_compatibility_engine.py
├── test_compatibility_engine_rules.py
├── test_compatibility_engine_acceptance.py
├── test_sandbox_validator_*.py
└── test_m6_*.py
```

## Technical usage

Requirements: Python 3.11+, PyMuPDF, PyYAML, Pydantic, and pytest.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
```

Inspect the M6B TLS-only Controller and one-cycle Agent entry points:

```bash
.venv/bin/python -m src.controller --help
.venv/bin/python -m src.agent --help
```

The Controller requires externally provisioned certificate/key paths, a database path,
and bootstrap/administrator credentials from protected files or named environment
variables. The Agent requires an HTTPS Controller URL, trusted CA path, persistent
state path, and a bootstrap credential only on first enrollment. There is no insecure
TLS option. The validated workflow, evidence record, and reproducible Mac Controller
and Ubuntu Agent procedure are in
[`docs/m6b-architecture.md`](docs/m6b-architecture.md).

The M6C administrative API, persistence design, semantic boundaries, and completed
stored-profile lab validation are documented in
[`docs/m6c-architecture.md`](docs/m6c-architecture.md).

Generate an M3 profile locally on the Ubuntu 24.04 host:

```bash
python -m src.target_profiler.cli \
  --format yaml \
  --output data/profiles/target-profile.yaml
```

To reproduce the workflow on a dedicated sandbox, generate the matching profile and
compatibility report locally inside that VM:

```bash
.venv/bin/python -m src.target_profiler.cli \
  --format yaml \
  --output data/profiles/sandbox-profile.yaml

.venv/bin/python -m src.compatibility_engine.cli \
  --profile data/profiles/sandbox-profile.yaml \
  --output data/compatibility/sandbox-compatibility.yaml
```

List M5 capabilities without inspecting the host:

```bash
.venv/bin/python -m src.sandbox_validator.cli --list-controls
```

Run an M5 read-only plan after generating the matching M4 report:

```bash
.venv/bin/python -m src.sandbox_validator.cli \
  --control 7.1.1 \
  --target-profile data/profiles/sandbox-profile.yaml \
  --compatibility-report data/compatibility/sandbox-compatibility.yaml \
  --plan
```

On the dedicated Ubuntu sandbox only, first create an external VM snapshot and review
the plan. For the current provisional/review-required `7.1.1` path, run:

```bash
sudo .venv/bin/python -m src.sandbox_validator.cli \
  --control 7.1.1 \
  --target-profile data/profiles/sandbox-profile.yaml \
  --compatibility-report data/compatibility/sandbox-compatibility.yaml \
  --sandbox-ack \
  --administrator-approval \
  --compatibility-ack \
  --execute \
  --output data/sandbox/7-1-1-validation.yaml
```

An existing output is never replaced unless `--overwrite` is also supplied. If M4
returns `insufficient_evidence`, execution additionally requires
`--override-insufficient-evidence "<specific research reason>"`. These are local-only
commands; the CLI has no remote-host option.

The benchmark converter requires the licensed PDF to be supplied locally. The PDF,
full generated catalog, host profiles, compatibility reports, and sandbox reports must
not be redistributed as normal repository content.

## Next research step

The initial M5 PoC validation scope, M6A protocol/storage core, M6B scoped TLS profiling
workflow, and M6C Controller-side compatibility implementation are complete at their
stated boundaries, including the scoped M6B and M6C real-lab validations. M6D–M8 remain
future work; any deployment/approval workflow, sandbox manager, or dashboard must
remain separate from M6C's non-mutating M4 adapter and must not introduce arbitrary
remote execution.

## Research and licensing note

Results are specific to the named CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0, the ten
PoC enrichments, the implemented profiler and compatibility rules, and the recorded
experiment. The CIS benchmark is licensed source material and is not distributed with
this project.
