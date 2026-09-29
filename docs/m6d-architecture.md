# SENTRA M6D constrained sandbox-validation orchestration

## Status and scope

M6D is implemented, automated-test validated, and validated in one controlled real-lab
workflow completed on 2026-09-26. It connects one Controller-stored M4 compatibility
result to the existing M5 sandbox validator through a narrowly structured Agent job,
then returns the strict M5 evidence to the Controller for validation, canonical hashing,
persistence, and authenticated retrieval.

The current M6D Proof of Concept supports only control `7.1.1`, the existing M5
`/etc/passwd` metadata adapter. Controls `5.1.20` and `4.2.3` are not reachable through
M6D. M6D is sandbox-validation orchestration, not production deployment or remediation
of customer targets. The current lab used a dedicated VM as the sandbox; automated VM
creation, cloning, snapshotting, disposal, and sandbox lifecycle management are not
implemented.

## Evidence and semantic boundaries

M6D preserves three distinct kinds of project material:

- **CIS-derived data:** licensed benchmark identity and extracted Audit/Remediation
  text remain inert data. SENTRA never executes raw CIS remediation text.
- **SENTRA-derived knowledge and analysis:** M2 enrichment, M3 observations, and M4
  compatibility decisions remain reviewable research metadata. In this lab,
  `review_required`, `metadata_review_status=needs_review`, and `provisional=true` were
  retained rather than converted into a compliance decision.
- **SENTRA implementation evidence:** the constrained job, M5 precheck and experiment
  result, validation journal state, Controller timestamps, canonical payload, and
  Controller-computed SHA-256 describe what the SENTRA PoC did in this lab.

An M4 result is not a CIS compliance verdict. An M5 result is also not a CIS compliance
verdict. In particular, M5 `validated` means that the candidate was empirically
validated by the bounded sandbox procedure and its required health checks; it does not
mean that the target is CIS compliant.

## Architecture

The implemented flow is:

```text
Controller-stored M4 compatibility report
        │
        ▼
explicit administrator validation authorization
        │
        ▼
constrained VALIDATE_CONTROL job
        │
        ▼
outbound Agent HTTPS polling
        │
        ▼
fixed local M5 adapter invoked in-process
        │
        ▼
fail-closed validation journal with trusted-ancestor enforcement
        │
        ▼
HTTPS validation-result submission
        │
        ▼
Controller strict validation → canonical SHA-256 → SQLite persistence
```

The authoritative lineage is:

```text
target_id
  -> profile_id
  -> compatibility_report_id
  -> validation_job_id
  -> validation_result_id
```

The Agent continues to initiate outbound, CA-verified HTTPS communication. The
Controller does not SSH into the target and does not send executable command text.
M6D reuses the existing M5 `SandboxValidator` and fixed `7.1.1` adapter in-process; it
does not invoke the M5 CLI through a shell and does not copy or reinterpret M5 logic.

### Narrow protocol and API surface

The administrator creates a validation job through the target/profile/report lineage:

```text
POST /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}/validation-jobs
```

The existing authenticated Agent polling route can return the Agent's own
`PROFILE_TARGET` work or at most one `VALIDATE_CONTROL` job in a cycle. The Agent
polls and submits strict result evidence through:

```text
POST /api/v1/agents/{agent_id}/jobs/poll
POST /api/v1/agents/{agent_id}/validation-results
```

Authenticated administrators can list or retrieve results through:

```text
GET /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}/validation-results
GET /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}/validation-results/{validation_result_id}
```

Path, body, authenticated Agent, stored profile, compatibility report, validation job,
and result lineage are all rebound and revalidated. SQLite composite foreign keys and
repository checks prevent a result or job from being associated with another target.

## Safety boundaries

M6D deliberately has no generic `RUN_COMMAND`, `RUN_SHELL`, or `EXEC` facility. Its
The Controller-to-Agent validation job and authorization models contain no arbitrary command, shell, argv, script, filesystem target, service-action, file
write, or adapter-selector field.

The initial authorization contract is closed as follows:

- `job_type` is fixed to `VALIDATE_CONTROL`;
- `control_id` is fixed to `7.1.1`;
- `validation_mode` is fixed to `sandbox`;
- `execution_mode` is fixed to `execute`;
- authenticated administrator approval is required;
- compatibility-risk acknowledgement is required for `warning`, `review_required`,
  and `insufficient_evidence`;
- a nonblank override rationale is mandatory for `insufficient_evidence` and is
  retained when voluntarily supplied for another compatibility condition; and
- the local Agent operator must independently pass `--sandbox-validation-ack`.

Controller approval cannot substitute for the local sandbox acknowledgement. Without
the local acknowledgement, existing M5 prechecks return `not_tested` and do not arm a
mutation. M5 continues to own privilege checks, pre-audit, backup decisions, the fixed
candidate action, post-audit, health checks, and rollback behavior.

The `sandbox` mode label does not create or prove an isolated environment. In the real
lab, VM isolation, snapshotting, and lifecycle decisions remained operator-provided.

The Controller strictly revalidates the submitted M5 model, exact immutable job
lineage, M4 compatibility reference, authorization acknowledgements, and timestamps.
It canonicalizes the validated result JSON and computes the authoritative result
SHA-256 over the canonical `ValidationResultPayload`, not over the surrounding database
row or transport envelope. An identical result replay is idempotent; changed evidence
for the same job is rejected as a conflict.


Returned M5 validation evidence is a separate evidence object and may legitimately
contain observed action targets, affected paths, or backup paths. Those evidence
fields are not Controller-supplied execution parameters and do not broaden the
Controller-to-Agent execution contract.

## Fail-closed Agent journal and trusted-ancestor boundary

The fail-closed replay guarantee depends on a trusted filesystem ancestry boundary.
Before the journal is used, SENTRA verifies that its protecting ancestor directories
are real directories rather than symlinks, are not writable by group or other
principals, and have ownership appropriate to the Agent effective UID. A privileged
Agent therefore rejects a journal protected by an unprivileged-user-owned ancestor.
The final journal directory remains effective-user-owned mode `0700`, with journal
entries and lock files mode `0600`. SENTRA does not silently `chown` or `chmod`
operator-provided parent paths.


Before invoking the M5 adapter, the Agent persists a credential-free journal entry.
The journal directory must be owned by the effective user and have mode `0700`; journal
entries and lock files have mode `0600`.

The state progression is:

```text
STARTED -> RESULT_READY -> ACKNOWLEDGED
```

- `STARTED` is written before validation execution is armed. If execution stops before
  evidence is durably cached, a later Agent cycle fails closed and does not
  automatically rerun the adapter. Manual sandbox inspection is required.
- `RESULT_READY` contains the strict completed evidence and is written before HTTPS
  submission. It can be resubmitted without rerunning M5.
- `ACKNOWLEDGED` records the Controller result identifier and hash after a successful
  response.

The journal fingerprints the complete Controller job. Reusing a validation job ID with
changed authorization or lineage conflicts rather than reusing the old local evidence.

## Real-lab validation record — 2026-09-26

This record separates the evidence sources:

- **Automated regression evidence** established model closure, authorization,
  target/Agent isolation, journal behavior, M5 gate preservation, canonical hashing,
  replay behavior, storage constraints, and M6B/M6C regression behavior.
- **SENTRA-generated runtime evidence** includes the M4 record, two M5 validation
  results, validation/result identifiers, stored job states, and Controller-computed
  hashes.
- **Operator-observed lab evidence** includes TLS verification, host and process
  context, VM polling order, filesystem state, journal ownership failure, snapshot
  creation, and final Controller/database inspection.

These observations apply to this controlled lab. They do not establish production
readiness, universal Ubuntu behavior, or CIS compliance.

### Environment

| Item | Recorded observation |
|---|---|
| Controller host | Mac |
| Controller HTTPS endpoint | `https://30.30.30.236:8445` |
| Controller storage | SQLite PoC database |
| TLS trust | Certificate verified through the lab-only SENTRA Development CA |
| Validation target | Dedicated Ubuntu VM `nadil2` |
| Validation target address | `30.30.30.50` |
| Validation target OS | Ubuntu 24.04.5 LTS |
| Validation target kernel | `6.8.0-142-generic` |
| Validation target architecture | `x86_64` |
| Isolation target | VM `server` at `30.30.30.160` |

The addresses and hostnames are observations from the controlled lab, not product
defaults or reusable configuration.

### Stored input lineage

The VM1 validation lineage was:

| Field | Value |
|---|---|
| `target_id` | `518ce26c-020c-4b6d-a600-3d12e95b1467` |
| `agent_id` | `088e8c2f-681b-446c-b20d-c1d0228b99a5` |
| `profile_id` | `21ec00dc-236d-4de6-9fd5-bdf2443514ec` |
| `compatibility_report_id` | `483fdcf0-0bc9-4e38-8ade-faf0c31b9899` |
| M4 report SHA-256 | `74676fd3906ed6fe205d347430a78c0d9dc1bc79250d03090ce7011c2d93e4f1` |
| M4 result for `7.1.1` | `review_required` |
| `metadata_review_status` | `needs_review` |
| `provisional` | `true` |

The stored M4 value remained `review_required`; it was neither cleared nor translated
into a safer result. The administrator explicitly authorized proceeding despite the
provisional compatibility risk, acknowledged that risk, and stored a rationale with
this lab authorization.

The second target used to test isolation had:

| Field | Value |
|---|---|
| Hostname / address | `server` / `30.30.30.160` |
| `target_id` | `76044415-8103-4558-829b-90e13a0e4871` |
| `agent_id` | `5ddb0c8f-6a41-4499-9758-4acf2fd66a5d` |
| `profile_id` | `503e10a0-d76a-4bc8-8820-1090a9d5340e` |
| `compatibility_report_id` | `d64a227e-b113-413b-bb2a-769a3ba5fa5c` |

### Cross-target isolation experiment

One `VALIDATE_CONTROL` job for control `7.1.1` was created only for VM1. VM2 polled
first and returned `jobs_polled=0` and `profiles_submitted=0`. It did not claim,
dispatch, or receive VM1's job. This is empirical isolation evidence for the tested
two-target case, consistent with the automated ownership and composite-foreign-key
tests; it is not a general production-concurrency proof.

### Unprivileged VM1 experiment

The first VM1 validation ran as the normal user `nadil`:

| Field | Recorded value |
|---|---|
| `validation_job_id` | `700eb040-5cd2-4858-84da-0f73cb100a47` |
| `validation_result_id` | `4433c042-a167-49a5-a922-650aefe579a7` |
| Result SHA-256 | `5520e449de6b2f98d45165e17e2e0d311c3c0cd526531492db463b56866046f8` |
| `sandbox_operator_acknowledged` | `true` |
| `administrator_approval_acknowledged` | `true` |
| `compatibility_risk_acknowledged` | `true` |
| `effective_uid` / `privileged` | `1000` / `false` |
| M5 result | `not_tested` |
| Remediation attempted / changed | `false` / `false` |
| Rollback attempted | `false` |

M5 correctly refused mutation because effective UID 0 was required. The read-only
pre-audit still recorded `/etc/passwd` as mode `0644`, UID `0`, and GID `0`. The
`not_tested` result records a correctly enforced prerequisite, not a CIS compliance
failure or verdict.

### Journal ownership safety experiment

An attempt to run the same Agent identity through `sudo` while reusing the original
`nadil`-owned journal failed closed with:

```text
validation journal must be owned by the effective user
```

No M5 adapter run occurred and no validation result was submitted by that failed
attempt. The existing user-owned evidence was not chowned or overwritten. A separate
root-owned Agent runtime state was created for the same already-enrolled Agent identity,
and the operator took a VM snapshot before privileged execution.

### Privileged VM1 experiment

The second authorized VM1 job ran under the separate root-owned runtime state:

| Field | Recorded value |
|---|---|
| `validation_job_id` | `78c0c9a3-8134-4e2c-8658-5d1aed256869` |
| `validation_result_id` | `f21d31dd-7a93-4d88-941a-072e6c4ef435` |
| Result SHA-256 | `9c1df875b280a1e94a19bf7b0188c51b2ca5864c5f1ec2047941e4f1fb137064` |
| `effective_uid` / `privileged` | `0` / `true` |
| `can_mutate` | `true` |
| Blockers | none |
| M5 result | `validated` |
| Remediation attempted / changed / succeeded | `true` / `false` / `true` |
| Rollback attempted | `false` |
| Final Controller job status | `completed` |

`/etc/passwd` was already mode `0644` and owned by `root:root`. M5 recorded:

- `backup-passwd=skipped` because no change was required;
- `apply-passwd-metadata=skipped` because the desired metadata already existed;
- `verify-passwd-state=applied`;
- successful `passwd-readable`, `passwd-record-sanity`, and
  `passwd-unprivileged-readability` health checks; and
- no rollback attempt because no change occurred.

The final `/etc/passwd` metadata remained `0644 root:root`. The experiment therefore
showed that SENTRA could exercise the full authorized validation path while avoiding an
unnecessary mutation when the required metadata was already present.

The M5 `validated` result means that this fixed candidate and its post-state were
successfully evaluated by the sandbox procedure. It is not, by itself, a CIS compliance
verdict or authorization to deploy a change to a production target.

## Automated validation baseline

The M6D implementation was regression-tested before this documentation pass:

| Suite/check | Result |
|---|---:|
| Focused M6/M5 tests | 253 passed |
| Full test suite | 443 passed, 0 failures |
| Existing warnings | 5 PyMuPDF/SWIG warnings |
| `git diff --check` | Clean |

Automated tests and real-lab observations are complementary evidence sources. The test
counts do not convert the recorded experiment into a production certification.

## Remaining limitations

- Only `7.1.1` is permitted through M6D. Existing M5 controls `5.1.20` and `4.2.3`
  remain unreachable through this orchestration path.
- The Controller dispatches at most one validation job to an Agent in one cycle.
- SQLite remains the PoC storage backend.
- A dedicated VM was used as the sandbox, but automated creation, cloning,
  snapshotting, disposal, and lifecycle management are not implemented.
- Production deployment and remediation of customer targets are not part of M6D.
- No generic remote execution facility exists.
- An interrupted `STARTED` journal record requires manual sandbox inspection and is
  not automatically retried.
- Current Agent credentials are bearer-based and are not hardware-attested.
- Reasonable clock synchronization between Agent and Controller is assumed for
  timestamp validation.
- If the Controller stores a result but the Agent loses the acknowledgement response,
  the Controller evidence remains stored and mutation is not repeated; automatic
  reconciliation of the local `RESULT_READY` journal state is not yet implemented.
- The real-lab record covers two target identities, one `7.1.1` isolation check, and
  two validation jobs on one dedicated Ubuntu sandbox. It does not establish
  production, multi-tenant, or broader-control readiness.
