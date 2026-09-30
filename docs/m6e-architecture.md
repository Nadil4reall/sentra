# SENTRA M6E-A Controller-side sandbox lifecycle foundation

## Status and scope

M6E-A adds the Controller-side model, persistence, administrative API, and explicit
state machine needed to represent a future disposable validation sandbox. It does not
provision, start, connect to, mutate, or dispose of a real virtual machine. The first
provider implementation is deferred to M6E-B.

The current Proof-of-Concept scope remains limited to control `7.1.1`. M6E-A does not
change M1–M5 behavior, weaken the existing M6D validation boundary, connect a sandbox
session to an M6D validation job, or add remediation or deployment. It introduces no
SSH, shell, argv, script, generic command, generic provider-payload, or remote-execution
facility.

M6E-A is lifecycle and evidence-lineage infrastructure. A sandbox session does not
mean that a candidate is safe, that a control passes CIS assessment, or that production
deployment is authorized.

## Intended appliance architecture

The longer-term SENTRA appliance is intended to keep its control plane and disposable
experiment environment conceptually and operationally separate:

```text
SENTRA Appliance VM
├── Controller
├── Database
├── Compatibility Engine
├── Validation Orchestrator
├── Sandbox Manager
├── Evidence Store
├── Dashboard
└── isolated disposable sandbox runtime
    └── future local nested-virtualization provider
```

The Controller and the infrastructure that manages sandboxes may coexist inside one
SENTRA appliance VM. That does **not** make the Controller operating system or its
filesystem the validation sandbox. Validation must occur inside a separately isolated,
disposable runtime with its own lifecycle and recovery boundary. A provider failure or
candidate mutation must not turn the appliance control plane itself into the experiment
target.

Only the Controller-side lifecycle foundation exists in M6E-A. The Dashboard, a real
Sandbox Manager provider, nested virtualization, automated VM construction, snapshot
handling, health observation, quarantine enforcement, and disposal are future work.

## Evidence lineage

M6E-A extends the existing target/profile/report chain with a Controller-issued sandbox
session identity:

```text
source_target_id
  -> source_profile_id
  -> source_compatibility_report_id
  -> sandbox_session_id
  -> later validation_job_id
  -> later validation_result_id
```

The final two relationships are deliberately not connected in M6E-A. A session can be
requested and represented, but M6E-A cannot dispatch M6D validation work into it.

Session creation revalidates the complete stored lineage:

- the source target exists;
- the source profile belongs to that target;
- the source compatibility report belongs to that profile and target; and
- the report contains the requested `7.1.1` compatibility result.

The session stores a canonical compatibility reference snapshot derived by the
Controller from the validated stored M4 report. The snapshot retains the report and
control identity, compatibility result and rationale evidence, report hash/version
context, and the existing `metadata_review_status` and `provisional` semantics needed
to show why that report/control authorized the session. The foreign-key-bound source
CompatibilityReport separately retains the benchmark identity. Together they provide
the authorization context; neither is a safety or CIS-compliance verdict.

## Sandbox session model

Each session contains, at minimum:

- Controller-issued `sandbox_session_id`;
- administrator-supplied idempotency `request_id`;
- `source_target_id`, `source_profile_id`, and
  `source_compatibility_report_id`;
- `control_id`, fixed to `7.1.1`;
- `provider_type`, fixed to `local_nested_vm` for this PoC;
- lifecycle status;
- an optional provider-generated opaque `sandbox_instance_id`;
- Controller-generated lifecycle timestamps;
- an optional failure reason or quarantine reason; and
- the canonical compatibility evidence/reference snapshot.

The creation request is intentionally smaller than the stored session:

```text
request_id
control_id = 7.1.1
administrator_sandbox_authorization_acknowledged = true
```

The caller cannot supply `sandbox_session_id`, `sandbox_instance_id`, timestamps,
status, failure or quarantine state, provider arguments, image paths, host mounts, or
execution details. A future provider may generate the opaque instance identifier only
when the session transitions from `PROVISIONING` to `READY`.

## Explicit lifecycle state machine

The stored status is one of:

```text
REQUESTED
PROVISIONING
READY
VALIDATING
COMPLETED
FAILED
QUARANTINED
CLOSED
```

Only these transitions are permitted:

```text
REQUESTED    -> PROVISIONING

PROVISIONING -> READY
PROVISIONING -> FAILED

READY        -> VALIDATING
READY        -> FAILED

VALIDATING   -> COMPLETED
VALIDATING   -> FAILED
VALIDATING   -> QUARANTINED

COMPLETED    -> CLOSED
FAILED       -> CLOSED
QUARANTINED  -> CLOSED
```

`CLOSED` is terminal. No backward transition, state skip, or reopening is allowed.
The Controller records the applicable timestamp during each transition; callers do not
supply lifecycle timestamps.

M6E-A exposes explicit internal service and repository methods for later trusted
provider logic:

- `mark_provisioning()`
- `mark_ready()`
- `mark_validating()`
- `mark_completed()`
- `mark_failed()`
- `mark_quarantined()`
- `close_session()`

Every operation verifies the exact expected previous state. M6E-A exposes no generic
"set status" route and no client-accessible lifecycle mutation route.
Future provider code is expected to enter through these Controller service methods;
the corresponding repository methods are the guarded persistence boundary, not a
provider-facing source of timestamps.

## Administrative API boundary

Sandbox-session creation and retrieval are available only through authenticated
Controller administration routes:

```text
POST /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}/sandbox-sessions

GET  /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}/sandbox-sessions

GET  /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}/sandbox-sessions/{sandbox_session_id}
```

There is no Agent sandbox-session endpoint. Route identifiers, stored lineage, and the
strict request model are rebound before storage or retrieval, so a session cannot be
created, listed, or retrieved under a different target/profile/report chain.

The API request and session models do not accept:

- a command, shell, argv, or script;
- a filesystem path or target;
- a service action or adapter selector;
- arbitrary VM arguments or a provider payload;
- host mounts;
- raw CIS Audit or Remediation text; or
- a caller-selected sandbox instance identifier.

`provider_type` is not an open dispatch string. It is fixed to
`local_nested_vm`, even though the corresponding real provider is not implemented in
M6E-A.

## Idempotency, storage, and fail-closed behavior

SQLite remains the M6 PoC storage backend. Sandbox rows retain the exact source
lineage, lifecycle data, and canonical compatibility reference. Foreign keys and
repository ownership checks preserve the target/profile/report relationship.

`request_id` is an idempotency identity:

- an identical canonical request replay returns the existing session;
- reuse with changed authorization or lineage conflicts; and
- stored UUID text must already equal `str(UUID(raw))`.

Parseable but noncanonical UUID spellings—such as uppercase or brace-wrapped values—
are treated as storage corruption. They are never silently normalized and cannot be
used to create a second logical session.

The M6E-A table follows the existing Controller storage boundary: exact schema and
constraint validation, foreign-key checking, transactional initialization, and
fail-closed handling of malformed populated state. Migration from an existing M6D
database adds the new session storage without rewriting or inventing prior M3, M4, or
M5 evidence.

## CIS and SENTRA separation

M6E-A preserves the project distinction among:

- **CIS-derived content:** licensed benchmark identity and Audit/Remediation text,
  retained as inert research inputs and never executed;
- **SENTRA-derived analysis:** M2 enrichment and M4 compatibility results, including
  `needs_review`, provisional status, uncertainty, and documented rationale; and
- **SENTRA implementation evidence:** the administrator authorization, session
  identity, source lineage, state transitions, Controller timestamps, and future
  provider observations.

Creating or completing a sandbox session will not turn M4 compatibility output or M5
experiment evidence into a CIS pass/fail result. `no_known_conflict` must not be
renamed or interpreted as `safe`, and M5 `validated` retains its existing bounded
experimental meaning.

## Security and lifecycle boundaries

- M6E-A never creates a VM and never connects to a target or sandbox.
- It does not add a Controller-to-Agent action or modify the M6D Agent protocol.
- It does not invoke M5, dispatch a validation job, or perform remediation.
- It accepts neither arbitrary provider configuration nor executable material.
- A caller cannot select an instance, transition state, or forge lifecycle timestamps.
- A session remains bound to one validated target/profile/report/control lineage.
- Failure and quarantine are explicit states; neither silently permits validation or
  reuse.
- Closing a session is terminal and does not itself prove that a future sandbox was
  securely erased.
- SQLite is a PoC database, not a production secret store or multi-tenant lifecycle
  platform.

M6E-A does not copy a production filesystem, import a production VM, capture production
secrets, or define a production cloning pipeline. A future provider must use a
purpose-built and sanitized sandbox source, explicitly define which minimal state is
reproduced, and prevent credentials, keys, tokens, personal data, and unrelated target
files from entering the sandbox by default. Full production filesystem cloning is not
part of this design.

## M6E-B and later work

M6E-B is intended to implement the first real `local_nested_vm` provider behind the
narrow lifecycle interface. Before it can be treated as operational, it must define
and test:

- nested-virtualization capability and host prerequisites;
- a trusted, versioned, sanitized Ubuntu sandbox image or template;
- network, process, storage, and management-plane isolation;
- provider-generated opaque instance identities;
- snapshot, console recovery, health, timeout, and failure behavior;
- quarantine containment and explicit operator release policy;
- deterministic teardown and disposal evidence;
- crash recovery and reconciliation between provider reality and Controller state;
- resource quotas, concurrency, rate limiting, and denial-of-service controls;
- secret-exclusion and minimal-state reproduction rules; and
- the later, explicit binding from a `READY` session to one constrained M6D
  `VALIDATE_CONTROL` job for `7.1.1`.

Production certificate and credential lifecycle, encrypted/high-availability storage,
hardware-backed key custody, a production concurrency model, full audit retention,
multi-provider support, broader control coverage, and the Dashboard also remain future
work. M6E-A must not be described as production-ready or as completion of full M6E.
