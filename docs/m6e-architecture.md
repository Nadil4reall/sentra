# SENTRA M6E sandbox lifecycle and provider architecture

## Status and scope

M6E-A adds the Controller-side model, persistence, administrative API, and explicit
state machine needed to represent a disposable validation sandbox. M6E-B adds the
narrow `SandboxManager` orchestration boundary and the first `local_nested_vm`
provider design. The M6E-B implementation has been developed and tested on macOS with
deterministic injected test backends; it has **not** provisioned a real virtual machine
and the real Ubuntu KVM/libvirt appliance experiment has **not yet been executed**.

The production-facing libvirt adapter is deliberately not enabled in M6E-B. Its lazy
boundary reports a controlled provider-unavailable failure rather than falling back to
a shell command, `virsh`, Docker, or an unverified substitute. A real provider cannot
be claimed operational until the later Ubuntu SENTRA Appliance experiment implements
and validates that boundary.

The current Proof-of-Concept scope remains limited to control `7.1.1`. M6E does not
change M1–M5 behavior, weaken the existing M6D validation boundary, connect a sandbox
session to an M6D validation job, or add remediation or deployment. It introduces no
SSH, shell, argv, script, generic command, generic provider-payload, or remote-execution
facility.

M6E-A is lifecycle and evidence-lineage infrastructure; M6E-B is bounded provider and
provisioning orchestration infrastructure. A sandbox session does not
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
├── Evidence Store
├── Dashboard
└── Sandbox Manager
        |
        v
    local nested virtualization
        |
        v
    disposable Ubuntu sandbox

Client Linux servers
└── SENTRA Agent only
```

The Controller and the infrastructure that manages sandboxes may coexist inside one
SENTRA appliance VM. That does **not** make the Controller operating system or its
filesystem the validation sandbox. Validation must occur inside a separately isolated,
disposable runtime with its own lifecycle and recovery boundary. A provider failure or
candidate mutation must not turn the appliance control plane itself into the experiment
target.

M6E-A supplies the Controller-side lifecycle foundation. M6E-B supplies the typed
manager/provider/backend boundaries and deterministic reconciliation logic, but not an
enabled real libvirt backend. Nested virtualization, empirically validated VM
construction, snapshot handling, guest readiness checks beyond the provider runtime
observation, quarantine enforcement, and disposal evidence remain future work.

Sandbox infrastructure belongs on the SENTRA appliance, not on client Linux servers.
A client runs the SENTRA Agent only. The provider does not clone a client VM or disk,
mount a production filesystem, or copy production secrets into the sandbox.

## Evidence lineage

M6E-A extends the existing target/profile/report chain with a Controller-issued sandbox
session identity:

```text
source_target_id
  -> source_profile_id
  -> source_compatibility_report_id
  -> sandbox_session_id
  -> provider-derived sandbox_instance_id
  -> later validation_job_id
  -> later validation_result_id
```

M6E-B may reconcile a requested session to one deterministic provider instance and
record `READY`, but the final two relationships are deliberately not connected. Neither
M6E-A nor M6E-B dispatches M6D validation work into the instance.

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
execution details. In M6E-B the provider derives the opaque instance identifier only
from the canonical session UUID, and the Controller stores it only when the session
transitions from `PROVISIONING` to `READY`.

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

## M6E-B provider and backend boundary

M6E-B introduces a closed `SandboxProvider` interface with three operations:

```text
provision(sandbox_session_id)
inspect(sandbox_session_id)
destroy(sandbox_session_id)
```

The input is a Controller-issued UUID, not a generic payload. The typed provider result
contains only the provider type, opaque instance identity, and one closed runtime state:
`PROVISIONING`, `RUNNING`, `STOPPED`, `FAILED`, or `MISSING`. M6E-B does not expose the
`destroy` operation over HTTP; its presence defines the narrow provider contract for a
later lifecycle phase.

`LocalNestedVmProvider` derives the resource name deterministically as:

```text
sentra-sbx-<canonical sandbox_session_id UUID>
```

It does not incorporate a customer hostname, target metadata, or arbitrary caller
input. The same session therefore resolves to the same provider resource after a retry
or Controller restart. Backend observations must match both that identity and the
SHA-256 of the sealed provider plan before they are accepted.

The provider passes only a strict `LocalNestedVmPlan` to its injected backend. The plan
is generated by SENTRA from trusted server-side `LocalNestedVmConfig`, not from the HTTP
request. The current fixed PoC plan describes:

- Ubuntu 24.04;
- 2 vCPU and 2048 MiB RAM by default;
- a server-configured libvirt network (`default` by default);
- a trusted read-only base image;
- one `qcow2` overlay named `root.qcow2` inside the session directory;
- no host mounts or device passthrough; and
- no caller-defined cloud-init data.

Memory, vCPU, network, sandbox root, and base-image settings are server configuration.
They cannot be supplied or overridden through sandbox-session creation or provisioning
requests. The provider API has no command, shell, argv, script, executable, XML, QEMU
argument, `virsh` argument, environment-variable, or generic provider-selector field.

The `LocalNestedVmBackend` protocol receives only that sealed plan. This dependency-
injection boundary permits deterministic fake backends to model success, existing-
instance reconciliation, unavailable or failed provisioning, failed inspection, and
non-running states on macOS without importing libvirt. `LibvirtBackend` loads the
libvirt Python module lazily only when invoked. Its M6E-B methods remain intentionally
disabled and fail with a controlled `SandboxProviderUnavailableError`; there is no
shell-based or container fallback.

## Trusted image and disposable overlay model

The local design is deliberately based on a sanitized, SENTRA-managed Ubuntu image:

```text
trusted Ubuntu 24.04 base image (read-only)
             |
             v
per-session disposable qcow2 overlay
             |
             v
temporary nested VM
```

M6E-B does not download or bundle an image and does not copy a production client disk.
The provider validates the configured root, base image, session directory, and overlay
using fail-closed ownership, type, link-count, permission, ancestry, and symlink checks.
Runtime paths are constructed beneath the configured sandbox root from the derived
resource name. Lexical traversal and an escape from the configured root are rejected;
unsafe operator paths are not silently chmodded or chowned.

The provider marks the base image read-only in the backend plan and compares its device,
inode, size, modification time, and mode before and after provisioning. A changed base
image fails closed. The expected overlay is unique to the session directory and must be
a regular, single-link, service-owned file that is not group/other writable. These
checks express the M6E-B storage contract; empirical behavior of a real libvirt/qcow2
implementation remains to be validated on the Ubuntu appliance.

## Provisioning and deterministic reconciliation

`SandboxManager` applies this bounded sequence:

```text
REQUESTED
    |
    v
mark_provisioning()
    |
    v
provider.provision(session UUID)
    |
    v
provider.inspect(session UUID)
    |
    +-- confirmed RUNNING and matching identity --> mark_ready(instance ID) --> READY
    |
    +-- still PROVISIONING -----------------------> remain PROVISIONING
    |
    `-- unavailable, failed, stopped, missing,
        mismatched, or untrusted -----------------> FAILED
```

`READY` is recorded only after inspection confirms `RUNNING` for the exact derived
instance identity. Failure evidence stored by the Controller is bounded and sanitized;
raw tracebacks, backend credentials, and full backend path details are not returned as
session reasons.

If a Controller crashes after the provider created an instance but before `READY` was
stored, the session remains `PROVISIONING`. Retrying provisioning derives the same
resource identity and calls the backend's idempotent `ensure_provisioned` boundary,
then inspects the resource before recording `READY`. It does not permit a backward
state transition or choose a new VM name. A session already recorded as `READY` is
returned only when its stored instance identity matches the deterministic expected
identity.

## Administrative API boundary

Sandbox-session creation and retrieval are available only through authenticated
Controller administration routes:

```text
POST /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}/sandbox-sessions

GET  /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}/sandbox-sessions

GET  /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}/sandbox-sessions/{sandbox_session_id}

POST /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}/sandbox-sessions/{sandbox_session_id}/provision
```

There is no Agent sandbox-session endpoint. Route identifiers, stored lineage, and the
strict request model are rebound before storage or retrieval, so a session cannot be
created, listed, or retrieved under a different target/profile/report chain.

The M6E-B provisioning action is also administrator-only and revalidates the complete
target/profile/report/session lineage before orchestration. Its request body is the
strict empty JSON object `{}`. Infrastructure settings, provider type, instance ID, and
lifecycle state cannot be supplied by the client. Agent credentials cannot invoke the
route. No generic lifecycle/status or destroy endpoint was added.

The API request and session models do not accept:

- a command, shell, argv, or script;
- a filesystem path or target;
- a service action or adapter selector;
- arbitrary VM arguments or a provider payload;
- host mounts;
- raw CIS Audit or Remediation text; or
- a caller-selected sandbox instance identifier.

`provider_type` is not an open dispatch string. It remains fixed to
`local_nested_vm`; the real libvirt implementation behind that type is not enabled in
M6E-B.

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
- M6E-B defines provider/orchestration behavior but has not executed real VM
  provisioning; its production libvirt adapter remains disabled.
- It does not add a Controller-to-Agent action or modify the M6D Agent protocol.
- It does not invoke M5, dispatch a validation job, or perform remediation.
- It accepts neither arbitrary provider configuration nor executable material; all VM
  infrastructure values are trusted server-side configuration.
- A caller cannot select an instance, transition state, or forge lifecycle timestamps.
- A session remains bound to one validated target/profile/report/control lineage.
- A backend observation cannot make a session `READY` unless it matches the sealed plan
  and the provider confirms the expected runtime is `RUNNING`.
- Failure and quarantine are explicit states; neither silently permits validation or
  reuse.
- Closing a session is terminal and does not itself prove that a future sandbox was
  securely erased.
- SQLite is a PoC database, not a production secret store or multi-tenant lifecycle
  platform.
- The Controller filesystem is not the sandbox, and client Linux servers do not host
  sandbox infrastructure.

M6E does not copy a production filesystem, import a production VM, capture production
secrets, or define a production cloning pipeline. The provider design assumes a
purpose-built and sanitized, appliance-managed Ubuntu base image. Later work must
explicitly define any minimal state reproduced and prevent credentials, keys, tokens,
personal data, and unrelated target files from entering the sandbox by default. Full
production filesystem cloning is not part of this design.

## macOS validation boundary

M6E-B's current development and automated-test environment is macOS. Deterministic
fake providers/backends exercise orchestration and retry decisions without requiring
KVM, libvirt, an Ubuntu guest, or any VM mutation. This validates the closed data and
state-machine boundaries in scope; it does not empirically validate nested
virtualization, libvirt domain construction, qcow2 behavior, network isolation, guest
boot, or teardown on an appliance.

The real nested KVM/libvirt appliance test is **not yet executed**. Accordingly, M6E-B
must not be described as automatic VM provisioning validated in a real environment,
production-ready sandboxing, or completion of full M6E.

## Real appliance integration and later work

The next provider-integration experiment must occur on the dedicated Ubuntu SENTRA
Appliance, not on a client Agent host. It must implement the currently disabled
libvirt backend using the sealed plan and then verify:

- nested-virtualization capability and host prerequisites;
- a trusted, versioned, sanitized Ubuntu 24.04 image or template;
- creation of one real per-session qcow2 overlay without base-image mutation;
- fixed domain configuration and network, process, storage, and management-plane
  isolation;
- deterministic provider identity and existing-instance reconciliation after a
  Controller interruption;
- guest boot/readiness, timeout, failure, snapshot, and console-recovery behavior;
- quarantine containment and explicit operator release policy;
- deterministic teardown and disposal evidence;
- resource quotas, concurrency, rate limiting, and denial-of-service controls; and
- secret-exclusion and minimal-state reproduction rules.

A later M6E step must separately bind a `READY` session to one constrained M6D
`VALIDATE_CONTROL` job for `7.1.1`. M6E-B does not perform that connection, run M5,
execute remediation, or automatically turn validation evidence into a CIS compliance
verdict.

Production certificate and credential lifecycle, encrypted/high-availability storage,
hardware-backed key custody, a production concurrency model, full audit retention,
multi-provider support, broader control coverage, real destroy/close orchestration,
and the Dashboard also remain future work.
