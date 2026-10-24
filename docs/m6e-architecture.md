# SENTRA M6E sandbox lifecycle and provider architecture

## Status and scope

M6E-A adds the Controller-side model, persistence, administrative API, and explicit
state machine needed to represent a disposable validation sandbox. M6E-B adds the
narrow `SandboxManager` orchestration boundary and the `local_nested_vm` provider
design. M6E-C implements the Python libvirt backend and has completed real Controller
validation on the dedicated Ubuntu appliance for pool, overlay, domain, runtime-state,
replay, and destroy behavior. A later M6 integration slice has also real-host validated
the fixed SENTRA virtio-serial channel's libvirt normalization; it does not add a new
canonical milestone. Deterministic fake-backend tests on macOS remain separate from
this operator-observed real-host evidence.

The enabled backend uses the libvirt Python API with `qemu:///system`; it does not fall
back to a shell command, `virsh`, Docker, or an unverified substitute. The experiment
proves the bounded host-side provisioning and cleanup behavior described below. It
does not establish guest-level readiness, automatic M6D validation dispatch,
production readiness, or deployment authorization.

The current Proof-of-Concept scope remains limited to control `7.1.1`. M6E does not
change M1–M5 behavior, weaken the existing M6D validation boundary, connect a sandbox
session to an M6D validation job, or add remediation or deployment. It introduces no
SSH, shell, argv, script, generic command, generic provider-payload, or remote-execution
facility.

M6E-A is lifecycle and evidence-lineage infrastructure; M6E-B is bounded provider and
provisioning orchestration infrastructure; M6E-C implements and real-host validates
the scoped libvirt backend. A sandbox session does not
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
manager/provider/backend boundaries and deterministic reconciliation logic. M6E-C
implements and real-host validates the scoped libvirt backend. Snapshot handling,
guest readiness checks beyond the provider runtime observation, automatic M6D
validation dispatch, quarantine enforcement, and broader disposal evidence remain
future work.

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

M6E-C can reconcile a requested session to one deterministic provider instance and
record `READY` after the provider confirms the domain is `RUNNING`. The final two
relationships are deliberately not connected: automatic dispatch of M6D validation
work into the instance has not been proven or enabled.

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
`PROVISIONING`, `RUNNING`, `STOPPED`, `FAILED`, or `MISSING`. M6E-C implements and
real-host validates the provider `destroy` operation, but it remains unavailable over
HTTP; no administrator destroy route was added.

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
libvirt Python module lazily only when invoked and uses the Python API for the scoped
pool, volume, and domain operations. There is no shell-based or container fallback.

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

M6E-C does not download or bundle an image and does not copy a production client disk.
The provider validates the configured root, base image, session directory, and overlay
using fail-closed ownership, type, link-count, permission, ancestry, and symlink checks.
Runtime paths are constructed beneath the configured sandbox root from the derived
resource name. Lexical traversal and an escape from the configured root are rejected;
unsafe operator paths are not silently chmodded or chowned.

The provider marks the base image read-only in the backend plan and compares its device,
inode, size, modification time, and mode before and after provisioning. A changed base
image fails closed. The expected overlay is unique to the session directory and must be
a regular, single-link, service-owned file that is not group/other writable. These
checks enforce the storage contract. The real Ubuntu Controller validation confirmed
the tested ownership and mode expectations for the configured base image, session
pool directory, and overlay; see the M6E-C validation record below.

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
`local_nested_vm`; the M6E-C implementation uses the Python libvirt API and does not
add a generic provider selector or command execution path.

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
- M6E-C has real-host evidence for the scoped libvirt provider lifecycle, but
  guest-level readiness and automatic sandbox-to-M6D validation dispatch are not yet
  proven.
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

## macOS automated-test boundary

Deterministic fake providers/backends exercise orchestration and retry decisions on
macOS without requiring KVM, libvirt, an Ubuntu guest, or VM mutation. These tests
validate the closed data and state-machine boundaries; the separate real Controller
validation below supplies host-side libvirt evidence. Neither test environment proves
guest-level readiness or full M6E completion.

## M6E-C real Controller validation

The real M6E-C validation used an Ubuntu 24.04 Controller with libvirt 10.0.0 and
QEMU 8.2.2 through `qemu:///system`. The exact Mac source used for review was
SHA-256-matched against the Controller source used for the experiment. The Controller
created the dedicated pool automatically, created a qcow2 overlay backed by the
trusted Ubuntu 24.04 base image, defined and started the domain, and observed the
domain reach `RUNNING`.

The following host-side properties were observed:

- dynamic AppArmor confinement was active and enforcing;
- the static DAC label used the planned numeric UID/GID with `relabel="no"`;
- the configured sandbox root was `root:kvm` mode `0710`;
- the per-session pool directory was `libvirt-qemu:kvm` mode `0750`;
- the disposable overlay was `libvirt-qemu:kvm` mode `0600`;
- the trusted base image remained `root:root` mode `0444` while the VM ran;
- the base image SHA-256 remained
  `6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2`;
- same-session provisioning replay was idempotent; and
- provider destroy removed the domain, pool, and session directory while preserving
  the base image's ownership, mode, and SHA-256.

This is operator-observed evidence for the scoped Controller/libvirt lifecycle, not
proof of a guest agent, guest readiness, or validation execution. In particular:

- guest-level readiness beyond host-side domain `RUNNING` is not yet proven;
- automatic sandbox-to-M6D `VALIDATE_CONTROL` dispatch is not yet proven or enabled;
- sandbox validation is not a CIS compliance result;
- no remediation or production deployment is automatically applied or authorized; and
- no generic SSH, remote shell, or command execution exists or is introduced.

## Fixed validation-channel integration after M6E-C

A subsequent M6 integration slice added one fixed Controller-to-sandbox channel to
the libvirt domain XML. SENTRA-generated XML contains only the fixed target
`org.sentra.validation.0`; SENTRA does not supply a Unix socket source path. The
sealed `LocalNestedVmPlan` remains unchanged in scope: no host mounts, device
passthrough, caller-defined cloud-init, SSH, QEMU guest agent, or generic
shell/command/argv/script execution was added.

On the Ubuntu 24.04 Controller (libvirt 10.0.0, QEMU 8.2.2, `qemu:///system`), live
libvirt XML added a source at
`/run/libvirt/qemu/channel/1-sentra-sbx-25b3d804-/org.sentra.validation.0`, target
state `disconnected`, `channel0` alias, and virtio-serial address on controller 0,
bus 0, port 1. The corresponding virtio-serial controller used index 0, alias
`virtio-serial0`, and PCI address `0000:02:00.0`. Inactive XML omitted the source
while retaining the fixed target and virtio-serial address.

The initial validator failed closed on the real libvirt-generated source path. The
normalization was then narrowed to accept the `/run/libvirt/qemu/channel/` form only
when its runtime ID matches the live domain and its short domain-name component is
derived from the expected SENTRA sandbox name using the observed first-20-character
behavior. The channel basename and source mode are fixed; no arbitrary socket paths
are accepted. `provider.inspect()` against the same already-running sandbox then
succeeded and returned `RUNNING`. The disposable sandbox was subsequently destroyed
through `LocalNestedVmProvider.destroy()`; its domain, pool, and session directory
were removed, while the protected older session was untouched.

After provisioning, inspection, and teardown, the trusted base image remained
`root:root` mode `0444`, with SHA-256
`6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2`.
Automated verification on the Mac reported 79 libvirt tests and 58 provider tests
passing; the full suite reported 619 passed with five existing PyMuPDF/SWIG warnings.
`py_compile` and `git diff --check` passed, and the forbidden-execution scan of
`src/controller` had no matches.

This validates host-side channel definition and normalization only. It does not show
that target facts are sent through the channel, that a guest consumes it, that a
Sandbox Runner exists, or that M5/M6D validation runs inside the guest. It does not
establish CIS compliance, authorize production deployment, or prove that the sandbox
perfectly reproduces a target system. The next integration work remains derivation of
minimal typed target context, a constrained guest-side Sandbox Runner, and invocation
of the existing allowlisted M5 validator with evidence returned through the normal
approval boundary.

## Remaining real-appliance work

Further testing on the dedicated Ubuntu SENTRA Appliance—not a client Agent host—must
address guest boot/readiness, timeout and failure handling, snapshot and console
recovery, quarantine containment and release policy, and evidence for those behaviors.
Resource quotas, concurrency, rate limiting, and denial-of-service controls also
remain future work, as do secret-exclusion and minimal-state reproduction rules.

A later M6E step must separately implement and validate binding a `READY` session to
one constrained M6D `VALIDATE_CONTROL` job for `7.1.1`. M6E-C does not perform that
connection, run M5, execute remediation, or automatically turn validation evidence
into a CIS compliance verdict.

Production certificate and credential lifecycle, encrypted/high-availability storage,
hardware-backed key custody, a production concurrency model, full audit retention,
multi-provider support, broader control coverage, HTTP destroy/close orchestration,
and the Dashboard also remain future work.
