# SENTRA M6B HTTPS Controller/Agent architecture

## Status and scope

M6B adds a real TLS-only HTTP transport and a deterministic one-cycle Agent to the
committed M6A identity, authentication, storage, and evidence-lineage core. The Agent
reuses the existing read-only M3 profiler through a narrow adapter. Automated tests
cover the implementation, and the scoped Controller-to-Agent profiling workflow has
also completed one real Mac-to-Ubuntu lab validation. This is not production
readiness, full-M6 completion, or validation across other hosts, networks, or PKI
deployments.

M6B adds no remediation, deployment, M4 or M5 orchestration, arbitrary command
execution, inbound target connection, background daemon, or dashboard.

## Lab role versus product boundary

The completed experiment temporarily assigned a MacBook Pro the Controller role and
an Ubuntu 24.04 LTS VM the Agent role. The recorded addresses, hostname, identifiers,
accounts, and filesystem paths are observations from this controlled lab only. They
are not built-in product identities, defaults, or topology assumptions.

The implemented boundary is:

```text
Ubuntu Agent                                      Controller
────────────                                      ──────────
mode-0600 persistent state                        mode-0600 SQLite database
installation_id                                  target/Agent/job/profile records
Controller-issued identity + credential
       │
       └── outbound HTTPS /api/v1 ────────────────►
           TLS >= 1.2
           configured CA and hostname verification
           no plaintext or insecure fallback
```

Certificates are provisioned externally. SENTRA does not generate a production CA or
server certificate.

## Real-lab validation record

This section deliberately distinguishes the evidence sources:

- **Automated regression evidence:** the Python suite establishes repeatable model,
  transport, isolation, state, and lineage behavior in tests.
- **SENTRA-produced runtime evidence:** the two Agent cycle summaries and
  Controller-created target, job, and profile records describe what SENTRA reported
  during this run.
- **Operator-observed lab evidence:** certificate verification, the unauthenticated
  HTTP response, state-file mode, target-count checks, and SQLite inspection were
  independently observed during the controlled experiment.

None of these evidence sources is a production certification or a claim that all of
M6 is complete.

### Lab environment

| Role | Recorded observation |
|---|---|
| Controller | MacBook Pro at `10.10.10.3:8443` |
| Controller TLS | Locally created development CA; server certificate SAN contained `IP:10.10.10.3`; certificate verification succeeded |
| Agent | Ubuntu 24.04 LTS at lab address `10.10.10.8` |
| Controller-observed Ubuntu version | `24.04` |
| Controller-observed kernel | `6.8.0-139-generic` |
| Controller-observed architecture | `aarch64` |
| Controller-observed hostname | `root` — the machine hostname, not the root user account |

The development CA was lab-only. No insecure TLS option or certificate-verification
bypass was used.

### Observed sequence and outcomes

1. Ubuntu verified the Controller certificate using the development CA.
2. An unauthenticated request to the administrative endpoint returned HTTP `401`.
3. The first Agent cycle enrolled successfully and returned:

   ```text
   enrolled_during_run=true
   heartbeat_accepted=true
   jobs_polled=0
   profiles_submitted=0
   ```

4. The Agent state was persisted with mode `0600`.
5. The Controller listed exactly one registered target.
6. The administrator created one `PROFILE_TARGET` job.
7. The second Agent cycle ran without the bootstrap credential and returned:

   ```text
   enrolled_during_run=false
   heartbeat_accepted=true
   jobs_polled=1
   profiles_submitted=1
   ```

8. The existing read-only M3 Target Profiler executed on the Ubuntu VM.
9. The Controller accepted and stored the strict submitted `TargetProfile`.
10. SQLite inspection showed the `PROFILE_TARGET` job as `completed`.
11. The profile record contained matching target, Agent, and job identifiers plus
    `profile_id`, `collected_at`, `received_at`, and the Controller-computed
    `profile_sha256`.
12. The Controller still listed exactly one target after the second cycle, providing
    operator-observed evidence that the persisted enrollment was reused rather than a
    duplicate target being created.

### Recorded lab identifiers

| Identifier | Value |
|---|---|
| `installation_id` | `c3f480d7-1a73-4d43-86f7-393ec97921e1` |
| `target_id` | `d16ab6b4-45ff-4031-8223-1c90e27c22ec` |
| `agent_id` | `9e334e04-0682-4052-ae1c-b1ac48eeb928` |
| `job_id` | `87a5e976-b05b-4c27-8c00-ceb024acb9b4` |
| `profile_id` | `949f950f-747c-4711-9684-95b186899013` |

These identifiers document one experiment. They are not reusable credentials or
configured defaults.

### Regression evidence recorded with the lab milestone

| Suite/check | Result |
|---|---:|
| M6 tests | 89 passed |
| Full test suite | 398 passed, 0 failures |
| Existing warnings | 5 PyMuPDF/SWIG warnings |
| `git diff --check` | Clean |

## Preserved security and research boundary

- The Agent initiates outbound HTTPS communication; the Controller does not SSH into
  the target.
- The protocol has no arbitrary shell, command, argv, script, or generic execution
  facility. Only `PROFILE_TARGET` was exercised.
- M3 profiling remains read-only. No remediation occurred.
- M4 compatibility orchestration and M5 sandbox/remediation orchestration are not part
  of M6B.
- The development CA is lab-only; no production certificate lifecycle has been
  implemented.
- Credential rotation/revocation, replay protection, a general idempotency framework,
  rate limiting, a production concurrency model, TPM/HSM credential storage, and an
  Agent daemon/service remain unimplemented.
- SQLite remains a PoC storage backend.

## One-cycle Agent flow

`python -m src.agent` performs one bounded cycle:

```text
load/create installation state
        │
        ├── not enrolled: ENROLL with bootstrap credential
        │                  persist target_id, agent_id, Agent credential
        └── enrolled: reuse existing state; do not enroll again
        │
        ▼
authenticated HEARTBEAT
        │
        ▼
authenticated POLL_JOB
        │
        ├── no work: return a successful credential-free summary
        └── PROFILE_TARGET only
                 │
                 ▼
          LocalTargetProfiler
                 │
                 ▼
       existing src/target_profiler
                 │
                 ▼
       strict TargetProfile submission
                 │
                 ▼
 Controller validates ownership, canonical-hashes and stores evidence,
 then completes that dispatched job exactly once
```

The runtime has no command string, argv, shell, script, remediation, or generic job
execution interface. Unknown or non-dispatched jobs are refused.

## Configuration and credential roles

The Controller CLI requires configured listen host and port, externally supplied TLS
certificate and private-key paths, SQLite path, and separate bootstrap and
administrator credentials. Credentials come from named environment variables or
protected files; there are no plaintext credential-value command-line flags. The TLS
private key must be owned by the current user and inaccessible to group/other users.

The Agent CLI requires:

- the Controller HTTPS origin or `/api/v1` URL;
- the trusted Controller CA bundle;
- a persistent Agent state path;
- optional version labels and request timeout; and
- on first enrollment only, the bootstrap credential from a protected mode-`0600`
  file or `SENTRA_AGENT_BOOTSTRAP_CREDENTIAL`.

The bootstrap credential is used only to call `ENROLL`. The returned per-Agent
credential is stored in the existing atomic mode-`0600` Agent state and is used for
heartbeat, polling, and profile submission. A normal restart loads that enrollment and
does not require or read the bootstrap credential again. Neither CLI prints a
credential.

## HTTPS boundary

The Controller listener uses the existing `ControllerAPI`, `ControllerService`, and
`SQLiteControllerRepository`; transport code does not duplicate their authorization
or lineage rules. It accepts bounded JSON request bodies, emits sanitized JSON errors,
disables request logging, and closes each HTTP/1.1 connection after its response.

The Agent client:

- accepts only HTTPS URLs without embedded credentials;
- builds a CA-backed server-authentication context with hostname verification;
- requires TLS 1.2 or later;
- has no `--insecure` or `verify=False` mode;
- ignores environment proxies and refuses redirects so authenticated request bodies
  cannot be replayed to another origin; and
- bounds and strictly validates Controller responses.

## M3 evidence and lineage

`LocalTargetProfiler` delegates directly to `src.target_profiler.profiler.collect_local_profile`.
It neither copies collectors nor interprets their results. The four M3 states remain:

- `collected`
- `unavailable`
- `unsupported`
- `error`

They are serialized inside the strict `TargetProfile` without converting a
non-collected state to `false`.

The authenticated submission lineage is:

```text
target_id -> agent_id -> PROFILE_TARGET job_id -> profile_id
```

The Controller, not the Agent, canonicalizes the validated profile and computes the
authoritative SHA-256. A successful insert and job completion occur in one repository
transaction. Existing target/Agent/job constraints prevent cross-target submission and
duplicate overwrite.

## Reproducing the validated lab workflow

The commands below retain operator-selected placeholders rather than embedding the
recorded lab addresses. A future reproduction must use a server certificate signed by
its trusted development CA and containing the exact Controller URL host as a DNS or IP
subject alternative name.

### 1. Start the Controller on the Mac

```bash
SENTRA_REPO='/absolute/path/to/sentra'
SENTRA_CONTROLLER_STATE='/absolute/operator-owned/path/m6b-controller'
SENTRA_PKI='/absolute/path/to/operator-provisioned/pki'
SENTRA_CONTROLLER_LISTEN_HOST='<configured-bind-address>'
SENTRA_CONTROLLER_PORT='<configured-port>'
SENTRA_CONTROLLER_NAME='<name-or-IP-present-in-certificate-SAN>'
SENTRA_CONTROLLER_ORIGIN="https://${SENTRA_CONTROLLER_NAME}:${SENTRA_CONTROLLER_PORT}"

install -d -m 700 "$SENTRA_CONTROLLER_STATE"
umask 077
openssl rand -hex 32 > "$SENTRA_CONTROLLER_STATE/bootstrap.credential"
openssl rand -hex 32 > "$SENTRA_CONTROLLER_STATE/admin.credential"
chmod 600 \
  "$SENTRA_CONTROLLER_STATE/bootstrap.credential" \
  "$SENTRA_CONTROLLER_STATE/admin.credential" \
  "$SENTRA_PKI/controller-key.pem"

cd "$SENTRA_REPO"
.venv/bin/python -m src.controller \
  --listen-host "$SENTRA_CONTROLLER_LISTEN_HOST" \
  --listen-port "$SENTRA_CONTROLLER_PORT" \
  --tls-certificate "$SENTRA_PKI/controller-cert.pem" \
  --tls-private-key "$SENTRA_PKI/controller-key.pem" \
  --database "$SENTRA_CONTROLLER_STATE/controller.sqlite3" \
  --bootstrap-credential-file "$SENTRA_CONTROLLER_STATE/bootstrap.credential" \
  --admin-credential-file "$SENTRA_CONTROLLER_STATE/admin.credential"
```

Transfer only the public CA certificate and a protected copy of the bootstrap
credential to the Ubuntu Agent through an operator-controlled out-of-band channel.
That provisioning step is not SENTRA remote management.

### 2. Run the first Agent cycle on Ubuntu

```bash
SENTRA_AGENT_REPO='/absolute/path/to/sentra'
SENTRA_AGENT_STATE_DIR='/absolute/operator-owned/path/m6b-agent'
SENTRA_CONTROLLER_ORIGIN='https://<certificate-SAN-name>:<port>'
SENTRA_CONTROLLER_CA='/absolute/path/to/controller-ca.pem'
SENTRA_AGENT_BOOTSTRAP='/absolute/path/to/protected/bootstrap.credential'

install -d -m 700 "$SENTRA_AGENT_STATE_DIR"
chmod 600 "$SENTRA_AGENT_BOOTSTRAP"
cd "$SENTRA_AGENT_REPO"
.venv/bin/python -m src.agent \
  --controller-url "$SENTRA_CONTROLLER_ORIGIN" \
  --controller-ca "$SENTRA_CONTROLLER_CA" \
  --state "$SENTRA_AGENT_STATE_DIR/state.json" \
  --bootstrap-credential-file "$SENTRA_AGENT_BOOTSTRAP" \
  --agent-version m6b-poc \
  --profiler-version m3 \
  --sentra-version m6b-poc
```

With no job queued, the expected summary reports enrollment and heartbeat success with
zero jobs and profiles. The new state contains the installation identity and
Controller-issued enrollment and has mode `0600`.

### 3. Create the single allowlisted job from the Mac

Create a protected curl header without placing the administrator secret in process
arguments:

```bash
SENTRA_ADMIN_HEADER="$SENTRA_CONTROLLER_STATE/admin-header"
{
  printf 'Authorization: Bearer '
  tr -d '\r\n' < "$SENTRA_CONTROLLER_STATE/admin.credential"
  printf '\n'
} > "$SENTRA_ADMIN_HEADER"
chmod 600 "$SENTRA_ADMIN_HEADER"

curl --fail-with-body --silent --show-error \
  --cacert "$SENTRA_PKI/controller-ca.pem" \
  --header @"$SENTRA_ADMIN_HEADER" \
  "$SENTRA_CONTROLLER_ORIGIN/api/v1/admin/targets"
```

Copy the returned target UUID into `SENTRA_TARGET_ID`, then create only
`PROFILE_TARGET`:

```bash
SENTRA_TARGET_ID='<Controller-issued-target-UUID>'
printf '{"target_id":"%s","job_type":"PROFILE_TARGET"}\n' \
  "$SENTRA_TARGET_ID" \
  > "$SENTRA_CONTROLLER_STATE/profile-target-job.json"

curl --fail-with-body --silent --show-error \
  --cacert "$SENTRA_PKI/controller-ca.pem" \
  --header @"$SENTRA_ADMIN_HEADER" \
  --header 'Content-Type: application/json' \
  --data-binary @"$SENTRA_CONTROLLER_STATE/profile-target-job.json" \
  "$SENTRA_CONTROLLER_ORIGIN/api/v1/admin/targets/$SENTRA_TARGET_ID/jobs"
```

### 4. Run the Agent again and verify non-secret lineage

Repeat the Agent command without `--bootstrap-credential-file`. It must reuse the
existing enrollment, heartbeat, poll its own job, execute the existing read-only M3
profiler, and submit one profile.

On the stopped Controller database or through a consistent read-only SQLite view,
inspect only non-secret lineage:

```bash
sqlite3 -readonly "$SENTRA_CONTROLLER_STATE/controller.sqlite3" \
  'SELECT job_id,target_id,assigned_agent_id,job_type,status,completed_at FROM jobs ORDER BY created_at; SELECT profile_id,target_id,agent_id,job_id,collected_at,received_at,profile_sha256 FROM profiles ORDER BY received_at;'
```

The expected result is one completed `PROFILE_TARGET` job and one profile with matching
target, Agent, and job identifiers plus the Controller-computed SHA-256. A later empty
cycle must reuse the same enrollment and must not create another target.

## Remaining limitations

- Real-lab evidence currently covers one MacBook Controller, one Ubuntu 24.04 LTS
  `aarch64` Agent, one development CA, and one `PROFILE_TARGET` workflow. It does not
  establish production or multi-environment readiness.
- Certificate issuance, distribution, rotation, revocation, and expiry operations are
  external responsibilities; the development CA used in this experiment is lab-only.
- Bootstrap and Agent credential rotation/revocation are not implemented.
- The transport has bounded bodies but no production rate limiting, concurrency
  control, or denial-of-service protection.
- Heartbeat replay protection, a general idempotency framework, and enrollment
  response-loss recovery are future work.
- Agent and Controller clock skew can affect evidence timestamps.
- The Agent credential is protected by a mode-`0600` local file rather than a
  keychain, TPM, or HSM.
- SQLite is PoC storage, not an encrypted or highly available production database.
- The Agent is a deterministic one-cycle command, not a daemon or service.
- M6B authenticates the submitting Agent and preserves lineage; it does not attest the
  underlying host or prove evidence freshness cryptographically.

## Exact M6C boundary

M6C should add a narrow Controller-side adapter that consumes the stored, validated
`TargetProfile`, invokes the existing non-mutating `src/compatibility_engine`, and
persists immutable:

```text
target_id -> profile_id -> compatibility_report_id
```

The record must retain the CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 identity and
version, generation time, and Controller-computed report SHA-256 while preserving M2
`needs_review` and M4 provisional semantics. M6C must add no Agent command,
remediation, deployment, M5 orchestration, or dashboard.
