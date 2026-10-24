# SENTRA M6C Controller-side compatibility architecture

## Status and scope

M6C is implemented, automated-test validated, and validated in one real stored-profile
lab workflow. It takes a validated M3 `TargetProfile` already stored by the Controller,
runs the existing non-mutating M4 compatibility engine centrally, validates and
canonicalizes the resulting `CompatibilityReport`, computes the authoritative report
SHA-256, and persists the report for authenticated administrative listing and
retrieval.

M6C is not production-ready and does not complete all of M6. It adds no Agent protocol
operation, target connection, SSH, arbitrary shell, command or argv execution,
remediation, deployment, M5 orchestration, or user interface.

## Controller-side architecture

The authoritative evidence lineage is:

```text
target_id -> profile_id -> compatibility_report_id
```

The implemented flow is:

```text
Controller SQLite profiles row
        │
        ├── revalidate strict TargetProfile payload
        ├── reproduce canonical profile JSON
        ├── verify Controller-computed profile_sha256
        └── verify target_id/profile_id ownership
        │
        ▼
existing src/compatibility_engine
        │
        ├── existing ten-control M2/M3 input checks
        ├── existing M4 rules and decision precedence
        └── no target-side operation or CIS text execution
        │
        ▼
strict CompatibilityReport validation
        │
        ├── canonical JSON serialization
        ├── Controller-computed report_sha256
        └── generated_at + report_version + benchmark identity
        │
        ▼
persisted compatibility_reports row
```

The narrow in-memory M4 input builder is the only M4 integration addition. The M4
engine and rules are not duplicated or reinterpreted. The four compatibility states
remain exactly:

- `no_known_conflict`
- `warning`
- `review_required`
- `insufficient_evidence`

`no_known_conflict` is never translated into `safe`, `pass`, or a CIS-compliance
verdict. M3 evidence states remain distinct as `collected`, `unavailable`,
`unsupported`, and `error`. With the current M2 enrichments, the report retains
`metadata_review_status=needs_review` and `provisional=true`.

## Administrative HTTPS API

M6C exposes only authenticated Controller administration routes:

```text
POST /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports
GET  /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports
GET  /api/v1/admin/targets/{target_id}/profiles/{profile_id}/compatibility-reports/{compatibility_report_id}
```

The `POST` body repeats `target_id` and `profile_id`; the transport/API requires them to
match the path. The service authenticates the administrator and rechecks stored-profile
ownership before analysis. The request cannot supply a report, hash, command, script,
or raw CIS Audit/Remediation content. No corresponding Agent route exists.

The collection `GET` lists reports for the exact target/profile pair. The item `GET`
requires the full target/profile/report lineage. Stored payloads and source profiles are
revalidated during retrieval so a report cannot be rebound to another target or
profile without detection.

## Persistence and migration behavior

Each `compatibility_reports` row stores:

- `compatibility_report_id`
- `target_id`
- `profile_id`
- `benchmark_identity`
- `benchmark_version`
- `generated_at`
- `report_version`
- `report_sha256`
- `payload_json`

SQLite foreign keys include the composite target/profile relationship. Repository
checks independently re-bind the report payload to its source profile, including the
profile source label, collection time, target metadata, and report generation time.
The canonical report JSON stored in `payload_json` is the exact payload covered by
`report_sha256`.

The M6A/M6B database contained an unused metadata-only compatibility-lineage
placeholder. An empty legacy placeholder table is replaced by the full M6C schema. A
non-empty legacy placeholder fails closed because M6C cannot truthfully invent the
missing report payload. The current schema is accepted only when its full constraint
definition matches the expected M6C schema.

## Real-lab validation record

This record separates three evidence sources:

- **Automated regression evidence:** repeatable tests established model, semantic,
  authentication, canonical-hash, ownership, retrieval, and migration behavior before
  the lab run.
- **SENTRA-generated runtime evidence:** the M6C `POST` response and persisted
  `CompatibilityReport` contain the report lineage, M4 results, metadata, and
  Controller-computed SHA-256.
- **Operator-observed lab evidence:** HTTPS certificate verification, administrative
  API behavior, repeated retrieval, SQLite columns, and the final SQL lineage join were
  observed in the controlled lab.

None of these sources is a production certification, a universal Ubuntu result, or a
CIS compliance verdict.

### Lab environment and input lineage

M6C used a protected copy of the completed M6B Controller database named
`controller-m6c-lab.sqlite3`. The stored input profile had originally been collected
from the real Ubuntu 24.04 VM during the M6B Mac-to-Ubuntu HTTPS validation.

| Item | Recorded observation |
|---|---|
| Controller host | Mac |
| Controller address used for M6C | `30.30.30.236` |
| TLS trust | Same lab-only SENTRA Development CA used for M6B |
| Controller certificate | Reissued with SAN `IP:30.30.30.236` |
| TLS verification | Succeeded; no insecure mode or verification bypass used |
| Source `target_id` | `d16ab6b4-45ff-4031-8223-1c90e27c22ec` |
| Source `profile_id` | `949f950f-747c-4711-9684-95b186899013` |

The address and identifiers are observations from this lab, not product defaults or
reusable credentials.

### Validated sequence

1. The protected M6B database copy was opened through the M6C-capable Controller.
2. The Controller started on the Mac over HTTPS with the reissued, CA-signed
   certificate containing `IP:30.30.30.236`.
3. An authenticated administrator submitted the stored target/profile pair to the M6C
   `POST` route.
4. The Controller revalidated the stored profile and its authoritative profile hash.
5. The existing M4 engine evaluated the ten PoC controls without contacting or
   changing the Ubuntu VM.
6. The Controller validated and canonicalized the M4 report, computed its SHA-256, and
   inserted the report with target/profile/report lineage.
7. The collection `GET` returned the stored report.
8. The single-report `GET` returned the same report.
9. The report ID and SHA-256 were identical across the `POST`, list, and item results.
10. Read-only SQLite inspection confirmed the expected columns and a matching
    target/profile lineage join.

### Generated compatibility report

| Field | Value |
|---|---|
| `compatibility_report_id` | `8d6136f4-621c-410b-b3c4-d87ce2220268` |
| `target_id` | `d16ab6b4-45ff-4031-8223-1c90e27c22ec` |
| `profile_id` | `949f950f-747c-4711-9684-95b186899013` |
| `benchmark_identity` | `CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0` |
| `benchmark_version` | `v1.0.0` |
| `report_version` | `1` |
| `report_sha256` | `240db166b07da3056babd76e7754fe7ac257043a4c4efa184a3210f29796ff84` |

The stored M4 summary was:

| Result | Count |
|---|---:|
| `controls_evaluated` | 10 |
| `no_known_conflict` | 3 |
| `review_required` | 4 |
| `warning` | 1 |
| `insufficient_evidence` | 2 |
| `provisional` | 10 |

### Semantic observations

- All ten results retained `metadata_review_status=needs_review` and
  `provisional=true`.
- `no_known_conflict` remained explicitly limited to the current evidence and rules;
  it was not presented as safety or CIS compliance.
- M3 `unavailable` and `unsupported` evidence remained explicit rather than being
  coerced to `false` or an invented value.
- UFW control `4.2.3` produced `warning` because an active remote/SSH context existed
  while some UFW evidence remained unavailable.
- The SSH controls retained `insufficient_evidence` where effective configuration
  could not be read.
- Compatibility analysis did not convert observed configuration into CIS `PASS` or
  `FAIL`.

### SQLite lineage verification

The final SQL lineage join reported:

```text
report target_id:  d16ab6b4-45ff-4031-8223-1c90e27c22ec
profile target_id: d16ab6b4-45ff-4031-8223-1c90e27c22ec
lineage_check:     MATCH
```

This is operator-observed confirmation for this database copy. The storage schema and
automated ownership tests provide the repeatable enforcement evidence.

## Automated validation recorded before the lab

| Suite/check | Result |
|---|---:|
| Focused M6/M4 tests | 123 passed |
| Full test suite | 412 passed, 0 failures |
| Existing warnings | 5 PyMuPDF/SWIG warnings |
| `git diff --check` | Clean |
| Agent implementation changes | None |

## Preserved security boundary

- M6C remained entirely Controller-side; the Agent protocol and Agent implementation
  were unchanged.
- The Controller did not connect to the Ubuntu target or use SSH.
- No arbitrary command, shell, argv, script, or generic execution facility was added.
- M4 remained read-only and retained its existing rules and decision semantics.
- No remediation, M5 execution, deployment, approval workflow, or UI was added.
- Raw CIS Audit and Remediation text remained inert data and was not executed.

## Remaining limitations

- SQLite remains a PoC storage backend rather than an encrypted, highly available, or
  production-concurrency database.
- The Development CA is lab-only. Production certificate issuance, distribution,
  renewal, revocation, expiry handling, and trust-store lifecycle are not implemented.
- Bootstrap, Agent, and administrator credential rotation/revocation remain future
  work.
- Replay protection, a general idempotency framework, rate limiting, denial-of-service
  controls, and a production concurrency model remain future work.
- Scope remains Ubuntu 24.04, CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0, and the ten
  current PoC controls.
- M2 enrichment remains `needs_review`, so the current M4 outputs remain provisional.
- The Controller does not yet orchestrate M5, remediation, deployment, or
  post-deployment verification.
- No dashboard or other user interface exists.
- The real-lab record covers one protected database copy, one stored target profile,
  one Mac Controller endpoint, and one lab-only certificate chain; it does not establish
  production or multi-environment readiness.
