# SENTRA M8 database foundation

This phase extends the existing Controller SQLite database. It adds no dashboard,
web login, demonstration targets, fabricated assessments, or deployment executor.
The Controller still owns enrollment, M3/M4 evidence, sandbox validation, and
fixed-control M7 enforcement. An M8 row cannot authorize M7 execution.

## One canonical file

Pass **the same absolute path** to the Controller and database CLI. The Controller
already requires `--database`; SENTRA has no hard-coded production database path.
The M8 CLI also requires `--database` and refuses the old independent `data/m8`
default. For example, if the Controller uses `data/controller/sentra.sqlite3`:

```bash
./.venv/bin/python -m src.m8db --database data/controller/sentra.sqlite3 init
./.venv/bin/python -m src.m8db --database data/controller/sentra.sqlite3 check
./.venv/bin/python -m src.m8db --database data/controller/sentra.sqlite3 migrations
```

Use the actual configured Controller path, not the example path. `init` creates the
existing M1–M7 Controller schema if the file is new, then applies additive M8
migrations. On a populated Controller file it preserves existing rows. It never
inserts targets, Agents, profiles, assessments, or users. The two static role names
(`admin`, `viewer`) are schema vocabulary, not accounts. Do not point `init` at a
production file without a consistent backup and a maintenance window.

An earlier, untracked `data/m8/sentra.sqlite3` scratch file is **not** the canonical
database and is left untouched. `data/m8/*` is ignored to prevent accidental commit.

## Existing authoritative tables reused

| Workflow entity | Existing Controller table |
|---|---|
| Targets / Agents | `targets`, `agents` |
| Historical M3 profiles | `profiles` (canonical payload and Controller SHA-256) |
| M4 reports | `compatibility_reports` (all ten control decisions in canonical payload) |
| M6/M6E sandbox sessions | `sandbox_sessions` |
| Validation jobs / results | `validation_jobs`, `validation_results`, `sandbox_validation_executions` |
| M7 target deployment job / result | `enforcement_jobs`, `enforcement_results` |
| Fresh M3 target verification | `jobs`, `profiles`, `post_enforcement_verifications` |

Other existing tables, including `metadata_changes`, remain unchanged. The M8
schema does **not** create `m8_targets`, `m8_agents`, `m8_profiles`, shadow M4/M6
results, or a second verification table.

## Added schema

Migration [`001_core.sql`](../src/m8db/sql/001_core.sql) adds:

- `m8_schema_migrations`: version, name, applied timestamp, SQL SHA-256.
- `m8_benchmarks`, `m8_controls`: versioned CIS identity and selected metadata;
  one active benchmark per platform, not one benchmark for all time. CIS-derived
  fields remain separate from SENTRA adapter/review metadata.
- `m8_users`, `m8_roles`, `m8_user_roles`: web login schema. The repository
  hashes new passwords with salted `scrypt`; plaintext is never persisted.
- `m8_assessments`, `m8_assessment_results`: historical run and per-control
  assertions linked by foreign keys to a real Controller target/profile and a
  selected benchmark control. No assessment is computed merely by DB insertion.
- `m8_assessment_report_links`: a foreign-key link to the actual M4 report. It
  does not copy or reinterpret M4 decisions. History reads the canonical M4
  report, retaining `no_known_conflict`, `warning`, `review_required`, and
  `insufficient_evidence` exactly; `no_known_conflict` is **not** a safety verdict.
- `m8_deployment_requests`, `m8_approvals`: pre-enforcement request and
  append-only user-decision history. An optional link points to an independently
  authorized M7 `enforcement_jobs` row. M7's distinct administrator approval,
  closed/validated M6 evidence gate, and execution path remain authoritative.
- `m8_evidence_records`, `m8_audit_events`: append-only references and audit
  history. Evidence records hold a source reference and SHA-256 where available,
  not arbitrary binary artifacts. Repository methods validate supported source
  IDs/target ownership and compare supplied hashes with authoritative hashes.

Four read-only views—`m8_compatibility_decisions`, `m8_validation_outcomes`,
`m8_deployments`, and `m8_verifications`—expose per-control M4 decisions and
M6/M7 states without duplicating their authoritative payloads. Deployment
states such as `applied`, `verified`, `rolled_back`, and `recovery_required` are
derived from the actual M7 result and fresh verification, not written by M8.

The schema uses primary/foreign/unique/CHECK constraints and indexes for target,
control, and time history. Assessment evidence references are constrained to
the same target and control. SQLite foreign keys are enabled on every managed
connection. Writes use bound parameters and transactions. Append-only triggers
reject ordinary SQL UPDATE/DELETE of evidence, approvals, assessment results,
report links, and audit events.

## Traceable lineage

`M8Repository.target_control_history(target_id, control_id)` reads the existing
and new tables as one chain:

```text
target → M3 profile → assessment/result → stored M4 report/decision
       → sandbox session → M6 validation evidence/hash
       → approval/request → M7 enforcement job/result/hash
       → fresh PROFILE_TARGET profile → post-enforcement verification
       → evidence references and audit events
```

Links use stored IDs and foreign keys, not timestamps or human descriptions.
Pre-M8 M7 enforcement jobs remain visible even if they have no M8 administrative
request row; no retrospective approval identity is invented.
The query returns facts and verdicts; it does not claim CIS compliance. The
existing M4 rule for control 7.1.1 legitimately returns `review_required` with
collected `/etc/passwd` facts. Tests preserve that result rather than forging a
`no_known_conflict` result for an illustrative example.

## Migration and integrity behavior

`init` applies numbered trusted SQL files in an explicit SQLite transaction and
inserts the matching migration row in that transaction. Re-running it is
idempotent. Changed checksums, unknown versions, partial schema conflicts, or
schema/trigger drift fail closed. Connections close deterministically.
`check` is read-only: it does not create a database and reports SQLite
`integrity_check`, `foreign_key_check`, migrations, tables, and required triggers.
Controller file ownership/mode remain current-user/0600 as enforced by the
existing repository; symlink/non-directory parent checks remain in force on
managed writes.

Before upgrading a populated file, stop the Controller and use SQLite's online
backup API or a consistent copy that includes WAL state. Preserve the backup
outside Git with mode 0600. Never copy only the main `.sqlite3` file while its
WAL has uncheckpointed transactions. Test restore and run `check` before service
restart. This migration does not delete legacy data.

## Current boundaries

This document describes the database foundation; the additive
[M8 web interface](M8_WEB.md) now provides login and bounded history pages.
Neither layer implements a CIS PASS/FAIL evaluator, automatic benchmark importer,
or an alternate target execution path. Existing M7 jobs can predate M8 users;
their historical administrator acknowledgement cannot be retroactively assigned
to a named M8 user. M8 audit-event storage is available and append-only, but
historical M1–M7 operations are not backfilled or automatically claimed as
user-attributed M8 events. The M8 web request/decision methods append user
events in their M8 transaction; future Controller API integration must append
events at the actual service boundary and retain the existing M7 approval gate.
SQLite remains a PoC backend; local file replacement or a privileged DBA can
defeat in-database append-only triggers, so backups and host permissions matter.
