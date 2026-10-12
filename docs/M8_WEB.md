# SENTRA M8 product interface

M8 is a server-rendered Flask/Jinja research interface over the **same canonical
Controller SQLite database** used by M1–M7. It adds no target, Agent, M3 profile,
M4 report, M6 validation, M7 outcome, or fresh-verification shadow table. See
[M8_DATABASE.md](M8_DATABASE.md) for schema and migration details.

## Trust boundary

The web process reads bounded identifiers, states, timestamps and authoritative
hashes from existing Controller tables and M8 views. It does not expose raw Agent
credentials, Controller secrets or arbitrary evidence payloads. It does not run
shell commands, connect to targets, manufacture evidence or write M7 enforcement
rows. There is no generic mutation API. The public `/health` and `/api/status`
retain their existing bounded health/count contracts; operational pages require
login. M1–M7 remain the sources of truth.

The pages distinguish M8 assessment assertions, M4 compatibility decisions, M6
sandbox validation, M7 enforcement outcomes and fresh M3 post-enforcement
verification. `no_known_conflict` is **not** safe or compliant; a sandbox
`validated` result is **not** target compliance. No percentage is shown because
the current stored selected-control assessment coverage does not support a
defensible evidence-backed score. The interface shows counts and unknown states.

## Authentication and roles

`m8_users` stores salted `scrypt` password hashes. Login uses constant-time hash
comparison and a generic failure message. The signed Flask session contains only
the user ID and a random CSRF token; active state and roles are re-read on each
request. Login clears the pre-login session; successful logout appends a
non-secret user audit event before the session is cleared. Cookies
are HttpOnly, SameSite=Lax and Secure by default. The key is never passed as a
CLI argument: normal web startup requires a protected, current-user-owned,
mode-0600 file containing 32–256 random bytes. A development-only flag permits
non-Secure cookies on a loopback HTTP listener; it is rejected on non-loopback
listeners. The development CLI itself refuses non-loopback listeners. Keep the
secret file outside the repository and Git. Production
deployment requires HTTPS and a production WSGI/server
configuration, not Flask's built-in development server.

`viewer` can read pages. `admin` can import the one supported benchmark,
select controls, initiate bounded Controller operations, submit a narrowly
scoped M8 deployment request, and record an approval or rejection. Every state-changing web form is
POST-only, authenticated, role-checked and CSRF-checked. Extra form fields are
rejected. Meaningful successful user actions are appended to the existing M8
audit table in the same transaction as the M8 change; successful logout is
audited before session clearing. The Audit page combines that append-only
user-action source with read-only, bounded projections of authoritative
Controller/Agent operational records. No earlier M7 operator identity is
invented or backfilled.

## Routes

| Route | Purpose |
|---|---|
| `/login`, `/logout` | Session sign-in and POST-only sign-out |
| `/` | Live workflow counts and real recent activity |
| `/runs` | Guided hardening run, projected from authoritative rows; no shadow state machine |
| `/benchmarks` | Supported-PDF import status and active benchmark selection |
| `/targets`, `/targets/<id>` | Enrollment metadata, historical M3 profiles and target history |
| `/targets/<id>/controls/<control>` | Profile → assessment → M4 → M6 → M7 → fresh verification lineage |
| `/controls` | Selected catalogue and explicitly recorded assessments/results |
| `/compatibility` | Provisional M4 decisions and authoritative report hashes |
| `/sandboxes` | Session creation/closure, current/final state, M5/M6 result and hash, failure/quarantine reasons |
| `/deployments` | M8 requests/reviewer username, ID and reason plus authoritative M7 outcomes |
| `/evidence`, `/audit` | M8 evidence references; unified read-only operational timeline including append-only M8 user actions |
| `/health`, `/api/status` | Existing bounded public health/status endpoints |

The wizard uses the existing Controller `PROFILE_TARGET` and M4 analysis
operations. Its M6 create/provision/validate/close calls remain in the running
Controller: the new fixed validation route derives the context from validated
Controller-stored M3/M4 lineage and calls the existing full M6 transaction with
the Controller's configured provider. The new M7 route calls the existing
`ControllerService.create_enforcement_job` gate. The web process has no
libvirt provider and never writes authoritative M3–M7 workflow tables.

M1 PDF import first checks a bounded readable PDF for independent cover/version/
date and target-technology text markers, then records its SHA-256. This is a
supported-scope text check, **not publisher authentication**. The upload's
filename is ignored; M1 conversion occurs in an isolated temporary directory.
Only the ten existing M2-selected control IDs and their non-command metadata
are imported atomically. Raw CIS Audit and Remediation text is neither executed
nor copied into M8. Selected controls may be changed on the Controls page, but
the existing M4 engine still evaluates its fixed ten-control PoC scope.

The M8 assessment group created after a fresh M3 profile and M4 report records
selected controls as `not_tested`, because M4 compatibility is not a CIS audit.
M7 Agent execution and fresh post-enforcement profiling remain asynchronous;
the wizard reads their authoritative outcomes rather than synthesizing a result.

Lists are bounded and do not expose raw profile JSON, M6 payloads or password
hashes. Empty pages show explicit empty states rather than fake data. Older M7
jobs without an M8 request remain visible as historical operational facts.

## Deployment workflow and approval boundary

An admin may create a request only for selected control `7.1.1` when an M8
assessment result is linked to the exact M4 report/profile and a closed sandbox
has validated M6 `EXECUTE` evidence. The repository revalidates that lineage;
the UI's eligible list is a convenience, not an authorization source. An admin
decision records a historical M8 approval/rejection and the reviewed M6 evidence
fingerprint. The approved request then remains **awaiting a separate explicit
Start Controlled Deployment action**. That action sends the exact reviewed
lineage and a new administrator acknowledgement to the authenticated Controller
M7 route. It does not write `enforcement_jobs` directly. The Controller's M7
service independently rechecks closed validated evidence. Rejection blocks the
action; an approved request alone creates zero jobs. Agent execution and fresh
`PROFILE_TARGET` verification remain entirely within M7.

## Local development smoke test

Use the actual existing Controller database path. Stop writers and make a
consistent backup before applying migrations to a populated file. No command
below creates demonstration records.

```bash
./.venv/bin/python -m src.m8db --database /absolute/path/controller.sqlite3 init
./.venv/bin/python -m src.m8db --database /absolute/path/controller.sqlite3 check
umask 077
openssl rand -out /absolute/protected/path/m8-web.secret 32
./.venv/bin/python -m src.m8web.users --database /absolute/path/controller.sqlite3 create-admin --username sentra-admin
./.venv/bin/python -m src.m8web --database /absolute/path/controller.sqlite3 --secret-key-file /absolute/protected/path/m8-web.secret --listen-host 127.0.0.1 --listen-port 8080 --insecure-cookie-for-local-http
```

For operational buttons, additionally configure `--controller-url
https://controller.example:8443`, `--controller-ca-file /absolute/protected/ca.pem`
and `--controller-admin-credential-file /absolute/protected/controller-admin.secret`.
These three settings are all-or-none. The admin credential stays server-side in
a current-user-owned mode-0600 file under trusted ancestry; the client enforces
CA-backed certificate and hostname verification and refuses redirects. Without
this configuration, evidence pages remain readable but Controller actions fail
closed. The Agent's existing `src.agent` CLI performs enrollment from the host;
the browser never receives a bootstrap credential or installs software remotely.

The admin creation command requires an absolute path to an existing, regular,
healthy M8 Controller database before it prompts for a password. It never
accepts the password on the command line. For an HTTPS deployment, omit
`--insecure-cookie-for-local-http` so the Secure cookie stays enabled. Browse
`http://127.0.0.1:8080/login` only for the loopback development command.

## PoC limitations

SQLite remains a single-host research backend. There is no MFA, login rate
limiting, distributed session store, production TLS/proxy/certificate lifecycle,
automatic host onboarding, automatic M7 execution, or full M1–M7 audit backfill.
Benchmark validation checks text identity and hash, not a publisher signature.
M1 conversion is synchronous and limited to the selected ten-control research
scope. Historical operational events are projected on read
from their source rows, with Controller/Agent actor labels rather than invented
usernames. The M8 user-action audit is append-only under normal application
operations but a privileged database administrator can alter the file. The web
UI displays at most bounded recent rows; it is not an export or legal audit
archive. Approval in M8 is not target deployment authorization, and neither M4
nor M6 establishes CIS compliance.
