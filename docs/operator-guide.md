# Alpha Data operator guide

## Purpose and authority

The repository [`README.md`](../README.md) is the primary self-contained,
zero-knowledge entry point for a new Alpha Data teammate or mentor. This file is
the detailed specialist operational runbook for setup, startup, login, Prefect
verification, authorized activation-if-new, shutdown, restart, and exceptional
troubleshooting. Its extra procedure detail supplements the README; it does not
replace the README's release and handover status.

This guide is for an approved mentor, staging operator, or junior analyst
administrator. It covers safe operation of the current local release package.
It does not authorize public deployment, destructive recovery, arbitrary
external requests, or access outside the assigned environment. The recurring
Alpha Data deployment was explicitly approved and activated on 11 August 2026;
the one-time activation procedure below is only for an authorized operator
recreating that same fixed deployment after its Prefect state has been lost.

The detailed production procedure remains [`production-docker-deployment.md`](production-docker-deployment.md); recovery safety gates remain [`c09-recovery-runbook.md`](c09-recovery-runbook.md). When this summary and a task-specific approved change record differ, stop and obtain direction.

## Before every operation

Confirm:

1. the approved task/change reference and named environment;
2. exact repository checkpoint and immutable image/config pair;
3. Docker project and Compose/environment file paths;
4. secrets are protected files outside Git and terminal capture;
5. any activation action is the exact approved fixed-deployment procedure below;
6. backup evidence and rollback owner exist for a staging change;
7. the action is non-destructive, or explicit destructive approval exists.

Never paste a password, database URL, API key, cookie, CSRF token, authorization header, age identity, or secret file content into a command, screenshot, ticket, report, or chat.

## Safe PowerShell placeholders

Define non-secret file references for the approved host. Do not use the committed example as a real deployment environment.

```powershell
$ComposeFile = "C:\approved\alpha-data\compose.prod.yml"
$ProdEnv = "C:\approved-protected-config\alpha-data-staging.env"
```

The environment file and secret files must be outside the repository, access-restricted, and populated by the approved secret owner. Do not print `docker compose config`; use `config --quiet`.

## New-operator quick start

1. Start Docker Desktop and wait for the Docker daemon to be ready.
2. Open PowerShell in the repository root.
3. Run `.\run.cmd` and wait for its bounded health checks to finish.
4. Open `http://localhost:3000/` in a browser.
5. Sign in with an authorized account. There is no shipped username or
   password.
6. Open `http://localhost:4200/` only when Prefect operational status is needed.
7. For a brand-new Prefect deployment, confirm that it is paused and use the
   authorized one-time activation procedure in this guide before recurring live
   collection is intended.
8. On later starts, no reactivation is needed when the existing Prefect state
   was preserved and is already active.
9. Stop the local stack with `docker compose down`.
10. Never use `docker compose down -v` unless the explicit goal is to destroy
    the persisted application and Prefect data.

Closing the frontend browser does not stop the backend, Prefect, its worker, or
scheduled ingestion. The local PC, Docker, Prefect server, and worker must stay
running for the two-hour schedule to execute.

## Local mentor or teammate handover

### 1. Prerequisites

This local workflow is separate from the protected production procedure below.
Clone or open the repository, then use Windows PowerShell or Command Prompt with
Git and Docker Desktop/Compose v2. The normal container workflow does not
require a separate host Python or Node installation. Host Python 3.13, Node.js,
and npm are needed for `.\run.cmd install` and `.\run.cmd dev`. Keep ports
`3000`, `8000`, `4200`, and `5432` available on loopback. Work from a verified
`main` checkout, the authoritative mentor/operator branch, and do not use
production data or credentials locally.

### 2. Environment configuration

`.env.example` is the authoritative local template. When root `.env` is absent,
the runner creates it with three independently generated database secrets and
does not display them. Existing `.env`, `backend/.env`, and
`frontend/.env.local` files are never overwritten. `.env.production.example`
is a protected-environment reference and is not copied by ordinary local setup.
See [environment and secrets](environment-and-secrets.md) for the three
configuration groups and complete variable reference.

Real `.env` files are ignored because they can contain secrets. Never commit,
share, screenshot, paste into documentation, or include them in a handover ZIP.
The runner does not overwrite an existing real `.env`.

### 3. First run

Start Docker Desktop and run from the verified repository root:

```powershell
.\run.cmd
```

The command validates PowerShell, Docker/Compose, the Docker daemon, local
configuration field names, cached image builds, both PostgreSQL services,
Alembic integrity/current head, application reference state, backend
`/api/health`, frontend availability, and Prefect server/worker/pool/queue and
deployment integrity. When root `.env` is absent, its structure comes from the
local template but the three database credentials are generated independently
with cryptographic randomness and never displayed. Existing environment files
are preserved; missing fields and exact committed placeholders block by
variable name rather than being silently replaced. A genuinely fresh, empty
database is migrated to the current Alembic head, the approved source catalog
is reconciled, and an offline bundled snapshot of exactly 112 real public
intelligence records is loaded: 100 NVD vulnerabilities and 4 publications
each from CERT-EU Security Advisories, Google Threat Intelligence public
research, and Mandiant public threat research. This bootstrap makes no live
external intelligence requests and fabricates no ingestion execution history
or checkpoint state: it creates 0 `IngestionCycle` rows, 0 `IngestionRun` rows,
no source checkpoints or watermarks, and advances no checkpoints. It also
creates no default application user. On subsequent startups, the snapshot is
not imported again once intelligence exists; existing intelligence is preserved
and normal ingestion later deduplicates or updates these records through its
usual persistence paths.

The same command builds and starts the required containers, checks and
forward-migrates the application database, reconciles required reference and
least-privilege state, registers or verifies Prefect, starts the backend and
frontend, and performs bounded health checks. It does **not** launch a manual
intelligence flow. A newly created Prefect deployment starts **PAUSED** on
purpose so that a fresh environment cannot begin external requests without an
authorized one-time decision.

### 4. Existing clone

Use the same `.\run.cmd` command. An existing database is reused and
forward-migrated only when necessary; users, articles,
vulnerabilities, operational history, checkpoints, Prefect metadata, and named
volumes are preserved. Never use a reset to resolve a blocked integrity check.
Current local verification preserved the existing intelligence while the
runtime and authentication path were validated.

### 5. Application URLs

Local PostgreSQL, backend, frontend, and Prefect UI ports are explicitly bound
to `127.0.0.1`.

| URL | Purpose |
| --- | --- |
| `http://localhost:3000/` | Frontend dashboard and sign-in page. |
| `http://localhost:8000/api/health` | Sanitized backend health check; expect HTTP 200 when healthy. |
| `http://localhost:4200/` | Loopback-only Prefect UI for deployment, worker, queue, and scheduled-run status. |

### 6. First administrator and user setup

The runner creates no account or default password, and there is no public
self-registration. Passwords are represented by one-way Argon2id hashes and
cannot be recovered from the database. Existing users persist with the
application database volume.

On a fresh empty installation, an approved administrator must use the reviewed
bootstrap-admin CLI once, from `backend`, only while the user table is empty:

```powershell
.\.venv\Scripts\python.exe -m app.security.bootstrap_admin_cli `
    --username <approved-local-username> `
    --display-name <approved-display-name>
```

The CLI prompts for the password without accepting it on the command line. Then
create additional unique accounts through the authenticated **User Access**
workflow. Never record or share passwords. Role details and account lifecycle
rules are in
[Login and account roles](#login-and-account-roles).

### 7. Development hot reload

For backend Uvicorn reload and frontend Next.js HMR, install host dependencies
once with `.\run.cmd install`, then use:

```powershell
.\run.cmd dev
```

PostgreSQL and Prefect infrastructure remain in Docker while the host backend
and frontend reload during active development. Dependency or Dockerfile changes
may require rerunning installation or the cached build. Prefer ordinary
`.\run.cmd` for final and release verification because it validates the
containerized handover path.

### 8. Normal daily start and current Prefect state

For every normal daily start, run:

```powershell
.\run.cmd
```

The runner preserves an existing deployment's activation state. Therefore the
currently verified **ACTIVE** deployment needs no separate activation command.
Closing the browser does not stop ingestion; stopping Docker, Prefect, or the
worker does.

The registered deployment is
`alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle`, using the
`alpha-data-process` pool, `/opt/alpha-data/backend` working directory,
`17 */2 * * *` cron, and `Asia/Dubai` timezone. The runner verifies exactly the
six approved scheduled bindings. It creates a missing deployment **PAUSED** and
preserves an existing paused or active state during code/configuration updates.
It does not run a parent flow or contact a live source.

The release deployment was explicitly approved and activated on 11 August
2026. Its current verified identity and state are:

| Field | Verified value |
| --- | --- |
| Deployment | `alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle` |
| Deployment ID | `8e584852-6ffc-4806-9cc9-22b758767bf3` |
| Activation/status | `paused=False`; `READY` |
| Schedule | `17 */2 * * *`; `Asia/Dubai`; active |
| Working directory | `/opt/alpha-data/backend` |
| Work pool / queue | `alpha-data-process` / `default`; pool `READY` |
| Concurrency | `1`; collision strategy `CANCEL_NEW` |

Activation did not use, create, or require a manual Prefect flow run.

### 9. How the two-hour cycle works

Cron `17 */2 * * *` in `Asia/Dubai` means the parent ingestion cycle is
scheduled every two hours at minute 17. It can run only while the required
Prefect server and process worker are running. The frontend browser and backend
web page do not need to remain open, but the PC, Docker daemon, Prefect server,
and worker must remain running in this local setup. Continuous 24/7 collection
requires an always-on staging host; no mentor-accessible external staging host
has been demonstrated yet.

The recurring cycle contains exactly these six reviewed handlers:

- `nvd`
- `first-epss`
- `cisa-kev`
- `cert-eu-security-advisories`
- `google-threat-intelligence-public-research`
- `mandiant-public-threat-research`

Approval-gated, commercial, UAE/DESC, disabled, manual-only, and all other
sources are not in the recurring schedule.

### 10. Prefect activation and restart cases

#### Case A - existing deployment already ACTIVE

Run `.\run.cmd`. No external activation command is required. The runner
preserves the existing active state and verifies its fixed configuration.

#### Case B - fresh or newly recreated Prefect deployment

Run `.\run.cmd`. The deployment is deliberately created **PAUSED**. There is
no dedicated `activate-prefect.ps1` in this project. An authorized operator may
activate only the fixed Alpha Data deployment using the pinned Prefect CLI
inside the worker container:

```powershell
docker compose exec -T prefect-worker python -m app.orchestration.deployments --verify-registration
docker compose exec -T prefect-worker prefect deployment inspect alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle
docker compose exec -T prefect-worker prefect deployment schedule resume alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle --all
docker compose exec -T prefect-worker prefect deployment inspect alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle
docker compose exec -T prefect-worker prefect deployment schedule ls alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle
```

Before the resume command, require the verification command to pass and inspect
the exact fixed name, `alpha-data-process` pool, `default` queue,
`/opt/alpha-data/backend` working directory, one `17 */2 * * *` `Asia/Dubai`
schedule, concurrency `1`, and `CANCEL_NEW`. For the preserved current
installation, also require deployment ID
`8e584852-6ffc-4806-9cc9-22b758767bf3`; a genuinely rebuilt Prefect metadata
database creates a new ID, which must be recorded in the change evidence after
all other fixed identity checks pass.

The resume command targets only the named Alpha Data deployment and resumes its
single already-verified schedule. It does not use `prefect deployment run` and
does not launch a manual flow. It enables future scheduled external requests to
the six handlers listed above. Afterward, require the deployment inspection to
show `paused: False`, `status: READY`, and the schedule listing to show
`Active: True`.

#### Case C - restart after `docker compose down`

When `prefect_postgres_data`, `prefect_data`, and the other named volumes remain,
run `.\run.cmd`. The existing ACTIVE state should be preserved and no
reactivation is needed.

#### Case D - Prefect database or volumes destroyed/recreated

Treat the deployment as new: run `.\run.cmd`, confirm the recreated deployment
is PAUSED, and complete the authorized Case B identity checks and activation
again.

### 11. Read-only Prefect status verification

These commands do not start a flow:

```powershell
docker compose ps prefect-server prefect-worker
docker compose exec -T prefect-worker python -m app.orchestration.deployments --verify-registration
docker compose exec -T prefect-worker prefect deployment inspect alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle
docker compose exec -T prefect-worker prefect deployment schedule ls alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle
docker compose exec -T prefect-worker prefect work-pool inspect alpha-data-process
docker compose exec -T prefect-worker prefect work-queue ls --pool alpha-data-process
docker compose exec -T prefect-worker prefect work-pool preview alpha-data-process --hours 6
```

Together they confirm container health, the exact deployment and six bindings,
paused/active state, schedule and timezone, working directory, work pool/queue,
online worker validation, and upcoming scheduled work without inspecting
database internals.

### 12. Scheduled versus manual ingestion

Recurring ingestion is created by the active two-hour Prefect schedule. A
manual flow run is a separate explicit operator action. Activation only resumes
future scheduled execution; it does not launch a manual run. Do not run
`prefect deployment run` merely to test activation, and do not encourage
unnecessary live-source executions. Manual source commands documented elsewhere
remain separate, bounded, approval-controlled workflows.

### 13. Troubleshooting

- **Docker is not running:** start Docker Desktop/the Docker daemon, wait until
  it is ready, and rerun `.\run.cmd`.
- **Frontend is unreachable:** run `docker compose ps`, then check
  `http://localhost:3000/`. Inspect only bounded frontend logs if needed.
- **Backend is unhealthy:** check `http://localhost:8000/api/health`, then use
  `docker compose logs --tail 100 backend`. Do not expose a stack trace.
- **Prefect cycle is not running:** inspect the deployment and require ACTIVE,
  confirm the Prefect server and worker are running, confirm the pool/queue is
  READY, preview upcoming work, and inspect `http://localhost:4200/`.
- **Login problems:** do not reset the database or password automatically.
  Confirm account status through the supported Administrator **User Access**
  workflow and use only sanitized bounded logs. Never expose password hashes or
  secrets. Successful authentication was verified after the release corrected
  PostgreSQL authentication row-lock scope; identity immutability and least
  privilege remain preserved.
- **Port conflict:** identify the local process using `3000`, `8000`, `4200`, or
  `5432`. Do not casually widen public bindings or weaken security defaults.

On any failure, do not print `docker compose config`, environment files, or
container environment/inspect output.

The runner generates only the three application-database secrets. Prefect
metadata credentials retain their internal-only local compatibility defaults:
changing only `.env` after `prefect_postgres_data` initialization would not
rotate the stored roles and could strand a preserved volume. Operators who
manage unique Prefect metadata credentials must set them before first
initialization; production uses the separately reviewed secret-file boundary.

### 14. Safe shutdown and restart

For the normal local stack, use:

```powershell
docker compose down
```

This stops the stack and removes its containers/networks while preserving named
volumes, users, intelligence, history, and Prefect metadata. No scheduled
ingestion can run while the Prefect server/worker are stopped. Rerun
`.\run.cmd` to start and re-verify it.

> **DATA-DESTRUCTION WARNING:** Do **not** use `docker compose down -v` unless
> the explicit approved goal is to destroy all local persisted application and
> Prefect data. Migrations are forward-only; deleting volumes is not a rollback
> or password-reset procedure.

For `.\run.cmd dev`, press Ctrl+C to stop the host backend/frontend, then run
`docker compose down` to stop the Docker infrastructure.

## Current release status and handover checklist

The local runtime and login are validated. The recurring Prefect deployment is
ACTIVE with the exact six reviewed handlers and current schedule described
above. Docker and Prefect must remain running locally for collection. An
always-on, mentor-accessible external staging environment still depends on
external infrastructure being provided and validated; this guide does not
claim that it exists.

Before handover, confirm:

- [ ] Docker is available and the daemon is running.
- [ ] An ignored `.env` is present but is not shared.
- [ ] `.\run.cmd` succeeds.
- [ ] `http://localhost:8000/api/health` returns HTTP 200.
- [ ] `http://localhost:3000/` is reachable.
- [ ] An authorized account can sign in.
- [ ] The Prefect worker/pool/queue are healthy.
- [ ] The deployment is ACTIVE when recurring collection is intended.
- [ ] Exactly the six approved handlers are bound.
- [ ] Cron is `17 */2 * * *` in `Asia/Dubai`.
- [ ] Existing users, intelligence, history, and named-volume data are preserved.
- [ ] No real secret appears in handover material, screenshots, or Git.

## Production-oriented startup

From the verified repository root:

```powershell
git status --short
git rev-parse HEAD
docker version
docker compose version
docker compose -f $ComposeFile --env-file $ProdEnv config --quiet
docker compose -f $ComposeFile --env-file $ProdEnv up -d db
docker compose -f $ComposeFile --env-file $ProdEnv --profile migration run --rm migrate
docker compose -f $ComposeFile --env-file $ProdEnv up -d
docker compose -f $ComposeFile --env-file $ProdEnv ps
```

Expected: the migration job completes successfully and the eight long-running services become healthy. A failed migration, missing secret, invalid commit identity, unhealthy service, or unexpected public port means **failed deployment**, not partial success. Follow the recovery runbook; do not improvise a downgrade.

Historical checkpoint evidence: production deployment registration was explicit
and paused by default at C11, which had zero production source handlers.
SIX-BIND-01 later code-bound exactly six reviewed scheduled handlers without
activating them. This historical production-oriented checkpoint does not
describe the current verified local deployment, which is ACTIVE. Do not add
activation flags to ordinary production startup.

For the corrected local-development workflow, `.\run.cmd` starts `prefect-db`,
`prefect-server`, and `prefect-worker` together and registers the deployment
without requesting an activation change. A missing deployment starts paused;
an existing paused or active state is preserved. The UI remains loopback-only
at `http://127.0.0.1:4200`; the local metadata database has no host port. The
worker recreates `alpha-data-process` idempotently. The old SQLite file in
`prefect_data` is retained and is not migrated or deleted.

## Shutdown

Routine stop preserves named volumes:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv stop
```

Removing containers/networks while preserving named volumes:

```powershell
docker compose -f $ComposeFile --env-file $ProdEnv down
```

Do **not** add `-v`. `down -v` deletes persistent database/state volumes and requires exact-target verification, a verified recoverable backup, an incident/change owner, and explicit destructive approval.

## Health verification

1. Run `docker compose ... ps` and require healthy states.
2. Use the approved Caddy HTTPS authority. Do not expose backend, PostgreSQL, Prefect, Prometheus, Alertmanager, or worker-health ports publicly.
3. Confirm the public HTTP endpoint redirects to the exact HTTPS authority.
4. Confirm unknown Host/SNI and `/internal/*` paths are rejected.
5. Sign in and open **System Health**. Verify eight components and the expected version/commit.
6. Treat `unknown`, `disabled`, `stale`, `degraded`, or `unhealthy` literally. Never relabel them as healthy.

Public certificate and HSTS verification against a real staging hostname belongs to M20; local/internal CA evidence is not sufficient.

## Login and account roles

The application uses local Argon2id credentials and opaque database-backed browser sessions. There is no shared default administrator and no self-registration.

- **Viewer:** read approved content/source health as granted.
- **Analyst:** content and IOC analysis/report permissions as granted.
- **Operator:** ingestion read/run/pause/retry permissions as granted.
- **Administrator:** account lifecycle, audit search, and higher-risk management permissions.

Backend permission checks are authoritative. A hidden button is not authorization. Provision unique mentor/UAT accounts through the reviewed bootstrap/user-admin procedure without recording passwords. Disable or expire accounts and revoke sessions through **User Access** when authorized. Never change a user role merely to bypass a denied action.

## Sources and source status

Use **Sources** to read:

- policy, operator, and effective state;
- implementation/execution readiness;
- credential-required/configured booleans (never credential values);
- freshness, quota/backoff, progress version/fingerprint, and latest safe run;
- actions explicitly returned by the backend.

The source registry's `enabled` metadata is not proof of live collection. The
historical C11 checkpoint recorded `DEFAULT_SOURCE_HANDLERS_COUNT = 0`, and
SIX-BIND-01 later bound exactly `nvd`, `first-epss`, `cisa-kev`,
`cert-eu-security-advisories`,
`google-threat-intelligence-public-research`, and
`mandiant-public-threat-research` without activation. The current verified
deployment is now ACTIVE following separate explicit approval. C05 sources,
STIX/TAXII, MITRE, DESC, commercial, manual-only, disabled, UAE approval-gated,
and every other non-approved source remain unbound or unscheduled as applicable.

Do not enter an arbitrary URL, edit source policy in a running container, invent an aeCERT/NibraS/DESC path, or create sample/live state to make the UI appear active.

## Ingestion Operations and Run History

**Ingestion Operations** shows committed summary, cycles, and run evidence. **Run History** shows lineage, safe counters, ordered events, and retryability.

- Pause/resume/disable only when the backend presents the action and the change is approved.
- Enable requires the stronger source-management permission and an approved implementation/activation task.
- Retry only a run marked retryable, after inspecting quota/backoff, operator state, and the prior checkpoint.
- One source failure must remain isolated. `failed`, `partial`, `rate_limited`, `credentials_missing`, `licence_required`, `disabled`, and `no_change` are valid truthful outcomes.
- Never edit database rows or checkpoints manually.

## Safe manual ingestion controls

Operator controls use fixed source slugs, empty strict request bodies, CSRF/Origin protection, audit evidence, and idempotency where required. They do not accept arbitrary hosts or paths.

The six reviewed handlers are the only recurring bindings. SIX-BIND-01 itself
did not activate or execute them; the separate final activation was approved
and completed on 11 August 2026 without a manual flow run. If no `manual_run`
action is offered, the correct manual action is **none**. Do not add a handler,
call a legacy manual CLI against live sources, or use a test fixture merely to
create data.

## Analyst workflows

- **Overview:** bounded KPIs, trends, stored CVEs/articles, and health.
- **Threat Feed:** stored publications and source-scoped threat metadata.
- **Vulnerabilities:** normalized CVSS/EPSS/KEV and provenance.
- **UAE Intelligence:** evidence categories; do not convert potential/global evidence into direct UAE attribution.
- **IOC Search:** searches stored indicators only; it performs no probing or external fetch.
- **Methodology:** authoritative wording for evidence, inference, freshness, and limitations.

Treat all OSINT text and links as untrusted. Open only links rendered by the safe URL boundary and according to organizational browsing policy.

## Reports

Reports are server-generated from allow-listed fields:

- types: UAE Intelligence or Source Operations;
- formats: CSV or PDF;
- limit: 1–100 rows;
- maximum output: 2 MiB;
- successful export requires committed audit evidence.

Do not edit client requests to add fields, names, paths, formulas, or larger limits. Store exports only in the approved case/report location and apply the organization's data handling/retention rules.

## Audit Log

Audit Log is administrator-authorized and bounded. Filter by approved action, outcome, correlation ID, and UTC interval. It contains safe details only and must not contain request bodies, credentials, cookies, SQL, raw exceptions, or environment values.

If sensitive data appears, stop distribution, preserve only safe correlation evidence, notify the security owner, and treat it as a potential security incident.

## Monitoring and alerts

Prometheus and Alertmanager are private. Alertmanager uses a local null receiver until an owner, recipient, provider, and routing policy are approved. Do not expose their ports or claim external alert delivery.

Use System Health and approved private monitoring to triage backend/database/Prefect/worker health, source freshness/attention, active cycles/runs, authentication abuse, storage pressure, and backup-evidence availability. A missing backup evidence metric is not a healthy backup.

## Backup

C09 tooling supports encrypted PostgreSQL and Prefect backup with strict metadata/checksum validation. Backups use separate least-privilege database access and age recipient material supplied through protected files.

Before a backup:

1. confirm approved destination/owner and available capacity;
2. confirm separate backup identity has no prohibited privileges;
3. for Prefect, quiesce server/worker and prove no running container mounts the volume;
4. run only the reviewed `scripts/production/backup_restore.py` subcommand documented by the recovery package;
5. retain encrypted artifact and metadata together; never retain/transfer plaintext.

Off-host storage remains a manual gate. A local encrypted artifact alone is not off-host protection.

## Restore

Restore is never an automatic production cutover.

- PostgreSQL target must be a new `alpha_data_restore_<safe-id>` database, never the active database.
- Validate metadata, checksum, encrypted size, Alembic head, safe row counts, and non-owner runtime privileges.
- Prefect target must be a new approved rehearsal/restore volume; active `prefect_data` is refused.
- Record `restore_state=validated` only after every check passes.
- On failure, keep the source artifact, isolate the throwaway target, and escalate.

Use [`c09-recovery-runbook.md`](c09-recovery-runbook.md) for exact procedures. Do not bypass checksum, privilege, tmpfs, archive-member, target-name, or quiescence checks.

## Rollback and failure triage

| Symptom | Safe response |
|---|---|
| Candidate health/migration fails | Stop cutover; preserve safe event/correlation evidence; restore known-good immutable package without automatic schema downgrade |
| Database unhealthy | Treat overall system unhealthy; stop release and investigate dependency/configuration safely |
| Prefect/worker unhealthy | Keep internal; restart only affected service after dependency health; confirm the deployment activation state matches the approved state and only the six approved bindings exist |
| Source failed/partial/rate-limited | Preserve truthful state; inspect policy/quota/checkpoint; retry only if authorized/retryable |
| Credential missing/invalid | Rotate through secret owner; never test/print value on command line |
| Report export fails | Do not fabricate/download a file; verify audit/database health and safe logs |
| Backup/restore validation fails | Do not cut over or delete source artifact; isolate new target and escalate |

## Log handling

Use bounded `docker compose ... logs --tail <approved-count> <service>` only for the affected service. Record categories, timestamps, request/correlation IDs, status, and safe summaries. Do not run or share broad environment/inspect output that could contain sensitive configuration. Never copy raw vendor payloads or stack traces into evidence.

## What not to do

- Do not use `git reset`, `restore`, `clean`, or unreviewed branch/commit changes during an incident.
- Do not run `docker compose down -v` as cleanup.
- Do not expose PostgreSQL, Prefect, worker health, Prometheus, Alertmanager, backend admin/docs, or metrics publicly.
- Do not enable a source handler/schedule without its approved activation task.
- Do not use arbitrary source URLs, headers, cookies, proxies, callbacks, or redirects.
- Do not scan/probe targets, retrieve malware/binaries, upload files, or execute exploits.
- Do not weaken authentication, CSRF, authorization, TLS, Host, CORS, CSP, request limits, checkpoints, or audit controls.
- Do not claim staging/UAT/RPO/RTO/alert/off-host evidence that was not observed.

## Escalation and evidence handoff

Stop and escalate on uncertain target identity, migration divergence, checksum mismatch, secret exposure, unexpected public service, authorization anomaly, data-integrity uncertainty, repeated unhealthy state, or any request to bypass a safety gate. Handoff only sanitized evidence and record the exact next authorized action.
