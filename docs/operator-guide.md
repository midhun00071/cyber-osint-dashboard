# Alpha Data operator guide

## Purpose and authority

This guide is for an approved mentor, staging operator, or junior analyst administrator. It covers safe operation of the C11 local release-candidate package. It does not authorize public deployment, source activation, destructive recovery, arbitrary external requests, or access outside the assigned environment.

The detailed production procedure remains [`production-docker-deployment.md`](production-docker-deployment.md); recovery safety gates remain [`c09-recovery-runbook.md`](c09-recovery-runbook.md). When this summary and a task-specific approved change record differ, stop and obtain direction.

## Before every operation

Confirm:

1. the approved task/change reference and named environment;
2. exact repository checkpoint and immutable image/config pair;
3. Docker project and Compose/environment file paths;
4. secrets are protected files outside Git and terminal capture;
5. no source handler or schedule activation is implied;
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

## Startup

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

Production deployment registration is explicit and paused by default. C11 had zero production source handlers at its historical checkpoint. SIX-BIND-01 now code-binds exactly six reviewed scheduled handlers, but binding does not equal activation and Prefect remains paused. Do not pass activation flags or enable a schedule during ordinary startup.

For the corrected local-development workflow only, start `prefect-db`,
`prefect-server`, and `prefect-worker` together. The UI remains loopback-only at
`http://127.0.0.1:4200`; the local metadata database has no host port. If the
new metadata volume starts empty, recreate the deployment only with
`python -m app.orchestration.deployments` inside `prefect-worker`, never with
`--activate`. The worker recreates `alpha-data-process` idempotently. The old
SQLite file in `prefect_data` is retained and is not migrated or deleted.

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

The source registry's `enabled` metadata is not proof of live collection. The historical C11 checkpoint recorded `DEFAULT_SOURCE_HANDLERS_COUNT = 0`. SIX-BIND-01 now binds exactly `nvd`, `first-epss`, `cisa-kev`, `cert-eu-security-advisories`, `google-threat-intelligence-public-research`, and `mandiant-public-threat-research` in code. Prefect remains paused, so binding does not activate collection. The C05 sources, STIX/TAXII, MITRE, DESC, commercial, manual-only, disabled, UAE approval-gated, and every other non-approved source remain unbound or unscheduled as applicable.

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

The six reviewed scheduled handlers are code-bound, but no production source execution was activated by SIX-BIND-01. If no `manual_run` action is offered, the correct action is **none**. Do not activate a handler, call a legacy manual CLI against live sources, or use a test fixture in staging merely to create data. A separate controlled activation-precondition task follows; a parent-cycle run still requires separate approval, and recurring Prefect unpause remains a later, separately approved step.

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
| Prefect/worker unhealthy | Keep internal; restart only affected service after dependency health; confirm the deployment remains paused and only the six approved bindings exist |
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
