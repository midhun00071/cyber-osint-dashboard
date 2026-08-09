# C09 Production Operations and Recovery

## Scope and official task IDs

C09 implements the locally provable scope for B8-06, B9-01, B9-02, B9-04, B9-05, and B9-06. B9-03 remains the separate mentor/company staging gate. This document does not claim public DNS, public certificate issuance, external alert delivery, an approved off-host backup destination, production credential rotation, or measured staging recovery objectives.

## Production topology and exposure

`compose.prod.yml` defines PostgreSQL, the FastAPI backend, Next.js frontend, a manual migration profile, Prefect server and worker, Caddy, Prometheus, and Alertmanager. Only Caddy publishes host ports. PostgreSQL, backend, frontend, Prefect, worker health, Prometheus, Alertmanager, and `/internal/metrics` have no host publication.

- `edge`: Caddy, frontend, and backend routing only.
- `database`: internal PostgreSQL network used by backend, worker, and the migration job.
- `orchestration`: backend, Prefect server, and worker. It is not marked Docker-internal because the future worker needs policy-controlled outbound source access; C09 does not activate any handler.
- `monitoring`: internal backend, Prometheus, and Alertmanager network. Caddy is not connected.

The production images use validated exact tags and immutable digests. Backend, frontend, Prefect server/worker, Caddy, Prometheus, and Alertmanager use fixed non-root identities. The small Caddy derivative strips the upstream low-port file capability, uses UID/GID 10001, and listens on high internal ports with all Linux capabilities dropped and `no-new-privileges`. Services use bounded logs, PID/CPU/memory limits, health checks, restart policies, read-only filesystems where validated, and explicit writable volumes/tmpfs.

## Caddy edge and TLS

`ops/caddy/Caddyfile` accepts only the explicit `EDGE_HOST`. Container ports 8080/8443 map to the explicitly configured public HTTP/HTTPS ports. HTTP redirects to the external HTTPS origin. HSTS is configured only in the HTTPS site. The HTTPS site sets CSP, MIME sniffing, anti-framing, referrer, and permissions policies; limits request bodies to 1 MiB; and bounds request/upstream timeouts.

`/api/*` routes to FastAPI and other application paths route to Next.js. `/internal/*`, metrics, health-admin, Prefect, and Alertmanager path shapes are rejected. FastAPI exact-Host validation remains a second boundary.

With `EDGE_TLS_MODE` blank, Caddy uses its normal public certificate management. `EDGE_TLS_MODE=internal` is permitted only for isolated local rehearsal and is not evidence of public TLS or certificate issuance.

## Reports and analyst pages

The release pages are Reports, System Health, Audit Log, and Methodology.

- `GET /api/v1/reports/catalog` requires `report.read`.
- `POST /api/v1/reports/export` requires `report.export`, Origin/CSRF validation, a fixed report type (`uae_intelligence` or `source_operations`), CSV/PDF format, and 1-100 rows.
- Exports are generated in memory from existing bounded C07/C08 read services. Fields are allow-listed, text cells are bounded to 500 characters, and total output is limited to 2 MiB.
- CSV cells with formula/control prefixes are neutralized. PDF uses ReportLab canvas strings without HTML, remote resources, or temporary plaintext files.
- The server generates ASCII filenames and returns `no-store`/`nosniff`. A successful export is returned only after `report.export.requested` audit evidence commits; audit failure fails closed.
- Audit Log reuses the existing administrator-authorized bounded audit API. It provides filters and pagination but no raw event export or request data.

## Health semantics and deployment identity

`GET /api/v1/system/health` requires `source.read` and reports exactly eight components: backend, database, Prefect server, Prefect worker, ingestion operations, source freshness, storage, and deployment identity. States are `healthy`, `degraded`, `unhealthy`, `stale`, `disabled`, or `unknown`.

Database failure makes overall health unhealthy. Other required-component failures degrade overall health. Stale and unknown states remain visible. With zero configured source handlers, execution and source freshness are disabled rather than falsely healthy. Storage is unknown unless `STORAGE_CAPACITY_BYTES` is explicitly trustworthy. Production startup requires a full 40-character `APP_COMMIT_SHA`; Git is never executed inside the container.

Prefect probes are fixed to `http://prefect-server:4200/api/health` and `http://prefect-worker:8080/health`, reject redirects, ignore proxy environment configuration, use short timeouts, and bound response consumption. They accept no caller-supplied URL.

## Logging, metrics, and alerts

Application logs are deterministic JSON with a fixed field allow-list. Raw request targets/query strings, headers, cookies, bodies, SQL, credentials, database URLs, exception strings, and tracebacks are not serialized.

`GET /internal/metrics` is excluded from OpenAPI and the edge. Metrics use fixed component/state labels and cover component health, freshness counts, the fixed aggregate `alpha_data_source_attention_count`, active cycles/runs, recent authentication/authorization abuse, configured storage observations, and backup-evidence availability. Missing backup evidence emits zero and is alertable; it is never fabricated as healthy.

Prometheus retains at most 15 days/2 GB and scrapes only `backend:8000/internal/metrics`. Ten alert rules cover backend/database/Prefect/worker health, stale sources, source attention, long active cycles, authentication abuse, configured storage pressure, and missing backup evidence. Freshness and attention expressions are gated by component state so intentionally disabled handlers remain visible without producing false degradation alerts. Alertmanager has only a local null receiver. The owner, recipient, provider, and any TLS-expiry external probe remain approval-gated; no external credential exists in configuration.

## Secrets and rotation

Production credentials are Docker secret file references. Bootstrap, runtime, migration, and externally provisioned backup-login credentials are separate. Age recipient/identity material is supplied by bounded regular non-symlink file references. Direct protected-environment password values and `DATABASE_URL` remain prohibited.

Rotation procedure:

1. Provision a replacement secret in the approved external secret store and record an owner/change ticket without the value.
2. For database identities, update the server-side credential through the approved administrator process, then atomically update the corresponding protected file reference.
3. Recreate only dependent services; verify exact Host, health, authentication, and sanitized logs.
4. For age, retain the old identity until all retained artifacts are re-encrypted or expire and an isolated restore succeeds with the replacement key.
5. Revoke the old credential, verify denial, record correlation/evidence identifiers, and never copy values into logs or reports.

No production rotation is claimed by C09 local implementation.

## Encrypted backup and restore

`scripts/production/backup_restore.py` provides `postgres-backup`, `postgres-restore`, `prefect-backup`, and `prefect-restore`.

After schema migration, the migration owner runs `ops/backup/configure-backup-role.sql`. It fails unless the fixed `alpha_data_backup` group remains a safe NOLOGIN role, then grants only schema read access to current/future migration-owned tables and sequences. Creation of a separate LOGIN, password assignment, and group membership remain external approval-gated administrator actions.

PostgreSQL backup requires separate `POSTGRES_BACKUP_*` components and a password file. The login is externally provisioned and must not be the closed `alpha_data_backup` NOLOGIN role. Preflight rejects superuser, CREATEDB, CREATEROLE, REPLICATION, and BYPASSRLS flags. `pg_dump` custom-format output streams directly to age; no plaintext dump is stored. The encrypted partial becomes final only after both processes succeed and the artifact is non-empty. SHA-256, Alembic revision, and bounded safe row counts are recorded in strict version-2 metadata.

PostgreSQL restore validates metadata, size, and SHA-256 before decrypting a bounded archive into verified `/dev/shm` tmpfs because PostgreSQL custom archives require seekable input. The mode-0600 temporary is always removed after `pg_restore`; no persistent plaintext artifact is written. The target must match `alpha_data_restore_<safe-id>` and cannot equal the configured production database. After applying the committed grants as the restore/migration owner, a separately supplied, non-owner runtime login must prove least-privilege schema/table access and read the expected Alembic head `c07a01b02c03` and safe row counts before `restore_state=validated` is returned. There is no automatic cutover.

Prefect backup requires explicit quiescence confirmation and verifies no running container mounts the source volume. It mounts the source read-only and streams tar to age. Restore validates checksum, rejects absolute/traversal paths, symlinks, hardlinks, and device entries, and creates only a new `alpha-data-rehearsal-*` or `alpha-data-restore-*` volume. Active `prefect_data` targets are refused. Before returning `restore_state=validated`, a bounded short-lived container uses the exact pinned Prefect image, UID/GID 10001, no network, and only the new volume mounted read-only to query the restored SQLite state. Failure removes only that newly created restore volume.

Retention planning is dry-run by default. PostgreSQL and Prefect each receive independent 7 daily, 4 weekly, and 3 monthly buckets; artifacts from one class never compete with the other. Only exact tool-owned artifact/metadata pairs with verified checksums are candidates, and each pair is revalidated immediately before deletion. Deletion requires `--confirm-retention-delete`. The approved off-host owner/destination is pending; operators must transfer encrypted artifacts and metadata to versioned approved storage after B9-03 approval. Plaintext artifacts must never be transferred or retained.

## Recovery and targets

The operator procedure is in `docs/c09-recovery-runbook.md`. `scripts/production/recovery_rehearsal.py` accepts only `alpha-data-rehearsal-<safe-id>`, requires synthetic-only mode, and separates fixed contract-test results from Docker operational results. Operational application rollback, failed deployment, migration failure, worker outage, and credential failure act only on Compose-label-verified rehearsal resources and use monotonic timing. Unsafe or unavailable scenarios are `UNRUN` with an exact reason. No live source URL is used, and neither contract nor local timings demonstrate production RPO/RTO.

Approved staging targets are RPO 24 hours and RTO 2 hours. They remain targets until an isolated or staging rehearsal measures the relevant failure-to-recovery interval and data-loss observation. C09 creates no timing-evidence document unless such a rehearsal actually runs.

## Pending manual/staging integrations

- B9-03 mentor/company-accessible staging, DNS, and public certificate evidence.
- Approved external alert owner/recipient/provider and delivery test.
- TLS-expiry external probe against the real staging endpoint.
- Approved versioned off-host backup destination and transfer owner.
- External least-privilege backup LOGIN provisioning and credential rotation.
- Mentor staging recovery rehearsal and measured RPO/RTO evidence.
