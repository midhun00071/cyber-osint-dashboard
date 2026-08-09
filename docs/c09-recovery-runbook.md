# C09 Recovery Runbook

## Safety gate

Use only an approved staging deployment or an isolated project named `alpha-data-rehearsal-<safe-id>`. Never run rehearsal commands against `alpha-data-production`, the active database, or the active Prefect volume. Use synthetic secrets and keep all source handlers disabled. Record the tested commit, operator/change reference, UTC timestamps, commands in sanitized form, and pass/fail results. Do not record secret paths, values, database URLs, SQL output, private endpoints, or raw exceptions.

Before action, confirm the incident owner, affected service, last known-good immutable image/commit, current backup evidence, and whether a migration started. Pause cutover when database state is uncertain.

## Failed deployment and application rollback

1. Treat failed health, failed migration, invalid Host/TLS routing, or missing deployment identity as failed deployment; never mark rollout successful.
2. Preserve logs by safe correlation/event category only. Do not expose raw container environment or inspect output containing secrets.
3. Select the previously approved immutable image/config pair. Do not rebuild a mutable tag during rollback.
4. Recreate backend/frontend/edge services without changing persistent volumes. Do not run downgrade automatically.
5. Verify edge HTTPS, exact Host rejection, HSTS only on HTTPS, API/auth paths, private service exposure, database health, and committed application identity.
6. Escalate if the prior package is unhealthy or schema compatibility is uncertain.

## Failed migration

1. Stop release/cutover and prevent the new application image from serving traffic.
2. Capture the pre-migration backup identifier and current Alembic revision safely.
3. Do not edit committed migration history or run an improvised downgrade.
4. Restore the encrypted pre-migration artifact only into `alpha_data_restore_<safe-id>` and validate checksum, head, and safe row counts.
5. A production cutover requires independent review and an approved maintenance decision. If a committed downgrade path is explicitly tested, follow that migration's reviewed procedure; otherwise restore/redeploy the last known-compatible package.

## Worker outage

1. Confirm system health/metrics identify `prefect_worker` as unhealthy while backend/database evidence remains truthful.
2. Check the fixed worker health endpoint internally and safe worker event categories; do not expose it through Caddy.
3. Restart only the worker after Prefect server and database health are confirmed.
4. Confirm worker health and that no source handler was activated. Review running/checkpoint-pending records before retrying.

## Source outage or credential failure

1. Do not probe the source outside its approved policy. One source failure must remain isolated.
2. Confirm the source becomes failed, rate-limited, credentials-missing, licence-required, disabled, or partial as supported by committed evidence; never convert it to success.
3. For credentials, rotate the external secret reference through the approved procedure. Never print/test the value on a command line.
4. Validate the source policy, quota, backoff, operator state, and checkpoint before an approved retry. C09 does not activate currently disabled handlers.

## Partial ingestion and checkpoint recovery

1. Identify the cycle/run by public evidence identifier and correlation ID.
2. Confirm committed records precede any checkpoint/watermark advancement using the existing persistence evidence/tests.
3. If persistence is partial or rolled back, leave the prior checkpoint unchanged. Do not manually advance it.
4. Retry only through the authorized audited operation after failure isolation and idempotency checks. Compare safe counters; do not inspect or export raw payloads.

## PostgreSQL restore

1. Select an exact tool-owned encrypted artifact/metadata pair from the approved off-host/local rehearsal destination.
2. Validate destination, metadata version, SHA-256, encrypted size, and age identity file permissions.
3. Provision a new isolated database matching `alpha_data_restore_<safe-id>` with separate restore credentials.
4. Provide a sufficiently sized verified `/dev/shm` tmpfs, then run `backup_restore.py postgres-restore` with the backup directory, server-generated backup ID, and identity file. PostgreSQL custom archives need seekable input, so the tool uses only a bounded mode-0600 tmpfs temporary and deletes it in all handled outcomes. Never supply the production database name.
5. Apply the committed least-privilege grant policy as the restore/migration owner.
6. Using a separately supplied runtime credential file, verify the runtime identity is non-administrative, has schema USAGE without CREATE, has required table read/write permissions without TRUNCATE/REFERENCES/TRIGGER, and can read the restored Alembic head and bounded row counts.
7. Record `restore_state=validated` only after all checks pass. No automated cutover follows.
8. If verification fails, retain the source artifact, isolate/delete only the new throwaway target through the approved operator process, and escalate.

## Prefect backup and restore

Before backup, stop/quiesce Prefect worker and server and confirm no running container mounts the state volume. Run `prefect-backup --confirm-quiesced`; restart only after encrypted artifact and checksum metadata succeed.

For restore, choose a new `alpha-data-rehearsal-*` or `alpha-data-restore-*` volume. `prefect-restore` validates checksum and archive structure, rejects links/traversal/devices, and refuses active `prefect_data`. Its fixed validator uses the pinned Prefect image, no network, runtime UID/GID 10001, and only the newly restored volume read-only to query SQLite state. A failed validation is not success and removes only the new restore volume. Production volume replacement is a separate reviewed maintenance action.

## Rehearsal and evidence

Run the harness only with `--synthetic-only --project-name alpha-data-rehearsal-<safe-id>`. Use `--mode contract`, `--mode operational`, or `--mode both`, and never merge those result categories. Operational mode additionally requires the bounded rehearsal Compose environment file. Offline contract results are useful validation but do not demonstrate a production rollback or RPO/RTO. Record each actual scenario, monotonic elapsed seconds, UTC start/end, safe data-loss observation, tested commit, and limitations; record unavailable scenarios as `UNRUN` with the exact reason.

The targets are RPO 24 hours and RTO 2 hours. State "demonstrated" only when measured evidence supports the specific restored data point and recovery interval.

## Escalation and stopping conditions

Stop and escalate on checksum mismatch, metadata mismatch, privileged backup identity, secret/symlink validation failure, active production target, failed quiescence, unsafe archive member, migration/head mismatch, row-count mismatch, repeated health failure, or uncertain data integrity. Do not bypass a failed safety gate to meet the target time.
