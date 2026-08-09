# C09 Local Isolated Rehearsal Evidence

## Evidence boundary

- Date: 2026-08-09 (Asia/Dubai)
- Reviewed commit: `a86d6d871610f0b4ffea065965aa4e59676f63f7`
- Compose project: `alpha-data-c09-rehearsal`
- Recovery harness identity: `alpha-data-rehearsal-c09local1`
- Data and credentials: synthetic only
- Live intelligence sources: none
- Public staging/DNS/certificate: not used

This is local evidence only. It does not demonstrate mentor staging, public TLS, external alert delivery, off-host retention, production RPO, or production RTO.

## Stack and edge evidence

The fresh isolated database image normalized Windows checkout line endings, provisioned separate bootstrap/runtime/migration roles, and migrated from base through the single head `c07a01b02c03`. All eight long-running production services became healthy. The one-shot ninth `migrate` service completed successfully.

Only Caddy published ports, both on `127.0.0.1` (9080 and 9443). HTTP returned 301 to the exact external HTTPS authority. HTTPS returned 200 with HSTS, CSP, MIME-sniffing, frame, referrer, and permissions headers. Unknown TLS Host/SNI was rejected, `/internal/metrics` returned 404 at the edge, and protected system health returned 401 anonymously. Prometheus reported `up=1` for its private backend target. Backend request/startup events were structured allow-listed JSON.

## PostgreSQL backup and restore

- Backup login: separate synthetic LOGIN inheriting only the fixed NOLOGIN `alpha_data_backup` group; prohibited privilege preflight passed.
- Synthetic source rows: `intelligence_items=1`, `ingestion_cycles=0`, `ingestion_runs=0`.
- Backup ID: `backup_20260809t122746z_5443e69f`.
- Result: age-encrypted custom-format artifact, 158,198 bytes; SHA-256 metadata validation passed.
- Restore target: new `alpha_data_restore_c09verify` database, never the source database.
- Restore input: bounded seekable `/dev/shm` tmpfs temporary, deleted after restore; no persistent plaintext dump.
- Restore result: head `c07a01b02c03` and all three row counts matched backup metadata.

## Prefect backup and restore

The isolated Prefect server and worker were stopped, and Docker confirmed no running container mounted the source state volume. Backup ID `prefect_backup_20260809t123221z_6b45075f` produced a 5,448,184-byte encrypted artifact. SHA-256 validation passed; traversal/link/device validation inspected four archive entries. Restore used the new volume `alpha-data-rehearsal-c09prefect`. Three source files and three restored files produced the same structural/content manifest. The eight long-running services were then restarted and returned healthy.

## Recovery contract scenarios

The fixed offline harness passed all eight allow-listed scenarios: application rollback, failed deployment, migration failure, worker outage, source outage, credential failure, partial-ingestion checkpoint, and backup restore. The harness observed zero synthetic-contract data loss for checkpoint and backup/restore scenarios. It deliberately reports `rpo_rto_demonstrated=false`.

The final timed synthetic run started at `2026-08-09T12:50:31.056Z` and completed at `2026-08-09T12:50:47.939Z`. Recorded per-scenario elapsed times were:

- application rollback: 0.647 seconds;
- failed deployment: 0.628 seconds;
- migration failure: 2.948 seconds;
- worker outage: 4.621 seconds;
- source outage: 4.031 seconds;
- credential failure: 0.770 seconds;
- partial-ingestion checkpoint: 2.455 seconds;
- backup restore contract: 0.781 seconds.

These are elapsed times for fixed offline validation tests, not service-recovery durations and not production RTO evidence. The earlier containerized PostgreSQL and Prefect backup/restore commands were not instrumented for elapsed-time measurement; their operation timings are therefore not claimed.

## Supply-chain and secret evidence

All six locally built images were checked with a synthetic canary. No canary appeared in image configuration, labels, build history, or recorded layer commands. Backend runtime contains ReportLab and no pytest; `pip check` passed. Docker Scout v1.21.0 was installed but image vulnerability scanning was UNRUN because it required an unavailable Docker ID session. No credential workaround was attempted.

`npm audit --omit=dev` reported 0 Critical and 4 High affected packages (`next`, `postcss`, `sharp`, and transitive `nanoid`). No C09 exploit path was demonstrated: this application has no Server Actions, middleware/proxy authorization boundary, custom server/rewrites, attacker-controlled CSS source map, upload path, or custom nanoid generator. Version consolidation remains a C10 follow-up; this local evidence is not a vulnerability-scan pass.

## Limitations

- Local Caddy internal CA is not public certificate evidence.
- Alertmanager uses the documented null receiver; no external delivery was attempted.
- Encrypted artifacts were not transferred off host.
- RPO 24 hours and RTO 2 hours remain targets, not demonstrated results.
- Browser automation, load testing, and real source traffic were intentionally excluded.

## Consolidated hardening rehearsal - 9 August 2026

This section records only the hardening rerun. It used isolated Compose project
`alpha-data-rehearsal-c09hard02`, reserved host
`c09-hardening.example.invalid`, loopback-only ports, synthetic secrets/data,
and zero live source handlers. Contract-test and Docker operational evidence are
intentionally separate.

### Contract-test validation

| Scenario | Result | Elapsed seconds |
| --- | --- | ---: |
| Application rollback | PASS | 0.618 |
| Failed deployment | PASS | 0.565 |
| Migration failure | PASS | 3.326 |
| Worker outage | PASS | 5.772 |
| Source outage | PASS | 6.623 |
| Credential failure | PASS | 0.741 |
| Partial ingestion/checkpoint | PASS | 2.384 |
| Backup/restore | PASS | 1.522 |

These timings are pytest contract durations, not operational recovery times.

### Operational Docker rehearsal

| Scenario | Result | Elapsed seconds | Safe observation |
| --- | --- | ---: | --- |
| Application rollback | PASS | 15.275 | A deliberately invalid candidate was rejected; the label-owned known-good backend and edge recovered healthy. |
| Failed deployment | PASS | 6.678 | The invalid deployment identity could not become healthy; known-good service health was retained/recovered. |
| Migration failure | PASS | 4.887 | A deterministic missing Alembic configuration failed against a throwaway target; known-good database/backend/head remained available. |
| Worker outage | PASS | 13.814 | Only the label-owned worker stopped; internal monitoring observed degradation, then healthy recovery. |
| Source outage | UNRUN | - | No safe runtime source-fault injection interface exists without enabling a handler or live source traffic. |
| Credential failure | PASS | 3.374 | A missing synthetic secret reference failed closed; the correct synthetic configuration remained healthy. |
| Partial ingestion/checkpoint | UNRUN | - | The transaction-failure injection is available only through the contract fixture, not a safe running-stack interface. |
| Backup/restore harness scenario | UNRUN | - | The host lacks the required age/PostgreSQL tools, and Docker-socket delegation is not an approved harness boundary. |

No production RPO or RTO is demonstrated. The local timings are not
representative of mentor staging, and no data-loss observation was inferred for
scenarios that did not restore a measured point-in-time dataset.

### Hardening backup/restore evidence

Outside the combined harness scenario, the actual encrypted PostgreSQL tool ran
in the isolated database network. Backup
`backup_20260809t135730z_e4f7fd4f` produced a 158,065-byte age artifact and
strict checksum metadata. Restore into `alpha_data_restore_hardening01` returned
`restore_state=validated` only after the distinct non-owner runtime login read
Alembic head `c07a01b02c03`, expected row-count evidence, and passed the frozen
least-privilege catalog checks. No persistent plaintext backup was created.

A new Prefect hardening restore/readability execution is `UNRUN`. The required
nested Docker operation would expose the host Docker socket to a validation
container; that escalation was rejected as too broad. The verified rehearsal
Prefect services were restarted and returned healthy, and no workaround was
attempted. The pinned-image, no-network, runtime-UID, read-only-volume validator
and bounded cleanup paths are covered by focused tests. The earlier initial C09
Prefect backup/restore evidence above remains historical evidence and is not
relabelled as this new readability run.
