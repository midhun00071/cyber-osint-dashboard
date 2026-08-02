# B1-05 Database Operations Controls

## Status and frozen scope

B1-05 implements review-ready database operational controls for bounded
SQLAlchemy pooling, PostgreSQL role separation, evidence-supported indexes, a
non-mutating retention planner, and a strict future backup-metadata contract.
It does not administer a staging or production database, execute retention,
create or restore a backup, select an off-host destination, or establish an RPO
or RTO. No production roles have been provisioned by this implementation.

APR-09, APR-10, and APR-11 remain approval dependencies. There is no approved
final retention period. Destructive retention is disabled. APR-10 still owns
the production secret-provider decision. APR-11 still owns the backup storage,
encryption, and recovery-policy decision.

## Role boundaries

The target production boundary separates these responsibilities:

| Responsibility | Identity or group | Exact intended privileges | Explicit denials |
|---|---|---|---|
| Bootstrap administration | deployment bootstrap login | Initial database and role provisioning only | Never mounted in backend or migration containers |
| Migrations | deployment migration login | `USAGE` and `CREATE` on `public`; owns application tables and sequences | Non-superuser; no database or role creation; not used by runtime |
| Runtime application | deployment application login | `USAGE`; `SELECT` and `INSERT` on the 21 application tables; `UPDATE` only on the mutable list below; `USAGE` and `SELECT` on sequences | No ownership, DDL, schema creation, role administration, `TRUNCATE`, or `DELETE` |
| Read-only | `alpha_data_readonly` group | `USAGE` and `SELECT` on the 21 application tables | No DML, DDL, ownership, schema creation, or role management |
| Logical backup | `alpha_data_backup` group | `USAGE` and `SELECT` on the 21 application tables | No DML, DDL, ownership, schema creation, role management, or replication |
| Retention planning | `alpha_data_retention` group | `USAGE` and `SELECT` on the eight operational tables listed below | No access to source configuration and no destructive privilege |

All non-administrative roles are `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`,
`NOREPLICATION`, `NOBYPASSRLS`, and `INHERIT`. The fixed read-only, backup, and retention
groups are `NOLOGIN`; a future approved deployment can attach separate login
identities only through a separately approved membership design. Current
provisioning permits no membership at a managed role boundary: a managed role
cannot inherit an unrelated role, and no unrelated role can be a member of a
managed login or group.

The runtime `UPDATE` allow-list is: `indicators`, `ingestion_cycles`,
`ingestion_runs`, `intelligence_items`, `intelligence_sources`,
`quarantined_records`, `source_credential_references`,
`source_rate_limit_states`, `source_records`, and `vulnerabilities`.
The runtime cannot update `ingestion_run_events`, `source_checkpoints`,
`source_watermarks`, `audit_events`, or `ingestion_errors`, and receives no
`DELETE` privilege on any application table.

The retention group can read only `audit_events`, `ingestion_errors`,
`ingestion_run_records`, `ingestion_run_events`, `ingestion_runs`,
`quarantined_records`, `source_checkpoints`, and `source_watermarks`.
`intelligence_sources` is intentionally excluded.

## Provisioning and future objects

`database/init/10-provision-database-roles.sh` validates every database, schema,
and role identifier against a strict PostgreSQL-compatible allow-list and
requires the bootstrap, application, migration, read-only, backup, and
retention names to be pairwise distinct. It rejects pre-existing or inbound
catalog memberships involving any managed role before normalization or
password rotation. Failure output is fixed and does not expose SQL or catalog
details. It reads
passwords from protected files in production, supplies them to the PostgreSQL
client through standard input, and never places them in SQL or command-line
arguments. It creates or normalizes the roles, rotates the two non-administrative
login passwords, then applies `11-apply-database-grants.sql`.

Compose mounts only the shell into PostgreSQL's automatic initialization
directory. The grants SQL is a read-only file at the fixed non-automatic path
`/opt/alpha-data/database/11-apply-database-grants.sql`; the shell rejects an
absent, unreadable, non-regular, symlinked, or unexpectedly resolved target and
invokes that file exactly once. This prevents the entrypoint and shell from
executing the same SQL independently.

The SQL runs transactionally with the explicit safe `pg_catalog` search path.
It revokes schema `CREATE` from `PUBLIC`, transfers existing application tables
and sequences to the migration identity, revokes inherited object permissions,
and reapplies allow-listed grants. Repeated execution is idempotent.

For a fresh disposable database, provisioning runs before Alembic. Default
privileges owned by the migration identity revoke all future table and sequence
access from `PUBLIC`, runtime, read-only, backup, and retention identities; they
grant nothing automatically. Provisioning runs again after a fresh migration
to apply the recognized current-table allow-lists and runtime sequence access
only for sequences owned by those recognized tables. An unknown future table
or sequence remains inaccessible even after provisioning is rerun. For an
existing database at `b103a71d2e4f`, an approved database operator runs the
same provisioning script before the migration identity upgrades to the B1-05
head and again afterward when object grants need refresh. The migration login
can downgrade and re-upgrade the B1-05 index revision.

Every migration that introduces a new runtime-accessible object requires an
explicit allow-list review and provisioning update.

Local Compose uses explicit development-only placeholders and exposes the
database port for the existing local workflow. Production Compose has an
internal database network and no PostgreSQL host port. It requires three
separate protected password-file references. Only the application secret is
mounted in the backend, only the migration secret is mounted in the migration
container, and bootstrap credentials remain confined to PostgreSQL.

### Password rotation and revocation

1. Obtain APR-10 approval and generate separate replacement values in the
   approved secret store.
2. Replace only the relevant protected password file; never print or record its
   contents.
3. Have an authorized database operator rerun the idempotent provisioning step
   so PostgreSQL receives the replacement through standard input.
4. Restart or redeploy only the affected application or migration service.
5. Verify service health and required least-privilege behavior with sanitized
   output.
6. Revoke the old credential in the approved secret-management process.
7. Review sanitized logs for failed use of the revoked identity and record only
   non-secret evidence.

This sequence does not automate PostgreSQL role-password rotation. Bootstrap
credential rotation is a separately approved database-administration password
change. Do not delete the database volume during rotation.

## Bounded connection pooling

| Variable | Default | Accepted strict integer range |
|---|---:|---:|
| `DATABASE_POOL_SIZE` | 5 | 1 to 20 |
| `DATABASE_MAX_OVERFLOW` | 5 | 0 to 20 |
| `DATABASE_POOL_TIMEOUT_SECONDS` | 30 | 1 to 60 seconds |
| `DATABASE_POOL_RECYCLE_SECONDS` | 1800 | 60 to 3600 seconds |
| `DATABASE_CONNECT_TIMEOUT_SECONDS` | 10 | 1 to 30 seconds |

Pool size plus overflow cannot exceed 30. Booleans, floats, numeric strings in
direct settings input, and out-of-range values are rejected. Protected
environments therefore fail during settings validation instead of using an
unsafe fallback. Engine creation remains lazy and cached. Transactions remain
caller-owned, sessions always close, and initial connection errors cross the
application boundary only as a fixed sanitized message.

The disposable PostgreSQL test uses pool size 1, overflow 1, and timeout 1
second. It checks out both available connections, proves the next checkout
times out within a bounded interval, returns one connection, proves a new
checkout succeeds, and verifies zero checked-out connections before disposal.

## Query-plan evidence and index decision

The review used PostgreSQL 17 `EXPLAIN (FORMAT JSON)` against representative
populations, inside a transaction that was rolled back and without planner
override settings. It evaluated
the real ordering and predicates used for source-latest runs, global-latest run,
cycle status history, current source checkpoint, current source watermark, and
audit history. Configured integration tests capture JSON plans for all six query
shapes on a disposable PostgreSQL 17 database.

The bounded population contains 20 sources, 5,000 run rows per source (100,000
runs total) with paired timestamp ties, 25,000 cycles, 5,000 source checkpoints,
5,000 source watermarks, and 40,000 audit rows. These counts support repeatable
planner evidence only; they do not claim production scale, latency, or capacity.

Before/after evidence temporarily removes only the two B1-05 candidate indexes,
captures a source-filter bitmap heap scan plus explicit sort and a global
sequential scan plus explicit sort, recreates the exact candidates, and captures
direct index plans with no sort or incremental-sort node. The former source-run
index lacked the deterministic `id` tie-breaker.
The accepted replacement is exactly
`(source_id, started_at DESC, id DESC)`. The global-latest query otherwise used
a sequential scan plus sort; the accepted index is exactly
`(started_at DESC, id DESC)`. Both candidate definitions produced direct index
plans for their current queries.

The existing cycle status/time index, partial unique checkpoint index, partial
unique watermark index, and audit time/id index already produced direct index
plans. They remain unchanged. No checkpoint, watermark, future Run History,
text-search, or other speculative index was added. Revision `d7a9e51c2f40`
has the B1-04 head `b103a71d2e4f` as its sole parent, preserving one linear
Alembic head and all uniqueness and partial-index predicates.

## Dry-run retention planning

`DatabaseRetentionService.plan` requires an explicit timezone-aware cutoff and
a strict integer limit from 1 through 1000. It issues bounded `SELECT` queries,
sorts safe identifiers deterministically by category and identifier, and always
returns `policy_state="approval_required"`, `candidate_count=0`, and protected
records only. It has no update, delete, flush, commit, rollback, scheduling, or
checkpoint-advancement path.

The planner protects running and pending ingestion, checkpoint-pending state,
unresolved quarantine, retries and retry parents, checkpoint-linked and
watermark-linked runs, append-only run events, append-only audits, ingestion
errors, run records, and active lifecycle state. Unknown or inconsistent state
is protected by default. Output contains only safe identifiers, categories,
counts, dispositions, and allow-listed protection reasons; it omits payloads,
source excerpts, checkpoint values, credentials, SQL, exceptions, and stack
traces. A database failure produces a fixed sanitized planning error, never a
candidate or allow-on-error result.

No final retention period is approved. Destructive retention execution and a
future retention-hold model remain accepted limitations pending APR-09.

## Backup metadata boundary

`database/backup-metadata.schema.json` is a strict JSON Schema 2020-12 contract
for future B9-05 evidence. It requires a version, bounded backup identifier,
PostgreSQL logical type, UTC `Z` timestamps, 12-character Alembic revision,
allow-listed outcome and encryption states, allow-listed checksum algorithm
with matching digest length, bounded non-negative artifact size, opaque
`artifact_ref_...` identifier, and printable bounded safe summary. Unknown
properties are rejected.

The opaque reference cannot encode a path, URL, hostname, endpoint, command,
database connection, or secret reference. The summary rejects credential
shapes, database URLs, raw tool output, raw exception evidence, commands, and
SQL-like diagnostics. The schema stores no arbitrary diagnostic property.

B1-05 has not executed a production backup. No restore has been proven. B9-05
owns encrypted backup creation, integrity evidence, and approved off-host
storage; B9-06 owns restore rehearsal and recovery evidence. No recoverability,
disaster-recovery readiness, RPO, or RTO is claimed.

## Validation commands

Run from `backend` with the repository virtual environment and an external
Windows pytest temporary directory:

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider --basetemp C:/Temp/b105-focused tests/test_database_config.py tests/test_db_session.py tests/test_docker_compose_config.py tests/test_environment_documentation.py tests/test_ingestion_models.py tests/test_production_compose.py tests/test_database_role_provisioning.py tests/test_database_retention_service.py tests/test_database_backup_metadata_schema.py tests/test_b1_05_database_operations_documentation.py
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider --basetemp C:/Temp/b105-postgresql tests/test_b1_05_database_operations_postgresql.py
.\.venv\Scripts\python.exe -m alembic -c alembic.ini heads
.\.venv\Scripts\python.exe -m alembic -c alembic.ini history
```

The configured PostgreSQL test requires a dedicated loopback-only disposable
database whose name begins `b105_test_`. The test configuration is supplied
without displaying its credential-bearing value. Full regression additionally
uses the complete backend suite, mapper validation, `git diff --check`, and the
repository `run.cmd test` workflow.

## Known limitations and sanitized evidence

- This is implementation evidence for independent review, not approval,
  deployment, backup, restore, or recoverability evidence.
- No staging or production database was changed.
- APR-09, APR-10, and APR-11 remain `Need Approval` dependencies.
- Transitional ingestion writers still do not acquire B1-04 advisory locks;
  old and new writers must not run concurrently.
- Prefect scheduling, progress integration, and lifecycle aggregation remain B2
  work.
- The accepted Windows CRLF predecessor-migration raw-byte hash behavior remains
  unchanged and must be reported separately if encountered.
- Safe failure evidence is limited to fixed messages, test labels, counts,
  elapsed times, revision identifiers, index names, and privilege outcomes. It
  excludes URLs, passwords, secret-file contents, raw exceptions, and SQL.
