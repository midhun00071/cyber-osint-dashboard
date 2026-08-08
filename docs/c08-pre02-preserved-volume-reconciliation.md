# C08-PRE-02 preserved-volume reconciliation

## Purpose and Phase A boundary

`C08-PRE-02` provides reviewed, fail-closed reconciliation tooling for the preserved local PostgreSQL volume. Phase A contains one PowerShell wrapper, two maintenance SQL files, focused tests, and this document. **Phase A does not modify the preserved database.** Preflight, Apply, and both SQL files have not been executed during implementation or hardening.

C08 remains blocked. A future maintenance session must separately approve the backup, exact post-commit Git checkpoint, Apply command, database reconciliation, later migrations, and runtime verification. This document does not claim remediation, migration, Administrator bootstrap, authentication, source activation, or ingestion success.

## Frozen data boundary

The PRE-01 read-only investigation found an older preserved volume at revision `f8d739439ed0`, four deterministic development-seed sources with the same legacy checkpoint, null last-success timestamps, and no ingestion runs. The runtime role owns the database, 11 public tables, and 9 public sequences and has legacy administrative attributes. Dedicated bootstrap and migration roles are absent. C06/C07 schema objects and approved production handler registrations are also absent.

The only authorized Phase A files are:

1. `scripts/c08-pre02-reconcile-preserved-volume.ps1`
2. `database/maintenance/c08-pre02-provision-existing-volume.sql`
3. `database/maintenance/c08-pre02-correct-synthetic-progress.sql`
4. `backend/tests/test_c08_pre02_reconciliation.py`
5. `docs/c08-pre02-preserved-volume-reconciliation.md`

No committed migration, application module, environment file, deployment file, source policy, registry, or handler map is changed.

## Reviewed Git checkpoint

The wrapper has no embedded dependency on the Phase A parent commit. A future reviewer must freeze the commit containing these five files and pass its full 40-character lowercase post-commit Git checkpoint explicitly:

```powershell
.\scripts\c08-pre02-reconcile-preserved-volume.ps1 `
  -Mode Apply `
  -ExpectedGitCheckpoint '<reviewed-40-character-lowercase-commit>' `
  -MaintenanceSessionId '<reviewed-non-secret-session-id>' `
  -BackupEvidencePath '<absolute-external-evidence-json>'
```

Apply never infers this checkpoint. Preflight also requires either `-ExpectedGitCheckpoint` or an external reviewed approval-evidence JSON containing task `C08-PRE-02` and the checkpoint. The script requires `HEAD` and `origin/dev` to equal the reviewed value, divergence `0 0`, and no staged, tracked, or untracked worktree entries. It repeats the clean Git gate immediately before each mutation phase. Branch `dev`, revision `f8d739439ed0`, database `alpha_data_db`, service `db`, container `alpha-data-db`, and volume `cyber-osint-dashboard_postgres_data` remain fixed.

## Actual backup artifact verification

Apply requires an external, non-empty JSON evidence file for the same maintenance session. It must record:

- task ID;
- maintenance-session ID;
- reviewed Git checkpoint;
- database name;
- volume name;
- database revision;
- ISO-8601 creation time;
- absolute backup artifact path; and
- declared lowercase SHA-256.

The script resolves the actual backup artifact, requires it outside the repository, accepts only `.backup`, `.dump`, `.tar`, or `.gz`, rejects links/reparse points and directories, and requires a non-empty regular file. It requires both the evidence and the artifact's own last-write time to be current, binds the artifact time to the declared creation time, computes SHA-256 over the actual file, and rechecks type, size, and last-write metadata after hashing. Missing, empty, changed-during-verification, hash-mismatched, checkpoint-mismatched, future-dated, or more-than-two-hours-old evidence or artifacts fail closed. The utility does not create, restore, or inspect backup contents.

## Non-echoing credential entry

Credentials are not accepted through command-line parameters, files, or environment variables. During a locally attended Apply session, the wrapper calls `Read-Host -AsSecureString` separately for `alpha_data_bootstrap` and `alpha_data_migration`. Enter them privately in the local terminal and **never paste credentials into chat**.

Each SecureString is converted only immediately before it is written to `psql` standard input. The unmanaged plaintext buffer is zeroed and freed in `finally`; managed plaintext references are cleared; the SecureString objects are disposed after fixed loopback login verification. Credential values are never logged, serialized into evidence, placed in process arguments, or retained as configuration.

## Exact role-state classification

Preflight collects sanitized Booleans, names, and counts and classifies the role boundary exactly:

- `legacy`: database owner `alpha_data_user`, `public` schema owner `pg_database_owner`, application role login plus `SUPERUSER`, `CREATEDB`, `CREATEROLE`, and `BYPASSRLS` (but not `REPLICATION`), no dedicated roles, and all 11 tables and 9 sequences owned by the application role;
- `prepared`: the legacy owner/application boundary remains unchanged, all five dedicated supporting roles have their exact safe attributes, migration has bounded database CONNECT and schema USAGE/CREATE, and the application role still owns all 11 tables and 9 sequences;
- `normalized`: database and `public` schema owner `alpha_data_bootstrap`, all 11 tables and 9 sequences owned by `alpha_data_migration`, the application role owns none and has no administrative/destructive capability, and the dedicated paths remain bounded and available; or
- `unexpected`: any owner, count, role attribute, membership, or representative privilege differs from those exact definitions.

Every accepted state also requires zero unexpected managed-role memberships, zero unexpected public object owners, the exact allow-listed names for all 11 public tables and 9 public sequences, no unexpected database CONNECT grantee, and no migration default-ACL drift. Legacy requires all five dedicated roles to be absent, including unsafe variants of the three auxiliary role names. Prepared requires migration and all three auxiliary roles to have no table or sequence privilege. Normalized revokes database CONNECT from `PUBLIC`, retains it only for the six managed identities, and keeps the fixed object/default-privilege allow lists. `unexpected` always fails closed; the script never overwrites unfamiliar database, schema, table, or sequence ownership.

Resume behavior is deterministic:

- `legacy`: Prepare, configure credentials, verify both logins and migration capability, then Normalize;
- `prepared`: re-enter and configure both intended credentials, verify both logins and migration capability, then Normalize; this permits recovery if execution stopped immediately after Prepare or during credential configuration;
- `normalized`: prompt for the existing credentials, verify both logins, skip every role mutation, and proceed only to the still-pending synthetic correction.

A fully corrected second Apply still fails safely because its four checkpoints are already null and no longer meet the exact correction precondition.

## Prepare and Normalize phases

The role SQL requires the explicit fixed `c08_phase` value `prepare` or `normalize`; invalid or missing values fail before a transaction. It never examines password hashes to infer state.

Prepare runs one serializable transaction. It verifies the exact legacy database owner, schema owner, application attributes including `REPLICATION`, the fixed 11-table/9-sequence name and ownership allow lists, absent managed roles, zero memberships, zero unexpected owners, and no unexpected database CONNECT grantee. It creates the bootstrap, migration, read-only, backup, and retention roles with fixed safe attributes and grants only the CONNECT and schema capabilities needed for verification. It then proves that migration and the auxiliary roles received no object or default privileges. Prepare does not transfer database, schema, table, or sequence ownership, does not revoke application privileges, and does not demote `alpha_data_user`.

After Prepare commits, the wrapper obtains both SecureStrings, configures the new credentials through standard input, verifies both logins using fixed `127.0.0.1:5432` TCP connections, and verifies migration CONNECT plus schema USAGE/CREATE from the migration login itself.

Normalize runs only after those checks. Its serializable transaction independently revalidates the exact prepared role, owner, object-name, object-privilege, membership, database-CONNECT, and default-ACL state. It transfers the database and schema owners, transfers exactly the allow-listed 11 tables and 9 sequences, removes `PUBLIC` database CONNECT, applies the six-identity CONNECT allow list plus bounded read-only/backup/retention and default privilege rules, and verifies the administrative and migration paths. The final application restriction block then removes broad schema/table/sequence privileges, reapplies the explicit runtime allow list, removes administrative attributes, and verifies zero remaining runtime ownership or destructive representative privileges.

No phase drops a role, database, schema, table, or sequence; uses `DROP OWNED` or `REASSIGN OWNED`; runs Alembic; or activates application behavior.

## SQL byte/hash binding

Both approved SQL paths and SHA-256 values are pinned in the wrapper. Each file is resolved, read as bytes, and hashed once. Strict UTF-8 retained reviewed text is created from those same bytes, and every `psql` execution receives only that retained reviewed text through standard input. The execution path does not reopen the SQL file, eliminating the review-to-execution hash race. Any initial path or hash drift fails closed.

## Synthetic correction boundary

The correction transaction requires database `alpha_data_db`, execution identity `alpha_data_user`, revision `f8d739439ed0`, and exactly these four slugs:

- `alpha-synthetic-cve`
- `alpha-synthetic-advisories`
- `alpha-synthetic-news`
- `alpha-synthetic-uae`

All four checkpoints must be non-null and match the reviewed SHA-256 fingerprint; all four timestamps must be null; associated, successful, running, and correlated run counts must be zero; and no non-target row may share the correction shape. Bounded locks and one serializable transaction protect the check/update boundary. The only update is `checkpoint_value = NULL`, and exactly four affected rows are mandatory. It does not alter timestamps, identity, enablement, schedules, content, provenance, operational history, or run records.

## Validation and evidence

Phase A validation is deliberately offline:

- functional PowerShell tests dot-source the script without invoking main and exercise checkpoint validation, explicit Apply/confirmation gates, real backup-file verification failures, all role states, normalized resume behavior, retained SQL text, hash drift, and SecureString prompt results;
- static tests inspect the exact SQL phases, ownership ordering, prohibited operations, correction boundary, secret handling, and five-file worktree scope;
- PowerShell parsing runs without Preflight or Apply;
- SQL validation reads text only and never invokes `psql`;
- `git diff --check` and complete-file self-review validate the artifacts; and
- sanitized review evidence is packaged outside the repository.

Runtime evidence is limited to safe task/session/checkpoint/revision identifiers, role-state names, Boolean/count database evidence, identifier fingerprints, SQL and backup hashes, the absolute reviewed backup artifact path, gate outcomes, executable exit codes, and a sanitized final status. It excludes credentials, raw checkpoints, raw database identifiers, connection URLs, environment values, SQL errors, stack traces, and backup contents.

## Recovery and limitations

- A failed SQL transaction rolls back its own phase.
- If Prepare succeeds but login verification fails, the legacy ownership and application administrative path remain intact; preserve evidence and investigate rather than Normalize manually.
- If Normalize succeeds but correction fails, the next approved session classifies `normalized`, verifies both dedicated logins, skips role mutation, and retries only the exact correction.
- If correction commits, rollback requires the separately verified backup and separate approval. Never fabricate checkpoint or run history.
- Do not delete/recreate the volume, edit committed migrations, or broaden owner/row matching as recovery shortcuts.
- Phase A cannot prove live PostgreSQL execution semantics, credentials, backup recoverability, later Alembic migrations, authentication, operator controls, or runtime sign-in.
- C08 remains blocked until separately authorized database, migration, and runtime evidence is complete.
