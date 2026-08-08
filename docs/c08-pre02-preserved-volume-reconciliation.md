# C08-PRE-02 preserved-volume reconciliation

## Purpose and current recovery boundary

`C08-PRE-02` provides reviewed, fail-closed reconciliation tooling for the preserved local PostgreSQL volume. Prepare completed during the approved maintenance session. Normalize failed transactionally because `alpha_data_user` is PostgreSQL bootstrap role OID 10 and PostgreSQL will not demote that bootstrap identity from `SUPERUSER`. The failed Normalize transaction did not commit its ownership, privilege, or synthetic-progress changes.

C08 remains blocked. `C08-PRE-02C-01` corrects that demonstrated identity collision in reviewed code only. A future maintenance session must still use a new checkpoint-bound backup, exact post-commit Git checkpoint, approved Apply command, database reconciliation, later migrations, and runtime verification. This document does not claim completed remediation, migration, Administrator bootstrap, authentication, source activation, or ingestion success.

## Frozen data boundary

The preserved volume remains at revision `f8d739439ed0`, with four deterministic development-seed sources at the frozen correction boundary, null last-success timestamps, and no ingestion runs. Prepare created and verified the dedicated bootstrap, migration, read-only, backup, and retention roles without changing ownership. The OID 10 `alpha_data_user` still owns the database, 11 public tables, and 9 public sequences and retains its legacy elevated attributes. C06/C07 schema objects and approved production handler registrations remain absent.

The only authorized `C08-PRE-02C-01` files are:

1. `scripts/c08-pre02-reconcile-preserved-volume.ps1`
2. `database/maintenance/c08-pre02-provision-existing-volume.sql`
3. `backend/tests/test_c08_pre02_reconciliation.py`
4. `docs/c08-pre02-preserved-volume-reconciliation.md`

The frozen `database/maintenance/c08-pre02-correct-synthetic-progress.sql` artifact remains unchanged. No committed migration, application module, environment file, deployment file, source policy, registry, or handler map is changed.

## Reviewed Git checkpoint

The wrapper has no embedded dependency on the original Phase A parent commit. A future reviewer must freeze the commit containing these four `C08-PRE-02C-01` files and pass its full 40-character lowercase post-commit Git checkpoint explicitly:

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

Credentials are not accepted through command-line parameters, files, or environment variables. During a locally attended identity-split Apply, the wrapper calls `Read-Host -AsSecureString` separately for the current application credential, `alpha_data_bootstrap`, and `alpha_data_migration`. The current application credential becomes the replacement `alpha_data_user` credential so existing application configuration remains valid. Enter all values privately in the local terminal and **never paste credentials into chat**.

Each SecureString is converted only immediately before it is written to `psql` standard input. The replacement runtime credential is consumed twice by the reviewed `\password alpha_data_user` metacommand inside the Normalize transaction. The unmanaged plaintext buffer is zeroed and freed in `finally`; managed plaintext references are cleared; the SecureString objects are disposed after use. Credential values are never logged, serialized into evidence, placed in process arguments, or retained as configuration.

## Exact role-state classification

Preflight collects sanitized Booleans, names, and counts and classifies the role boundary exactly:

- `legacy_bootstrap_collision`: database owner `alpha_data_user`, `public` schema owner `pg_database_owner`, `alpha_data_user` is OID 10 with the exact legacy elevated state, managed reconciliation roles are absent, and all 11 tables and 9 sequences are owned by that identity;
- `prepared_bootstrap_collision`: the current live resumable state, where OID 10 remains `alpha_data_user`, the legacy owner/application boundary remains unchanged, all five supporting roles have their exact reviewed attributes and capabilities, and no cluster-bootstrap replacement identity exists yet;
- `normalized`: OID 10 is exactly `alpha_data_cluster_bootstrap` with `SUPERUSER` and `NOLOGIN`; replacement `alpha_data_user` has OID other than 10 and exact least-privilege runtime attributes; database and `public` schema owner is `alpha_data_bootstrap`; all 11 tables and 9 sequences are owned by `alpha_data_migration`; and the cluster bootstrap has no application object ownership or explicit database CONNECT grant; or
- `unexpected`: any owner, count, role attribute, membership, or representative privilege differs from those exact definitions.

Every accepted state also requires zero unexpected managed-role memberships, zero unexpected public object owners, the exact allow-listed names for all 11 public tables and 9 public sequences, no unexpected database CONNECT grantee, and no migration default-ACL drift. `legacy_bootstrap_collision` requires all five supporting roles to be absent, including unsafe variants of the three auxiliary role names. `prepared_bootstrap_collision` requires migration and all three auxiliary roles to have no table or sequence privilege. `normalized` revokes database CONNECT from `PUBLIC`, retains it only for the six operational managed identities, and keeps the fixed object/default-privilege allow lists. `unexpected` always fails closed; the script never overwrites unfamiliar database, schema, table, or sequence ownership.

Resume behavior is deterministic:

- `legacy_bootstrap_collision`: Prepare, securely configure and verify supporting credentials, then Normalize with the securely entered replacement runtime credential;
- `prepared_bootstrap_collision`: securely re-enter the replacement runtime, bootstrap, and migration credentials, verify both supporting logins and migration capability, then Normalize;
- `normalized`: prompt for the existing credentials, verify both logins, skip every role mutation, and proceed only to the still-pending synthetic correction.

A fully corrected second Apply still fails safely because its four checkpoints are already null and no longer meet the exact correction precondition.

## Prepare and Normalize phases

The role SQL requires the explicit fixed `c08_phase` value `prepare` or `normalize`; invalid or missing values fail before a transaction. It never examines password hashes to infer state.

Prepare runs one serializable transaction. It verifies the exact legacy database owner, schema owner, OID 10 application identity, bounded legacy elevated attributes while tolerating the demonstrated historic `REPLICATION` variant, the fixed 11-table/9-sequence name and ownership allow lists, absent managed roles, zero memberships, zero unexpected owners, and no unexpected database CONNECT grantee. It creates the bootstrap, migration, read-only, backup, and retention roles with fixed safe attributes and grants only the CONNECT and schema capabilities needed for verification. It then proves that migration and the auxiliary roles received no object or default privileges. Prepare does not transfer database, schema, table, or sequence ownership, does not revoke application privileges, and does not demote `alpha_data_user`.

After Prepare commits, the wrapper obtains both SecureStrings, configures the new credentials through standard input, verifies both logins using fixed `127.0.0.1:5432` TCP connections, and verifies migration CONNECT plus schema USAGE/CREATE from the migration login itself.

Normalize runs as `alpha_data_bootstrap` only after those checks. Its serializable transaction independently revalidates the exact prepared collision, including OID 10, the supporting bootstrap OID, owner, object-name, object-privilege, membership, database-CONNECT, and default-ACL state. It renames OID 10 to `alpha_data_cluster_bootstrap`, fixes that role at `SUPERUSER NOLOGIN`, creates a new least-privilege `alpha_data_user` with the securely supplied current application credential, and proves the new runtime OID is not 10. It then transfers the database and schema owners, transfers exactly the allow-listed 11 tables and 9 sequences, removes `PUBLIC` and cluster-bootstrap CONNECT grants, applies the six-identity operational CONNECT allow list plus bounded read-only/backup/retention and default privilege rules, and verifies the administrative and migration paths. The final application restriction block removes broad schema/table/sequence privileges, reapplies the explicit runtime allow list, and verifies zero runtime or cluster-bootstrap application ownership.

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

`C08-PRE-02C-01` implementation validation is deliberately non-mutating:

- functional PowerShell tests dot-source the script without invoking main and exercise checkpoint validation, explicit Apply/confirmation gates, real backup-file verification failures, all role states, partial identity-split rejection, normalized resume behavior, retained SQL text, hash drift, and SecureString prompt results;
- static tests inspect the exact SQL phases, ownership ordering, prohibited operations, correction boundary, secret handling, and five-file worktree scope;
- PowerShell parsing runs without invoking main, Preflight, or Apply;
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
- This implementation pass cannot prove the future identity-split transaction, replacement credential, new backup recoverability, later Alembic migrations, authentication, operator controls, or runtime sign-in until the explicitly approved post-commit maintenance session.
- C08 remains blocked until separately authorized database, migration, and runtime evidence is complete.
