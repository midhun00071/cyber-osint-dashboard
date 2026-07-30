# B1-02 Operational Schema Migration Plan

## 1. Purpose and scope

This plan describes how B1-03 can implement the B1-02 operational ingestion and
audit design additively from checkpoint
`4b25a5366ca02d3f94c3e75fec98f0d5dc2b6897`. It creates no Alembic revision and
makes no model, database, deployment, or approval claim.

The B1-02 schema document remains the unchanged final target. Revision
`b103a71d2e4f` is explicitly a compatibility phase: it installs the complete
operational structure while current ingestion writers still use the baseline
run shape and status spellings. It is not the final run-column enforcement
revision.

## 2. Baseline migration inventory

The committed linear baseline is:

| Order | Revision | Parent | Implemented objects |
| ---: | --- | --- | --- |
| 1 | `f8d739439ed0` | Base | Ten initial intelligence, provenance, tag, vulnerability, and ingestion tables. |
| 2 | `a6c9d4e2f107` | `f8d739439ed0` | `indicators`, `indicator_provenances`, and the source-record composite key. |
| 3 | `c4e8b2a91d30` | `a6c9d4e2f107` | `intelligence_item_indicators`; current sole head. |

Alembic imports `app.models`, targets `Base.metadata`, uses type comparison, and
uses a dedicated `NullPool` migration engine. The current metadata contains 13
tables and must remain importable without opening a database connection.

## 3. Immutable migration-history rule

All three committed migration files are immutable. B1-03 must create one new
revision whose `down_revision` is `c4e8b2a91d30`; it must not edit, reformat,
rename, regenerate, squash, reorder, or replace an existing revision. Existing
migration tests and expected hashes must not be weakened or changed to conceal
an environment failure. The result must remain a single linear head.

## 4. Additive migration sequence

Within the new B1-03 revision, use this dependency-safe order:

1. Create independent parent/current-state tables that reference only
   `intelligence_sources`: `ingestion_cycles`,
   `source_credential_references`, and `source_rate_limit_states` (leaving the
   optional updater run FK for a later step).
2. Add nullable extension columns to `ingestion_runs`: `cycle_id`,
   `idempotency_key`, `attempt_number`, `retry_of_run_id`, `state_version`, and
   `defer_reason`.
3. Backfill deterministic legacy cycles and run-extension values.
4. Validate every pre-upgrade backfill, retain the four operational identity
   columns as nullable for current-writer compatibility, and add cycle, retry
   self, source/cycle/attempt, idempotency, composite `(id, source_id)`, and
   composite `(id, cycle_id)` constraints. Add one check that permits only a
   complete operational shape or a fully null compatibility shape.
5. Migrate pre-upgrade legacy status spellings and replace the status check with
   the temporary union of target and baseline-compatible vocabularies, including
   nonterminal `checkpoint_pending`. Preserve every run's `trigger_type`
   unchanged. Baseline spellings remain valid only for a fully transitional row.
6. Create run-dependent tables in order: `ingestion_run_events`,
   `source_checkpoints`, `source_watermarks`, and `quarantined_records`.
7. Add the deferred source-matched updater FK from
   `source_rate_limit_states` to `ingestion_runs`.
8. Extend `ingestion_errors` with nullable safe metadata, validate legacy data,
   and replace the retry check with the bounded form.
9. Create `audit_events` after both cycle and run targets exist.
10. Backfill legacy checkpoint/watermark history and only evidence-supported run
    events; do not relabel legacy terminal runs as `checkpoint_pending`.
11. Add the source/partition partial unique indexes, composite correlation FKs,
    remaining checks, and query indexes only after data validation succeeds.

No table is renamed or dropped. `intelligence_sources`, `ingestion_runs`, and
`ingestion_errors` remain the registry, source-run, and sanitized-failure
foundations.

## 5. New-table ordering

| Order | Table | Dependency reason |
| ---: | --- | --- |
| 1 | `ingestion_cycles` | Parent of evolved runs; no run dependency. |
| 2 | `source_credential_references` | Source-only provider-neutral metadata. |
| 3 | `source_rate_limit_states` | Source-only initially; updater FK added after run extension. |
| 4 | `ingestion_run_events` | Requires evolved `ingestion_runs`. |
| 5 | `source_checkpoints` | Requires run composite key and self-history constraint. |
| 6 | `source_watermarks` | Same dependency as checkpoints. |
| 7 | `quarantined_records` | Requires source-matched run and optional event. |
| 8 | `audit_events` | Optional cycle/run correlations require both parents. |

Downgrade reverses this order and removes optional FKs/indexes before their
tables or columns.

## 6. Existing-table extension ordering

### `ingestion_runs`

Add columns nullable first. Create one deterministic `legacy_import` cycle per
existing run, using its public ID as input to bounded non-secret legacy
idempotency keys. Runtime cycle creation remains restricted to `scheduled` or
`manual`; `legacy_import` is migration-only. Preserve the existing
`ingestion_runs.trigger_type` unchanged and do not invent `scheduled_for` or
retry ancestry. Set `cycle_id` to that cycle, `attempt_number=0`,
`retry_of_run_id=NULL`, `state_version=1`, and a deterministic source-run key.
Map run `succeeded` to `success` and `canceled` to `cancelled`.

At the `b103a71d2e4f` head, rows inserted before upgrade use the fully backfilled
operational shape. During the bounded compatibility phase, unchanged current
writers may insert a second explicit shape with `cycle_id`, `idempotency_key`,
`attempt_number`, `retry_of_run_id`, `state_version`, and `defer_reason` all
null and status limited to `running`, `succeeded`, `partial`, `failed`, or
`canceled`. The named
`ck_ingestion_runs_operational_or_compatibility_shape` constraint rejects every
mixed or partially populated shape. `checkpoint_pending` and every target-only
status require the complete operational shape. No automatic cycle or
idempotency fallback is allowed, and no attempt or state-version default may
synthesize a partial identity.

Derive cycle `started_at` and `completed_at` directly from the run. Set
`sources_expected=1` and `sources_started=1`. A running run produces a running
cycle with `sources_completed=0`, `sources_successful=0`,
`sources_non_successful=0`, and null `completed_at`. A terminal run produces a
terminal cycle with `sources_completed=1`; mapped success sets
`sources_successful=1` and `sources_non_successful=0`, while partial, failed, or
cancelled sets the inverse. Stop if a terminal legacy run lacks a valid
completion time. One legacy cycle per run deliberately preserves standalone
evidence and does not claim to reconstruct historical parent grouping.

### `ingestion_errors`

Add `failure_stage`, `diagnostic_fingerprint`, and `safe_context` nullable.
Existing rows remain valid without fabricated stage/fingerprint context.
Validate existing `retry_count` values before replacing the nonnegative check
with the bounded `0..10` check. Add safe identifier/fingerprint checks only if
validation proves every existing value conforms; otherwise B1-03 must stop and
report exact rows/categories rather than rewrite evidence silently.

### `intelligence_sources`

Do not remove or repurpose `checkpoint_value` or
`last_successful_fetch_at` in the first additive revision. Backfill normalized
history, keep compatibility explicit, and defer authoritative cutover/removal
to separately reviewed service work after B2-05 evidence.

## 7. Constraint and index ordering

For every table: create columns/table and primary key; backfill; validate;
create foreign keys; create named checks; create named unique constraints or
unique indexes; then create non-unique query indexes. Build high-impact indexes
with the deployment-safe method selected by B1-03/B9 work; Alembic transaction
handling must be explicit if concurrent PostgreSQL indexes are used.

Source-matched composite FKs depend on
`uq_ingestion_runs_id_source_id`; audit run/cycle correlation depends on
`uq_ingestion_runs_id_cycle_id`; quarantine event correlation depends on
`uq_ingestion_run_events_id_run_id`. Checkpoint/watermark predecessor FKs also
depend on unique `(id, source_id)` pairs in their own tables. Install
previous-row uniqueness only after deterministic chains validate. Status checks
are replaced only after legacy spelling conversion. No constraint is marked
valid before its data has been checked.

PostgreSQL treats nulls as distinct in an ordinary unique constraint, so a
single identity constraint containing nullable `partition_key` is prohibited.
Create these four partial unique indexes exactly:

- `uq_source_checkpoints_source_identity_version` on
  `(source_id, checkpoint_name, version) WHERE scope_kind = 'source' AND
  partition_key IS NULL`;
- `uq_source_checkpoints_partition_identity_version` on
  `(source_id, partition_key, checkpoint_name, version) WHERE scope_kind =
  'partition' AND partition_key IS NOT NULL`;
- `uq_source_watermarks_source_identity_version` on
  `(source_id, watermark_name, version) WHERE scope_kind = 'source' AND
  partition_key IS NULL`; and
- `uq_source_watermarks_partition_identity_version` on
  `(source_id, partition_key, watermark_name, version) WHERE scope_kind =
  'partition' AND partition_key IS NOT NULL`.

Each uses the columns and predicates specified by the schema design. The
identity prefix plus a backward B-tree scan on `version` serves latest-version
lookup; add no redundant latest index without B1-05 plan evidence. Tests must
prove duplicate identity/version rows are rejected independently in both
scopes and that blank partition identities fail the scope check.

Create correlation FKs with these exact column pairs:

- checkpoint/watermark `(advanced_by_run_id, source_id)` to
  `(ingestion_runs.id, ingestion_runs.source_id)`;
- checkpoint `(previous_checkpoint_id, source_id)` to
  `(source_checkpoints.id, source_checkpoints.source_id)` and the equivalent
  watermark pair;
- rate state `(updated_by_run_id, source_id)` to
  `(ingestion_runs.id, ingestion_runs.source_id)`;
- quarantine `(ingestion_run_id, source_id)` to the same run/source pair and
  `(ingestion_run_event_id, ingestion_run_id)` to
  `(ingestion_run_events.id, ingestion_run_events.ingestion_run_id)`; and
- audit `(ingestion_run_id, cycle_id)` to
  `(ingestion_runs.id, ingestion_runs.cycle_id)`, with a check requiring non-null
  cycle whenever run is non-null.

Retry lineage uses both `(retry_of_run_id, source_id)` and
`(retry_of_run_id, cycle_id)` composite FKs. Nullable FK components retain
normal PostgreSQL semantics; row-local shape checks close any consistency gap.
All listed advancement, predecessor, rate-state, quarantine, and retry
composite FKs use `ON DELETE RESTRICT`. The audit run/cycle composite FK uses
`ON DELETE SET NULL` for both correlation columns, while bounded target fields
preserve append-only meaning.

The complete new/evolved integrity-object manifest is:

- cycles: `uq_ingestion_cycles_idempotency_key`,
  `ck_ingestion_cycles_trigger_type_allowed`,
  `ck_ingestion_cycles_trigger_schedule_consistency`,
  `ck_ingestion_cycles_status_allowed`,
  `ck_ingestion_cycles_status_time_consistency`,
  `ck_ingestion_cycles_completed_at_order`,
  `ck_ingestion_cycles_counters_non_negative`,
  `ck_ingestion_cycles_counter_relationships`;
- runs: `uq_ingestion_runs_idempotency_key`,
  `uq_ingestion_runs_source_cycle_attempt`,
  `uq_ingestion_runs_id_source_id`, `uq_ingestion_runs_id_cycle_id`,
  `fk_ingestion_runs_retry_source`, `fk_ingestion_runs_retry_cycle`,
  `ck_ingestion_runs_attempt_number_bounded`,
  `ck_ingestion_runs_retry_lineage_consistency`,
  `ck_ingestion_runs_operational_or_compatibility_shape`,
  `ck_ingestion_runs_status_allowed`,
  `ck_ingestion_runs_status_time_consistency`;
- run events: `uq_ingestion_run_events_run_sequence`,
  `uq_ingestion_run_events_id_run_id`,
  `ck_ingestion_run_events_sequence_bounded`,
  `ck_ingestion_run_events_event_type_allowed`,
  `ck_ingestion_run_events_transition_shape`,
  `ck_ingestion_run_events_created_at_order`;
- checkpoints: `uq_source_checkpoints_source_identity_version`,
  `uq_source_checkpoints_partition_identity_version`,
  `uq_source_checkpoints_id_source_id`, `uq_source_checkpoints_previous`,
  `fk_source_checkpoints_advanced_run_source`,
  `fk_source_checkpoints_previous_source`,
  `ck_source_checkpoints_scope_identity`,
  `ck_source_checkpoints_version_positive`,
  `ck_source_checkpoints_commit_order`;
- watermarks: `uq_source_watermarks_source_identity_version`,
  `uq_source_watermarks_partition_identity_version`,
  `uq_source_watermarks_id_source_id`, `uq_source_watermarks_previous`,
  `fk_source_watermarks_advanced_run_source`,
  `fk_source_watermarks_previous_source`,
  `ck_source_watermarks_scope_identity`,
  `ck_source_watermarks_version_positive`,
  `ck_source_watermarks_commit_order`;
- rate state: `uq_source_rate_limit_states_source_policy`,
  `fk_source_rate_limit_states_run_source`,
  `ck_source_rate_limit_states_counts_valid`,
  `ck_source_rate_limit_states_window_bounded`,
  `ck_source_rate_limit_states_version_positive`;
- errors: `ck_ingestion_errors_retry_count_bounded`,
  `ck_ingestion_errors_diagnostic_fingerprint_format`;
- quarantine: `uq_quarantined_records_run_key`,
  `fk_quarantined_records_run_source`,
  `fk_quarantined_records_event_run`,
  `ck_quarantined_records_key_format`,
  `ck_quarantined_records_sizes_bounded`,
  `ck_quarantined_records_status_allowed`,
  `ck_quarantined_records_reviewed_at_consistency`;
- audit: `uq_audit_events_idempotency_key`,
  `fk_audit_events_run_cycle`, `ck_audit_events_run_cycle_consistency`,
  `ck_audit_events_actor_type_allowed`, `ck_audit_events_action_format`,
  `ck_audit_events_target_type_format`,
  `ck_audit_events_target_ref_length`, `ck_audit_events_outcome_allowed`,
  `ck_audit_events_created_at_order`; and
- credential references:
  `uq_source_credential_references_source_name_purpose`,
  `ck_source_credential_references_state_allowed`,
  `ck_source_credential_references_configured_shape`,
  `ck_source_credential_references_rotation_expiry_order`,
  `ck_source_credential_references_updated_at_order`.

## 8. Nullable first-stage columns

Nullable-first is required for `ingestion_runs.cycle_id`,
`ingestion_runs.idempotency_key`, `ingestion_runs.attempt_number`, and
`ingestion_runs.state_version` so deployed old code can coexist during the
migration transaction and deterministic backfill. `retry_of_run_id` and
`defer_reason` remain nullable by design. New `ingestion_errors` metadata also
remains nullable because old evidence cannot be reconstructed honestly.

Revision `b103a71d2e4f` intentionally ends with `cycle_id`, `idempotency_key`,
`attempt_number`, and `state_version` nullable so current writers do not fail
between structural deployment and B1-04-compatible writer rollout. PostgreSQL
null semantics intentionally allow multiple transitional rows with null
idempotency and source/cycle/attempt identities. The shape constraint prevents
those nulls from being mixed with a partial operational identity. No partial
automatic identity is created.

Final non-null and status enforcement is deferred until compatible writers
exist. B1-04-compatible writers must always create the complete operational
target shape and B1-04 owns writer lifecycle behavior. A later separately
reviewed enforcement migration owns final enforcement and must:

1. stop old writers;
2. identify and deterministically backfill every transitional row;
3. create truthful `legacy_import` cycles where needed;
4. map `succeeded` to `success` and `canceled` to `cancelled`;
5. verify that no mixed or transitional rows remain;
6. make `cycle_id`, `idempotency_key`, `attempt_number`, and `state_version`
   non-null; and
7. replace the compatibility status/shape checks with the final B1-02 target
   checks.

That follow-on migration receives no revision ID in B1-03.

## 9. Deterministic backfills

- Create exactly one migration-only `legacy_import` cycle for each existing run,
  ordered by run ID. Derive its key from a fixed legacy namespace plus the run
  public ID; do not use clock time, random values, environment data, or source
  content. Preserve the original run trigger, leave `scheduled_for` null, copy
  run times, and apply the exact status/counter rules in section 6.
- Derive each run key from a fixed legacy namespace plus its public ID. Assign
  attempt zero and state version one; leave retry ancestry null.
- Add `acquired` and, where evidenced, the matching terminal event with stable
  sequence numbers based on existing run status/times. Do not fabricate
  `persistence_committed`, `checkpoint_advanced`, `checkpoint_pending`, an
  intermediate transition, a schedule, or retry ancestry.
- For a non-null legacy source checkpoint, insert version one under the
  developer-controlled name `legacy_default`, source scope, and correlate it to
  the most recent eligible successful run only when the source/run relation and
  timestamp can be proven. Otherwise record a migration validation exception
  and stop; do not invent an advancing run.
- For a non-null `last_successful_fetch_at`, insert a version-one success
  watermark only when an eligible run can be deterministically correlated.
- Do not backfill credential references, quota counts, quarantine, or actor
  audit events with guessed data.

Backfills must be rerunnable in an isolated migration test without creating
duplicates. Counts before and after are reconciled by table and source.

## 10. Validation queries

B1-03 must implement parameterized/read-only validation that reports counts and
safe IDs only, never source payloads, checkpoint values, messages, actor details,
credential references, environment data, or database connection information.
Validate:

- one Alembic head and expected revision ancestry;
- no null operational identity fields on rows that existed before upgrade, and
  no mixed compatibility/operational row shapes at the head;
- cycle and run idempotency uniqueness;
- one `legacy_import` cycle for every legacy run and one run for every such
  cycle, unchanged run triggers, null legacy schedules/retry ancestry, copied
  times, and exact single-run counter/status mappings;
- unique `(source_id, cycle_id, attempt_number)`;
- valid status spellings, nonterminal `checkpoint_pending`, status/completion
  time shape, cycle counter relationships, retry bounds, and event sequence;
- no orphan or source-mismatched run/checkpoint/watermark/rate/quarantine FK,
  no quarantine event from another run, and no audit run/cycle mismatch;
- rejection of duplicate source-scope and partition-scope
  checkpoint/watermark identity/version rows under the four partial indexes;
  valid non-empty partition scope, linear source-matched predecessor chains,
  monotonic versions, and commit order;
- quota/rate counter relationships;
- failure and fingerprint checks plus quarantine `octet_length` equality,
  4096-byte maximum, original/stored relationship, and review-state shape;
- no secret-shaped column names or unrestricted payload columns in new tables;
- retained counts for all 13 baseline tables; and
- model metadata and migrated database table/constraint/index agreement.

## 11. Upgrade verification

Run B1-03 focused model/migration tests first, then upgrade a fresh PostgreSQL
database from base to head and a representative database from
`c4e8b2a91d30` to the new head. Verify the new head, linear history, all target
tables, named constraints, indexes, FK actions, deterministic backfills,
metadata registration, and zero unexpected tables. Exercise duplicate,
constraint, concurrent acquisition, commit failure, rollback, retry,
checkpoint, watermark, and downgrade tests owned by B1-03/B1-04 as applicable.

Repository-static compilation is necessary but not sufficient for final
acceptance; migrated PostgreSQL inspection is required by the release scope.

## 12. Downgrade expectations

Downgrade is for controlled pre-release rollback, not routine data deletion. It
must drop new indexes/constraints/FKs before dependent tables/columns and restore
legacy `ingestion_runs` status spellings/check constraints. Before removing
target-only evidence, it must fail closed unless the operator has an approved
backup/export and confirms no target-only cycles, retries, events, checkpoint
versions, quarantine decisions, or audit evidence must be preserved.

Where target semantics cannot be represented in the legacy schema, downgrade
is intentionally lossy and must be documented and rehearsed in isolation. It
must never collapse a partial/failed/deferred attempt into legacy success or
select a checkpoint from an uncommitted/failed run.

Downgrade must fail closed while any run is `checkpoint_pending`; that state
cannot be truthfully mapped to legacy success. Recovery must first finish the
atomic progress/finalization transaction or an authorized separate transaction
must abandon recovery as `failed`/`cancelled`. Dropping `legacy_import` cycles
does not alter the preserved run trigger; no schedule or retry lineage is
written back.

Baseline-compatible transitional rows may downgrade when all six compatibility
extension fields are null, their statuses use only the baseline vocabulary, and
they have no target-only cycle, event, progress, audit, quarantine, credential,
or rate-state evidence. Before dropping ingestion-error extension columns,
downgrade must fail closed with sanitized category
`target_only_ingestion_error_metadata` if any row has non-null `failure_stage`,
`diagnostic_fingerprint`, or `safe_context`; metadata values must never appear
in migration output.

## 13. Rollback and partial-deployment handling

- Alembic failure inside transactional DDL rolls back and leaves the prior head
  authoritative. Readiness remains false until the expected head and constraints
  are present.
- If an index requires a non-transactional phase, split it into an explicitly
  observable deployment step with idempotent existence/validity checks; do not
  report migration success early.
- Application rollout remains compatible with the fully null baseline writer
  shape at the new head. No automatic cycle, idempotency key, attempt, version,
  or status conversion is permitted for new inserts. New B1-04 writers activate
  only after the head and compatibility constraint are confirmed.
- For a required progress contract, new writers commit records, provenance,
  outcomes, safe failures/quarantine, counters, `checkpoint_pending`, and
  `persistence_committed` together. A later atomic transaction validates that
  run/source/version, inserts progress and `checkpoint_advanced`, then records
  terminal `success`/`no_change`, `completed_at`, and `completed`. It never
  commits terminal success first.
- If that later commit fails, the run remains `checkpoint_pending` and the prior
  progress row remains authoritative. Idempotent recovery reuses the same
  deterministic identity; only explicit recovery abandonment may separately
  record `failed`/`cancelled`. A source may complete directly only when its
  fixed policy declares `progress_contract=none` before acquisition.
- If application deployment fails after schema upgrade, roll back application
  code only when compatibility is proven; retain additive schema and evidence.
- Restore from a protected backup rather than editing committed revisions or
  hand-rewriting evidence.
- Any uncertain backfill, constraint failure, or source mismatch is a failed
  deployment with sanitized diagnostics, not an accepted partial success.

## 14. Model registration

B1-03 adds models for all eight new tables, extends the three retained
foundations where specified, exports new models from `app.models`, and keeps
imports database-free. Relationships must match FK deletion rules without
ambiguous joins or unsafe `repr`. `Base.metadata` must contain the 21 expected
target tables and no speculative tables. Alembic autogenerate output is reviewed
line by line; generated output is not accepted without comparison to this
design.

## 15. Test requirements for B1-03

B1-03 tests must cover:

- exact columns/types/nullability/defaults for new and evolved models;
- a parameterized exact-name assertion for every check, unique index/constraint,
  and FK in the complete section 7 integrity-object manifest, including its
  columns, predicates, targets, and deletion behavior;
- mapper registration and PostgreSQL compilation without connection;
- one linear revision after `c4e8b2a91d30` and immutable prior bytes;
- fresh upgrade/downgrade and existing-head upgrade/downgrade;
- deterministic and rerunnable `legacy_import` backfills with unchanged run
  trigger, no fabricated schedule/retry ancestry or historical grouping, copied
  times, and exact running/terminal counter/status mappings;
- duplicate cycle/run acquisition, bounded attempts/sequences/counters/sizes;
- valid/invalid cycle counter relationships and cycle/run status-completion-time
  shapes, including nonterminal `checkpoint_pending`;
- ORM persistence using the unchanged current-writer shape, including its
  `running -> succeeded` update, null operational identity, and proof that no
  cycle or key is fabricated; rejection of mixed rows and target-only statuses
  without operational identity; and acceptance of a complete target row;
- `running -> checkpoint_pending -> success|no_change` with terminal evidence
  only in the atomic progress transaction, direct completion only for
  `progress_contract=none`, advancement failure retaining
  `checkpoint_pending`, idempotent recovery, and explicit abandonment;
- rejection of duplicate source-scope and partition-scope checkpoint/watermark
  identity/version rows under all four partial unique indexes and rejection of
  blank partition keys under PostgreSQL null semantics;
- source-matched checkpoint, watermark, predecessor, and rate-state references;
  source-matched quarantine runs, same-run quarantine events, and run/cycle-
  consistent audit correlation;
- exact run-event vocabulary and transition shapes;
- quarantine PostgreSQL `octet_length` equality, size limits, nonnegative
  counts, original-byte relationship, and review-state consistency;
- monotonic version and fork rejection under the B1-04 service boundary;
- commit/rollback/checkpoint-after-commit failure paths;
- append-only run/audit event permissions or service behavior;
- exact credential-reference configured-shape cases, timestamp order,
  provider-neutral metadata, and secret-canary scans; and
- metadata-to-migrated-database reconciliation.
- fail-closed downgrade for each non-null ingestion-error metadata field,
  preservation of the head and evidence after refusal, successful downgrade
  when all three fields are null, and controlled transitional-row downgrade.

Existing tests must not be weakened. No live source request is needed.

## 16. Deployment sequencing

1. Confirm clean `dev`, approved checkpoint, backup, and one current head.
2. Run focused static/model/migration tests.
3. Apply and verify the new revision in an isolated PostgreSQL environment.
4. Exercise upgrade, validation, downgrade, restore, and re-upgrade.
5. Apply the additive revision to staging while old writers are stopped or a
   proven compatibility window is active.
6. Verify head, objects, safe counts, constraints, and query plans.
7. Deploy B1-04-compatible writers that always create the operational target
   shape; keep legacy checkpoint compatibility until B2-05 reconciliation
   passes.
8. In a separately reviewed follow-on migration, stop old writers, backfill any
   transitional rows, and enforce the final non-null/status target only after
   compatible-writer evidence passes.
9. Enable Prefect work only under B2 ownership and required approvals.
10. Monitor sanitized migration/application evidence and keep a rollback/restore
   decision point before external access.

## 17. Known Windows CRLF raw-byte limitation

`test_ioc_relationship_migration.py` records raw SHA-256 values for the first
two committed migration files. On Windows, a checkout that converts line
endings can fail those raw-byte assertions even when migration semantics and Git
content are unchanged. This is an accepted limitation only when it is the sole
backend failure, no migration file changed, no expected hash changed, the
Alembic head/history and semantic migration tests pass, and all B1-02
documentation tests pass. Do not edit migration bytes, tests, hashes, or Git
line-ending configuration to hide it.

## 18. Ownership and limitations

B1-03 owns model and migration implementation. B1-04 owns transaction, locking,
idempotency, lifecycle and monotonicity services, including compatible writer
behavior. A later separately reviewed migration owns final run-column and status
enforcement after old writers stop. B2 owns Prefect execution;
B2-05 owns checkpoint advancement after committed persistence. Later API/UI
tasks own read exposure. APR-10 remains pending and no credential provider is
approved here.

This plan is not a migration implementation, approval, deployment, or claim of
runtime success. Exact production retention, database role grants, rollout
window, and provider/delivery choices remain deferred to their assigned tasks
and approvals.
