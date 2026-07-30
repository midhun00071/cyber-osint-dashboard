# B1-04 Operational Persistence Contracts

## Scope and checkpoint

B1-04 is based on repository checkpoint
`59b6ce8f67cbf16ecd9924e65e70d9130c509227`. It implements reusable
transaction, idempotency, locking, retry, lifecycle, checkpoint, watermark and
rate-state primitives over the B1-03 compatibility schema. It changes no model,
migration, current writer, source workflow, Prefect deployment, API or frontend.

## Caller-owned transactions

`OperationalPersistenceService` receives an existing SQLAlchemy `Session`.
Every mutation requires an active caller-owned transaction. The service may
select, lock, add and flush, but never begins, commits, rolls back or closes a
transaction/session and never creates a session. Database exceptions become
sanitized persistence failures; the original is retained only by exception
chaining. The caller decides commit or rollback.

## Public service API

| Method | Narrow intent |
| --- | --- |
| `acquire_cycle` | Deterministically acquire/create a scheduled/manual cycle and its `ingestion.cycle.acquired` audit event. |
| `acquire_source_run` | Create attempt zero and sequence-one `acquired` evidence under source no-overlap. |
| `acquire_retry` | Create the immediate next non-branching retry of a terminal operational attempt. |
| `record_persistence_commit` | Save counters and `persistence_committed`; pend progress or atomically finish a `none` source. |
| `complete_non_request` | Finish one closed zero-record skipped/deferred outcome. |
| `complete_partial_or_failure` | Finish a validated `partial`, `failed` or acknowledged `cancelled` attempt. |
| `abandon_pending_progress` | Stop pending recovery explicitly as `failed` or `cancelled`. |
| `advance_checkpoint` | Append the next checkpoint and finalize its pending run. |
| `advance_watermark` | Append a strictly increasing UTC watermark and finalize its pending run. |
| `update_rate_limit_state` | Create/update normalized source/policy state by exact-version compare-and-swap. |

There is no public generic event append or arbitrary status setter.

## Deterministic identities

Keys use SHA-256 over canonical UTF-8 JSON with versioned namespace `b104-v1`.
Database values contain a fixed prefix and 64 lowercase hexadecimal characters:

| Identity | Format | Canonical inputs |
| --- | --- | --- |
| Scheduled cycle | `b104cs-` + hex | safe deployment reference, UTC scheduled slot |
| Manual cycle | `b104cm-` + hex | digest of the bounded opaque manual request value |
| Source attempt | `b104r-` + hex | cycle-key digest, registered source slug, attempt `0..10` |
| Cycle audit | `b104a-` + hex | allow-listed action and target-key digest |

The raw manual request value is never persisted. Keys never use `hash()`,
random data, local time, environment state, database content, URLs, headers,
cookies, tokens or secrets. Advisory identities become deterministic signed
64-bit integers. A hash collision conservatively causes contention.

## Locking, no-overlap and retries

Locking is PostgreSQL-only and fails closed elsewhere. The service calls
`pg_try_advisory_xact_lock` using SQLAlchemy expressions and locks relevant ORM
rows with `SELECT ... FOR UPDATE`. Namespaces are `cycle-idempotency`,
`source-no-overlap`, `progress-identity` and `rate-state-identity`.

Exact duplicate source acquisition returns the committed row without another
event. Otherwise `running` and `checkpoint_pending` rows block a new attempt,
including visible transitional active rows. Concurrent participating writers
cannot start the same source. Existing transitional writers do not acquire the
advisory lock and must not run concurrently with new operational writers until
migrated.

A retry requires a complete terminal operational parent in the same
source/cycle, uses the immediately next attempt, links to that parent and is
bounded at attempt 10. Only the current highest attempt can be retried. Exact
duplicates return the existing retry; stale parents, branches and competing
identities conflict.

## State versions and append-only events

Each lifecycle operation locks the run, rejects compatibility rows, requires
the exact positive `state_version`, increments it once and appends evidence in
the same transaction. Terminal rows never transition again. Event sequence is
reserved while the run row is locked, begins at 1, increases monotonically and
is bounded at 100000. Existing events, audits, progress rows and prior attempts
are never updated or deleted.

## Lifecycle and event mapping

| From | To | Evidence |
| --- | --- | --- |
| creation | `running` | `acquired` |
| `running` | `checkpoint_pending` | `persistence_committed` |
| `running` | `success` / `no_change` for `none` | `persistence_committed`, `completed` |
| `running` | `skipped` | `skipped` |
| `running` | exact deferred status | `deferred` |
| `running` | `partial` | `partial` |
| `running` | `failed` | `failed` |
| `running` | `cancelled` | `cancelled` |
| `checkpoint_pending` | `success` / `no_change` | `checkpoint_advanced`, `completed` |
| `checkpoint_pending` | `failed` / `cancelled` after abandoned recovery | matching terminal event |

Deferred statuses require a matching closed `DeferReason`; unrelated statuses
retain no reason. Target spelling is always `cancelled`.

## Counters and truthful partial failure

`RunCounters` is immutable. Integers are nonnegative and within the model's
signed 32-bit limit. Fetched equals created + updated + unchanged + skipped +
failed, and error count is at least failed. Success requires zero failed and
skipped plus a durable create/update. No-change requires zero create, update,
failed and skipped. Partial requires completed create/update/unchanged work and
at least one skipped/failed item. Failed requires a failed item or explicit
run-level failure. Non-request and cancelled outcomes use zero counters. Empty
or partially processed collections never become success.

## Checkpoint-after-commit, rollback and recovery

For checkpoint/watermark sources, the persistence transaction commits records,
evidence, counters, `checkpoint_pending` and `persistence_committed` first. Only
after that caller commit may a separate caller-owned transaction advance
progress. Advancement locks the run and identity, verifies the registry policy
and persistence event, validates the expected prior head, appends exactly the
next linear version, appends progress/completion evidence and finalizes the run.

An exact retry returns committed progress without another version, event or
transition. A mismatch conflicts. Rollback removes the new progress row and
events and restores the previous pending state/version. B2-05 owns integration
into source flows and runtime recovery orchestration.

Prior commit is enforced by PostgreSQL transaction visibility, not by merely
finding an event in the caller's session. The service reads the fixed
`ingestion_run_events.xmin` system column and requires
`pg_visible_in_snapshot(xmin::text::xid8, pg_current_snapshot())` for the
single `persistence_committed` event. This proves that the event was committed
before the current statement snapshot. Calling `record_persistence_commit`
and checkpoint or watermark advancement in the same transaction therefore
fails closed before progress, finalization evidence or another state-version
change. Advancement succeeds only in a new caller-owned transaction after the
persistence transaction commits.

Checkpoint scope is source with null partition, or partition with one bounded
non-empty key. Names and values are bounded; obvious credential/authorization
material, credential-bearing database URLs and private-key content are rejected
without disclosure. Empty and whitespace-only checkpoint values are rejected;
ordinary opaque non-secret values are preserved exactly. Watermark values are
required and never default. Watermarks must be timezone-aware, normalize to UTC
and strictly increase.

## Rate-state compare-and-swap

Rate state is locked per registered source/policy. Creation requires no row and
produces version 1. Update requires the exact current version and increments
once. Counts and UTC times are normalized; unknowns remain null, remaining
cannot exceed the request limit, and window seconds are bounded to one year.
State is closed to `available`, `limited`, `backoff`, `quota_unavailable` or
`unknown`. An updater run must be complete and source-matched. Raw headers,
cookies, responses and unrestricted metadata are not accepted.

## Sanitized errors and limitations

Public categories are validation, missing record, lock unavailable, conflict,
stale state/version and persistence failure. Messages contain no SQL,
parameters, database URLs, raw exceptions, payloads, checkpoint values, manual
keys, environment values or credentials.

Persisted cycle/run safe summaries accept bounded operational prose but reject
high-confidence secret and unsafe diagnostic content. Rejected content includes
credential-bearing URLs, Authorization values, password/API-key/token/cookie
assignments, private-key blocks, traceback/stack-trace text, obvious raw SQL and
control characters. Unsafe summaries fail validation rather than being redacted
and persisted, and rejected content is never copied into evidence or errors.

- Transitional writers remain unintegrated; only visible active rows are
  checked, so they must not be activated concurrently with operational writers.
- Prefect belongs to B2; B2-05 owns source-flow progress integration/recovery;
  later orchestration owns cycle aggregation/finalization.
- The final non-null/status enforcement migration remains deferred until all
  writers are migrated and independently reviewed.
- B1-05 owns database roles/retention. APR-10 remains pending.
- The documented Windows CRLF predecessor-migration hash issue remains an
  accepted environment limitation under its existing conditions.
