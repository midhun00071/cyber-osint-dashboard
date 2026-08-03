# C01 Prefect orchestration core

## Frozen identity

- Bundle: C01 — Prefect orchestration core
- Official tasks: B2-02, B2-03, B2-04, and B2-05
- Branch: `dev`
- Authoritative starting checkpoint: `d8fbb77feb82885acb6adf386ecba5eff57c12f1`
- Starting `origin/dev`: `d8fbb77feb82885acb6adf386ecba5eff57c12f1`
- Starting divergence: `0/0`
- Starting working tree and index: clean and unstaged

C01 builds on the historical B2-01 self-hosted Prefect platform. It does not
modify migrations or ORM models, convert a source collector, make a live source
request, register a deployment automatically, or activate a schedule.

## Task mapping

| Official task | C01 implementation |
| --- | --- |
| B2-02 | Immutable result, eligibility, attempt, counter, metric, retry, quota, failure, progress, handler, persistence, and deployment contracts; generic source and parent flows; exact Prefect 3.8.1 dependency. |
| B2-03 | Fixed parent flow and deployment identities, deterministic enabled-source ordering, one policy evaluation per source, bounded staggering, isolated source results, evidence-backed cycle finalization, and one two-hour cron schedule specification. |
| B2-04 | Closed transient/permanent failure classification, policy-bounded retry delays and attempts, provider quota/backoff outcomes, deployment concurrency one, and database-backed per-source exclusion. |
| B2-05 | Typed checkpoint/watermark snapshots and proposals, separate durable-persistence and progress transactions, stale-version rejection, unchanged-progress detection, checkpoint-pending recovery, and fail-closed conflicting evidence. |

## Architecture and responsibility boundaries

`backend/app/orchestration/contracts.py` owns only immutable, source-neutral
contracts and the developer-controlled policy registry. It has no source client,
credential, header, cookie, arbitrary URL, provider payload, session, ORM
mutation, or Prefect API call.

`backend/app/orchestration/persistence.py` owns short SQLAlchemy transactions.
It delegates mutations to `OperationalPersistenceService` and maps ORM evidence
to typed flow contracts. Prefect flow bodies do not issue SQL, mutate models,
commit, roll back, close sessions, or construct external source clients.

`backend/app/orchestration/flows.py` owns the generic source execution algorithm
and parent aggregation. It depends on `SourceHandler` and `PersistenceAdapter`
protocols. The production handler mapping is immutable and empty in C01. Unit
tests inject deterministic handlers and persistence fakes; C02 must supply real,
separately approved bindings.

`backend/app/orchestration/deployments.py` owns the fixed deployment contract,
activation validation, duplicate-schedule checks, and explicit registration
CLI. The CLI does not collect source data.

The worker image copies only `backend/requirements.txt` and `backend/app` into
the fixed `/opt/alpha-data/backend` work directory, with
`PYTHONPATH=/opt/alpha-data/backend`. Both Prefect services retain fixed
UID/GID `10001:10001`. No source bind mount, Docker socket, privileged mode, or
host network is added.

## Fixed flow and deployment identity

| Field | Value |
| --- | --- |
| Parent flow | `alpha-data-parent-ingestion-cycle` |
| Source flow | `alpha-data-source-ingestion` |
| Deployment | `alpha-data-ingestion-cycle` |
| Stable deployment reference | `alpha-data-ingestion-cycle` |
| Work pool | `alpha-data-process` |
| Cron | `17 */2 * * *` |
| Timezone | `Asia/Dubai` |
| Deployment concurrency | `1`, collision strategy `CANCEL_NEW` |
| Default registration state | Paused |

The Prefect APIs used by this implementation were inspected directly in the
pinned local `prefecthq/prefect:3.8.1-python3.13` image. The implementation uses
`RunnerDeployment.from_flow`, `CronSchedule`, and `ConcurrencyLimitConfig`
signatures present in Prefect 3.8.1.

The deployed parent obtains cycle identity from the Prefect 3.8.1 flow-run
context's `expected_start_time`. An explicit timestamp remains available for
deterministic tests and approved direct invocation, but it must represent
minute 17 of an even `Asia/Dubai` hour with zero seconds and microseconds. A
deployed run rejects an explicit value that differs from its authoritative
expected start. Validation occurs in Dubai time before normalization to UTC;
no current-clock field replacement or inferred future slot is used. Delayed
execution and reruns therefore retain the original scheduled idempotency slot.

## Source policies and bindings

Every enabled implemented source returned by the existing source registry has
exactly one immutable policy. Policy construction rejects an unknown or
duplicate slug, an incomplete policy set, unsafe names, concurrency other than
one, attempt counts above ten, non-monotonic or excessive retry delays, stagger
delays above 300 seconds, unsupported progress shapes, and execution bounds
above one hour.

Policies are returned in canonical slug order. Each policy fixes:

- scheduled or manual-only eligibility;
- source concurrency one;
- three total attempts with 30- and 60-second exponential delays;
- a deterministic zero-to-50-second stagger in five-second increments;
- one safe quota policy key;
- no-progress, checkpoint, or watermark storage;
- the typed progress kind; and
- a 900-second source execution bound.

The production source subflow accepts only the serializable source slug, cycle
identity, and scheduled timestamp. Prefect parameter validation remains enabled
and the flow has a fixed 900-second timeout. The internal typed boundary also
validates policy, positive cycle identity, aligned slot, handler protocol, and
persistence protocol before acquiring a run. Handler execution uses Prefect's
same-thread timeout context rather than returning while background work
continues.

Existing manual-catalogue families remain manual-only and evaluate to
`approval_pending` without calling a handler. Scheduled-eligible sources with a
missing binding evaluate to `failed`, never success. Credential, licence,
approval, disabled, quota, and rate-limit outcomes stay distinct.

## Result and failure behavior

The exact source result vocabulary is:

```text
success
no_change
skipped
deferred_quota
approval_pending
disabled
credentials_missing
licence_required
rate_limited
partial
failed
cancelled
```

Only explicitly classified timeout, temporary connection, provider rate limit,
retryable server response, and persistence contention categories are transient.
Validation, unsupported content, invalid policy, missing credential, missing
licence, approval requirement, unsafe input, permanent provider rejection, and
contract violation are permanent. Unknown exceptions become permanent contract
violations with a fixed safe message; raw exception text is not retained.

Provider rate-limit observations stop the current attempt and remain
`rate_limited`. A policy-level unavailable quota remains `deferred_quota`.
Permanent failures do not retry. A retry always uses the prior terminal run as
its immediate parent, so history cannot branch. The database schema permits
attempt numbers through ten; C01 policies use only three attempts.

Diagnostics are printable, bounded to 500 characters, and screened for
credential fields, authorization/cookie values, URLs, stack traces, and SQL.
Counters and metrics are immutable, integer-only, bounded, and reconciled.

## Parent cycle and no-overlap behavior

The parent reads all enabled implemented policies in slug order, acquires or
reuses the scheduled cycle key for the supplied slot, evaluates every policy,
applies deterministic staggering, and isolates each source result. After all
evaluations, it reads the latest committed attempt for every started source and
derives started, completed, successful, non-successful, and incomplete counts
from that evidence. An in-memory exception is never counted as a terminal run.
`success` requires every expected source to have committed `success` or
`no_change`; mixed completed or incomplete evidence becomes `partial` when at
least one source succeeded, otherwise `failed`; committed cancellation makes
the cycle `cancelled`.

Scheduled acquisition first resolves the exact slot-specific idempotency key.
Before a new slot is inserted, one fixed PostgreSQL advisory-lock identity
serializes all scheduled acquisitions and a deterministic row-lock check rejects
the new slot when another scheduled cycle is running. Rejection occurs before
the cycle and acquisition audit are inserted. A completed terminal scheduled
cycle does not block a later slot, and manual acquisition remains independent.

`OperationalPersistenceService.finalize_cycle` requires an active
caller-owned PostgreSQL transaction, locks the cycle, validates bounded counter
relationships and terminal status, reconstructs the latest attempt for every
source, and requires the supplied aggregate counters to match that committed
evidence. Exact repeated finalization is idempotent; changed status, counters,
summary, or explicit completion time conflicts. Cancelled finalization requires
a committed cancelled latest attempt unless the cycle is genuinely incomplete;
all-success evidence cannot be cancelled. Finalization retains a defensive
overlap check for historical or externally introduced inconsistent evidence.
Prefect deployment concurrency one remains the outer no-overlap boundary, while
PostgreSQL advisory locking and active-run checks supply the database boundary.

The service never commits, rolls back, closes a session, or hides a transaction.
Rollback leaves no final cycle state.

## Progress transaction ordering and recovery

Supported typed progress kinds are ETag, Last-Modified, modified-since UTC
timestamp, source cursor, pagination token, and content hash. Opaque values are
bounded to 500 printable characters and are never logged. Time progress must be
timezone-aware and is normalized to UTC.

The required order is:

1. The C02 handler persists normalized source data in its own durable
   transaction and returns only after commit.
2. The orchestration persistence adapter records reconciled persistence
   evidence in a separate caller-owned transaction.
3. A progress-enabled run becomes `checkpoint_pending`; it is not terminal
   success.
4. A later transaction verifies that the persistence event is visible in a
   prior PostgreSQL snapshot, compares the expected progress version, advances
   the existing `SourceCheckpoint` or `SourceWatermark` chain, and finalizes the
   run atomically.

A crash before source-data commit leaves both operational progress and terminal
success unchanged. A crash after source-data commit but before the operational
commit leaves no fabricated orchestration evidence. A crash after the
operational commit but before progress advancement leaves `checkpoint_pending`.
On reuse, the handler must reconstruct a proposal against the already committed
counters; only the exact expected storage, kind, name, and previous version can
advance. A transient reconstruction failure leaves `checkpoint_pending`
unchanged and safely resumable. Cancellation or a permanent reconstruction
conflict becomes terminal only through the explicit
`abandon_pending_progress` persistence transition. Stale versions and
conflicting evidence fail closed.

Repeated checkpoint text or an equal watermark is detected. It can finalize
only a true `no_change` run and does not append a duplicate progress row.
Created/updated work paired with unchanged progress conflicts. Partial, failed,
cancelled, deferred, and non-request outcomes cannot carry a progress proposal.
Rollback cannot leave a checkpoint, watermark, terminal success, or cycle
completion.

## Deployment validation and registration

Registration uses fixed developer-controlled names and produces one deployment
with one cron schedule. An existing deployment must have exactly one matching
cron/timezone schedule; zero, duplicate, non-cron, or conflicting schedules fail
before apply. Reapplying the same fixed definition is idempotent. Compose starts
only the server and worker and never invokes registration.

Activation fails unless all of these conditions hold:

- `--activate` was supplied;
- `APP_ENV` is exactly `staging`;
- `--confirm-controlled-staging-evidence` was supplied;
- the fixed `alpha-data-process` pool exists, is a non-paused process pool;
- every scheduled-eligible source has a valid handler binding; and
- no unknown binding is configured.

C01's production binding registry is empty, so activation is intentionally
unavailable. No live schedule was activated during C01.

## Offline validation and paused registration commands

Run focused tests from `backend` so the existing `app` package layout resolves:

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
    tests\test_orchestration_contracts.py `
    tests\test_orchestration_persistence.py `
    tests\test_orchestration_flows.py `
    tests\test_orchestration_deployments.py `
    tests\test_operational_persistence_service.py `
    tests\test_prefect_platform.py
```

Validate Compose without printing resolved values:

```powershell
docker compose config --quiet
docker compose -f compose.prod.yml --env-file <protected-validation-env> config --quiet
```

Build and inspect the worker without running a source workflow:

```powershell
docker compose build prefect-worker
docker run --rm --entrypoint python alpha-data-prefect:3.8.1-python3.13 `
    -c "import os; import app.orchestration; from app.orchestration.flows import parent_ingestion_cycle; from app.orchestration.deployments import deployment_specification; print(os.getuid(), os.getgid(), parent_ingestion_cycle.name, deployment_specification())"
```

After the local server and worker are healthy, explicit paused registration is:

```powershell
docker compose exec -T prefect-worker python -m app.orchestration.deployments
docker compose exec -T prefect-worker `
    prefect deployment inspect alpha-data-parent-ingestion-cycle/alpha-data-ingestion-cycle
```

Do not add `--activate` in C01. Registration is not required for offline unit or
image-import validation and was not executed as implementation evidence.

## Validation evidence

- Consolidated C01 hardening focused command: `143 passed in 3.55s`.
- PostgreSQL-focused test result, full backend result, mapper/Alembic checks,
  Compose validation, worker-image import/runtime result, and `run.cmd test`
  evidence are recorded in the final task report after the complete validation
  sequence.
- No external source request and no Prefect deployment activation occurred.

## Limitations and follow-ups

- C02 must implement and review real approved source handlers, including their
  durable source-data transactions, bounded clients, offline fixtures, and
  source-specific progress reconstruction.
- C07 owns authenticated operator controls for manual run, pause, retry, enable,
  and disable actions.
- C11/deployment work owns controlled staging registration/activation evidence,
  monitoring, authentication, and production readiness.
- Prefect remains a single server with SQLite state and no high availability,
  Redis, Prefect-specific PostgreSQL, authentication, backup/restore proof, or
  RPO/RTO evidence.
- Prefect 3.8.1 does not implement synchronous cancellation on native Windows.
  The enforced same-thread timeout runs in the project-owned Linux worker
  image; Windows unit validation injects the timeout signal and verifies safe
  classification, persistence, and bounded retry behavior without starting a
  background handler thread.
- C01 does not add a migration, model field, public API, frontend control,
  source credential, arbitrary endpoint, live request, or source collector.

Historical infrastructure details remain in
[B2-01 Prefect platform](b2-01-prefect-platform.md).
