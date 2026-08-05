# C07 Authenticated Operations Experience

C07 implements the authenticated, permission-gated operations experience for
source visibility, durable operation acceptance, source controls, run history,
and administrator user visibility. It builds on the C06 browser-session and
RBAC boundary and the C07A durable `operator_state` migration at repository
head `c07a01b02c03`. C07 adds no model or migration.

## API contract

All routes below are under `/api/v1`, use the C06 opaque HttpOnly session, and
return `Cache-Control: no-store`. Unknown or repeated query parameters are
rejected. Mutation bodies are empty JSON objects with extra fields forbidden;
exact-Origin, JSON content type, and the C06 double-submit `X-CSRF-Token`
boundary are required.

| Method | Path | Permission | Result |
| --- | --- | --- | --- |
| `GET` | `/sources` | `source.read` | Bounded source list |
| `GET` | `/sources/{source_slug}` | `source.read` | One source or safe 404 |
| `GET` | `/ingestion/operations/summary` | `ingestion.read` | Current committed operations summary |
| `GET` | `/ingestion/cycles` | `ingestion.read` | Bounded cycle history |
| `GET` | `/ingestion/runs` | `ingestion.read` | Bounded run history |
| `GET` | `/ingestion/runs/{run_public_id}` | `ingestion.read` | One committed run |
| `GET` | `/ingestion/runs/{run_public_id}/events` | `ingestion.read` | Ordered append-only run events |
| `POST` | `/sources/{source_slug}/runs` | `ingestion.run` | Durable manual-run acceptance |
| `POST` | `/ingestion/runs/{run_public_id}/retry` | `ingestion.retry` | Durable deterministic retry acceptance |
| `POST` | `/sources/{source_slug}/pause` | `ingestion.pause` | Atomic pause |
| `POST` | `/sources/{source_slug}/resume` | `ingestion.pause` | Atomic resume |
| `POST` | `/sources/{source_slug}/disable` | `ingestion.pause` | Atomic disable |
| `POST` | `/sources/{source_slug}/enable` | `source.manage` | Administrator enable |

List defaults are `limit=25` and `offset=0`; list limits are 1–100 and offsets
are bounded at 100000. Run events allow 1–500 items. Cycle and run filters use
UTC-aware `from` and `to` values; a supplied pair must be ordered and no more
than 90 days apart. Runs are newest first with ID tie-breaking, cycles are
newest first with ID tie-breaking, sources are ordered by slug, and run events
are ordered by sequence.

Source responses allow-list immutable policy metadata, durable operator state,
calculated effective state, a credential-required/configured Boolean, freshness,
quota/backoff state, safe progress evidence, latest-run summary, and permitted
actions. Credential references are never returned. Checkpoints and watermarks
are represented only by kind, version, commit time, and a SHA-256 fingerprint;
raw values are never returned. Run and cycle responses expose public UUIDs,
bounded counters, status/timing, lineage, and sanitized summaries, never raw
payloads, headers, exceptions, SQL, or internal numeric identifiers.

## Permission matrix

| Capability | Viewer | Analyst | Ingestion operator | Administrator |
| --- | --- | --- | --- | --- |
| Content and source metadata read | Yes | Yes | Yes | Yes |
| Ingestion status/history read | No | No | Yes | Yes |
| Manual run and retry | No | No | Yes | Yes |
| Pause, resume, disable | No | No | Yes | Yes |
| Enable disabled source | No | No | No | Yes |
| User read/manage, session revoke, audit read | No | No | No | Yes |

Backend dependencies enforce every permission. Role-aware navigation and action
hiding are usability controls only and do not replace backend authorization.

## Source state and operation acceptance

Immutable source policy and durable operator state remain separate. Effective
state is calculated fail-closed from implementation status, immutable enabled
policy, `operator_state`/`is_enabled`, credentials, quota/backoff, active work,
and execution binding availability. Valid state changes are:

- `enabled -> paused`, `enabled -> disabled`;
- `paused -> enabled` through resume, or `paused -> disabled`;
- `disabled -> enabled` through the Administrator-only enable operation.

Repeating the current target is an audited `no_change`. Invalid transitions,
immutable-policy-disabled sources, active runs, absent credentials, unavailable
quota, backoff/rate limiting, or absent execution binding fail safely without a
state change. `operator_state` and the compatibility `is_enabled` projection
are changed in the same caller-owned transaction as the audit evidence.

Manual acceptance requires an allow-listed 16–128 character `Idempotency-Key`.
The existing deterministic key derivation and PostgreSQL advisory-lock boundary
create at most one manual cycle/run; replay returns the existing acceptance with
HTTP 200 and `replayed=true`, while first acceptance returns HTTP 202. Retry
uses the existing deterministic retry identity and nonbranching ancestry—there
is no second client retry key. The same eligible parent replays its existing
child, while stale parents, attempted branches, ineligible status, absent
retryable evidence, and exhausted attempts return a safe conflict. Acceptance
means committed durable evidence, not successful upstream execution.

## Audit and transaction boundary

C07 adds closed actions for `ingestion.manual.requested`,
`ingestion.retry.requested`, `ingestion.run.execution_failed`, `source.paused`,
`source.resumed`, `source.disabled`, `source.enabled`, and
`source.state.changed`. Outcomes remain the closed vocabulary `success`,
`denied`, `failed`, and `no_change`. Safe details are restricted to bounded
allow-listed fields such as reason, prior/new state, trigger type, run status,
and operation. Raw idempotency keys, credentials, tokens, cookies, checkpoints,
provider headers, payloads, SQL, exceptions, and stack traces are forbidden.

Successful mutations and their audit records share one route-owned commit.
Domain rejections roll back first, then commit a separate denial audit; if that
audit cannot be persisted, the route fails closed with a sanitized 500.

## Frontend contract

The root `AuthProvider` bootstraps through `/auth/me` before protected content
is rendered. It exposes bootstrapping, anonymous, authenticating,
authenticated, session-expired, access-denied, recoverable-error, and
logging-out states. The browser uses credentials-included requests; the opaque
session cookie remains inaccessible to JavaScript, and no token is stored in
localStorage or sessionStorage. A 401 expires the session and routes to
`/login`; a 403 preserves the principal and shows access denied for that route.
Mutations are never automatically replayed.

Implemented routes are `/login`, `/`, `/articles/[publicId]`,
`/vulnerabilities/[publicId]`, `/sources`, `/operations`, `/run-history`, and
`/admin/users`. Navigation is role-aware, logout is explicit, and Administrator
UI is permission protected. Post-login return destinations are limited to `/`,
the four fixed dashboard paths, and article/vulnerability paths containing a
canonical public UUID. Absolute, protocol-relative, malformed, encoded escape,
and unknown paths fall back to `/`.

Sources, operations, and run history poll every 15 seconds only while the
document is visible. Each view permits one request at a time, skips overlapping
interval ticks, cancels work when hidden or unmounted, treats cancellation as a
non-error, and queues exactly one replacement if visibility returns before an
aborted request settles. A successful mutation requests one immediate refresh.
Authentication bootstrap uses the same quiet cancellation rule and cannot
overwrite a later valid state. WebSockets are out of scope.

## Completed operations pages

Run history constructs `URLSearchParams` from only `source_slug`, `status`,
`trigger_type`, `retryable`, timezone-aware `from` and `to`, bounded `limit`,
and bounded `offset`. It shows source, status, trigger, attempt, retry-parent
public UUID, acceptance/start/finish timing, duration, retryability, safe
summary, and safe counters. Selection loads safe run detail and ordered events
by public run UUID. Event display is limited to sequence, event type, status
transition, safe message, and timestamp. Retry appears only when the backend
marks the run retryable.

The operations page retrieves summary, cycle history, and recent runs
sequentially so only one page-level request is active. It reports execution
availability, configured handler count, generated/refresh timestamps, active
cycles, running and checkpoint-pending runs, status counts, attention count,
and real cycle/run records. Empty responses remain explicitly empty.

The sources page displays policy/operator/effective state, credential-required
and configured Booleans, execution availability, freshness, safe progress kind,
version, commit time and SHA-256 fingerprint, latest-run metadata, quota,
backoff, next schedule, and backend-provided actions. It never displays raw
checkpoint/watermark values or credential-reference identifiers.

The Administrator page uses the existing APIs for user creation, status, role,
expiry, and session revocation. Each request builds a fixed payload rather than
returning a user object. Disabling, role/expiry changes, and session revocation
require confirmation. Creation password state is cleared after completion; no
password, principal, session, or token is written to browser storage or logs.
Backend Administrator authorization remains authoritative.

## Safety state and accepted limitations

The four C05 sources—`mitre-attack-enterprise`,
`cert-fr-security-alerts`, `cert-fr-security-advisories`, and
`uk-ncsc-threat-reports`—remain disabled and unscheduled. The production
`DEFAULT_SOURCE_HANDLERS` mapping is empty, so the operations summary reports
zero configured handlers and manual/retry requests cannot fabricate execution
success. No source request, production binding, schedule activation, real user
creation, bootstrap, staging access, or deployment is part of C07.

The API records durable acceptance but does not start a worker or activate a
schedule. Production monitoring, execution-failure reporting integration,
WebSockets, staging activation, and live-source validation remain later work.
