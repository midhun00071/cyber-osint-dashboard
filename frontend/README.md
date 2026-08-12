# Frontend - Cyber OSINT Dashboard

## Purpose

The frontend provides the analyst-facing dashboard interface for viewing vulnerabilities, threat intelligence records, UAE/global relevance, summaries, filters, and detailed pages.

## Responsibilities

- Display dashboard summary cards.
- Display latest cybersecurity intelligence.
- Provide search and filtering.
- Display vulnerability and threat detail pages.
- Show loading, empty, and error states.
- Safely render external source text.
- Communicate with the backend API using a frontend service layer.

## Frontend Structure

- src/app/ - Next.js app routes and pages
- src/components/ - reusable UI components
- src/services/ - backend API client logic
- src/types/ - shared TypeScript types
- src/hooks/ - reusable React hooks
- src/styles/ - styling and theme files
- public/ - static assets

## Environment Variables

`frontend/.env.example` defines the host-side frontend development structure.
See the authoritative
[environment and secrets guide](../docs/environment-and-secrets.md) for public
configuration classification. Complete application setup, startup, URLs, and
troubleshooting belong in the single canonical
[operator guide](../docs/operator-guide.md).

Only NEXT_PUBLIC_ variables are exposed to the browser. Do not place secrets in frontend environment variables.

## Dependencies

Initial dependencies are defined in package.json.

## Automated Tests

The frontend test suite uses Vitest, jsdom, and React Testing Library with
Testing Library user-event and jest-dom assertions. It covers the dashboard,
health and summary states, trends, article and vulnerability lists, filters,
pagination, detail pages, request cancellation, safe external links, and
untrusted text rendering.

Run the suite once:

```powershell
npm run test:run
```

Use watch mode while developing tests:

```powershell
npm test
```

Tests are offline. They use synthetic fixtures and mock frontend service
responses, so no backend, database, Docker service, live OSINT source, or secret
is required. From the repository root, `.\run.cmd test` runs backend pytest,
the frontend test suite, frontend type-checking, and the production build. The
standalone `npm run validate:safe-rendering` command remains available.

The repository currently has no CI workflow.

## Current Status

The dashboard UI, backend-connected read-only data views, safe-rendering
controls, and automated component/page tests are implemented for the current
MVP scope. The frontend presents the safe operational state returned by the
backend rather than inferring it from handler bindings. Current deployment and
activation procedures belong in the
[operator guide](../docs/operator-guide.md).

## C07 authenticated frontend

The root session provider bootstraps `/auth/me` before protected content is
rendered. `/login`, `/sources`, `/operations`, `/run-history`, and
`/admin/users` provide distinct anonymous, expired, denied, loading,
refreshing, empty, success, and sanitized failure behavior. Login accepts only
an allow-listed local `next` destination; external, protocol-relative,
malformed, encoded escape, and unknown paths return to `/`. Bootstrap aborts
end quietly without overwriting a later session state.

Run history uses only fixed `source_slug`, `status`, `trigger_type`,
`retryable`, timezone-aware `from`/`to`, bounded `limit`, and bounded `offset`
query fields. It displays safe timing, retry lineage, summaries and counters,
then loads allow-listed run detail and ordered events by public UUID. Operations
loads summary, cycle history, and recent runs sequentially. Sources expose the
complete safe policy/readiness/freshness/progress-fingerprint/quota/schedule
view without raw checkpoints or credential references. Administrator controls
use strict create/status/role/expiry payloads, public user identifiers, explicit
confirmation for sensitive changes, and clear password state after creation.

Sources, operations, and run history use cancellable 15-second polling only
while visible. Interval overlap is skipped; hiding or unmounting aborts active
work; visibility return queues exactly one replacement while cancellation
settles; and a successful mutation requests one immediate refresh. Requests
include browser credentials, opaque session tokens are never stored by
JavaScript, mutations are not automatically replayed, and role-aware navigation
does not replace backend authorization. Scheduled execution follows the actual
deployment state; handler binding alone does not equal activation. See
[C07 authenticated operations experience](../docs/c07-authenticated-operations-experience.md).
