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

Use frontend/.env.example as the template.

For local development, copy it to frontend/.env.local.

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
MVP scope.
