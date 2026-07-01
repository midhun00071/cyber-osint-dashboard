# Frontend - Cyber OSINT Dashboard

## Purpose

The frontend provides the analyst-facing dashboard interface for viewing vulnerabilities, threat intelligence records, UAE/global relevance, summaries, filters, and detailed pages.

## Planned Responsibilities

- Display dashboard summary cards.
- Display latest cybersecurity intelligence.
- Provide search and filtering.
- Display vulnerability and threat detail pages.
- Show loading, empty, and error states.
- Safely render external source text.
- Communicate with the backend API using a frontend service layer.

## Planned Frontend Structure

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

## Current Status

Phase 1 setup only. UI implementation will be added in a later phase.
