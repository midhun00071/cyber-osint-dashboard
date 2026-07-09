# Cyber OSINT Dashboard / Alpha Data

## Project Overview

Cyber OSINT Dashboard / Alpha Data is a full-stack cybersecurity dashboard designed to collect, process, store, and display open-source cybersecurity intelligence for defensive awareness.

The project focuses on vulnerabilities, known exploited vulnerabilities, threat intelligence reports, cyberattack updates, and UAE/global cybersecurity context.

## Project Goal

Build a deployment-ready full-stack cybersecurity OSINT dashboard with:

- Backend API
- Frontend dashboard
- PostgreSQL database
- Automated open-source intelligence ingestion
- Threat and vulnerability detail pages
- Search, filtering, and summary views
- Testing and deployment documentation

## Ethical Use Statement

This project is intended only for defensive cybersecurity awareness, vulnerability tracking, educational analysis, and authorized open-source intelligence review.

The application must not provide exploit instructions, weaponized proof-of-concept content, unauthorized attack guidance, malware downloads, or steps to compromise real systems.

## Recommended Stack

- Frontend: Next.js with TypeScript
- Backend: Python FastAPI
- Database: PostgreSQL
- Background scheduling: APScheduler for MVP
- Deployment: Docker and Docker Compose
- Testing: pytest for backend and frontend tests later

## Repository Structure

- backend/ - FastAPI backend application
- frontend/ - Next.js frontend dashboard
- database/ - PostgreSQL initialization and database notes
- docs/ - architecture, security, testing, deployment, and data-source documentation
- scripts/ - developer setup scripts

## Current Phase

Phase 1 project setup and repository structure are complete. The project is now
in the MVP ingestion and backend foundation stage.

Current focus:

- Manual, bounded NVD CVE ingestion
- Manual, bounded FIRST EPSS enrichment for existing CVEs
- Manual, bounded CISA KEV enrichment for existing CVEs
- Manual, bounded CERT-EU Security Advisories RSS ingestion
- Idempotent vulnerability persistence and source provenance
- Sanitized ingestion runs, per-record outcomes, and error auditing
- Read-only backend intelligence API endpoints for stored CVE records
- Read-only dashboard summary endpoint for stored KPI and freshness metrics
- Frontend dashboard KPI cards connected to the backend summary endpoint
- Dashboard integration work in later stages

## Setup Status

The local development environment, backend foundation, database schema, and
initial frontend shell are implemented. NVD ingestion, FIRST EPSS enrichment,
CISA KEV enrichment, and CERT-EU RSS ingestion remain manual-only: they are not
scheduled and are not connected to FastAPI startup, API routes, or the frontend
dashboard.

## Security Principles

- Do not commit real .env files.
- Do not hardcode API keys, passwords, tokens, or private configuration.
- Keep external data collection limited to approved public sources.
- Do not fetch dangerous files or malware samples.
- Validate backend inputs.
- Render external text safely in the frontend.
- Log errors without exposing secrets.

## Running the Project

Run these commands from the repository root:

```powershell
.\run.cmd install
.\run.cmd test
.\run.cmd docker
.\run.cmd dev
```

`install` prepares the backend and frontend dependencies, while `test` runs the
backend tests plus the frontend type check and production build. `docker` builds,
starts, and verifies the complete Docker Compose application.

For day-to-day development, `dev` starts only PostgreSQL in Docker, then runs the
FastAPI backend and Next.js frontend locally with reload support. Press Ctrl+C to
stop the local backend and frontend processes. The database container remains
running so it can be reused; stop it manually with Docker Compose when needed.

### Manual NVD smoke test

From the `backend` directory, a developer can make one small, network-active
request to the public NVD API:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.collectors.nvd_smoke_test `
    --window-minutes 5 `
    --results-per-page 3
```

This command runs only when invoked manually. It uses `NVD_API_KEY` from local
settings when available, prints summary counts and safe CVE identifiers only,
and does not store data or start scheduled ingestion.

To manually fetch and store a bounded set of public NVD CVEs, run this separate
network- and database-active command from `backend`:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.nvd_cli `
    --window-minutes 60 `
    --results-per-page 25 `
    --max-records 25
```

It runs only when explicitly invoked, stores bounded normalized public data and
sanitized audit records, and is not connected to application startup or a
scheduler.

### Manual FIRST EPSS enrichment

From the `backend` directory, a developer can enrich existing stored CVEs with
latest public FIRST EPSS probability and percentile values:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.epss_cli `
    --max-cves 25 `
    --batch-size 25
```

This command runs only when explicitly invoked. It matches EPSS records only to
existing global CVE identifiers, stores latest-value score metadata with
non-primary FIRST EPSS provenance, records sanitized audit outcomes, and never
creates new CVE intelligence items from EPSS data.

### Manual CERT-EU RSS ingestion

From the `backend` directory, a developer can fetch and store a bounded set of
approved public CERT-EU Security Advisories feed entries:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.rss_cli `
    --max-records 25
```

This command runs only when explicitly invoked. It is locked to the approved
`https://cert.europa.eu/publications/security-advisories-rss` feed, stores
normalized advisory metadata as `security_advisory` intelligence items, records
sanitized audit outcomes, and does not fetch article bodies or arbitrary RSS
sources.

### Read-only intelligence API

The backend now exposes stored intelligence items through manual read-only API
endpoints:

- `GET /api/v1/articles`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/intelligence/items`
- `GET /api/v1/intelligence/items/{item_public_id}`

The article list endpoint returns active article-like records with bounded
`limit` and `offset` pagination, title/summary search through `q`, and safe
filters for category, source slug, tag slug, publication date range,
geographic scope, and UAE relevance status. The generic intelligence list
endpoint supports bounded `limit` and `offset` pagination plus these safe
filters: `q`, `severity`, `source_slug`, `item_type`, and `cve_id`. Responses
return normalized dashboard-ready fields only, including safe EPSS score,
percentile, and score-date fields when enrichment exists. The dashboard summary
endpoint returns database-backed KPI counts, latest article previews, and latest
stored fetch status. The dashboard landing page uses this endpoint for the four
top KPI cards only; other dashboard preview panels still use deterministic
frontend preview data until their dedicated backend views are implemented. Raw
source payloads, request headers, secrets, and ingestion audit internals are
intentionally not returned, and these endpoints never trigger ingestion or
external network calls.

## Documentation

See the docs/ folder for:

- architecture.md
- data-sources.md
- security-notes.md
- testing-plan.md
- deployment-notes.md
