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
- Manual, bounded local-JSON import for Censys ARC research and Rapid Response
  publication metadata
- Manual, bounded Google Cloud Threat Intelligence RSS ingestion for public
  Google Threat Intelligence Group and Mandiant publication metadata
- Manual, bounded local-JSON import for Anomali Cyber Watch publication metadata
- Manual, bounded local-JSON imports for separate IBM X-Force public research
  and public OSINT advisory metadata families
- Developer-controlled source registry metadata for implemented sources and
  disabled planned public-source families
- Common publication pipeline for validating and persisting approved
  pre-fetched public publication candidates
- Manual, dry-run-by-default UAE relevance classification and deterministic
  rule-strength confidence backfill for existing records
- Idempotent vulnerability persistence and source provenance
- Sanitized ingestion runs, per-record outcomes, and error auditing
- Read-only backend intelligence API endpoints for stored CVE records
- Read-only dashboard summary endpoint for stored KPI and freshness metrics
- Frontend dashboard KPI cards connected to the backend summary endpoint
- Frontend dashboard vulnerability table connected to the read-only intelligence
  API, with backend-powered search, severity filtering, and pagination
- Frontend CVE/vulnerability detail page connected to the read-only
  intelligence detail API
- Frontend latest articles feed connected to the read-only article API, with
  backend-powered search, category filtering, scope filtering, and pagination
- Frontend article detail page connected to the read-only article detail API
- Frontend recent trends panel connected to existing read-only APIs, with
  bounded stored-data severity, category, and timeline visualizations
- Remaining dashboard integration work in later stages

## Setup Status

The local development environment, backend foundation, database schema, and
initial frontend shell are implemented. NVD ingestion, FIRST EPSS enrichment,
CISA KEV enrichment, CERT-EU RSS ingestion, and Censys publication metadata
import remain manual-only: they are not scheduled and are not connected to
FastAPI startup, API routes, or the frontend dashboard.

### Source registry foundation

P9-02 adds an immutable backend source registry for safe source metadata,
canonical source slugs, implementation status, and developer-controlled host
allow-lists. The registry marks NVD, FIRST EPSS, CISA KEV, CERT-EU Security
Advisories, the two manual Censys publication families, the two Google
Threat Intelligence/Mandiant public RSS publication families, and the Anomali
Cyber Watch manual catalogue as enabled implemented sources. P9-07 also enables
only the `ibm-x-force-public-research` and
`ibm-x-force-public-osint-advisories` manual catalogue definitions. Other
Anomali and IBM X-Force families remain unapproved.

Registry entries do not grant authorization, licensing, API access, or
collection approval. No public source-management API, scheduler, startup
ingestion, frontend workflow, or new vendor collector was added. Existing
source ingestion remains manual-only.

### Common publication pipeline

P9-03 adds a shared backend pipeline for already-fetched and already-parsed
public publication candidates. The pipeline validates source registry status,
publication-compatible source families, HTTPS URLs, exact allowed hostnames,
safe shallow metadata, timezone-aware timestamps, deterministic title and URL
fingerprints, and caller-owned database persistence. Adapters enter through
`PublicationCandidate` validation only; they cannot supply arbitrary normalized
source definitions or runtime host allow-lists.

The stored article item type is derived from the registered source content
family. Required identity fields such as source external ID and title are
rejected when oversized rather than silently truncated. Safe source metadata is
defensively copied, shallow, bounded, and screened for sensitive header, token,
password, signed-URL alias, and credential-style keys. Malformed ASCII control
characters and Unicode surrogates are rejected before hashing or persistence;
normal human-readable Unicode remains supported.

Publication identity handling supports the trusted `security_advisory` and
`threat_report` article types without linking identities across those types.
Publication timestamps are runtime validated and normalized to UTC before
hashing and storage. Publication URLs reject credential-bearing or signed-query
aliases, including common separator and case variants, while continuing to
strip ordinary tracking parameters. Raw URL control characters are rejected
before parsing rather than silently cleaned.

CERT-EU RSS ingestion now uses this shared persistence path through its
existing manual service facade. P9-03 does not add new collectors, new vendor
adapters, scheduling, API-triggered ingestion, database migrations, frontend
changes, article-body fetching, or live network behavior.

P9-04 adds a source-specific local-file adapter for operator-prepared metadata
about official Censys ARC research and Rapid Response pages. Those upstream
public pages remain unstructured publication content; only the operator-supplied
import catalogue is strict structured JSON. Every accepted record enters through
the same common publication pipeline. This does not add Censys website crawling
or scraping, a Censys API integration, account or API key configuration,
exposure/host/certificate/scan data, search, or rescan capability.

P9-05 adds a manual shared-feed adapter for the official Google Cloud Threat
Intelligence RSS feed at
`https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v`. Entries are
persisted only when the authoritative feed author is exactly `Google Threat
Intelligence Group` or `Mandiant`; those authors map to separate source slugs
and source-separated identifiers. The collector validates only the exact
FeedBurner collection host, while stored publication URLs must use exact host
`cloud.google.com` and path `/blog/topics/threat-intelligence/...`. The command
stores metadata only and does not fetch article bodies, scrape pages, ingest
developer documentation, use Google Threat Intelligence or VirusTotal APIs, use
credentials, submit or retrieve files/samples, extract IOCs, schedule work, run
at startup, or expose a public ingestion endpoint.

P9-06 adds a manual local-JSON catalogue for operator-prepared metadata about
the official Anomali Cyber Watch publication series only. Accepted URLs use
exact host `www.anomali.com` and literal path family
`/blog/anomali-cyber-watch-`; titles use exact prefix `Anomali Cyber Watch:`.
The application performs no Anomali network requests and does not fetch article
bodies, embedded third-party stories, IOCs, ThreatStream objects, reports,
PDFs, media, or downloads. General Anomali blog content, commercial feeds and
APIs, STIX/TAXII, and STAXX are not implemented.

P9-07 adds two separate manual local-JSON catalogues for IBM X-Force metadata.
Research records require exact `www.ibm.com/think/x-force/<lower-kebab-slug>`
URLs and become `threat_report` items. Public OSINT advisory records require
exact `exchange.xforce.ibmcloud.com/osint/guid%3A<32-hex>` URLs and become
`security_advisory` items. The application performs no IBM request, scraping,
guest browsing, IBMid automation, API access, report/PDF download, IOC or
reputation ingestion, STIX/TAXII processing, or paid-tier integration.

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
sanitized audit outcomes through the common publication pipeline, and does not
fetch article bodies or arbitrary RSS sources.

### Manual Censys publication import

From the `backend` directory, an operator can import a bounded local JSON file:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.censys_publications_cli `
    --file C:\path\to\censys-publications.json
```

The UTF-8 file is limited to 1 MiB and 100 publication records. It must contain
exactly `schema_version`, `source_slug`, and `publications`; each publication
must contain exactly `title`, `url`, `summary`, `published_at`, `modified_at`,
`authors`, and `categories`. Author and category lists are each limited to 20
plain-text values. The source slug must select either ARC research under
`https://censys.com/blog/` or Rapid Response advisories under
`https://censys.com/advisory/`. The input must use an ordinary local path;
UNC/network and Windows device-namespace paths are rejected before traversal.
Catalogue URLs must use the literal approved publication path, without percent
escapes or path parameters.

Publication metadata preparation and page verification happen outside this
application. The command reads only the supplied regular local file, performs
no Censys network request, and records sanitized audit outcomes. No scheduler,
background worker, public ingestion endpoint, Censys account, or API key is
used.

### Manual Google TI and Mandiant publication ingestion

From the `backend` directory, a developer can fetch and store a bounded set of
official public Google Threat Intelligence topic RSS entries:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.google_threat_publications_cli `
    --max-records 25
```

The command is manual-only and uses the fixed official RSS feed. It has no URL
argument and uses no credentials. Entries are accepted only when the normalized
author is exactly `Google Threat Intelligence Group` or `Mandiant`; ownership is
not inferred from titles, categories, product names, report links, or article
text. Stored records are `threat_report` metadata with exact
`cloud.google.com/blog/topics/threat-intelligence/` publication URLs. Article
bodies, downloadable reports, PDFs, malware samples, observables, and IOCs are
not fetched or stored.
Only feed `summary` or `description` values may become stored summaries; feed
`content`, article bodies, attachments, media links, and report downloads are
ignored. If an otherwise owned entry fails validation, the failure is audited
only under that resolved source. If an entry cannot be attributed to an approved
author, the command records sanitized shared-feed error evidence on both
logical runs without incrementing either source's fetched or failed record
counters.

### Manual Anomali Cyber Watch publication import

From the `backend` directory, an operator can import a bounded local JSON file:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.anomali_publications_cli `
    --file C:\path\to\anomali-cyber-watch.json
```

The command accepts only schema version 1 for source slug
`anomali-cyber-watch`, with at most 100 exact seven-field records in a 1 MiB
UTF-8 file. Metadata must be operator-prepared plain text. Authors and
categories are bounded optional metadata and never establish source ownership.
Execution is manual only: there is no Anomali HTTP collector, RSS endpoint,
scraper, scheduler, startup hook, background worker, or public ingestion route.

### Manual IBM X-Force publication import

From the `backend` directory, an operator can import one approved source family
from a strict local JSON document:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.ibm_x_force_publications_cli `
    --file C:\path\to\ibm-x-force-publications.json
```

The document source must be exactly `ibm-x-force-public-research` or
`ibm-x-force-public-osint-advisories`; one file and ingestion run cannot mix
them. Files are UTF-8 JSON limited to 1 MiB, 100 exact seven-field records, and
plain-text operator-prepared metadata. The command has no source, URL, login,
credential, API, browser, scheduler, startup, worker, or public endpoint option.

### Read-only intelligence API

The backend now exposes stored intelligence items through manual read-only API
endpoints:

- `GET /api/v1/articles`
- `GET /api/v1/articles/{public_id}`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/intelligence/items`
- `GET /api/v1/intelligence/items/{item_public_id}`

The article list endpoint returns active article-like records with bounded
`limit` and `offset` pagination, title/summary search through `q`, and safe
filters for category, source slug, tag slug, publication date range,
geographic scope, and UAE relevance status. The article detail endpoint returns
one active article-like record by public UUID using the same safe normalized
fields and returns `404` for missing, inactive, non-article, merged,
superseded, archived, or vulnerability records. The generic intelligence list
endpoint supports bounded `limit` and `offset` pagination plus these safe
filters: `q`, `severity`, `source_slug`, `item_type`, `cve_id`,
`geographic_scope`, and `uae_relevance_status`. Responses return normalized
dashboard-ready fields only, including safe EPSS score, percentile,
score-date, KEV date, KEV due-date, and ransomware-use fields when enrichment
exists. The dashboard summary endpoint returns database-backed KPI counts,
latest article previews, and latest stored fetch status. The dashboard landing
page uses this endpoint for the four top KPI cards and uses
`GET /api/v1/intelligence/items` for the vulnerability table. The vulnerability
table links each CVE by public UUID to a frontend vulnerability detail page, and
the latest articles feed links each article to a frontend article detail page.
The dashboard latest-articles feed and vulnerability table both send
backend-driven geographic-scope and UAE relevance-status filters through those
read-only APIs. Search, filters, and offset pagination combine at the backend;
changing a filter resets the frontend view to the first page.
The dashboard also composes bounded latest CVE and article API results for a
recent stored-data trends panel; this is not a complete historical analytics
module. Other dashboard preview panels still use deterministic frontend preview
data until their dedicated backend views are implemented. Raw source payloads,
request headers, secrets, and ingestion audit internals are intentionally not
returned, and these endpoints never trigger ingestion or external network calls.

### Manual UAE relevance classification

From the `backend` directory, a developer can preview deterministic offline UAE
classification for existing records:

```powershell
.\.venv\Scripts\python.exe -m app.processing.uae_classification_cli `
    --max-items 20
```

The command is dry-run by default. To persist eligible automatic/unassigned
classification changes, use:

```powershell
.\.venv\Scripts\python.exe -m app.processing.uae_classification_cli `
    --max-items 20 `
    --apply
```

The classifier uses safe normalized metadata only, preserves manual and
source-declared classification ownership, performs no network calls, and is not
connected to application startup, a scheduler, or any public write endpoint.
Automatic confidence is a fixed deterministic mapping from the winning UAE
classification rule to the existing nullable `uae_relevance_confidence` field:
approved UAE source and direct `United Arab Emirates` phrase use `0.950`,
standalone `UAE` uses `0.900`, direct emirate names use `0.850`, and records
with no direct UAE evidence keep confidence `null`. The value represents the
strength of deterministic evidence used for UAE relevance classification. It
does not represent exploit probability, threat attribution, attacker intent,
targeting certainty, or business impact.
The frontend displays this canonical numeric value as a clear presentation
label: High for `0.900`-`1.000`, Medium for `0.750`-`0.899`, Low for
`0.000`-`0.749`, and no confidence label for `null`. The current automatic
rules emit High or Medium labels; Low remains available for manually reviewed,
source-declared, seeded, or future valid confidence values. These labels are
not threat severity, exploit probability, statistical calibration, attribution
certainty, or proof that low-confidence items are not relevant. P4-03 frontend
filters use the relevance status values only and do not add confidence filters.

## Documentation

See the docs/ folder for:

- architecture.md
- data-sources.md
- source-assessment-matrix.md
- source-integration-policy.md
- security-notes.md
- testing-plan.md
- deployment-notes.md
- uae-classification.md
