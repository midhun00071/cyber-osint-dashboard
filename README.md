# Alpha Data / Cyber OSINT Dashboard

## Project overview

Alpha Data is a full-stack defensive cybersecurity OSINT dashboard for
collecting, normalizing, storing, searching, visualizing, and reviewing approved
public cybersecurity intelligence. It combines a FastAPI API, PostgreSQL,
operator-invoked ingestion workflows, and a Next.js analyst interface for
vulnerability and publication awareness, including UAE/global context.

This repository is an internship project prepared for mentor and senior-reviewer
handover. It provides a tested local development workflow and a hardened
production-oriented Docker Compose baseline. It is not a claim of a complete,
public-internet-ready production platform.

## Defensive and ethical-use boundary

Use this project only for defensive, ethical, authorized, educational, or
lab-safe cybersecurity work. It must not be used for exploit execution,
unauthorized scanning or probing, phishing, credential theft, persistence,
evasion, stealth, bypass activity, malware retrieval, or steps to compromise
real systems.

External OSINT content is untrusted data. The implemented collectors use fixed,
developer-controlled sources and bounded inputs; the backend returns allow-listed
fields, and the frontend renders external text through defensive controls. A
source-registry entry does not grant collection authorization, licensing, API
access, storage rights, or redistribution rights. Future source work requires a
separate review of access, terms, rate limits, and project approval.

## Current implementation status

The current MVP includes the database schema and migrations, manual defensive
ingestion and enrichment services, read-only APIs, backend-connected dashboard
views, security hardening, automated tests, development runners, a self-hosted
Prefect 3.8.1 server and process worker, and production-oriented Docker
documentation. Ingestion remains manual-only: there is no active scheduler,
startup ingestion, recurring background ingestion, public ingestion API, or
frontend ingestion trigger. C01 adds typed source-execution contracts, a
deterministic parent/source flow core, bounded retry and progress handling, and
a paused-by-default deployment definition. No source-specific handler is bound,
no deployment has been activated, and no live source schedule is claimed.

Key implemented capabilities include:

- PostgreSQL persistence with normalized intelligence, provenance, identifiers,
  enrichment data, and sanitized ingestion audit records.
- Manual, bounded ingestion or enrichment for the approved source families
  summarized below.
- Read-only dashboard, article, and intelligence APIs with validated search,
  filtering, pagination, and safe response fields.
- Backend-connected dashboard summaries, vulnerability and article lists,
  detail pages, trends, loading/empty/error states, and safe external links.
- Exact-origin CORS, API security headers, server-generated request IDs,
  sanitized error responses, and allow-listed application logging.
- Backend pytest coverage, frontend Vitest/React Testing Library coverage,
  TypeScript checking, production builds, manual QA procedures, and deployment
  validation evidence.
- Separate development and production-oriented Compose definitions with manual
  Alembic migrations in the production-oriented workflow.
- A pinned, non-root self-hosted Prefect server and process worker with
  persistent orchestration state, application orchestration code, application-
  role database access for the worker, and the fixed `alpha-data-process` work
  pool.
- Immutable policies for every enabled implemented source, caller-transaction-
  owned operational persistence, database-backed source no-overlap, safe
  checkpoint resume, and a fixed two-hour parent schedule contract.

## Technology stack

- Frontend: Next.js, React, and TypeScript.
- Backend: Python 3.13, FastAPI, Pydantic, and Uvicorn.
- Persistence: PostgreSQL, SQLAlchemy, and Alembic.
- Source clients: httpx and feedparser.
- Containers: Docker and Docker Compose.
- Workflow orchestration platform: self-hosted Prefect 3.8.1.
- Testing: pytest; Vitest, jsdom, React Testing Library, and TypeScript checks.

APScheduler remains removed. Prefect is pinned exactly to 3.8.1. The C01
deployment contract uses `17 */2 * * *` in `Asia/Dubai` with parent concurrency
one, but registration is explicit and paused by default. C01 did not activate a
schedule or execute a source workflow.

## Repository structure

| Path | Purpose |
| --- | --- |
| [`backend/`](backend/) | FastAPI application, database models, migrations, ingestion and processing services, and pytest tests. |
| [`frontend/`](frontend/) | Next.js App Router dashboard, service layer, types, styles, and Vitest component/page tests. |
| [`database/`](database/) | PostgreSQL initialization material and database notes. |
| [`docs/`](docs/) | Architecture, source, security, testing, environment, and deployment documentation. |
| [`scripts/`](scripts/) | Safe local developer setup helper. |
| [`prefect/`](prefect/) | Pinned non-root Prefect server/worker image containing the backend runtime and orchestration package. |
| [`run.cmd`](run.cmd) / [`run.ps1`](run.ps1) | Windows entry point and PowerShell implementation for setup, validation, and local execution. |
| [`docker-compose.yml`](docker-compose.yml) | Local development Compose stack. |
| [`compose.prod.yml`](compose.prod.yml) | Standalone production-oriented Compose baseline. |

## Ingestion control and source scope

All implemented collection and enrichment remains explicitly invoked by an
operator. No command below runs on FastAPI startup, from a scheduler, through a
public write endpoint, or from the frontend.

Implemented source workflows:

- Manual, bounded NVD CVE ingestion
- Manual, bounded FIRST EPSS enrichment for existing CVEs
- Manual, bounded CISA KEV enrichment for existing CVEs
- Manual, bounded CERT-EU Security Advisories RSS ingestion
- Manual, bounded live collection and reviewed local-JSON fallback for Censys
  ARC research and Rapid Response publication metadata
- Manual, bounded Google Cloud Threat Intelligence RSS ingestion for public
  Google Threat Intelligence Group and Mandiant publication metadata
- Manual, bounded live collection and reviewed local-JSON fallback for Anomali
  Cyber Watch publication metadata
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
- Some dashboard preview panels remain deterministic frontend preview data until
  their dedicated backend views are implemented.

The local development environment, backend foundation, database schema, and
backend-connected frontend are implemented. NVD ingestion, FIRST EPSS enrichment,
CISA KEV enrichment, CERT-EU RSS ingestion, Censys publication metadata
ingestion, Google TI/Mandiant publication ingestion, both Anomali publication
workflows, and IBM X-Force catalogue imports remain manual-only: they are not
scheduled and are not connected to FastAPI startup, background ingestion, API
routes, or the frontend dashboard.

The historical B2-01 platform remains the infrastructure foundation. C01 now
adds reusable orchestration contracts, generic flow logic, persistence adapters,
and a reproducible deployment definition without converting any manual source
collector. The production binding registry is intentionally empty, activation
fails closed while scheduled-eligible handlers are missing, and Compose does
not register or execute the deployment. Source conversion belongs to C02;
operator controls, authentication, monitoring, and activation remain later
tasks.

### Source registry foundation

P9-02 adds an immutable backend source registry for safe source metadata,
canonical source slugs, implementation status, and developer-controlled host
allow-lists. The registry marks NVD, FIRST EPSS, CISA KEV, CERT-EU Security
Advisories, the two manual Censys publication families, the two Google
Threat Intelligence/Mandiant public RSS publication families, and the Anomali
Cyber Watch live-and-fallback definition as enabled implemented sources. P9-07
also enables only the `ibm-x-force-public-research` and
`ibm-x-force-public-osint-advisories` manual catalogue definitions. Other
Anomali and IBM X-Force families remain unapproved.

Registry entries do not grant authorization, licensing, API access, or
collection approval. No public source-management API, scheduler, startup
ingestion, or frontend ingestion workflow is installed. Source ingestion
remains manual-only.

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
the same common publication pipeline. The later bounded live collector uses only
two fixed public discovery locations and reuses this adapter and pipeline. It
does not add general Censys crawling or scraping, a Censys API integration,
account or API key configuration, exposure/host/certificate/scan data, search,
or rescan capability.

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

P9-06 provides the reviewed local-JSON catalogue for operator-prepared metadata
about the official Anomali Cyber Watch series. The local adapter validates the
strict schema, bounds, source identity, timestamps, and plain-text fields, while
catalogue review ensures that prohibited article content and indicators are not
supplied. A later secure collector adds manual-only live metadata collection
from the single fixed discovery URL `https://www.anomali.com/blog`. It accepts no
arbitrary URL, restricts requests to exact HTTPS host `www.anomali.com` and
article path family `/blog/anomali-cyber-watch-`, does not parse article-body
prose, and rejects IOC-like selected metadata before adapter invocation. General
Anomali content, ThreatStream, commercial feeds/APIs, STIX/TAXII, and STAXX are
not implemented.

P9-07 adds two separate manual local-JSON catalogues for IBM X-Force metadata.
Research records require exact `www.ibm.com/think/x-force/<lower-kebab-slug>`
URLs and become `threat_report` items. Public OSINT advisory records require
exact `exchange.xforce.ibmcloud.com/osint/guid%3A<32-hex>` URLs and become
`security_advisory` items. The application performs no IBM request, scraping,
guest browsing, IBMid automation, API access, report/PDF download, IOC or
reputation ingestion, STIX/TAXII processing, or paid-tier integration.

P9-10 now includes bounded STIX 2.1 validation/persistence and a fixed-policy
TAXII 2.1 collection client. The separate immutable TAXII policy fixes one
canonical HTTPS API root, exact collection ID, derived objects endpoint,
timeouts, total monotonic deadline, and response/page/object/token limits. The
client permits only exact `httpx.BasicAuth`, revalidates the authenticated
method, URL, query, fixed header allow-list, and bounded timeout extensions
immediately before transport, and rejects redirects or invalid media types. It
requests identity transfer encoding, rejects compressed or malformed content
encodings, and counts raw streamed bytes. Per-collection thread filters suppress
HTTPX/HTTPCore transport records so pagination tokens, response headers, and
cookies do not enter third-party HTTP logs. Opaque pagination tokens travel only
to the same endpoint, and combined pages are rechecked against aggregate JSON
tree limits before whole-document STIX validation and the caller-owned import
transaction. The production STIX and TAXII registries
remain empty, so no live source or approved live execution is configured.
Testing uses only synthetic files and `httpx.MockTransport`; no live TAXII
request was made.
There is no TAXII CLI, API route, frontend control, scheduler, startup hook, or
P9-11 threat-entity implementation. See
[STIX/TAXII Import](docs/stix-taxii-import.md) for the complete boundary.

## Security Principles

- Do not commit real .env files.
- Do not hardcode API keys, passwords, tokens, or private configuration.
- Keep external data collection limited to approved public sources.
- Do not fetch dangerous files or malware samples.
- Validate backend inputs.
- Render external text safely in the frontend.
- Log errors without exposing secrets.

### Frontend external-content rendering

P5-03 treats all feed and API content as untrusted at the frontend boundary.
Titles, summaries, source names, and other external text remain ordinary React
text nodes; raw feed HTML is not parsed or injected. External intelligence links
are centrally validated and become clickable only when they are absolute HTTP or
HTTPS URLs. URLs with credentials, unsafe schemes, malformed hosts or ports, or
control, format, whitespace, or other non-printable characters fail closed and
their labels render as non-clickable text. Valid links retain the existing new-tab
behavior with `rel="noopener noreferrer"`.

This frontend control is defense in depth. It does not make unsafe backend
ingestion or storage acceptable, and the P5-02 Content Security Policy remains a
separate response-layer safeguard.

### Backend logging and error correlation

P5-04 configures the standard-library `app` logger namespace through one
central handler. `LOG_LEVEL` accepts `DEBUG`, `INFO`, `WARNING`, `ERROR`, or
`CRITICAL`; the default is `INFO`, including production. Unsupported values are
rejected without echoing the configured value, production rejects `DEBUG=true`,
and Uvicorn's raw access logger is replaced by the application's safer request
completion events.

Every HTTP request receives a new server-generated canonical UUID in the
`X-Request-ID` response header. Incoming `X-Request-ID` values are ignored. One
request event contains only the event name, request ID, allow-listed method,
matched route template (or `unmatched`), status code, and duration in
milliseconds. It excludes raw paths, query values, bodies, response content,
headers, cookies, tokens, database URLs, external payloads, and client-provided
correlation values.

Unexpected request-time exceptions return the stable body
`{"detail":"An unexpected server error occurred."}` with the same request ID,
CORS behavior where applicable, and the existing P5-02 security headers. Logs
record only the safe category `unexpected_exception`, never exception text or a
traceback. Existing route-specific `400`, `404`, and handled `500` bodies and the
P5-01 generic `422` body remain unchanged. This is local application logging;
no remote telemetry or log-shipping service is introduced.

### Backend CORS and HTTP security headers

P5-02 restricts browser access through the existing backend settings model.
`BACKEND_CORS_ALLOWED_ORIGINS` is a comma-separated list of exact origins. The
safe local-development value is:

```text
http://localhost:3000,http://127.0.0.1:3000
```

Scheme, host, and non-default port are matched exactly. Default HTTP port `80`
and HTTPS port `443` are normalized away, and IP addresses use their canonical
representation. Wildcards, empty entries, URL paths, queries, fragments, user
information, unsupported schemes, malformed ports, and control, format,
whitespace, or other non-printable characters are rejected before URL parsing.
When `APP_ENV=production`, an explicit HTTPS-only allow-list is required and
localhost, `.localhost` subdomains, and IPv4/IPv6 loopback addresses are
rejected. A valid production example is
`https://dashboard.example.com`. Set `NEXT_PUBLIC_API_BASE_URL` to the backend
URL visible to that frontend, and never commit a real `.env` file or secrets.

The browser CORS method policy allows only `GET` and configures no additional
non-safelisted request headers. Starlette advertises the standard CORS-safelisted
`Accept`, `Accept-Language`, `Content-Language`, and `Content-Type` names during
preflight; this does not add write endpoints because the method allow-list
remains `GET`. Wildcard, authorization, and custom headers are not granted.
Credentials are disabled; the current application does not use browser cookies,
sessions, or authorization headers. Requests without an `Origin` header remain
available to ordinary API clients.

API and non-documentation responses include these exact headers:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'
```

The enabled `/docs` and `/redoc` HTML pages retain the first four headers but
omit the API CSP so FastAPI's existing interactive documentation remains
renderable; API routes keep the strict policy. HSTS is deferred because the
repository does not yet define trusted HTTPS termination or a trusted reverse
proxy. The backend does not trust arbitrary forwarded headers to make that
decision, and local HTTP development remains unaffected.

## Local development

### Prerequisites

Use the documented Windows workflow with Git, PowerShell, Python 3.13, Node.js
and npm, and Docker Desktop with the Docker Compose v2 plugin. Ports `3000`,
`8000`, and the configured local PostgreSQL port must be available for the
corresponding workflow. Never use real production data or secrets for local
development.

From the repository root, inspect prerequisites and create only missing ignored
local environment files:

```powershell
.\run.cmd setup
```

The setup helper copies the committed examples to `.env`, `backend/.env`, and
`frontend/.env.local` only when the destination is absent; it does not overwrite
an existing local file. Review the placeholders locally without printing or
committing completed values. Install backend and frontend dependencies with:

```powershell
.\run.cmd install
```

### Runner commands

Run these commands from the repository root. They are development and local
validation commands, not production deployment commands.

| Command | Implemented behavior |
| --- | --- |
| `.\run.cmd setup` | Check prerequisites and create missing local environment files without installing dependencies. |
| `.\run.cmd install` | Run setup, create the Python virtual environment when absent, and install backend and frontend dependencies. |
| `.\run.cmd test` | Run the complete backend pytest suite, frontend Vitest suite, frontend type-check, and frontend production build. |
| `.\run.cmd docker` | Validate development Compose, then build and start its default `db`, `backend`, `frontend`, `prefect-server`, and `prefect-worker` services, check local application endpoints, and show service status. The profile-gated `migrate` service does not start. |
| `.\run.cmd dev` | Start PostgreSQL with development Compose, then run the backend and frontend on the host with reload support. |
| `.\run.cmd full` | Run setup, install missing dependencies, execute the complete test workflow, then run the development Docker workflow. |
| `.\run.cmd help` | Display the runner command reference. |

With no argument, `run.cmd` defaults to `full`. For day-to-day development,
`dev` starts only PostgreSQL in Docker, then runs FastAPI at
`http://127.0.0.1:8000/` and Next.js at `http://127.0.0.1:3000/` on the host.
The host backend loads `backend/.env`; when a configured `DATABASE_URL` uses the
exact Compose hostname `db`, the runner gives only the child backend process an
equivalent `localhost` URL without printing it. Press Ctrl+C to stop the local
backend and frontend. The database container remains running for reuse.

### Local Prefect platform

Build and start only the local Prefect services from the repository root:

```powershell
docker compose up --build -d prefect-server prefect-worker
docker compose ps
```

The Prefect administration UI and API are published only on loopback at
`http://127.0.0.1:4200` by default. `PREFECT_PORT` may change the host port, but
not the `127.0.0.1` bind address. The worker health port is not published. The
server owns the `prefect_data` volume; the worker reaches state only through
`http://prefect-server:4200/api` and creates or reuses the fixed process work
pool `alpha-data-process`. This local platform boundary does not mean that any
source-specific ingestion handler or active schedule exists. C01's fixed
deployment must be registered explicitly and remains paused by default. See the
[C01 orchestration core](docs/c01-prefect-orchestration-core.md) for offline
validation and paused registration, and the historical
[B2-01 Prefect platform](docs/b2-01-prefect-platform.md) for infrastructure
health and persistence validation.

## Production-oriented deployment

Local development and production-oriented deployment are separate workflows.
Do not use `.\run.cmd dev`, `.\run.cmd docker`, `docker-compose.yml`, reload
servers, or development environment values for production. The standalone
[`compose.prod.yml`](compose.prod.yml) baseline uses production application
images, private database networking, loopback-default application bindings,
health checks, bounded local logs, a manual Alembic migration profile, and a
private self-hosted Prefect server/worker pair. Production publishes no Prefect
host port. The server uses only the internal `orchestration` network; the worker
uses only `orchestration` and the internal `database` network and receives only
the existing application database credential secret.

Use the canonical guides rather than duplicating or improvising secret and
deployment procedures here:

- [Environment and secret handling](docs/environment-and-secrets.md)
- [Production Docker deployment](docs/production-docker-deployment.md)
- [Deployment build validation](docs/deployment-build-validation.md)
- [B2-01 Prefect platform](docs/b2-01-prefect-platform.md)
- [C01 Prefect orchestration core](docs/c01-prefect-orchestration-core.md)

This is a hardened production-oriented baseline, not a complete or validated
public-internet production platform. The official PostgreSQL image uses the
operator-selected bootstrap identity for initialization and administration;
normal runtime does not reuse it. Provisioning creates a separate non-superuser
migration identity, a separate least-privilege runtime application identity,
and fixed read-only, logical-backup, and retention-planning groups. Production
delivers the three login passwords through separate secret files and publishes
no PostgreSQL host port. The named `postgres_data` volume is persistent storage,
not a backup. Automated backup and tested recovery are not implemented, and
destructive retention remains disabled until its safety and recovery evidence
exists.

Routine shutdown and destructive recovery procedures belong in the production
deployment guide. `docker compose down -v` deletes the persistent PostgreSQL
volume and its database data; it is not routine cleanup and requires exact
target verification, a verified backup and recovery plan, and explicit
authorization.

## Tests and validation

From the repository root, the authoritative complete local regression is:

```powershell
.\run.cmd test
```

It runs backend pytest, frontend Vitest, frontend type-checking, and the frontend
production build. Tests use synthetic or mocked inputs and must not contact live
OSINT sources unless a separately documented manual smoke command is explicitly
invoked.

### Frontend component tests

The frontend uses Vitest, jsdom, and React Testing Library. Tests run offline
with synthetic fixtures and mocked frontend service responses; they do not need
a running backend, database, Docker service, live OSINT source, or secret.

From `frontend`, run the suite once for automated validation:

```powershell
npm run test:run
```

Use watch mode during local test development:

```powershell
npm test
```

The project-level `.\run.cmd test` workflow includes the one-shot frontend
suite. The standalone `npm run validate:safe-rendering` command remains
available for the broader P5-03 URL and text-payload validation. This repository
does not currently define a CI workflow.

### Backend API tests

The backend API tests run offline with deterministic dependency overrides. They
cover the public metadata, dashboard summary, article list/detail, intelligence
list/detail, validation, pagination, error, CORS, request-ID, and security-header
contracts. From the repository root, run the focused suite with:

```powershell
$OriginalTemp = $env:TEMP
$OriginalTmp = $env:TMP
$OriginalPytestAddopts = $env:PYTEST_ADDOPTS
$ValidationTemp = Join-Path $env:USERPROFILE "pytest-temp-api"
New-Item -ItemType Directory -Path $ValidationTemp -Force | Out-Null
$env:TEMP = $ValidationTemp
$env:TMP = $ValidationTemp
Remove-Item Env:PYTEST_ADDOPTS -ErrorAction SilentlyContinue

Push-Location .\backend
.\.venv\Scripts\python.exe -m pytest `
    tests/test_health.py tests/test_version.py `
    tests/test_dashboard_summary_api.py tests/test_articles_api.py `
    tests/test_intelligence_api.py tests/test_security_middleware.py `
    tests/test_logging_and_errors.py -q -p no:cacheprovider
Pop-Location

$env:TEMP = $OriginalTemp
$env:TMP = $OriginalTmp
if ($null -eq $OriginalPytestAddopts) {
    Remove-Item Env:PYTEST_ADDOPTS -ErrorAction SilentlyContinue
} else {
    $env:PYTEST_ADDOPTS = $OriginalPytestAddopts
}
```

The alternate temp directory avoids Windows profile temp-folder permission
problems and remains outside the repository. Full project validation remains
`.\run.cmd test`. The current dependency set can emit the known
`StarletteDeprecationWarning` about the FastAPI/Starlette test client and
`httpx`; this does not indicate a test failure.

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

### Manual curated multi-year NVD dataset

The separate curated command builds a representative sample rather than a
complete NVD mirror. Its defaults target 20 CVEs per UTC publication year from
2020 through the current UTC year: 10 Critical, 5 High, 3 Medium, and 2 Low.
Within each severity it prioritizes NVD records carrying CISA KEV metadata, then
orders by CVSS score, NVD last-modified time, and CVE ID.

Preview the validated plan without network or database access:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.nvd_curated_cli --plan
```

Run the network- and database-active workflow only through explicit operator
invocation:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.nvd_curated_cli `
    --start-year 2020 `
    --end-year 2026 `
    --chunk-days 90 `
    --results-per-page 50 `
    --max-pages-per-query 2 `
    --max-requests 400 `
    --retention-multiplier 1
```

Replace `2026` with the current UTC year. Candidate requests use only the fixed
NVD endpoint and typed publication, CVSS v3/v4 severity, pagination, and KEV
filters. The client rejects an oversized valid `Content-Length` before body
consumption and otherwise stops its decoded streaming read immediately above
20 MiB. By default, each year retains at most 10 Critical, 5 High, 3 Medium, and
2 Low full candidates; discarded or evicted valid candidates make that year
incomplete. Page/request caps and quota shortfalls are likewise explicit, and
the summary identifies every capped or incomplete year.

Audit counts include malformed, duplicate, retention-discarded, and valid
unselected observations as skipped, and the completion timestamp is captured
after processing. Existing CVEs use the normal update/unchanged path, unrelated
CVEs are never deleted, and the incremental NVD checkpoint is not advanced.
Run FIRST EPSS and CISA KEV commands separately as operator workflows. The
catalog-driven bounded CISA run does not prove a not-listed KEV result for every
local CVE; only the separate complete-catalog local reconciliation can do so.

> This product uses data from the NVD API but is not endorsed or certified by the NVD.

See [the NVD ingestion guide](docs/nvd-ingestion.md) for limits and known
limitations.

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

### Manual CISA KEV local reconciliation

The existing `app.ingestion.cisa_kev_cli` command is catalog-driven and marks
bounded matched catalog entries as listed. The separate command below fetches
and validates every declared catalog entry before assigning listed or
not-listed status to bounded local vulnerability rows:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.cisa_kev_reconcile_cli `
    --max-cves 500 `
    --batch-size 100
```

Use `--plan` to show the fixed source and bounds without network or database
access. `--max-cves` accepts 1 through 500 local rows and `--batch-size` accepts
1 through 100. An empty, partial, malformed, interrupted, or oversized catalog
cannot produce a not-listed result. The database-active command commits once
after all selected batches and safe audit records complete. A clean result is
`succeeded` with exit code 0. A skipped selected row or any selected row still
in `unknown` state produces a controlled `partial` result with exit code 1;
valid status changes and safe audit records are still committed. The
`unknown_remaining` count includes only selected rows that remain in the
`unknown` state.

Formal `IngestionRun` counters describe local rows and reconcile exactly:
fetched equals created plus updated plus unchanged plus skipped plus failed,
with created fixed at zero. Catalog raw-record and unique-CVE counts remain
separate summary and checkpoint evidence. The start time is captured before
catalog fetch, the checked time after complete validation immediately before
local reconciliation, and the completion time after local reconciliation and
audit processing. Repeated successful runs are idempotent apart from refreshing
the KEV checked timestamp.

Selection produces exactly one outcome per unique vulnerability row and always
starts with the lowest local vulnerability IDs. Global CVE identifiers are
loaded separately for each bounded batch. A row with no usable global CVE or
more than one distinct usable global CVE is skipped; ambiguous identity never
selects a CVE based on identifier query order. A skipped row still in the
`unknown` state makes the run a controlled partial result. Catalog-version
evidence is restricted to a non-empty, bounded ASCII token containing only
letters, digits, periods, underscores, and hyphens.

Because the command is capped at 500 rows, a database with more than 500
vulnerabilities requires a future cursor/resume enhancement to reconcile later
IDs. This remains manual-only: no scheduler, startup execution, public
ingestion API, or frontend trigger invokes it.

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

### Manual Censys publication ingestion

The Censys live collector is network- and database-active but manual-only. From
the `backend` directory, use one of these Windows PowerShell commands for the
two supported and source-separated publication families:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.censys_publications_live_cli `
    --source arc `
    --max-records 5

.\.venv\Scripts\python.exe -m app.ingestion.censys_publications_live_cli `
    --source rapid-response `
    --max-records 5
```

`--source` is required and accepts only `arc` or `rapid-response`.
`--max-records` defaults to 5 and its valid range is 1 through 20. No arbitrary
URL is accepted: the discovery locations are fixed in code, and discovered
publication links must remain in the selected approved Censys path family. The
collector bounds redirects, response sizes, accepted HTML content types, and
request pacing. It allows no more than three redirects, reads at most 2 MiB per
response, and enforces at least ten seconds between request starts.

The collector retrieves publication metadata only. Raw HTML or JSON-LD is not
stored. Normalized allow-listed metadata enters the existing Censys adapter and
shared ingestion service, then the common publication pipeline and database.
Safe partial failures are audited without URLs, raw exception details, response
content, or headers. Rerunning a command deduplicates through the existing
publication pipeline; existing manually imported catalogue records do not need
to be deleted.

The implemented path is:

```text
manual command
    -> fixed approved Censys discovery page
    -> secure bounded collector
    -> existing Censys adapter
    -> shared Censys ingestion service
    -> existing publication pipeline
    -> database and safe ingestion audit records
```

Before live ingestion:

1. Activate the backend virtual environment with
   `.\.venv\Scripts\Activate.ps1`.
2. Confirm the approved environment configuration provides the database
   settings; do not place a database URL or credentials in the command.
3. Confirm Alembic migrations are current with the repository's approved
   migration checks.
4. Run only one manual Censys collection at a time. Start with
   `--max-records 1` or `--max-records 5`.
5. Expect at least ten seconds between request starts. Even a small run can take
   several minutes, so do not interrupt it unless necessary.
6. Review the safe run summary, then inspect stored application records through
   approved read-only API or database tooling.

A successful ARC run prints only an allow-listed summary in this format:

```text
Manual Censys live ingestion completed.
Source: censys-arc-research
Run ID: <run-uuid>
Status: succeeded
Fetched: 5
Created: 0
Updated: 0
Unchanged: 5
Skipped: 0
Failed: 0
Capped: false
```

The summary never prints publication URLs, titles, source external IDs,
internal database IDs, raw exceptions, HTTP headers, or response content.
Invalid arguments fail before collection with exit code 2. Discovery-level
failure occurs before database-session creation. A run may store valid
publications when another page fails; mixed success and failure produces a
`partial` run, while all-page failure produces a `failed` run. Controlled
collection, partial, failed, and database-error outcomes return exit code 1;
database failures are rolled back and console errors remain sanitized. A fully
successful run returns exit code 0. System-level interruptions propagate and
are not converted into false success.

The reviewed local-file fallback remains available when live collection is not
appropriate:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.censys_publications_cli `
    --file <reviewed-local-json-file>
```

The local file must be reviewed and conform to the existing strict Censys
catalogue schema. It is UTF-8 JSON limited to 1 MiB and 100 publication records,
with exactly `schema_version`, `source_slug`, and `publications` at the document
level and the existing exact publication fields. Author and category lists are
each limited to 20 plain-text values. The input must use an ordinary local path;
UNC/network and Windows device-namespace paths are rejected before traversal.
This fallback reads only the supplied regular file and makes no Censys network
request.

No scheduler, recurring background job, startup ingestion, public ingestion
endpoint, or automatic frontend invocation is installed. The feature collects
defensive public research publication metadata only; it must not be used to
scan, probe, search, or rescan internet assets and does not use a Censys account,
API key, or scanning API.

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

### Manual Anomali Cyber Watch publication ingestion

From the `backend` directory, an operator can run the secure live collector:

```powershell
.\.venv\Scripts\python.exe `
    -m app.ingestion.anomali_publications_live_cli `
    --max-records 5
```

This command is manually triggered only. `--max-records` defaults to 5 and its
supported range is 1 through 20. The collector requests only the fixed discovery
URL `https://www.anomali.com/blog`; it accepts no arbitrary URL. Discovery and
article requests require HTTPS, exact host `www.anomali.com`, and the literal
Cyber Watch article path `/blog/anomali-cyber-watch-...`. Redirects are followed
only after explicit validation. Requests are not automatically retried, start at
least ten seconds apart, and have bounded timeouts and response sizes.

The live collector extracts bounded publication metadata only and does not parse
article-body prose. It screens selected title, summary, author, and category
metadata for IOC-like URLs, IP addresses, domains, hashes, internationalized
domains, and common defanged forms; unsafe metadata is rejected before adapter
invocation. Raw HTML, HTTP headers, cookies, attachments, media, PDFs, downloads,
and malware samples are not persisted by live collection.

Collection completes before a database session is opened. If collection
succeeds, persistence is atomic and safely audited through the existing
publication pipeline. Console output uses allow-listed summaries; raw HTTP and
database errors are not exposed.

The currently operational method is the reviewed local JSON fallback:

```powershell
.\.venv\Scripts\python.exe `
    -m app.ingestion.anomali_publications_cli `
    --file C:\path\to\anomali-cyber-watch.json
```

The local command accepts only schema version 1 for source slug
`anomali-cyber-watch`, with at most 100 exact seven-field records in a 1 MiB
UTF-8 file. It validates the title family, canonical URL identity, timestamps,
plain-text bounds, authors, and categories. The input must be reviewed,
operator-prepared publication metadata only. Operators and reviewers must
exclude article-body text; IOCs and observables; hashes, IP addresses, and
domains used as indicators; raw HTML; HTTP headers and cookies; and attachments,
media, PDFs, downloads, or malware samples. The local adapter is not a
comprehensive automatic IOC detector. The verified five-record catalogue was
reviewed and contained safe metadata. There is no scheduler, recurring
background job, startup ingestion, public ingestion API, or frontend trigger.

Manual live Anomali Cyber Watch collection is implemented and validated
offline. During a controlled live smoke test on 19 July 2026, the fixed official
blog page returned HTML with no deterministic main-content region and no
approved Cyber Watch article links. Discovery therefore failed safely before an
article request was issued and before database-session creation; no ingestion
run was created and no live records were persisted. The request was not rejected
with HTTP 403; the observed response status was HTTP 200. The reviewed safe local
JSON catalogue was then imported successfully for source
`anomali-cyber-watch`: 5 records were fetched, created, and linked. Reviewed
local JSON ingestion remains the currently supported operational method.

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

The two list endpoints use bounded offset pagination: `limit` defaults to `25`
and accepts `1` through `100`, while `offset` defaults to `0` and accepts `0`
through `10,000`. Out-of-range values return sanitized HTTP `422`. Every
currently implemented query parameter is single-value; repeated scalar names,
unknown names, and unimplemented names such as `sort` return `422` after
percent-decoding. Different supported parameters can still be combined. The
dashboard summary accepts only `window_days`; article/intelligence detail,
`GET /`, `GET /api/health`, and `GET /api/version` accept no query parameters.

The implemented `q` fields are plain-text searches with a maximum supplied
length of 120 characters. Surrounding whitespace is trimmed, while
whitespace-only values, NUL/control or non-printable characters, embedded line
breaks, Unicode format/control characters, and `<` or `>` return `422`.
Ordinary Unicode and useful punctuation remain valid. SQL LIKE wildcard and
escape characters are treated literally, and raw payloads or sensitive fields
are never searched. Article search covers title and summary; intelligence-item
search also covers the primary CVE identifier.

Article and intelligence detail IDs must be canonical 36-character hyphenated
UUIDs such as `12345678-1234-5678-1234-567812345678`. Uppercase hexadecimal is
accepted and normalized; compact, braced, malformed, or overlong UUIDs return
`422`, while a correctly formatted nonexistent UUID returns `404`. Current
P5-01 validation failures use the sanitized body
`{"detail":"Request validation failed."}` without echoing rejected input or
exposing parser internals, exception context, stack traces, headers, database
details, or configuration. A richer standardized error envelope remains future
error-handling work.

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

## Canonical documentation

Use the root README as the entry point and the following documents as the
authoritative detailed references:

| Area | Canonical document |
| --- | --- |
| Phase A evidence and Phase B start checkpoint | [Phase A baseline](docs/phase-a-baseline.md) |
| System design and data flow | [Architecture](docs/architecture.md) |
| Implemented and candidate sources | [Data sources](docs/data-sources.md) |
| Vendor-family decisions | [Source assessment matrix](docs/source-assessment-matrix.md) |
| Source authorization and safety rules | [Source integration policy](docs/source-integration-policy.md) |
| Application security controls | [Security notes](docs/security-notes.md) |
| Automated testing strategy | [Testing plan](docs/testing-plan.md) |
| Human-executed QA cases | [Manual test cases](docs/manual-test-cases.md) |
| Environment variables and secrets | [Environment and secret handling](docs/environment-and-secrets.md) |
| Production-oriented operation | [Production Docker deployment](docs/production-docker-deployment.md) |
| Self-hosted workflow orchestration platform | [B2-01 Prefect platform](docs/b2-01-prefect-platform.md) |
| Prefect flow, deployment, reliability, and progress contracts | [C01 Prefect orchestration core](docs/c01-prefect-orchestration-core.md) |
| Verified local deployment-build evidence | [Deployment build validation](docs/deployment-build-validation.md) |
| Development deployment notes | [Deployment notes](docs/deployment-notes.md) |
| UAE classification semantics | [UAE classification](docs/uae-classification.md) |

## Known limitations

- Operational ingestion remains manual-only. C01 defines generic flows and one
  paused-by-default deployment specification, but no source handler is bound,
  no schedule is active, and there is no startup ingestion, public ingestion
  route, or frontend ingestion control.
- Some dashboard preview panels still use deterministic preview data; the
  implemented article, vulnerability, summary, detail, and recent-trend views
  use read-only backend APIs as described above.
- TLS termination, HSTS trust, a reverse proxy, and a load balancer are not
  included.
- Automated PostgreSQL backups, representative restore testing, and validated
  disaster recovery are not included. The persistent volume is not a backup.
- Logs are bounded locally, but centralized logging, production monitoring, and
  alerting are not integrated.
- CI/CD deployment, Kubernetes or another orchestration platform for container
  deployment, autoscaling, zero-downtime deployment, and automated secret
  rotation are not implemented. Prefect provides workflow orchestration only.
- Prefect uses one server and SQLite state, with no high availability, Redis,
  Prefect-specific PostgreSQL, authentication, backup/restore proof, or staging
  deployment. Network isolation is the current administration boundary.
- Current production Compose separates the privileged PostgreSQL bootstrap
  identity from non-superuser migration and runtime application identities;
  read-only, logical-backup, and retention-planning groups remain bounded to
  their implemented duties. Staging/production provisioning, backup execution,
  destructive retention, and recovery evidence remain future operational work.
- Production load, capacity, failover, and public-internet deployment have not
  been validated.
- The backend production image currently installs the shared requirements file,
  which includes development and test dependencies.
- Manual QA cases remain `Not Run` until a tester executes them and records
  evidence; automated regression does not change their status.

## Reviewer and mentor handover path

1. Read this README for scope, implemented behavior, local commands, and known
   limitations.
2. Review [Architecture](docs/architecture.md), [Data sources](docs/data-sources.md),
   and the [Source integration policy](docs/source-integration-policy.md) before
   evaluating data-collection claims.
3. Review [Security notes](docs/security-notes.md) and
   [Environment and secret handling](docs/environment-and-secrets.md) before
   evaluating configuration or deployment.
4. Use [Testing plan](docs/testing-plan.md),
   [Manual test cases](docs/manual-test-cases.md), and
   [Deployment build validation](docs/deployment-build-validation.md) to
   distinguish automated, manual, and deployment evidence.
5. Use [Production Docker deployment](docs/production-docker-deployment.md) only
   with protected external configuration and the documented operational
   controls. Do not infer full production readiness from a successful local
   Compose build.

Before staging any handover update, independently review the complete changed
files together with the focused and full-regression evidence.
