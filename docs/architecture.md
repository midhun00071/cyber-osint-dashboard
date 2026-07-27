# Architecture

## Purpose and audience

This document describes the implemented technical design of the Alpha Data /
Cyber OSINT Dashboard for mentors, senior cybersecurity reviewers, developers,
and deployment reviewers. It explains component ownership, data and trust
boundaries, development and production-oriented runtimes, security controls,
test architecture, and known limitations. It is a review guide for the current
repository, not an aspirational design or a claim of public-internet production
readiness.

## Defensive and ethical scope

The system collects and presents defensive public cybersecurity intelligence
through explicitly approved, bounded workflows. It is intended for authorized,
ethical, educational, or lab-safe analysis. It must not be used for arbitrary
URL collection, active scanning or target probing, active IOC validation,
exploit execution, credential collection, malware retrieval, file submission,
or offensive automation.

External OSINT is untrusted data. Public visibility does not grant collection
authorization, licensing, storage, mirroring, redistribution, or API rights.
Source onboarding remains subject to the documented approval process; a source
registry entry does not grant legal authorization, credentials, or permission
for a new live collection method.

## Architecture principles

- Ingestion is manual-only and explicitly operator invoked.
- Fixed endpoints, exact hosts, closed selectors, or reviewed local files bound
  every implemented source workflow; operators cannot supply network URLs.
- Collectors, adapters/normalizers, persistence, queries, and presentation have
  separate responsibilities.
- PostgreSQL is the authoritative persistence layer; frontend preview data is
  clearly labeled where it remains presentational only.
- Public APIs are read-only and expose allow-listed response schemas rather than
  ORM objects or raw source records.
- External text is treated as untrusted plain text throughout collection,
  persistence, API serialization, and React rendering.
- Secrets and internal errors are excluded from source, responses, logs, and
  review evidence.
- Development convenience and production-oriented configuration are separate
  architectures with different risk boundaries.
- Absent controls and operational limitations are documented rather than
  implied to exist.

## High-level system context

```text
Approved public intelligence sources
        |
        | Explicit manual collector/CLI execution
        v
Backend ingestion, validation, and normalization
        |
        | SQLAlchemy ORM-managed persistence
        v
PostgreSQL

Defensive analyst browser
        |
        +--> Next.js frontend through its published frontend URL
        |
        +--> FastAPI query endpoints through the browser-resolvable
             NEXT_PUBLIC_API_BASE_URL
                  |
                  | Allow-listed read-only response schemas and
                  | backend-controlled SQLAlchemy sessions
                  v
              PostgreSQL
```

Dashboard and detail API calls originate in the browser. The public
`NEXT_PUBLIC_API_BASE_URL` value is embedded in the frontend browser assets at
build time; the frontend container does not proxy the current API requests.
The browser has no direct access to PostgreSQL or external intelligence
sources, and the backend remains the only application component that accesses
PostgreSQL. There is no direct frontend-to-source or frontend-to-PostgreSQL
connection. The diagram does not imply automatic collection: FastAPI startup
creates no ingestion job, scheduler, recurring background worker, frontend
ingestion trigger, or public ingestion API.

## Major components and responsibilities

| Component | Implemented responsibility | Boundary |
| --- | --- | --- |
| Source registry | Developer-controlled source identity, vendor, content family, access method, implementation/enabled state, fixed base URL, and exact host allow-list | Metadata and enabled status do not execute or authorize collection |
| Collectors | Retrieve an approved fixed feed/API/publication location, or accept the workflow’s reviewed local input | Bounded timeouts, redirects, response/file sizes, record counts, content types, and safe failures; no arbitrary network URL |
| Adapters and normalizers | Convert source-specific untrusted structures into normalized CVE/enrichment records or `PublicationCandidate` values | Validate schema, plain text, timestamps, URLs, and source ownership before persistence |
| Ingestion services and CLIs | Orchestrate explicit source runs, database sessions, workflow-specific transactions, and sanitized run/error evidence | No startup, scheduler, background, frontend, or public-API invocation |
| Common publication pipeline | Validate candidates, derive item type, normalize safe metadata, apply identity/deduplication rules, and persist through the supplied session | Fetches no upstream content and does not universally own commit/rollback |
| Processing | Deterministic UAE relevance classification and bounded IOC extraction from normalized publication title/summary fields | No network, active validation, raw-payload access, LLM, machine learning, or public mutation route |
| PostgreSQL and SQLAlchemy | Store normalized intelligence, provenance, identifiers, tags, vulnerabilities, and ingestion audit records | Persistence is not backup; access is through backend/migration sessions |
| FastAPI | Validate read-only queries and serialize allow-listed health, version, dashboard, article, and intelligence responses | No write, ingestion, administration, authentication, or authorization endpoint |
| Next.js | Fetch validated API data and present dashboard/list/detail states safely | No source collection, database connection, credentials, or raw HTML rendering |

## Repository and module structure

```text
backend/
  app/
    api/v1/routes/       read-only HTTP route groups
    api/v1/schemas/      allow-listed public response contracts
    core/                settings, logging, request context, security headers
    db/                  SQLAlchemy engine/session and declarative metadata
    models/              ORM persistence model
    services/            read/query services
    ingestion/           registry, collectors, normalizers, adapters, CLIs,
                         source services, and common publication pipeline
    processing/          deterministic UAE relevance processing
  alembic/               migration environment and versioned schema
  tests/                 backend, security, documentation, Compose, and runner tests
frontend/
  src/app/               App Router dashboard and detail pages
  src/components/        dashboard and safe-link presentation components
  src/services/          browser API clients and response validators
  src/types/             public frontend data contracts
  src/utils/             safe URL and display helpers
compose.prod.yml         production-oriented runtime and manual migration profile
docker-compose.yml       local development container stack
run.cmd / run.ps1        Windows setup, test, Docker, and host-development runner
docs/                    canonical design, security, source, test, and operations guides
```

## End-to-end data flow

### Vulnerability flow

```text
Operator runs NVD CLI (incremental or curated)
  -> fixed NVD API collector
  -> bounded modification window or publication-year candidate selection
  -> NVD vulnerability normalizer
  -> NVD ingestion service
  -> CVE identity + vulnerability persistence
  -> optional later operator-run FIRST EPSS enrichment
  -> optional later operator-run CISA KEV enrichment
  -> read-only intelligence/dashboard APIs
  -> validated frontend lists, trends, and detail view
```

The curated path is a deterministic bounded representative sample, not complete
NVD coverage. It defaults to 2020 through the current UTC year, applies explicit
severity quotas after CVSS v3/v4 normalization, prioritizes NVD candidates with
CISA KEV metadata, and reports page/request caps or quota shortfalls as
incomplete. Retained-candidate ceilings are reported the same way. The collector
enforces its 20 MiB limit while streaming decoded bytes rather than
materializing an unbounded response. Candidate memory is also bounded per
severity and year; the default retained limits equal the 10/5/3/2 quotas.

Every inspected curated observation reconciles into a persistence outcome or a
skipped category, including malformed, duplicate, retention-discarded, and
valid unselected candidates. Completion time is obtained after processing, not
copied from the start time. Both NVD paths create or update normalized
vulnerability items through the same identity and persistence service; neither
deletes unselected CVEs. FIRST EPSS uses local CVE identifiers to enrich
existing vulnerability records with score, percentile, and score-date evidence;
it does not create arbitrary CVEs. The catalog-driven CISA KEV workflow likewise
enriches bounded listed matches and skips unknown KEV-only entries; it does not
prove a `not_listed` result for every local CVE. The separate local
reconciliation workflow first validates every declared catalog entry, then
assigns `listed` or `not_listed` to bounded local vulnerability rows in one
caller-owned transaction. A partial, capped, malformed, or failed catalog
cannot produce `not_listed`, and a database failure rolls back all selected
status and audit changes. A skipped selected row or one that remains `unknown`
is a controlled partial run: valid reconciliation and safe audit changes commit,
but the command returns exit code 1. `unknown_remaining` counts selected rows
still in the `unknown` state.

The reconciliation `IngestionRun` counters describe local rows and satisfy
fetched = created + updated + unchanged + skipped + failed; catalog raw-entry
and unique-CVE counts remain separate summary/checkpoint evidence. Its start,
checked, and completion timestamps are captured before fetch, after complete
catalog validation immediately before reconciliation, and after local
reconciliation plus audit processing, respectively. Local selection always
starts at the lowest vulnerability IDs and produces one outcome per unique
vulnerability row. Each bounded batch loads global CVE identifiers separately.
Missing or ambiguous global CVE identity is skipped, and ambiguous identity
never selects a CVE based on identifier query order. A skipped row that remains
`unknown` causes the controlled partial result. Catalog-version evidence is a
bounded safe ASCII token containing only letters, digits, periods, underscores,
and hyphens. The 500-row cap therefore requires a future cursor/resume
enhancement for databases containing more than 500 local vulnerabilities.
These workflows are source-data processing, not active vulnerability scanners.

> This product uses data from the NVD API but is not endorsed or certified by the NVD.

### Publication flow

```text
Fixed feed / fixed public discovery page / reviewed local JSON
  -> source-specific collector or bounded file adapter
  -> source-specific adapter
  -> PublicationCandidate
  -> common PublicationPipeline
  -> article identity and deduplication
  -> PostgreSQL
  -> read-only article/intelligence APIs
  -> validated frontend feed and detail view
```

CERT-EU, Google Threat Intelligence/Mandiant, Censys, Anomali Cyber Watch, and
IBM X-Force use source-specific collection or reviewed-file boundaries described
in [Data Sources](data-sources.md). Publication item type is derived from the
registered content family, not supplied by the adapter. Security advisories and
public OSINT advisories become `security_advisory`; threat and exposure research
become `threat_report`.

The common `PublicationPipeline` validates and persists candidates using a
caller-supplied SQLAlchemy session. It does not fetch upstream content and does
not commit transactions. Transaction ownership is workflow-specific: some
invoking CLIs own commit/rollback, while Censys local/live and live Anomali
delegate transaction and audit ownership to their source-specific ingestion
services. The reviewed local-file Anomali CLI owns its own transaction.

### Publication IOC extraction

P9-09 adds an offline, explicitly invoked processing foundation after normalized
publication persistence. It considers only `canonical_title` and `summary` for
allow-listed `security_advisory` and `threat_report` items. Bounded deterministic
rules identify supported observables, normalize them through the P9-08 boundary,
and store only a `mentioned` publication relationship plus exact source-record
provenance. A mention is not a claim that an observable is malicious, active,
confirmed, exploited, or attributed.

The service uses its caller's SQLAlchemy session and may flush a new indicator
identity, but it never commits or rolls back. It reads no raw payload and makes
no DNS, HTTP, socket, scanning, probing, file, or malware request. Existing
`false_positive` indicators suppress automatic relationship and provenance
writes. Historical evidence is audit-preserving: a later source-text change
does not automatically delete prior indicators, relationships, or provenance.
The detailed rules and limits are documented in [IOC Extraction](ioc-extraction.md).

### Audit flow

```text
Explicit source run
  -> IngestionRun status and bounded counters
  -> per-record IngestionRunRecord outcomes
  -> sanitized IngestionError evidence when needed
  -> commit or rollback by the owning CLI/service
```

Audit records use safe trigger/status/outcome fields, counts, timestamps,
retryability, and sanitized summaries. They do not expose credentials, request
or response headers, cookies, complete exception objects, stack traces, raw SQL,
or database URLs. The publication pipeline itself is not the universal audit or
transaction owner.

## Source-ingestion architecture

The static source registry contains eleven enabled implemented source identities
for NVD, FIRST EPSS, CISA KEV, CERT-EU, two Censys families, Anomali Cyber Watch,
two IBM X-Force families, Google Threat Intelligence research, and Mandiant
research. Its source metadata, access methods, commands, bounds, and exclusions
are maintained in [Data Sources](data-sources.md). Enabled status only permits
the reviewed code path to create or validate its `IntelligenceSource`; it does
not create automatic execution or authorize arbitrary collection.

Collectors enforce controls verified for their source, including fixed HTTPS
locations/exact hosts, request timeouts, redirect validation where applicable,
bounded response sizes, record limits, expected content, and sanitized status
handling. Reviewed-file adapters additionally enforce strict UTF-8 JSON shape,
file/record limits, direct local paths, and source-specific URL families. No
generic crawler or arbitrary URL collector is implemented.

Adapters and normalizers treat all upstream values as untrusted. They validate
source identity, required fields, text length and safety, timezones, source URL,
and bounded metadata before a value reaches persistence. Raw HTML, attachments,
headers/cookies, downloaded reports, and malware samples do not cross the
approved publication-metadata boundary or appear in public APIs.

### Censys boundary

The bounded live and reviewed local-file Censys workflows cover only ARC
research and Rapid Response publication metadata. A closed selector maps to a
fixed approved public discovery page in code. The shared Censys ingestion
service owns audit and transaction handling before candidates enter the common
pipeline and stores no raw HTML or JSON-LD. The P9-04 reviewed local-file
importer remains the fallback. Exposure records, hosts, certificates, DNS data,
scan/search results, scanning, probing, and rescanning are excluded.

### Google Threat Intelligence and Mandiant boundary

One fixed public RSS feed is split into two logical sources only by exact feed
author: `Google Threat Intelligence Group` and `Mandiant`. The adapter does not
infer ownership from titles, categories, products, links, threat names, or
article text. It ignores feed content bodies, reports, PDFs, attachments, and
media. Google TI/VirusTotal APIs, credentials, file submission/retrieval,
malware retrieval, and source-specific IOC extraction are not implemented in
this ingestion workflow. Eligible normalized publications may be processed
separately by the offline P9-09 title/summary extraction foundation.

### Anomali Cyber Watch boundary

Anomali is limited to Cyber Watch publication metadata on the exact approved
host and literal article path family. The live collector does not parse
article-body prose. It screens selected title, summary, author, and category
metadata for IOC-like URLs, IP addresses, domains, hashes, internationalized
domains, and common defanged forms; unsafe metadata is rejected before adapter
invocation.

The reviewed local catalogue is a reviewed, operator-prepared input containing
publication metadata only. The adapter is not a comprehensive automatic IOC
detector. Reviewers must exclude article-body text, IOCs and observables, raw
HTML, HTTP headers and cookies, attachments, media, PDFs, downloads, and malware
samples. The verified five-record catalogue was reviewed and contained safe
metadata.

During controlled live validation on 19 July 2026, the fixed official discovery
page returned HTML with no deterministic main-content region and no approved
Cyber Watch article links. Discovery failed safely before an article request
was issued and before database-session creation; no live records were persisted.
The request was not rejected with HTTP 403; the observed response status was HTTP 200.
The reviewed local-file workflow remains the currently operational method.

### IBM X-Force boundary

IBM X-Force support is limited to two reviewed manual JSON metadata families:
IBM Think X-Force research and public Exchange OSINT advisory identifiers. The
application makes no IBM request. IBMid/guest automation, scraping, APIs,
reputation/indicator queries, collections, comments, paid data, report or
attachment downloads, malware retrieval, and STIX/TAXII are excluded.

## Normalized indicator foundation (P9-08)

P9-08 adds a metadata-only foundation for normalized defensive indicators. The
supported observable types are IPv4 addresses, IPv6 addresses, domains, HTTP or
HTTPS URLs, and MD5, SHA-1, SHA-256, or SHA-512 file-hash metadata. A pure
offline validation boundary canonicalizes each value. Internationalized domain
names use the maintained IDNA implementation with UTS #46 processing, STD3
rules, and non-transitional behavior. The boundary derives a lowercase SHA-256
identity fingerprint from an unambiguous representation of the observable type,
optional hash algorithm, and normalized value. The fingerprint provides bounded
duplicate protection without creating a unique index over a potentially long
canonical URL.

Indicators carry an explicit lifecycle status, optional bounded context,
confidence from zero through one, and timezone-aware observation, revocation,
and expiry metadata. Source provenance links an indicator to an approved
`intelligence_sources` row and optionally to a `source_records` row, with
partial unique indexes preventing duplicate source attribution both with and
without a source record. A composite database foreign key requires any linked
source record to belong to that same registered intelligence source. Source
records referenced by indicator provenance are deletion-restricted for audit
integrity; provenance must be deliberately removed or migrated through a
separately reviewed operation first. Public UUIDs are the safe external
identifiers; internal bigint identities remain database-only.

This P9-08 foundation performs syntax validation only. It does not resolve
domains, connect to indicators, retrieve URLs or files, download malware, scan,
probe, enrich, or import STIX/TAXII data. It adds no ingestion trigger,
scheduler, startup processing, public API route, or frontend exposure. P9-09
builds on it with a separately reviewed, bounded offline title/summary
extraction service and `mentioned` publication relationships; P9-10 and later
enrichment and analyst-review tasks remain unimplemented.

## Normalization, identity, deduplication, and persistence

Normalized records preserve the canonical source, external source identifier,
safe source link, bounded title/summary, source timestamps, observation times,
item type/status, and workflow-specific vulnerability or publication metadata.
The application uses stable content hashes to distinguish created, unchanged,
and updated evidence.

NVD identity is anchored by the global canonical CVE namespace/value and NVD
source external ID. EPSS and KEV locate that existing CVE identity rather than
creating a second vulnerability. Publication source records use a source-owned
external ID and canonical URL hash. Global canonical-URL and normalized-title
SHA-256 identifiers can link the same trusted article type across sources;
conflicting URL/title/type signals fail safely or require analyst review.
Cross-type merging between `security_advisory` and `threat_report` is refused.

The common publication pipeline derives item type from registry content family,
normalizes timezone-aware dates to UTC, removes tracking query parameters,
rejects credentials and sensitive signed-query aliases, and bounds safe shallow
metadata. Control characters, Unicode surrogates, oversized identities, nested
payloads, and unsafe database text fail before persistence.

## Database and migration architecture

PostgreSQL is the authoritative persistence layer. SQLAlchemy supplies the
declarative ORM, synchronous query/persistence sessions, relationships,
constraints, and indexes. FastAPI’s session dependency lazily creates a pooled
engine, yields one session per request, and always closes it; query routes do not
commit. Ingestion transaction ownership remains explicit in the workflow.

The current schema contains:

- `intelligence_items` for lifecycle, normalized content, geographic/UAE fields;
- `vulnerabilities` for CVSS, EPSS, KEV, and affected-product extensions;
- `intelligence_sources` and `source_records` for source identity/provenance;
- `indicators` and `indicator_provenances` for canonical observable metadata
  and bounded source attribution;
- `intelligence_item_identifiers` for CVE and publication fingerprints;
- `tags` and `intelligence_item_tags` for controlled tagging;
- `ingestion_runs`, `ingestion_run_records`, and `ingestion_errors` for safe
  execution evidence.

Alembic owns schema migration through `backend/alembic.ini`, the migration
environment, and versioned revisions. The migration engine uses `NullPool` and
the same validated settings boundary. Production migrations are manual through
the profiled one-shot `migrate` service; application startup does not run
migrations or create tables.

The production `postgres_data` named volume provides persistent storage across
container recreation. It is not a backup. Automated backup, representative
restore testing, and disaster recovery are not implemented. `docker compose
down -v` deletes the persistent PostgreSQL volume and is a destructive operation,
not routine cleanup; it requires explicit authorization and verified recovery
evidence.

## Backend API architecture

FastAPI registers these implemented read-only routes:

| Route | Responsibility |
| --- | --- |
| `GET /` | Safe service/root metadata |
| `GET /api/health` | Availability and environment metadata without database access |
| `GET /api/version` | Safe application name/version metadata |
| `GET /api/v1/dashboard/summary` | Database-backed KPI summary with bounded `window_days` |
| `GET /api/v1/articles` | Active article list with search, category, source/tag, date, geography/UAE, limit, and offset filters |
| `GET /api/v1/articles/{public_id}` | One active article by canonical public UUID |
| `GET /api/v1/intelligence/items` | Intelligence/vulnerability list with item type, CVE, severity, source, geography/UAE, search, limit, and offset filters |
| `GET /api/v1/intelligence/items/{item_public_id}` | One intelligence item by canonical public UUID |

Unknown or repeated query parameters are rejected. Search text, enums, source
slugs, CVE identifiers, UUIDs, pagination, article date ranges, and incompatible
filter combinations have explicit bounds. Query services use SQLAlchemy
expressions and serialize only Pydantic response fields; ORM source payloads,
database errors, internal exceptions, and configuration are excluded.

The application has no write, ingestion, administration, login, authentication,
or authorization endpoint. Interactive OpenAPI documentation remains enabled,
but it does not add privileged operations. Until an independently reviewed
identity/access layer exists, this API must be treated as an unauthenticated
read-only interface and protected by deployment network controls.

## Frontend architecture

The frontend uses the Next.js App Router and React client components. Implemented
routes are the dashboard `/`, article details `/articles/[publicId]`, and
vulnerability details `/vulnerabilities/[publicId]`. Dashboard components load
backend KPI summaries, bounded trend samples, paginated/filterable
vulnerabilities, paginated/filterable articles, and backend health. Detail pages
provide loading, success, not-found, and sanitized error states.

Browser API clients read `NEXT_PUBLIC_API_BASE_URL` (falling back to
`http://localhost:8000` for local development), send read-only GET requests with
`cache: no-store`, and validate every JSON response shape before use. In the
production frontend image, this public URL is a build argument embedded in
browser assets; changing it requires rebuilding the image. It must never contain
a secret. These client-side requests originate in the browser and go directly
to that browser-resolvable backend URL; the Next.js frontend container does not
proxy them.

Search, severity, geographic-scope, UAE-relevance, and pagination controls call
the implemented query APIs and reset offsets when filters change. Trend charts
derive a bounded view from recent API records; they are not a complete
historical analytics engine. The operational/source-overview preview panels
remain explicitly labeled synthetic presentation data and do not query the
database.

React renders source content as text; `dangerouslySetInnerHTML` is not used.
`SafeExternalLink` accepts only well-formed HTTP/HTTPS URLs without credentials
or unsafe characters and applies `target="_blank"` with
`rel="noopener noreferrer"`; invalid links become disabled text. API failures
produce controlled user messages rather than backend exception details.
No authentication session or login state exists in the frontend.

## Development runtime architecture

`run.cmd` delegates to `run.ps1` and supports these repository-root commands:

| Command | Implemented behavior |
| --- | --- |
| `.\run.cmd setup` | Check prerequisites and create missing local environment files without overwriting existing files |
| `.\run.cmd install` | Run setup and install missing backend/frontend dependencies |
| `.\run.cmd test` | Run full backend pytest, frontend Vitest, TypeScript type-check, and production build |
| `.\run.cmd docker` | Validate, build, start, and smoke-check the full development Compose stack |
| `.\run.cmd dev` | Run PostgreSQL in Docker while backend and frontend development servers run on the Windows host |
| `.\run.cmd full` | Setup, install if needed, test/build, then run the Docker workflow |
| `.\run.cmd help` | Print runner usage |

In `dev` mode, `docker compose up -d db` starts PostgreSQL. The runner waits for
database health, then starts reload-enabled Uvicorn at `127.0.0.1:8000` and the
Next.js development server at port `3000` on the host. It reads an existing
`DATABASE_URL` or `backend/.env` value and structurally rewrites only an exact,
case-insensitive hostname `db` to `localhost` for the backend child process.
Local, remote, and IPv6 hosts and all other URL components remain unchanged.
The parent environment is restored in `finally`, and the credential-bearing URL
must not be printed or passed on the process command line. Stopping `dev` ends
only the host process trees; the database container remains running.

The development Compose stack runs `db`, `backend`, and `frontend` containers on
a shared bridge network and publishes PostgreSQL, backend, and frontend ports to
the host. Its local defaults, development environment, fixed container names,
and placeholder credentials are not production controls. Although the
development Compose environment contains legacy interval/admin feature flags,
the current application has no scheduler, startup ingestion, or admin ingestion
route.

## Production Docker architecture

`compose.prod.yml` is a standalone production-oriented baseline, separate from
development Compose. Normal:

```powershell
docker compose -f compose.prod.yml config --services
```

lists `db`, `backend`, and `frontend`. The `migrate` service appears only when
the `migration` profile is enabled or that service is explicitly targeted; it
runs `alembic upgrade head` as a manual one-shot operation and is not normal
startup.

```text
approved operator/browser
        |
        +--> frontend published port or external frontend route
        |
        +--> backend URL configured in NEXT_PUBLIC_API_BASE_URL
                    |
                    +--> internal database network --> PostgreSQL

manual migrate service -------------------------------> PostgreSQL
```

The database has no production host port by default. Frontend joins only the
application network; backend joins application and the internal database
network; PostgreSQL and `migrate` join only the database network. Backend and
frontend default host bindings are loopback-only. No application source,
environment file, or Docker socket is mounted into application containers.

Compose attaches frontend and backend to the `application` network, but that is
a container-topology property, not the current client-side API request path.
Browser clients use the browser-resolvable backend URL embedded at frontend
build time in `NEXT_PUBLIC_API_BASE_URL`; an external browser cannot
automatically resolve the Docker service hostname `backend`. No included
reverse proxy combines frontend and backend under one public origin, so
production CORS must allow the actual browser frontend origin. A separately
approved TLS/reverse-proxy boundary may provide external routing, but this
repository does not implement it.

Backend and frontend images run as dedicated non-root users (`appuser` and
`nextjs`). Application services and `migrate` enable an init process,
`no-new-privileges`, and drop all Linux capabilities; all services are
non-privileged. Runtime services use `restart: unless-stopped`, health checks,
and the bounded local log driver with three 10 MiB files. PostgreSQL uses the
official image’s `postgres` operating-system user. No development reload server,
Next.js development server, startup migration, or automatic ingestion command is
present.

Production requires explicit environment values. `APP_ENV=production`,
`DEBUG=false`, and `ENABLE_ADMIN_INGESTION=false` are fixed. CORS requires
explicit non-loopback HTTPS origins. `NEXT_PUBLIC_API_BASE_URL` is public
build-time configuration. The production Compose file does not provide TLS
termination, a reverse proxy/load balancer, monitoring, backups, or secret
management; deployment infrastructure must supply those separately.

### Database-role limitation

`POSTGRES_USER` initializes PostgreSQL through the official image behavior,
which creates a privileged PostgreSQL role. The current backend and manual
migration service reuse that privileged role. No separate restricted
application database role is provisioned, and the current role must not be
described as least privilege. Introducing a non-superuser application role and
separate migration ownership is future reviewed database/deployment work.

## Trust boundaries and security controls

1. **External source boundary:** public intelligence locations are outside the
   application trust domain. Fixed collectors and reviewed-file validators
   constrain what can enter normalization.
2. **Normalization boundary:** source-specific code converts untrusted data into
   bounded internal values; only validated records cross into persistence.
3. **Database boundary:** backend ingestion/query and migration workflows reach
   PostgreSQL. Frontend and external sources do not connect to it.
4. **API boundary:** Pydantic schemas expose allow-listed normalized fields and
   stable errors. Raw source payloads and internal exception details are not
   public response fields.
5. **Browser boundary:** frontend clients validate response shapes, React
   escapes text, and external links pass scheme/credential/character checks.

Backend settings use environment variables and `SecretStr` for sensitive
values. Production rejects debug mode and non-HTTPS/loopback CORS origins. CORS
uses an exact environment-driven allow-list, grants GET only, disables browser
credentials, and never uses a wildcard.

Security middleware applies `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive
`Permissions-Policy`, and an API Content Security Policy. A server-generated
`X-Request-ID` correlates responses and safe completion logs. HSTS is not added
because TLS termination is not implemented by the application stack; an
approved external TLS boundary must own transport security.

No user authentication, authorization, role-based access control, or audit of
human API access is implemented. The public read-only API must not be treated as
an authenticated analyst portal.

## Logging, errors, and auditability

Application logging uses UTC key-value records and an allow-listed log level.
Uvicorn access logging is disabled because request targets can contain query
values. Request middleware logs a generated request ID, allow-listed method,
route template, status, duration, and safe error category—never the raw path
identifier, query string, body, authorization header, cookie, database URL, or
exception text.

Unknown exceptions become a stable 500 response; request validation, not-found,
date-range, and database-query failures have bounded public messages. Security,
CORS, and request-ID middleware cover successful and handled error responses.
Ingestion uses separate safe run/record/error evidence as described above.
Production container logs are size/rotation bounded, but centralized log
aggregation, monitoring, alerting, and retention governance are not implemented.

## Testing and validation architecture

- Backend pytest covers settings, database sessions, ORM/migrations, API routes,
  query validation, security middleware, logging/error sanitization, source
  registry, collectors, adapters, services, CLIs, publication identity, runner,
  Dockerfiles/Compose, and documentation contracts.
- Frontend Vitest and Testing Library cover API response validation, loading,
  empty/error/success states, filters/navigation, detail pages, safe external
  links, and plain-text rendering.
- TypeScript validation uses `next typegen` and `tsc --noEmit`.
- The production build verifies the standalone Next.js output.
- Compose tests parse the development and production YAML to assert networking,
  profiles, health, persistence, hardening, and required environment behavior.
- `git diff --check` protects whitespace integrity. `.\run.cmd test` runs the
  complete backend/frontend/type-check/build regression.

Automated tests are evidence for code contracts, not proof of production load,
public-internet safety, live-source availability, backup recovery, or manual QA.
Manual cases remain `Not Run` until separately executed and recorded.

## Operational workflows

- Source collection/enrichment is invoked through reviewed backend CLIs only;
  operators choose timing and bounds. No standard refresh interval exists.
- Development seed data is a separate explicit development-only CLI and is not
  production ingestion or an API fallback.
- Development startup uses the Windows runner and local Compose boundaries above.
- Production migrations use the manual `migrate` profile before normal runtime
  services are started or updated.
- Deployment, CORS, smoke, restart, rollback, secret rotation, and destructive
  actions follow the linked operations guides and require review/authorization.

## Known limitations and absent capabilities

The current repository does not implement:

- user authentication, authorization, roles, or protected analyst sessions;
- TLS termination, reverse proxy, or load balancer;
- automated PostgreSQL backups, representative restore tests, or validated
  disaster recovery;
- centralized logging, production monitoring, or alerting;
- CI/CD deployment, Kubernetes, or another orchestration platform;
- automated secret rotation, a restricted application database role, or
  zero-downtime deployment;
- production load testing or validated public-internet deployment;
- startup ingestion, scheduled/background ingestion, or recurring refresh;
- a public ingestion API, frontend ingestion trigger, or arbitrary URL ingestion;
- active scanning/probing, active IOC validation, malware retrieval, file
  submission, or exploit execution;
- complete historical analytics, relationship graphs, generic STIX/TAXII, or
  the broader commercial/platform source capabilities excluded above.

Persistent database storage is not backup. `docker compose down -v` destroys
the named PostgreSQL volume and is not routine cleanup. Manual approval remains
required for source collection, migration, rollback, volume deletion, and other
destructive deployment commands.

## Canonical references

- [Project handover and runner commands](../README.md)
- [Implemented data sources](data-sources.md)
- [Source assessment matrix](source-assessment-matrix.md)
- [Source integration policy](source-integration-policy.md)
- [Security notes](security-notes.md)
- [Testing plan](testing-plan.md)
- [Manual test cases](manual-test-cases.md)
- [Environment and secrets](environment-and-secrets.md)
- [Production Docker deployment](production-docker-deployment.md)
- [Deployment build validation](deployment-build-validation.md)
