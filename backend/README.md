# Backend - Cyber OSINT Dashboard

## Purpose

The backend provides the API, database access, ingestion services, processing logic, and scheduled data-fetching foundation for the Cyber OSINT Dashboard.

## Planned Responsibilities

- Run the FastAPI backend server.
- Connect securely to PostgreSQL.
- Expose dashboard and threat intelligence API endpoints.
- Store normalized threat and vulnerability records.
- Fetch approved open-source cybersecurity data.
- Process, normalize, deduplicate, and classify records.
- Provide safe logging and error handling.
- Support backend tests.

## Planned Backend Structure

- app/main.py - FastAPI application entry point
- app/api/ - API route definitions
- app/core/ - configuration and logging
- app/db/ - database session and base setup
- app/models/ - SQLAlchemy database models
- app/schemas/ - Pydantic request/response schemas
- app/services/ - business logic services
- app/ingestion/ - external source collectors and jobs
- app/processing/ - normalization, severity mapping, tagging, and deduplication
- tests/ - backend automated tests
- alembic/ - database migration files

## Environment Variables

Use backend/.env.example as the template.

Never commit real backend/.env files.

## Dependencies

Initial dependencies are listed in requirements.txt.

## Current Status

Phase 1 setup only. Application logic will be added in a later phase.

## Utility API Endpoints

- `GET /api/health` returns safe service health metadata for deployment and
  monitoring checks.
- `GET /api/version` returns safe public application metadata:
  `{"service":"Cyber OSINT Dashboard","version":"0.1.0"}`. The version comes
  from `APP_VERSION` and defaults to `0.1.0`.

## Synthetic Development Seed Data

P1-12 adds an explicitly invoked synthetic dataset for local development and
frontend testing. It inserts fictional sources, tags, intelligence items,
identifiers, source records, and vulnerability extension rows into the existing
schema. The data is not real threat intelligence and must not be used for
security decisions.

Safety boundaries:

- Runs only when `APP_ENV` is `development` or `test`.
- Performs no network requests.
- Does not reset, truncate, or delete database data.
- Does not run automatically during application startup.
- Uses only `example.com`, `example.org`, and `example.net` URLs.

Prerequisites:

1. Configure a local or disposable PostgreSQL database through the existing
   environment variables in `backend/.env.example`.
2. Apply the existing Alembic migration.
3. Run the seed command from the `backend` directory.

The database host must be reachable from where the command runs. The hostname
`db` is intended for commands running inside the Docker Compose network. Commands
run directly from Windows PowerShell normally need the host-mapped PostgreSQL
address, such as `localhost` with the configured PostgreSQL port.

Commands:

```powershell
python -m alembic -c alembic.ini upgrade head
$env:APP_ENV = "development"
python -m app.dev_data.cli
python -m app.dev_data.cli
```

Expected first run: creates the synthetic dataset and prints created counts.
Expected second run: creates no duplicate logical records and prints existing
counts. If an existing seed-keyed record conflicts with the expected synthetic
data, the command stops with a safe conflict message.

Example verification queries:

```sql
select count(*) from intelligence_sources where slug like 'alpha-synthetic-%';
select count(*) from intelligence_item_identifiers where namespace = 'alpha-seed';
select count(*) from vulnerabilities;
select count(*) from source_records where source_external_id like 'ALPHA-SEED-%';
```

If the command fails, verify that `APP_ENV` is `development` or `test`, the
database settings are present for the current execution environment, and the
migration has been applied. Do not paste real database URLs, passwords, tokens,
or stack traces into issues or reports.

## Manual Google TI and Mandiant Publication Ingestion

P9-05 adds an explicitly invoked metadata-only RSS command:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.google_threat_publications_cli `
    --max-records 25
```

It uses the fixed official Google Cloud Threat Intelligence RSS feed and has no
arbitrary URL or credential option. The collection host is
`feeds.feedburner.com`; stored publication URLs must be exact
`cloud.google.com/blog/topics/threat-intelligence/` article URLs. Feed entries
are routed only by exact authoritative author: `Google Threat Intelligence
Group` or `Mandiant`. The command does not fetch article bodies, scrape pages,
ingest developer documentation, call GTI/VirusTotal APIs, submit or retrieve
files or malware samples, extract IOCs, schedule work, run at startup, or expose
public ingestion endpoints.
Stored summaries come only from feed `summary` or `description` values. Feed
`content`, article bodies, attachments, media links, downloadable reports, and
PDFs are ignored. Known-owner validation failures are audited only on that
source run; entries without an approved authoritative owner produce sanitized
shared-feed error evidence on both logical runs without counting as source-owned
fetched or failed records.

## Manual Anomali Cyber Watch Publication Ingestion

Run the live collector from the `backend` directory:

```powershell
.\.venv\Scripts\python.exe `
    -m app.ingestion.anomali_publications_live_cli `
    --max-records 5
```

The live command is manually triggered only. The supported `--max-records`
range is 1 through 20. The collector requests one fixed discovery URL,
`https://www.anomali.com/blog`, and accepts no arbitrary URL. It requires HTTPS
and exact host `www.anomali.com`; article requests must also use the literal
`/blog/anomali-cyber-watch-...` path family. Redirects are explicitly validated.
There are no automatic retries, request starts are paced at least ten seconds
apart, and timeouts and response sizes are bounded.

The live collector does not parse article-body prose. It extracts bounded
publication metadata only and screens selected title, summary, author, and
category metadata for IOC-like URLs, IP addresses, domains, hashes,
internationalized domains, and common defanged forms. Unsafe metadata is
rejected before adapter invocation. Live collection does not persist raw HTML,
HTTP headers, cookies, attachments, media, PDFs, downloads, or malware samples.

Collection completes before a database session is opened. Successful
persistence is atomic and safely audited, while console messages do not expose
raw HTTP or database errors.

The reviewed local JSON fallback is the currently operational method:

```powershell
.\.venv\Scripts\python.exe `
    -m app.ingestion.anomali_publications_cli `
    --file C:\path\to\anomali-cyber-watch.json
```

The strict versioned local catalogue is limited to 1 MiB, 100 publications, and
the fixed `anomali-cyber-watch` source. URLs must use exact host
`www.anomali.com` and literal path prefix `/blog/anomali-cyber-watch-`; titles
must use exact prefix `Anomali Cyber Watch:`. The adapter also validates
timestamps, plain-text bounds, authors, and categories. The input must be
reviewed, operator-prepared publication metadata only. Operators and reviewers
must exclude article-body text; IOCs and observables; hashes, IP addresses, and
domains used as indicators; raw HTML; HTTP headers and cookies; and attachments,
media, PDFs, downloads, or malware samples. The local adapter is not a
comprehensive automatic IOC detector. The verified five-record catalogue was
reviewed and contained safe metadata.

Neither workflow implements ThreatStream, commercial feeds/APIs, STIX/TAXII, or
STAXX. There is no scheduler, startup ingestion, background ingestion, API
trigger, or frontend trigger.

Manual live collection is implemented and validated offline. During the
controlled smoke test on 19 July 2026, the fixed official discovery page
returned HTML with no deterministic main-content region and no approved Cyber
Watch article links. Discovery failed safely before an article request was
issued and before database-session creation; no ingestion run was created and no
live records were persisted. The request was not rejected with HTTP 403; the
observed response status was HTTP 200. The reviewed safe local JSON fallback
then imported 5 records for `anomali-cyber-watch`: 5 were created and linked, and
the run succeeded.

## Manual IBM X-Force Publication Ingestion

P9-07 adds one explicit command for two document-owned, strictly separate local
catalogue sources:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.ibm_x_force_publications_cli `
    --file C:\path\to\ibm-x-force-publications.json
```

Research metadata accepts only exact `www.ibm.com/think/x-force/<slug>` article
URLs. Public OSINT advisory metadata accepts only exact
`exchange.xforce.ibmcloud.com/osint/guid%3A<32-hex>` URLs. The JSON document,
not a CLI option, owns the fixed source slug. Both catalogues are metadata-only,
1 MiB/100-record bounded, and manually invoked. No IBM website or Exchange
request, scraper, guest browser, IBMid login, API credential, indicator or
reputation lookup, report/PDF download, STIX/TAXII import, scheduler, startup
hook, worker, or public upload route is added.
