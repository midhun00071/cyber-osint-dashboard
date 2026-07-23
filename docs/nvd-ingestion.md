# NVD Ingestion Design

## P2-01 scope

P2-01 adds a defensive ingestion path for public CVE records from the official
National Vulnerability Database API. The HTTP client and manual live smoke test
are already separate from normalization. Pass 1 adds only a pure normalization
contract and offline tests; it does not write to the database.

## NVD source mapping

One NVD vulnerability wrapper maps to a normalized vulnerability intelligence
item. The CVE ID is the global primary identifier and the NVD detail page is the
canonical source URL. Published and modified timestamps remain timezone-aware
UTC values. Rejected CVEs map to an archived lifecycle status; other records map
to active status.

The preferred CVSS order is 4.0, 3.1, 3.0, then 2.0. EPSS and CISA KEV fields are
not populated from NVD. CWE values are not converted into globally unique item
identifiers because many CVEs can share the same weakness.

## Normalizer responsibilities

The normalizer accepts exactly one vulnerability wrapper, validates and
normalizes its CVE ID, chooses the first English description, parses source
timestamps, selects the preferred supported CVSS metric, and extracts a bounded
allow-list of affected CPE fields. Only CPE matches where `vulnerable` is exactly
`true` are retained. Titles are limited to 500 characters and summaries to
10,000 characters. At most 100 affected product entries are kept.

The normalizer is pure: it imports no HTTP client, settings, SQLAlchemy model, or
database session and does not mutate its input.

## Raw payload and error policy

The complete public wrapper is deterministically serialized with sorted JSON
keys. The UTF-8 representation must not exceed 512 KiB. The same canonical bytes
produce a SHA-256 content hash for later update detection. Accepted payloads are
returned as a deep JSON copy suitable for later bounded JSONB persistence.

All upstream content is untrusted. Normalization errors use controlled messages
and never include raw payload fragments, headers, credentials, environment
values, stack traces, or database configuration.

## Persistence service boundary

Pass 2 keeps persistence outside the HTTP client and normalizer. The service uses
the existing intelligence source, item, vulnerability, source record, and
identifier models. Repeated CVEs are matched by their global CVE identifier and
NVD source external ID, while the content hash distinguishes unchanged
observations from updates. A disagreement between those keys is a controlled
conflict and is never auto-merged.

The service may flush pending ORM state but never commits or rolls back. The
manual command planned for Pass 3 owns the transaction and ingestion-run audit
records. Updates replace only NVD-owned normalized fields and preserve analyst
review, UAE relevance, tags, EPSS, KEV, `collected_at`, and `first_seen_at`.
If an existing vulnerability item is missing its one-to-one vulnerability
extension, an updated NVD record repairs it with normalized NVD values and empty
EPSS/KEV enrichment fields. This repair also occurs when the source content hash
is unchanged, and the local outcome is reported as updated.

## Safety boundary

NVD ingestion remains manual-only. Nothing in this design runs during FastAPI
startup or through a scheduler. There is no frontend or dashboard integration,
and no live network request is made by the normalizer or its tests.

## Manual ingestion command

Run the network- and database-active ingestion command explicitly from the
`backend` directory:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.nvd_cli `
    --window-minutes 60 `
    --results-per-page 25 `
    --max-records 25
```

`--window-minutes` is limited to 1-1440. Both `--results-per-page` and
`--max-records` are limited to 1-100. The command respects conservative NVD
pacing, performs no automatic retries, and never marks absent records missing.

The CLI owns one outer transaction and uses nested transactions for individual
records when supported. Controlled partial runs commit successful CVEs and safe
audit records; whole-run database failures roll back. A run succeeds only when
the complete requested window is processed without record failures or a record
cap. Capped or mixed-result runs are partial, and a first-page fetch failure is
failed. Source checkpoints advance only after complete success.

Console and audit output contain bounded counters and sanitized error categories
only. Raw payloads, descriptions, references, headers, keys, environment values,
stack traces, SQL errors, and database URLs are never printed. The command is not
connected to FastAPI startup, a scheduler, an API route, or the dashboard.

## Curated multi-year representative dataset

`app.ingestion.nvd_curated_cli` is a separate manual workflow. It does not
replace or change the incremental last-modified-window command. It builds a
bounded representative dataset, not the complete NVD, and defaults to UTC
publication years 2020 through the current UTC year.

The default quota for each year is:

| Normalized severity | Target | Default maximum retained per year |
|---|---:|---:|
| Critical | 10 | 10 |
| High | 5 | 5 |
| Medium | 3 | 3 |
| Low | 2 | 2 |
| **Total** | **20** | **20** |

Only non-rejected candidates with a valid uppercase CVE identity and usable
preferred CVSS v3 or v4 score/severity can fill a slot. The existing normalizer
selects CVSS 4.0 before 3.1 and 3.0, so the stored score, version, vector, and
severity use the same persistence contract as incremental NVD ingestion.

Within a severity, selection is deterministic:

1. NVD candidates carrying CISA KEV metadata first.
2. Preferred CVSS base score descending.
3. NVD last-modified timestamp descending.
4. Normalized CVE ID ascending.

Duplicate results across CVSS versions, pages, or date chunks collapse by
uppercase CVE ID before selection. Missing quota capacity is reported exactly;
the command does not invent or relabel severity.

### Planning and execution

Preview the default plan from `backend` without loading runtime settings,
contacting NVD, or opening a database session:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.nvd_curated_cli --plan
```

An explicit example for the current 2026 UTC year is:

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

Supported bounds and defaults:

- start year: 2020 by default and never earlier than 2020;
- end year: current UTC year by default and never in the future;
- date chunks: 90 days by default, 1–120 days;
- candidate page size: 50 by default, 1–200;
- candidate pages per query: 2 by default, 1–10;
- total NVD requests: 400 by default, 1–1,000;
- retention multiplier: 1 by default, 1–5; it multiplies each severity quota
  to calculate the maximum retained full candidates per severity and year;
- automatic retries: 0.

Chunks use millisecond UTC boundaries with no gaps or overlaps. A completed past
year ends at `23:59:59.999Z` on 31 December; the current year ends at the
captured current UTC time. Each chunk requests a bounded KEV-only candidate page
set plus CVSS v4 and v3 candidate pages for Critical, High, Medium, and Low.
Only typed allow-listed parameters are available; callers cannot provide an
arbitrary URL, host, or query dictionary.

The shared client applies bounded timeouts and a true streaming response-body
limit. It validates HTTP status before parsing, rejects a valid oversized
`Content-Length` before consuming the body, and otherwise reads decoded bytes
incrementally. Reading stops immediately when the cumulative body would exceed
20 MiB; partial oversized content is discarded and JSON parsing occurs only
after a bounded read completes. Each accepted normalized CVE payload remains
capped at 512 KiB.

Candidate memory is separately bounded. The default multiplier retains only the
best 10 Critical, 5 High, 3 Medium, and 2 Low full normalized candidates per
year. A candidate outside a full top-ranked severity pool is discarded
promptly; a better candidate evicts the current worst retained candidate.
Duplicate replacement remains deterministic. Any eviction or valid candidate
discarded by this ceiling adds `maximum retained candidate limit reached` to
the affected year, so the result is partial/incomplete rather than a claim of
exhaustive consideration. Planning and execution summaries display the
configured retained limits.

Candidate page and total-request ceilings are hard limits. If unseen upstream
pages remain, a request fails, or a quota cannot be filled, the affected year is
reported as capped or incomplete and the command returns a controlled
non-success result. Successfully selected records may still be committed with
sanitized audit evidence. The summary reports requested years, yearly quotas,
candidates inspected, selections and shortfalls by year/severity, KEV-prioritized
count, persistence outcomes, request count, and incomplete years.

The CLI owns the outer transaction and retains per-record savepoints. It sends
selected records through `NvdIngestionService`, so existing CVEs follow the
normal update/unchanged path, no duplicate CVE rows are created, EPSS/KEV and
analyst-owned fields are preserved, and unselected existing CVEs are not
deleted. It deliberately does not advance the incremental NVD source
checkpoint.

Run counters reconcile every inspected observation:

```text
records_fetched =
  records_created + records_updated + records_unchanged
  + records_skipped + records_failed
```

`records_skipped` includes malformed or rejected observations, duplicate
observations, candidates discarded or evicted by retention limits, and valid
retained candidates outside the final quotas. `started_at` is captured once
before collection and `completed_at` is captured from a fresh timezone-aware
UTC clock after processing; a backward or invalid completion time fails safely
without persisting raw error details.

FIRST EPSS and CISA KEV enrichment remain separate later operator steps:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.epss_cli `
    --max-cves 25 `
    --batch-size 25

.\.venv\Scripts\python.exe -m app.ingestion.cisa_kev_cli --max-records 25
```

The current CISA command processes a bounded catalogue subset and marks listed
matches. It does not establish `not_listed` for every local CVE, so the absence
of KEV enrichment must not be interpreted as a completed negative check.

> This product uses data from the NVD API but is not endorsed or certified by the NVD.

Known limitations: the bounded candidate pool is not exhaustive, NVD page
ordering and upstream data availability constrain representativeness, quota
shortfalls are possible, and live execution duration reflects official pacing.
Planning and automated tests are offline; neither performs live NVD, FIRST EPSS,
or CISA requests.

## Out of scope

- Migrations and schema changes.
- PostgreSQL integration testing for the manual ingestion CLI beyond the
  existing offline automated test suite.
- Scheduled or startup ingestion.
- FastAPI ingestion routes.
- Dashboard and frontend changes.
- Automatic retries or historical backfills.
- Redesign of CISA KEV, EPSS, RSS, or vendor advisory ingestion.
- Automatic vendor, product, CWE, or CPE tag creation.
