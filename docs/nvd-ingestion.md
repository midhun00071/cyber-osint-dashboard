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

## Out of scope

- Migrations and schema changes.
- PostgreSQL integration testing for the manual ingestion CLI beyond the
  existing offline automated test suite.
- Scheduled or startup ingestion.
- FastAPI ingestion routes.
- Dashboard and frontend changes.
- Automatic retries or historical backfills.
- CISA KEV, EPSS, RSS, and vendor advisory ingestion.
- Automatic vendor, product, CWE, or CPE tag creation.
