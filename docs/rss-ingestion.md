# CERT-EU RSS Ingestion

## Purpose

P2-04 adds a manual-only ingestion workflow for the approved CERT-EU Security
Advisories RSS feed. The workflow stores defensive public advisory metadata as
`security_advisory` intelligence items. It does not execute exploits, scan
targets, download malware, parse arbitrary websites, or trigger ingestion from
FastAPI startup, API routes, a scheduler, or the frontend.

## Source

Approved source registry values:

| Field | Value |
|---|---|
| slug | `cert-eu-security-advisories` |
| name | `CERT-EU Security Advisories` |
| source_type | `rss` |
| base_url | `https://cert.europa.eu/publications/security-advisories-rss` |

No API key or secret setting is required.

## Collector Controls

The RSS collector is locked to the approved HTTPS host and feed URL. It uses a
static defensive user agent, bounded timeouts, manual redirect handling, and a
1 MiB response limit. Redirects are accepted only when they remain on
`https://cert.europa.eu` without credentials, fragments, non-standard ports, or
unapproved hosts. HTTP 429, network failures, unsafe redirects, oversized
responses, and unsupported content types are surfaced through sanitized
exceptions. Malformed redirect destinations, including invalid or out-of-range
ports, are rejected as non-retryable safety failures without printing the raw
`Location` value.

## Normalization

The normalizer accepts RSS or Atom feed bytes and performs no network or
database access. Each entry is converted to:

- a bounded plain-text title
- a bounded plain-text summary when available
- a canonical CERT-EU advisory URL
- a stable source external ID from feed ID/GUID or a URL hash fallback
- optional published and modified UTC timestamps
- deterministic canonical URL and content hashes
- an allow-listed raw payload containing only safe source metadata

HTML in titles and summaries is treated as untrusted text. Script, style,
iframe, object, and embed content is ignored. Tracking query parameters such as
`utm_*`, `gclid`, and common ad campaign identifiers are stripped from canonical
URLs. Exact duplicate feed entries are processed once; conflicting duplicates
receive a sanitized failed audit outcome and do not create duplicate
intelligence items. Entry-level normalization failures are isolated: a malformed
selected entry is recorded as failed, while other valid selected entries may
still be persisted in the same partial run. Malformed advisory URLs are rejected
through sanitized normalization errors without printing the raw URL.

## Storage Model

Each new advisory creates one `IntelligenceItem` with `item_type` set to
`security_advisory` and one primary `SourceRecord` for the CERT-EU source.
The workflow uses the existing intelligence item, source, source-record,
ingestion-run, ingestion-record, and ingestion-error tables. No Alembic
migration is required.

Updates replace only source-owned normalized fields such as title, summary,
canonical URL, upstream dates, content hash, and allow-listed raw payload.
Analyst review, UAE relevance, lifecycle, collected-at, and first-seen fields
are preserved.

## Manual CLI

Run from the `backend` directory:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.rss_cli `
    --max-records 25
```

Bounds:

- `--max-records`: 1 to 100

The CLI owns one outer transaction and creates one manual `IngestionRun`.
Per-record work uses nested transactions when supported. Controlled partial
runs commit safe audit records; whole-run database failures roll back. Source
checkpoints advance only after a successful run. `records_fetched` counts parsed
feed entries before the `--max-records` processing cap. If the feed contains
more entries than `--max-records`, the run processes only the selected prefix,
is marked partial, commits the safe audit evidence, and does not advance the
checkpoint.

Console and audit output contain bounded counters and sanitized error
categories only. Raw feed bytes, article bodies, headers, stack traces, SQL
errors, database URLs, environment values, and secrets are not printed.

No live source test is performed by the automated P2-04 validation suite unless
separately approved.

## Out of Scope

P2-04 does not add frontend changes, public API contract changes, article-body
fetching, arbitrary RSS ingestion, scheduling, startup ingestion, API-triggered
ingestion, migrations, authentication changes, or report generation.
