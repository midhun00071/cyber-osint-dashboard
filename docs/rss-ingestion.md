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
The workflow uses the existing intelligence item, item identifier, source,
source-record, ingestion-run, ingestion-record, and ingestion-error tables. No
Alembic migration is required.

Duplicate prevention uses two identity layers:

- Source-scoped provenance identity still resolves the CERT-EU source record
  first by source external ID and then by the source-scoped canonical URL hash.
- Global article identity uses `intelligence_item_identifiers` rows with the
  non-source-scoped namespaces `canonical_url_sha256` and
  `normalized_title_sha256`.

The canonical URL fingerprint is the SHA-256 hash of the normalized advisory
URL after the existing URL safety checks and tracking-parameter stripping. The
title fingerprint is the SHA-256 hash of the title after Unicode NFKC
normalization, whitespace collapsing, trimming, and deterministic case folding.
It does not remove punctuation or words.

When a new CERT-EU source record has the same global canonical URL fingerprint
as an existing active `security_advisory`, the workflow reuses the existing
item and creates only the new source record. If that item already has a primary
source record, the additional source record is non-primary. The existing
canonical item fields are not overwritten merely because another source record
was attached.

When both URL and title fingerprints resolve to the same advisory item, that
item is reused. When only the title matches but the URL does not, ingestion
fails safely with a sanitized possible-duplicate message and creates no new
item or source record. Conflicting URL/title signals, non-advisory matches, or
source-scoped records that disagree with global identity also fail safely. The
workflow does not destructively merge, relink, or move records; title-only
matches require later analyst review or a future explicit merge workflow.

Updates replace only source-owned normalized fields such as title, summary,
canonical URL, upstream dates, content hash, and allow-listed raw payload.
Analyst review, UAE relevance, lifecycle, collected-at, and first-seen fields
are preserved. Proposed URL and title fingerprint changes are validated before
mutating stored fields, and existing fingerprint identifier rows for the same
item are updated rather than duplicated.

Existing CERT-EU source records from before global article fingerprints are
backfilled safely when they are reprocessed, including when the upstream content
hash is unchanged and the public result remains `unchanged`. Before any item,
source-record, timestamp, or identifier field is mutated, the service checks
that the linked item is an active advisory, that there is at most one global URL
identifier and one global title identifier for the item, and that the proposed
fingerprints are not owned by another item. Ambiguous identifier cardinality or
ownership fails with a sanitized result and leaves ORM fields unchanged.

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
