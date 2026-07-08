# FIRST EPSS Enrichment

## Purpose

P2-03 adds a manual-only enrichment workflow for existing CVE vulnerability
items using the public FIRST Exploit Prediction Scoring System API. EPSS is used
defensively to help prioritize vulnerability review. It does not execute
exploits, scan targets, download malware, or create new CVE records.

## Source

Approved source registry values:

| Field | Value |
|---|---|
| slug | `first-epss` |
| name | `FIRST EPSS` |
| source_type | `api` |
| base_url | `https://api.first.org/data/v1/epss` |

No API key or secret setting is required.

## Storage Model

The MVP stores latest EPSS values only:

- `vulnerabilities.epss_score` stores the latest EPSS probability.
- `vulnerabilities.epss_percentile` stores the latest EPSS percentile.
- EPSS probability and percentile values are normalized to six fractional
  decimal places because the existing MVP columns use `Numeric(7,6)`.
- Normalization, the allow-listed source payload, hashing, ORM assignment, and
  later unchanged comparisons all use this same canonical persisted precision.
- `source_records.source_modified_at` on the `first-epss` source record stores
  the upstream EPSS score date at UTC midnight.
- `source_records.raw_payload` stores only a bounded allow-listed score payload:
  CVE ID, EPSS score, percentile, and date.
- One non-primary EPSS source record is stored per CVE using
  `source_external_id=<CVE ID>`.

The original NVD source record remains the primary reference for the CVE.

No Alembic migration is required because the vulnerability table already has
EPSS score and percentile columns, and the existing source-record provenance
fields are sufficient for score-date metadata.

## Manual CLI

Run from the `backend` directory:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.epss_cli `
    --max-cves 25 `
    --batch-size 25
```

Bounds:

- `--max-cves`: 1 to 500
- `--batch-size`: 1 to 100

The CLI loads a deterministic bounded set of existing global CVE identifiers,
batches requests so the FIRST `cve` query remains within the 2,000-character
limit, and creates one manual `IngestionRun`.

Upstream score dates must use the exact `YYYY-MM-DD` format. Other date forms
are rejected during normalization and are recorded through sanitized audit
outcomes.

## Matching Rules

EPSS records are matched only to existing global CVE identifiers where:

- `source_id IS NULL`
- `namespace == "cve"`
- `normalized_value == <CVE ID>`

The workflow never creates new `IntelligenceItem` rows, never creates global CVE
identifiers, and skips EPSS records whose CVE is not already stored locally.
If a matching item is not a vulnerability or has no vulnerability extension, the
record is skipped safely.

## Duplicate and Conflict Behavior

- Duplicate requested CVE IDs are normalized and deduplicated before fetching.
- Exact duplicate API records for the same CVE are processed once.
- Conflicting duplicate API records for the same CVE are recorded as failed.
- Requested CVEs omitted from the API response are recorded as skipped.
- API records for unrequested CVEs are recorded as failed and do not enrich any
  unrelated local item.
- Existing EPSS source records linked to a different item are recorded as failed.
- Older EPSS score dates do not overwrite newer stored EPSS values.
- Each requested CVE receives at most one terminal per-run audit outcome:
  `created`, `updated`, `unchanged`, `skipped`, or `failed`.

## Audit and Failure Policy

The CLI records:

- run-level status and counters
- per-record `created`, `updated`, `unchanged`, `skipped`, or `failed` outcomes
- sanitized `IngestionError` rows for controlled failures
- retryable markers for upstream network, temporary HTTP, or rate-limit failures

Console output is limited to safe summary counters. It does not print raw EPSS
payloads, headers, SQL, database URLs, environment values, stack traces, or
secrets.

## API Fields

Read-only intelligence item responses include:

- `epss_score`
- `epss_percentile`
- `epss_score_date`

The score and percentile come from the vulnerability extension. The score date
comes from the associated `first-epss` source record. Existing `source_slug`,
`source_name`, and `source_url` fields continue to use the primary NVD source
record.

## Out of Scope

P2-03 does not add scheduling, startup ingestion, API-triggered ingestion,
frontend changes, CISA KEV integration, EPSS historical time-series storage, new
authentication, or new public filters.

## Known Limitation

EPSS is an external public source whose values change over time. This MVP stores
only the latest value and date observed by the manual enrichment workflow; it is
not a historical scoring archive.
