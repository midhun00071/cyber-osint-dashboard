# CISA KEV Ingestion

## Purpose

P2-08 adds a manual-only enrichment workflow for existing CVE vulnerability
items using the public CISA Known Exploited Vulnerabilities catalog. KEV status
is used defensively to prioritize vulnerability review. The workflow does not
execute exploits, scan targets, download malware, or trigger ingestion from
FastAPI startup, API routes, a scheduler, or the frontend.

## Source

Approved source registry values:

| Field | Value |
|---|---|
| slug | `cisa-kev` |
| name | `CISA Known Exploited Vulnerabilities Catalog` |
| source_type | `json` |
| base_url | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |

No API key or secret setting is required.

## Manual CLI

Run from the `backend` directory:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.cisa_kev_cli --max-records 25
```

Bounds:

- `--max-records`: 1 to 500

The command creates one manual `IngestionRun`, fetches the fixed approved HTTPS
JSON catalog, normalizes selected KEV entries, and records one per-entry audit
outcome for each selected entry that is processed or rejected.

## Matching Rules

KEV entries are matched only to existing global CVE identifiers where:

- `source_id IS NULL`
- `namespace == "cve"`
- `normalized_value == <CVE ID>`

The workflow never creates new `IntelligenceItem` rows, never creates global CVE
identifiers, and skips KEV entries whose CVE is not already stored locally. If a
matching item is not a vulnerability or has no vulnerability extension, the
entry is skipped safely.

## Storage Model

For matched vulnerabilities, the workflow updates only KEV-owned fields:

- `kev_status = "listed"`
- `kev_last_checked_at`
- `kev_date_added`
- `kev_due_date`
- `kev_required_action`
- `known_ransomware_campaign_use`

It creates or updates one non-primary CISA KEV `SourceRecord` per matched CVE
using `source_external_id=<CVE ID>`. The source record stores only an
allow-listed, bounded payload for the KEV entry and a deterministic content
hash. NVD-owned fields, EPSS fields, analyst fields, tags, UAE relevance,
`collected_at`, and `first_seen_at` are not overwritten.

`knownRansomwareCampaignUse` is normalized as:

- `Known` -> `True`
- `Unknown` -> `False`

Malformed or unrecognized values fail safe normalization.

## Audit and Status Rules

The CLI records:

- run-level status and counters
- per-record `created`, `updated`, `unchanged`, `skipped`, or `failed` outcomes
- sanitized `IngestionError` rows for fetch, normalization, and persistence
  failures
- retryable markers for upstream network, temporary HTTP, or rate-limit failures

Status behavior:

- `succeeded` only when fetch succeeds and all selected records process without
  failures, skips, or caps
- `partial` when capped, skipped, or some records fail
- `failed` when fetch fails before records are processed or a whole-run database
  failure occurs

Source checkpoints advance only after complete success.

Console and audit output contain bounded counters and controlled messages only.
They do not print raw catalog content, headers, SQL, database URLs, environment
values, stack traces, internal database IDs, or secrets.

## Out of Scope

- Migrations and schema changes.
- Scheduled or startup ingestion.
- FastAPI ingestion routes.
- Frontend changes.
- Creating local CVE records from KEV-only entries.
- Exploit execution, scanning, exploit reproduction, payload testing, or
  offensive functionality.
