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

## Manual Catalog-Driven Enrichment

Run from the `backend` directory:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.cisa_kev_cli --max-records 25
```

Bounds:

- `--max-records`: 1 to 500

The command creates one manual `IngestionRun`, fetches the fixed approved HTTPS
JSON catalog, normalizes selected KEV entries, and records one per-entry audit
outcome for each selected entry that is processed or rejected.

This existing command is catalog-driven: `--max-records` limits catalog entries,
not local vulnerability rows. It can prove that a processed match is `listed`,
but its bounded entry slice cannot prove that an absent local CVE is
`not_listed`.

## Manual Local Reconciliation

The separate reconciliation command fetches and validates the complete catalog
before beginning database reconciliation, then compares bounded local
vulnerability rows with the complete normalized uppercase catalog CVE set.

Preview the fixed plan without network or database access:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.cisa_kev_reconcile_cli `
    --max-cves 500 `
    --batch-size 100 `
    --plan
```

After review, run the database-active command from the `backend` directory:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.cisa_kev_reconcile_cli `
    --max-cves 500 `
    --batch-size 100
```

Bounds:

- `--max-cves`: 1 to 500 local vulnerability rows; default 500
- `--batch-size`: 1 to 100 local rows per ORM batch; default 100

The local limit never caps catalog entries. Complete validation requires
positive catalog metadata, an aware release timestamp, exact declared-count
agreement, successful required-field normalization for every entry, and safe
duplicate handling. An empty, malformed, interrupted, oversized, or otherwise
incomplete catalog fails before local-row access. A sanitized failed
`IngestionRun` may still be committed for operator evidence, but no local
vulnerability status is read or changed.

Reconciliation status meanings:

- `listed`: the local CVE is present in the completely validated catalog.
- `not_listed`: the local CVE is absent from that complete catalog.
- `unknown`: no successful complete-catalog reconciliation has established
  either result for that local CVE.

Every selected unique vulnerability row produces exactly one reconciliation
outcome. Each bounded vulnerability batch uses one separate lookup for global
CVE identifiers restricted to `source_id IS NULL` and namespace `cve`. After
normalization and deduplication, exactly one usable CVE is required. Missing or
ambiguous global CVE identity is skipped without changing KEV status or checked
time, and ambiguous identity never selects a CVE based on identifier insertion
or query order. The safe audit reason never includes the raw identifier list.

Every successfully reconciled local CVE receives a refreshed
`kev_last_checked_at`. The first run updates differing states; later runs report
them as unchanged when the catalog membership and stored status agree, while
still refreshing the checked timestamp. The command creates no vulnerability
or identifier rows and does not store raw catalog entries in reconciliation
audit records.

The command reports `succeeded` and returns 0 only when failed, skipped, and
`unknown_remaining` are all zero. A skipped selected row or any selected row
that remains `unknown` is a controlled `partial` result: valid reconciliation
changes and safe audit records commit, the console clearly reports the partial
outcome, and the command returns 1. `unknown_remaining` counts selected rows
that are still in the `unknown` state; skipped rows already marked `listed` or
`not_listed` do not increase it. Invalid arguments return 2.

Formal `IngestionRun` counters refer only to selected local rows. Created stays
zero, fetched is the number inspected, and:

```text
fetched = created + updated + unchanged + skipped + failed
```

Catalog raw-record count and unique normalized catalog CVE count are separate
safe-summary, console, and checkpoint evidence; neither is mixed into the local
row counters. Catalog-fetch failure audit runs keep local fetched at zero.

Workflow times are separate timezone-aware UTC observations. `started_at` is
captured before catalog fetch, the checked time is captured after complete
catalog validation immediately before local reconciliation, and `completed_at`
is captured after local reconciliation and audit processing. Per-row
`kev_last_checked_at` and reconciliation audit `processed_at` use the checked
time; the run uses the completion time. A catalog failure receives a fresh
completion time after the failure is known.

The deterministic query always starts with the lowest local vulnerability IDs.
`--max-cves` counts those unique vulnerability rows rather than joined
identifier rows, and database work remains bounded by `--batch-size` while
later vulnerability IDs continue across batches. Consequently, the 500-row
command selects those same lowest IDs on each run; a database with more than
500 vulnerabilities requires a future cursor/resume enhancement before later
IDs can be reconciled.

The declared `catalogVersion` must be a non-empty token no longer than 100
characters. It is ASCII-only and permits only letters, digits, periods,
underscores, and hyphens. Whitespace, control or formatting characters, and
checkpoint delimiters such as semicolons and colons are rejected before local
reconciliation. Only this validated safe token may appear in the checkpoint,
safe summary, or console evidence.

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

The reconciliation command uses one caller-owned database transaction for its
selected local set. It creates the run and per-row safe audit records only after
complete catalog validation, commits once after every batch succeeds, and rolls
back status and audit changes together after an uncaught database failure.
`not_listed` is never assigned from a capped, partial, failed, or malformed
catalog. Its summary includes separate catalog raw-record and unique-CVE counts,
local rows inspected, listed, not-listed, updated, unchanged, skipped, failed,
unknown remaining, and the complete-validation result.

Console and audit output contain bounded counters and controlled messages only.
They do not print raw catalog content, headers, SQL, database URLs, environment
values, stack traces, internal database IDs, or secrets.

## Out of Scope

- Migrations and schema changes.
- Scheduled or startup ingestion.
- FastAPI ingestion routes.
- Frontend changes.
- Creating local CVE records from KEV-only entries.
- Updating detailed KEV source evidence through the reconciliation command; use
  the existing catalog-driven enrichment command for that purpose.
- Exploit execution, scanning, exploit reproduction, payload testing, or
  offensive functionality.

Both commands remain explicit operator actions. Neither is connected to a
scheduler, FastAPI startup, a public API, or a frontend ingestion control. No
live reconciliation was performed while developing this workflow.
