# Data Sources

## C03A STIX/TAXII eligibility

C03A provides an immutable test/later-staging TAXII handler builder, but no
production TAXII source identity, hostname, endpoint, collection, credential,
binding, or deployment. `PRODUCTION_STIX_SOURCE_POLICIES`,
`PRODUCTION_TAXII_COLLECTION_POLICIES`, and `DEFAULT_SOURCE_HANDLERS` remain
empty. Missing production policy is `disabled` before any client or transport
is created; `licence_required` is limited to an explicit developer-controlled
fixed identity. No live TAXII request was performed. See
[C03A threat knowledge and STIX persistence](c03-threat-knowledge-stix-persistence.md).

## Purpose and audience

This guide is the source-traceability record for mentors, reviewers, operators,
and future developers of the Alpha Data / Cyber OSINT Dashboard. It maps every
enabled implemented source identity to its approved endpoint or reviewed input,
manual invocation path, normalization and persistence behavior, identity
controls, and exclusions. The current backend source registry and ingestion code
are authoritative when this guide and an older planning statement differ.

External OSINT is untrusted data. “Publicly visible” does not by itself grant
permission to scrape, automate access, store, mirror, redistribute, or use a
commercial API. A source-registry entry records developer-controlled metadata;
registry inclusion, `implemented` status, or `enabled: true` does not grant
collection authorization, licensing permission, API access, storage rights, or
approval for a new live collection method.

## Defensive selection and authorization rules

An integration is eligible only when it is defensive, ethical, authorized,
educational, or lab-safe and uses a public or explicitly authorized access
method. Before a future source is implemented, the project must verify its
current terms, access and automation permission, licensing, storage and
redistribution rights, host and URL boundaries, rate limits, data minimization,
and mentor approval.

The project does not collect stolen, leaked, private, restricted, or dark-web
data. It does not perform active scanning or target probing, exploit execution,
credential collection, malware retrieval, file submission, arbitrary URL
fetching, or offensive automation. Public source text is processed as bounded
plain text. Credentials, authorization material, HTTP headers and cookies,
attachments, downloaded reports, malware samples, and raw payloads are not
exposed through public APIs.

Exact HTTPS host allow-lists and fixed endpoint paths are controlled in
`backend/app/ingestion/source_registry.py` and the source-specific collectors or
adapters. Adding metadata to the registry is not a substitute for implementing
and reviewing an approved collector.

## Registry status and operational support

`implementation_status: implemented` means repository code and deterministic
tests exist for the registered workflow. `enabled: true` allows that specific
workflow to create or validate its `IntelligenceSource` row. Neither field
starts ingestion or broadens the registered endpoint, content family, or access
method. The current registry has three planned C04A UAE definitions and two
B5-04 DESC definitions with `implementation_status: implemented` and
`enabled: false`. All five remain outside enabled-source and generated
orchestration policies and do not create an approved automatic request path.
Other future and excluded
vendors are recorded separately in the assessment documents.

All ingestion and enrichment is manual-only and explicitly operator invoked.
There is no active scheduler, startup ingestion, recurring background ingestion,
background worker, frontend ingestion trigger, or public ingestion API. No
standard refresh interval is implemented. Operators choose when to run an
approved command; local-file imports require a separately reviewed file each
time. Live network requests occur only through the fixed endpoints used by the
corresponding command.

C02 adds six reviewed, flow-ready handler implementations for CISA KEV, NVD,
FIRST EPSS, CERT-EU, Google Threat Intelligence public research, and Mandiant
public threat research. They are not bound to the immutable production
`DEFAULT_SOURCE_HANDLERS` mapping, registered as a deployment, or activated.
Operational collection therefore remains manual-only. The exact capability,
progress, bounds, and inactive binding status are recorded in
[C02 existing approved source flows](c02-existing-approved-source-flows.md).
Anomali, both Censys identities, and both IBM identities remain manual-only,
unbound, and unavailable as scheduled success paths.

## Implemented-source summary

Every row below is `implemented`, `enabled: true`, and unauthenticated by
requirement (`authentication_required: false`). NVD supports an optional API key
for the official service’s higher rate allowance, but the source itself does not
require authentication.

### B1-04 progress contracts

Every production source declares exactly one developer-controlled progress
contract. Runtime callers cannot select or override it. The frozen mapping is:

| Progress contract | Canonical source slugs |
| --- | --- |
| `watermark` | `nvd`, `first-epss`, `cert-eu-security-advisories`, `google-threat-intelligence-public-research`, `mandiant-public-threat-research` |
| `checkpoint` | `cisa-kev` |
| `none` | `censys-arc-research`, `censys-rapid-response-advisories`, `anomali-cyber-watch`, `ibm-x-force-public-research`, `ibm-x-force-public-osint-advisories` |

Checkpoint and watermark sources enter `checkpoint_pending` only after record
persistence commits and are finalized in a later caller-owned transaction.
Sources with `none` may complete directly in the persistence transaction. The
existing transitional writers are not integrated with the B1-04 service and do
not participate in its advisory locks; they must not run concurrently with new
operational writers until their separately reviewed migration is complete.

| Canonical slug | Display name / owner | Content family; source type | Fixed base URL; exact approved host | Registry access; structured input |
| --- | --- | --- | --- | --- |
| `nvd` | National Vulnerability Database / NIST | `vulnerability`; `api` | `https://services.nvd.nist.gov/rest/json/cves/2.0`; `services.nvd.nist.gov` | `authorized_api`; yes |
| `first-epss` | FIRST EPSS / FIRST | `exploit_enrichment`; `api` | `https://api.first.org/data/v1/epss`; `api.first.org` | `authorized_api`; yes |
| `cisa-kev` | CISA Known Exploited Vulnerabilities Catalog / CISA | `exploit_enrichment`; `json` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`; `www.cisa.gov` | `public_publication`; yes |
| `cert-eu-security-advisories` | CERT-EU Security Advisories / CERT-EU | `security_advisory`; `rss` | `https://cert.europa.eu/publications/security-advisories-rss`; `cert.europa.eu` | `public_feed`; yes |
| `censys-arc-research` | Censys ARC Research / Censys | `exposure_research`; `json` | `https://censys.com/blog/`; `censys.com` | `manual_catalogue`; no |
| `censys-rapid-response-advisories` | Censys Rapid Response Advisories / Censys | `public_osint_advisory`; `json` | `https://censys.com/advisory/`; `censys.com` | `manual_catalogue`; no |
| `anomali-cyber-watch` | Anomali Cyber Watch / Anomali | `threat_research`; `json` | `https://www.anomali.com/blog`; `www.anomali.com` | `manual_catalogue`; no |
| `ibm-x-force-public-research` | IBM X-Force Public Research / IBM X-Force | `threat_research`; `json` | `https://www.ibm.com/think/x-force/`; `www.ibm.com` | `manual_catalogue`; no |
| `ibm-x-force-public-osint-advisories` | IBM X-Force Public OSINT Advisories / IBM X-Force | `public_osint_advisory`; `json` | `https://exchange.xforce.ibmcloud.com/osint/`; `exchange.xforce.ibmcloud.com` | `manual_catalogue`; no |
| `google-threat-intelligence-public-research` | Google Threat Intelligence Public Research / Google Threat Intelligence | `threat_research`; `rss` | `https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v`; collection host `feeds.feedburner.com`, publication host `cloud.google.com` | `public_feed`; yes |
| `mandiant-public-threat-research` | Mandiant Public Threat Research / Mandiant / Google Security | `threat_research`; `rss` | `https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v`; collection host `feeds.feedburner.com`, publication host `cloud.google.com` | `public_feed`; yes |

Commands below are run from `backend` after the documented environment and
PostgreSQL service are ready. They are examples of explicit invocation, not
scheduled refresh instructions.

## Vulnerability and enrichment sources

### `nvd` — National Vulnerability Database

- **Role and path:** `NvdClient` fetches the fixed official CVE API and
  `NvdIngestionService` creates or updates vulnerability items. Invoke:

  ```powershell
  .\.venv\Scripts\python.exe -m app.ingestion.nvd_cli --window-minutes 60 --results-per-page 25 --max-records 25
  ```

  The separate representative multi-year workflow can be previewed and then
  invoked explicitly:

  ```powershell
  .\.venv\Scripts\python.exe -m app.ingestion.nvd_curated_cli --plan
  .\.venv\Scripts\python.exe -m app.ingestion.nvd_curated_cli --start-year 2020 --end-year 2026 --chunk-days 90 --results-per-page 50 --max-pages-per-query 2 --max-requests 400 --retention-multiplier 1
  ```

- **Normalized persistence:** uppercase CVE identifier; bounded canonical title
  and English description; canonical NVD detail URL; source publication and
  modification timestamps; active or archived status; severity; selected CVSS
  score, vector, and version; bounded affected-product configuration summary and
  values; source observation timestamps and sanitized audit counters/status.
- **Refresh and identity:** each command requests a caller-bounded last-modified
  window. Defaults are 60 minutes, 25 records per page, and 25 total records;
  supported CLI bounds are 1–1440 minutes and 1–100 records. CVE namespace/value
  plus the NVD source external ID identify records; a canonical content hash
  separates unchanged data from updates.
- **Curated selection:** the curated command represents, but does not mirror,
  NVD. It defaults to publication years 2020 through the current UTC year and
  targets 10 Critical, 5 High, 3 Medium, and 2 Low CVEs per year. It requires a
  usable preferred CVSS v3/v4 result and ranks each severity by CISA KEV
  metadata first, CVSS score descending, NVD modification time descending, and
  uppercase CVE ID ascending. Duplicate candidates collapse by CVE ID.
  Existing records use the same update/unchanged path; unselected records are
  not deleted and the incremental checkpoint is not advanced. EPSS and KEV
  enrichment remain separate subsequent manual workflows. Default retained
  full-candidate limits per year are 10 Critical, 5 High, 3 Medium, and 2 Low.
  The 1–5 retention multiplier scales those per-severity limits. An eviction or
  valid candidate discarded at the configured ceiling marks the year
  incomplete.
- **Controls and limitations:** HTTPS is fixed to `services.nvd.nist.gov`;
  date-window and pagination metadata are validated; normalized source evidence
  is capped at 512 KiB per CVE. The client rejects an oversized valid
  `Content-Length` before body consumption, incrementally reads decoded body
  bytes, stops immediately above 20 MiB, discards the partial body, and parses
  JSON only after the bounded stream completes. Client timeouts apply.
  Consecutive official API request starts are delayed 6 seconds without an API
  key or 0.6 seconds with the optional `NVD_API_KEY`. The key is secret-managed
  and never documented or logged. The workflow does not execute exploits,
  retrieve malware, or scan affected systems. Curated chunks default to 90 days
  and cannot exceed the NVD 120-day limit. Candidate pages (default 2 per
  query), page size (default 50), total requests (default 400), retention, and
  retries (0) are bounded. Caps, retention discards, request failures, and exact
  quota shortfalls are reported as incomplete; therefore the curated result
  must not be treated as complete NVD coverage. Audit counters reconcile every
  fetched observation, including valid unselected candidates as skipped, and
  completion time is captured after processing.

  > This product uses data from the NVD API but is not endorsed or certified by the NVD.

### `first-epss` — FIRST EPSS

- **Role and path:** FIRST EPSS enriches existing local CVE vulnerability
  records; it does not create arbitrary vulnerability items. Invoke:

  ```powershell
  .\.venv\Scripts\python.exe -m app.ingestion.epss_cli --max-cves 25 --batch-size 100
  ```

- **Normalized persistence:** uppercase CVE identifier, six-decimal EPSS
  probability, six-decimal percentile, score date, source observation state,
  content hash, and sanitized run counters/status.
- **Refresh and identity:** each run selects at most the requested local CVEs,
  batches their IDs, and requests only those IDs from the fixed API. `--max-cves`
  is 1–500; `--batch-size` is 1–100 and is also constrained by the client’s
  2,000-character query limit. The CVE identifier links enrichment to an
  existing item; source external ID and content hash distinguish unchanged from
  updated evidence.
- **Inactive C02 handler:** the flow-ready handler orders at most 500 global CVE
  identifiers by unseen/oldest evidence and CVE identity. Its EPSS evidence
  lookup correlates the source, intelligence item, and exact CVE external ID,
  so two CVEs on one vulnerability keep independent refresh dates.
- **Controls and limitations:** HTTPS host and endpoint are fixed, responses and
  probability/date formats are validated, and source evidence is capped at 4
  KiB per record. Missing or non-vulnerability local CVEs are skipped safely.
  EPSS is a probability estimate, not proof of exploitation or a scan result.

### `cisa-kev` — CISA Known Exploited Vulnerabilities Catalog

- **Role and path:** CISA KEV enriches existing local CVE vulnerability records
  from the fixed official JSON catalogue. The existing catalog-driven command
  processes a bounded catalog slice:

  ```powershell
  .\.venv\Scripts\python.exe -m app.ingestion.cisa_kev_cli --max-records 25
  ```

  The separate local-reconciliation command validates the complete catalog
  before comparing bounded local rows:

  ```powershell
  .\.venv\Scripts\python.exe -m app.ingestion.cisa_kev_reconcile_cli `
      --max-cves 500 `
      --batch-size 100
  ```

- **Normalized persistence:** CVE identifier; listed status and last-checked
  time; catalogue date added; remediation due date; required action; known
  ransomware-campaign-use boolean; bounded vendor, product, vulnerability name,
  short description, and notes in source evidence; content hash and sanitized
  audit status.
- **Refresh and identity:** each command retrieves the current catalogue and
  processes a caller-bounded 1–500 entries (default 25). Exact duplicate CVEs
  collapse; conflicting duplicates fail safely. CVE identity links only to an
  existing local vulnerability. Unknown KEV-only CVEs are skipped and are not
  created locally.
- **Controls and limitations:** the collector permits only the exact HTTPS
  catalogue URL, at most three validated redirects, bounded timeouts, JSON
  content, and a 2 MiB response. Individual normalized evidence is capped at 16
  KiB. It does not claim that items absent from a bounded run are not exploited.
  The catalog-driven workflow marks listed matches but does not prove a
  `not_listed` result. Only the separate reconciliation workflow assigns
  `not_listed`, and only after every declared catalog entry passes validation.
  Its `--max-cves` limit (1–500) applies to local rows, its `--batch-size` bound
  is 1–100, and one caller-owned transaction rolls back all selected status and
  audit changes after an uncaught database failure. Repeated runs are
  idempotent apart from refreshing the KEV checked timestamp. A skipped row or
  selected row still in `unknown` state produces a controlled partial result
  with exit code 1 while valid changes and safe audits commit;
  `unknown_remaining` counts only selected rows still in that state.
- **Local identity safety:** Reconciliation emits one outcome per unique
  vulnerability row. Each bounded batch loads only global `cve` identifiers
  with `source_id IS NULL`, then normalizes and deduplicates them. Missing or
  ambiguous identity is skipped without changing KEV status or checked time;
  ambiguous identity never selects a CVE based on identifier query order. A
  skipped unknown row causes the controlled partial result.
- **Reconciliation evidence:** Formal `IngestionRun` counters describe local
  rows and reconcile as fetched = created + updated + unchanged + skipped +
  failed, with created fixed at zero. Catalog raw-record and unique-CVE counts
  are separate summary/checkpoint evidence. Start, checked, and completion times
  are captured before fetch, after complete validation immediately before local
  reconciliation, and after reconciliation plus audit processing. Catalog
  version evidence is restricted to a non-empty, bounded ASCII token containing
  only letters, digits, periods, underscores, and hyphens.
- **Current manual-command pagination limit:** The manual reconciliation query
  always begins with the lowest local vulnerability IDs. The 500-row command
  therefore still requires a future cursor/resume enhancement for databases
  with more than 500 vulnerabilities. C02 separately adds deterministic
  start-after cursor continuation and one wrap-around to the caller-owned
  reconciliation service for its inactive handler. Neither manual command nor
  the C02 handler is scheduled or connected to startup, an API route, or the
  frontend.
- **Inactive C02 enrichment filtering:** The complete catalogue still supplies
  validation, SHA-256 checkpoint, and listed/not-listed reconciliation input.
  Before enrichment, catalogue CVEs are matched to existing global local CVE
  identifiers in deterministic chunks of at most 100. Expected KEV-only entries
  create no processing failure, while matched invalid/conflicting local targets
  retain the existing explicit non-success behavior.

## Advisory and research publication sources

All publication adapters emit `PublicationCandidate` objects. The shared
`PublicationPipeline` validates the registered source, derives item type from
the content family, normalizes text and timezone-aware timestamps, canonicalizes
approved HTTPS URLs, removes tracking parameters, rejects credential-like or
signed query keys, bounds safe metadata, and persists without fetching upstream
content or committing the transaction. Sanitized ingestion-run evidence and
commit/rollback ownership are workflow-specific: some commands own the
transaction directly, while the Censys and live Anomali workflows delegate it to
their source-specific ingestion services.

### `cert-eu-security-advisories` — CERT-EU Security Advisories

- **Role and path:** the fixed public RSS feed creates or updates
  `security_advisory` items. Invoke:

  ```powershell
  .\.venv\Scripts\python.exe -m app.ingestion.rss_cli --max-records 25
  ```

- **Normalized persistence:** feed ID/GUID or a URL-derived fallback source ID;
  bounded plain-text title and summary; canonical CERT-EU publication URL;
  publication and modification timestamps; bounded author and category
  metadata; item type, source identity, content hash, observation timestamps,
  and sanitized audit counts/status.
- **Refresh and identity:** the command fetches the feed on demand and processes
  1–100 entries (default 25). Source external ID and canonical URL hash identify
  a source record; global canonical-URL and normalized-title fingerprints avoid
  unsafe cross-source duplication within the same article type. Exact duplicates
  collapse and conflicting duplicates fail safely.
- **Controls and limitations:** collection is locked to
  `cert.europa.eu/publications/security-advisories-rss`, with validated redirects,
  timeouts, RSS/XML content, and a 1 MiB response. It does not fetch article
  bodies, attachments, PDFs, or malware samples.

### `censys-arc-research` — Censys ARC Research

This source stores approved Censys ARC publication metadata as `threat_report`
items. Manual live invocation uses the closed selector `arc`:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.censys_publications_live_cli --source arc --max-records 5
```

The reviewed local-file fallback remains supported:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.censys_publications_cli --file <reviewed-local-json-file>
```

### `censys-rapid-response-advisories` — Censys Rapid Response Advisories

This source stores approved rapid-response publication metadata as
`security_advisory` items. Manual live invocation uses the closed selector
`rapid-response`:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.censys_publications_live_cli --source rapid-response --max-records 5
```

The same reviewed local-file command is used with a document whose
`source_slug` is `censys-rapid-response-advisories`.

For both Censys sources, the closed selectors `arc` and `rapid-response` map to
fixed approved public discovery pages in code; no arbitrary URL input is
available. `--source` is required,
`--max-records` defaults to 5, and its valid range is 1 through 20. Requests use
bounded redirects, timeouts, response sizes, HTML content types, and at least ten
seconds between request starts. The collector parses bounded title, summary,
publication/modified timestamps, authors, and categories from selected metadata
only. Raw HTML and JSON-LD are not stored.

The strict reviewed JSON fallback is UTF-8, at most 1 MiB, 100 publications, 20
authors, and 20 categories per publication. It accepts an ordinary local path,
rejects UNC/network, device-namespace, symlink, and reparse-point traversal, and
requires one of the two exact seven-field source schemas. Censys canonical URLs
use exact host `censys.com` and the selected literal `/blog/` or `/advisory/`
path family. A source-family namespace plus SHA-256 of the canonical URL forms
the external ID; common publication URL/title fingerprints and content hash
provide cross-source linking, duplicate conflict detection, and update checks.

There is no scheduler, startup hook, background worker, frontend invocation, or
public ingestion endpoint. Censys exposure records, hosts, certificates, DNS
data, scan results, search results, active scanning, target probing, and rescan
capability are excluded. The integration does not use a Censys API, account, or
API key and must not be used to scan, probe, search, or rescan internet assets.

### `google-threat-intelligence-public-research` — Google Threat Intelligence Public Research

### `mandiant-public-threat-research` — Mandiant Public Threat Research

Both logical sources share the one fixed public RSS feed but remain separate
registered identities. Invoke the bounded shared collector explicitly:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.google_threat_publications_cli --max-records 25
```

The command accepts 1–100 records (default 25). Collection uses exact host
`feeds.feedburner.com`; stored canonical publication URLs use exact host
`cloud.google.com` and literal prefix `/blog/topics/threat-intelligence/`.
Ownership is determined only by one exact authoritative feed author: `Google
Threat Intelligence Group` maps to
`google-threat-intelligence-public-research`, while `Mandiant` maps to
`mandiant-public-threat-research`. Ownership is never inferred from titles,
categories, product names, report links, threat names, or article text.

Both sources persist `threat_report` items with source-separated URL-derived
external IDs, bounded title and feed summary/description, canonical URL, feed
publication/modified timestamps, bounded authors/categories, and safe feed ID
when present. Common URL/title fingerprints and content hashes provide identity
and update behavior. Known-owner validation failures are audited only on the
resolved source run. Unassigned shared-feed entries are not counted or described
as Google TI or Mandiant publications; sanitized aggregate evidence is recorded
on both logical runs.

Feed `content`, article bodies, attachments, media links, reports, PDFs, and
downloads are ignored. The workflow does not scrape Google Cloud HTML, use
search results, call Google Threat Intelligence or VirusTotal APIs, use
credentials, submit or retrieve files or malware samples, extract or validate
IOCs, schedule work, run at startup, or expose a public ingestion endpoint.

### `anomali-cyber-watch` — Anomali Cyber Watch

The source stores only official Cyber Watch publication metadata from exact host
`www.anomali.com` as `threat_report` items. Invoke bounded live collection:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.anomali_publications_live_cli --max-records 5
```

Or invoke the reviewed local JSON fallback, which remains the currently
operational method:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.anomali_publications_cli --file C:\path\to\anomali-cyber-watch.json
```

The manual live collector accepts only `max_records` from 1 through 20. It
requests the fixed discovery URL `https://www.anomali.com/blog`; no arbitrary URL
is accepted. Approved article paths start `/blog/anomali-cyber-watch-`.
Redirects are validated, there are no automatic retries, request starts are at
least ten seconds apart, and timeouts and response sizes are bounded. Collection
finishes before a database session is opened; persistence is atomic and safely
audited. Raw HTTP and database errors are not exposed.

The collector does not parse article-body prose. It screens selected title,
summary, author, and category metadata for IOC-like URLs, IP addresses, domains,
hashes, internationalized domains, and common defanged forms; unsafe metadata is
rejected before adapter invocation. The reviewed, operator-prepared fallback is
strict UTF-8 JSON of at most 1 MiB and 100 seven-field publications. Titles must
start `Anomali Cyber Watch:` and URLs must use the exact host and literal Cyber
Watch path family. The source-separated canonical-URL hash is the external ID;
the common URL/title fingerprints and content hash control duplicates/updates.

The adapter is not a comprehensive automatic IOC detector. Reviewed catalogues
must contain publication metadata only and exclude article-body text; IOCs and
observables; hashes, IP addresses, and domains used as indicators; raw HTML;
HTTP headers and cookies; attachments, media, PDFs, downloads, and malware
samples. The verified five-record catalogue was reviewed and contained safe
metadata; the local import recorded 5 records fetched, created, and linked.

Manual live collection is implemented and validated offline. During a
controlled live smoke test on 19 July 2026, the fixed official blog was checked.
The request was not rejected with HTTP 403; the observed response status was HTTP 200.
The returned HTML had no deterministic main-content region and no approved Cyber
Watch article links, so discovery failed safely before an article request was
issued and before database-session creation. No ingestion run was created and
no live records were persisted.

There is no credential, RSS, scheduler, startup ingestion, background ingestion,
public ingestion API, or frontend trigger. General Anomali research,
ThreatStream, commercial feeds/APIs, STIX/TAXII, STAXX, IOC services, and malware
functionality are excluded.

### `ibm-x-force-public-research` — IBM X-Force Public Research

This reviewed manual catalogue accepts only canonical
`https://www.ibm.com/think/x-force/<lower-kebab-slug>` publication metadata and
stores `threat_report` items.

### `ibm-x-force-public-osint-advisories` — IBM X-Force Public OSINT Advisories

This separate reviewed manual catalogue accepts only canonical
`https://exchange.xforce.ibmcloud.com/osint/guid%3A<32-lowercase-hex>` metadata
and stores `security_advisory` items. The GUID separator and hex case are
canonicalized locally without following the URL.

Both source families use the same manual-only importer; the reviewed document’s
exact `source_slug` selects one family:

```powershell
.\.venv\Scripts\python.exe -m app.ingestion.ibm_x_force_publications_cli --file <reviewed-local-json-file>
```

Each versioned UTF-8 JSON file names exactly one source and contains at most 100
exact seven-field records in 1 MiB. The adapter accepts bounded plain-text title,
summary, publication/modified timestamps, authors, and categories. It derives a
source-separated canonical-URL hash external ID and uses the common URL/title
fingerprints and content hash for duplicate and update decisions.

The application performs no IBM request. IBMid automation, scraping, APIs,
reputation queries, indicators, collections, comments, structured threat
objects, paid-tier data, Threat Intelligence Index/report/PDF/attachment
downloads, malware retrieval, and STIX/TAXII are excluded. Guest-readable pages
do not authorize automation. The general X-Force Exchange platform is not an
implemented source.

## Persisted fields, normalization, and audit evidence

`IntelligenceSource` preserves the canonical slug, display name, source type,
fixed base URL, enabled state, rate-limit notes, and safe checkpoint metadata.
`SourceRecord` links one source-owned external ID and source URL to an
`IntelligenceItem`, with content and optional canonical-URL hashes, first/last
seen and source timestamps, processing/upstream status, and safe error summary.
These persistent source links preserve traceability to the approved publication
or catalogue identity.
Ingestion runs record the explicit manual trigger, status, bounded counters for
fetched/created/updated/unchanged/skipped/failed records, and sanitized error and
run-record evidence. Raw database errors, stack traces, secrets, and
authorization material are not placed in those summaries.

Publication items persist a registry-derived `security_advisory` or
`threat_report` type, canonical title, bounded summary, canonical URL, source
publication/modification timestamps, observation timestamps, active status,
confidence, UAE classification state, and pending analyst-review state. Safe
publication payload metadata is shallow and bounded to 50 keys, 100 values per
sequence, and 8 KiB canonical JSON; credential-, token-, signature-, cookie-,
password-, header-, and signed-URL aliases are rejected. Normal human-readable
Unicode is retained, while control characters and Unicode surrogates fail
safely.

Vulnerability items additionally persist CVE identity, NVD status/severity/CVSS
and affected-product fields, then optional EPSS and KEV enrichment fields as
described above. Enrichment services never create a new vulnerability solely
from EPSS or KEV input.

## Validation, deduplication, and error handling

- Fixed-source collectors validate HTTPS scheme, exact host and endpoint/path,
  redirect destinations, status/content type, response size, and parsed shape.
  They do not accept operator-supplied network URLs.
- Publication URLs discard fragments and tracking parameters such as `utm_*`,
  but reject credentials, unexpected ports, unsupported hosts, and sensitive
  query aliases. Source adapters add literal path-family and schema checks.
- Publication source records deduplicate within a source by external ID or
  canonical URL hash. Global canonical-URL and normalized-title SHA-256
  identifiers can link the same trusted article type across sources; conflicting
  URL/title/type signals fail safely or require analyst review. Stable content
  hashes produce `unchanged` or `updated` outcomes.
- NVD identity uses the global CVE namespace/value and NVD source ID. EPSS and
  KEV locate that existing CVE identity, skip missing items, and use source IDs
  plus content hashes for idempotent enrichment.
- Transaction ownership is workflow-specific. The invoking CLI or the
  source-specific ingestion service owns commit/rollback and produces sanitized
  outcomes; `PublicationPipeline` itself does not commit. Invalid records can be
  counted safely; database/network internals, raw SQL, headers, cookies, secrets,
  and full exception details are not printed or exposed. For the source-owned
  Anomali and Censys transactions, a rollback failure emits a fixed sanitized
  error event, invalidates the uncertain session, and produces non-success. The
  session is first marked with a fixed internal poison attribute. Logging and
  invalidation are best-effort and cannot change exception control flow or clear
  that marker; no raw cleanup detail is logged or raised. Existing and newly
  created Anomali or Censys services reject a poisoned session before pipeline or
  database activity. The caller must discard it. Rollback failure is never
  silently ignored and cannot advance progress, checkpoints, or success evidence.

## Implemented but disabled DESC metadata collectors

`desc-news` and `desc-published-research` are fixture-tested B5-04 metadata
collectors. They use source type `html`, access method `public_publication`, and
watermark progress, but remain `enabled: false`. Their only fixed listing URLs
are `https://www.desc.gov.ae/media-hub/news/` and
`https://www.desc.gov.ae/research-innovation/published-research/`. Approval is
pending, no live request was made, and neither handler is bound or scheduled.
Pagination, news articles, PDFs, attachments, images, and external publication
pages are never requested. Allow-listed research landing links are stored as
metadata identities only; direct PDF links are rejected. See
[DESC Publication Metadata Collectors](desc-publications.md).

## Planned and assessed sources

The three planned UAE registry identities are `ae-cert`,
`uae-cyber-security-council`, and `uae-cyber-security-council-nibras`. The two
DESC identities are implemented but disabled as described above. All five
remain absent from enabled-source listings,
generated orchestration policies, `DEFAULT_SOURCE_HANDLERS`, and production
STIX/TAXII policies. No UAE collector is activated; no UAE schedule, deployment,
or live network request exists.

| UAE identity | Exact assessed host | Evidence-derived assessed listing paths | Automation state |
| --- | --- | --- | --- |
| `ae-cert` | `tdra.gov.ae` | None; no stable advisory/security-publication listing demonstrated | Approval pending; disabled; cadence unset |
| `uae-cyber-security-council` | `csc.gov.ae` | `/en/stay-alert`, `/en/all-threats`, `/en/all-updates`; `/en/w/<safe-lowercase-publication-slug>` is a metadata-link family, not a request target | Approval required/pending; disabled; proposed minimum 6 hours only after approval |
| `uae-cyber-security-council-nibras` | `csc.gov.ae` | None; navigation text did not demonstrate a stable path or extraction model | Manual/disabled only; cadence unset; B5-03 incomplete |
| `desc-news` | `www.desc.gov.ae` | `/media-hub/news/`; no pagination or article-body path approved | Implementation complete; fixture-tested; approval pending; disabled |
| `desc-published-research` | `www.desc.gov.ae` | `/research-innovation/published-research/`; PDF, attachment, binary, body, and external-page requests prohibited | Implementation complete; fixture-tested; approval pending; disabled |

The immutable evidence and approval boundary is documented in
[UAE Source Governance](uae-source-governance.md). An assessed URL match is not
network approval. APR-05 remains `Need Approval`; its decision and decision date
remain `Pending`; all UAE collectors remain disabled.

The [Source Assessment Matrix](source-assessment-matrix.md) evaluates additional
families from Censys, Anomali, VirusTotal / Google Threat Intelligence, Recorded
Future, Mandiant / Google Security, and IBM X-Force. The
[Source Integration Policy](source-integration-policy.md) defines the review and
approval gate. Assessment is not implementation, and names in those documents
must not be treated as enabled collection support.

Thirteen registry identities are implemented: the eleven enabled identities in
the implemented-source table and the two disabled DESC identities. No other
Censys data, Anomali family, IBM/X-Force platform feature,
VirusTotal capability, Recorded Future source, STIX/TAXII endpoint, commercial
API, or UAE live source is implemented. Controlled classifier slugs such as
`ae-cert`, the legacy classification alias `uae-cert`, and
`uae-cyber-security-council` form a classification trust boundary only and do
not authorize live collection. `uae-cert` is not a network source, and adding a
planned registry identity does not automatically make it classification-trusted
or collection-eligible.

Any future integration requires a new explicit task, current authorization and
licensing verification, an exact source definition, a bounded collector or
reviewed input contract, safe normalization/persistence, tests, documentation,
and independent review. Scheduling remains out of scope unless separately
approved.

## Known limitations

- Refresh timing is operator-controlled; no automatic freshness guarantee or
  standard refresh interval exists.
- Registry metadata does not verify that upstream terms, page structure, or
  availability remain unchanged. Those facts require review before each future
  integration change.
- A bounded run can be partial, capped, skipped, or safely failed and must not be
  interpreted as comprehensive upstream coverage.
- Publication ingestion stores metadata, not full article bodies, attachments,
  reports, PDFs, IOCs, malware, exposure/search datasets, or scan results.
- The controlled Anomali live smoke test did not discover ingestible links; the
  reviewed local JSON fallback is the currently operational method.
- Manual workflows and sanitized audit records do not replace analyst review,
  source licensing review, production monitoring, or a data-retention policy.

Related repository guidance:

- [Architecture](architecture.md)
- [Security Notes](security-notes.md)
- [Testing Plan](testing-plan.md)
- [Manual Test Cases](manual-test-cases.md)
- [Environment and Secrets](environment-and-secrets.md)
- [Production Docker Deployment](production-docker-deployment.md)
