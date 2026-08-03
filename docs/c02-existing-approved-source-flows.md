# C02 existing approved source flows

## Authoritative checkpoint and scope

- Bundle: C02
- Official tasks: B3-01, B3-02, B3-03, B3-04, B3-05
- Branch: `dev`
- Starting `HEAD` and `origin/dev`: `06e1c4a54268079585f9084783a7b9f1b4e0bbf6`
- Starting divergence: `0 0`
- Starting subject: `C01 Add Prefect orchestration core`

C02 audits the eleven existing registry identities and adds six inactive,
flow-ready handlers. It does not add a source, endpoint, credential, public API,
frontend control, deployment registration, or active schedule. The production
`DEFAULT_SOURCE_HANDLERS` mapping remains immutable and empty. The separate
immutable `build_c02_source_handlers()` result exists for offline tests and a
later controlled staging-binding task only.

## Source capability and handler status

“Live-capable” and “publication-only” describe reviewed code capability, not
activation or permission for an unapproved live run.

| Canonical identity | Capability | Access and exact fixed location | Authentication or licence state | C02 status and progress |
| --- | --- | --- | --- | --- |
| `cisa-kev` | Live-capable exploit-enrichment catalogue | Public JSON; `www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Public; no credential or commercial licence required | Flow-ready, inactive; `content_hash` checkpoint containing catalogue SHA-256 and next local cursor |
| `nvd` | Live-capable vulnerability API | Authorized public API; `services.nvd.nist.gov/rest/json/cves/2.0` | Public access; optional configured `NVD_API_KEY` only for documented higher pacing | Flow-ready, inactive; modified-since watermark at the scheduled slot |
| `first-epss` | Live-capable local-CVE enrichment API | Authorized public API; `api.first.org/data/v1/epss` | Public; no credential or commercial licence required | Flow-ready, inactive; modified-since watermark at the scheduled slot |
| `cert-eu-security-advisories` | Publication-only security-advisory feed | Public RSS; `cert.europa.eu/publications/security-advisories-rss` | Public; no credential or commercial licence required | Flow-ready, inactive; modified-since watermark at the scheduled slot |
| `google-threat-intelligence-public-research` | Publication-only threat-research feed | Public RSS collection at `feeds.feedburner.com/threatintelligence/pvexyqv7v0v`; canonical articles only on `cloud.google.com/blog/topics/threat-intelligence/` | Public metadata; no credential or commercial licence required | Flow-ready, inactive; modified-since watermark at the scheduled slot |
| `mandiant-public-threat-research` | Publication-only threat-research feed | Same fixed public RSS and canonical publication path as Google | Public metadata; no credential or commercial licence required | Flow-ready, inactive; separate fetch and modified-since watermark at the scheduled slot |
| `anomali-cyber-watch` | Unstable manual publication discovery | Manual catalogue at `www.anomali.com/blog` | Public metadata; automation remains unapproved and unstable | Manual-only and unbound; no operational progress |
| `censys-arc-research` | Unstable manual publication discovery | Manual catalogue at `censys.com/blog/` | Public metadata; manual controls remain required | Manual-only and unbound; no operational progress |
| `censys-rapid-response-advisories` | Unstable manual publication discovery | Manual catalogue at `censys.com/advisory/` | Public metadata; manual controls remain required | Manual-only and unbound; no operational progress |
| `ibm-x-force-public-research` | Local-catalogue-only research metadata | Reviewed local input attributed to `www.ibm.com/think/x-force/` | No IBM network automation, credential, or commercial API approval | Manual-only and unbound; no operational progress |
| `ibm-x-force-public-osint-advisories` | Local-catalogue-only advisory metadata | Reviewed local input attributed to `exchange.xforce.ibmcloud.com/osint/` | No X-Force Exchange network, guest/login automation, credential, or commercial API approval | Manual-only and unbound; no operational progress |

No current registry identity is classified as retired. Anomali, both Censys
identities, and both IBM identities are not scheduled success paths.

## Shared flow and transaction contract

Each handler validates its exact C01 `SourcePolicy`, attempt source, registry
definition, progress storage, kind, and name. Developer-controlled constants
bound every query, page, response, batch, record, and local selection.

The ordering is:

1. reuse exact immutable run-linked evidence when a previous source-data commit
   exists for the same run;
2. otherwise fetch and parse the fixed external source outside the source-data
   persistence transaction;
3. persist normalized source rows and sanitized `IngestionRunRecord` outcomes
   in one handler-owned transaction;
4. store one compact immutable execution-evidence record in that transaction;
5. return only after commit;
6. let C01 record operational persistence in a separate transaction; and
7. advance progress only after that operational evidence commits.

`reconstruct_progress()` reads only the committed execution evidence. It does
not call a source client. Partial or failed execution evidence has no progress
proposal. The handlers never update legacy
`IntelligenceSource.checkpoint_value`.

## Source-specific request and persistence bounds

### CISA KEV

- one fixed catalogue request, at most 2 MiB and 2,000 declared catalogue rows;
- every declared row is normalized and the declared count, catalogue metadata,
  duplicates, and complete CVE set are validated before absence decisions;
- the complete catalogue is hashed and reconciled, while deterministic chunks
  of at most 100 catalogue CVEs select only existing local global identifiers
  for enrichment through the existing service; expected non-local catalogue
  entries create no skipped/failed outcome;
- at most 500 local vulnerability rows are reconciled in batches of at most
  100, starting after the stored cursor and wrapping once without repeating a
  row in the cycle;
- a changed catalogue hash restarts local reconciliation at the beginning;
  the same hash continues the next bounded local batch; and
- the canonical token is `sha256=<64 lowercase hex>;cursor=<non-negative id>`.

### NVD

- window end is `context.scheduled_for`; the initial window is two hours and a
  previous watermark receives a fixed five-minute overlap;
- windows over 120 days, future/conflicting watermarks, changing pagination
  totals, incomplete pages, and totals above the fixed bound fail without
  persistence or watermark advancement;
- 500 results per page, at most 10 pages and 5,000 records per cycle;
- the optional API key remains a `SecretStr`; consecutive request starts keep
  6-second public or 0.6-second authenticated pacing; and
- normalized CVE identity deduplicates exact repeats and rejects conflicting
  repeats before one caller-owned persistence transaction.

### FIRST EPSS

- a deterministic query selects at most 500 existing local CVEs, unseen first,
  then oldest EPSS source date, then uppercase CVE identity; its EPSS-date
  subquery matches source, intelligence item, and the current CVE external ID,
  so separate CVEs on one vulnerability retain separate fairness dates;
- requests contain at most 100 CVEs and retain the existing 2,000-character
  query limit;
- each response is limited to 2 MiB by both declared length and incremental
  streamed-byte checks;
- every returned CVE must belong to its requested batch, have a valid non-future
  score date, and not conflict with a duplicate; omitted and unexpected records
  become explicit failed outcomes; and
- valid records use existing score-date provenance and transactional
  enrichment, allowing fair candidate progression across later cycles.

### Publication feeds

- CERT-EU, Google, and Mandiant each make one bounded full-feed request and
  accept at most 100 entries; no article body, attachment, PDF, or binary is
  requested;
- Google and Mandiant may independently fetch their shared fixed feed;
- adapters require exact author attribution and canonical
  `cloud.google.com/blog/topics/threat-intelligence/` publication URLs;
- each handler persists only entries attributed to its active source;
- malformed individual entries become sanitized failed records while valid
  entries may commit as an explicit partial run without progress; and
- the existing publication pipeline supplies content hashes, canonical URL and
  title identity, tracking-parameter removal, safe metadata bounds, and
  idempotent create/update/no-change behavior.

## Tested evidence

Offline tests cover policy identity, immutable map construction, reconciled
counters, execution-evidence replay, conflicting reconstruction, expected
non-local CISA entries, complete-catalogue hashing, bounded local-identifier
lookup, cursor continuation, changed-catalogue restart, wrap-around, NVD window
overlap, paging, record caps, public/authenticated pacing, exact CVE deduplication, EPSS
per-CVE multi-identifier fairness ordering, dataset dates, omissions,
unexpected rows, partial results, declared and streamed response-size bounds,
publication attribution, fixed
feeds, malformed entry isolation, no-change, and progress suppression.

All external-client tests use fake clients, fixtures, or `httpx.MockTransport`.
No live source request, Prefect deployment registration, schedule activation,
or staging/production success claim occurred in C02 implementation or testing.

## Limitations and later work

- The six handlers are not production-bound or deployment-activated.
- C07 owns authenticated operator run, pause, retry, enable, and disable
  controls.
- C11/deployment work owns controlled staging binding, paused registration,
  activation approval, monitoring, backup/recovery evidence, and production
  readiness.
- C02 does not implement historical NVD backfill, shared Google/Mandiant fetch
  caching, commercial sources, new credentials, or new source families.
- Manual CLIs remain separate compatibility workflows; their successful manual
  execution is not evidence of scheduled flow activation.
