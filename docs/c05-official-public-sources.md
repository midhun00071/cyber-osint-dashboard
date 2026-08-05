# C05 Official Public Sources

## Status and scope

C05 is the combined B6-01/B6-02/B6-03 implementation bundle. It was built and
tested only with synthetic local fixtures and mocked HTTP transports. No live
source request occurred. No C05 source is enabled, scheduled, or present in the
production default-handler mapping.

| Source slug | Official source | Implementation | Operational state | Authentication |
| --- | --- | --- | --- | --- |
| `mitre-attack-enterprise` | MITRE ATT&CK Enterprise / MITRE | Implemented | Disabled | Prohibited |
| `cert-fr-security-alerts` | CERT-FR Security Alerts / CERT-FR / ANSSI | Implemented | Disabled | Not required |
| `cert-fr-security-advisories` | CERT-FR Security Advisories / CERT-FR / ANSSI | Implemented | Disabled | Not required |
| `uk-ncsc-threat-reports` | UK NCSC Threat Reports / UK National Cyber Security Centre | Implemented | Disabled | Not required |

Later activation requires a separate approval, an explicit registry and handler
binding change, and bounded staging evidence. C05 does not authorize that work.
No database migration or schema change was introduced.

## B6-01 paid-source retirement

Paid and commercial source implementation work is retired and superseded by C05.
There is no pending or planned Censys Platform/Search API exposure enrichment,
host search, scan or rescan; VirusTotal premium/business integration; Recorded
Future integration; commercial free-tier workaround; paid credential request;
paid-subscription mock; or fabricated commercial-source result. APR-01 through
APR-04 and the former B6-02 through B6-08 commercial implementation mappings are
retained only as retired historical records and are not approval gates or future
work for this release.

The two existing public Censys publication-metadata sources remain distinct and
preserved: `censys-arc-research` and
`censys-rapid-response-advisories`. They collect bounded public publication
metadata and do not use or represent the Censys Platform API.

## B6-02 MITRE Enterprise ATT&CK TAXII/STIX 2.1

The immutable policy permits only:

- host `attack-taxii.mitre.org`;
- API root `https://attack-taxii.mitre.org/api/v21/`;
- collection `x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019`;
- objects endpoint `https://attack-taxii.mitre.org/api/v21/collections/x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019/objects/`;
- collection title `Enterprise ATT&CK`;
- `application/taxii+json;version=2.1`; and
- STIX 2.1 objects.

Every initial request contains `limit=1000`, `match[spec_version]=2.1`, and the
fixed type filter for `attack-pattern,campaign,intrusion-set,malware,relationship,identity,marking-definition`.
The first run omits `added_after`. A later run uses one canonical committed
server date-added cursor. Pagination retains those filters and adds only the
immediately preceding opaque `next` token. Tokens are bounded to 1,024 printable
ASCII characters and repeated or cyclic tokens fail the run.

The client is GET-only, uses no authentication or cookies, follows zero
redirects, disables environment proxy trust, sends `Accept-Encoding: identity`,
and uses 5/30/5/5-second connect/read/write/pool timeouts with a 600-second total
deadline. Limits are 40 pages and requests, 8 MiB per page, 64 MiB per execution,
30,000 server objects, 20,000 accepted relationships, JSON depth 24, two million
JSON nodes, 50,000 characters per string, 100 aliases, and 25 external references.
An exceeded limit fails without truncation or cursor advancement. HTTP 429 is not
retried in the same execution, and a failure after a consumed page is not replayed.

Only the seven fixed STIX object types are accepted. `intrusion-set` maps to the
existing threat-actor entity. ATT&CK custom properties use an explicit allow-list
and explicit type/count/text bounds; unknown custom properties and custom object
types fail closed. An object that explicitly belongs only to another ATT&CK
domain is rejected. External-reference URLs and descriptions are validated and
discarded; only safe `source_name` and `external_id` metadata persists, and no
external reference is requested.

The combined inactive lifecycle is `revoked=true` or
`x_mitre_deprecated=true`. Both validated source flags are retained in the safe
payload, while the existing monotonic revoked representation prevents later
reactivation. Only `uses` and `attributed-to` relationships between supported
entities can materialize; unsupported combinations are counted and excluded.
Incremental relationships may resolve a previously committed same-source object
inside the database transaction. Missing, conflicting, or corrupt stored source
records fail and roll back.

The cursor is a canonical UTC RFC 3339 TAXII server date-added value, including a
validated `X-TAXII-Date-Added-Last` boundary when supplied. It never derives from
the STIX `modified` field, never regresses, and becomes a progress proposal only
after the complete document validates and the database transaction commits.

## B6-03 strict official RSS metadata

The three immutable feed contracts are:

- CERT-FR alerts: `https://www.cert.ssi.gouv.fr/alerte/feed/`, canonical paths `/alerte/CERTFR-YYYY-ALE-NNN/`, language `fr`;
- CERT-FR advisories: `https://cert.ssi.gouv.fr/avis/feed/`, canonical paths `/avis/CERTFR-YYYY-AVI-NNNN/`, language `fr`; and
- UK NCSC reports: `https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml`, canonical paths `/report/<safe-lowercase-slug>`, language `en-GB`.

The shared client is HTTPS/GET-only, accepts no caller URL, query, header,
credential, cookie, proxy, callback, redirect target, or authentication input,
disables redirects and environment proxy trust, and sends identity encoding.
Timeouts are 5/15/5/5 seconds with a 30-second total deadline. The response limit
is 2 MiB. Only `application/rss+xml`, `application/xml`, and `text/xml`, with at
most one valid charset parameter, are accepted. Missing, conflicting, compressed,
HTML, JSON, octet-stream, or unsupported media types fail closed.

XML must be well formed and may not contain `DOCTYPE`, entity declarations, or
external processing instructions. A feed is limited to 100 entries and 100
accepted records. Titles, summaries, identifiers, URLs, authors, categories,
category counts, languages, retained diagnostics, XML nodes, and XML depth are
bounded. Summaries are converted deterministically to plain text; active HTML is
never persisted.

Canonical publication URLs require exact HTTPS hosts and source-specific paths.
User information, ports, query strings, fragments, percent-encoded paths, dot
segments, controls, and ambiguous hosts are rejected rather than rewritten.
Exact duplicates are deterministically deduplicated. Conflicting external-ID or
canonical-URL identities fail and roll back.

Only publication metadata is retained: source identity, deterministic external
identifier, canonical URL, title, plain-text summary, bounded author/categories,
published/updated times, fixed language, safe provenance, and content hash. The
collector never requests article bodies, PDFs, attachments, enclosures, images,
media, scripts, stylesheets, linked JSON, related reports, or external links.

The compact cursor is `v1:<canonical-metadata-sha256>:<greatest-UTC-timestamp>`.
The same hash yields `no_change`. A fully valid changed feed advances only after
the publication transaction commits. Any rejected entry yields `partial` with no
cursor advancement. Oversize, malformed, conflicting, transport, or persistence
failure rolls back and retains the prior cursor. Partial persistence is never
reported as success.

## Accepted limitations

- All four C05 sources are disabled and have no production handler or schedule.
- Only fixture and mocked-transport behavior is evidenced; no live availability,
  freshness, rate-limit, or upstream-format claim is made.
- No article/PDF/attachment/enclosure/external-reference retrieval exists.
- Activation and bounded staging validation are separate future approval work.
