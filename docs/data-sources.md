# Data Sources

## Purpose

This document tracks approved and candidate safe public and authorized cybersecurity data sources for the dashboard.

## Source Selection Rules

All sources must be:

- Publicly available, or explicitly authorized for project use through approved licensed, account, API, feed, or standards-based access.
- Automated access must be authorized.
- Access and licensing must be verified before implementation; mentor and project approval are required before implementing a future gated or commercial source.
- Relevant to defensive cybersecurity awareness.
- Documented with source name, access method, and original URL.
- Used without scraping restricted or unsafe content; arbitrary private, stolen, leaked, restricted, dark-web, and unauthorized data are not allowed.

## MVP Candidate Sources

### NVD

Purpose:

- CVE records
- CVSS scores
- Vulnerability descriptions
- Published and modified dates
- References

Access method:

- Official API

### CISA Known Exploited Vulnerabilities Catalog

Purpose:

- Known exploited vulnerability status
- Prioritization of actively exploited CVEs

Access method:

- Official JSON catalog
- URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

Implementation status:

- Implemented as a manual-only bounded backend enrichment command for existing
  local CVE vulnerability records.
- Locked to the approved HTTPS host and catalog URL.
- Unknown KEV-only CVEs are skipped safely and are not created locally.
- No scheduler, startup hook, API route trigger, or frontend integration is
  included.

### Cybersecurity RSS or News Source

Purpose:

- Recent cyberattack reports
- Malware campaigns
- Ransomware news
- Phishing and breach updates

Access method:

- Approved RSS feed or public API

### CERT-EU Security Advisories

Purpose:

- Public defensive security advisories
- Advisory titles, source links, summaries, and source timestamps
- Additional non-CVE security-advisory intelligence items

Access method:

- Approved RSS feed
- URL: `https://cert.europa.eu/publications/security-advisories-rss`

Implementation status:

- Implemented as a manual-only bounded backend ingestion command.
- Locked to the approved HTTPS host and feed URL.
- No scheduler, startup hook, API route trigger, frontend integration, or
  article-body fetcher is included.

## UAE-Relevant Sources

UAE-focused sources should only be automated if an approved feed, API, or authorized access method exists.

P4-01 UAE classification may trust only controlled canonical source slugs in
the backend classifier allow-list. The current classification allow-list is
limited to UAE government or cybersecurity source identities:

- `ae-cert`
- `uae-cert`
- `uae-cyber-security-council`

These slugs do not authorize new live collection by themselves. Any future UAE
source ingestion still requires separate approval of the feed, API, access
method, terms, and rate limits.

## Censys Public Publications

Approved manual metadata families:

- `censys-arc-research`: official `https://censys.com/blog/` pages, stored as
  `threat_report` items.
- `censys-rapid-response-advisories`: official
  `https://censys.com/advisory/` pages, stored as `security_advisory` items.

The manual live collector accepts only the closed selectors `arc` and
`rapid-response`. Each maps to a fixed public discovery location in code; no
arbitrary URL input is available. Requests have bounded redirects, timeouts,
response sizes, HTML content types, and at least ten seconds between request
starts. Only normalized publication metadata is persisted through the existing
Censys adapter, shared ingestion service, and P9-03 common publication pipeline.
Raw HTML and JSON-LD are not stored. The collector is not a general crawler and
does not use a Censys API, account, or API key.

The P9-04 reviewed local-file fallback remains supported. Its strict UTF-8 JSON
input is limited to 1 MiB, 100 publications, 20 authors per publication, and 20
categories per publication. Only fixed schema fields and plain-text metadata
are accepted. The file must be reached through an ordinary local path without
symlink or reparse-point components; UNC/network and Windows device-namespace
forms are rejected before traversal. URLs must use exact host `censys.com`, the
selected source's literal path family without percent escapes or path
parameters, and no residual non-tracking query string.

Both workflows are explicitly invoked and deduplicate through the same
publication pipeline. There is no scheduler, startup hook, background worker,
frontend invocation, or public ingestion endpoint. Exposure records, hosts,
certificates, DNS data, scan results, search results, and rescan capability are
not imported.

## Google TI and Mandiant Public Publications

Approved manual shared-feed families:

- `google-threat-intelligence-public-research`: official Google Cloud Threat
  Intelligence topic RSS entries authored exactly by `Google Threat Intelligence
  Group`, stored as `threat_report` items.
- `mandiant-public-threat-research`: official Google Cloud Threat Intelligence
  topic RSS entries authored exactly by `Mandiant`, stored as `threat_report`
  items.

P9-05 implements a manual-only bounded collector for the fixed official RSS feed:
`https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v`. The collection
host is exactly `feeds.feedburner.com`; canonical stored publication URLs must
use exact host `cloud.google.com` and literal path prefix
`/blog/topics/threat-intelligence/`.

The adapter stores metadata only: title, canonical URL, short feed-provided
`summary` or `description`, feed timestamps, bounded author/category metadata,
and a safe feed ID when available. Feed `content`, article bodies, attachments,
media links, downloadable reports, and PDFs are ignored. It does not scrape
Google Cloud HTML, use search-engine results, ingest developer documentation,
call Google Threat Intelligence or VirusTotal APIs, use credentials, submit or
retrieve files or malware samples, extract IOCs, schedule work, run at startup,
or expose a public ingestion endpoint. Source ownership is based only on the
exact authoritative feed author and is never inferred from titles, categories,
product names, report links, threat names, or article text.

Known-owner validation failures are counted and audited only on the resolved
source run. Unassigned shared-feed entries are not described as Google TI or
Mandiant publications and are not counted as source-owned fetched or failed
records; the command records sanitized shared-feed error evidence on both
logical runs and includes the aggregate unassigned count in each safe summary.

## Anomali Cyber Watch Publications

Approved manual live and reviewed catalogue family:

- `anomali-cyber-watch`: official Cyber Watch publication pages on exact host
  `www.anomali.com`, stored as `threat_report` items.

The manual live collector accepts only `max_records` from 1 through 20. It
requests the one fixed discovery URL `https://www.anomali.com/blog` and accepts
no arbitrary URL. Discovery and article requests must use HTTPS and exact host
`www.anomali.com`; article URLs must use literal path family
`/blog/anomali-cyber-watch-`. Redirects receive explicit validation, there are no
automatic retries, request starts are at least ten seconds apart, and timeouts
and response sizes are bounded. Collection completes before a database session
is opened. Successful persistence is atomic and safely audited, and raw HTTP and
database errors are not exposed. The collector does not parse article-body
prose. It extracts bounded publication metadata and screens selected title,
summary, author, and category fields for IOC-like URLs, IP addresses, domains,
hashes, internationalized domains, and common defanged forms. Unsafe metadata is
rejected before adapter invocation. Raw HTML, HTTP headers, cookies, attachments,
media, PDFs, downloads, and malware samples are not persisted by live
collection.

The P9-06 reviewed local JSON fallback remains supported and is the currently
operational method. Its reviewed, operator-prepared file is strict UTF-8 JSON
limited to 1 MiB and 100 seven-field publications.

Every title must start exactly with `Anomali Cyber Watch:` and contain
publication-specific text. Every canonical URL must use literal path family
`/blog/anomali-cyber-watch-` with a non-empty article slug. Tracking parameters
may be removed; other query strings, encoded paths, credentials, fragments,
path parameters, alternate hosts, and general blog paths are rejected.

The adapter validates the schema, file and record bounds, title family,
canonical URL identity, timestamps, and bounded plain-text title, summary,
author, and category values. It is not a comprehensive automatic IOC detector.
Reviewed catalogues must contain publication metadata only. Operators and
reviewers must exclude article-body text; IOCs and observables; hashes, IP
addresses, and domains used as indicators; raw HTML; HTTP headers and cookies;
and attachments, media, PDFs, downloads, or malware samples. The verified
five-record catalogue was reviewed and contained safe metadata. There is no RSS,
credential, scheduler, startup hook, background ingestion, public ingestion API,
or frontend trigger. General Anomali public research, ThreatStream, commercial
feeds/APIs, STIX/TAXII, and STAXX remain unimplemented or excluded according to
their recorded decisions.

Manual live collection is implemented and validated offline. During a
controlled live smoke test on 19 July 2026, the fixed official blog page returned
HTML with no deterministic main-content region and no approved Cyber Watch
article links. Discovery therefore failed safely before an article request was
issued and before database-session creation. No ingestion run was created and no
live records were persisted. The request was not rejected with HTTP 403; the
observed response status was HTTP 200. The reviewed safe local JSON fallback then
completed successfully for source `anomali-cyber-watch`: 5 records were fetched,
created, and linked.

## IBM X-Force Public Publications

P9-07 implements two source-separated manual metadata catalogues:

- `ibm-x-force-public-research`: exact
  `https://www.ibm.com/think/x-force/<lower-kebab-slug>` articles, stored as
  `threat_report` items.
- `ibm-x-force-public-osint-advisories`: exact
  `https://exchange.xforce.ibmcloud.com/osint/guid%3A<32-lowercase-hex>` pages,
  stored as `security_advisory` items.

Each versioned UTF-8 JSON document names exactly one source and contains at most
100 exact seven-field metadata records in 1 MiB. The OSINT GUID separator and
hex case are canonicalized without following the URL. Only plain-text title,
summary, timestamps, authors, and categories are accepted.

No IBM or X-Force Exchange network request is made. Guest-readable pages do not
authorize scraping, bulk collection, API access, IBMid automation, indicators,
reputation data, collections, comments, structured threat objects, paid-tier
data, Threat Intelligence Index/report/PDF/attachment downloads, or STIX/TAXII.
The general X-Force Exchange platform is not marked implemented.

## Safety Notes

- Do not download malware samples.
- Do not collect from dark web or restricted sources.
- Do not include exploit instructions.
- Store source links for traceability.
- Respect API rate limits and terms of use.

## Current Status

NVD CVE ingestion, FIRST EPSS enrichment, CISA KEV enrichment, CERT-EU Security
Advisories RSS ingestion, Censys bounded live publication collection and local
fallback, Anomali bounded live collection and local fallback, IBM X-Force
local-file imports, and Google TI/Mandiant
shared-RSS publication ingestion are implemented as manual-only backend
workflows with sanitized audit records.
Other candidate sources still require explicit approval before ingestion is
implemented.

P9-02 adds a static backend source registry for developer-controlled metadata
only. The implemented entries for NVD, FIRST EPSS, CISA KEV, CERT-EU Security
Advisories, the two source-separated Censys publication families, the Anomali
Cyber Watch live-and-fallback source, both IBM X-Force manual catalogue
families, and the two Google TI/Mandiant public RSS publication families
preserve canonical slugs and manual ingestion behavior.

P9-03 adds a common publication pipeline for source adapters that already have
safe parsed publication candidates. CERT-EU RSS now uses this shared
persistence path. The pipeline does not approve or fetch new vendors; planned
source registry entries remain disabled until a later task explicitly approves
and implements an adapter. P9-05 enables only the Google TI and Mandiant public
RSS publication source definitions; Anomali Cyber Watch is enabled only for its
bounded manual live collector and reviewed local-file metadata fallback; P9-07
enables only the two exact IBM X-Force manual metadata families. Adapters cannot
supply arbitrary normalized source
definitions, and publication item type is derived from the registered content
family rather than adapter input.

Required publication identities are rejected when oversized. Safe source
metadata is shallow, defensively copied, bounded, and must not contain
credential, token, signed-URL alias, cookie, password, or request/response
header metadata. ASCII controls and Unicode surrogates are rejected from
persisted publication and payload text while normal human-readable Unicode is
retained.
Publication identity is isolated by trusted article type, currently
`security_advisory` and `threat_report`, and timestamps are normalized to UTC.
Publication URLs with raw control characters or exact normalized credential and
signed-URL query aliases are rejected before persistence.

Planned registry entries do not authorize collection, scraping, API use,
licensing, report mirroring, IOC extraction, or scheduler behavior. Host
allow-lists are controlled by application code and use strict exact-host
matching; there is no public source-management API.

## Proposed Source Expansion

The following vendors have been assessed for future source-expansion planning
only:

- Censys
- Anomali
- VirusTotal / Google Threat Intelligence
- Recorded Future
- Mandiant / Google Security
- IBM X-Force

Censys bounded manual live publication-metadata collection and its reviewed
local-file fallback, Anomali Cyber Watch bounded manual live collection and its
reviewed local fallback, the two IBM X-Force manual catalogues, and the bounded
Google TI/Mandiant public RSS adapter
are implemented from this proposed group. No live IBM collection or live
collection from other Anomali families is implemented. The assessment separates
public publication metadata, manual catalogue candidates, developer reference
material, standardized STIX/TAXII concepts, and authorized structured API
enrichment. Any future implementation
still requires source onboarding, security review, and current access/licensing
verification.

Planning references:

- [Source Assessment Matrix](source-assessment-matrix.md)
- [Source Integration Policy](source-integration-policy.md)

The proposed source expansion preserves the existing defensive scope:
manual-only ingestion unless scheduling is explicitly approved, no startup
ingestion, no background worker, no arbitrary URL fetching, no active scanning,
no target probing, no malware retrieval, no automatic file submission, no
exploit execution, and no raw upstream payload exposure through public APIs.
