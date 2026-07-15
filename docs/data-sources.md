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

P9-04 implements only an offline, operator-triggered import of a strict local
structured JSON catalogue. The upstream source pages are unstructured public
publication content; the JSON `source_type` describes only the operator-supplied
catalogue format. The application does not visit, crawl, or scrape Censys pages
and does not use a Censys API, account, or API key. Publication fetching and
metadata preparation are external/manual. Exposure records, hosts,
certificates, DNS data, scan results, search results, and rescan capability are
not imported.

Input is strict UTF-8 JSON limited to 1 MiB, 100 publications, 20 authors per
publication, and 20 categories per publication. Only the fixed schema fields
and plain-text metadata are accepted. The file must be reached through an
ordinary local path without symlink or reparse-point components; UNC/network
and Windows device-namespace forms are rejected before traversal. URLs must use
exact host `censys.com`, the selected source's literal path family without
percent escapes or path parameters, and no residual non-tracking query string.
All accepted records pass through the P9-03 common publication pipeline and
produce sanitized ingestion audit records.

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

Approved manual catalogue family:

- `anomali-cyber-watch`: official Cyber Watch publication pages on exact host
  `www.anomali.com`, stored as `threat_report` items.

P9-06 implements only an operator-triggered local JSON metadata catalogue. The
file is strict UTF-8 JSON limited to 1 MiB and 100 seven-field publications.
Every title must start exactly with `Anomali Cyber Watch:` and contain
publication-specific text. Every canonical URL must use literal path family
`/blog/anomali-cyber-watch-` with a non-empty article slug. Tracking parameters
may be removed; other query strings, encoded paths, credentials, fragments,
path parameters, alternate hosts, and general blog paths are rejected.

Only operator-prepared plain-text title, summary, timestamps, authors, and
categories are accepted. Article bodies and embedded third-party stories are
not fetched or stored. IOCs, observables, hashes, domains, IPs, external story
links, ThreatStream objects, reports, PDFs, media, attachments, samples, and
downloads are not extracted or ingested. The command performs no Anomali
network request and has no RSS, scraper, API, credentials, scheduler, startup
hook, background worker, or public ingestion endpoint. General Anomali public
research, ThreatStream, commercial feeds/APIs, STIX/TAXII, and STAXX remain
unimplemented or excluded according to their recorded decisions.

## Safety Notes

- Do not download malware samples.
- Do not collect from dark web or restricted sources.
- Do not include exploit instructions.
- Store source links for traceability.
- Respect API rate limits and terms of use.

## Current Status

NVD CVE ingestion, FIRST EPSS enrichment, CISA KEV enrichment, CERT-EU Security
Advisories RSS ingestion, Censys and Anomali local-file publication metadata
imports, and Google TI/Mandiant shared-RSS publication metadata ingestion are
implemented as
manual-only backend workflows with sanitized audit records.
Other candidate sources still require explicit approval before ingestion is
implemented.

P9-02 adds a static backend source registry for developer-controlled metadata
only. The implemented entries for NVD, FIRST EPSS, CISA KEV, CERT-EU Security
Advisories, the two Censys manual-catalogue families, the Anomali Cyber Watch
manual catalogue, and the two Google TI/Mandiant public RSS publication
families preserve canonical slugs and manual ingestion behavior. The registry
also records disabled planned metadata for IBM X-Force public-source families.

P9-03 adds a common publication pipeline for source adapters that already have
safe parsed publication candidates. CERT-EU RSS now uses this shared
persistence path. The pipeline does not approve or fetch new vendors; planned
source registry entries remain disabled until a later task explicitly approves
and implements an adapter. P9-05 enables only the Google TI and Mandiant public
RSS publication source definitions; P9-06 enables only Anomali Cyber Watch for
manual local-file metadata. Adapters cannot supply arbitrary normalized source
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

Only Censys's and Anomali Cyber Watch's bounded manual publication-metadata
catalogues and the bounded Google TI/Mandiant public RSS publication-metadata
adapter are implemented from this proposed group; no live Censys or Anomali
collection exists. The assessment separates
public publication metadata, manual catalogue candidates, developer reference
material, standardized STIX/TAXII concepts, and authorized structured API
enrichment. Any future implementation must complete source onboarding,
security review, and current access/licensing verification before live
collection or enrichment is added beyond the approved P9-05 shared RSS feed and
P9-06 offline Cyber Watch catalogue.

Planning references:

- [Source Assessment Matrix](source-assessment-matrix.md)
- [Source Integration Policy](source-integration-policy.md)

The proposed source expansion preserves the existing defensive scope:
manual-only ingestion unless scheduling is explicitly approved, no startup
ingestion, no background worker, no arbitrary URL fetching, no active scanning,
no target probing, no malware retrieval, no automatic file submission, no
exploit execution, and no raw upstream payload exposure through public APIs.
