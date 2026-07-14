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

## Safety Notes

- Do not download malware samples.
- Do not collect from dark web or restricted sources.
- Do not include exploit instructions.
- Store source links for traceability.
- Respect API rate limits and terms of use.

## Current Status

NVD CVE ingestion, FIRST EPSS enrichment, CISA KEV enrichment, and CERT-EU
Security Advisories RSS ingestion are implemented as manual-only backend
workflows with sanitized audit records. Other candidate sources still require
explicit approval before live ingestion is implemented.

P9-02 adds a static backend source registry for developer-controlled metadata
only. The implemented entries for NVD, FIRST EPSS, CISA KEV, and CERT-EU
Security Advisories preserve the existing canonical slugs and manual ingestion
behavior. The registry also records disabled planned metadata for selected
future public-source families, including Censys, Google Threat Intelligence,
Mandiant, Anomali, and IBM X-Force.

P9-03 adds a common publication pipeline for source adapters that already have
safe parsed publication candidates. CERT-EU RSS now uses this shared
persistence path. The pipeline does not approve or fetch new vendors; planned
source registry entries remain disabled until a later task explicitly approves
and implements an adapter. Adapters cannot supply arbitrary normalized source
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

They are not implemented sources in the current dashboard. The assessment
separates public publication metadata, manual catalogue candidates, developer
reference material, standardized STIX/TAXII concepts, and authorized structured
API enrichment. Any future implementation must complete source onboarding,
security review, and current access/licensing verification before live
collection or enrichment is added.

Planning references:

- [Source Assessment Matrix](source-assessment-matrix.md)
- [Source Integration Policy](source-integration-policy.md)

The proposed source expansion preserves the existing defensive scope:
manual-only ingestion unless scheduling is explicitly approved, no startup
ingestion, no background worker, no arbitrary URL fetching, no active scanning,
no target probing, no malware retrieval, no automatic file submission, no
exploit execution, and no raw upstream payload exposure through public APIs.
