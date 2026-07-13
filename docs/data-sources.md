# Data Sources

## Purpose

This document tracks approved and candidate open-source cybersecurity data sources for the dashboard.

## Source Selection Rules

All sources must be:

- Publicly available.
- Authorized for automated access.
- Relevant to defensive cybersecurity awareness.
- Documented with source name, access method, and original URL.
- Used without scraping restricted or unsafe content.

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
