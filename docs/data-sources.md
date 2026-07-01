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

- Official CSV or JSON catalog

### Cybersecurity RSS or News Source

Purpose:

- Recent cyberattack reports
- Malware campaigns
- Ransomware news
- Phishing and breach updates

Access method:

- Approved RSS feed or public API

## UAE-Relevant Sources

UAE-focused sources should only be automated if an approved feed, API, or authorized access method exists.

## Safety Notes

- Do not download malware samples.
- Do not collect from dark web or restricted sources.
- Do not include exploit instructions.
- Store source links for traceability.
- Respect API rate limits and terms of use.

## Current Status

Phase 1 setup only. Final source approval will happen before live ingestion is implemented.
