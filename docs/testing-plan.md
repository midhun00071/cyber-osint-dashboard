# Testing Plan

## Purpose

This document tracks the planned testing approach for the Cyber OSINT Dashboard / Alpha Data project.

## Backend Testing

Planned backend tests:

- Health endpoint returns expected response.
- Dashboard summary endpoint returns expected fields.
- Latest threats endpoint returns records.
- Threat detail endpoint handles valid and invalid IDs.
- Search and filters validate input safely.
- Invalid query parameters return controlled errors.
- Database operations avoid duplicate records.

## Ingestion Testing

Planned ingestion tests:

- NVD collector handles successful response.
- CISA KEV collector handles successful response.
- RSS collector handles valid feed data.
- Collector failure does not crash the full ingestion job.
- HTTP timeouts are handled safely.
- Duplicate source records are not inserted repeatedly.

## Processing Testing

Planned processing tests:

- Severity mapping works correctly.
- CVE ID extraction works where available.
- UAE relevance classification uses deterministic direct-evidence rules,
  preserves analyst/source-declared ownership, and remains offline.
- Attack category classification works using basic rules.
- Normalized output contains required fields.

Implemented P4-01 backend coverage includes:

- Unicode-safe text normalization and bounded inputs;
- direct UAE country, acronym, and emirate matching;
- regional and sector false-positive controls;
- trusted source slug allow-list behavior;
- rule priority and deterministic output;
- dry-run and apply behavior for existing records;
- protected classification ownership;
- manual CLI validation and sanitized failure output;
- NVD and CERT-EU RSS creation/update integration;
- EPSS and CISA KEV preservation regressions through existing enrichment tests.

Implemented P4-02 backend coverage adds:

- exact fixed confidence mapping for approved UAE source, direct country phrase,
  standalone UAE acronym, direct emirate name, and no direct evidence;
- nullable `numeric(4,3)` confidence semantics, Decimal type, finite-value,
  range, and precision checks;
- confidence-only dry-run/apply backfill behavior through the existing bounded
  classification service and CLI counts;
- ownership preservation for manual, source-declared, and unknown methods;
- NVD and CERT-EU RSS creation/update confidence assignment;
- EPSS and CISA KEV confidence preservation;
- API regression coverage for JSON number and `null` confidence serialization.

Implemented P4-02 frontend validation uses type-check, lint, and production
build coverage for the centralized UAE confidence presentation helper and the
three existing UI surfaces that render it: latest article feed, article detail,
and vulnerability detail. The helper maps High to `0.900`-`1.000`, Medium to
`0.750`-`0.899`, Low to `0.000`-`0.749`, and displays no confidence label for
`null` or invalid non-finite/out-of-range presentation values.

Implemented P4-03 coverage adds focused API tests for intelligence-item
`geographic_scope` and `uae_relevance_status` filters, invalid enum rejection,
and combined search/severity/UAE filters. Frontend validation relies on the
existing TypeScript, lint, production build, and manual browser/network checks
because the broader automated frontend test suite remains deferred to P6-03.
The dashboard filters are backend-driven and reset offset pagination when a
search or filter changes.

## Frontend Testing

Planned frontend tests:

- Dashboard loads summary data.
- Threat feed displays records.
- Search input works.
- Filters update displayed results.
- Detail page opens correctly.
- Loading, empty, and error states display properly.
- External text does not execute as HTML or JavaScript.

## Manual Review Checklist

- No real secrets committed.
- .env files are ignored.
- Docker config renders successfully.
- Documentation is updated.
- Project can be explained clearly to a mentor.

## Current Status

Phase 1 setup only. Automated tests will be added after backend and frontend skeleton code exists.
