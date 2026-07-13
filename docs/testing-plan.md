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
