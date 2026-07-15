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

Implemented P9-02 backend coverage adds focused offline tests for the static
source registry: unique canonical slugs, immutable definitions, unknown-source
failure behavior, enabled implemented-source listing, disabled planned-source
metadata, implemented NVD/FIRST EPSS/CISA KEV/CERT-EU definitions, strict
allowed-host validation, exact-host matching, suffix-confusion rejection,
duplicate definition rejection, invalid enabled/planned combinations, and
compatibility with existing collector/service source constants.

Implemented P9-03 backend coverage adds focused offline tests for the common
publication pipeline: publication source enforcement, non-publication source
rejection, exact URL host-boundary validation, tracking-parameter removal,
timezone-aware candidate validation, shallow safe metadata handling,
caller-owned persistence, removed normalized-persistence bypass coverage,
content-family item-type derivation, required identity length rejection,
raw-URL pre-parse length limits, bounded immutable payload snapshots,
sanitized database failures, batch result counters, `threat_report`
idempotency and update behavior, cross-type identity collision rejection,
aware timestamp type validation with UTC normalization, credential and
signed-query alias rejection, malformed text/payload/URL control and surrogate
rejection, sanitized UTF-8 failures, type-aware duplicate-identifier conflict
wording, CERT-EU RSS adapter integration, and regression coverage for the
existing manual RSS normalizer, service, and CLI behavior.

Implemented P9-04 backend coverage adds fully offline tests for strict Censys
local-file parsing, the versioned seven-field publication schema, duplicate JSON
keys, UTF-8 and 1 MiB file limits, nesting and 100-record bounds, exact source
slugs, 20-item author/category limits, plain-text metadata, timezone-aware
timestamps, exact `censys.com` host and source-family paths, URL credential,
port, fragment, query, control, Unicode, percent-escape, and path-parameter
rejection, tracking removal, stable source-separated URL-derived identifiers,
pre-traversal UNC/device-namespace rejection, registry-derived item types,
create, unchanged, update, and cross-type identity behavior, caller-owned
transactions, identical in-file duplicate audit accounting, conflicting
duplicate protection, sanitized CLI audits, mixed-record continuation, and
whole-run rollback on database failures. Regression coverage includes the
common publication pipeline, source registry, and existing RSS service and CLI.
All fixtures are synthetic; the tests perform no Censys or other network
request.

Implemented P9-05 backend coverage adds fully offline tests for the Google
TI/Mandiant shared RSS publication integration: registry collection-host versus
canonical-publication-host separation, exact FeedBurner collection host checks,
exact `cloud.google.com` publication host checks, mocked HTTP redirects and
response bounds, XML content-type validation, exact GTIG-versus-Mandiant author
routing, unknown/conflicting author rejection, FeedBurner original-link handling,
canonical path-family rejection, tracking removal, signed/credential query
rejection, missing/octet-stream content-type rejection, summary/description-only
storage, ignored feed content/media links, encoded or malformed markup handling,
required identity length rejection, Unicode/control handling, UTC timestamp
normalization, source-separated URL-derived identifiers, known-owner validation
failure attribution, unassigned shared-feed audit evidence, capped-feed
summaries, duplicate and update accounting through the common publication
pipeline, caller-owned final transaction behavior, rollback on database or
commit failure, session/client closure, and sanitized CLI/audit output. All
fixtures are synthetic; the tests perform no Google, FeedBurner, Mandiant,
VirusTotal, or other live network request.

Implemented P9-06 backend coverage adds fully offline tests for the strict
Anomali Cyber Watch local catalogue: exact versioned document and seven-field
record schemas, duplicate JSON keys and non-standard constants, UTF-8/BOM,
1 MiB, depth, and 100-record bounds, immutable parsed values, UNC/device/pipe,
symlink/reparse, regular-file, descriptor identity, growth, and closure checks,
exact Cyber Watch title and URL families, tracking and trailing-slash identity
normalization, plain-text and encoded-markup rejection, UTC timestamp ordering,
bounded stable author/category deduplication, source-separated SHA-256 identity,
registry-derived `threat_report` type, create/update/unchanged outcomes,
source-record-free identical/conflicting duplicate audits, mixed-record
continuation, zero-record success, sanitized failures, protected clocks,
caller-owned final commit, and whole-run rollback on database failures. All
fixtures are synthetic; no Anomali, ThreatStream, RSS, website, API, report,
PDF, media, download, or other network request is made.

Implemented P9-07 backend coverage adds fully offline tests for two strict IBM
X-Force local catalogues: exact document/source separation, immutable policies,
UTF-8/BOM, duplicate-key, constant, depth, 1 MiB, 100-record, UNC/device/pipe,
symlink/reparse, descriptor identity/growth/closure, and regular-file bounds;
exact IBM Think `/think/x-force/<slug>` research URLs; exact Exchange
`/osint/guid%3A<32-hex>` advisory URLs; tracking, slash, separator, host,
credential, and query rejection; plain-text/entity/Unicode/list/timestamp
validation; source-separated SHA-256 identity; pipeline-derived item types;
duplicate/conflict audit accounting; mixed/empty runs; nested transactions;
final commit, rollback, and close failure handling; and sanitized CLI output.
All fixtures are synthetic. No IBM website, X-Force Exchange, API, login,
guest-browser, report/PDF, indicator/reputation, STIX/TAXII, or external network
request occurs.

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
