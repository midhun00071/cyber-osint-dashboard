# Source Integration Policy

## Purpose

This policy defines approved integration classes, onboarding requirements, and excluded capabilities for future cybersecurity intelligence source expansion. It applies to proposed vendors such as Censys, Anomali, VirusTotal / Google Threat Intelligence, Recorded Future, Mandiant / Google Security, and IBM X-Force.

This is planning documentation only. It does not approve new live ingestion, credentials, scheduler behavior, background workers, API routes, frontend behavior, packages, migrations, or database schema changes.

## Approved Integration Classes

### A. Public Publication Ingestion

Examples:

- research posts;
- advisories;
- threat bulletins;
- public report metadata.

Allowed use:

- ingest safe publication metadata from fixed, developer-controlled, approved sources;
- store normalized title, summary, source URL, publication timestamps, source identity, and safe tags;
- keep shared feed collection hosts separate from canonical publication hosts
  when a provider publishes through a feed service;
- cite source attribution clearly;
- use manual-only ingestion unless scheduling is explicitly approved later.

Restrictions:

- do not scrape restricted pages;
- do not infer publication ownership from titles, article text, product names,
  categories, or report links when the approved source requires exact feed
  author ownership;
- do not mirror full reports or PDFs unless permission is explicitly verified;
- do not assume indicator reuse or redistribution rights;
- do not expose raw upstream payloads through public APIs.

### B. Authorized Structured API Enrichment

Examples:

- Censys exposure context;
- Google Threat Intelligence relationships;
- licensed commercial risk intelligence.

Allowed use:

- enrich existing stored indicators, CVEs, domains, IPs, hashes, or approved assets with bounded, allow-listed fields;
- use official APIs only with current access, licensing, terms, and rate-limit verification;
- keep credentials in environment-based secret handling only;
- record sanitized audit outcomes.

Restrictions:

- no arbitrary target probing;
- no active scanning;
- no rescan triggers;
- no arbitrary URL ingestion;
- no public API endpoint that triggers enrichment;
- no raw licensed payload exposure through public APIs.

### C. Standardized Threat Intelligence Ingestion

Examples:

- STIX;
- TAXII.

Allowed use:

- prefer a generic STIX/TAXII importer over vendor-specific STIX parsers;
- ingest only approved servers or bundles with verified authorization;
- preserve object markings, source attribution, relationship semantics, and confidence limitations;
- normalize to allow-listed project entities and fields.

Restrictions:

- do not ignore TLP, markings, or redistribution limits;
- do not ingest arbitrary user-supplied bundles without a separate validation and approval model;
- do not add unsupported dependencies such as STAXX.

Current implementation boundary:

- the first internal P9-10 unit accepts only reviewed local STIX 2.1 bundles
  and offline TAXII 2.1 envelope fixtures;
- the immutable production approved-policy registry is empty, so no live feed
  or production source is enabled;
- bounded JSON validation precedes the official STIX parser, custom types and
  properties are disabled, and an unsupported object rejects the whole input;
- object markings and same-source relationships must resolve and remain within
  policy; granular markings are rejected because their selectors are not
  preserved by the safe mapper;
- exact per-type and nested key allow-lists govern safe source-record payloads;
  arbitrary extra keys fail closed, external reference values are identifier
  tokens rather than URLs, and descriptions are omitted during P9-10;
- approved observables reuse the P9-08 Indicator and IndicatorProvenance
  boundary;
- the importer owns neither commit nor rollback and adds no CLI, API, frontend,
  scheduler, startup task, or automatic processing;
- no network request, DNS, socket, server discovery, arbitrary endpoint,
  malware retrieval, scan, probe, STAXX, or `taxii2-client` exists in this unit;
- the fixed-policy TAXII 2.1 collection client requires a separate second
  P9-10 implementation unit and source onboarding approval;
- bundle IDs, when present, are canonical lowercase RFC 4122 STIX IDs; policy
  bases use canonical HTTPS hosts and unreserved path segments without percent
  escapes, traversal, empty segments, credentials, queries, or fragments;
- staged observable identity fingerprints prevent a newer version from
  changing exact provenance under the one-record-per-STIX-ID design;
- created time and creator identity remain stable, revocation is terminal, and
  revoked Indicator versions suppress local Indicator/provenance automation;
- caller-provided existing-object mappings are revalidated rather than trusted;
  existing markings and relationship endpoints require exact canonical safe
  STIX identity and use-specific fields;
- same-source database records satisfy external references only when processed,
  present, error-free, safely staged, bound to the canonical policy URL and URL
  hash, and verified against their canonical content hash;
- the current object's existing SourceRecord is revalidated to the same
  complete schema and hash boundary before version comparison; failed, missing,
  malformed, hash-inconsistent, and extra-field records are neither trusted nor
  automatically repaired;
- public validation dataclasses are independently canonicalized before any
  SourceRecord lookup; safe payloads are deep-copied and frozen, while content
  hashes, observables, object counts, relationship/marking counts, ordering,
  and same-document references are reconstructed or verified;
- P9-10 SourceRecords remain staging-only with no IntelligenceItem link and no
  primary-reference role; stored STIX version timestamps and timezone-aware
  collection/seen/processing audit timestamps must remain internally
  consistent, and malformed records fail closed without repair;
- policy hosts must already be canonical lowercase ASCII under UTS #46, STD3,
  non-transitional IDNA processing; validation performs no DNS resolution.

See [Offline STIX/TAXII Import](stix-taxii-import.md) for supported objects,
limits, marking behavior, version rules, and conservative exclusions. This
offline foundation does not complete P9-10 or implement P9-11 entities.

### D. Manual Catalogue Metadata

Examples:

- reports or resources where automatic ingestion is not appropriate;
- gated reports where only metadata should be tracked;
- strategic annual reports used for analyst context.

Allowed use:

- manually record title, vendor, publication date when known, canonical URL, content family, and short analyst-safe summary;
- avoid storing full report content unless licensing is verified.

Restrictions:

- do not imply the dashboard has ingested or licensed full structured data;
- do not store credentials, registration artifacts, or private download URLs.
- source-specific implemented catalogues must use fixed developer-controlled
  source, host, path, title, schema, size, record-count, and plain-text bounds;
- a manual catalogue approval does not authorize website requests, scraping,
  RSS discovery, article-body storage, IOC extraction, report/PDF download, or
  commercial API/feed access.
- the implemented IBM X-Force manual catalogues authorize only operator-provided
  metadata for exact public research and OSINT advisory URL families; they do
  not authorize IBMid or guest automation, Exchange APIs, indicators,
  reputation data, paid tiers, report downloads, or STIX/TAXII.

### E. Developer Reference Only

Examples:

- API documentation;
- protocol glossaries;
- integration guides;
- case studies, webinars, and product pages that help design future integrations but are not intelligence sources.

Allowed use:

- use for architecture and implementation planning;
- cite as reference material in planning tasks.

Restrictions:

- do not treat documentation as a live intelligence feed;
- do not infer entitlement to APIs, endpoints, data, or commercial features.

### F. Excluded Capabilities

The following are excluded from this project:

- malware binary retrieval;
- malware detonation;
- automatic VirusTotal file submission;
- automatic file uploading to external analysis services;
- active Internet scanning;
- arbitrary target probing;
- Censys rescan triggering;
- Recorded Future scraping;
- arbitrary URL ingestion;
- unsupported STAXX dependency;
- exploit execution;
- phishing, credential theft, persistence, stealth, evasion, bypass, or offensive tooling;
- dark web collection;
- public API routes that trigger ingestion, enrichment, scanning, submissions, or external network calls.

Any future proposal to change the project's safe public-source scope would
require a separate formally approved requirements decision. This
source-expansion workstream does not include Tor, onion sources, dark-web
marketplaces, dark-web forums, dark-web credentials, or dark-web collectors.

## Source Onboarding Requirements

Every future source must have a source review before implementation. At minimum, the review must document:

- fixed developer-controlled source definition;
- approved host allow-list;
- HTTPS-only access;
- redirect validation;
- bounded response size;
- bounded record count;
- network timeouts;
- content-type validation where appropriate;
- safe user agent and request headers that do not expose secrets;
- normalized allow-listed fields;
- deterministic identity and deduplication rules;
- transaction safety;
- sanitized errors;
- audit records;
- manual-only ingestion unless scheduling is explicitly approved;
- no application startup ingestion;
- no background worker unless explicitly approved;
- no raw upstream payload exposure through public APIs;
- no secrets, tokens, headers, database URLs, stack traces, or environment values in logs, API responses, reports, or frontend UI.

## Access and Licensing Requirements

Before any gated or commercial source is implemented, the project must verify:

- current account entitlement;
- API documentation access;
- authentication method;
- rate limits;
- permitted automation;
- permitted storage;
- permitted redistribution and display;
- restrictions on indicators, reputation scores, comments, reports, PDFs, and derived fields;
- data retention requirements;
- attribution requirements.

If any of these are unknown, the implementation decision must state:

```text
requires current access/licensing verification
```

## Safe Architecture Fit

Future integrations should fit the existing project pattern:

```text
approved public or authorized source
-> manual ingestion or authorized enrichment command
-> bounded collector/client
-> normalizer
-> persistence service
-> PostgreSQL
-> read-only FastAPI response fields
-> safely rendered Next.js frontend
```

This policy preserves the current defensive OSINT scope and avoids turning the dashboard into an offensive tool, scanning system, malware analysis sandbox, or unrestricted enrichment proxy.
