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
