# Architecture Notes

## Purpose

This document explains the planned architecture for the Cyber OSINT Dashboard / Alpha Data project.

## High-Level Architecture

The application will follow a modular full-stack architecture:

Open-source cybersecurity sources
-> Backend ingestion layer
-> Processing and enrichment layer
-> PostgreSQL database
-> FastAPI backend API
-> Next.js frontend dashboard

## Planned Main Modules

1. Backend API and Database
2. Data Ingestion
3. Data Processing and Enrichment
4. Frontend Dashboard

## Current Implemented Data Flow

The implemented MVP data flow is intentionally bounded and defensive:

```text
approved public OSINT source
-> manual ingestion CLI
-> bounded collector
-> normalizer
-> persistence service
-> PostgreSQL
-> read-only FastAPI APIs
-> Next.js frontend
```

Current implemented source workflows are manual-only NVD CVE ingestion, FIRST
EPSS enrichment for existing CVEs, CISA KEV enrichment for existing CVEs,
CERT-EU Security Advisories RSS ingestion, and local-file Censys publication
metadata import, plus manual Google TI/Mandiant shared-RSS publication metadata
ingestion and local-file Anomali Cyber Watch publication metadata import. These
workflows are not connected to application startup, a
scheduler, background workers, public write endpoints, or frontend-triggered
ingestion.

P9-02 adds a static source registry inside the backend ingestion layer. It is a
developer-controlled code registry for safe non-secret source metadata,
canonical source slugs, implementation status, and exact host allow-lists. It
does not add source registration APIs, database-backed source onboarding,
runtime source mutation, startup ingestion, scheduling, or new external
requests. For implemented collectors, the registry is the source of truth for
the approved base URLs used by exported collector URL constants.

P9-03 adds a common publication pipeline below source-specific adapters. It
accepts already-fetched and already-parsed publication candidates only; it does
not perform HTTP requests, parse arbitrary upstream pages, schedule jobs, or
expose public write APIs. The pipeline enforces implemented/enabled registry
sources, publication-compatible content families, HTTPS-only exact host
allow-lists, sanitized shallow source metadata, timezone-aware timestamps, and
the existing article identity and provenance rules. Source-specific adapters
must pass `PublicationCandidate` values through common validation and cannot
provide arbitrary `SourceDefinition` objects or pre-normalized database-ready
source definitions.

Publication item type is derived from registry content family: security
advisory and public OSINT advisory sources store `security_advisory` items,
while threat research and exposure research sources store `threat_report`
items. The article identity helper accepts only these trusted publication
types and refuses cross-type linking, so an advisory cannot merge with a threat
report even when URL or title fingerprints collide. Required identity fields
are rejected if they exceed current schema limits. Safe source metadata is
shallow, defensively copied, byte/key/sequence bounded, and rejects sensitive
credential, signed-URL alias, or header-like keys. Persisted publication and
payload text rejects ASCII controls and Unicode surrogates before hashing and
persistence while retaining normal human-readable Unicode. Publication
timestamps are validated as aware datetimes and normalized to UTC. Publication
URLs reject raw controls before parsing and reject exact normalized credential,
token, password, signature, and cloud signed-URL query aliases while preserving
ordinary safe query parameters and stripping tracking parameters.

P9-04 adds an offline adapter above that pipeline for a strict, bounded,
operator-supplied structured JSON catalogue. The upstream Censys pages remain
unstructured public publication content. The selected registry source fixes the
item type and literal URL path family: Censys ARC `/blog/` pages become
`threat_report` items, while Rapid Response `/advisory/` pages become
`security_advisory` items. Percent-escaped paths and path parameters are not
accepted. The local-file boundary rejects UNC/network and Windows device
namespaces before traversal. The adapter derives source-family-separated
identifiers from canonical URL hashes and retains only plain-text
author/category metadata. It reads no website pages and uses no Censys API,
credentials, exposure data, host data, certificates, scan results, search, or
rescan operation.

P9-05 adds a manual shared-feed adapter for the fixed official Google Cloud
Threat Intelligence RSS feed. The registry now separates collection hosts from
canonical publication hosts: the collector may fetch only the exact FeedBurner
RSS host, while persisted publication URLs must use exact host
`cloud.google.com` and literal path prefix `/blog/topics/threat-intelligence/`.
Author ownership is source-specific and exact: `Google Threat Intelligence
Group` maps to `google-threat-intelligence-public-research`, and `Mandiant`
maps to `mandiant-public-threat-research`. The adapter emits only safe
`PublicationCandidate` metadata and leaves all persistence, duplicate handling,
item-type derivation, and database mutation to the common publication pipeline.
Stored summaries are taken only from feed `summary` or `description` fields;
feed `content`, article bodies, attachments, media links, reports, and PDFs are
ignored. Known-owner validation failures are attributed only to the resolved
source run. Entries that cannot be attributed to an approved author are kept out
of source-owned fetched/failed counters and recorded as sanitized shared-feed
error evidence on both logical runs. The adapter does not fetch article bodies,
scrape HTML, ingest developer documentation, use GTI/VirusTotal APIs, use
credentials, extract IOCs, download reports, submit or retrieve files/samples,
schedule work, run at startup, or expose public ingestion routes.

P9-06 adds a source-specific offline adapter for a strict local JSON catalogue
of the Anomali Cyber Watch series. The fixed registry source, exact
`www.anomali.com` host, literal `/blog/anomali-cyber-watch-` path family, exact
`Anomali Cyber Watch:` title family, and seven-field record schema establish
scope; author and category text do not establish ownership. The adapter emits
only plain-text `PublicationCandidate` metadata, and the common pipeline derives
the `threat_report` item type. The CLI owns one run, per-record nested
transactions, source-record-free duplicate/conflict audits, and one final
commit. It performs no Anomali request, scraping, RSS collection, article-body
fetch, IOC extraction, ThreatStream access, report/PDF/media download,
scheduling, startup execution, background work, or public API ingestion.

## UAE Relevance Classification

The backend includes an offline processing component for P4-01 UAE relevance
classification and P4-02 rule-strength confidence. It runs only when manually
invoked for existing records or when new NVD/CERT-EU RSS records are persisted
through the existing manual ingestion commands. It uses normalized title,
summary, controlled source identity, and existing safe geographic metadata. It
does not use raw payloads, network calls, machine learning, an LLM, schedulers,
startup hooks, or public mutation routes.

Automatic confidence is a fixed deterministic mapping from the winning
classification rule to a nullable `numeric(4,3)` value. It is not exploit
probability, threat attribution, attacker intent, targeting certainty, source
reliability in general, or business impact. Records with no direct UAE evidence
retain `null` confidence rather than a misleading zero score.

The frontend presents that canonical numeric confidence as a label for review
clarity: High for `0.900`-`1.000`, Medium for `0.750`-`0.899`, Low for
`0.000`-`0.749`, and no label for `null`. These labels are UI presentation
levels only. They are not severity, exploit likelihood, statistical
calibration, or attribution certainty, and P4-02 does not add confidence
filters.

P4-03 adds backend-driven frontend controls for geographic scope and UAE
relevance status on the dashboard latest-articles feed and vulnerability table.
Those controls send the existing read-only backend query parameters, combine
with search and pagination, and reset the current offset when changed. UAE
relevance status remains a classification field; it is not threat attribution,
attacker intent, or targeting certainty.

Manual and source-declared classifications are treated as analyst-owned and are
not overwritten by automatic rules, including their existing confidence values.

## Backend Responsibilities

- Provide API endpoints for dashboard data.
- Connect to PostgreSQL.
- Store normalized threat and vulnerability records.
- Run or trigger ingestion jobs.
- Validate query parameters.
- Handle errors safely.

## Frontend Responsibilities

- Display summary cards.
- Display threat and vulnerability records.
- Support search and filters.
- Display detail pages.
- Show loading, empty, and error states.
- Safely render external text.

## Database Responsibilities

- Store normalized intelligence records.
- Preserve source traceability.
- Support filtering and future historical analysis.

## Proposed Source-Expansion Architecture

The following roadmap covers remaining source-expansion architecture. It does
not approve live collection from Censys, Anomali, Recorded Future, IBM X-Force,
or structured VirusTotal / Google Threat Intelligence API families. The only
implemented Censys behavior is the P9-04 offline publication-metadata import,
the only implemented Google TI/Mandiant behavior is the P9-05 bounded manual
shared-RSS publication metadata adapter, and the only implemented Anomali
behavior is the P9-06 offline Cyber Watch metadata catalogue described above.

1. Source assessment
2. Source registry (P9-02 metadata foundation implemented)
3. Common publication pipeline (P9-03 foundation implemented)
4. Censys public research adapter (P9-04 implemented)
5. Google TI/Mandiant public publication RSS adapter (P9-05 implemented)
6. Anomali Cyber Watch manual publication catalogue (P9-06 implemented)
7. Indicator model
8. IOC extraction and relationships
9. Generic STIX/TAXII importer
10. Threat entity model
11. Censys exposure enrichment
12. Commercial API assessment
13. Threat-intelligence frontend views
14. Full integration/security review

Source expansion must follow [source-integration-policy.md](source-integration-policy.md)
and the vendor family decisions in
[source-assessment-matrix.md](source-assessment-matrix.md). Future structured
or commercial integrations require current access/licensing verification,
approved host allow-lists, bounded collection, normalized allow-listed fields,
sanitized audit records, and read-only public API exposure. Public publication
ingestion and structured API enrichment must remain separate architecture
families.

The Censys ARC and Rapid Response registry definitions are enabled only for the
P9-04 manual local-file importer. Google Threat Intelligence and Mandiant public
threat-research definitions are enabled only for the P9-05 manual shared RSS
publication adapter. The Anomali Cyber Watch definition is enabled only for the
P9-06 manual local-file catalogue; other Anomali families are not implemented.
Planned IBM X-Force entries remain disabled metadata only. No registry entry authorizes licensing, API access,
scraping, IOC extraction, or storage of upstream report bodies. Public
publication hosts and developer documentation hosts are separate source
families; documentation hosts are not automatically allowed for public
threat-research definitions. P9-05 is implemented as metadata-only RSS
publication ingestion, and P9-06 does not approve live Anomali collection.

## Current Status

Phase 1 setup only. Architecture will be refined as implementation progresses.
