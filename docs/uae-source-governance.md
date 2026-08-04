# UAE Source Governance

## Frozen task and evidence

This document records the C04A / B5-01 governance decision at repository
checkpoint `37a8906e0f65f2391fbbbe42c2980bdbb6c945e3`. The evidence assessment date
is 4 August 2026. The reviewed evidence bundles are:

- `c04-source-discovery-20260804-104617.zip` — SHA-256
  `8993FBE95288EBF8019942CFCA8D474E72D05D9D61AF0B5C1229BE34EA7EAA9B`;
- `c04-source-discovery-pass2-20260804-105156.zip` — SHA-256
  `3FBCD687DA0D6B9A599C8C3E2C7E4E0A976550F6371370E2498876C31174B9F3`;
- `c04-source-discovery-pass3-20260804-105959.zip` — SHA-256
  `69CAE79E9D10E9CA54A2683ACF51E13CBAE8AB5FFC1FF5B59E21958BFD9C3BFB`.

These bundles are evidence references, not legal permission. They contain no
approval decision. APR-05 remains `Need Approval`, with its decision and
decision date both `Pending`.

## Decision model

The immutable backend policy separates three facts:

1. whether a URL matches an evidence-derived assessed host/path boundary;
2. whether that identity is an assessed listing request target or only a
   canonical metadata link; and
3. whether automated network access is approved.

A boundary match is not permission to issue a request. All five sources have
`automated_access_approved: false` and approval state `pending`. At the B5-01
checkpoint every definition was `planned` and `enabled: false`; B5-01 itself
implemented no collector or live request. B5-04 now marks only the two DESC
identities `implemented` while keeping them `enabled: false` and absent from
enabled-source, orchestration, default-handler, STIX, TAXII, schedule, and
deployment policies. No live request was made.

## Assessed source boundaries

### `ae-cert`

- Source identity: TDRA / aeCERT.
- Assessed host: `tdra.gov.ae`.
- Outcome: no stable advisory or security-publication listing was demonstrated.
- Assessed request paths: none.
- Base/listing URL: none claimed.
- Proposed cadence: unset until a stable source and explicit approval exist.
- Current state: planned, disabled, approval pending.

### `uae-cyber-security-council`

- Assessed host: `csc.gov.ae`.
- Assessed listing URLs:
  - `https://csc.gov.ae/en/stay-alert`
  - `https://csc.gov.ae/en/all-threats`
  - `https://csc.gov.ae/en/all-updates`
- Observed canonical metadata-link family:
  `https://csc.gov.ae/en/w/<safe-lowercase-publication-slug>`.
- Publication pages in that family are metadata identities only. They are not
  assessed or approved request targets in B5-01.
- Robots evidence disallowed document and platform-internal paths including
  `/documents/`, `/o/`, `/c/`, `/combo`, `/cdn-cgi/`, and group paths.
- Published property-rights language requires explicit permission before
  automated copying or republication.
- Proposed minimum cadence after approval: six hours.
- Current state: planned, disabled, approval required and pending. This does not
  complete B5-02.

### `uae-cyber-security-council-nibras`

- Assessed host: `csc.gov.ae`.
- Outcome: NibraS appeared only as navigation text. No stable listing, record
  structure, path, feed, or deterministic extraction was demonstrated.
- Assessed request paths and base/listing URL: none.
- Proposed cadence: unset.
- Current state: manual/disabled planning only. This does not complete B5-03.

### `desc-news`

- Assessed host: `www.desc.gov.ae`.
- Assessed listing URL:
  `https://www.desc.gov.ae/media-hub/news/`.
- A page-2 link was observed, but pagination was neither assessed as an exact
  path nor implemented.
- Listing metadata contained titles, dates, and canonical same-host links.
  Article-body requests are not approved.
- DESC terms require project-owner review before automated staging collection
  or republication.
- Proposed minimum cadence after approval: twelve hours.
- Current state: B5-04 implementation complete and fixture-tested; disabled,
  approval required and pending; no live request or coverage claim.

### `desc-published-research`

- Assessed host: `www.desc.gov.ae`.
- Assessed listing URL:
  `https://www.desc.gov.ae/research-innovation/published-research/`.
- The page contained research metadata and PDF or external-publication links.
- PDF, attachment, external-host, report-body, and binary requests are
  prohibited. Future work may store or validate safe metadata links only.
- DESC terms require project-owner review before automated staging collection
  or republication.
- Proposed minimum cadence after approval: six hours.
- Current state: B5-04 implementation complete and fixture-tested; disabled,
  approval required and pending. Allow-listed research landing links are stored
  as metadata identities only; direct PDF links are rejected and never
  retrieved. No live request or coverage claim is made.

## Permitted future metadata and prohibited data

B5-04 permits the DESC collectors to retain bounded plain-text title,
publication date/time when exactly present, safe listing summary, canonical
news URL or allow-listed research landing-link identity, source slug, source
attribution, and bounded safe categories. B5-02 and B5-03 remain deferred.
Link storage preserves the distinction between metadata identity and request
target.

The following remain prohibited: article or report bodies, raw HTML or vendor
payloads, PDFs, attachments, downloads, media, binaries, external-publication
retrieval, IOCs or CVE extraction, credentials, tokens, cookies, headers,
arbitrary URLs, callbacks, APIs, forms, search paths, active probing, scanning,
malware retrieval, and any disallowed robots path. Queries, fragments,
credentials, percent-encoded identities, traversal, ambiguous segments,
suffix-confusion hosts, IP hosts, and non-HTTPS URLs fail closed. All explicit
ports fail closed, including the default HTTPS port `:443`; only the exact
canonical hostname with no explicit port is an assessed URL identity. URL
assessment does not grant automated collection approval: all UAE sources remain
disabled and approval-pending, and B5-01 activates no live UAE collection.

## Approval and review requirements

The decision owner is the mentor or project owner, with organisational legal or
policy review where required. Approval must be source-specific and record the
exact HTTPS host, request paths, cadence, allow-listed fields, robots and terms
basis, retention and republication limits, redirect policy, operational owner,
decision date, and review/expiry date. A future terms, robots, path, ownership,
or page-structure change requires reassessment before activation.

## Truthful limitations

- Evidence-derived paths can become stale and do not prove ongoing availability.
- No robots or terms finding is legal advice or project-specific permission.
- No source has an approved automation path today.
- No live source request was made by C04A / B5-01.
- No live data coverage or freshness, and no B5-02 or B5-03 completion, may be
  claimed. B5-04 readiness is limited to implemented, fixture-tested,
  operationally disabled metadata collection.
