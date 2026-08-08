# C08 Analyst and UAE Release Experience

## Frozen acceptance contract

### Checkpoint and boundaries

C08 starts from `cfef7477c26f568e738a966c26c03100e640e53e` on
`dev`, with refreshed `origin/dev` at the same commit, divergence `0 0`, and a
clean worktree. The preserved database revision is `c07a01b02c03`.

The bounded bundle is B4-04, B5-05, B5-06, B8-01, B8-04, B8-05, and B8-07.
It reuses C03 threat knowledge, C04 UAE source governance, C05 disabled public
source policies, C06 backend authentication/RBAC, and C07 authenticated source
operations. It does not implement B8-06 reports, health, audit, or methodology
pages; activate a source, handler, schedule, deployment, or credential; make a
live external request; add a separate Threat Entities page; or reopen
C08-PRE-02.

### Task map

| Task | Frozen requirement | Current baseline | Required C08 closure |
| --- | --- | --- | --- |
| B4-04 | Expose bounded read-only threat metadata through Threat Feed and provenance details without a separate sidebar page. | Source-scoped threat entities, aliases, relationships, and provenance exist, but no authorized API or UI exists. | Content-read authorization, strict filters, bounded pagination, safe fields, source provenance, XSS-safe rendering, and integrated Threat Feed metadata. |
| B5-05 | Classify direct UAE evidence, potential UAE relevance, global relevance, or no demonstrated relevance and add controlled sector, emirate, authority, and language tags with evidence/confidence. Keyword-only evidence must never assert UAE attribution. | A legacy offline classifier marks country/acronym/emirate keywords as confirmed and has no structured classification tags. | Conservative deterministic rules, controlled namespaced tags using existing tag persistence, protected manual/source decisions, bounded transactional application, false-positive/conflict/provenance tests, and updated documentation. |
| B5-06 | Integrate UAE evidence into freshness, operations, and intelligence views. | C07 exposes truthful source state and run evidence; no complete UAE analyst view exists. | UAE source state/freshness, authority evidence, existing related CVEs, sectors, languages, collection/publication times, and safe source links, with disabled/deferred states unchanged. |
| B8-01 | Remove Coming Soon, dead controls, production preview data, hard-coded dashboard state, and unsupported visible claims. | The Overview still imports preview status/count data and the header contains a nonfunctional search placeholder. | Overview uses only API-backed or honest unavailable/empty state, C08 routes are functional, navigation has no placeholder controls, and unfinished B8-06 pages remain absent rather than advertised. |
| B8-04 | Complete the UAE Intelligence page. | No route exists. | Authenticated loading, success, empty, error, pagination/filter, responsive, safe-link, false-positive-label, accessibility, source-state, and provenance behavior. |
| B8-05 | Complete Threat Feed, Vulnerabilities, IOC Search, and provenance drill-down. | Dashboard embeds partial article/CVE components and detail pages; no canonical top-level routes, IOC search, threat metadata read model, or complete provenance contract exists. | Four functional analyst routes, normalized data and enrichment evidence, bounded filters/pages, safe canonical URLs, content hashes and import-run evidence where present, no raw/internal IDs, malicious-output tests, and backend permission enforcement. |
| B8-07 | Harden exposed API schemas, validation, pagination, rate limiting, content types, inventory, and exceptional states. | Existing APIs authenticate and validate common filters, but the intelligence list loads all active rows before filtering and the C08 read models do not exist. | Strict allow-listed response models, unknown/repeated query rejection, bounded SQL filtering/count/page queries, per-session bounded read throttling, sanitized 404/422/429/500 behavior, direct-request authorization negatives, OpenAPI inventory tests, and no mass-assignment surface. |

### Security and integrity freeze

- Backend permissions are authoritative: content views require `content.read`;
  IOC analysis requires `analysis.use`; frontend visibility is only a usability
  projection.
- Every response is an explicit allow-list and excludes database IDs, raw
  payloads, unsafe errors, SQL, secrets, credentials, cookies, headers, and
  arbitrary configuration.
- Nested analyst collections are SQL-bounded and deterministic: 20 threat
  aliases, 100 threat relationships, 50 indicator provenance records, 100
  indicator publications, 25 item source records, 20 import runs per source,
  16 controlled tags, and 100 item-indicator relationships. Indicator list
  counts use SQL aggregates rather than loading those relationships.
- Search, enum filters, UUIDs, limits, offsets, and repeated/unknown query names
  are bounded and fail closed. ORM expressions remain parameterized.
- React text rendering and `SafeExternalLink` remain the only rendering/link
  paths for external metadata. No untrusted HTML is rendered.
- Classification reads normalized local metadata only. A text keyword may
  create a cautiously labelled potential-relevance signal, never direct UAE
  attribution. Direct classification requires controlled UAE authority-source
  evidence or a protected reviewed decision.
- Classification and query failures cannot be reported as success. Existing
  protected manual/source-declared classifications are not overwritten.
- `DEFAULT_SOURCE_HANDLERS_COUNT` stays `0`; the four C05 source integrations
  and all UAE sources stay disabled/unscheduled. No network request is part of
  validation.

### Database and migration decision

C08 adds no table or column. Controlled UAE classification tags use the
existing `tags` and `intelligence_item_tags` schema with explicit namespaces:
`uae-sector-*` (`sector`), `uae-emirate-*` (`region`),
`uae-authority-*` (`general`), and `language-*` (`theme`). Existing confidence,
assignment provenance, source records, content hashes, and ingestion-run
records provide the persistence and provenance boundary. Therefore committed
migrations remain unchanged and `c07a01b02c03` remains the single expected
head.

### Required validation and definition of done

Focused backend tests must cover classifier false positives/conflicts/tags,
threat/indicator/UAE/provenance API fields and permissions, invalid inputs,
pagination, rate limits, failures, and raw/internal-field exclusion. Existing
article, intelligence, C06 authorization, C07 operations, source-registry, and
orchestration safety tests must remain green. Frontend tests must cover all new
page states, permission projection, safe links, pagination, and removal of
preview/dead controls. SQLAlchemy mapper validation, Alembic heads/history,
frontend Vitest/type-check/build, `git diff --check`, appropriate backend
regression, and `run.cmd test` are required. Complete-file review of every
meaningful changed file is required before C08 can be called ready.

Accepted limitations are that source-state freshness can only reflect persisted
evidence; disabled or never-run UAE sources truthfully show no live coverage;
text-only UAE mentions remain potential rather than attribution; no manual
browser/UAT, staging activation, deployment, real account provisioning, or live
source validation occurs in this implementation run; and B8-06 remains a later
bundle with no visible placeholder surface.
