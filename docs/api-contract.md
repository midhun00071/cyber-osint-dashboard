# API Contract

Project: Alpha Data / Cyber OSINT Dashboard<br>
Task: P1-03 — Define the API contract<br>
Status: Approved design<br>
API framework: FastAPI<br>
Domain API version: v1<br>
Scope: Design documentation only; no routes or Pydantic schemas implemented<br>
Related design: `docs/database-schema-design.md`

Implementation note as of July 7, 2026: the first stored-intelligence read API
now exists at `GET /api/v1/intelligence/items` and
`GET /api/v1/intelligence/items/{public_id}`. This document remains the broader
design target; the implemented MVP currently exposes a smaller safe subset of
the full planned contract and does not return raw source payloads or trigger
ingestion.

Implementation note as of July 8, 2026: the implemented read API also returns
safe latest EPSS fields when manual FIRST EPSS enrichment has populated the
stored vulnerability. `epss_score` and `epss_percentile` come from the
vulnerability extension, while `epss_score_date` comes from the non-primary
`first-epss` source record. Primary source display fields continue to use the
NVD source record.

Implementation note as of July 8, 2026: P2-09 adds the implemented article
list endpoint at `GET /api/v1/articles`. It returns active article-like
intelligence items only and does not expose raw payloads, hashes, source
external IDs, ingestion audit fields, or internal database IDs.

Implementation note as of July 8, 2026: P2-11 adds strict validation for
implemented article and intelligence list filters. Invalid individual query
values return `422`; invalid combinations of otherwise valid filters return
`400` with sanitized messages.

Implementation note as of July 10, 2026: P2-10 adds the implemented dashboard
summary endpoint at `GET /api/v1/dashboard/summary`. It returns database-backed
counts, latest article previews, and latest ingestion-run status without
triggering ingestion or exposing raw payloads, hashes, checkpoints, internal
database IDs, headers, secrets, stack traces, database URLs, or environment
values.

## 1. Executive Recommendation

The approved API contract uses `/api/v1` for domain resources. The existing `GET /api/health` endpoint remains unversioned as the stable operational health check, and future safe version metadata is deferred to `GET /api/version` under P1-13.

`intelligence-items` is the primary API resource. Vulnerability data appears as a nullable nested extension on intelligence-item responses. Separate `/vulnerabilities` list and detail endpoints are deferred to avoid duplicate routing and response logic in the MVP.

The unauthenticated MVP API is read-only and does not expose ingestion-run details, ingestion errors, retry actions, or manual ingestion controls. Operational ingestion details require future authentication and authorization.

## 2. Repository Context

The existing backend routes are:

- `GET /`
- `GET /api/health`

No P1-03 route implementations or Pydantic schemas exist yet. Public UUIDs are used for items and sources. Tag slugs are used as stable public tag identifiers. Internal database IDs must not be exposed through the API.

No runtime application checks were performed for this documentation task.

## 3. API Design Principles

- Expose defensive public intelligence only.
- Use public UUIDs instead of internal database IDs.
- Use strict allow-listed filters and sort expressions.
- Use bounded pagination and bounded nested collections.
- Use safe response envelopes.
- Use safe structured errors.
- Preserve source attribution.
- Clearly distinguish unknown states from confirmed negative states.
- Do not expose raw source payloads.
- Do not expose secrets, tokens, cookies, headers, stack traces, SQL errors, file paths, or sensitive configuration.
- Do not expose public ingestion administration.
- Treat all external source text as untrusted.

## 4. Versioning and Base Paths

Domain resources use:

```text
/api/v1
```

The existing stable operational health endpoint remains:

```text
GET /api/health
```

Safe version metadata is deferred to P1-13:

```text
GET /api/version
```

The approved MVP does not add `/api/v1/health`.

## 5. Final MVP Endpoint Inventory

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/dashboard/summary` | Dashboard KPI and freshness summary |
| GET | `/api/v1/intelligence-items` | Searchable and filterable intelligence-item list |
| GET | `/api/v1/intelligence-items/{public_id}` | Intelligence-item detail |
| GET | `/api/v1/sources` | Public source registry summary |
| GET | `/api/v1/tags` | Tag discovery for filters |
| Existing | `/api/health` | Operational health |
| Future P1-13 | `/api/version` | Safe version metadata |

Deferred protected endpoints:

- ingestion-run list and detail
- ingestion-run records
- ingestion errors
- retry or manual ingestion triggers

## 6. Endpoint-by-Endpoint Contract

| Method | Path | Purpose | Authentication assumption | Parameters | Success model | Errors | Security considerations |
|---|---|---|---|---|---|---|---|
| GET | `/api/v1/dashboard/summary` | Dashboard KPI and ingestion freshness summary. | Public read-only MVP. | `window_days`. | `ApiResponse[DashboardSummary]` | `400`, `422`, `429`, `500`, `503` | No raw payloads, checkpoints, operator errors, or internal IDs. |
| GET | `/api/v1/intelligence-items` | Searchable and filterable intelligence-item list. | Public read-only MVP. | Filters, pagination, sort. | `PaginatedResponse[IntelligenceItemListItem]` | `400`, `422`, `429`, `500`, `503` | Compact rows only; no full source or identifier arrays. |
| GET | `/api/v1/intelligence-items/{public_id}` | Detail for one intelligence item. | Public read-only MVP. | `public_id` UUID path parameter. | `ApiResponse[IntelligenceItemDetail]` | `404`, `422`, `429`, `500`, `503` | Safe source references only; no raw payloads or operator-only fields. |
| GET | `/api/v1/sources` | Public source registry summary. | Public read-only MVP. | `source_type`, `page`, `page_size`. | `PaginatedResponse[SourceSummary]` | `400`, `422`, `429`, `500`, `503` | Does not expose `is_enabled`, checkpoints, rate-limit notes, or fetch configuration. |
| GET | `/api/v1/tags` | Tag discovery for filters. | Public read-only MVP. | `tag_type`, `q`, `page`, `page_size`. | `PaginatedResponse[TagSummary]` | `400`, `422`, `429`, `500`, `503` | `q` searches tag slug and display name only. |

The MVP public API is read-only.

Implemented P2-09/P2-11 article list endpoint:

| Method | Path | Purpose | Parameters | Success model | Security considerations |
|---|---|---|---|---|---|
| GET | `/api/v1/articles` | Paginated active cybersecurity articles and advisories. | `limit`, `offset`, `q`, `category`, `source_slug`, `tag_slug`, `published_from`, `published_to`, `geographic_scope`, `uae_relevance_status`. | Offset envelope with article rows. | No raw payloads, hashes, identifiers, ingestion side effects, or internal IDs. |

`GET /api/v1/articles` includes these active `item_type` values:

- `security_advisory`
- `cyber_news`
- `threat_report`
- `uae_official_alert`
- `other_defensive_intel`

It excludes `vulnerability` and excludes inactive `merged`, `superseded`, and
`archived` records. Pagination is offset-based with `limit`
default `25`, minimum `1`, maximum `100`, and `offset` default `0`, minimum
`0`. The response envelope is:

```json
{
  "items": [],
  "total": 0,
  "limit": 25,
  "offset": 0
}
```

Article row fields are:

- `public_id`
- `title`
- `summary`
- `category`
- `source_slug`
- `source_name`
- `source_url`
- `published_at`
- `modified_at`
- `geographic_scope`
- `uae_relevance_status`
- `uae_relevance_confidence`
- `last_seen_at`

The optional `q` parameter trims surrounding whitespace, supports 1 to 120
characters, and performs case-insensitive substring search over only
`canonical_title` and `summary`. When `q` is supplied, the trimmed value must
contain at least one non-whitespace character; whitespace-only searches return
`422`. SQL wildcard characters such as `%` and `_` are escaped and treated as
literal text. Raw payloads, URLs, source external IDs, hashes, identifiers,
errors, headers, and configuration are not searched.

Article filters are optional single-value filters and combine with logical
`AND`. Each supplied text filter trims surrounding whitespace, normalizes to
lowercase where applicable, and rejects whitespace-only input with `422`.

| Parameter | Rules |
|---|---|
| `category` | Exact `item_type` match. Allowed values are the five article types above. Maximum 40 characters. `vulnerability` is rejected. |
| `source_slug` | Exact canonical slug match against any linked provenance source record, including non-primary records. Maximum 80 characters. Slugs allow lowercase letters, digits, and single hyphens between components only. |
| `tag_slug` | Exact canonical tag slug match against assigned tags. Maximum 100 characters. Uses the same slug format as `source_slug`. Tag assignment metadata and IDs are not returned. |
| `published_from` | ISO date `YYYY-MM-DD`; inclusive lower boundary on `source_published_at`, interpreted as the start of that UTC day. Null publication dates do not match when supplied. |
| `published_to` | ISO date `YYYY-MM-DD`; inclusive upper boundary on `source_published_at`, implemented as `<` the start of the following UTC day. Maximum supported value is `9999-12-30`. Null publication dates do not match when supplied. |
| `geographic_scope` | Exact match. Allowed values: `global`, `regional`, `uae`, `unknown`. `unknown` is not treated as `global`. |
| `uae_relevance_status` | Exact match. Allowed values: `confirmed`, `probable`, `possible`, `not_relevant`, `unknown`. Statuses are not collapsed into a boolean. |

Either publication date may be supplied alone. When both are supplied,
`published_from` must not be later than `published_to`, and the date range must
not exceed five calendar years. Invalid date formats return `422`; invalid
date combinations return `400` with `Invalid article date range.`.
Because the inclusive upper boundary is implemented as an exclusive next-day
UTC boundary, `published_to=9999-12-31` is not supported and returns the same
sanitized `400` date-range response instead of exposing arithmetic errors.

Source filtering is applied at the SQL level against any linked provenance
source record. The displayed `source_slug`, `source_name`, and `source_url`
continue to use the primary source-selection policy, so the matched provenance
source may differ from the displayed primary source. Tag filtering is also
applied at the SQL level and does not multiply rows or inflate `total`.

Ordering is deterministic and newest-first:

```text
source_published_at DESC NULLS LAST
last_seen_at DESC
internal database ID DESC
```

The internal database ID is only an unexposed tie-breaker. Source display uses
the primary source record when present. If malformed legacy data has no primary
source record, the implementation uses a deterministic fallback based on safe
stable source/source-record fields. `published_at` and `modified_at` prefer
primary source-record dates and fall back to item-level dates. UAE/global
display uses the normalized `geographic_scope`, `uae_relevance_status`, and
`uae_relevance_confidence` fields without inventing a combined tag string.

The endpoint is read-only and never calls ingestion collectors, persistence
services, schedulers, startup ingestion, API-triggered ingestion, or external
network requests. Public sort parameters remain pending.

Implemented `GET /api/v1/intelligence/items` validation:

- `q` is optional, trims surrounding whitespace, has maximum length 120, and
  rejects whitespace-only input with `422`.
- `severity` is optional, normalizes to lowercase, and allows only `unknown`,
  `none`, `low`, `medium`, `high`, or `critical`.
- `source_slug` is optional, normalizes to lowercase, has maximum length 80,
  and uses the canonical slug format described above.
- `item_type` is optional, normalizes to lowercase, and allows only the
  approved item types listed in this document. When omitted, the implemented
  endpoint still defaults to `vulnerability`.
- `cve_id` is optional, trims surrounding whitespace, normalizes to uppercase,
  and must match `CVE-YYYY-NNNN...` with a four-digit year and at least four
  sequence digits. The year and sequence digits must be ASCII digits.
- Supplying `severity` or `cve_id` with an explicit non-vulnerability
  `item_type` returns `400` with
  `Vulnerability filters require item_type=vulnerability.`.

## 7. Intelligence-Item Query Parameters

| Parameter | Rules |
|---|---|
| `item_type` | Repeatable controlled enum. |
| `status` | Repeatable; default `active`. |
| `source` | Repeatable source slug; maximum 10 values. |
| `tag` | Repeatable tag slug; maximum 20 values. |
| `severity` | Repeatable controlled enum. |
| `kev_status` | Repeatable controlled enum. |
| `geographic_scope` | Repeatable controlled enum. |
| `uae_relevance_status` | Repeatable controlled enum. |
| `published_from` | ISO 8601 timestamp. |
| `published_to` | ISO 8601 timestamp. |
| `collected_from` | ISO 8601 timestamp. |
| `collected_to` | ISO 8601 timestamp. |
| `epss_min` | Finite number from 0 to 1. |
| `cvss_min` | Finite number from 0 to 10. |
| `identifier` | Exact external identifier; maximum 300 characters. |
| `q` | Case-insensitive title/summary search; 2-120 characters. |
| `page` | Minimum 1; default 1. |
| `page_size` | Default 25; maximum 100. |
| `sort` | Allow-listed sort expression. |

Approved `item_type` values:

- `vulnerability`
- `security_advisory`
- `cyber_news`
- `threat_report`
- `uae_official_alert`
- `other_defensive_intel`

Approved `status` values:

- `active`
- `superseded`
- `merged`
- `archived`

Approved severity values:

- `unknown`
- `none`
- `low`
- `medium`
- `high`
- `critical`

Approved KEV values:

- `unknown`
- `not_listed`
- `listed`

Approved `geographic_scope` values:

- `global`
- `regional`
- `uae`
- `unknown`

Approved UAE relevance values:

- `confirmed`
- `probable`
- `possible`
- `not_relevant`
- `unknown`

Filter behavior:

- Different filter categories combine with `AND`.
- Repeated values of the same filter combine with `OR`.
- `q` searches only canonical title and summary.
- Exact identifier matching uses `identifier`.
- Raw payload content is never searched.
- `analyst_review_status` is excluded from the public MVP.

## 8. Pagination and Sorting

Page-based pagination:

- `page=1`
- `page_size=25`
- maximum `page_size=100`

Pagination metadata:

- `page`
- `page_size`
- `total_items`
- `total_pages`
- `has_next`
- `has_previous`

Pagination links:

- `self`
- `next`
- `previous`

Rules:

- `next` and `previous` are `null` when unavailable.
- Links preserve all active filters.
- Links preserve repeated query parameters.
- Links preserve sort and page size.
- Links are safely URL encoded.
- Only the page value changes for next and previous links.

Default intelligence-item ordering:

```text
source_published_at DESC NULLS LAST
internal database ID DESC
```

The internal ID is an unexposed tie-breaker only.

Approved public sort names:

- `published_at`
- `modified_at`
- `collected_at`
- `last_seen_at`
- `severity`
- `cvss_score`
- `epss_score`
- `kev_date_added`

Sort mappings:

- `published_at` -> `source_published_at`
- `modified_at` -> `source_modified_at`
- `collected_at` -> `collected_at`
- `last_seen_at` -> `last_seen_at`
- `cvss_score` -> vulnerability CVSS score
- `epss_score` -> vulnerability EPSS score
- `kev_date_added` -> vulnerability KEV date

Sort format:

```text
sort=published_at
sort=-published_at
```

Severity rank from lowest to highest:

1. `unknown`
2. `none`
3. `low`
4. `medium`
5. `high`
6. `critical`

Therefore:

- `sort=severity` returns unknown first.
- `sort=-severity` returns critical first.

All sorts use `NULLS LAST` and a stable unexposed internal-ID tie-breaker.

Title sorting and cursor pagination are deferred.

## 9. Response Model Hierarchy

Models:

- `ApiResponse[T]`
- `PaginatedResponse[T]`
- `PaginationMeta`
- `PaginationLinks`
- `DashboardSummary`
- `IntelligenceItemListItem`
- `IntelligenceItemDetail`
- `VulnerabilitySummary`
- `VulnerabilityDetail`
- `IdentifierSummary`
- `TagSummary`
- `SourceSummary`
- `SourceReferenceSummary`
- `BoundedCollection[T]`
- `ApiErrorResponse`

Detail response envelope:

```json
{
  "data": {}
}
```

List response envelope:

```json
{
  "data": [],
  "meta": {},
  "links": {}
}
```

Use:

```text
vulnerability: VulnerabilityDetail | null
```

Do not create separate top-level vulnerability response types for the MVP.

## 10. Dashboard Summary Contract

Endpoint:

```text
GET /api/v1/dashboard/summary
```

Query parameter:

- `window_days`: default 30, minimum 1, maximum 365

Response fields:

- `window_days`
- `window_start`
- `window_end`
- `generated_at`
- `metrics`
- `counts`
- `thresholds`
- `ingestion`
- `latest_articles`
- `latest_fetch`

Semantics:

- `window_end` equals `generated_at`.
- `window_start` equals `window_end` minus `window_days`.
- Use half-open ranges: `window_start <= timestamp < window_end`.
- Counts include only normalized items with `status="active"` unless explicitly stated.
- Critical count includes severity exactly `critical`.
- High severity count includes severity exactly `high`, not critical.
- KEV count includes only `kev_status="listed"`.
- High EPSS count includes EPSS greater than or equal to the applied threshold.
- UAE-relevant count includes `confirmed` and `probable`.
- UAE-relevant count excludes `possible`, `unknown`, and `not_relevant`.
- Collected count uses `collected_at` within the window.
- Recommended high EPSS threshold is `0.7`.
- The applied threshold is returned.
- Latest articles include only active article-like item types and exclude
  vulnerabilities.
- Latest fetch status comes only from stored ingestion-run metadata and never
  performs a live source check.

`last_successful_ingestion_at` is the latest `last_successful_fetch_at` among enabled sources registered in `intelligence_sources`.

Inclusion in `intelligence_sources` represents an approved project source for the MVP. No separate source approval field is introduced.

Implemented `metrics` fields:

- `critical_vulnerability_count`
- `kev_vulnerability_count`
- `active_article_count`
- `uae_related_item_count`

Implemented `latest_articles` row fields:

- `public_id`
- `title`
- `summary`
- `category`
- `source_slug`
- `source_name`
- `published_at`
- `last_seen_at`

Implemented `latest_fetch` fields:

- `source_slug`
- `source_name`
- `status`
- `started_at`
- `completed_at`
- `fetched_count`
- `processed_count`
- `failed_count`

The implemented endpoint is read-only. It uses stored database data only and
does not call collectors, ingestion services, startup jobs, schedulers,
workers, or external network resources.

Example:

```json
{
  "window_days": 30,
  "window_start": "2026-06-10T12:00:00Z",
  "window_end": "2026-07-10T12:00:00Z",
  "generated_at": "2026-07-10T12:00:00Z",
  "metrics": {
    "critical_vulnerability_count": 18,
    "kev_vulnerability_count": 42,
    "active_article_count": 25,
    "uae_related_item_count": 14
  },
  "counts": {
    "active_intelligence_items": 1240,
    "critical_vulnerabilities": 18,
    "high_severity_vulnerabilities": 86,
    "cisa_kev_listed_vulnerabilities": 42,
    "high_epss_vulnerabilities": 31,
    "uae_relevant_intelligence": 14,
    "intelligence_items_collected_in_window": 220
  },
  "thresholds": {
    "high_epss_minimum": 0.7
  },
  "ingestion": {
    "last_successful_ingestion_at": "2026-07-10T10:00:00Z"
  },
  "latest_articles": [
    {
      "public_id": "6c20c9f8-70cb-4905-8221-4b16c7d3d7cc",
      "title": "Public defensive security advisory",
      "summary": "A safe public advisory summary.",
      "category": "security_advisory",
      "source_slug": "cert-eu-security-advisories",
      "source_name": "CERT-EU Security Advisories",
      "published_at": "2026-07-10T08:00:00Z",
      "last_seen_at": "2026-07-10T09:00:00Z"
    }
  ],
  "latest_fetch": {
    "source_slug": "cert-eu-security-advisories",
    "source_name": "CERT-EU Security Advisories",
    "status": "partial",
    "started_at": "2026-07-10T11:00:00Z",
    "completed_at": "2026-07-10T11:01:00Z",
    "fetched_count": 8,
    "processed_count": 7,
    "failed_count": 1
  }
}
```

## 11. Intelligence-Item List Contract

List fields:

- `public_id`
- `item_type`
- `title`
- shortened `summary`
- `status`
- `source_published_at`
- `last_seen_at`
- `geographic_scope`
- `uae_relevance_status`
- `primary_identifier`
- `primary_source`
- bounded tags
- `tag_count`
- `tags_truncated`
- compact vulnerability summary or `null`

Rules:

- Summary maximum is 280 characters.
- Shortening must not insert unsafe HTML.
- Only the primary identifier appears.
- Only the primary source summary appears.
- `primary_identifier` may be null.
- `primary_source` may be null only for pending normalization or exceptional manual records.
- Normal collected intelligence should have source provenance.
- Include at most five tags.
- `tag_count` contains the complete count.
- `tags_truncated` indicates whether tags were omitted.

Example:

```json
{
  "data": [
    {
      "public_id": "2f4a3fd8-5d6b-4c72-9d9a-1c2b0d1b8a10",
      "item_type": "vulnerability",
      "title": "CVE-2026-12345 in Example Product",
      "summary": "A public vulnerability record from an approved source.",
      "status": "active",
      "source_published_at": "2026-06-28T10:00:00Z",
      "last_seen_at": "2026-07-02T07:30:00Z",
      "geographic_scope": "global",
      "uae_relevance_status": "unknown",
      "primary_identifier": {
        "namespace": "cve",
        "value": "CVE-2026-12345"
      },
      "primary_source": {
        "name": "NVD",
        "slug": "nvd",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"
      },
      "tags": [
        {
          "slug": "cloud",
          "display_name": "Cloud",
          "tag_type": "theme"
        }
      ],
      "tag_count": 7,
      "tags_truncated": true,
      "vulnerability": {
        "severity": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.812345,
        "epss_percentile": 0.9821,
        "epss_score_date": "2026-07-08",
        "kev_status": "listed"
      }
    }
  ],
  "meta": {
    "page": 1,
    "page_size": 25,
    "total_items": 1,
    "total_pages": 1,
    "has_next": false,
    "has_previous": false
  },
  "links": {
    "self": "/api/v1/intelligence-items?page=1&page_size=25",
    "next": null,
    "previous": null
  }
}
```

## 12. Intelligence-Item Detail Contract

Detail fields:

- public UUID
- item type
- title
- full safe summary
- lifecycle status
- canonical URL
- source timestamps
- collection timestamps
- geographic scope
- UAE relevance object
- confidence
- bounded identifiers
- bounded tags
- bounded source references
- nullable vulnerability extension

Lifecycle fields:

- `merged_into_public_id`
- `superseded_by_public_id`

Rules:

- Merged status requires `merged_into_public_id`.
- Superseded status requires `superseded_by_public_id`.
- Both cannot be populated simultaneously.
- Internal self-reference IDs are never exposed.
- Bounded detail collections contain `items`, `total_count`, and `truncated`.

Approved UAE relevance method values:

- `automatic`
- `manual`
- `source_declared`
- `unassigned`

Recommended limits:

- Identifiers: 50
- Source references: 25
- Affected products: 100

Vulnerability detail example:

```json
{
  "data": {
    "public_id": "2f4a3fd8-5d6b-4c72-9d9a-1c2b0d1b8a10",
    "item_type": "vulnerability",
    "title": "CVE-2026-12345 in Example Product",
    "summary": "A public defensive vulnerability summary.",
    "status": "active",
    "merged_into_public_id": null,
    "superseded_by_public_id": null,
    "canonical_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
    "source_published_at": "2026-06-28T10:00:00Z",
    "source_modified_at": "2026-06-30T12:00:00Z",
    "collected_at": "2026-07-01T09:00:00Z",
    "last_seen_at": "2026-07-02T07:30:00Z",
    "geographic_scope": "global",
    "uae_relevance": {
      "status": "unknown",
      "confidence": null,
      "reason": null,
      "method": "unassigned"
    },
    "data_confidence": 0.95,
    "identifiers": {
      "items": [
        {
          "namespace": "cve",
          "value": "CVE-2026-12345",
          "normalized_value": "CVE-2026-12345",
          "is_primary": true
        }
      ],
      "total_count": 1,
      "truncated": false
    },
    "tags": {
      "items": [],
      "total_count": 0,
      "truncated": false
    },
    "source_references": {
      "items": [
        {
          "source": {
            "name": "NVD",
            "slug": "nvd",
            "source_type": "api"
          },
          "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
          "source_external_id": "CVE-2026-12345",
          "is_primary_reference": true,
          "source_published_at": "2026-06-28T10:00:00Z",
          "source_modified_at": "2026-06-30T12:00:00Z",
          "first_seen_at": "2026-07-01T09:00:00Z",
          "last_seen_at": "2026-07-02T07:30:00Z",
          "upstream_status": "present"
        }
      ],
      "total_count": 1,
      "truncated": false
    },
    "vulnerability": {
      "severity": "critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cvss_version": "3.1",
      "epss_score": 0.812345,
      "epss_percentile": 0.9821,
      "kev_status": "listed",
      "kev_last_checked_at": "2026-07-02T07:40:00Z",
      "kev_date_added": "2026-07-01",
      "kev_due_date": "2026-07-22",
      "kev_required_action": "Apply vendor mitigation or update according to official guidance.",
      "known_ransomware_campaign_use": false,
      "affected_summary": "Example Product before 1.2.3.",
      "affected_products": {
        "items": [],
        "total_count": 0,
        "truncated": false
      }
    }
  }
}
```

Non-vulnerability detail example:

```json
{
  "data": {
    "public_id": "6c20c9f8-70cb-4905-8221-4b16c7d3d7cc",
    "item_type": "threat_report",
    "title": "Public report on defensive cloud security trends",
    "summary": "A public report summary from an approved source.",
    "status": "active",
    "merged_into_public_id": null,
    "superseded_by_public_id": null,
    "canonical_url": "https://example.org/reports/cloud-security-trends",
    "source_published_at": "2026-06-20T08:00:00Z",
    "source_modified_at": null,
    "collected_at": "2026-07-01T10:00:00Z",
    "last_seen_at": "2026-07-02T07:00:00Z",
    "geographic_scope": "global",
    "uae_relevance": {
      "status": "possible",
      "confidence": 0.42,
      "reason": "Mentions regional cloud security considerations.",
      "method": "automatic"
    },
    "data_confidence": 0.8,
    "identifiers": {
      "items": [],
      "total_count": 0,
      "truncated": false
    },
    "tags": {
      "items": [
        {
          "slug": "cloud",
          "display_name": "Cloud",
          "tag_type": "theme"
        }
      ],
      "total_count": 1,
      "truncated": false
    },
    "source_references": {
      "items": [
        {
          "source": {
            "name": "Example Cyber Advisory Feed",
            "slug": "example-feed",
            "source_type": "rss"
          },
          "source_url": "https://example.org/reports/cloud-security-trends",
          "source_external_id": "cloud-security-trends-2026",
          "is_primary_reference": true,
          "source_published_at": "2026-06-20T08:00:00Z",
          "source_modified_at": null,
          "first_seen_at": "2026-07-01T10:00:00Z",
          "last_seen_at": "2026-07-02T07:00:00Z",
          "upstream_status": "present"
        }
      ],
      "total_count": 1,
      "truncated": false
    },
    "vulnerability": null
  }
}
```

## 13. Vulnerability Contract

Vulnerability fields:

- severity
- CVSS score
- CVSS vector
- CVSS version
- EPSS score
- EPSS percentile
- EPSS score date
- KEV status
- KEV last checked timestamp
- KEV date added
- KEV due date
- KEV required action
- known ransomware campaign use
- affected summary
- bounded affected products

Preserve these KEV states:

- `unknown`
- `not_listed`
- `listed`

Do not convert unknown KEV status to false.

`known_ransomware_campaign_use` is nullable:

- `true` means campaign use is confirmed.
- `false` means campaign use was checked and confirmed absent.
- `null` means the value is unknown or has not been checked.

Implemented EPSS response behavior:

- `epss_score` is `null` until manual FIRST EPSS enrichment succeeds for the CVE.
- `epss_percentile` is `null` until manual FIRST EPSS enrichment succeeds for the CVE.
- `epss_score_date` is `null` when no FIRST EPSS source record is linked.
- EPSS source-record IDs, raw score payloads, and audit internals are not exposed.
- EPSS provenance does not replace the primary NVD `source_slug`, `source_name`,
  or `source_url` fields in the current flat MVP response.

## 14. Source and Provenance Exposure

Public source fields:

- `public_id`
- `name`
- `slug`
- `source_type`
- `base_url`
- `last_successful_fetch_at`

Do not expose:

- `is_enabled`
- checkpoints
- rate-limit notes
- internal fetch configuration
- raw payloads
- headers
- credentials
- tokens

Source-list default ordering:

```text
name ASC
internal ID ASC
```

The internal ID is an unexposed tie-breaker.

Item source-reference fields:

- source name
- source slug
- source type
- original source URL
- source external ID
- publication and modification timestamps
- primary-reference flag
- first-seen timestamp
- last-seen timestamp
- upstream status

Approved public `source_type` values:

- `api`
- `rss`
- `csv`
- `json`

Approved `upstream_status` values:

- `present`
- `missing`
- `unavailable`

Source list example:

```json
{
  "data": [
    {
      "public_id": "fd7c9c45-3706-4a0c-b802-0ff1e1c7b728",
      "name": "NVD",
      "slug": "nvd",
      "source_type": "api",
      "base_url": "https://nvd.nist.gov/",
      "last_successful_fetch_at": "2026-07-02T07:45:00Z"
    }
  ],
  "meta": {
    "page": 1,
    "page_size": 25,
    "total_items": 1,
    "total_pages": 1,
    "has_next": false,
    "has_previous": false
  },
  "links": {
    "self": "/api/v1/sources?page=1&page_size=25",
    "next": null,
    "previous": null
  }
}
```

## 15. Tag Contract

Public tag fields:

- `slug`
- `display_name`
- `tag_type`

Tags are addressed by slug.

Tag endpoint query parameters:

- `tag_type`
- `q`
- `page`
- `page_size`

Tag `q` behavior:

- case-insensitive search
- searches slug and display name only
- does not search intelligence-item content
- does not search raw payloads

Approved `tag_type` values:

- `general`
- `vendor`
- `product`
- `sector`
- `region`
- `technique`
- `theme`

Tag-list default ordering:

```text
display_name ASC
slug ASC
internal database ID ASC
```

The internal ID is an unexposed stable tie-breaker.

## 16. Error Contract and HTTP Status Codes

Error shape:

```json
{
  "error": {
    "code": "stable_error_code",
    "message": "Safe human-readable message.",
    "details": [],
    "request_id": "req_example",
    "timestamp": "2026-07-02T08:30:00Z"
  }
}
```

Approved error codes:

- `validation_error`
- `invalid_query`
- `not_found`
- `conflict`
- `rate_limited`
- `upstream_unavailable`
- `internal_server_error`

HTTP status codes:

- `200` for successful list/detail
- `400` for invalid combinations of individually valid parameters
- `422` for type, UUID, format, enum, range, and length validation errors
- `404` for missing resources
- `409` for conflicts
- `429` for rate limiting
- `503` when a serving dependency such as PostgreSQL is unavailable
- `500` for unexpected server errors

Examples of `400`:

- start date later than end date
- date range exceeding the allowed maximum

Normalize FastAPI validation errors into the standard envelope while retaining `422`.

External feed outages should not cause stored-data list or detail requests to return `503`.

Validation error example:

```json
{
  "error": {
    "code": "validation_error",
    "message": "One or more request parameters are invalid.",
    "details": [
      {
        "field": "page_size",
        "message": "Must be less than or equal to 100."
      }
    ],
    "request_id": "req_01HZEXAMPLE0001",
    "timestamp": "2026-07-02T08:30:00Z"
  }
}
```

Not-found error example:

```json
{
  "error": {
    "code": "not_found",
    "message": "The requested intelligence item was not found.",
    "details": [],
    "request_id": "req_01HZEXAMPLE0002",
    "timestamp": "2026-07-02T08:30:00Z"
  }
}
```

Internal server error example:

```json
{
  "error": {
    "code": "internal_server_error",
    "message": "An unexpected server error occurred.",
    "details": [],
    "request_id": "req_01HZEXAMPLE0003",
    "timestamp": "2026-07-02T08:30:00Z"
  }
}
```

## 17. Request ID and Rate-Limit Behavior

- Every response includes `X-Request-ID`.
- Error bodies include the same request ID.
- The server generates the request ID.
- Client-provided request IDs are not blindly trusted.
- Client-provided values must be validated, bounded, and sanitized before any use.
- Request IDs must not contain secrets.

For `429`:

- Use the standard error envelope.
- Include `Retry-After` when the retry interval is known.
- Public rate-limit thresholds remain environment-configurable.
- Exact quotas are deferred until implementation.

## 18. Nullability, Naming, and Serialization

Use:

- `snake_case` JSON fields
- ISO 8601 UTC timestamps with `Z`
- `YYYY-MM-DD` date fields
- finite JSON numbers for CVSS, EPSS, percentiles, and confidence
- `null` for unknown numeric values
- empty arrays for empty collections
- enum values for tri-state concepts

Reject:

- `NaN`
- positive infinity
- negative infinity

Future Pydantic serialization may require explicit configuration so Decimal-backed values become JSON numbers rather than strings.

## 19. Security, Privacy, and Performance Limits

Security and privacy:

- no raw payload exposure
- no internal IDs
- no secrets, cookies, headers, stack traces, SQL errors, or file paths
- external content remains untrusted
- frontend must safely escape text
- allow-listed sorting only
- bounded queries and nested collections
- no public analyst-review workflow
- no public ingestion administration

Limits:

- default page size 25
- maximum page size 100
- search maximum 120 characters
- maximum repeated tags 20
- maximum repeated sources 10
- dashboard window maximum 365 days
- publication range maximum 5 years
- collection range maximum 366 days
- list summary maximum 280 characters
- list tags maximum 5
- detail identifiers maximum 50
- detail source references maximum 25
- affected products maximum 100

## 20. OpenAPI Documentation Requirements

Future implementation should document:

- summaries
- descriptions
- parameters
- enums
- defaults and limits
- sort mappings
- response models
- error responses
- examples
- `X-Request-ID`
- `Retry-After`
- security notes for deferred protected endpoints

Do not implement OpenAPI customization during this task.

## 21. Deferred Features

- ingestion-run public endpoints
- ingestion error details
- manual ingestion triggers
- authenticated analyst-review API
- separate vulnerability endpoints
- item-to-item relationship endpoints
- cursor pagination
- title sorting
- full-text search
- exports and reports
- authentication and authorization

## 22. P1-03 Acceptance Criteria and Approved Defaults

Completed checklist:

- [x] API versioning selected.
- [x] Endpoint inventory defined.
- [x] Query validation defined.
- [x] Pagination defined.
- [x] Stable sorting defined.
- [x] Dashboard semantics defined.
- [x] Response hierarchy defined.
- [x] Source and tag exposure defined.
- [x] Security boundaries defined.
- [x] Error model defined.
- [x] Request-ID behavior defined.
- [x] Serialization defined.
- [x] Performance limits defined.
- [x] Ingestion administration deferred.
- [x] No implementation performed.

Approved defaults:

- Official public source base URLs may be exposed.
- High EPSS threshold defaults to `0.7`.
- Public freshness metadata is sufficient for the MVP demo.
- Convenience vulnerability endpoints remain deferred.
