# DESC Publication Metadata Collectors

## B5-04 status

B5-04 implements fixture-tested metadata collectors and one inactive persistence
handler for `desc-news` and `desc-published-research`. Both registry identities
are `implemented`, source type `html`, progress contract `watermark`, and
`enabled: false`. Automated access remains approval-pending. No live DESC
request was made, and there is no claim of current live DESC coverage.

## Fixed collection boundary

The enum-selected collector can issue at most one GET to exactly one of:

- `https://www.desc.gov.ae/media-hub/news/`
- `https://www.desc.gov.ae/research-innovation/published-research/`

It follows no pagination and never requests article pages, research landing
pages, PDFs, attachments, downloads, images, media, scripts, stylesheets,
WordPress APIs, feeds, forms, search paths, or callback URLs. The observed news
page-2 link is ignored.

Before opening transport, the collector checks the immutable UAE source-policy
decision. Pending approval means zero requests, no newly fetched persistence,
and no progress proposal. The handler is absent from `SOURCE_POLICIES`,
`DEFAULT_SOURCE_HANDLERS`, schedules, and deployments.

## Transport controls

Requests require HTTPS, exact authority `www.desc.gov.ae` with no explicit
port, credentials, query, or fragment, redirects disabled, `trust_env=False`,
fixed `User-Agent` and `Accept` headers, bounded connect/read/write/pool
timeouts, and no caller URL, headers, cookies, proxy, or callback. Responses
must be `text/html` or `application/xhtml+xml`. Redirects and non-2xx responses
fail safely. A valid oversized `Content-Length` is rejected before body use,
streaming stops above 2 MiB, and a listing is capped at 50 parsed records.
The cap counts trusted news articles or Elementor research-card sections before
parsing and deduplication. Overflow contributes to rejected-record counters;
capped results are partial and cannot advance progress.

## News DOM and metadata contract

News parsing accepts only an `article` classified as `post`, `type-post`, and
`category-news`, containing one `h2.entry-title` title anchor and one
`time.entry-date.published` with a timezone-aware ISO `datetime`. An optional
`div.entry-summary` supplies listing text only; `Read More` is removed. Relevant
title, date, read-more, and thumbnail anchors must agree.

Canonical news links are exact-host root-level lowercase safe slug paths with a
trailing slash, such as `https://www.desc.gov.ae/safe-news-slug/`. Nested,
encoded, traversal, query, fragment, explicit-port, IP, suffix-confusion,
WordPress, pagination, search, and form paths fail closed. Stored metadata is
limited to title, URL, publication time, bounded summary, `DESC News` category,
and deterministic `desc-news:<slug>` identity. Article bodies are never fetched.

## Published-research DOM and metadata contract

Research parsing accepts only one Elementor inner research section containing
one `h4.elementor-heading-title`, one `h6.elementor-heading-title`, one
`Publishers:` paragraph, and one link whose text is exactly `Visit Publication`.
Month/year prose is not converted into a fabricated date.

Only these HTTPS landing hosts may be stored as metadata identities:

- `ieeexplore.ieee.org`
- `www.sciencedirect.com`
- `dl.acm.org`
- `www.researchgate.net`

They are never request targets. Arbitrary paths on an allow-listed host are
rejected. Accepted landing paths are limited to:

- IEEE Xplore: `/document/<1-20-digit-id>`;
- ScienceDirect: `/science/article/pii/<safe-pii>` or
  `/science/article/abs/pii/<safe-pii>`;
- ACM Digital Library: `/doi/10.<registrant>/<safe-suffix>` or the corresponding
  `/doi/abs/` path;
- ResearchGate: `/publication/<numeric-id>` with an optional bounded safe title
  slug joined by an underscore.

Direct `.pdf` and download endpoints fail closed. Path indicators `pdf`,
`pdfft`, `epdf`, `downloadFile`, `attachment`, `file`, `image`, `media`,
`stamp`, and `export` are rejected case-insensitively, as are download-related
query keys including `download`, `pdf`, `pdfft`, `epdf`, `attachment`, `file`,
`export`, and `format`. Encoded separators, traversal, extra nested segments,
and unapproved hosts are rejected. Optional trailing slashes are removed after
strict path validation, so equivalent slash variants cannot create separate
identities. Malformed URL authorities receive a sanitized `unsafe_url`
classification without exposing the URL or parser exception.
Direct-PDF cards are known skipped entries; unrelated valid cards continue
processing safely.

Research external identity is the lowercase SHA-256 digest of the already
validated canonical publication URL only. Exact duplicate cards collapse
deterministically. When cards sharing one canonical URL disagree on any
persisted metadata, every conflicting card is rejected: every source container
in that conflicting identity is rejected, and unrelated cards continue in
first-identity source order. Payloads allow only publication statement,
publishers, publication host, and `DESC Published Research` category.

DOM traversal and text extraction use iterative bounded walks with explicit
node and text limits. Deeply nested bounded markup cannot expose a raw Python
`RecursionError`; excessive structure fails with a sanitized error containing
no source HTML or provider text.

## Persistence and evidence

`PublicationPipeline` accepts implemented publication sources independently of
operational enablement, while its operational helper still requires
`enabled: true`. This performs no network operation and does not enable DESC.
The handler independently enforces approval, uses caller-owned SQLAlchemy
transactions, persists idempotently, reconciles accepted and rejected records,
stores sanitized outcome and terminal evidence, and flushes before transaction
exit. Replayed attempts reuse committed evidence. Failures roll back; partial
results are not complete success and do not advance watermark progress.
Collection-result invariants are validated both when immutable results are
created and again by the handler before persistence or progress construction.
Malformed counters, categories, candidates, cap flags, or page counts fail as
contract violations and cannot produce persistence evidence or success.

## Fixture validation and future activation

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests/test_desc_publications_client.py tests/test_desc_publication_handler.py tests/test_desc_publications_documentation.py
```

Future activation requires explicit APR-05 source-specific approval, current
terms review, reviewed cadence and quotas, secure staging configuration,
bounded staging validation against the exact listing URL, and a separate
binding/scheduling decision. B5-02 and B5-03 remain deferred.
