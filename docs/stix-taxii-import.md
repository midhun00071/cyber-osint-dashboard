# STIX/TAXII Import and Fixed-Policy Collection

## Status and scope

The first two internal P9-10 units provide bounded STIX 2.1 validation and
caller-transaction-owned persistence plus a separately controlled fixed-policy
TAXII 2.1 collection client. Reviewed operator files and synthetic TAXII
envelopes remain supported by the offline foundation. Both production policy
registries are deliberately empty, so no production STIX/TAXII source can run.

The network unit adds no API-root or collection discovery, arbitrary server,
URL, endpoint, redirect target, request header, cookie, CLI, API route, frontend
control, scheduler, startup task, or background worker. It does not retrieve
malware, attachments, binaries, or files; scan or probe; evaluate Indicator
patterns against systems; or implement P9-11 threat-entity tables. Validation
uses only synthetic responses through `httpx.MockTransport`; no live TAXII
request or source check has been performed.

The direct dependency is the maintained OASIS `stix2>=3.0,<4.0` library. STAXX,
`taxii2-client`, STIX 1 conversion, MISP conversion, and vendor-specific STIX
libraries are not dependencies.

## Approved source and input boundary

An immutable developer-controlled STIX policy fixes the exact source slug, one
explicit transport, safe object/relationship/marking allow-lists, a synthetic
or later-approved HTTPS identity base, and processing limits. A separate
immutable TAXII collection policy contains that validated semantic policy and
fixes its network and pagination limits. Runtime production lookup always fails
closed because both immutable registries have no entries. Tests build isolated
synthetic policies without registering a runtime source.

The two explicit input shapes are:

- a STIX 2.1 bundle with only `type`, optional bounded `id`, and `objects` at
  the top level;
- an offline TAXII 2.1 envelope fixture with only `objects`, optional boolean
  `more`, and optional bounded `next` when `more` is true.

Formats are never auto-detected. The TAXII fixture cannot carry a server,
collection, headers, credentials, or request parameters. The local-file reader
accepts only a direct regular file, rejects UNC/device/pipe paths and detectable
links/reparse points, validates descriptor identity and path stability, bounds
growth while reading, and returns immutable data. It rejects invalid UTF-8,
duplicate keys, non-standard numeric constants, and excessive JSON depth,
nodes, collections, strings, bytes, or objects. A live TAXII transport may use
the bounded in-memory envelope parser but is explicitly rejected by the local
file loader. Errors omit paths and content.

Default policy limits are 2 MiB, depth 16, 10,000 JSON nodes, 10,000 characters
per string, 500 objects, 200 relationships, 20 marking references per object,
20 external references, and 50 aliases or comparable bounded arrays.

A bundle may omit its `id`. When present, the ID must be exactly
`bundle--<canonical lowercase RFC 4122 UUID>`; alternate prefixes, malformed or
noncanonical UUID text, invalid variants, controls, URL syntax, paths, and
oversized values fail before object parsing.

The fixed policy base is HTTPS with one lowercase DNS host identity and no
credentials, query, fragment, IP literal, host alias, or non-default port.
Explicit port 443 normalizes to the omitted-port identity. Path segments use
only RFC 3986 unreserved characters. Percent escapes, empty interior segments,
repeated separators, traversal, backslashes, controls, and paths too long for
the existing `SourceRecord.source_url` boundary are rejected. The resulting
identity URL is never requested.

Policy hosts additionally use maintained IDNA processing with UTS #46, STD3
rules, and non-transitional behavior. The submitted host must already equal its
canonical lowercase ASCII form. Valid canonical A-labels are accepted;
malformed punycode, Unicode aliases, uppercase or trailing-dot aliases, invalid
or overlong labels, and IP literals are rejected without DNS resolution.

## Fixed-policy TAXII 2.1 network boundary

The separate frozen collection policy fixes one canonical lowercase-ASCII HTTPS
API-root URL and one exact unreserved-character collection ID. It derives the
only permitted request target as:

```text
<api-root>/collections/<collection-id>/objects/
```

The production function accepts only an exact approved source slug and optional
exact `httpx.BasicAuth`; custom or subclassed executable authentication is
rejected. It has no server, API-root, collection, endpoint, URL, path,
headers, cookies, or redirect parameters. The client performs no API-root or
collection discovery and makes GET requests only to the derived objects
endpoint. Each collection call owns a fresh synchronous `httpx.Client` with
`follow_redirects=False`, `trust_env=False`, a fixed project User-Agent, and
fixed `application/taxii+json;version=2.1` Accept and `Accept-Encoding: identity`
headers. After authentication and immediately before transport, an exact guard
revalidates the GET method, full URL and query, Host and fixed request-header
allow-list, absence of cookies and arbitrary headers, and the bounded connect,
read, write, and pool timeout extensions. A mismatch raises a sanitized typed
error before the transport handler can run. Redirect responses are rejected
without following them. Authentication is never included in results, errors,
logs, or policy dataclasses, and response cookies are cleared between page
attempts.

Before client construction, each collection call installs one temporary filter
instance on the `httpx`, `httpcore`, `httpcore.connection`, `httpcore.http11`,
`httpcore.http2`, `httpcore.proxy`, and `httpcore.socks` loggers. The filter
rejects only records created or handled by the synchronous collection thread,
so opaque pagination queries, response headers, and cookies cannot enter
third-party HTTP logs while unrelated-thread logging remains available. The
exact filter instance is always removed without changing logger levels,
handlers, propagation, disabled state, root logging, or global logging. Setup
or cleanup failure raises a fixed sanitized client error.

Every response body is streamed through `iter_raw()`. A response may omit
`Content-Encoding` or use only a single valid `identity` value; gzip, deflate,
Brotli, multiple or duplicate values, parameters, and malformed values fail
closed before body iteration. A declared `Content-Length` is checked before
reading, and raw encoded bytes are counted regardless of that header. Defaults are
2 MiB per response, 8 MiB across the collection, 10 pages, 500 total objects,
and 1,024 characters per pagination token. Connect, read, write, and pool
timeouts default to 5, 10, 5, and 5 seconds. A separate 60-second monotonic
deadline covers all requests and streamed reads; every per-request timeout is
capped by its remaining duration.

Only the TAXII 2.1 JSON media type is accepted. Case and insignificant
whitespace are normalized, while missing, malformed, duplicate, conflicting,
non-2.1, or extra parameters fail closed. Status 429, redirects, unsuccessful
statuses, timeouts, transport failures, request-policy failures, content-type or
content-encoding failures, oversize bodies, pagination failures, envelope
failures, and complete-document STIX failures use typed fixed-message exceptions
that omit bodies, headers, URLs, query values, cookies, credentials, tokens, raw
exceptions, and stack traces.

The first request uses the exact derived endpoint without a query. Later
requests use the same endpoint and carry only the opaque `next` value through
the `next` query parameter; the token is never interpreted as a URL. Missing or
contradictory `more`/`next` values, unsafe or oversized tokens, repeated tokens,
repeated response or object-page identities, empty continuation pages,
no-progress continuation, and page/object/byte/deadline overflow all fail
closed. Safely parsed page objects are combined into one immutable bounded
document. A reusable non-serializing traversal rechecks the lightweight
`{"objects": combined_objects}` tree against aggregate node, depth, string,
collection, numeric, and supported-value limits before
`validate_stix_document` runs, allowing relationships and marking references to
resolve across page boundaries without bypassing whole-document memory bounds.

The collection result contains safe counters and the immutable
`ValidatedStixDocument`. Callers may pass that document to
`StixBundleImportService`; the client does not duplicate mapping, lineage,
provenance, or persistence logic. The import service still never commits or
rolls back, so the caller owns the complete database transaction.

## STIX validation and safe staging

Bounded immutable JSON reaches the OASIS STIX 2.1 parser with
`allow_custom=False`. Any invalid or unsupported object rejects the whole
document; objects are not silently skipped. Supported types are:

- `marking-definition`, `identity`, `indicator`, and `relationship`;
- `attack-pattern`, `campaign`, `malware`, and `threat-actor` for later P9-11
  modelling preparation only;
- `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, and `file` observables.

All other standard and custom types are rejected, including observed data,
sightings, reports, notes, opinions, groupings, infrastructure, locations,
vulnerabilities, courses of action, intrusion sets, malware analysis, process,
network traffic, artifacts, email messages, user accounts, registry keys,
autonomous systems, certificates, and extension definitions. Custom
properties, extensions, STIX 2.0, malformed IDs, unsafe timestamps, literal
control characters, oversized fields, and granular markings are also rejected.

Only allow-listed fields enter the immutable staged representation. A
`SourceRecord.raw_payload` contains that safe representation, never the full
bundle, envelope, or original object. Every supported type has an exact key
allow-list, including exact nested shapes for mapped observables, markings,
external references, hashes, observable mappings, kill-chain phases, and text
arrays. Arbitrary extra keys are rejected rather than ignored. External
references retain only a lowercase ASCII canonical `source_name` token and an
optional bounded plain `external_id` token; URLs, credentials, query or
fragment syntax, paths, tracking parameters, descriptions, hashes, and vendor
payloads are rejected. External descriptions are deliberately omitted in
P9-10 because this unit has no entity-specific control that can reliably
separate narrative from commands, exploit instructions, payload URLs, or
credentials. File staging contains approved hashes only.

Each accepted object uses one `SourceRecord` for its source and STIX ID. Its URL
is constructed only from the fixed policy base and validated ID, and it is
never requested. The content hash covers only canonical safe staged fields.
The record has no publication item, is not a primary reference, and is not
exposed by a public API.

The validation dataclasses are public Python types and are therefore never a
trust boundary. Before persistence, the service independently canonicalizes
every staged object from its safe payload, revalidates its exact schema and
identity, recomputes its content hash, reconstructs every mapped observable,
and compares all normalized identity, value, algorithm, confidence, observed
time, and deterministic context fields. It deep-freezes a new safe payload and
persists only that reconstructed copy. Caller-owned nested containers, hashes,
observables, counters, and ordering are not used as persistence authority.

## Markings and relationships

Object-level marking references are retained and must resolve within the same
validated document or to explicitly supplied same-source staged metadata.
Standard STIX 2.1 TLP definitions are accepted only when both their standard ID
and definition match and the policy explicitly permits that level. Unknown,
custom, inconsistent, missing, cross-source, or unapproved TLP markings reject
the document. Statement markings default to disabled; a policy may enable
bounded control-free statement text while retaining its reference.

Granular markings are conservatively rejected because the safe mapper does not
retain arbitrary property selectors. Removing those selectors would risk
discarding field-level handling restrictions.

The exact supported standard marking IDs are:

- TLP:WHITE: `marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9`
- TLP:GREEN: `marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da`
- TLP:AMBER: `marking-definition--f88d31f6-486f-44da-b317-01333bde0b82`
- TLP:RED: `marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed`

Relationships are validated only after the other objects. `source_ref` and
`target_ref` must resolve inside the document or to an existing `SourceRecord`
for the same approved source. The allowed vocabulary is `indicates`, `uses`,
`attributed-to`, `targets`, and `related-to`; time ordering and self-reference
rules are enforced. Only safe relationship fields are staged. No P9-11 entity
or normalized threat relationship is created.

Caller-provided `existing_objects` mappings are never treated as trusted
database evidence. Their bounded safe trees are revalidated and reduced to the
minimum canonical identity needed for the reference. Existing markings require
an exact ID, `marking-definition` type, STIX 2.1 metadata, and either the exact
policy-approved standard TLP ID/level pair or an enabled canonical bounded
statement. Existing relationship endpoints require an exact supported ID/type
pair and STIX 2.1 metadata; marking definitions, relationship objects, custom
types, and unsupported types cannot be endpoints.

The persistence boundary independently treats the database as final authority
for external references. A same-source SourceRecord must have the exact external
ID, canonical policy-derived URL and URL hash, be `processed` and `present`,
have no safe error, contain a dictionary safe payload that passes the complete
per-type verifier, and carry a canonical lowercase SHA-256 content hash that
exactly matches a recomputation over that payload. Failed, pending, missing,
unavailable, malformed, wrong-type, cross-source, hash-inconsistent, or
extra-field records cannot satisfy a marking or relationship reference and are
never repaired implicitly.

Every current or reference SourceRecord must remain dedicated P9-10 staging
metadata: `intelligence_item_id` is null and `is_primary_reference` is false.
The stored source-published and source-modified timestamps must exactly agree,
in UTC, with the canonical safe `created` and `modified` fields; non-versioned
objects must have neither. Collection, first-seen, last-seen, and processed
audit timestamps must be timezone-aware, processed records require a
`last_processed_at`, and first-seen cannot follow last-seen. Ownership or audit
metadata failures are sanitized and never repaired or detached automatically.

## Observable mapping

Direct IPv4, IPv6, domain, URL, and file-hash SCOs pass through the existing
P9-08 normalization boundary. Approved file algorithms are MD5, SHA-1,
SHA-256, and SHA-512, mapped to `md5`, `sha1`, `sha256`, and `sha512`.

Indicator SDOs accept only one officially valid STIX 2.1 equality comparison
against one supported observable path. Boolean combinations, qualifiers,
pattern operators, wildcards, indexes, multiple observations or values, and
other object paths are rejected. Patterns are parsed and normalized, never
executed or used for active validation.

Accepted observables create or reuse `Indicator` by `identity_sha256` and
source-record-specific `IndicatorProvenance`. STIX confidence 0 through 100 is
converted to project Decimal 0 through 1. Observation ranges expand safely,
but existing lifecycle status is never changed. A `false_positive` indicator
suppresses automated provenance. No P9-09 publication relationship is created,
and arbitrary descriptions never populate analyst-authored global context.

Each safe staged object with mapped observables also stores a deterministic,
immutable identity list containing only `observable_type`, `hash_algorithm`,
and `identity_sha256`. It participates in the safe content hash and allows
updates to compare normalized IOC identity without reparsing stored patterns.

A STIX Indicator with `revoked: true` is still validated and staged, but it
cannot create or mutate a local Indicator or IndicatorProvenance. The sanitized
result increments `revoked_indicators_suppressed`. A newer version becoming
revoked may update its SourceRecord when all other invariants hold, while every
local lifecycle state—including active, inactive, archived, revoked, and
false-positive—remains unchanged.

## Versions, idempotency, and transactions

All duplicate versions in one document are validated, sorted by `modified`
independently of input order, and required to be strictly increasing; only the
latest is staged. Every safely staged version is also retained as immutable
in-memory `validated_versions` lineage; no raw STIX JSON is retained. The
lineage is grouped deterministically by STIX ID and ordered chronologically
within each ID, so reverse document order has the same version result. Equal
version and content is unchanged, equal version with
different safe content is a conflict, a newer version updates, and an older
version is stale without overwrite. Non-versioned marking definitions and SCOs
are unchanged only when their ID and safe content agree; changed content under
the same ID is a conflict.

Before classifying the object currently being reimported as stale, unchanged,
conflicting, or updateable, the importer revalidates its existing SourceRecord:
same source and STIX ID, canonical policy URL and deterministic URL hash,
processed/present/error-free state, complete exact safe-payload schema, and a
recomputed matching content hash. The payload type, ID, and STIX version must
match the incoming staged object. Same-version and non-versioned equality is
then based on the complete canonical safe payload, never only the stored hash.
Validation failure occurs before timestamps, record fields, Indicators,
provenance, or flush are touched. There is no automatic repair or reconciliation
workflow in this unit.

The persistence copy independently revalidates every safe lineage entry,
reruns stable-created, stable-creator, unique-modified, non-versioned duplicate,
and terminal-revocation rules, and derives the latest object tuple again. The
supplied latest tuple must exactly match that derivation. Object counters must
equal the complete lineage length, while relationship and marking counters are
recomputed across all validated versions. Only the latest object per STIX ID is
persisted, so two accepted versions report two inspected and validated objects
but create one SourceRecord. The copy also requires non-relationship latest
objects before relationships and independently resolved same-document or
same-source references. Claimed lineage, counters, latest selection, and
relationship or marking approval are not trusted.

Versions of one object must retain the same `created` timestamp and the same
`created_by_ref`, including stable absence. Modified timestamps remain unique.
Revocation is terminal: only the latest version may be revoked, and no version
may follow a revoked stored version. These invariants are also checked against
existing safe SourceRecord metadata; missing or malformed expected metadata is
a sanitized consistency failure.

Because one source and STIX ID currently map to one SourceRecord, a newer
version may not change its mapped observable identity set. Such a change is
rejected before record, Indicator, or provenance mutation. Confidence, label,
alias, marking, validity, timestamp, and syntactic pattern
changes remain updateable when the normalized identity set is stable. No STIX
version-history schema exists yet; supporting identity-changing history would
require a separate reviewed design.

The import service uses a caller-supplied SQLAlchemy session and flushes only to
obtain identities required by dependent rows. It never commits or rolls back.
The caller therefore owns one atomic transaction covering staged objects,
relationships, indicators, and provenance. Results contain immutable bounded
counters only; they do not return values, patterns, JSON, paths, SQL, headers,
credentials, or third-party exceptions.
