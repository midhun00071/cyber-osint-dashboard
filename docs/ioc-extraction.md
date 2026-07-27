# IOC extraction

## Implemented boundary

P9-09 provides deterministic, offline extraction of defensive observable
metadata from an existing normalized publication. It reads only
`IntelligenceItem.canonical_title` and `IntelligenceItem.summary` for
`security_advisory` and `threat_report` items. It does not read
`SourceRecord.raw_payload`, article bodies, authors, categories, headers,
attachments, or downloaded content.

Supported observable types are IPv4, IPv6, domain, HTTP/HTTPS URL, and file
hash. Hash algorithms are MD5, SHA-1, SHA-256, and SHA-512. Every accepted value
passes through the P9-08 `normalize_observable` boundary before persistence.

## Conservative extraction rules

Extraction processes URLs, IP addresses, hashes, and domains in that order.
Every bounded token using `scheme://` or `scheme[:]//` protects its full span:
contained domains, IP addresses, and hashes are suppressed even when the URI is
unsupported, malformed, credentialed, excluded, or otherwise rejected as a
URL. Email suppression is a conservative lexical boundary, not email
validation: a bounded non-whitespace token containing a non-final `@` protects
all contained domain, IPv4, IPv6, and hash candidates. This includes malformed,
overlong, deeply nested, uppercase, defanged, plus-addressed, `mailto:`, and
bracketed IP-address forms. The token is neither parsed nor retained. A separate
contextual domain or IP elsewhere in the text remains eligible. Results are
deduplicated by the normalized identity fingerprint while preserving first
occurrence order. The highest deterministic confidence is retained; a title
occurrence wins an otherwise equal tie.

The supported defanging forms are deliberately narrow: `hxxp://`, `hxxps://`,
the same schemes or HTTP/HTTPS with `[:]`, and `[.]` or `(.)` separators for
domains and IPv4 addresses. Mixed or malformed defanging is rejected. Refanging
is local string normalization only; it never causes a connection.

Literal IP addresses and domains require nearby IOC-specific context. Defanged
forms provide stronger intent. Automatic IP extraction accepts only globally
routable addresses and rejects private, loopback, link-local, multicast,
unspecified, reserved, and documentation ranges. Canonical domain, IPv4, and
IPv6 candidates are rejected when they match an excluded publication/source
host. Literal dotted versions immediately marked as a version, release, build,
or `v` value are not treated as IP addresses; explicit IP context and supported
defanged notation remain eligible. Domain controls reject complete email
components, package/module/library/dependency/import tokens, filenames, files,
filesystem paths, publication/source hosts, and obvious example or local
suffixes. Immediate explicit `domain`, `host`, `C2`, or `URL` context and
supported defanged notation remain eligible subject to the other exclusions.
Hashes require an algorithm label or specific IOC/hash context and reject
repeated-character placeholders. URLs reject credentials, malformed ports,
excluded publication/source URLs and hosts, and non-global IP hosts. URL-aware
punctuation handling preserves the closing bracket in a valid bracketed IPv6
authority while still removing surrounding prose punctuation.

These rules establish only that a publication `mentioned` an observable. They
do not establish maliciousness, activity, confirmation, exploitation,
attribution, threat-actor ownership, or campaign association.

## Processing bounds

- Combined title and summary input: 12,000 characters.
- Total candidates inspected: 100.
- Per-type candidates: 20 URLs, 25 IPv4, 20 IPv6, 20 hashes, and 25 domains.
- Context window: 120 characters on each side of a match.
- Stored relationship/provenance context: at most 500 characters with
  whitespace collapsed.
- Literal Unicode control characters are rejected.

An overlong input is rejected without processing a prefix. Candidate-limit
exhaustion is reported as bounded processing with structured counts. Output
ordering and context are deterministic for identical input.

## Persistence and provenance

The `intelligence_item_indicators` association uses the publication and
indicator IDs as a composite primary key. Automatic extraction writes only
`relationship_type = mentioned` and
`extraction_method = deterministic_text`, with bounded confidence, context, and
first/last observation timestamps. Source provenance always identifies the
same approved intelligence source and exact eligible source record.

Canonical indicators are reused by `identity_sha256`. Repeat processing reuses
the publication relationship and exact source-record provenance. A second
source record for the same publication can reuse the relationship while adding
its own provenance. Earliest and latest observations are preserved, confidence
only increases to the greater deterministic value, and existing lifecycle
status and analyst-authored global context are not overwritten.

An indicator already marked `false_positive` is left unchanged and suppresses
automatic relationship and provenance creation or update. The service returns
sanitized immutable counters and leaves commit and rollback to its caller.

## Explicit exclusions and limitations

Extraction performs no DNS resolution, HTTP request, socket operation, active
validation, scanning, probing, file retrieval, attachment retrieval, malware
retrieval, or external enrichment. It exposes no API, frontend action, CLI,
scheduler, or startup processing path.

P9-09 does not automatically delete historical indicators, relationships, or
provenance when normalized source text later changes. This audit-preserving
limitation avoids destructive reconciliation without a separately reviewed
design. P9-10 and later enrichment, analyst-review, reconciliation, and public
presentation tasks remain unimplemented.
