# C03A Threat Knowledge and STIX Persistence

## Checkpoint and bounded scope

C03A starts from `02f1d206a0765d014db41c27f5eecdfb202288df` on `dev`. It implements B4-01, B4-02, B3-06, and B4-03 only. B4-04 remains deferred because the authoritative workbook has a circular B4-04/B8-05 dependency and authorization depends on B7-03/C06. No API, frontend, authentication, temporary authorization, live source activation, or deployment registration is part of this pass.

## Reduced model and exact provenance

Migration `e91f4c2a7b60` adds exactly `threat_entities`, `threat_entity_aliases`, and `threat_relationships`. The entity vocabulary is `threat_actor`, `campaign`, `malware_family`, and `attack_technique`. Entity and relationship identities are deterministic SHA-256 values over approved source slug and canonical STIX ID. Names, aliases, labels, keywords, similarity, and ordering never establish identity or attribution.

Composite foreign keys bind normalized rows to the exact `IntelligenceSource` and `SourceRecord`, aliases to parent provenance, and relationship endpoints to the relationship source. Public UUIDs support later API use without creating an API here. Only bounded names, aliases, confidence, STIX timestamps, and revocation are retained. Descriptions, malware samples, binaries, payloads, code, operational instructions, and raw bundles are excluded from normalized threat tables.

Aliases use Unicode normalization, whitespace collapse, and case-insensitive identity. Newer versions reconcile the bounded set deterministically. An `attack-pattern` maps only with one non-conflicting `mitre-attack` external reference whose ID is `T####` or `T####.###`; other patterns remain safe SourceRecord metadata.

## Approved relationships

Only these combinations normalize:

- threat actor `uses` malware family or attack technique;
- campaign `uses` malware family or attack technique;
- malware family `uses` attack technique;
- campaign `attributed-to` threat actor.

Self-reference and unsupported combinations between two normalized endpoints fail closed. First-time relationships outside the reduced domain, or with one normalized endpoint, remain SourceRecord-only. A newer version of an already-normalized same-source relationship cannot remove that mapping by changing either endpoint outside the reduced domain: the exact source and canonical relationship STIX ID are checked, and a match fails closed without deleting or rewriting normalized state. Existing endpoints may be materialized only from revalidated committed same-source safe SourceRecords, without network reconstruction or cross-source resolution.

## Import transaction and lifecycle

`StixBundleImportService` owns neither commit nor rollback. In one caller-owned transaction it revalidates the document and references, stages SourceRecords, persists entities and reconciles aliases, then persists relationships after endpoints exist. It preserves indicator behavior and returns bounded SourceRecord outcomes plus entity, alias, relationship, unmapped, and stale counters.

Newer versions update mutable fields. Same-version same-content is unchanged; same-version conflict fails; stale input cannot overwrite state. Source, STIX ID, entity type, ATT&CK ID, created time, and endpoint identity are immutable. Revocation remains auditable and cannot be silently reactivated.

Before any normalized update, the importer retains the independently revalidated previous canonical safe SourceRecord payload and proves that the current entity, complete alias set, or relationship is its exact normalized representation. The comparison includes source and SourceRecord provenance, deterministic identity, bounded mutable values, timestamps, revocation, alias display and normalized values, relationship type, and endpoint STIX identities. A mismatch fails closed without repairing or overwriting the conflicting normalized state. The same fail-closed rule applies before a relationship is counted as unmapped when an exact same-source normalized relationship already exists; caller rollback restores the staged SourceRecord version while leaving its prior normalized provenance consistent. Missing normalized rows may still be materialized from a valid existing same-source SourceRecord, including pre-C03 records and approved relationship endpoints; this reconstruction is database-only and never uses the network.

## Inactive TAXII handler

The C03A `SourceHandler` accepts only an immutable validated `ApprovedTaxiiCollectionPolicy` registry and calls `TaxiiCollectionClient` directly. Complete bounded collection and validation finish before the persistence transaction. The transaction verifies the exact enabled JSON source, slug, and policy base URL, then commits source data and run-linked evidence atomically.

Progress is `CHECKPOINT` / `CONTENT_HASH`: SHA-256 over every canonical safe validated version in deterministic order, never response bytes. Only success or no-change proposes progress. Stale, partial, failed, or conflicting runs cannot advance it. Reconstruction reads committed run evidence and never refetches.

Database failures caught at the import boundary use a sanitized persistence-specific exception. The handler therefore classifies them as transient `persistence_contention` failures using the existing shared classifier contract. Threat-state conflicts and malformed or unsupported STIX remain non-transient `validation_failure` results. Neither classification exposes database or upstream exception text, and failed transactions write no progress proposal or committed execution evidence.

`PRODUCTION_STIX_SOURCE_POLICIES`, `PRODUCTION_TAXII_COLLECTION_POLICIES`, and `DEFAULT_SOURCE_HANDLERS` remain immutable and empty. Missing policy is `disabled`; `licence_required` is reserved for an explicit developer-controlled fixed identity and evaluated before client construction. Synthetic immutable policies are only for tests and later controlled staging.

Existing fixed HTTPS host/path/collection, no-discovery, redirect rejection, `trust_env=False`, timeout, deadline, byte, page, object, JSON tree, alias, external-reference, and relationship bounds remain enforced. Evidence and diagnostics are sanitized.

## Validation and limitations

Focused model, migration, disposable-PostgreSQL-gated, STIX import, handler, existing STIX/TAXII, orchestration, Alembic, and documentation tests cover these boundaries. The PostgreSQL test skips only without its explicit disposable URL.

Accepted limitations are the reduced vocabulary, no TAXII discovery or `added_after`, no cross-source merge, no graph scoring, and deferred B4-04 authorization/API/UI work. No live request, source activation, deployment registration, API change, or frontend change occurred.
