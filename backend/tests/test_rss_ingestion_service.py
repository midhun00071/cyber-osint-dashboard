from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import operators

from app.ingestion.normalizers.rss import normalize_rss_feed
from app.ingestion.services.article_identity_service import (
    ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
    ARTICLE_URL_IDENTIFIER_NAMESPACE,
)
from app.ingestion.services.rss_ingestion_service import (
    RSS_SOURCE_BASE_URL,
    RSS_SOURCE_NAME,
    RSS_SOURCE_SLUG,
    RssIngestionService,
    RssPersistenceError,
)
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
)


OBSERVED_AT = datetime(2026, 7, 9, 10, 0, tzinfo=UTC)
UPDATED_AT = datetime(2026, 7, 10, 10, 0, tzinfo=UTC)


class ScalarResult:
    def __init__(self, value: object | None):
        self.value = value

    def scalar_one_or_none(self) -> object | None:
        return self.value


class FakeSession:
    def __init__(self, *, fail_flush: bool = False):
        self.fail_flush = fail_flush
        self.flushes = 0
        self.commits = 0
        self.rollbacks = 0
        self.sources: list[IntelligenceSource] = []
        self.items: list[IntelligenceItem] = []
        self.source_records: list[SourceRecord] = []
        self.identifiers: list[IntelligenceItemIdentifier] = []

    def add(self, record: object) -> None:
        if isinstance(record, IntelligenceSource):
            collection = self.sources
        elif isinstance(record, IntelligenceItem):
            collection = self.items
        elif isinstance(record, SourceRecord):
            collection = self.source_records
        elif isinstance(record, IntelligenceItemIdentifier):
            collection = self.identifiers
        else:
            raise AssertionError(f"Unexpected record type: {type(record)}")
        if record not in collection:
            collection.append(record)

    def flush(self) -> None:
        if self.fail_flush:
            raise SQLAlchemyError(
                "postgresql://private-user:private-password@private-host/database"
            )
        self.flushes += 1
        for collection in (self.sources, self.items, self.source_records, self.identifiers):
            for index, record in enumerate(collection, start=1):
                if getattr(record, "id", None) is None:
                    record.id = index
                if isinstance(record, SourceRecord):
                    if record.source is not None:
                        record.source_id = record.source.id
                    if record.intelligence_item is not None:
                        record.intelligence_item_id = record.intelligence_item.id
                if isinstance(record, IntelligenceItemIdentifier):
                    if record.intelligence_item is not None:
                        record.intelligence_item_id = record.intelligence_item.id
                    if record.source is not None:
                        record.source_id = record.source.id
                    if record.source_record is not None:
                        record.source_record_id = record.source_record.id

    def execute(self, statement: Any) -> ScalarResult:
        entity = statement.column_descriptions[0]["entity"]
        criteria = list(statement._where_criteria)
        if entity is IntelligenceSource:
            return ScalarResult(
                next((source for source in self.sources if source.slug == RSS_SOURCE_SLUG), None)
            )
        if entity is SourceRecord:
            source_id = criterion_value(criteria, "source_id")
            external_id = criterion_value(criteria, "source_external_id")
            url_hash = criterion_value(criteria, "canonical_url_hash")
            return ScalarResult(
                next(
                    (
                        record
                        for record in self.source_records
                        if record.source_id == source_id
                        and (
                            (
                                external_id is not None
                                and record.source_external_id == external_id
                            )
                            or (
                                url_hash is not None
                                and record.canonical_url_hash == url_hash
                            )
                        )
                    ),
                    None,
                )
            )
        if entity is IntelligenceItemIdentifier:
            namespace = criterion_value(criteria, "namespace")
            normalized_value = criterion_value(criteria, "normalized_value")
            source_is_null = any(
                getattr(getattr(criterion, "left", None), "name", None) == "source_id"
                and getattr(criterion, "operator", None) is operators.is_
                for criterion in criteria
            )
            matches = [
                identifier
                for identifier in self.identifiers
                if (not source_is_null or identifier.source_id is None)
                and identifier.namespace == namespace
                and identifier.normalized_value == normalized_value
            ]
            if len(matches) > 1:
                raise AssertionError("Ambiguous identifier query in fake session.")
            return ScalarResult(matches[0] if matches else None)
        raise AssertionError(f"Unexpected select entity: {entity}")

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def criterion_value(criteria: list[object], column_name: str) -> object:
    for criterion in criteria:
        left = getattr(criterion, "left", None)
        if getattr(left, "name", None) != column_name:
            continue
        right = getattr(criterion, "right", None)
        if hasattr(right, "value"):
            return right.value
    return None


def normalized(
    guid: str = "CERT-EU-SA2026-001",
    *,
    title: str = "CERT-EU Security Advisory",
    link: str = "https://cert.europa.eu/publications/security-advisories/2026-001",
):
    body = f"""<rss><channel><item>
<guid>{guid}</guid>
<title>{title}</title>
<link>{link}</link>
<description>Safe advisory summary.</description>
<pubDate>Wed, 08 Jul 2026 08:30:00 GMT</pubDate>
</item></channel></rss>""".encode()
    return normalize_rss_feed(body)[0]


def persist_new(session: FakeSession, record=None):
    return RssIngestionService(session).persist(  # type: ignore[arg-type]
        record or normalized(),
        observed_at=OBSERVED_AT,
    )


def add_existing_advisory(
    session: FakeSession,
    *,
    title: str = "Existing advisory",
    url_hash: str = "1" * 64,
    title_hash: str = "2" * 64,
    item_type: str = "security_advisory",
    status: str = "active",
    primary_reference: bool = True,
    with_identifiers: bool = True,
):
    source = IntelligenceSource(
        slug=f"existing-source-{len(session.sources) + 1}",
        name=f"Existing Source {len(session.sources) + 1}",
        source_type="rss",
        base_url="https://example.com/feed",
        is_enabled=True,
    )
    item = IntelligenceItem(
        item_type=item_type,
        canonical_title=title,
        canonical_url="https://example.com/advisory",
        collected_at=OBSERVED_AT,
        last_seen_at=OBSERVED_AT,
        status=status,
        geographic_scope="global",
        uae_relevance_status="unknown",
        uae_relevance_method="unassigned",
        analyst_review_status="pending",
    )
    source_record = SourceRecord(
        source=source,
        intelligence_item=item,
        source_external_id=f"existing-{len(session.source_records) + 1}",
        source_url="https://example.com/advisory",
        canonical_url_hash=url_hash,
        content_hash="0" * 64,
        is_primary_reference=primary_reference,
        payload_collected_at=OBSERVED_AT,
        first_seen_at=OBSERVED_AT,
        last_seen_at=OBSERVED_AT,
        processing_status="processed",
        upstream_status="present",
    )
    session.add(source)
    session.add(item)
    session.add(source_record)
    url_identifier = None
    title_identifier = None
    if with_identifiers:
        url_identifier = IntelligenceItemIdentifier(
            intelligence_item=item,
            source=None,
            source_record=None,
            namespace=ARTICLE_URL_IDENTIFIER_NAMESPACE,
            identifier_value=url_hash,
            normalized_value=url_hash,
            is_primary=False,
        )
        title_identifier = IntelligenceItemIdentifier(
            intelligence_item=item,
            source=None,
            source_record=None,
            namespace=ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
            identifier_value=title_hash,
            normalized_value=title_hash,
            is_primary=False,
        )
        session.add(url_identifier)
        session.add(title_identifier)
    session.flush()
    return item, source_record, url_identifier, title_identifier


def fingerprint_identifiers(
    session: FakeSession,
    namespace: str | None = None,
) -> list[IntelligenceItemIdentifier]:
    identifiers = [
        identifier
        for identifier in session.identifiers
        if identifier.source_id is None
        and identifier.namespace
        in {ARTICLE_URL_IDENTIFIER_NAMESPACE, ARTICLE_TITLE_IDENTIFIER_NAMESPACE}
    ]
    if namespace is not None:
        identifiers = [
            identifier for identifier in identifiers if identifier.namespace == namespace
        ]
    return identifiers


def source_record_snapshot(source_record: SourceRecord) -> dict[str, object]:
    return {
        "source_external_id": source_record.source_external_id,
        "source_url": source_record.source_url,
        "canonical_url_hash": source_record.canonical_url_hash,
        "content_hash": source_record.content_hash,
        "raw_payload": source_record.raw_payload,
        "payload_collected_at": source_record.payload_collected_at,
        "first_seen_at": source_record.first_seen_at,
        "last_seen_at": source_record.last_seen_at,
        "last_processed_at": source_record.last_processed_at,
    }


def item_snapshot(item: IntelligenceItem) -> dict[str, object]:
    return {
        "canonical_title": item.canonical_title,
        "summary": item.summary,
        "canonical_url": item.canonical_url,
        "source_published_at": item.source_published_at,
        "source_modified_at": item.source_modified_at,
        "last_seen_at": item.last_seen_at,
    }


def test_fixed_rss_source_is_created_once_and_reused() -> None:
    session = FakeSession()

    first = persist_new(session)
    second = persist_new(
        session,
        normalized(
            "CERT-EU-SA2026-002",
            title="Second CERT-EU Security Advisory",
            link="https://cert.europa.eu/publications/security-advisories/2026-002",
        ),
    )

    assert first.outcome == "created"
    assert second.outcome == "created"
    assert len(session.sources) == 1
    source = session.sources[0]
    assert source.slug == RSS_SOURCE_SLUG
    assert source.name == RSS_SOURCE_NAME
    assert source.source_type == "rss"
    assert source.base_url == RSS_SOURCE_BASE_URL
    assert source.is_enabled is True


def test_conflicting_source_configuration_fails_safely() -> None:
    session = FakeSession()
    session.add(
        IntelligenceSource(
            slug=RSS_SOURCE_SLUG,
            name="Wrong",
            source_type="rss",
            base_url=RSS_SOURCE_BASE_URL,
            is_enabled=True,
        )
    )

    with pytest.raises(RssPersistenceError, match="conflicts"):
        RssIngestionService(session).ensure_source()  # type: ignore[arg-type]


def test_new_advisory_creates_security_advisory_item_and_primary_source_record() -> None:
    session = FakeSession()
    record = normalized()

    result = persist_new(session, record)

    assert result.outcome == "created"
    assert len(session.items) == 1
    assert len(session.source_records) == 1
    assert len(session.identifiers) == 2
    item = session.items[0]
    source_record = session.source_records[0]
    assert item.item_type == "security_advisory"
    assert item.canonical_title == record.canonical_title
    assert item.summary == record.summary
    assert item.status == "active"
    assert item.data_confidence == Decimal("0.900")
    assert item.uae_relevance_status == "unknown"
    assert item.uae_relevance_method == "automatic"
    assert item.uae_relevance_reason == "No direct UAE evidence found."
    assert item.analyst_review_status == "pending"
    assert source_record.intelligence_item is item
    assert source_record.is_primary_reference is True
    assert source_record.source_external_id == record.source_external_id
    assert source_record.canonical_url_hash == record.canonical_url_hash
    assert source_record.processing_status == "processed"
    assert source_record.upstream_status == "present"
    assert {
        (identifier.namespace, identifier.normalized_value, identifier.is_primary)
        for identifier in session.identifiers
    } == {
        (ARTICLE_URL_IDENTIFIER_NAMESPACE, record.canonical_url_hash, False),
        (ARTICLE_TITLE_IDENTIFIER_NAMESPACE, record.normalized_title_hash, False),
    }


def test_repeated_identical_advisory_is_unchanged_without_duplicates() -> None:
    session = FakeSession()
    record = normalized()
    first = persist_new(session, record)

    second = RssIngestionService(session).persist(  # type: ignore[arg-type]
        record,
        observed_at=UPDATED_AT,
    )

    assert first.outcome == "created"
    assert second.outcome == "unchanged"
    assert len(session.items) == 1
    assert len(session.source_records) == 1
    assert len(session.identifiers) == 2
    assert session.items[0].last_seen_at == UPDATED_AT
    assert session.source_records[0].first_seen_at == OBSERVED_AT


def test_existing_record_can_be_found_by_url_hash_when_external_id_changes() -> None:
    session = FakeSession()
    first = normalized()
    persist_new(session, first)
    updated = replace(first, source_external_id="CERT-EU-SA2026-001-v2", content_hash="a" * 64)

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        updated,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "updated"
    assert len(session.items) == 1
    assert len(session.identifiers) == 2
    assert session.source_records[0].source_external_id == "CERT-EU-SA2026-001-v2"


def test_changed_hash_updates_source_owned_fields_and_preserves_analyst_fields() -> None:
    session = FakeSession()
    first = normalized()
    persist_new(session, first)
    item = session.items[0]
    source_record = session.source_records[0]
    item.uae_relevance_status = "confirmed"
    item.uae_relevance_confidence = Decimal("0.750")
    item.uae_relevance_reason = "Analyst-owned reason"
    item.uae_relevance_method = "manual"
    item.analyst_review_status = "reviewed"
    original_collected_at = item.collected_at
    original_first_seen = source_record.first_seen_at
    updated = replace(
        first,
        canonical_title="Updated advisory",
        summary="Updated summary",
        content_hash="b" * 64,
        raw_payload={"source_id": first.source_external_id, "updated": True},
    )

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        updated,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "updated"
    assert item.canonical_title == "Updated advisory"
    assert item.summary == "Updated summary"
    assert source_record.content_hash == "b" * 64
    assert next(
        identifier
        for identifier in session.identifiers
        if identifier.namespace == ARTICLE_TITLE_IDENTIFIER_NAMESPACE
    ).normalized_value == updated.normalized_title_hash
    assert item.uae_relevance_status == "confirmed"
    assert item.uae_relevance_reason == "Analyst-owned reason"
    assert item.uae_relevance_method == "manual"
    assert item.analyst_review_status == "reviewed"
    assert item.collected_at == original_collected_at
    assert source_record.first_seen_at == original_first_seen


def test_new_rss_record_receives_automatic_uae_classification() -> None:
    session = FakeSession()
    record = normalized(title="Dubai defensive security advisory")

    result = persist_new(session, record)

    assert result.outcome == "created"
    item = session.items[0]
    assert item.geographic_scope == "uae"
    assert item.uae_relevance_status == "confirmed"
    assert item.uae_relevance_method == "automatic"
    assert item.uae_relevance_reason == "Matched emirate name: Dubai."


def test_external_id_and_url_hash_conflict_fails_without_auto_merge() -> None:
    session = FakeSession()
    first = normalized(
        "CERT-EU-SA2026-001",
        title="First advisory",
        link="https://cert.europa.eu/publications/a",
    )
    second = normalized(
        "CERT-EU-SA2026-002",
        title="Second advisory",
        link="https://cert.europa.eu/publications/b",
    )
    persist_new(session, first)
    persist_new(session, second)
    conflicting = replace(first, canonical_url_hash=second.canonical_url_hash)

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        conflicting,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "failed"
    assert "different source records" in result.message
    assert len(session.items) == 2


def test_existing_non_advisory_record_fails_safely() -> None:
    session = FakeSession()
    record = normalized()
    persist_new(session, record)
    session.items[0].item_type = "vulnerability"

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        record,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "failed"
    assert "security advisory" in result.message


def test_same_global_url_reuses_existing_item_with_non_primary_source_record() -> None:
    session = FakeSession()
    record = normalized()
    existing_item, existing_source_record, _, _ = add_existing_advisory(
        session,
        url_hash=record.canonical_url_hash,
        title_hash="9" * 64,
    )

    result = persist_new(session, record)

    assert result.outcome == "created"
    assert result.message == "A new source record was linked to an existing advisory."
    assert len(session.items) == 1
    assert len(session.source_records) == 2
    new_source_record = session.source_records[-1]
    assert new_source_record.intelligence_item is existing_item
    assert new_source_record.is_primary_reference is False
    assert existing_source_record.is_primary_reference is True


def test_url_and_title_identifiers_on_same_item_reuse_existing_item() -> None:
    session = FakeSession()
    record = normalized()
    existing_item, _, _, _ = add_existing_advisory(
        session,
        url_hash=record.canonical_url_hash,
        title_hash=record.normalized_title_hash,
    )

    result = persist_new(session, record)

    assert result.outcome == "created"
    assert len(session.items) == 1
    assert session.source_records[-1].intelligence_item is existing_item


def test_title_only_match_fails_without_mutation() -> None:
    session = FakeSession()
    record = normalized()
    add_existing_advisory(
        session,
        url_hash="8" * 64,
        title_hash=record.normalized_title_hash,
    )
    counts = (len(session.items), len(session.source_records), len(session.identifiers))

    result = persist_new(session, record)

    assert result.outcome == "failed"
    assert "possible duplicate" in result.message
    assert (len(session.items), len(session.source_records), len(session.identifiers)) == counts


def test_conflicting_global_url_and_title_identifiers_fail_without_merge() -> None:
    session = FakeSession()
    record = normalized()
    add_existing_advisory(session, url_hash=record.canonical_url_hash, title_hash="3" * 64)
    add_existing_advisory(session, url_hash="4" * 64, title_hash=record.normalized_title_hash)
    counts = (len(session.items), len(session.source_records), len(session.identifiers))

    result = persist_new(session, record)

    assert result.outcome == "failed"
    assert "identity signals conflict" in result.message
    assert (len(session.items), len(session.source_records), len(session.identifiers)) == counts


def test_source_record_pointing_to_different_item_than_global_identity_fails() -> None:
    session = FakeSession()
    record = normalized()
    persist_new(session, record)
    original_record = session.source_records[0]
    other_item = IntelligenceItem(
        item_type="security_advisory",
        canonical_title="Other item",
        collected_at=OBSERVED_AT,
        last_seen_at=OBSERVED_AT,
        status="active",
        geographic_scope="global",
        uae_relevance_status="unknown",
        uae_relevance_method="unassigned",
        analyst_review_status="pending",
    )
    session.add(other_item)
    session.flush()
    original_record.intelligence_item = other_item

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        record,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "failed"
    assert "identity signals conflict" in result.message
    assert original_record.intelligence_item is other_item


def test_update_url_or_title_collision_fails_before_mutation() -> None:
    session = FakeSession()
    first = normalized()
    persist_new(session, first)
    item = session.items[0]
    source_record = session.source_records[0]
    original_title = item.canonical_title
    original_url = item.canonical_url
    original_url_hash = source_record.canonical_url_hash
    original_content_hash = source_record.content_hash
    colliding = normalized(
        "CERT-EU-SA2026-999",
        title="Different advisory",
        link="https://cert.europa.eu/publications/security-advisories/collision",
    )
    add_existing_advisory(
        session,
        url_hash=colliding.canonical_url_hash,
        title_hash=colliding.normalized_title_hash,
    )
    updated = replace(
        first,
        canonical_title=colliding.canonical_title,
        canonical_url=colliding.canonical_url,
        canonical_url_hash=colliding.canonical_url_hash,
        normalized_title_hash=colliding.normalized_title_hash,
        content_hash="d" * 64,
    )

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        updated,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "failed"
    assert item.canonical_title == original_title
    assert item.canonical_url == original_url
    assert source_record.canonical_url_hash == original_url_hash
    assert source_record.content_hash == original_content_hash


def test_non_advisory_global_identity_match_fails_safely() -> None:
    session = FakeSession()
    record = normalized()
    add_existing_advisory(
        session,
        url_hash=record.canonical_url_hash,
        title_hash=record.normalized_title_hash,
        item_type="vulnerability",
    )

    result = persist_new(session, record)

    assert result.outcome == "failed"
    assert "identity signals conflict" in result.message


def test_inactive_advisory_global_identity_match_fails_safely() -> None:
    session = FakeSession()
    record = normalized()
    add_existing_advisory(
        session,
        url_hash=record.canonical_url_hash,
        title_hash=record.normalized_title_hash,
        status="archived",
    )

    result = persist_new(session, record)

    assert result.outcome == "failed"
    assert "identity signals conflict" in result.message


def test_repeated_processing_does_not_create_duplicate_identifier_rows() -> None:
    session = FakeSession()
    record = normalized()

    persist_new(session, record)
    RssIngestionService(session).persist(  # type: ignore[arg-type]
        record,
        observed_at=UPDATED_AT,
    )

    assert len(session.identifiers) == 2
    assert all(identifier.is_primary is False for identifier in session.identifiers)


@pytest.mark.parametrize(
    ("namespace", "changed_value"),
    [
        (ARTICLE_URL_IDENTIFIER_NAMESPACE, "7" * 64),
        (ARTICLE_TITLE_IDENTIFIER_NAMESPACE, "6" * 64),
    ],
)
def test_duplicate_item_identifier_rows_fail_before_mutation(
    namespace: str,
    changed_value: str,
) -> None:
    session = FakeSession()
    first = normalized()
    persist_new(session, first)
    item = session.items[0]
    source_record = session.source_records[0]
    duplicate = IntelligenceItemIdentifier(
        intelligence_item=item,
        source=None,
        source_record=None,
        namespace=namespace,
        identifier_value=changed_value,
        normalized_value=changed_value,
        is_primary=False,
    )
    session.add(duplicate)
    session.flush()
    original_item = item_snapshot(item)
    original_source_record = source_record_snapshot(source_record)
    original_identifiers = [
        (identifier.namespace, identifier.identifier_value, identifier.normalized_value)
        for identifier in session.identifiers
    ]
    updated = replace(
        first,
        canonical_title="Changed title",
        summary="Changed summary",
        canonical_url="https://cert.europa.eu/publications/security-advisories/changed",
        canonical_url_hash="5" * 64,
        normalized_title_hash="4" * 64,
        content_hash="3" * 64,
        raw_payload={"source_id": first.source_external_id, "changed": True},
    )

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        updated,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "failed"
    assert result.message == "The advisory identity signals conflict with existing records."
    assert item_snapshot(item) == original_item
    assert source_record_snapshot(source_record) == original_source_record
    assert [
        (identifier.namespace, identifier.identifier_value, identifier.normalized_value)
        for identifier in session.identifiers
    ] == original_identifiers
    assert len(session.items) == 1
    assert len(session.source_records) == 1
    assert len(session.identifiers) == 3


def test_unchanged_legacy_record_backfills_missing_fingerprint_identifiers() -> None:
    session = FakeSession()
    record = normalized()
    persist_new(session, record)
    item = session.items[0]
    session.identifiers.clear()
    item.identifiers.clear()

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        record,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "unchanged"
    assert len(session.items) == 1
    assert len(session.source_records) == 1
    identifiers = fingerprint_identifiers(session)
    assert len(identifiers) == 2
    assert {
        (identifier.namespace, identifier.normalized_value, identifier.source_id, identifier.is_primary)
        for identifier in identifiers
    } == {
        (ARTICLE_URL_IDENTIFIER_NAMESPACE, record.canonical_url_hash, None, False),
        (ARTICLE_TITLE_IDENTIFIER_NAMESPACE, record.normalized_title_hash, None, False),
    }


def test_unchanged_legacy_record_backfills_one_missing_fingerprint_identifier() -> None:
    session = FakeSession()
    record = normalized()
    persist_new(session, record)
    item = session.items[0]
    missing = next(
        identifier
        for identifier in session.identifiers
        if identifier.namespace == ARTICLE_TITLE_IDENTIFIER_NAMESPACE
    )
    session.identifiers.remove(missing)
    item.identifiers.remove(missing)

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        record,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "unchanged"
    assert len(fingerprint_identifiers(session, ARTICLE_URL_IDENTIFIER_NAMESPACE)) == 1
    assert len(fingerprint_identifiers(session, ARTICLE_TITLE_IDENTIFIER_NAMESPACE)) == 1
    assert len(fingerprint_identifiers(session)) == 2


def test_existing_record_repairs_outdated_identifier_without_duplicate_rows() -> None:
    session = FakeSession()
    record = normalized()
    persist_new(session, record)
    url_identifier = next(
        identifier
        for identifier in session.identifiers
        if identifier.namespace == ARTICLE_URL_IDENTIFIER_NAMESPACE
    )
    url_identifier.identifier_value = "0" * 64
    url_identifier.normalized_value = "0" * 64

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        record,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "unchanged"
    assert len(fingerprint_identifiers(session, ARTICLE_URL_IDENTIFIER_NAMESPACE)) == 1
    repaired = fingerprint_identifiers(session, ARTICLE_URL_IDENTIFIER_NAMESPACE)[0]
    assert repaired is url_identifier
    assert repaired.normalized_value == record.canonical_url_hash
    assert "0" * 64 not in [
        identifier.normalized_value for identifier in fingerprint_identifiers(session)
    ]


def test_safe_title_and_url_update_repairs_fingerprint_rows() -> None:
    session = FakeSession()
    first = normalized()
    persist_new(session, first)
    updated = normalized(
        "CERT-EU-SA2026-001",
        title="Updated CERT-EU Advisory",
        link="https://cert.europa.eu/publications/security-advisories/updated",
    )
    updated = replace(updated, content_hash="e" * 64)

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        updated,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "updated"
    identifiers = fingerprint_identifiers(session)
    assert len(identifiers) == 2
    assert {identifier.normalized_value for identifier in identifiers} == {
        updated.canonical_url_hash,
        updated.normalized_title_hash,
    }
    assert first.canonical_url_hash not in {
        identifier.normalized_value for identifier in identifiers
    }
    assert first.normalized_title_hash not in {
        identifier.normalized_value for identifier in identifiers
    }
    assert all(identifier.is_primary is False for identifier in identifiers)


@pytest.mark.parametrize("collision", ["url", "title"])
def test_update_collision_fails_before_mutation(collision: str) -> None:
    session = FakeSession()
    first = normalized()
    persist_new(session, first)
    item = session.items[0]
    source_record = session.source_records[0]
    candidate = normalized(
        "CERT-EU-SA2026-999",
        title="Collision candidate",
        link="https://cert.europa.eu/publications/security-advisories/collision-candidate",
    )
    if collision == "url":
        add_existing_advisory(
            session,
            url_hash=candidate.canonical_url_hash,
            title_hash="a" * 64,
        )
    else:
        add_existing_advisory(
            session,
            url_hash="b" * 64,
            title_hash=candidate.normalized_title_hash,
        )
    original_item = item_snapshot(item)
    original_source_record = source_record_snapshot(source_record)
    updated = replace(
        first,
        canonical_title=candidate.canonical_title,
        canonical_url=candidate.canonical_url,
        canonical_url_hash=candidate.canonical_url_hash,
        normalized_title_hash=candidate.normalized_title_hash,
        content_hash="c" * 64,
    )

    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        updated,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "failed"
    assert "identity signals conflict" in result.message
    assert item_snapshot(item) == original_item
    assert source_record_snapshot(source_record) == original_source_record


def test_source_scoped_identifier_does_not_affect_global_identity_resolution() -> None:
    session = FakeSession()
    record = normalized()
    source_scoped_item, source_scoped_record, _, _ = add_existing_advisory(
        session,
        url_hash="c" * 64,
        title_hash="d" * 64,
    )
    source_scoped_identifier = IntelligenceItemIdentifier(
        intelligence_item=source_scoped_item,
        source=source_scoped_record.source,
        source_record=source_scoped_record,
        namespace=ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
        identifier_value=record.normalized_title_hash,
        normalized_value=record.normalized_title_hash,
        is_primary=False,
    )
    session.add(source_scoped_identifier)
    session.flush()

    result = persist_new(session, record)

    assert result.outcome == "created"
    assert len(session.items) == 2
    assert session.source_records[-1].intelligence_item is not source_scoped_item
    assert len(fingerprint_identifiers(session, ARTICLE_TITLE_IDENTIFIER_NAMESPACE)) == 2
    assert source_scoped_identifier.source_id is not None


def test_service_flushes_but_never_commits_or_rolls_back() -> None:
    session = FakeSession()

    persist_new(session)

    assert session.flushes >= 1
    assert session.commits == 0
    assert session.rollbacks == 0


def test_database_failure_raises_sanitized_error() -> None:
    session = FakeSession(fail_flush=True)

    with pytest.raises(RssPersistenceError) as exc_info:
        persist_new(session)

    message = str(exc_info.value)
    assert message == "Database error while persisting normalized RSS data."
    assert "private-password" not in message
    assert "postgresql://" not in message
