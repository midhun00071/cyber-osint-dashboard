from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion.normalizers.rss import normalize_rss_feed
from app.ingestion.services.rss_ingestion_service import (
    RSS_SOURCE_BASE_URL,
    RSS_SOURCE_NAME,
    RSS_SOURCE_SLUG,
    RssIngestionService,
    RssPersistenceError,
)
from app.models import IntelligenceItem, IntelligenceSource, SourceRecord


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

    def add(self, record: object) -> None:
        if isinstance(record, IntelligenceSource):
            collection = self.sources
        elif isinstance(record, IntelligenceItem):
            collection = self.items
        elif isinstance(record, SourceRecord):
            collection = self.source_records
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
        for collection in (self.sources, self.items, self.source_records):
            for index, record in enumerate(collection, start=1):
                if getattr(record, "id", None) is None:
                    record.id = index
                if isinstance(record, SourceRecord):
                    if record.source is not None:
                        record.source_id = record.source.id
                    if record.intelligence_item is not None:
                        record.intelligence_item_id = record.intelligence_item.id

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


def test_fixed_rss_source_is_created_once_and_reused() -> None:
    session = FakeSession()

    first = persist_new(session)
    second = persist_new(session, normalized("CERT-EU-SA2026-002", link="https://cert.europa.eu/publications/security-advisories/2026-002"))

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
    item = session.items[0]
    source_record = session.source_records[0]
    assert item.item_type == "security_advisory"
    assert item.canonical_title == record.canonical_title
    assert item.summary == record.summary
    assert item.status == "active"
    assert item.data_confidence == Decimal("0.900")
    assert item.uae_relevance_status == "unknown"
    assert item.uae_relevance_method == "unassigned"
    assert item.analyst_review_status == "pending"
    assert source_record.intelligence_item is item
    assert source_record.is_primary_reference is True
    assert source_record.source_external_id == record.source_external_id
    assert source_record.canonical_url_hash == record.canonical_url_hash
    assert source_record.processing_status == "processed"
    assert source_record.upstream_status == "present"


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
    assert item.uae_relevance_status == "confirmed"
    assert item.uae_relevance_reason == "Analyst-owned reason"
    assert item.uae_relevance_method == "manual"
    assert item.analyst_review_status == "reviewed"
    assert item.collected_at == original_collected_at
    assert source_record.first_seen_at == original_first_seen


def test_external_id_and_url_hash_conflict_fails_without_auto_merge() -> None:
    session = FakeSession()
    first = normalized("CERT-EU-SA2026-001", link="https://cert.europa.eu/publications/a")
    second = normalized("CERT-EU-SA2026-002", link="https://cert.europa.eu/publications/b")
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
