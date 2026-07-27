from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.indicators.value_normalization import normalize_observable
from app.models import (
    Indicator,
    IndicatorProvenance,
    IntelligenceItem,
    IntelligenceItemIndicator,
    IntelligenceSource,
    SourceRecord,
)
from app.processing.ioc_extraction_service import (
    IOCExtractionService,
    IOCExtractionServiceError,
)


OBSERVED = datetime(2026, 7, 1, 12, tzinfo=UTC)


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class FakeSession:
    def __init__(self, records=()):
        self.records = {record.id: record for record in records}
        self.indicators = []
        self.relationships = []
        self.provenances = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.execute_error = None

    def get(self, model, identity, *, options=()):
        assert model is SourceRecord
        assert len(options) == 2
        return self.records.get(identity)

    def execute(self, statement):
        if self.execute_error is not None:
            raise self.execute_error
        entity = statement.column_descriptions[0]["entity"]
        collection = {
            Indicator: self.indicators,
            IntelligenceItemIndicator: self.relationships,
            IndicatorProvenance: self.provenances,
        }[entity]
        criteria = {
            criterion.left.name: criterion.right.value
            for criterion in statement._where_criteria
        }
        matches = [
            row
            for row in collection
            if all(getattr(row, name) == value for name, value in criteria.items())
        ]
        assert len(matches) <= 1
        return _ScalarResult(matches[0] if matches else None)

    def add(self, value):
        if isinstance(value, Indicator):
            self.indicators.append(value)
        elif isinstance(value, IntelligenceItemIndicator):
            self.relationships.append(value)
        elif isinstance(value, IndicatorProvenance):
            self.provenances.append(value)
        else:
            raise AssertionError(f"unexpected add type: {type(value).__name__}")

    def flush(self):
        self.flush_calls += 1
        for index, indicator in enumerate(self.indicators, start=1):
            if indicator.id is None:
                indicator.id = index

    def commit(self):
        self.commit_calls += 1

    def rollback(self):
        self.rollback_calls += 1


def make_record(
    *,
    record_id=10,
    source_id=20,
    item_id=30,
    title="IOC domain bad[.]co",
    summary=None,
    item_type="security_advisory",
    processing_status="processed",
    upstream_status="present",
    item_published_at=OBSERVED,
    record_published_at=None,
):
    source = IntelligenceSource(
        id=source_id,
        name=f"Source {source_id}",
        slug=f"source-{source_id}",
        source_type="rss",
        base_url=f"https://publisher-{source_id}.co",
        is_enabled=True,
    )
    item = IntelligenceItem(
        id=item_id,
        item_type=item_type,
        canonical_title=title,
        summary=summary,
        canonical_url=f"https://publisher-{source_id}.co/story",
        source_published_at=item_published_at,
    )
    record = SourceRecord(
        id=record_id,
        source_id=source_id,
        intelligence_item_id=item_id,
        source_url=f"https://publisher-{source_id}.co/story",
        is_primary_reference=True,
        raw_payload={"must_not_be_read": "sensitive"},
        payload_collected_at=OBSERVED,
        first_seen_at=OBSERVED + timedelta(days=5),
        last_seen_at=OBSERVED + timedelta(days=5),
        source_published_at=record_published_at,
        processing_status=processing_status,
        upstream_status=upstream_status,
    )
    record.source = source
    record.intelligence_item = item
    return record


def _assert_caller_owns_transaction(session):
    assert session.commit_calls == 0
    assert session.rollback_calls == 0


def test_creates_indicator_relationship_and_exact_source_record_provenance():
    record = make_record()
    session = FakeSession([record])

    result = IOCExtractionService(session).extract_source_record(record.id)

    assert result.status == "processed"
    assert (result.indicators_created, result.relationships_created) == (1, 1)
    assert result.provenances_created == 1
    assert session.flush_calls == 1
    indicator = session.indicators[0]
    relationship = session.relationships[0]
    provenance = session.provenances[0]
    assert indicator.normalized_value == "bad.co"
    assert indicator.status == "active"
    assert indicator.first_seen_at == indicator.last_seen_at == OBSERVED
    assert relationship.intelligence_item_id == record.intelligence_item_id
    assert relationship.relationship_type == "mentioned"
    assert relationship.extraction_method == "deterministic_text"
    assert provenance.indicator_id == indicator.id
    assert provenance.source_id == record.source_id
    assert provenance.source_record_id == record.id
    _assert_caller_owns_transaction(session)


def test_repeat_run_is_idempotent_and_returns_unchanged_counts():
    record = make_record()
    session = FakeSession([record])
    service = IOCExtractionService(session)

    first = service.extract_source_record(record.id)
    second = service.extract_source_record(record.id)

    assert first.indicators_created == 1
    assert second.indicators_existing == 1
    assert second.relationships_unchanged == 1
    assert second.provenances_unchanged == 1
    assert (len(session.indicators), len(session.relationships), len(session.provenances)) == (
        1,
        1,
        1,
    )
    assert session.flush_calls == 1
    _assert_caller_owns_transaction(session)


def test_same_item_and_indicator_reuse_relationship_with_separate_provenance():
    first = make_record(record_id=10, source_id=20, item_id=30)
    second = make_record(record_id=11, source_id=21, item_id=30)
    second.intelligence_item = first.intelligence_item
    second.intelligence_item_id = first.intelligence_item_id
    session = FakeSession([first, second])
    service = IOCExtractionService(session)

    service.extract_source_record(first.id)
    result = service.extract_source_record(second.id)

    assert result.indicators_existing == 1
    assert result.relationships_unchanged == 1
    assert result.provenances_created == 1
    assert len(session.relationships) == 1
    assert {(row.source_id, row.source_record_id) for row in session.provenances} == {
        (20, 10),
        (21, 11),
    }


def test_false_positive_suppresses_relationship_and_provenance_without_mutation():
    record = make_record()
    normalized = normalize_observable("domain", "bad.co")
    indicator = Indicator(
        id=7,
        observable_type="domain",
        normalized_value="bad.co",
        identity_sha256=normalized.identity_sha256,
        status="false_positive",
        confidence=Decimal("0.400"),
        first_seen_at=OBSERVED - timedelta(days=10),
        last_seen_at=OBSERVED - timedelta(days=5),
    )
    session = FakeSession([record])
    session.indicators.append(indicator)
    before = (indicator.status, indicator.confidence, indicator.last_seen_at)

    result = IOCExtractionService(session).extract_source_record(record.id)

    assert result.suppressed_false_positive == 1
    assert session.relationships == []
    assert session.provenances == []
    assert (indicator.status, indicator.confidence, indicator.last_seen_at) == before


@pytest.mark.parametrize("status", ["inactive", "revoked", "archived"])
def test_existing_lifecycle_status_is_preserved_while_observation_range_updates(status):
    record = make_record()
    normalized = normalize_observable("domain", "bad.co")
    indicator = Indicator(
        id=7,
        observable_type="domain",
        normalized_value="bad.co",
        identity_sha256=normalized.identity_sha256,
        status=status,
        confidence=Decimal("0.500"),
        first_seen_at=OBSERVED + timedelta(days=1),
        last_seen_at=OBSERVED - timedelta(days=1),
    )
    session = FakeSession([record])
    session.indicators.append(indicator)

    IOCExtractionService(session).extract_source_record(record.id)

    assert indicator.status == status
    assert indicator.first_seen_at == OBSERVED
    assert indicator.last_seen_at == OBSERVED
    assert indicator.confidence == Decimal("0.900")


def test_observation_time_priority_and_aware_supplied_fallback():
    record = make_record(item_published_at=None, record_published_at=None)
    supplied = datetime(2026, 6, 1, 8, tzinfo=UTC)
    session = FakeSession([record])

    IOCExtractionService(session).extract_source_record(record.id, observed_at=supplied)

    assert session.indicators[0].first_seen_at == supplied
    with pytest.raises(ValueError, match="timezone-aware"):
        IOCExtractionService(session).extract_source_record(
            record.id,
            observed_at=datetime(2026, 1, 1),
        )


@pytest.mark.parametrize(
    ("mutation", "status"),
    [
        (lambda record: setattr(record, "intelligence_item", None), "skipped_missing_intelligence_item"),
        (lambda record: setattr(record, "source", None), "skipped_missing_intelligence_source"),
        (lambda record: setattr(record, "processing_status", "pending"), "skipped_source_record_state"),
        (lambda record: setattr(record.intelligence_item, "item_type", "vulnerability"), "skipped_item_type"),
    ],
)
def test_ineligible_source_records_are_safely_skipped(mutation, status):
    record = make_record()
    mutation(record)
    session = FakeSession([record])

    result = IOCExtractionService(session).extract_source_record(record.id)

    assert result.status == status
    assert session.indicators == []
    assert session.flush_calls == 0
    _assert_caller_owns_transaction(session)


def test_missing_record_and_no_candidate_text_return_sanitized_results():
    session = FakeSession()
    assert IOCExtractionService(session).extract_source_record(999).status == (
        "skipped_missing_source_record"
    )
    record = make_record(title="Routine publication", summary="No observable metadata")
    session = FakeSession([record])
    assert IOCExtractionService(session).extract_source_record(record.id).status == (
        "no_candidates"
    )


def test_excluded_source_ip_uri_cannot_create_fallback_ip_evidence():
    record = make_record(title="IOC hxxps[:]//8[.]8[.]8[.]8/path")
    record.source.base_url = "https://8.8.8.8"
    record.source_url = "https://8.8.8.8/path"
    record.intelligence_item.canonical_url = "https://8.8.8.8/path"
    session = FakeSession([record])

    result = IOCExtractionService(session).extract_source_record(record.id)

    assert result.status == "no_candidates"
    assert session.indicators == []
    assert session.relationships == []
    assert session.provenances == []
    assert session.flush_calls == 0
    _assert_caller_owns_transaction(session)


@pytest.mark.parametrize(
    "title",
    [
        "IOC contact user@[8.8.8.8]",
        "IOC contact user@a.b.c.d.e.f.g.h.i.j.k.evil.co",
        "IOC contact @8.8.8.8",
    ],
)
def test_email_like_tokens_cannot_create_indicator_evidence(title):
    record = make_record(title=title)
    session = FakeSession([record])

    result = IOCExtractionService(session).extract_source_record(record.id)

    assert result.status == "no_candidates"
    assert session.indicators == []
    assert session.relationships == []
    assert session.provenances == []
    assert session.flush_calls == 0
    _assert_caller_owns_transaction(session)


def test_context_is_bounded_and_raw_payload_is_not_referenced_by_service():
    record = make_record(title="IOC " + "word " * 80 + "bad[.]co" + " tail" * 80)
    session = FakeSession([record])

    IOCExtractionService(session).extract_source_record(record.id)

    assert len(session.relationships[0].context_summary) <= 500
    assert len(session.provenances[0].context_summary) <= 500
    service_source = Path(__file__).parents[1].joinpath(
        "app", "processing", "ioc_extraction_service.py"
    ).read_text(encoding="utf-8")
    assert "raw_payload" not in service_source


def test_database_errors_are_sanitized_without_transaction_interference():
    record = make_record()
    session = FakeSession([record])
    session.execute_error = SQLAlchemyError("secret submitted value bad.co")

    with pytest.raises(IOCExtractionServiceError) as caught:
        IOCExtractionService(session).extract_source_record(record.id)

    assert str(caught.value) == "Database error while extracting publication indicators."
    assert "bad.co" not in str(caught.value)
    _assert_caller_owns_transaction(session)


def test_source_record_id_validation_is_strict():
    service = IOCExtractionService(FakeSession())
    for value in (0, -1, True, "1"):
        with pytest.raises(ValueError, match="positive integer"):
            service.extract_source_record(value)
