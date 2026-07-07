from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion.normalizers.nvd import NormalizedNvdCve, normalize_nvd_cve
from app.ingestion.services.nvd_ingestion_service import (
    NVD_SOURCE_BASE_URL,
    NVD_SOURCE_NAME,
    NVD_SOURCE_SLUG,
    NvdIngestionService,
    NvdPersistenceError,
)
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
    Vulnerability,
)


OBSERVED_AT = datetime(2026, 7, 9, 10, 0, tzinfo=UTC)
UPDATED_AT = datetime(2026, 7, 9, 11, 0, tzinfo=UTC)


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
        self.vulnerabilities: list[Vulnerability] = []
        self.source_records: list[SourceRecord] = []
        self.identifiers: list[IntelligenceItemIdentifier] = []

    def add(self, record: object) -> None:
        collection: list | None = None
        if isinstance(record, IntelligenceSource):
            collection = self.sources
        elif isinstance(record, IntelligenceItem):
            collection = self.items
        elif isinstance(record, Vulnerability):
            collection = self.vulnerabilities
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
        for collection in (
            self.sources,
            self.items,
            self.vulnerabilities,
            self.source_records,
            self.identifiers,
        ):
            for index, record in enumerate(collection, start=1):
                if getattr(record, "id", None) is None:
                    record.id = index

    def execute(self, statement: Any) -> ScalarResult:
        entity = statement.column_descriptions[0]["entity"]
        criteria = list(statement._where_criteria)
        if entity is IntelligenceSource:
            return ScalarResult(
                next(
                    (source for source in self.sources if source.slug == NVD_SOURCE_SLUG),
                    None,
                )
            )
        if entity is IntelligenceItemIdentifier:
            cve_id = criterion_value(criteria, "normalized_value")
            return ScalarResult(
                next(
                    (
                        identifier
                        for identifier in self.identifiers
                        if identifier.source is None
                        and identifier.namespace == "cve"
                        and identifier.normalized_value == cve_id
                    ),
                    None,
                )
            )
        if entity is SourceRecord:
            cve_id = criterion_value(criteria, "source_external_id")
            return ScalarResult(
                next(
                    (
                        record
                        for record in self.source_records
                        if record.source.slug == NVD_SOURCE_SLUG
                        and record.source_external_id == cve_id
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


def make_normalized(cve_id: str = "CVE-2026-12345") -> NormalizedNvdCve:
    return normalize_nvd_cve(
        {
            "cve": {
                "id": cve_id,
                "published": "2026-01-02T03:04:05Z",
                "lastModified": "2026-01-03T04:05:06Z",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "en", "value": "Safe NVD vulnerability summary."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L",
                            }
                        }
                    ]
                },
                "configurations": [],
            }
        }
    )


def persist_new(
    session: FakeSession,
    normalized: NormalizedNvdCve | None = None,
):
    record = normalized or make_normalized()
    result = NvdIngestionService(session).persist(  # type: ignore[arg-type]
        record,
        observed_at=OBSERVED_AT,
    )
    return record, result


def test_fixed_nvd_source_is_created_once_and_reused() -> None:
    session = FakeSession()

    first = persist_new(session, make_normalized("CVE-2026-12345"))[1]
    second = persist_new(session, make_normalized("CVE-2026-12346"))[1]

    assert first.outcome == "created"
    assert second.outcome == "created"
    assert len(session.sources) == 1
    source = session.sources[0]
    assert source.slug == NVD_SOURCE_SLUG
    assert source.name == NVD_SOURCE_NAME
    assert source.source_type == "api"
    assert source.base_url == NVD_SOURCE_BASE_URL
    assert source.is_enabled is True


def test_new_cve_creates_complete_normalized_record_graph() -> None:
    session = FakeSession()
    normalized, result = persist_new(session)

    assert result.outcome == "created"
    assert len(session.items) == 1
    assert len(session.vulnerabilities) == 1
    assert len(session.source_records) == 1
    assert len(session.identifiers) == 1
    item = session.items[0]
    vulnerability = session.vulnerabilities[0]
    source_record = session.source_records[0]
    identifier = session.identifiers[0]
    assert item.item_type == "vulnerability"
    assert item.collected_at == OBSERVED_AT
    assert item.analyst_review_status == "pending"
    assert vulnerability.intelligence_item is item
    assert identifier.intelligence_item is item
    assert identifier.namespace == "cve"
    assert identifier.normalized_value == normalized.cve_id
    assert identifier.is_primary is True
    assert source_record.intelligence_item is item


def test_repeated_identical_cve_is_unchanged_without_duplicates() -> None:
    session = FakeSession()
    normalized, first = persist_new(session)

    second = NvdIngestionService(session).persist(  # type: ignore[arg-type]
        normalized,
        observed_at=UPDATED_AT,
    )

    assert first.outcome == "created"
    assert second.outcome == "unchanged"
    assert len(session.items) == 1
    assert len(session.vulnerabilities) == 1
    assert len(session.source_records) == 1
    assert len(session.identifiers) == 1
    assert session.items[0].last_seen_at == UPDATED_AT
    assert session.source_records[0].first_seen_at == OBSERVED_AT


def test_changed_hash_updates_nvd_fields_and_preserves_analyst_enrichment() -> None:
    session = FakeSession()
    normalized, _ = persist_new(session)
    item = session.items[0]
    vulnerability = session.vulnerabilities[0]
    source_record = session.source_records[0]
    item.uae_relevance_status = "confirmed"
    item.uae_relevance_confidence = Decimal("0.900")
    item.uae_relevance_reason = "Analyst-owned reason"
    item.uae_relevance_method = "manual"
    item.analyst_review_status = "reviewed"
    vulnerability.epss_score = Decimal("0.123456")
    vulnerability.epss_percentile = Decimal("0.654321")
    vulnerability.kev_status = "listed"
    original_collected_at = item.collected_at
    original_first_seen = source_record.first_seen_at
    updated = replace(
        normalized,
        title="Updated NVD title",
        summary="Updated NVD summary",
        severity="critical",
        cvss_score=Decimal("9.9"),
        content_hash="f" * 64,
        raw_payload={"cve": {"id": normalized.cve_id, "updated": True}},
    )

    result = NvdIngestionService(session).persist(  # type: ignore[arg-type]
        updated,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "updated"
    assert item.canonical_title == "Updated NVD title"
    assert vulnerability.severity == "critical"
    assert vulnerability.cvss_score == Decimal("9.9")
    assert source_record.content_hash == "f" * 64
    assert item.uae_relevance_status == "confirmed"
    assert item.uae_relevance_reason == "Analyst-owned reason"
    assert item.analyst_review_status == "reviewed"
    assert vulnerability.epss_score == Decimal("0.123456")
    assert vulnerability.epss_percentile == Decimal("0.654321")
    assert vulnerability.kev_status == "listed"
    assert item.collected_at == original_collected_at
    assert source_record.first_seen_at == original_first_seen


def test_update_repairs_missing_vulnerability_extension_without_duplicates() -> None:
    session = FakeSession()
    normalized, _ = persist_new(session)
    item = session.items[0]
    source_record = session.source_records[0]
    item.vulnerability = None
    session.vulnerabilities.clear()
    original_collected_at = item.collected_at
    original_first_seen = source_record.first_seen_at
    updated = replace(
        normalized,
        severity="critical",
        cvss_score=Decimal("9.7"),
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N",
        cvss_version="3.1",
        affected_summary="NVD lists 1 affected product configuration(s).",
        affected_products=[
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:example:repaired:*:*:*:*:*:*:*:*",
            }
        ],
        content_hash="e" * 64,
    )

    result = NvdIngestionService(session).persist(  # type: ignore[arg-type]
        updated,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "updated"
    assert len(session.vulnerabilities) == 1
    vulnerability = session.vulnerabilities[0]
    assert vulnerability.intelligence_item is item
    assert vulnerability.severity == "critical"
    assert vulnerability.cvss_score == Decimal("9.7")
    assert vulnerability.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N"
    assert vulnerability.cvss_version == "3.1"
    assert vulnerability.affected_summary == updated.affected_summary
    assert vulnerability.affected_products_json == updated.affected_products
    assert vulnerability.epss_score is None
    assert vulnerability.epss_percentile is None
    assert vulnerability.kev_status == "unknown"
    assert vulnerability.kev_last_checked_at is None
    assert vulnerability.kev_date_added is None
    assert vulnerability.kev_due_date is None
    assert vulnerability.kev_required_action is None
    assert vulnerability.known_ransomware_campaign_use is None
    assert len(session.items) == 1
    assert len(session.source_records) == 1
    assert len(session.identifiers) == 1
    assert item.collected_at == original_collected_at
    assert source_record.first_seen_at == original_first_seen
    assert session.commits == 0
    assert session.rollbacks == 0


def test_unchanged_hash_repairs_missing_vulnerability_extension() -> None:
    session = FakeSession()
    normalized, _ = persist_new(session)
    item = session.items[0]
    source_record = session.source_records[0]
    item.vulnerability = None
    session.vulnerabilities.clear()

    result = NvdIngestionService(session).persist(  # type: ignore[arg-type]
        normalized,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "updated"
    assert len(session.vulnerabilities) == 1
    vulnerability = session.vulnerabilities[0]
    assert vulnerability.intelligence_item is item
    assert vulnerability.severity == normalized.severity
    assert vulnerability.cvss_score == normalized.cvss_score
    assert vulnerability.cvss_vector == normalized.cvss_vector
    assert vulnerability.cvss_version == normalized.cvss_version
    assert vulnerability.affected_summary == normalized.affected_summary
    assert vulnerability.affected_products_json == normalized.affected_products
    assert vulnerability.epss_score is None
    assert vulnerability.epss_percentile is None
    assert vulnerability.kev_status == "unknown"
    assert vulnerability.kev_last_checked_at is None
    assert vulnerability.kev_date_added is None
    assert vulnerability.kev_due_date is None
    assert vulnerability.kev_required_action is None
    assert vulnerability.known_ransomware_campaign_use is None
    assert item.last_seen_at == UPDATED_AT
    assert source_record.last_seen_at == UPDATED_AT
    assert source_record.payload_collected_at == UPDATED_AT
    assert source_record.upstream_status == "present"
    assert len(session.items) == 1
    assert len(session.source_records) == 1
    assert len(session.identifiers) == 1
    assert session.commits == 0
    assert session.rollbacks == 0


def test_source_record_conflict_fails_without_auto_merge() -> None:
    session = FakeSession()
    normalized, _ = persist_new(session)
    other_item = IntelligenceItem(
        item_type="vulnerability",
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
    session.source_records[0].intelligence_item = other_item

    result = NvdIngestionService(session).persist(  # type: ignore[arg-type]
        normalized,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "failed"
    assert result.message == (
        "The CVE identifier and NVD source record refer to different items."
    )
    assert len(session.items) == 2


def test_identifier_conflict_fails_safely() -> None:
    session = FakeSession()
    normalized, _ = persist_new(session)
    marker = "private-payload-marker"
    session.items[0].item_type = "cyber_news"
    unsafe = replace(normalized, raw_payload={"marker": marker})

    result = NvdIngestionService(session).persist(  # type: ignore[arg-type]
        unsafe,
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "failed"
    assert "does not belong to a vulnerability" in result.message
    assert marker not in result.message


def test_source_provenance_and_raw_payload_are_populated_from_normalized_data() -> None:
    session = FakeSession()
    normalized, _ = persist_new(session)
    source_record = session.source_records[0]

    assert source_record.source_external_id == normalized.cve_id
    assert source_record.source_url == normalized.canonical_url
    assert source_record.source_published_at == normalized.source_published_at
    assert source_record.source_modified_at == normalized.source_modified_at
    assert source_record.content_hash == normalized.content_hash
    assert source_record.raw_payload is normalized.raw_payload
    assert source_record.processing_status == "processed"
    assert source_record.upstream_status == "present"


def test_service_flushes_but_never_commits_or_rolls_back() -> None:
    session = FakeSession()

    persist_new(session)

    assert session.flushes >= 1
    assert session.commits == 0
    assert session.rollbacks == 0


def test_database_failure_raises_sanitized_error() -> None:
    session = FakeSession(fail_flush=True)

    with pytest.raises(NvdPersistenceError) as exc_info:
        persist_new(session)

    message = str(exc_info.value)
    assert message == "Database error while persisting normalized NVD data."
    assert "private-password" not in message
    assert "postgresql://" not in message
