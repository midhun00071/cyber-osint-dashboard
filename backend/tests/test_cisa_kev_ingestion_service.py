from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion.normalizers.cisa_kev import normalize_cisa_kev_entry
from app.ingestion.services.cisa_kev_ingestion_service import (
    CISA_KEV_SOURCE_BASE_URL,
    CISA_KEV_SOURCE_NAME,
    CISA_KEV_SOURCE_SLUG,
    CisaKevIngestionService,
    CisaKevPersistenceError,
)
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
    Vulnerability,
)


OBSERVED_AT = datetime(2026, 7, 9, 10, 0, tzinfo=UTC)
UPDATED_AT = datetime(2026, 7, 10, 10, 0, tzinfo=UTC)
COLLECTED_AT = datetime(2026, 7, 1, 10, 0, tzinfo=UTC)


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
                    (source for source in self.sources if source.slug == CISA_KEV_SOURCE_SLUG),
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
                        if record.source is not None
                        and record.source.slug == CISA_KEV_SOURCE_SLUG
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


def normalized(
    cve_id: str = "CVE-2026-12345",
    *,
    required_action: str = "Apply updates per vendor instructions.",
    due_date: str = "2026-07-29",
    ransomware: str = "Known",
):
    return normalize_cisa_kev_entry(
        {
            "cveID": cve_id,
            "vendorProject": "Vendor",
            "product": "Product",
            "vulnerabilityName": "Example Vulnerability",
            "dateAdded": "2026-07-08",
            "shortDescription": "A public defensive description.",
            "requiredAction": required_action,
            "dueDate": due_date,
            "knownRansomwareCampaignUse": ransomware,
            "notes": "Safe notes.",
        }
    )


def add_nvd_vulnerability(
    session: FakeSession,
    *,
    cve_id: str = "CVE-2026-12345",
    item_type: str = "vulnerability",
    with_vulnerability: bool = True,
):
    nvd_source = IntelligenceSource(
        slug="nvd",
        name="National Vulnerability Database",
        source_type="api",
        base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        is_enabled=True,
    )
    item = IntelligenceItem(
        item_type=item_type,
        canonical_title=cve_id,
        summary="NVD summary",
        collected_at=COLLECTED_AT,
        last_seen_at=COLLECTED_AT,
        status="active",
        geographic_scope="global",
        uae_relevance_status="confirmed",
        uae_relevance_reason="Analyst note",
        uae_relevance_method="manual",
        analyst_review_status="reviewed",
    )
    nvd_record = SourceRecord(
        source=nvd_source,
        intelligence_item=item,
        source_external_id=cve_id,
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        is_primary_reference=True,
        payload_collected_at=COLLECTED_AT,
        first_seen_at=COLLECTED_AT,
        last_seen_at=COLLECTED_AT,
        processing_status="processed",
        upstream_status="present",
    )
    identifier = IntelligenceItemIdentifier(
        intelligence_item=item,
        source=None,
        source_record=nvd_record,
        namespace="cve",
        identifier_value=cve_id,
        normalized_value=cve_id,
        is_primary=True,
    )
    session.add(nvd_source)
    session.add(item)
    session.add(nvd_record)
    session.add(identifier)
    vulnerability = None
    if with_vulnerability:
        vulnerability = Vulnerability(
            intelligence_item=item,
            severity="high",
            cvss_score=Decimal("8.8"),
            cvss_vector="CVSS:3.1/AV:N",
            cvss_version="3.1",
            epss_score=Decimal("0.123456"),
            epss_percentile=Decimal("0.654321"),
            kev_status="unknown",
            kev_last_checked_at=None,
            kev_date_added=None,
            kev_due_date=None,
            kev_required_action=None,
            known_ransomware_campaign_use=None,
            affected_summary="original",
            affected_products_json=[{"criteria": "cpe:2.3:a:vendor:product:*"}],
        )
        session.add(vulnerability)
    session.flush()
    return item, vulnerability, nvd_record


def test_approved_source_is_created_once() -> None:
    session = FakeSession()

    first = CisaKevIngestionService(session).ensure_source()  # type: ignore[arg-type]
    second = CisaKevIngestionService(session).ensure_source()  # type: ignore[arg-type]

    assert first is second
    assert first.slug == CISA_KEV_SOURCE_SLUG
    assert first.name == CISA_KEV_SOURCE_NAME
    assert first.source_type == "json"
    assert first.base_url == CISA_KEV_SOURCE_BASE_URL


def test_conflicting_source_configuration_fails_safely() -> None:
    session = FakeSession()
    session.add(
        IntelligenceSource(
            slug=CISA_KEV_SOURCE_SLUG,
            name="Wrong",
            source_type="json",
            base_url=CISA_KEV_SOURCE_BASE_URL,
            is_enabled=True,
        )
    )

    with pytest.raises(CisaKevPersistenceError, match="conflicts"):
        CisaKevIngestionService(session).ensure_source()  # type: ignore[arg-type]


def test_existing_cve_is_updated_with_non_primary_cisa_source_record() -> None:
    session = FakeSession()
    item, vulnerability, nvd_record = add_nvd_vulnerability(session)

    result = CisaKevIngestionService(session).enrich(  # type: ignore[arg-type]
        normalized(),
        observed_at=OBSERVED_AT,
    )

    assert result.outcome == "created"
    assert vulnerability.kev_status == "listed"
    assert vulnerability.kev_last_checked_at == OBSERVED_AT
    assert vulnerability.kev_date_added.isoformat() == "2026-07-08"
    assert vulnerability.kev_due_date.isoformat() == "2026-07-29"
    assert vulnerability.kev_required_action == "Apply updates per vendor instructions."
    assert vulnerability.known_ransomware_campaign_use is True
    kev_record = result.source_record
    assert kev_record is not None
    assert kev_record.intelligence_item is item
    assert kev_record.is_primary_reference is False
    assert kev_record.source.slug == CISA_KEV_SOURCE_SLUG
    assert kev_record.source_external_id == "CVE-2026-12345"
    assert nvd_record.is_primary_reference is True


def test_repeated_same_kev_entry_is_unchanged() -> None:
    session = FakeSession()
    add_nvd_vulnerability(session)
    service = CisaKevIngestionService(session)  # type: ignore[arg-type]
    first = service.enrich(normalized(), observed_at=OBSERVED_AT)

    second = service.enrich(normalized(), observed_at=UPDATED_AT)

    assert first.outcome == "created"
    assert second.outcome == "unchanged"
    assert len([record for record in session.source_records if record.source.slug == CISA_KEV_SOURCE_SLUG]) == 1
    assert second.source_record.last_seen_at == UPDATED_AT


def test_changed_kev_fields_update_existing_record_and_preserve_non_kev_fields() -> None:
    session = FakeSession()
    item, vulnerability, nvd_record = add_nvd_vulnerability(session)
    original_collected_at = item.collected_at
    original_first_seen_at = nvd_record.first_seen_at
    service = CisaKevIngestionService(session)  # type: ignore[arg-type]
    service.enrich(normalized(), observed_at=OBSERVED_AT)

    result = service.enrich(
        normalized(required_action="Apply mitigation.", due_date="2026-08-01", ransomware="Unknown"),
        observed_at=UPDATED_AT,
    )

    assert result.outcome == "updated"
    assert vulnerability.kev_required_action == "Apply mitigation."
    assert vulnerability.kev_due_date.isoformat() == "2026-08-01"
    assert vulnerability.known_ransomware_campaign_use is False
    assert vulnerability.severity == "high"
    assert vulnerability.cvss_score == Decimal("8.8")
    assert vulnerability.epss_score == Decimal("0.123456")
    assert vulnerability.epss_percentile == Decimal("0.654321")
    assert vulnerability.affected_summary == "original"
    assert item.summary == "NVD summary"
    assert item.uae_relevance_status == "confirmed"
    assert item.uae_relevance_reason == "Analyst note"
    assert item.uae_relevance_method == "manual"
    assert item.analyst_review_status == "reviewed"
    assert item.collected_at == original_collected_at
    assert nvd_record.first_seen_at == original_first_seen_at


def test_missing_local_cve_is_skipped_without_creating_item() -> None:
    session = FakeSession()

    result = CisaKevIngestionService(session).enrich(  # type: ignore[arg-type]
        normalized(),
        observed_at=OBSERVED_AT,
    )

    assert result.outcome == "skipped"
    assert session.items == []


def test_missing_vulnerability_extension_is_skipped_safely() -> None:
    session = FakeSession()
    add_nvd_vulnerability(session, with_vulnerability=False)

    result = CisaKevIngestionService(session).enrich(  # type: ignore[arg-type]
        normalized(),
        observed_at=OBSERVED_AT,
    )

    assert result.outcome == "skipped"
    assert "vulnerability extension" in result.message


def test_non_vulnerability_item_is_skipped_safely() -> None:
    session = FakeSession()
    add_nvd_vulnerability(session, item_type="cyber_news", with_vulnerability=False)

    result = CisaKevIngestionService(session).enrich(  # type: ignore[arg-type]
        normalized(),
        observed_at=OBSERVED_AT,
    )

    assert result.outcome == "skipped"
    assert "not a vulnerability" in result.message


def test_existing_cisa_source_record_for_different_item_fails() -> None:
    session = FakeSession()
    add_nvd_vulnerability(session)
    service = CisaKevIngestionService(session)  # type: ignore[arg-type]
    first = service.enrich(normalized(), observed_at=OBSERVED_AT)
    other_item = IntelligenceItem(
        item_type="vulnerability",
        canonical_title="Other",
        collected_at=OBSERVED_AT,
        last_seen_at=OBSERVED_AT,
        status="active",
        geographic_scope="global",
        uae_relevance_status="unknown",
        uae_relevance_method="unassigned",
        analyst_review_status="pending",
    )
    session.add(other_item)
    first.source_record.intelligence_item = other_item

    result = service.enrich(normalized(), observed_at=UPDATED_AT)

    assert result.outcome == "failed"
    assert "different item" in result.message


def test_database_errors_are_sanitized() -> None:
    session = FakeSession()
    add_nvd_vulnerability(session)
    session.fail_flush = True

    with pytest.raises(CisaKevPersistenceError) as exc_info:
        CisaKevIngestionService(session).enrich(  # type: ignore[arg-type]
            normalized(),
            observed_at=OBSERVED_AT,
        )

    assert str(exc_info.value) == "Database error while persisting normalized CISA KEV data."
    assert "private-password" not in str(exc_info.value)


def test_service_flushes_but_never_commits_or_rolls_back() -> None:
    session = FakeSession()
    add_nvd_vulnerability(session)

    CisaKevIngestionService(session).enrich(  # type: ignore[arg-type]
        normalized(),
        observed_at=OBSERVED_AT,
    )

    assert session.flushes >= 1
    assert session.commits == 0
    assert session.rollbacks == 0
