from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import get_db_session
from app.main import app
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
    Vulnerability,
)


NOW = datetime(2026, 7, 7, 12, 0, tzinfo=UTC)


class FakeScalarResult:
    def __init__(self, items: list[IntelligenceItem]):
        self._items = items

    def all(self) -> list[IntelligenceItem]:
        return list(self._items)


class FakeExecuteResult:
    def __init__(self, items: list[IntelligenceItem]):
        self._items = items

    def scalars(self) -> FakeScalarResult:
        return FakeScalarResult(self._items)


class FakeSession:
    def __init__(
        self,
        items: list[IntelligenceItem] | None = None,
        *,
        error_message: str | None = None,
    ) -> None:
        self.items = items or []
        self.error_message = error_message

    def execute(self, _statement):
        if self.error_message is not None:
            raise SQLAlchemyError(self.error_message)
        return FakeExecuteResult(self.items)


@pytest.fixture
def client():
    created_clients: list[TestClient] = []

    def factory(session: FakeSession) -> TestClient:
        app.dependency_overrides[get_db_session] = lambda: session
        test_client = TestClient(app)
        created_clients.append(test_client)
        return test_client

    yield factory

    app.dependency_overrides.clear()
    for test_client in created_clients:
        test_client.close()


def make_vulnerability_item(
    *,
    public_id: UUID | None = None,
    cve_id: str = "CVE-2026-12345",
    title: str = "Example vulnerability title",
    summary: str = "Example vulnerability summary.",
    severity: str = "high",
    source_slug: str = "nvd",
    source_name: str = "National Vulnerability Database",
    source_modified_at: datetime | None = None,
    last_seen_at: datetime | None = None,
    first_seen_at: datetime | None = None,
    raw_payload_marker: str | None = None,
) -> IntelligenceItem:
    item_public_id = public_id or uuid4()
    item_last_seen_at = last_seen_at or NOW
    item_source_modified_at = source_modified_at or NOW
    item_first_seen_at = first_seen_at or NOW

    source = IntelligenceSource(
        public_id=uuid4(),
        name=source_name,
        slug=source_slug,
        source_type="api",
        base_url="https://nvd.nist.gov/",
        is_enabled=True,
        rate_limit_notes=None,
        last_successful_fetch_at=NOW,
        checkpoint_value=None,
        created_at=NOW,
        updated_at=NOW,
    )
    item = IntelligenceItem(
        public_id=item_public_id,
        item_type="vulnerability",
        canonical_title=title,
        summary=summary,
        canonical_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        source_published_at=NOW,
        source_modified_at=item_source_modified_at,
        collected_at=NOW,
        last_seen_at=item_last_seen_at,
        status="active",
        data_confidence=Decimal("1.000"),
        geographic_scope="global",
        uae_relevance_status="unknown",
        uae_relevance_confidence=None,
        uae_relevance_reason=None,
        uae_relevance_method="unassigned",
        analyst_review_status="pending",
        created_at=NOW,
        updated_at=NOW,
    )
    vulnerability = Vulnerability(
        intelligence_item=item,
        severity=severity,
        cvss_score=Decimal("8.8"),
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_version="3.1",
        epss_score=None,
        epss_percentile=None,
        kev_status="unknown",
        kev_last_checked_at=None,
        kev_date_added=None,
        kev_due_date=None,
        kev_required_action=None,
        known_ransomware_campaign_use=None,
        affected_summary="Example Product before 1.2.3.",
        affected_products_json=[{"criteria": "cpe:2.3:a:example:product"}],
        created_at=NOW,
        updated_at=NOW,
    )
    identifier = IntelligenceItemIdentifier(
        intelligence_item=item,
        source=None,
        source_record=None,
        namespace="cve",
        identifier_value=cve_id,
        normalized_value=cve_id,
        is_primary=True,
        created_at=NOW,
    )
    source_record = SourceRecord(
        source=source,
        intelligence_item=item,
        source_external_id=cve_id,
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        canonical_url_hash=None,
        content_hash="a" * 64,
        is_primary_reference=True,
        raw_payload={"marker": raw_payload_marker or "secret-raw-payload"},
        payload_collected_at=NOW,
        first_seen_at=item_first_seen_at,
        last_seen_at=item_last_seen_at,
        source_published_at=NOW,
        source_modified_at=item_source_modified_at,
        processing_status="processed",
        last_processed_at=NOW,
        safe_error_summary=None,
        upstream_status="present",
        created_at=NOW,
        updated_at=NOW,
    )
    item.vulnerability = vulnerability
    item.identifiers = [identifier]
    item.source_records = [source_record]
    source.source_records = [source_record]
    source.identifiers = []
    return item


def make_non_vulnerability_item() -> IntelligenceItem:
    source = IntelligenceSource(
        public_id=uuid4(),
        name="Example Feed",
        slug="example-feed",
        source_type="rss",
        base_url="https://example.test/feed",
        is_enabled=True,
        rate_limit_notes=None,
        last_successful_fetch_at=NOW,
        checkpoint_value=None,
        created_at=NOW,
        updated_at=NOW,
    )
    item = IntelligenceItem(
        public_id=uuid4(),
        item_type="cyber_news",
        canonical_title="Regional cyber news",
        summary="A defensive news summary.",
        canonical_url="https://example.test/news/regional",
        source_published_at=NOW,
        source_modified_at=None,
        collected_at=NOW,
        last_seen_at=NOW,
        status="active",
        data_confidence=Decimal("0.800"),
        geographic_scope="regional",
        uae_relevance_status="possible",
        uae_relevance_confidence=Decimal("0.420"),
        uae_relevance_reason="Regional mention",
        uae_relevance_method="automatic",
        analyst_review_status="reviewed",
        created_at=NOW,
        updated_at=NOW,
    )
    source_record = SourceRecord(
        source=source,
        intelligence_item=item,
        source_external_id="regional-news-1",
        source_url="https://example.test/news/regional",
        canonical_url_hash=None,
        content_hash="b" * 64,
        is_primary_reference=True,
        raw_payload={"marker": "news-raw-payload"},
        payload_collected_at=NOW,
        first_seen_at=NOW,
        last_seen_at=NOW,
        source_published_at=NOW,
        source_modified_at=None,
        processing_status="processed",
        last_processed_at=NOW,
        safe_error_summary=None,
        upstream_status="present",
        created_at=NOW,
        updated_at=NOW,
    )
    item.source_records = [source_record]
    item.identifiers = []
    source.source_records = [source_record]
    source.identifiers = []
    return item


def test_list_endpoint_returns_empty_result_safely(client) -> None:
    response = client(FakeSession()).get("/api/v1/intelligence/items")

    assert response.status_code == 200
    assert response.json() == {
        "items": [],
        "total": 0,
        "limit": 25,
        "offset": 0,
    }


def test_list_endpoint_returns_stored_vulnerability_record_without_raw_payloads(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = make_vulnerability_item(raw_payload_marker="super-secret-marker")

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("Read-only intelligence API must not trigger ingestion.")

    monkeypatch.setattr(
        "app.ingestion.collectors.nvd_client.NvdClient.fetch_page",
        fail_if_called,
        raising=False,
    )
    monkeypatch.setattr(
        "app.ingestion.services.nvd_ingestion_service.NvdIngestionService.persist",
        fail_if_called,
        raising=False,
    )

    response = client(FakeSession([item])).get("/api/v1/intelligence/items")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    returned = data["items"][0]
    assert returned["public_id"] == str(item.public_id)
    assert returned["title"] == item.canonical_title
    assert returned["cve_id"] == "CVE-2026-12345"
    assert returned["source_slug"] == "nvd"
    assert returned["source_name"] == "National Vulnerability Database"
    assert returned["severity"] == "high"
    assert returned["cvss_score"] == 8.8
    assert "raw_payload" not in returned
    assert "affected_products_json" not in returned
    assert "super-secret-marker" not in response.text


def test_list_pagination_limit_and_offset_work(client) -> None:
    older = make_vulnerability_item(
        cve_id="CVE-2026-00001",
        source_modified_at=datetime(2026, 7, 7, 9, 0, tzinfo=UTC),
        last_seen_at=datetime(2026, 7, 7, 9, 0, tzinfo=UTC),
    )
    newer = make_vulnerability_item(
        cve_id="CVE-2026-00002",
        source_modified_at=datetime(2026, 7, 7, 11, 0, tzinfo=UTC),
        last_seen_at=datetime(2026, 7, 7, 10, 30, tzinfo=UTC),
    )

    response = client(FakeSession([older, newer])).get(
        "/api/v1/intelligence/items?limit=1&offset=1"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert data["limit"] == 1
    assert data["offset"] == 1
    assert [entry["cve_id"] for entry in data["items"]] == ["CVE-2026-00001"]


def test_invalid_limit_returns_validation_error(client) -> None:
    response = client(FakeSession()).get("/api/v1/intelligence/items?limit=101")

    assert response.status_code == 422


def test_invalid_offset_returns_validation_error(client) -> None:
    response = client(FakeSession()).get("/api/v1/intelligence/items?offset=-1")

    assert response.status_code == 422


def test_severity_filter_is_case_insensitive(client) -> None:
    high = make_vulnerability_item(cve_id="CVE-2026-01000", severity="high")
    medium = make_vulnerability_item(cve_id="CVE-2026-01001", severity="medium")

    response = client(FakeSession([high, medium])).get(
        "/api/v1/intelligence/items?severity=HIGH"
    )

    assert response.status_code == 200
    assert [entry["cve_id"] for entry in response.json()["items"]] == [
        "CVE-2026-01000"
    ]


def test_source_slug_filter_works(client) -> None:
    nvd = make_vulnerability_item(cve_id="CVE-2026-02000", source_slug="nvd")
    other = make_vulnerability_item(
        cve_id="CVE-2026-02001",
        source_slug="vendor-feed",
        source_name="Vendor Feed",
    )

    response = client(FakeSession([nvd, other])).get(
        "/api/v1/intelligence/items?source_slug=vendor-feed"
    )

    assert response.status_code == 200
    assert [entry["cve_id"] for entry in response.json()["items"]] == [
        "CVE-2026-02001"
    ]


def test_q_search_matches_title_summary_and_cve_id(client) -> None:
    title_match = make_vulnerability_item(
        cve_id="CVE-2026-03000",
        title="OpenSSL issue",
    )
    summary_match = make_vulnerability_item(
        cve_id="CVE-2026-03001",
        summary="Kernel memory corruption",
    )
    cve_match = make_vulnerability_item(cve_id="CVE-2026-77777")

    title_response = client(FakeSession([title_match, summary_match, cve_match])).get(
        "/api/v1/intelligence/items?q=openssl"
    )
    summary_response = client(
        FakeSession([title_match, summary_match, cve_match])
    ).get("/api/v1/intelligence/items?q=memory")
    cve_response = client(FakeSession([title_match, summary_match, cve_match])).get(
        "/api/v1/intelligence/items?q=77777"
    )

    assert [entry["cve_id"] for entry in title_response.json()["items"]] == [
        "CVE-2026-03000"
    ]
    assert [entry["cve_id"] for entry in summary_response.json()["items"]] == [
        "CVE-2026-03001"
    ]
    assert [entry["cve_id"] for entry in cve_response.json()["items"]] == [
        "CVE-2026-77777"
    ]


def test_cve_id_filter_normalizes_to_uppercase(client) -> None:
    item = make_vulnerability_item(cve_id="CVE-2026-04000")

    response = client(FakeSession([item])).get(
        "/api/v1/intelligence/items?cve_id=cve-2026-04000"
    )

    assert response.status_code == 200
    assert [entry["cve_id"] for entry in response.json()["items"]] == [
        "CVE-2026-04000"
    ]


def test_item_type_filter_can_include_non_vulnerability_records(client) -> None:
    vulnerability = make_vulnerability_item(cve_id="CVE-2026-05000")
    news = make_non_vulnerability_item()

    response = client(FakeSession([vulnerability, news])).get(
        "/api/v1/intelligence/items?item_type=cyber_news"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["item_type"] == "cyber_news"
    assert data["items"][0]["severity"] is None


def test_default_sort_is_newest_first_with_stable_results(client) -> None:
    older = make_vulnerability_item(
        cve_id="CVE-2026-06000",
        source_modified_at=datetime(2026, 7, 7, 8, 0, tzinfo=UTC),
        last_seen_at=datetime(2026, 7, 7, 8, 30, tzinfo=UTC),
    )
    newer = make_vulnerability_item(
        cve_id="CVE-2026-06001",
        source_modified_at=datetime(2026, 7, 7, 11, 30, tzinfo=UTC),
        last_seen_at=datetime(2026, 7, 7, 11, 0, tzinfo=UTC),
    )

    response = client(FakeSession([older, newer])).get("/api/v1/intelligence/items")

    assert response.status_code == 200
    assert [entry["cve_id"] for entry in response.json()["items"]] == [
        "CVE-2026-06001",
        "CVE-2026-06000",
    ]


def test_detail_endpoint_returns_one_safe_item(client) -> None:
    item = make_vulnerability_item(cve_id="CVE-2026-07000")

    response = client(FakeSession([item])).get(
        f"/api/v1/intelligence/items/{item.public_id}"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["public_id"] == str(item.public_id)
    assert data["cve_id"] == "CVE-2026-07000"
    assert "raw_payload" not in data


def test_detail_endpoint_returns_safe_404(client) -> None:
    response = client(FakeSession()).get(
        f"/api/v1/intelligence/items/{uuid4()}"
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "The requested intelligence item was not found."
    }


def test_database_errors_are_sanitized(client) -> None:
    response = client(
        FakeSession(
            error_message="postgresql://private-user:private-password@private-host/db"
        )
    ).get("/api/v1/intelligence/items")

    assert response.status_code == 500
    body = response.json()
    assert body == {"detail": "Unable to load intelligence items."}
    assert "private-password" not in response.text
    assert "postgresql://" not in response.text
