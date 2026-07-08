from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import get_db_session
from app.main import app
from app.models import IntelligenceItem, IntelligenceSource, SourceRecord
from app.services.article_query_service import ARTICLE_ITEM_TYPES


NOW = datetime(2026, 7, 8, 12, 0, tzinfo=UTC)


class FakeCountResult:
    def __init__(self, value: int):
        self._value = value

    def scalar_one(self) -> int:
        return self._value


class FakeScalarResult:
    def __init__(self, items: list[IntelligenceItem]):
        self._items = items

    def all(self) -> list[IntelligenceItem]:
        return list(self._items)


class FakeItemResult:
    def __init__(self, items: list[IntelligenceItem]):
        self._items = items

    def scalars(self) -> FakeScalarResult:
        return FakeScalarResult(self._items)


class FakeSession:
    def __init__(
        self,
        items: list[IntelligenceItem] | None = None,
        *,
        error_on: str | None = None,
        error_message: str = "postgresql://private-user:private-password@private-host/db",
    ) -> None:
        self.items = items or []
        self.error_on = error_on
        self.error_message = error_message
        self.execute_calls: list[str] = []

    def execute(self, statement):
        kind = "count" if _is_count_statement(statement) else "items"
        self.execute_calls.append(kind)
        if self.error_on == kind:
            raise SQLAlchemyError(self.error_message)

        query = _extract_query(statement)
        matches = _filtered_articles(self.items, query)
        if kind == "count":
            return FakeCountResult(len(matches))

        page = matches[_offset(statement) : _offset(statement) + _limit(statement)]
        return FakeItemResult(page)


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


def make_article(
    *,
    index: int = 1,
    item_type: str = "security_advisory",
    status: str = "active",
    title: str = "CERT-EU Security Advisory",
    summary: str | None = "Safe advisory summary.",
    source_slug: str | None = "cert-eu-security-advisories",
    source_name: str | None = "CERT-EU Security Advisories",
    source_url: str = "https://cert.europa.eu/publications/security-advisories/2026-001",
    canonical_url: str | None = "https://example.test/canonical",
    item_published_at: datetime | None = NOW,
    item_modified_at: datetime | None = None,
    source_published_at: datetime | None = NOW,
    source_modified_at: datetime | None = None,
    last_seen_at: datetime = NOW,
    geographic_scope: str = "global",
    uae_relevance_status: str = "unknown",
    uae_relevance_confidence: Decimal | None = None,
    primary_source: bool = True,
    with_source_record: bool = True,
    raw_payload_marker: str = "secret-raw-payload",
) -> IntelligenceItem:
    item = IntelligenceItem(
        id=index,
        public_id=uuid4(),
        item_type=item_type,
        canonical_title=title,
        summary=summary,
        canonical_url=canonical_url,
        source_published_at=item_published_at,
        source_modified_at=item_modified_at,
        collected_at=NOW,
        last_seen_at=last_seen_at,
        status=status,
        data_confidence=Decimal("0.900"),
        geographic_scope=geographic_scope,
        uae_relevance_status=uae_relevance_status,
        uae_relevance_confidence=uae_relevance_confidence,
        uae_relevance_reason="analyst-only reason",
        uae_relevance_method="manual",
        analyst_review_status="reviewed",
        created_at=NOW,
        updated_at=NOW,
    )
    item.source_records = []
    item.identifiers = []
    if not with_source_record:
        return item

    source = None
    if source_slug is not None and source_name is not None:
        source = IntelligenceSource(
            id=index,
            public_id=uuid4(),
            name=source_name,
            slug=source_slug,
            source_type="rss",
            base_url="https://example.test/feed",
            is_enabled=True,
            created_at=NOW,
            updated_at=NOW,
        )
    source_record = SourceRecord(
        id=index,
        source=source,
        intelligence_item=item,
        source_external_id=f"external-{index}",
        source_url=source_url,
        canonical_url_hash="a" * 64,
        content_hash="b" * 64,
        is_primary_reference=primary_source,
        raw_payload={"marker": raw_payload_marker},
        payload_collected_at=NOW,
        first_seen_at=NOW,
        last_seen_at=last_seen_at,
        source_published_at=source_published_at,
        source_modified_at=source_modified_at,
        processing_status="processed",
        last_processed_at=NOW,
        safe_error_summary=None,
        upstream_status="present",
        created_at=NOW,
        updated_at=NOW,
    )
    item.source_records = [source_record]
    if source is not None:
        source.source_records = [source_record]
        source.identifiers = []
    return item


def _is_count_statement(statement) -> bool:
    return "count" in str(statement).lower().split("from", 1)[0]


def _extract_query(statement) -> str | None:
    for value in statement.compile().params.values():
        if isinstance(value, str) and value.startswith("%") and value.endswith("%"):
            return _unescape_like(value[1:-1])
    return None


def _unescape_like(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            output.append(value[index + 1])
            index += 2
            continue
        output.append(value[index])
        index += 1
    return "".join(output)


def _limit(statement) -> int:
    clause = getattr(statement, "_limit_clause", None)
    return int(getattr(clause, "value", 25) or 25)


def _offset(statement) -> int:
    clause = getattr(statement, "_offset_clause", None)
    return int(getattr(clause, "value", 0) or 0)


def _filtered_articles(
    items: list[IntelligenceItem],
    query: str | None,
) -> list[IntelligenceItem]:
    matches = [
        item
        for item in items
        if item.status == "active" and item.item_type in ARTICLE_ITEM_TYPES
    ]
    if query is not None:
        lowered = query.lower()
        matches = [
            item
            for item in matches
            if lowered in item.canonical_title.lower()
            or (item.summary is not None and lowered in item.summary.lower())
        ]
    return sorted(
        matches,
        key=lambda item: (
            item.source_published_at is not None,
            item.source_published_at or datetime.min.replace(tzinfo=UTC),
            item.last_seen_at,
            item.id,
        ),
        reverse=True,
    )


def test_articles_endpoint_returns_empty_result(client) -> None:
    session = FakeSession()

    response = client(session).get("/api/v1/articles")

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "limit": 25, "offset": 0}
    assert session.execute_calls == ["count", "items"]


def test_articles_endpoint_returns_safe_article_fields(client) -> None:
    item = make_article(
        title="CERT-EU advisory",
        summary="Plain text summary.",
        geographic_scope="uae",
        uae_relevance_status="confirmed",
        uae_relevance_confidence=Decimal("0.750"),
        raw_payload_marker="do-not-leak",
    )

    response = client(FakeSession([item])).get("/api/v1/articles")

    assert response.status_code == 200
    data = response.json()
    returned = data["items"][0]
    assert data["total"] == 1
    assert returned == {
        "public_id": str(item.public_id),
        "title": "CERT-EU advisory",
        "summary": "Plain text summary.",
        "category": "security_advisory",
        "source_slug": "cert-eu-security-advisories",
        "source_name": "CERT-EU Security Advisories",
        "source_url": "https://cert.europa.eu/publications/security-advisories/2026-001",
        "published_at": "2026-07-08T12:00:00Z",
        "modified_at": None,
        "geographic_scope": "uae",
        "uae_relevance_status": "confirmed",
        "uae_relevance_confidence": 0.75,
        "last_seen_at": "2026-07-08T12:00:00Z",
    }
    forbidden = [
        "raw_payload",
        "canonical_url_hash",
        "content_hash",
        "source_external_id",
        "safe_error_summary",
        "analyst",
        "do-not-leak",
    ]
    for value in forbidden:
        assert value not in response.text


def test_all_article_item_types_are_included(client) -> None:
    items = [
        make_article(index=index, item_type=item_type, title=item_type)
        for index, item_type in enumerate(ARTICLE_ITEM_TYPES, start=1)
    ]

    response = client(FakeSession(items)).get("/api/v1/articles")

    assert response.status_code == 200
    assert {entry["category"] for entry in response.json()["items"]} == set(
        ARTICLE_ITEM_TYPES
    )


def test_vulnerabilities_are_excluded_from_article_list(client) -> None:
    article = make_article(index=1, title="Article")
    vulnerability = make_article(index=2, item_type="vulnerability", title="CVE")

    response = client(FakeSession([article, vulnerability])).get("/api/v1/articles")

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert [entry["title"] for entry in response.json()["items"]] == ["Article"]


def test_inactive_items_are_excluded(client) -> None:
    items = [
        make_article(index=1, title="Active", status="active"),
        make_article(index=2, title="Merged", status="merged"),
        make_article(index=3, title="Superseded", status="superseded"),
        make_article(index=4, title="Archived", status="archived"),
    ]

    response = client(FakeSession(items)).get("/api/v1/articles")

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["title"] == "Active"


def test_pagination_uses_total_matching_count(client) -> None:
    items = [
        make_article(index=1, title="Old", item_published_at=datetime(2026, 7, 1, tzinfo=UTC)),
        make_article(index=2, title="Middle", item_published_at=datetime(2026, 7, 2, tzinfo=UTC)),
        make_article(index=3, title="New", item_published_at=datetime(2026, 7, 3, tzinfo=UTC)),
    ]

    response = client(FakeSession(items)).get("/api/v1/articles?limit=1&offset=1")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert data["limit"] == 1
    assert data["offset"] == 1
    assert [entry["title"] for entry in data["items"]] == ["Middle"]


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "offset=-1"])
def test_invalid_pagination_returns_422(client, query: str) -> None:
    response = client(FakeSession()).get(f"/api/v1/articles?{query}")

    assert response.status_code == 422


def test_search_matches_title_summary_and_trims_whitespace(client) -> None:
    title_match = make_article(index=1, title="Cloud Advisory", summary="x")
    summary_match = make_article(index=2, title="Other", summary="Regional defense note")
    unrelated = make_article(index=3, title="Unrelated", summary="No match")

    title_response = client(FakeSession([title_match, summary_match, unrelated])).get(
        "/api/v1/articles?q= cloud "
    )
    summary_response = client(FakeSession([title_match, summary_match, unrelated])).get(
        "/api/v1/articles?q=DEFENSE"
    )

    assert [entry["title"] for entry in title_response.json()["items"]] == [
        "Cloud Advisory"
    ]
    assert [entry["title"] for entry in summary_response.json()["items"]] == ["Other"]


@pytest.mark.parametrize("query", ["q=%20%20%20", "q=%09%09"])
def test_whitespace_only_search_returns_422(client, query: str) -> None:
    response = client(FakeSession([make_article()])).get(f"/api/v1/articles?{query}")

    assert response.status_code == 422


def test_omitted_search_returns_unfiltered_article_list(client) -> None:
    first = make_article(index=1, title="First article")
    second = make_article(index=2, title="Second article")

    response = client(FakeSession([first, second])).get("/api/v1/articles")

    assert response.status_code == 200
    assert response.json()["total"] == 2
    assert {entry["title"] for entry in response.json()["items"]} == {
        "First article",
        "Second article",
    }


def test_search_treats_sql_wildcards_as_literal_text(client) -> None:
    percent = make_article(index=1, title="Patch reaches 100% coverage")
    underscore = make_article(index=2, title="Actor uses A_B marker")
    unrelated = make_article(index=3, title="Actor uses AXB marker")

    percent_response = client(FakeSession([percent, underscore, unrelated])).get(
        "/api/v1/articles?q=100%25"
    )
    underscore_response = client(FakeSession([percent, underscore, unrelated])).get(
        "/api/v1/articles?q=A_B"
    )

    assert [entry["title"] for entry in percent_response.json()["items"]] == [
        "Patch reaches 100% coverage"
    ]
    assert [entry["title"] for entry in underscore_response.json()["items"]] == [
        "Actor uses A_B marker"
    ]


def test_search_does_not_inspect_raw_payload_source_url_or_external_id(client) -> None:
    raw_only = make_article(
        index=1,
        title="No matching text",
        summary="No matching summary",
        source_url="https://example.test/secret-source-url-marker",
        raw_payload_marker="secret-payload-marker",
    )
    raw_only.source_records[0].source_external_id = "secret-external-marker"

    for query in ("secret-payload-marker", "secret-source-url-marker", "secret-external-marker"):
        response = client(FakeSession([raw_only])).get(f"/api/v1/articles?q={query}")
        assert response.status_code == 200
        assert response.json()["items"] == []


def test_sorting_is_newest_first_nulls_last_and_stable(client) -> None:
    same_date_low_id = make_article(
        index=1,
        title="Same date lower id",
        item_published_at=datetime(2026, 7, 3, tzinfo=UTC),
        last_seen_at=datetime(2026, 7, 3, 9, tzinfo=UTC),
    )
    null_date = make_article(index=2, title="Null date", item_published_at=None)
    newest = make_article(
        index=3,
        title="Newest",
        item_published_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    same_date_high_id = make_article(
        index=4,
        title="Same date higher id",
        item_published_at=datetime(2026, 7, 3, tzinfo=UTC),
        last_seen_at=datetime(2026, 7, 3, 9, tzinfo=UTC),
    )

    session = FakeSession([same_date_low_id, null_date, newest, same_date_high_id])
    first = client(session).get("/api/v1/articles")
    second = client(session).get("/api/v1/articles")

    expected = ["Newest", "Same date higher id", "Same date lower id", "Null date"]
    assert [entry["title"] for entry in first.json()["items"]] == expected
    assert [entry["title"] for entry in second.json()["items"]] == expected


def test_primary_source_is_selected_over_non_primary_linked_source(client) -> None:
    item = make_article(index=1, title="Multi-source")
    linked_source = IntelligenceSource(
        id=2,
        public_id=uuid4(),
        name="Linked Source",
        slug="linked-source",
        source_type="rss",
        base_url="https://example.test/linked",
        is_enabled=True,
        created_at=NOW,
        updated_at=NOW,
    )
    item.source_records.append(
        SourceRecord(
            id=2,
            source=linked_source,
            intelligence_item=item,
            source_external_id="linked",
            source_url="https://example.test/linked/article",
            canonical_url_hash="c" * 64,
            content_hash="d" * 64,
            is_primary_reference=False,
            raw_payload={"marker": "linked"},
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
    )

    response = client(FakeSession([item])).get("/api/v1/articles")

    returned = response.json()["items"][0]
    assert returned["source_slug"] == "cert-eu-security-advisories"
    assert returned["source_name"] == "CERT-EU Security Advisories"
    assert returned["source_url"] == item.source_records[0].source_url


def test_deterministic_source_fallback_and_missing_source_data(client) -> None:
    fallback_item = make_article(index=1, title="Fallback")
    fallback_item.source_records[0].is_primary_reference = False
    second_source = IntelligenceSource(
        id=2,
        public_id=uuid4(),
        name="Alpha Source",
        slug="alpha-source",
        source_type="rss",
        base_url="https://example.test/alpha",
        is_enabled=True,
        created_at=NOW,
        updated_at=NOW,
    )
    fallback_item.source_records.append(
        SourceRecord(
            id=2,
            source=second_source,
            intelligence_item=fallback_item,
            source_external_id="alpha",
            source_url="https://example.test/alpha/article",
            canonical_url_hash="e" * 64,
            content_hash="f" * 64,
            is_primary_reference=False,
            raw_payload=None,
            payload_collected_at=NOW,
            first_seen_at=NOW,
            last_seen_at=NOW,
            source_published_at=None,
            source_modified_at=None,
            processing_status="processed",
            last_processed_at=NOW,
            safe_error_summary=None,
            upstream_status="present",
            created_at=NOW,
            updated_at=NOW,
        )
    )
    missing = make_article(
        index=3,
        title="Missing source",
        canonical_url="https://example.test/canonical-fallback",
        with_source_record=False,
    )

    response = client(FakeSession([fallback_item, missing])).get("/api/v1/articles")

    by_title = {entry["title"]: entry for entry in response.json()["items"]}
    assert by_title["Fallback"]["source_slug"] == "alpha-source"
    assert by_title["Fallback"]["source_url"] == "https://example.test/alpha/article"
    assert by_title["Missing source"]["source_slug"] is None
    assert by_title["Missing source"]["source_name"] is None
    assert by_title["Missing source"]["source_url"] == "https://example.test/canonical-fallback"


def test_date_fallback_prefers_source_then_item_then_null(client) -> None:
    source_dates = make_article(
        index=1,
        title="Source dates",
        item_published_at=datetime(2026, 7, 1, tzinfo=UTC),
        item_modified_at=datetime(2026, 7, 2, tzinfo=UTC),
        source_published_at=datetime(2026, 7, 3, tzinfo=UTC),
        source_modified_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    item_dates = make_article(
        index=2,
        title="Item dates",
        item_published_at=datetime(2026, 7, 5, tzinfo=UTC),
        item_modified_at=datetime(2026, 7, 6, tzinfo=UTC),
        source_published_at=None,
        source_modified_at=None,
    )
    no_dates = make_article(
        index=3,
        title="No dates",
        item_published_at=None,
        item_modified_at=None,
        source_published_at=None,
        source_modified_at=None,
    )

    response = client(FakeSession([source_dates, item_dates, no_dates])).get(
        "/api/v1/articles"
    )

    by_title = {entry["title"]: entry for entry in response.json()["items"]}
    assert by_title["Source dates"]["published_at"] == "2026-07-03T00:00:00Z"
    assert by_title["Source dates"]["modified_at"] == "2026-07-04T00:00:00Z"
    assert by_title["Item dates"]["published_at"] == "2026-07-05T00:00:00Z"
    assert by_title["Item dates"]["modified_at"] == "2026-07-06T00:00:00Z"
    assert by_title["No dates"]["published_at"] is None
    assert by_title["No dates"]["modified_at"] is None


def test_uae_global_fields_are_returned_without_invention(client) -> None:
    unknown = make_article(
        index=1,
        title="Unknown",
        geographic_scope="unknown",
        uae_relevance_status="unknown",
        uae_relevance_confidence=None,
    )
    probable = make_article(
        index=2,
        title="Probable UAE",
        geographic_scope="uae",
        uae_relevance_status="probable",
        uae_relevance_confidence=Decimal("0.333"),
    )

    response = client(FakeSession([unknown, probable])).get("/api/v1/articles")

    by_title = {entry["title"]: entry for entry in response.json()["items"]}
    assert by_title["Unknown"]["geographic_scope"] == "unknown"
    assert by_title["Unknown"]["uae_relevance_status"] == "unknown"
    assert by_title["Unknown"]["uae_relevance_confidence"] is None
    assert by_title["Probable UAE"]["geographic_scope"] == "uae"
    assert by_title["Probable UAE"]["uae_relevance_status"] == "probable"
    assert by_title["Probable UAE"]["uae_relevance_confidence"] == 0.333
    assert "uae_global_tag" not in response.text


@pytest.mark.parametrize("error_on", ["count", "items"])
def test_database_errors_are_sanitized(client, error_on: str) -> None:
    response = client(FakeSession([make_article()], error_on=error_on)).get(
        "/api/v1/articles"
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to load articles."}
    assert "private-password" not in response.text
    assert "postgresql://" not in response.text


def test_article_listing_does_not_trigger_ingestion(client, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("Article listing must not trigger ingestion.")

    monkeypatch.setattr(
        "app.ingestion.collectors.rss_client.RssClient.fetch_cert_eu_security_advisories",
        fail_if_called,
        raising=False,
    )
    monkeypatch.setattr(
        "app.ingestion.collectors.nvd_client.NvdClient.fetch_page",
        fail_if_called,
        raising=False,
    )
    monkeypatch.setattr(
        "app.ingestion.collectors.epss_client.EpssClient.fetch_scores",
        fail_if_called,
        raising=False,
    )
    monkeypatch.setattr(
        "app.ingestion.services.rss_ingestion_service.RssIngestionService.persist",
        fail_if_called,
        raising=False,
    )
    monkeypatch.setattr(
        "app.ingestion.services.nvd_ingestion_service.NvdIngestionService.persist",
        fail_if_called,
        raising=False,
    )
    monkeypatch.setattr(
        "app.ingestion.services.epss_enrichment_service.EpssEnrichmentService.enrich",
        fail_if_called,
        raising=False,
    )

    response = client(FakeSession([make_article()])).get("/api/v1/articles")

    assert response.status_code == 200
