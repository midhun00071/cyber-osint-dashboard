from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.query_validation import (
    MAX_PAGINATION_OFFSET,
    MAX_SEARCH_LENGTH,
    VALIDATION_ERROR_DETAIL,
)
from app.db.session import get_db_session
from app.main import app
from app.models import (
    IntelligenceItem,
    IntelligenceItemTag,
    IntelligenceSource,
    SourceRecord,
    Tag,
)
from app.services.article_query_service import (
    ARTICLE_ITEM_TYPES,
    ArticleQueryFilters,
    ArticleQueryService,
)


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

    def one_or_none(self) -> IntelligenceItem | None:
        if not self._items:
            return None
        if len(self._items) > 1:
            raise AssertionError("Fake detail query returned multiple rows.")
        return self._items[0]


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
        filters = _extract_filters(statement)
        kind = (
            "count"
            if _is_count_statement(statement)
            else "detail"
            if filters.get("public_id") is not None
            else "items"
        )
        self.execute_calls.append(kind)
        if self.error_on == kind or (kind == "detail" and self.error_on == "items"):
            raise SQLAlchemyError(self.error_message)

        matches = _filtered_articles(self.items, filters)
        if kind == "count":
            return FakeCountResult(len(matches))

        if kind == "detail":
            return FakeItemResult(matches[:1])

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
    item.tag_assignments = []
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


def add_linked_source(
    item: IntelligenceItem,
    *,
    index: int,
    slug: str,
    name: str | None = None,
    primary: bool = False,
) -> SourceRecord:
    source = IntelligenceSource(
        id=index,
        public_id=uuid4(),
        name=name or slug.replace("-", " ").title(),
        slug=slug,
        source_type="rss",
        base_url=f"https://example.test/{slug}",
        is_enabled=True,
        created_at=NOW,
        updated_at=NOW,
    )
    record = SourceRecord(
        id=index,
        source=source,
        intelligence_item=item,
        source_external_id=f"linked-{index}",
        source_url=f"https://example.test/{slug}/article",
        canonical_url_hash="c" * 64,
        content_hash="d" * 64,
        is_primary_reference=primary,
        raw_payload={"marker": slug},
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
    item.source_records.append(record)
    source.source_records = [record]
    source.identifiers = []
    return record


def add_tag(item: IntelligenceItem, *, index: int, slug: str) -> IntelligenceItemTag:
    tag = Tag(
        id=index,
        slug=slug,
        display_name=slug.replace("-", " ").title(),
        tag_type="theme",
        created_at=NOW,
    )
    assignment = IntelligenceItemTag(
        intelligence_item=item,
        tag=tag,
        assigned_by="system",
        confidence=Decimal("0.900"),
        created_at=NOW,
    )
    item.tag_assignments.append(assignment)
    tag.item_assignments = [assignment]
    return assignment


def _extract_filters(statement) -> dict[str, object]:
    sql = str(statement)
    params = statement.compile().params
    filters: dict[str, object] = {}
    for value in params.values():
        if isinstance(value, UUID):
            filters["public_id"] = value
            break
    if isinstance(params.get("item_type_2"), str):
        filters["category"] = params["item_type_2"]
    for index in range(1, 5):
        key = f"slug_{index}"
        if key not in params:
            continue
        if f"intelligence_sources.slug = :{key}" in sql:
            filters["source_slug"] = params[key]
        if f"tags.slug = :{key}" in sql:
            filters["tag_slug"] = params[key]
    if "source_published_at_1" in params:
        filters["published_from"] = params["source_published_at_1"]
    if "source_published_at_2" in params:
        filters["published_to_exclusive"] = params["source_published_at_2"]
    if "geographic_scope_1" in params:
        filters["geographic_scope"] = params["geographic_scope_1"]
    if "uae_relevance_status_1" in params:
        filters["uae_relevance_status"] = params["uae_relevance_status_1"]
    filters["query"] = _extract_query(params)
    return filters


def _extract_query(params: dict[str, object]) -> str | None:
    for value in params.values():
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
    filters: dict[str, object],
) -> list[IntelligenceItem]:
    matches = [
        item
        for item in items
        if item.status == "active" and item.item_type in ARTICLE_ITEM_TYPES
    ]
    if filters.get("public_id") is not None:
        matches = [item for item in matches if item.public_id == filters["public_id"]]
    if filters.get("category") is not None:
        matches = [item for item in matches if item.item_type == filters["category"]]
    if filters.get("source_slug") is not None:
        matches = [
            item
            for item in matches
            if any(
                source_record.source is not None
                and source_record.source.slug == filters["source_slug"]
                for source_record in item.source_records
            )
        ]
    if filters.get("tag_slug") is not None:
        matches = [
            item
            for item in matches
            if any(
                assignment.tag is not None
                and assignment.tag.slug == filters["tag_slug"]
                for assignment in item.tag_assignments
            )
        ]
    if filters.get("published_from") is not None:
        matches = [
            item
            for item in matches
            if item.source_published_at is not None
            and item.source_published_at >= filters["published_from"]
        ]
    if filters.get("published_to_exclusive") is not None:
        matches = [
            item
            for item in matches
            if item.source_published_at is not None
            and item.source_published_at < filters["published_to_exclusive"]
        ]
    if filters.get("geographic_scope") is not None:
        matches = [
            item
            for item in matches
            if item.geographic_scope == filters["geographic_scope"]
        ]
    if filters.get("uae_relevance_status") is not None:
        matches = [
            item
            for item in matches
            if item.uae_relevance_status == filters["uae_relevance_status"]
        ]
    query = filters.get("query")
    if query is not None:
        lowered = str(query).lower()
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


def test_article_detail_endpoint_returns_safe_article_fields(client) -> None:
    item = make_article(
        title="CERT-EU detail advisory",
        summary="Plain text detail summary.",
        geographic_scope="uae",
        uae_relevance_status="probable",
        uae_relevance_confidence=Decimal("0.640"),
        raw_payload_marker="detail-do-not-leak",
    )

    response = client(FakeSession([item])).get(f"/api/v1/articles/{item.public_id}")

    assert response.status_code == 200
    assert response.json() == {
        "public_id": str(item.public_id),
        "title": "CERT-EU detail advisory",
        "summary": "Plain text detail summary.",
        "category": "security_advisory",
        "source_slug": "cert-eu-security-advisories",
        "source_name": "CERT-EU Security Advisories",
        "source_url": "https://cert.europa.eu/publications/security-advisories/2026-001",
        "published_at": "2026-07-08T12:00:00Z",
        "modified_at": None,
        "geographic_scope": "uae",
        "uae_relevance_status": "probable",
        "uae_relevance_confidence": 0.64,
        "last_seen_at": "2026-07-08T12:00:00Z",
    }
    forbidden = [
        "raw_payload",
        "canonical_url_hash",
        "content_hash",
        "source_external_id",
        "source_record",
        "internal",
        "safe_error_summary",
        "analyst",
        "detail-do-not-leak",
    ]
    for value in forbidden:
        assert value not in response.text


def test_article_detail_endpoint_returns_404_for_missing_public_id(client) -> None:
    response = client(FakeSession()).get(f"/api/v1/articles/{uuid4()}")

    assert response.status_code == 404
    assert response.json() == {"detail": "The requested article was not found."}


def test_article_detail_endpoint_returns_404_for_vulnerability(client) -> None:
    item = make_article(item_type="vulnerability", title="CVE record")

    response = client(FakeSession([item])).get(f"/api/v1/articles/{item.public_id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "The requested article was not found."}


@pytest.mark.parametrize("status_value", ["merged", "superseded", "archived"])
def test_article_detail_endpoint_returns_404_for_inactive_status(
    client,
    status_value: str,
) -> None:
    item = make_article(status=status_value, title=status_value)

    response = client(FakeSession([item])).get(f"/api/v1/articles/{item.public_id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "The requested article was not found."}


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


@pytest.mark.parametrize("category", ARTICLE_ITEM_TYPES)
def test_category_filter_accepts_approved_article_categories(client, category: str) -> None:
    matching = make_article(index=1, item_type=category, title=category)
    other_type = "cyber_news" if category != "cyber_news" else "security_advisory"
    other = make_article(index=2, item_type=other_type, title="Other")

    response = client(FakeSession([matching, other])).get(
        f"/api/v1/articles?category={category}"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["category"] == category


@pytest.mark.parametrize("category", ["vulnerability", "made_up", "%20%20"])
def test_invalid_category_filter_returns_422(client, category: str) -> None:
    response = client(FakeSession([make_article()])).get(
        f"/api/v1/articles?category={category}"
    )

    assert response.status_code == 422


def test_category_filter_combines_with_search(client) -> None:
    matching = make_article(
        index=1,
        item_type="security_advisory",
        title="Exchange advisory",
    )
    wrong_category = make_article(index=2, item_type="cyber_news", title="Exchange news")
    wrong_search = make_article(index=3, item_type="security_advisory", title="Other")

    response = client(FakeSession([matching, wrong_category, wrong_search])).get(
        "/api/v1/articles?category=security_advisory&q=exchange"
    )

    assert response.status_code == 200
    assert [entry["title"] for entry in response.json()["items"]] == [
        "Exchange advisory"
    ]


def test_source_slug_filter_matches_any_linked_source_and_displays_primary(client) -> None:
    item = make_article(index=1, title="Cross-source advisory")
    add_linked_source(item, index=20, slug="vendor-feed")
    unrelated = make_article(index=2, title="Unrelated")

    response = client(FakeSession([item, unrelated])).get(
        "/api/v1/articles?source_slug=VENDOR-FEED"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "Cross-source advisory"
    assert data["items"][0]["source_slug"] == "cert-eu-security-advisories"


def test_unrelated_source_slug_does_not_match(client) -> None:
    item = make_article(index=1, title="Primary only")

    response = client(FakeSession([item])).get(
        "/api/v1/articles?source_slug=vendor-feed"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 0


@pytest.mark.parametrize(
    "source_slug",
    ["bad_slug", "-bad", "bad-", "bad--slug", "https://example.test/feed", "bad/slug"],
)
def test_invalid_source_slug_filter_returns_422(client, source_slug: str) -> None:
    response = client(FakeSession([make_article()])).get(
        f"/api/v1/articles?source_slug={source_slug}"
    )

    assert response.status_code == 422


def test_source_filter_preserves_total_and_pagination(client) -> None:
    older = make_article(
        index=1,
        title="Older vendor",
        item_published_at=datetime(2026, 7, 1, tzinfo=UTC),
        source_slug="vendor-feed",
        source_name="Vendor Feed",
    )
    newer = make_article(
        index=2,
        title="Newer vendor",
        item_published_at=datetime(2026, 7, 2, tzinfo=UTC),
        source_slug="vendor-feed",
        source_name="Vendor Feed",
    )
    other = make_article(index=3, title="Other source")

    response = client(FakeSession([older, newer, other])).get(
        "/api/v1/articles?source_slug=vendor-feed&limit=1&offset=1"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 2
    assert [entry["title"] for entry in response.json()["items"]] == ["Older vendor"]


def test_tag_slug_filter_matches_exact_assignment_without_exposing_metadata(client) -> None:
    matching = make_article(index=1, title="Tagged advisory")
    add_tag(matching, index=1, slug="exchange-server")
    add_tag(matching, index=2, slug="patch-management")
    unrelated = make_article(index=2, title="Other tag")
    add_tag(unrelated, index=3, slug="vpn")

    response = client(FakeSession([matching, unrelated])).get(
        "/api/v1/articles?tag_slug=EXCHANGE-SERVER"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert [entry["title"] for entry in response.json()["items"]] == ["Tagged advisory"]
    assert "tag_assignments" not in response.text
    assert "assigned_by" not in response.text


def test_tag_filter_does_not_duplicate_articles_with_multiple_assignments(client) -> None:
    item = make_article(index=1, title="Multi-tag")
    add_tag(item, index=1, slug="exchange-server")
    add_tag(item, index=2, slug="exchange-server")

    response = client(FakeSession([item])).get(
        "/api/v1/articles?tag_slug=exchange-server"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert len(response.json()["items"]) == 1


@pytest.mark.parametrize("tag_slug", ["bad_slug", "-bad", "bad-", "bad--slug"])
def test_invalid_tag_slug_filter_returns_422(client, tag_slug: str) -> None:
    response = client(FakeSession([make_article()])).get(
        f"/api/v1/articles?tag_slug={tag_slug}"
    )

    assert response.status_code == 422


def test_publication_date_filters_are_inclusive_and_exclude_null_dates(client) -> None:
    before = make_article(
        index=1,
        title="Before",
        item_published_at=datetime(2026, 7, 7, 23, 59, tzinfo=UTC),
    )
    boundary_start = make_article(
        index=2,
        title="Boundary start",
        item_published_at=datetime(2026, 7, 8, 0, 0, tzinfo=UTC),
    )
    boundary_end = make_article(
        index=3,
        title="Boundary end",
        item_published_at=datetime(2026, 7, 9, 23, 59, tzinfo=UTC),
    )
    after = make_article(
        index=4,
        title="After",
        item_published_at=datetime(2026, 7, 10, 0, 0, tzinfo=UTC),
    )
    no_date = make_article(index=5, title="No date", item_published_at=None)

    response = client(FakeSession([before, boundary_start, boundary_end, after, no_date])).get(
        "/api/v1/articles?published_from=2026-07-08&published_to=2026-07-09"
    )

    assert response.status_code == 200
    assert {entry["title"] for entry in response.json()["items"]} == {
        "Boundary start",
        "Boundary end",
    }


def test_single_ended_and_equal_publication_date_ranges_work(client) -> None:
    day = make_article(
        index=1,
        title="On day",
        item_published_at=datetime(2026, 7, 8, 12, tzinfo=UTC),
    )
    later = make_article(
        index=2,
        title="Later",
        item_published_at=datetime(2026, 7, 9, 12, tzinfo=UTC),
    )

    from_response = client(FakeSession([day, later])).get(
        "/api/v1/articles?published_from=2026-07-09"
    )
    equal_response = client(FakeSession([day, later])).get(
        "/api/v1/articles?published_from=2026-07-08&published_to=2026-07-08"
    )

    assert [entry["title"] for entry in from_response.json()["items"]] == ["Later"]
    assert [entry["title"] for entry in equal_response.json()["items"]] == ["On day"]


@pytest.mark.parametrize(
    "query",
    [
        "published_from=2026-07-10&published_to=2026-07-09",
        "published_from=2026-01-01&published_to=2031-01-02",
        "published_from=2024-02-29&published_to=2029-03-01",
        "published_to=9999-12-31",
        "published_from=9999-12-31&published_to=9999-12-31",
        "published_from=9994-12-29&published_to=9999-12-30",
    ],
)
def test_invalid_publication_date_combinations_return_400(client, query: str) -> None:
    response = client(FakeSession([make_article()])).get(f"/api/v1/articles?{query}")

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid article date range."}
    assert "OverflowError" not in response.text
    assert "ValueError" not in response.text


def test_exactly_five_calendar_years_and_leap_day_range_are_accepted(client) -> None:
    response = client(FakeSession([make_article()])).get(
        "/api/v1/articles?published_from=2024-02-29&published_to=2029-02-28"
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    "query",
    [
        "published_from=9995-01-01&published_to=9999-01-01",
        "published_from=9994-12-30&published_to=9999-12-30",
    ],
)
def test_high_year_publication_date_ranges_do_not_overflow(client, query: str) -> None:
    response = client(FakeSession([make_article()])).get(f"/api/v1/articles?{query}")

    assert response.status_code == 200
    assert "OverflowError" not in response.text
    assert "ValueError" not in response.text


def test_invalid_publication_date_text_returns_422(client) -> None:
    response = client(FakeSession([make_article()])).get(
        "/api/v1/articles?published_from=not-a-date"
    )

    assert response.status_code == 422


@pytest.mark.parametrize("scope", ["global", "regional", "uae", "unknown"])
def test_geographic_scope_filter_accepts_approved_values(client, scope: str) -> None:
    matching = make_article(index=1, title=scope, geographic_scope=scope)
    other_scope = "global" if scope != "global" else "regional"
    other = make_article(index=2, title="Other", geographic_scope=other_scope)

    response = client(FakeSession([matching, other])).get(
        f"/api/v1/articles?geographic_scope={scope.upper()}"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["geographic_scope"] == scope


@pytest.mark.parametrize(
    "status_value",
    ["confirmed", "probable", "possible", "not_relevant", "unknown"],
)
def test_uae_relevance_status_filter_accepts_approved_values(
    client,
    status_value: str,
) -> None:
    matching = make_article(index=1, title=status_value, uae_relevance_status=status_value)
    other_status = "unknown" if status_value != "unknown" else "confirmed"
    other = make_article(index=2, title="Other", uae_relevance_status=other_status)

    response = client(FakeSession([matching, other])).get(
        f"/api/v1/articles?uae_relevance_status={status_value.upper()}"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["uae_relevance_status"] == status_value


@pytest.mark.parametrize(
    "query",
    [
        "geographic_scope=local",
        "geographic_scope=%20%20",
        "uae_relevance_status=yes",
        "uae_relevance_status=%20%20",
    ],
)
def test_invalid_geographic_and_uae_filters_return_422(client, query: str) -> None:
    response = client(FakeSession([make_article()])).get(f"/api/v1/articles?{query}")

    assert response.status_code == 422


def test_unknown_geographic_scope_is_distinct_from_global(client) -> None:
    unknown = make_article(index=1, title="Unknown", geographic_scope="unknown")
    global_item = make_article(index=2, title="Global", geographic_scope="global")

    response = client(FakeSession([unknown, global_item])).get(
        "/api/v1/articles?geographic_scope=unknown"
    )

    assert response.status_code == 200
    assert [entry["title"] for entry in response.json()["items"]] == ["Unknown"]


def test_all_article_filters_combine_with_and_semantics(client) -> None:
    matching = make_article(
        index=1,
        item_type="security_advisory",
        title="Exchange advisory",
        summary="Patch required for regional operators.",
        item_published_at=datetime(2026, 7, 8, 9, tzinfo=UTC),
        source_slug="primary-feed",
        source_name="Primary Feed",
        geographic_scope="uae",
        uae_relevance_status="confirmed",
    )
    add_linked_source(matching, index=20, slug="vendor-feed")
    add_tag(matching, index=1, slug="exchange-server")
    wrong_tag = make_article(
        index=2,
        item_type="security_advisory",
        title="Exchange advisory",
        item_published_at=datetime(2026, 7, 8, 10, tzinfo=UTC),
        geographic_scope="uae",
        uae_relevance_status="confirmed",
    )
    add_linked_source(wrong_tag, index=21, slug="vendor-feed")
    add_tag(wrong_tag, index=2, slug="vpn")

    response = client(FakeSession([matching, wrong_tag])).get(
        "/api/v1/articles"
        "?q=exchange"
        "&category=security_advisory"
        "&source_slug=vendor-feed"
        "&tag_slug=exchange-server"
        "&published_from=2026-07-08"
        "&published_to=2026-07-08"
        "&geographic_scope=uae"
        "&uae_relevance_status=confirmed"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert [entry["title"] for entry in response.json()["items"]] == [
        "Exchange advisory"
    ]


def test_source_and_tag_filters_are_database_level_exists_predicates() -> None:
    statement = ArticleQueryService(FakeSession())._filtered_statement(
        ArticleQueryFilters(source_slug="vendor-feed", tag_slug="exchange-server")
    )
    sql = str(statement)

    assert "EXISTS" in sql
    assert "source_records" in sql
    assert "intelligence_sources" in sql
    assert "intelligence_item_tags" in sql
    assert "tags" in sql
    assert " JOIN " not in sql.split("WHERE", 1)[0]


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


def test_article_detail_database_errors_are_sanitized(client) -> None:
    item = make_article()

    response = client(FakeSession([item], error_on="detail")).get(
        f"/api/v1/articles/{item.public_id}"
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to load article."}
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


def test_article_detail_does_not_trigger_ingestion(client, monkeypatch: pytest.MonkeyPatch) -> None:
    item = make_article()

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("Article detail must not trigger ingestion.")

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

    response = client(FakeSession([item])).get(f"/api/v1/articles/{item.public_id}")

    assert response.status_code == 200


def test_offset_zero_and_maximum_are_accepted(client) -> None:
    zero_session = FakeSession([make_article()])
    maximum_session = FakeSession([make_article()])

    zero_response = client(zero_session).get("/api/v1/articles?offset=0")
    maximum_response = client(maximum_session).get(
        f"/api/v1/articles?offset={MAX_PAGINATION_OFFSET}"
    )

    assert zero_response.status_code == 200
    assert zero_response.json()["offset"] == 0
    assert maximum_response.status_code == 200
    assert maximum_response.json()["offset"] == MAX_PAGINATION_OFFSET


@pytest.mark.parametrize(
    "offset",
    [MAX_PAGINATION_OFFSET + 1, 10**100],
)
def test_oversized_offset_is_rejected_before_database_access(client, offset: int) -> None:
    session = FakeSession([make_article()])

    response = client(session).get(f"/api/v1/articles?offset={offset}")

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_calls == []


@pytest.mark.parametrize(
    "query",
    [
        "limit=1&limit=100",
        "offset=0&offset=1",
        "q=alpha&q=beta",
        "category=cyber_news&category=threat_report",
        "published_from=2026-01-01&published_from=2025-01-01",
        "li%6Dit=1&limit=2",
    ],
)
def test_repeated_scalar_query_parameters_are_rejected(client, query: str) -> None:
    session = FakeSession([make_article()])

    response = client(session).get(f"/api/v1/articles?{query}")

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_calls == []


def test_different_supported_query_parameters_remain_accepted(client) -> None:
    response = client(FakeSession([make_article()])).get(
        "/api/v1/articles?limit=1&offset=0"
    )

    assert response.status_code == 200


@pytest.mark.parametrize("query", ["unknown_param=x", "sort=title"])
def test_unsupported_article_query_parameters_are_rejected(client, query: str) -> None:
    session = FakeSession([make_article()])

    response = client(session).get(f"/api/v1/articles?{query}")

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_calls == []


@pytest.mark.parametrize(
    "search_text",
    [
        "O'Brien - TLS 1.3 / API: (Dubai).",
        "تنبيه أمني دبي",
    ],
)
def test_search_accepts_useful_punctuation_and_unicode(client, search_text: str) -> None:
    response = client(FakeSession([make_article(title=search_text)])).get(
        "/api/v1/articles",
        params={"q": search_text},
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_search_length_boundary_is_enforced(client) -> None:
    maximum = "a" * MAX_SEARCH_LENGTH
    too_long = "b" * (MAX_SEARCH_LENGTH + 1)

    valid_response = client(FakeSession([make_article(title=maximum)])).get(
        "/api/v1/articles",
        params={"q": maximum},
    )
    invalid_response = client(FakeSession([make_article(title=too_long)])).get(
        "/api/v1/articles",
        params={"q": too_long},
    )

    assert valid_response.status_code == 200
    assert valid_response.json()["total"] == 1
    assert invalid_response.status_code == 422
    assert invalid_response.json() == {"detail": VALIDATION_ERROR_DETAIL}


@pytest.mark.parametrize(
    "search_text",
    [
        "nul\x00value",
        "line\nfeed",
        "carriage\rreturn",
        "tab\tvalue",
        "zero\u200bwidth",
        "<script",
        "script>",
    ],
)
def test_search_rejects_controls_format_characters_and_markup(
    client,
    search_text: str,
) -> None:
    session = FakeSession([make_article()])

    response = client(session).get(
        "/api/v1/articles",
        params={"q": search_text},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert search_text not in response.text
    assert session.execute_calls == []


def test_search_treats_escape_character_as_literal_text(client) -> None:
    matching = make_article(index=1, title=r"Windows path C:\\Temp")
    unrelated = make_article(index=2, title="Windows path C:Temp")

    response = client(FakeSession([matching, unrelated])).get(
        "/api/v1/articles",
        params={"q": r"C:\\Temp"},
    )

    assert response.status_code == 200
    assert [item["title"] for item in response.json()["items"]] == [matching.canonical_title]


def test_uppercase_canonical_article_uuid_is_accepted(client) -> None:
    item = make_article()
    item.public_id = UUID("abcdefab-cdef-4abc-8def-abcdefabcdef")

    response = client(FakeSession([item])).get(
        f"/api/v1/articles/{str(item.public_id).upper()}"
    )

    assert response.status_code == 200
    assert response.json()["public_id"] == str(item.public_id)


@pytest.mark.parametrize(
    "public_id",
    [
        "12345678123456781234567812345678",
        "{12345678-1234-5678-1234-567812345678}",
        "not-a-uuid",
        "12345678-1234-5678-1234-567812345678-extra",
    ],
)
def test_noncanonical_article_uuid_is_safely_rejected_before_lookup(
    client,
    public_id: str,
) -> None:
    session = FakeSession([make_article()])

    response = client(session).get(f"/api/v1/articles/{public_id}")

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert public_id not in response.text
    assert session.execute_calls == []
    for prohibited in (
        "uuid_parsing",
        "input",
        "ValueError",
        "RequestValidationError",
        "traceback",
        "postgresql://",
    ):
        assert prohibited not in response.text


def test_article_detail_rejects_query_parameters(client) -> None:
    item = make_article()
    session = FakeSession([item])

    response = client(session).get(f"/api/v1/articles/{item.public_id}?unknown=x")

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_calls == []
