from __future__ import annotations

from datetime import UTC, datetime
from datetime import date as date_type
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.query_validation import MAX_PAGINATION_OFFSET, VALIDATION_ERROR_DETAIL
from app.core.request_context import REQUEST_ID_HEADER
from app.core.security_headers import API_CONTENT_SECURITY_POLICY, SECURITY_HEADERS
from app.db.session import get_db_session
from app.security.dependencies import require_content_read
from app.main import app
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
    Vulnerability,
)
from app.processing.uae_relevance_classifier import confidence_for_rule


NOW = datetime(2026, 7, 7, 12, 0, tzinfo=UTC)


class FakeScalarResult:
    def __init__(self, items: list[IntelligenceItem]):
        self._items = items

    def all(self) -> list[IntelligenceItem]:
        return list(self._items)


class FakeExecuteResult:
    def __init__(
        self,
        items: list[IntelligenceItem],
        *,
        scalar_value: int | None = None,
    ):
        self._items = items
        self._scalar_value = scalar_value

    def scalars(self) -> FakeScalarResult:
        return FakeScalarResult(self._items)

    def scalar_one(self) -> int:
        if self._scalar_value is None:
            raise AssertionError("This fake result does not contain a scalar value.")
        return self._scalar_value


class FakeSession:
    def __init__(
        self,
        items: list[IntelligenceItem] | None = None,
        *,
        error_message: str | None = None,
    ) -> None:
        self.items = items or []
        self.error_message = error_message
        self.execute_calls = 0
        self.last_statement = None
        self.statements = []

    def execute(self, statement):
        self.execute_calls += 1
        self.last_statement = statement
        self.statements.append(statement)
        if self.error_message is not None:
            raise SQLAlchemyError(self.error_message)
        sql = str(statement)
        params = statement.compile().params
        filtered = self._filter_items(sql, params)
        if "count(" in sql.lower():
            return FakeExecuteResult([], scalar_value=len(filtered))
        order_sql = sql.partition("ORDER BY")[2]
        stable_id = lambda item: item.id or item.public_id.int
        if "intelligence_items.source_published_at ASC" in order_sql:
            ordered = sorted(
                filtered,
                key=lambda item: (
                    item.source_published_at is None,
                    item.source_published_at or datetime.max.replace(tzinfo=UTC),
                    stable_id(item),
                ),
            )
        elif "intelligence_items.source_published_at DESC" in order_sql:
            ordered = sorted(
                filtered,
                key=lambda item: (
                    item.source_published_at is not None,
                    item.source_published_at or datetime.min.replace(tzinfo=UTC),
                    stable_id(item),
                ),
                reverse=True,
            )
        else:
            ordered = sorted(
                filtered,
                key=lambda item: (item.created_at, stable_id(item)),
                reverse=True,
            )
        limit_clause = getattr(statement, "_limit_clause", None)
        offset_clause = getattr(statement, "_offset_clause", None)
        limit = getattr(limit_clause, "value", None)
        offset = getattr(offset_clause, "value", None) or 0
        page = ordered[offset : offset + limit] if limit is not None else ordered
        return FakeExecuteResult(page)

    def _filter_items(self, sql: str, params: dict[str, object]) -> list[IntelligenceItem]:
        values = list(params.values())
        item_type = next(
            (value for key, value in params.items() if "item_type" in key),
            None,
        )
        severity = next(
            (value for key, value in params.items() if "severity" in key),
            None,
        )
        source_slug = next(
            (value for key, value in params.items() if key.startswith("slug_")),
            None,
        )
        geographic_scope = next(
            (value for key, value in params.items() if "geographic_scope" in key),
            None,
        )
        relevance_status = next(
            (value for key, value in params.items() if "uae_relevance_status" in key),
            None,
        )
        boundaries = sorted(value for value in values if isinstance(value, datetime))
        search_value = next(
            (
                str(value)[1:-1]
                for value in values
                if isinstance(value, str)
                and value.startswith("%")
                and value.endswith("%")
            ),
            None,
        )
        exact_cve = next(
            (
                value
                for key, value in params.items()
                if "normalized_value" in key
                and isinstance(value, str)
                and not value.startswith("%")
            ),
            None,
        )

        def matches(item: IntelligenceItem) -> bool:
            if item.status != "active" or (item_type and item.item_type != item_type):
                return False
            if severity and (
                item.vulnerability is None or item.vulnerability.severity != severity
            ):
                return False
            if source_slug and not any(
                record.source is not None and record.source.slug == source_slug
                for record in item.source_records
            ):
                return False
            if geographic_scope and item.geographic_scope != geographic_scope:
                return False
            if relevance_status and item.uae_relevance_status != relevance_status:
                return False
            if len(boundaries) == 2 and not (
                item.source_published_at is not None
                and boundaries[0] <= item.source_published_at < boundaries[1]
            ):
                return False
            if exact_cve and not any(
                identifier.namespace == "cve"
                and identifier.normalized_value == exact_cve
                for identifier in item.identifiers
            ):
                return False
            if search_value is not None:
                normalized_search = (
                    search_value.replace("\\%", "%")
                    .replace("\\_", "_")
                    .replace("\\\\", "\\")
                    .casefold()
                )
                candidates = [item.canonical_title, item.summary]
                candidates.extend(
                    identifier.normalized_value for identifier in item.identifiers
                )
                if not any(
                    candidate is not None
                    and normalized_search in candidate.casefold()
                    for candidate in candidates
                ):
                    return False
            return True

        return [item for item in self.items if matches(item)]


@pytest.fixture
def client():
    created_clients: list[TestClient] = []

    def factory(session: FakeSession) -> TestClient:
        app.dependency_overrides[get_db_session] = lambda: session
        app.dependency_overrides[require_content_read] = lambda: None
        test_client = TestClient(app)
        created_clients.append(test_client)
        return test_client

    yield factory

    app.dependency_overrides.clear()
    for test_client in created_clients:
        test_client.close()


def assert_success_response_headers(response) -> None:
    assert response.headers["content-type"].split(";", maxsplit=1)[0] == "application/json"
    request_id = UUID(response.headers[REQUEST_ID_HEADER])
    assert request_id.version == 4
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert response.headers["Content-Security-Policy"] == API_CONTENT_SECURITY_POLICY


def make_vulnerability_item(
    *,
    item_id: int | None = None,
    public_id: UUID | None = None,
    cve_id: str = "CVE-2026-12345",
    title: str = "Example vulnerability title",
    summary: str = "Example vulnerability summary.",
    severity: str = "high",
    source_slug: str = "nvd",
    source_name: str = "National Vulnerability Database",
    source_published_at: datetime | None = NOW,
    source_modified_at: datetime | None = None,
    last_seen_at: datetime | None = None,
    first_seen_at: datetime | None = None,
    raw_payload_marker: str | None = None,
    epss_score: Decimal | None = None,
    epss_percentile: Decimal | None = None,
    epss_score_date: date_type | None = None,
    kev_status: str = "unknown",
    kev_date_added: date_type | None = None,
    kev_due_date: date_type | None = None,
    known_ransomware_campaign_use: bool | None = None,
    geographic_scope: str = "global",
    uae_relevance_status: str = "unknown",
    uae_relevance_confidence: Decimal | None = None,
    created_at: datetime = NOW,
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
        id=item_id,
        public_id=item_public_id,
        item_type="vulnerability",
        canonical_title=title,
        summary=summary,
        canonical_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        source_published_at=source_published_at,
        source_modified_at=item_source_modified_at,
        collected_at=NOW,
        last_seen_at=item_last_seen_at,
        status="active",
        data_confidence=Decimal("1.000"),
        geographic_scope=geographic_scope,
        uae_relevance_status=uae_relevance_status,
        uae_relevance_confidence=uae_relevance_confidence,
        uae_relevance_reason=None,
        uae_relevance_method="unassigned",
        analyst_review_status="pending",
        created_at=created_at,
        updated_at=NOW,
    )
    vulnerability = Vulnerability(
        intelligence_item=item,
        severity=severity,
        cvss_score=Decimal("8.8"),
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_version="3.1",
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        kev_status=kev_status,
        kev_last_checked_at=None,
        kev_date_added=kev_date_added,
        kev_due_date=kev_due_date,
        kev_required_action=None,
        known_ransomware_campaign_use=known_ransomware_campaign_use,
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
        source_published_at=source_published_at,
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
    if epss_score_date is not None:
        epss_source = IntelligenceSource(
            public_id=uuid4(),
            name="FIRST EPSS",
            slug="first-epss",
            source_type="api",
            base_url="https://api.first.org/data/v1/epss",
            is_enabled=True,
            rate_limit_notes=None,
            last_successful_fetch_at=NOW,
            checkpoint_value=None,
            created_at=NOW,
            updated_at=NOW,
        )
        epss_record = SourceRecord(
            source=epss_source,
            intelligence_item=item,
            source_external_id=cve_id,
            source_url="https://api.first.org/data/v1/epss",
            canonical_url_hash=None,
            content_hash="e" * 64,
            is_primary_reference=False,
            raw_payload={
                "cve": cve_id,
                "epss": str(epss_score),
                "percentile": str(epss_percentile),
                "date": epss_score_date.isoformat(),
            },
            payload_collected_at=NOW,
            first_seen_at=item_first_seen_at,
            last_seen_at=item_last_seen_at,
            source_published_at=None,
            source_modified_at=datetime.combine(epss_score_date, datetime.min.time(), tzinfo=UTC),
            processing_status="processed",
            last_processed_at=NOW,
            safe_error_summary=None,
            upstream_status="present",
            created_at=NOW,
            updated_at=NOW,
        )
        item.source_records.append(epss_record)
        epss_source.source_records = [epss_record]
        epss_source.identifiers = []
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
    assert_success_response_headers(response)
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
    assert returned["epss_score"] is None
    assert returned["epss_percentile"] is None
    assert returned["epss_score_date"] is None
    assert returned["kev_status"] == "unknown"
    assert returned["kev_date_added"] is None
    assert returned["kev_due_date"] is None
    assert returned["known_ransomware_campaign_use"] is None
    assert returned["uae_relevance_confidence"] is None
    assert "raw_payload" not in returned
    assert "affected_products_json" not in returned
    assert "analyst_review_status" not in returned
    assert "created_at" not in returned
    assert "updated_at" not in returned
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


@pytest.mark.parametrize("limit", [0, 101])
def test_invalid_limit_returns_validation_error(client, limit: int) -> None:
    session = FakeSession()
    response = client(session).get(f"/api/v1/intelligence/items?limit={limit}")

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_calls == 0


@pytest.mark.parametrize("offset", [-1, MAX_PAGINATION_OFFSET + 1, 10**100])
def test_invalid_offset_returns_validation_error(client, offset: int) -> None:
    session = FakeSession()
    response = client(session).get(f"/api/v1/intelligence/items?offset={offset}")

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_calls == 0


@pytest.mark.parametrize("limit", [1, 100])
def test_limit_boundaries_are_accepted(client, limit: int) -> None:
    response = client(FakeSession()).get(
        f"/api/v1/intelligence/items?limit={limit}"
    )

    assert response.status_code == 200
    assert response.json() == {
        "items": [],
        "total": 0,
        "limit": limit,
        "offset": 0,
    }


@pytest.mark.parametrize("offset", [0, MAX_PAGINATION_OFFSET])
def test_offset_boundaries_are_accepted(client, offset: int) -> None:
    response = client(FakeSession()).get(
        f"/api/v1/intelligence/items?offset={offset}"
    )

    assert response.status_code == 200
    assert response.json()["offset"] == offset


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


@pytest.mark.parametrize("scope", ["global", "regional", "uae", "unknown"])
def test_geographic_scope_filter_accepts_approved_values(client, scope: str) -> None:
    other_scope = "global" if scope != "global" else "regional"
    matching = make_vulnerability_item(
        cve_id="CVE-2026-02100",
        geographic_scope=scope,
    )
    other = make_vulnerability_item(
        cve_id="CVE-2026-02101",
        geographic_scope=other_scope,
    )

    response = client(FakeSession([matching, other])).get(
        f"/api/v1/intelligence/items?geographic_scope={scope.upper()}"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["cve_id"] == "CVE-2026-02100"
    assert data["items"][0]["geographic_scope"] == scope


@pytest.mark.parametrize(
    "status_value",
    ["confirmed", "probable", "possible", "not_relevant", "unknown"],
)
def test_uae_relevance_status_filter_accepts_approved_values(
    client,
    status_value: str,
) -> None:
    other_status = "unknown" if status_value != "unknown" else "confirmed"
    matching = make_vulnerability_item(
        cve_id="CVE-2026-02110",
        uae_relevance_status=status_value,
    )
    other = make_vulnerability_item(
        cve_id="CVE-2026-02111",
        uae_relevance_status=other_status,
    )

    response = client(FakeSession([matching, other])).get(
        f"/api/v1/intelligence/items?uae_relevance_status={status_value.upper()}"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["cve_id"] == "CVE-2026-02110"
    assert data["items"][0]["uae_relevance_status"] == status_value


def test_geographic_and_uae_relevance_filters_combine_after_search(client) -> None:
    matching = make_vulnerability_item(
        cve_id="CVE-2026-02120",
        title="Exchange appliance issue",
        severity="critical",
        geographic_scope="uae",
        uae_relevance_status="confirmed",
    )
    wrong_scope = make_vulnerability_item(
        cve_id="CVE-2026-02121",
        title="Exchange appliance issue",
        severity="critical",
        geographic_scope="global",
        uae_relevance_status="confirmed",
    )
    wrong_status = make_vulnerability_item(
        cve_id="CVE-2026-02122",
        title="Exchange appliance issue",
        severity="critical",
        geographic_scope="uae",
        uae_relevance_status="possible",
    )
    wrong_search = make_vulnerability_item(
        cve_id="CVE-2026-02123",
        title="Other appliance issue",
        severity="critical",
        geographic_scope="uae",
        uae_relevance_status="confirmed",
    )

    response = client(
        FakeSession([matching, wrong_scope, wrong_status, wrong_search])
    ).get(
        "/api/v1/intelligence/items?"
        "q=exchange"
        "&severity=critical"
        "&geographic_scope=uae"
        "&uae_relevance_status=confirmed",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["cve_id"] == "CVE-2026-02120"


def test_published_year_uses_utc_boundaries_and_filtered_total(client) -> None:
    current_year = datetime.now(UTC).year
    start = datetime(current_year, 1, 1, tzinfo=UTC)
    next_year = datetime(current_year + 1, 1, 1, tzinfo=UTC)
    included_start = make_vulnerability_item(
        cve_id=f"CVE-{current_year}-10000",
        source_published_at=start,
    )
    included_end = make_vulnerability_item(
        cve_id=f"CVE-{current_year}-10001",
        source_published_at=datetime(
            current_year,
            12,
            31,
            23,
            59,
            59,
            999999,
            tzinfo=UTC,
        ),
    )
    excluded_next_year = make_vulnerability_item(
        cve_id=f"CVE-{current_year + 1}-10002",
        source_published_at=next_year,
    )
    session = FakeSession([included_start, included_end, excluded_next_year])

    response = client(session).get(
        f"/api/v1/intelligence/items?published_year={current_year}&limit=1"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 1
    assert session.last_statement is not None
    sql = str(session.last_statement)
    assert "intelligence_items.source_published_at >=" in sql
    assert "intelligence_items.source_published_at <" in sql
    assert {
        "active",
        "vulnerability",
        start,
        next_year,
    } <= set(session.last_statement.compile().params.values())


def test_intelligence_list_filters_counts_and_pages_in_sql(client) -> None:
    session = FakeSession(
        [
            make_vulnerability_item(cve_id=f"CVE-2026-{index:05d}")
            for index in range(30)
        ]
    )

    response = client(session).get(
        "/api/v1/intelligence/items?q=example&severity=high&limit=5&offset=10"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 30
    assert len(response.json()["items"]) == 5
    assert len(session.statements) == 2
    count_sql = str(session.statements[0]).lower()
    page_sql = str(session.statements[1]).lower()
    assert "count(" in count_sql
    assert "vulnerabilities.severity" in count_sql
    assert "intelligence_items.canonical_title" in count_sql
    assert " limit " in f" {page_sql} "
    assert " offset " in f" {page_sql} "


def test_no_published_year_preserves_existing_results(client) -> None:
    older = make_vulnerability_item(
        cve_id="CVE-2020-10000",
        source_published_at=datetime(2020, 6, 1, tzinfo=UTC),
    )
    current = make_vulnerability_item(
        cve_id=f"CVE-{datetime.now(UTC).year}-10001",
        source_published_at=datetime(datetime.now(UTC).year, 6, 1, tzinfo=UTC),
    )

    response = client(FakeSession([older, current])).get(
        "/api/v1/intelligence/items"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 2


def test_published_year_composes_with_search_severity_and_scope(client) -> None:
    current_year = datetime.now(UTC).year
    matching = make_vulnerability_item(
        cve_id=f"CVE-{current_year}-11000",
        title="Exchange gateway issue",
        severity="critical",
        source_published_at=datetime(current_year, 4, 1, tzinfo=UTC),
        geographic_scope="global",
        uae_relevance_status="confirmed",
    )
    wrong_year = make_vulnerability_item(
        cve_id=f"CVE-{current_year - 1}-11001",
        title="Exchange gateway issue",
        severity="critical",
        source_published_at=datetime(current_year - 1, 4, 1, tzinfo=UTC),
        geographic_scope="global",
        uae_relevance_status="confirmed",
    )
    wrong_severity = make_vulnerability_item(
        cve_id=f"CVE-{current_year}-11002",
        title="Exchange gateway issue",
        severity="high",
        source_published_at=datetime(current_year, 4, 1, tzinfo=UTC),
        geographic_scope="global",
        uae_relevance_status="confirmed",
    )
    wrong_scope = make_vulnerability_item(
        cve_id=f"CVE-{current_year}-11003",
        title="Exchange gateway issue",
        severity="critical",
        source_published_at=datetime(current_year, 4, 1, tzinfo=UTC),
        geographic_scope="uae",
        uae_relevance_status="confirmed",
    )

    response = client(
        FakeSession([matching, wrong_year, wrong_severity, wrong_scope])
    ).get(
        "/api/v1/intelligence/items"
        f"?published_year={current_year}"
        "&q=exchange"
        "&severity=critical"
        "&geographic_scope=global"
        "&uae_relevance_status=confirmed"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["cve_id"] == f"CVE-{current_year}-11000"


@pytest.mark.parametrize(
    ("year", "published_at"),
    [
        (2020, datetime(2020, 1, 1, tzinfo=UTC)),
        (
            datetime.now(UTC).year,
            datetime(datetime.now(UTC).year, 1, 1, tzinfo=UTC),
        ),
    ],
)
def test_published_year_supported_boundaries_are_accepted(
    client,
    year: int,
    published_at: datetime,
) -> None:
    item = make_vulnerability_item(
        cve_id=f"CVE-{year}-12000",
        source_published_at=published_at,
    )

    response = client(FakeSession([item])).get(
        f"/api/v1/intelligence/items?published_year={year}"
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1


@pytest.mark.parametrize(
    "published_year",
    [
        "2019",
        str(datetime.now(UTC).year + 1),
        "true",
        "20x6",
        "2020.0",
        "02020",
    ],
)
def test_invalid_published_year_returns_safe_422(client, published_year: str) -> None:
    session = FakeSession([make_vulnerability_item()])

    response = client(session).get(
        f"/api/v1/intelligence/items?published_year={published_year}"
    )

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_calls == 0


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


@pytest.mark.parametrize("search_text", ["%", "_", "\\", "تنبيه دبي"])
def test_q_search_treats_wildcards_and_escape_as_text_and_accepts_unicode(
    client,
    search_text: str,
) -> None:
    match = make_vulnerability_item(
        cve_id="CVE-2026-77778",
        title=f"Defensive advisory {search_text}",
    )
    unrelated = make_vulnerability_item(
        cve_id="CVE-2026-77779",
        title="Unrelated record",
    )

    response = client(FakeSession([match, unrelated])).get(
        "/api/v1/intelligence/items",
        params={"q": search_text},
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert [entry["cve_id"] for entry in response.json()["items"]] == [
        "CVE-2026-77778"
    ]


def test_whitespace_only_q_returns_422(client) -> None:
    response = client(FakeSession([make_vulnerability_item()])).get(
        "/api/v1/intelligence/items?q=%20%20%20"
    )

    assert response.status_code == 422


@pytest.mark.parametrize("severity", ["severe", "%20%20"])
def test_invalid_severity_returns_422(client, severity: str) -> None:
    response = client(FakeSession([make_vulnerability_item()])).get(
        f"/api/v1/intelligence/items?severity={severity}"
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "query",
    [
        "geographic_scope=local",
        "geographic_scope=%20%20",
        "uae_relevance_status=yes",
        "uae_relevance_status=%20%20",
    ],
)
def test_invalid_uae_filter_returns_422(client, query: str) -> None:
    response = client(FakeSession([make_vulnerability_item()])).get(
        f"/api/v1/intelligence/items?{query}"
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "source_slug",
    ["bad_slug", "-bad", "bad-", "bad--slug", "https://example.test/feed", "bad/slug"],
)
def test_invalid_source_slug_returns_422(client, source_slug: str) -> None:
    response = client(FakeSession([make_vulnerability_item()])).get(
        f"/api/v1/intelligence/items?source_slug={source_slug}"
    )

    assert response.status_code == 422


@pytest.mark.parametrize("item_type", ["article", "%20%20"])
def test_invalid_item_type_returns_422(client, item_type: str) -> None:
    response = client(FakeSession([make_vulnerability_item()])).get(
        f"/api/v1/intelligence/items?item_type={item_type}"
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "cve_id",
    [
        "CVE-26-1234",
        "CVE-2026-123",
        "CVE-2026-12AB",
        "2026-1234",
        "%20%20",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
        "CVE-٢٠٢٦-١٢٣٤",
        "CVE-２０２６-１２３４",
        "CVE-2026-１２３４",
        "CVE-２０２６-1234",
    ],
)
def test_malformed_cve_id_returns_422(client, cve_id: str) -> None:
    response = client(FakeSession([make_vulnerability_item()])).get(
        "/api/v1/intelligence/items",
        params={"cve_id": cve_id},
    )

    assert response.status_code == 422


def test_cve_id_filter_normalizes_to_uppercase(client) -> None:
    item = make_vulnerability_item(cve_id="CVE-2026-04000")

    response = client(FakeSession([item])).get(
        "/api/v1/intelligence/items?cve_id=cve-2026-04000"
    )

    assert response.status_code == 200
    assert [entry["cve_id"] for entry in response.json()["items"]] == [
        "CVE-2026-04000"
    ]


@pytest.mark.parametrize(
    "query",
    [
        "severity=high",
        "cve_id=CVE-2026-12345",
        "published_year=2020",
    ],
)
def test_vulnerability_filters_with_explicit_article_item_type_return_400(
    client,
    query: str,
) -> None:
    response = client(FakeSession([make_non_vulnerability_item()])).get(
        f"/api/v1/intelligence/items?item_type=cyber_news&{query}"
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Vulnerability filters require item_type=vulnerability."
    }


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


def test_vulnerability_sort_modes_are_distinct_stable_and_paginated(client) -> None:
    older_publication_new_ingest = make_vulnerability_item(
        item_id=1,
        cve_id="CVE-2026-06000",
        source_published_at=datetime(2026, 1, 1, tzinfo=UTC),
        created_at=datetime(2026, 7, 7, 12, 0, tzinfo=UTC),
    )
    newer_publication_old_ingest = make_vulnerability_item(
        item_id=2,
        cve_id="CVE-2026-06001",
        source_published_at=datetime(2026, 6, 1, tzinfo=UTC),
        created_at=datetime(2026, 7, 7, 8, 0, tzinfo=UTC),
    )
    same_publication_high_id = make_vulnerability_item(
        item_id=3,
        cve_id="CVE-2026-06002",
        source_published_at=datetime(2026, 6, 1, tzinfo=UTC),
        created_at=datetime(2026, 7, 7, 8, 0, tzinfo=UTC),
    )
    session = FakeSession(
        [older_publication_new_ingest, newer_publication_old_ingest, same_publication_high_id]
    )

    recent = client(session).get("/api/v1/intelligence/items?sort=recently_ingested")
    newest_page = client(session).get(
        "/api/v1/intelligence/items?sort=newest_published&limit=2&offset=1"
    )
    oldest = client(session).get("/api/v1/intelligence/items?sort=oldest_published")

    assert [entry["cve_id"] for entry in recent.json()["items"]] == [
        "CVE-2026-06000",
        "CVE-2026-06002",
        "CVE-2026-06001",
    ]
    assert newest_page.json()["total"] == 3
    assert [entry["cve_id"] for entry in newest_page.json()["items"]] == [
        "CVE-2026-06001",
        "CVE-2026-06000",
    ]
    assert [entry["cve_id"] for entry in oldest.json()["items"]] == [
        "CVE-2026-06000",
        "CVE-2026-06001",
        "CVE-2026-06002",
    ]


@pytest.mark.parametrize("sort", ["created_at", "newest_published desc", "unknown"])
def test_invalid_vulnerability_sort_is_rejected(client, sort: str) -> None:
    response = client(FakeSession()).get(
        "/api/v1/intelligence/items",
        params={"sort": sort},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == VALIDATION_ERROR_DETAIL


def test_detail_endpoint_returns_one_safe_item(client) -> None:
    item = make_vulnerability_item(
        cve_id="CVE-2026-07000",
        epss_score=Decimal("0.123456"),
        epss_percentile=Decimal("0.654321"),
        epss_score_date=date_type(2026, 7, 8),
        kev_status="listed",
        kev_date_added=date_type(2026, 7, 7),
        kev_due_date=date_type(2026, 7, 21),
        known_ransomware_campaign_use=False,
        uae_relevance_confidence=confidence_for_rule("direct_country_name"),
        raw_payload_marker="nvd-secret-marker",
    )

    response = client(FakeSession([item])).get(
        f"/api/v1/intelligence/items/{item.public_id}"
    )

    assert response.status_code == 200
    assert_success_response_headers(response)
    data = response.json()
    assert data["public_id"] == str(item.public_id)
    assert data["cve_id"] == "CVE-2026-07000"
    assert data["epss_score"] == 0.123456
    assert data["epss_percentile"] == 0.654321
    assert data["epss_score_date"] == "2026-07-08"
    assert data["kev_status"] == "listed"
    assert data["kev_date_added"] == "2026-07-07"
    assert data["kev_due_date"] == "2026-07-21"
    assert data["known_ransomware_campaign_use"] is False
    assert data["source_slug"] == "nvd"
    assert data["source_name"] == "National Vulnerability Database"
    assert data["geographic_scope"] == "global"
    assert data["uae_relevance_confidence"] == 0.95
    assert isinstance(data["uae_relevance_confidence"], float)
    assert "raw_payload" not in data
    assert "source_record" not in data
    assert "source_external_id" not in data
    assert "content_hash" not in data
    assert "canonical_url_hash" not in data
    assert "headers" not in data
    assert "analyst_review_status" not in data
    assert "created_at" not in data
    assert "updated_at" not in data
    assert "nvd-secret-marker" not in response.text


def test_detail_endpoint_returns_safe_non_vulnerability_item(client) -> None:
    item = make_non_vulnerability_item()

    response = client(FakeSession([item])).get(
        f"/api/v1/intelligence/items/{item.public_id}"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["public_id"] == str(item.public_id)
    assert data["item_type"] == "cyber_news"
    assert data["title"] == "Regional cyber news"
    assert data["source_slug"] == "example-feed"
    assert data["severity"] is None
    assert data["cve_id"] is None
    assert data["geographic_scope"] == "regional"
    assert data["uae_relevance_status"] == "possible"
    assert data["uae_relevance_confidence"] == 0.42
    for prohibited in (
        "news-raw-payload",
        "raw_payload",
        "content_hash",
        "analyst_review_status",
        "uae_relevance_reason",
        "uae_relevance_method",
    ):
        assert prohibited not in response.text


def test_detail_endpoint_does_not_trigger_ingestion_or_network(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = make_vulnerability_item(cve_id="CVE-2026-07001")

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("Read-only detail API must not trigger ingestion.")

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

    response = client(FakeSession([item])).get(
        f"/api/v1/intelligence/items/{item.public_id}"
    )

    assert response.status_code == 200
    assert response.json()["cve_id"] == "CVE-2026-07001"


def test_list_endpoint_returns_epss_fields_without_replacing_primary_source(client) -> None:
    item = make_vulnerability_item(
        cve_id="CVE-2026-08000",
        epss_score=Decimal("0.500000"),
        epss_percentile=Decimal("0.900000"),
        epss_score_date=date_type(2026, 7, 9),
    )

    response = client(FakeSession([item])).get("/api/v1/intelligence/items")

    assert response.status_code == 200
    returned = response.json()["items"][0]
    assert returned["epss_score"] == 0.5
    assert returned["epss_percentile"] == 0.9
    assert returned["epss_score_date"] == "2026-07-09"
    assert returned["source_slug"] == "nvd"
    assert returned["source_name"] == "National Vulnerability Database"
    assert "FIRST EPSS" not in returned["source_name"]
    assert "raw_payload" not in returned


def test_detail_endpoint_returns_safe_404(client) -> None:
    response = client(FakeSession()).get(
        f"/api/v1/intelligence/items/{uuid4()}"
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "The requested intelligence item was not found."
    }


@pytest.mark.parametrize("status", ["archived", "merged", "superseded"])
def test_inactive_intelligence_is_excluded_and_detail_matches_nonexistent_404(
    client,
    status: str,
) -> None:
    inactive = make_vulnerability_item()
    inactive.status = status
    session = FakeSession([inactive])

    list_response = client(session).get("/api/v1/intelligence/items")
    inactive_response = client(session).get(
        f"/api/v1/intelligence/items/{inactive.public_id}"
    )
    missing_response = client(session).get(
        f"/api/v1/intelligence/items/{uuid4()}"
    )

    assert list_response.status_code == 200
    assert list_response.json()["items"] == []
    assert inactive_response.status_code == missing_response.status_code == 404
    assert inactive_response.json() == missing_response.json() == {
        "detail": "The requested intelligence item was not found."
    }
    detail_sql = str(session.last_statement)
    assert "intelligence_items.public_id" in detail_sql
    assert "intelligence_items.status" in detail_sql


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


def test_detail_database_errors_are_sanitized(client) -> None:
    database_canary = "postgresql://detail-user:detail-password@private-host/db"
    response = client(FakeSession(error_message=database_canary)).get(
        f"/api/v1/intelligence/items/{uuid4()}"
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Unable to load the requested intelligence item."
    }
    assert database_canary not in response.text
    assert "detail-password" not in response.text


def test_detail_endpoint_rejects_query_parameters_before_lookup(client) -> None:
    session = FakeSession([make_vulnerability_item()])

    response = client(session).get(
        f"/api/v1/intelligence/items/{uuid4()}?unknown=x"
    )

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_calls == 0


@pytest.mark.parametrize(
    "query",
    [
        "severity=critical&severity=low",
        "published_year=2020&published_year=2021",
        "q=first&q=second",
        "offset=0&offset=1",
    ],
)
def test_repeated_intelligence_query_parameters_are_rejected(
    client,
    query: str,
) -> None:
    session = FakeSession([make_vulnerability_item()])

    response = client(session).get(f"/api/v1/intelligence/items?{query}")

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_calls == 0


@pytest.mark.parametrize(
    "query",
    ["unknown_param=x", "sort=title", "order=sideways", "field=raw_payload"],
)
def test_unsupported_intelligence_query_parameters_are_rejected(
    client,
    query: str,
) -> None:
    session = FakeSession([make_vulnerability_item()])

    response = client(session).get(f"/api/v1/intelligence/items?{query}")

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_calls == 0


def test_uppercase_canonical_intelligence_uuid_is_accepted(client) -> None:
    item = make_vulnerability_item(
        public_id=UUID("abcdefab-cdef-4abc-8def-abcdefabcdef")
    )

    response = client(FakeSession([item])).get(
        f"/api/v1/intelligence/items/{str(item.public_id).upper()}"
    )

    assert response.status_code == 200
    assert response.json()["public_id"] == str(item.public_id)


@pytest.mark.parametrize(
    "item_public_id",
    [
        "12345678123456781234567812345678",
        "{12345678-1234-5678-1234-567812345678}",
        "malformed-uuid",
        "12345678-1234-5678-1234-5678123456780",
    ],
)
def test_noncanonical_intelligence_uuid_is_rejected_before_lookup(
    client,
    item_public_id: str,
) -> None:
    session = FakeSession([make_vulnerability_item()])

    response = client(session).get(
        f"/api/v1/intelligence/items/{item_public_id}"
    )

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert item_public_id not in response.text
    assert session.execute_calls == 0
