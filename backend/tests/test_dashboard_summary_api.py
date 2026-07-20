from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.query_validation import VALIDATION_ERROR_DETAIL
from app.core.request_context import REQUEST_ID_HEADER
from app.core.security_headers import API_CONTENT_SECURITY_POLICY, SECURITY_HEADERS
from app.db.session import get_db_session
from app.main import app
from app.models import (
    IngestionRun,
    IntelligenceItem,
    IntelligenceSource,
    SourceRecord,
    Vulnerability,
)
from app.services.dashboard_summary_service import (
    ARTICLE_ITEM_TYPE_VALUES,
    HIGH_EPSS_THRESHOLD,
)


NOW = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)


class FakeScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one(self):
        return self._value

    def scalar_one_or_none(self):
        return self._value


class FakeScalars:
    def __init__(self, values: list):
        self._values = values

    def all(self) -> list:
        return list(self._values)

    def first(self):
        return self._values[0] if self._values else None


class FakeRowsResult:
    def __init__(self, values: list):
        self._values = values

    def scalars(self) -> FakeScalars:
        return FakeScalars(self._values)


class FakeSession:
    def __init__(
        self,
        *,
        items: list[IntelligenceItem] | None = None,
        sources: list[IntelligenceSource] | None = None,
        runs: list[IngestionRun] | None = None,
        error_on: str | None = None,
        error_message: str = "postgresql://private-user:private-password@private-host/db",
    ) -> None:
        self.items = items or []
        self.sources = sources or []
        self.runs = runs or []
        self.error_on = error_on
        self.error_message = error_message
        self.execute_kinds: list[str] = []

    def execute(self, statement):
        options = statement.get_execution_options()
        kind = options.get("dashboard_metric") or options.get("dashboard_query")
        self.execute_kinds.append(kind or "unknown")
        if self.error_on == kind:
            raise SQLAlchemyError(self.error_message)
        if kind in METRIC_CALCULATORS:
            return FakeScalarResult(METRIC_CALCULATORS[kind](self.items))
        if kind == "latest_articles":
            return FakeRowsResult(_latest_articles(self.items))
        if kind == "last_successful_ingestion":
            values = [
                source.last_successful_fetch_at
                for source in self.sources
                if source.is_enabled and source.last_successful_fetch_at is not None
            ]
            return FakeScalarResult(max(values) if values else None)
        if kind == "latest_fetch":
            return FakeRowsResult(_latest_runs(self.runs))
        raise AssertionError(f"Unexpected dashboard query kind: {kind}")


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    created_clients: list[TestClient] = []

    def fixed_clock():
        return NOW

    monkeypatch.setattr(
        "app.services.dashboard_summary_service.utc_now",
        fixed_clock,
        raising=False,
    )

    def factory(session: FakeSession) -> TestClient:
        app.dependency_overrides[get_db_session] = lambda: session
        test_client = TestClient(app)
        created_clients.append(test_client)
        return test_client

    yield factory

    app.dependency_overrides.clear()
    for test_client in created_clients:
        test_client.close()


def make_source(
    *,
    index: int,
    slug: str,
    name: str | None = None,
    source_type: str = "rss",
    last_successful_fetch_at: datetime | None = None,
    is_enabled: bool = True,
) -> IntelligenceSource:
    return IntelligenceSource(
        id=index,
        public_id=uuid4(),
        name=name or slug.replace("-", " ").title(),
        slug=slug,
        source_type=source_type,
        base_url=f"https://example.test/{slug}",
        is_enabled=is_enabled,
        rate_limit_notes="not public",
        last_successful_fetch_at=last_successful_fetch_at,
        checkpoint_value="internal-checkpoint",
        created_at=NOW,
        updated_at=NOW,
    )


def make_item(
    *,
    index: int,
    item_type: str,
    title: str,
    status: str = "active",
    severity: str | None = None,
    kev_status: str = "unknown",
    epss_score: Decimal | None = None,
    uae_relevance_status: str = "unknown",
    source_published_at: datetime | None = None,
    collected_at: datetime | None = None,
    last_seen_at: datetime | None = None,
    source: IntelligenceSource | None = None,
    raw_payload_marker: str = "secret-raw-payload",
) -> IntelligenceItem:
    item_source = source or make_source(index=index, slug="cert-eu-security-advisories")
    item = IntelligenceItem(
        id=index,
        public_id=uuid4(),
        item_type=item_type,
        canonical_title=title,
        summary=f"{title} summary.",
        canonical_url=f"https://example.test/{index}",
        source_published_at=source_published_at,
        source_modified_at=None,
        collected_at=collected_at or NOW - timedelta(hours=1),
        last_seen_at=last_seen_at or NOW,
        status=status,
        data_confidence=Decimal("0.900"),
        geographic_scope="global",
        uae_relevance_status=uae_relevance_status,
        uae_relevance_confidence=Decimal("0.750")
        if uae_relevance_status != "unknown"
        else None,
        uae_relevance_reason="internal analyst note",
        uae_relevance_method="manual",
        analyst_review_status="reviewed",
        created_at=NOW,
        updated_at=NOW,
    )
    item.source_records = []
    item.identifiers = []
    item.tag_assignments = []
    source_record = SourceRecord(
        id=index,
        source=item_source,
        intelligence_item=item,
        source_external_id=f"external-{index}",
        source_url=f"https://example.test/source/{index}",
        canonical_url_hash="a" * 64,
        content_hash="b" * 64,
        is_primary_reference=True,
        raw_payload={"marker": raw_payload_marker},
        payload_collected_at=NOW,
        first_seen_at=NOW,
        last_seen_at=last_seen_at or NOW,
        source_published_at=source_published_at,
        source_modified_at=None,
        processing_status="processed",
        last_processed_at=NOW,
        safe_error_summary=None,
        upstream_status="present",
        created_at=NOW,
        updated_at=NOW,
    )
    item.source_records = [source_record]
    existing_records = list(getattr(item_source, "source_records", []) or [])
    if source_record not in existing_records:
        existing_records.append(source_record)
    item_source.source_records = existing_records
    item_source.identifiers = list(getattr(item_source, "identifiers", []) or [])
    if item_type == "vulnerability":
        item.vulnerability = Vulnerability(
            id=index,
            intelligence_item=item,
            severity=severity,
            cvss_score=Decimal("9.8") if severity == "critical" else Decimal("8.8"),
            cvss_vector="CVSS:3.1/AV:N",
            cvss_version="3.1",
            epss_score=epss_score,
            epss_percentile=None,
            kev_status=kev_status,
            kev_last_checked_at=NOW if kev_status == "listed" else None,
            kev_date_added=None,
            kev_due_date=None,
            kev_required_action=None,
            known_ransomware_campaign_use=None,
            affected_summary="affected",
            affected_products_json=[],
            created_at=NOW,
            updated_at=NOW,
        )
    else:
        item.vulnerability = None
    return item


def make_run(
    *,
    index: int,
    source: IntelligenceSource,
    status: str,
    started_at: datetime,
    completed_at: datetime | None,
    fetched: int,
    created: int = 0,
    updated: int = 0,
    unchanged: int = 0,
    skipped: int = 0,
    failed: int = 0,
) -> IngestionRun:
    return IngestionRun(
        id=index,
        public_id=uuid4(),
        source=source,
        trigger_type="manual",
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        records_fetched=fetched,
        records_created=created,
        records_updated=updated,
        records_unchanged=unchanged,
        records_skipped=skipped,
        records_failed=failed,
        error_count=failed,
        checkpoint_before=None,
        checkpoint_after=None,
        safe_summary="not public",
        created_at=started_at,
    )


def _active_items(items: list[IntelligenceItem]) -> list[IntelligenceItem]:
    return [item for item in items if item.status == "active"]


def _active_articles(items: list[IntelligenceItem]) -> list[IntelligenceItem]:
    return [
        item
        for item in _active_items(items)
        if item.item_type in ARTICLE_ITEM_TYPE_VALUES
    ]


def _active_vulnerabilities(items: list[IntelligenceItem]) -> list[IntelligenceItem]:
    return [
        item
        for item in _active_items(items)
        if item.item_type == "vulnerability" and item.vulnerability is not None
    ]


def _latest_articles(items: list[IntelligenceItem]) -> list[IntelligenceItem]:
    return sorted(
        _active_articles(items),
        key=lambda item: (
            item.source_published_at is not None,
            item.source_published_at or datetime.min.replace(tzinfo=UTC),
            item.last_seen_at,
            item.id,
        ),
        reverse=True,
    )[:5]


def _latest_runs(runs: list[IngestionRun]) -> list[IngestionRun]:
    return sorted(runs, key=lambda run: (run.started_at, run.id), reverse=True)[:1]


METRIC_CALCULATORS = {
    "active_intelligence_items": lambda items: len(_active_items(items)),
    "active_article_count": lambda items: len(_active_articles(items)),
    "critical_vulnerabilities": lambda items: len(
        [
            item
            for item in _active_vulnerabilities(items)
            if item.vulnerability.severity == "critical"
        ]
    ),
    "high_severity_vulnerabilities": lambda items: len(
        [
            item
            for item in _active_vulnerabilities(items)
            if item.vulnerability.severity == "high"
        ]
    ),
    "cisa_kev_listed_vulnerabilities": lambda items: len(
        [
            item
            for item in _active_vulnerabilities(items)
            if item.vulnerability.kev_status == "listed"
        ]
    ),
    "high_epss_vulnerabilities": lambda items: len(
        [
            item
            for item in _active_vulnerabilities(items)
            if item.vulnerability.epss_score is not None
            and item.vulnerability.epss_score >= HIGH_EPSS_THRESHOLD
        ]
    ),
    "uae_relevant_intelligence": lambda items: len(
        [
            item
            for item in _active_items(items)
            if item.uae_relevance_status in {"confirmed", "probable"}
        ]
    ),
    "intelligence_items_collected_in_window": lambda items: len(
        [
            item
            for item in _active_items(items)
            if item.collected_at is not None
            and NOW - timedelta(days=30) <= item.collected_at < NOW
        ]
    ),
}


def test_dashboard_summary_empty_database_returns_safe_zero_values(client) -> None:
    response = client(FakeSession()).get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    data = response.json()
    assert data["generated_at"] == "2026-07-10T12:00:00Z"
    assert data["window_days"] == 30
    assert data["window_start"] == "2026-06-10T12:00:00Z"
    assert data["window_end"] == "2026-07-10T12:00:00Z"
    assert data["metrics"] == {
        "critical_vulnerability_count": 0,
        "kev_vulnerability_count": 0,
        "active_article_count": 0,
        "uae_related_item_count": 0,
    }
    assert all(value == 0 for value in data["counts"].values())
    assert data["ingestion"]["last_successful_ingestion_at"] is None
    assert data["latest_articles"] == []
    assert data["latest_fetch"] is None
    request_id = UUID(response.headers[REQUEST_ID_HEADER])
    assert request_id.version == 4
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert response.headers["Content-Security-Policy"] == API_CONTENT_SECURITY_POLICY


@pytest.mark.parametrize(
    ("window_days", "expected_start"),
    [
        (1, "2026-07-09T12:00:00Z"),
        (365, "2025-07-10T12:00:00Z"),
    ],
)
def test_window_days_boundaries_are_accepted(
    client,
    window_days: int,
    expected_start: str,
) -> None:
    response = client(FakeSession()).get(
        f"/api/v1/dashboard/summary?window_days={window_days}"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["window_days"] == window_days
    assert data["window_start"] == expected_start
    assert data["window_end"] == "2026-07-10T12:00:00Z"


def test_dashboard_summary_counts_match_database_fixtures(client) -> None:
    article_source = make_source(
        index=10,
        slug="cert-eu-security-advisories",
        name="CERT-EU Security Advisories",
        last_successful_fetch_at=datetime(2026, 7, 10, 10, tzinfo=UTC),
    )
    nvd_source = make_source(
        index=11,
        slug="nvd",
        name="National Vulnerability Database",
        source_type="api",
        last_successful_fetch_at=datetime(2026, 7, 10, 9, tzinfo=UTC),
    )
    items = [
        make_item(
            index=1,
            item_type="vulnerability",
            title="Critical KEV",
            severity="critical",
            kev_status="listed",
            epss_score=Decimal("0.900000"),
            uae_relevance_status="confirmed",
            source=nvd_source,
        ),
        make_item(
            index=2,
            item_type="vulnerability",
            title="High",
            severity="high",
            kev_status="unknown",
            epss_score=Decimal("0.100000"),
            uae_relevance_status="probable",
            source=nvd_source,
        ),
        make_item(
            index=3,
            item_type="vulnerability",
            title="Archived Critical",
            status="archived",
            severity="critical",
            kev_status="listed",
            epss_score=Decimal("0.950000"),
            source=nvd_source,
        ),
        make_item(
            index=4,
            item_type="security_advisory",
            title="Article One",
            uae_relevance_status="possible",
            source_published_at=datetime(2026, 7, 9, tzinfo=UTC),
            source=article_source,
        ),
        make_item(
            index=5,
            item_type="cyber_news",
            title="Article Two",
            uae_relevance_status="not_relevant",
            source_published_at=datetime(2026, 7, 8, tzinfo=UTC),
            source=article_source,
        ),
        make_item(
            index=6,
            item_type="threat_report",
            title="Old Collected",
            collected_at=datetime(2026, 5, 1, tzinfo=UTC),
            source_published_at=datetime(2026, 7, 7, tzinfo=UTC),
            source=article_source,
        ),
    ]
    run = make_run(
        index=1,
        source=article_source,
        status="partial",
        started_at=datetime(2026, 7, 10, 11, tzinfo=UTC),
        completed_at=datetime(2026, 7, 10, 11, 1, tzinfo=UTC),
        fetched=8,
        created=2,
        updated=1,
        unchanged=3,
        skipped=1,
        failed=1,
    )

    response = client(
        FakeSession(items=items, sources=[article_source, nvd_source], runs=[run])
    ).get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    data = response.json()
    assert data["metrics"] == {
        "critical_vulnerability_count": 1,
        "kev_vulnerability_count": 1,
        "active_article_count": 3,
        "uae_related_item_count": 2,
    }
    assert data["counts"]["active_intelligence_items"] == 5
    assert data["counts"]["critical_vulnerabilities"] == 1
    assert data["counts"]["high_severity_vulnerabilities"] == 1
    assert data["counts"]["cisa_kev_listed_vulnerabilities"] == 1
    assert data["counts"]["high_epss_vulnerabilities"] == 1
    assert data["counts"]["uae_relevant_intelligence"] == 2
    assert data["counts"]["intelligence_items_collected_in_window"] == 4
    assert data["thresholds"]["high_epss_minimum"] == 0.7
    assert data["ingestion"]["last_successful_ingestion_at"] == "2026-07-10T10:00:00Z"
    assert data["latest_fetch"] == {
        "source_slug": "cert-eu-security-advisories",
        "source_name": "CERT-EU Security Advisories",
        "status": "partial",
        "started_at": "2026-07-10T11:00:00Z",
        "completed_at": "2026-07-10T11:01:00Z",
        "fetched_count": 8,
        "processed_count": 7,
        "failed_count": 1,
    }


def test_latest_articles_are_safe_newest_first_and_exclude_vulnerabilities(client) -> None:
    source = make_source(index=20, slug="cert-eu-security-advisories")
    newest = make_item(
        index=1,
        item_type="security_advisory",
        title="Newest Article",
        source_published_at=datetime(2026, 7, 10, 8, tzinfo=UTC),
        source=source,
        raw_payload_marker="do-not-leak",
    )
    same_time_lower_id = make_item(
        index=2,
        item_type="cyber_news",
        title="Same Time Lower",
        source_published_at=datetime(2026, 7, 9, 8, tzinfo=UTC),
        source=source,
    )
    same_time_higher_id = make_item(
        index=3,
        item_type="threat_report",
        title="Same Time Higher",
        source_published_at=datetime(2026, 7, 9, 8, tzinfo=UTC),
        source=source,
    )
    vulnerability = make_item(
        index=4,
        item_type="vulnerability",
        title="CVE Not Article",
        severity="critical",
        source_published_at=datetime(2026, 7, 11, tzinfo=UTC),
    )
    archived = make_item(
        index=5,
        item_type="cyber_news",
        title="Archived Article",
        status="archived",
        source_published_at=datetime(2026, 7, 12, tzinfo=UTC),
    )

    response = client(
        FakeSession(items=[same_time_lower_id, newest, archived, vulnerability, same_time_higher_id])
    ).get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    data = response.json()
    assert [article["title"] for article in data["latest_articles"]] == [
        "Newest Article",
        "Same Time Higher",
        "Same Time Lower",
    ]
    returned = data["latest_articles"][0]
    assert returned["public_id"] == str(newest.public_id)
    assert returned["category"] == "security_advisory"
    assert returned["source_slug"] == "cert-eu-security-advisories"
    assert "raw_payload" not in response.text
    assert "content_hash" not in response.text
    assert "canonical_url_hash" not in response.text
    assert "source_external_id" not in response.text
    assert "do-not-leak" not in response.text


def test_window_days_changes_window_boundaries_and_collected_count(client) -> None:
    in_window = make_item(
        index=1,
        item_type="security_advisory",
        title="In Window",
        collected_at=NOW - timedelta(days=2),
    )
    out_of_window = make_item(
        index=2,
        item_type="security_advisory",
        title="Out Window",
        collected_at=NOW - timedelta(days=10),
    )

    response = client(FakeSession(items=[in_window, out_of_window])).get(
        "/api/v1/dashboard/summary?window_days=7"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["window_days"] == 7
    assert data["window_start"] == "2026-07-03T12:00:00Z"


@pytest.mark.parametrize("query", ["window_days=0", "window_days=366"])
def test_invalid_window_days_returns_422(client, query: str) -> None:
    response = client(FakeSession()).get(f"/api/v1/dashboard/summary?{query}")

    assert response.status_code == 422


def test_latest_fetch_uses_newest_ingestion_run(client) -> None:
    source = make_source(index=1, slug="nvd", name="National Vulnerability Database")
    older = make_run(
        index=1,
        source=source,
        status="succeeded",
        started_at=datetime(2026, 7, 9, tzinfo=UTC),
        completed_at=datetime(2026, 7, 9, 0, 1, tzinfo=UTC),
        fetched=2,
        created=2,
    )
    newer = make_run(
        index=2,
        source=source,
        status="failed",
        started_at=datetime(2026, 7, 10, tzinfo=UTC),
        completed_at=None,
        fetched=0,
        failed=1,
    )

    response = client(FakeSession(runs=[older, newer])).get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    latest = response.json()["latest_fetch"]
    assert latest["status"] == "failed"
    assert latest["started_at"] == "2026-07-10T00:00:00Z"
    assert latest["fetched_count"] == 0
    assert latest["processed_count"] == 0
    assert latest["failed_count"] == 1


def test_database_errors_are_sanitized(client) -> None:
    response = client(
        FakeSession(error_on="critical_vulnerabilities")
    ).get("/api/v1/dashboard/summary")

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to load dashboard summary."}
    assert "private-password" not in response.text
    assert "postgresql://" not in response.text
    assert "SQLAlchemyError" not in response.text


def test_dashboard_summary_does_not_trigger_ingestion_or_network(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("Dashboard summary must not trigger ingestion or network calls.")

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
        "app.ingestion.collectors.cisa_kev_client.CisaKevClient.fetch_catalog",
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
    monkeypatch.setattr(
        "app.ingestion.services.cisa_kev_ingestion_service.CisaKevIngestionService.enrich",
        fail_if_called,
        raising=False,
    )

    response = client(FakeSession(items=[make_item(index=1, item_type="cyber_news", title="News")])).get(
        "/api/v1/dashboard/summary"
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    "query",
    ["unknown=x", "window_days=7&window_days=30"],
)
def test_dashboard_summary_rejects_unsupported_or_repeated_queries(
    client,
    query: str,
) -> None:
    session = FakeSession()

    response = client(session).get(f"/api/v1/dashboard/summary?{query}")

    assert response.status_code == 422
    assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert session.execute_kinds == []
