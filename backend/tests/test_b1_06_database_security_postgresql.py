"""Disposable PostgreSQL 17 acceptance for the B1-06 database boundary."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal
import ipaddress
import os
from pathlib import Path
import socket

from alembic import command
from alembic.config import Config
import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import (
    IngestionRun,
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
    Vulnerability,
)
from app.services.article_query_service import ArticleQueryFilters, ArticleQueryService
from app.services.dashboard_summary_service import DashboardSummaryService
from app.services.intelligence_query_service import (
    IntelligenceNotFoundError,
    IntelligenceQueryFilters,
    IntelligenceQueryService,
)


DATABASE_ENV = "B106_POSTGRESQL_TEST_DATABASE_URL"
BACKEND_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"
HEAD = "d7a9e51c2f40"
NOW = datetime(2026, 8, 2, 8, 0, tzinfo=UTC)
RAW_CANARY = "raw-payload-canary password=highly-sensitive"
CHECKPOINT_CANARY = "checkpoint-canary-do-not-expose"
SUMMARY_CANARY = "safe-summary-canary-do-not-expose"
PROHIBITED_COLUMNS = {
    "raw_payload",
    "affected_products_json",
    "canonical_url_hash",
    "content_hash",
    "processing_status",
    "safe_error_summary",
    "uae_relevance_reason",
    "uae_relevance_method",
    "analyst_review_status",
    "checkpoint_value",
    "checkpoint_before",
    "checkpoint_after",
    "safe_summary",
    "kev_required_action",
    "kev_last_checked_at",
}
PAYLOADS = (
    "' OR 1=1 --",
    "%'; DROP TABLE intelligence_items; --",
    "UNION SELECT",
    "%",
    "_",
    "\\",
    "--",
    "/*",
    "*/",
    "1; SELECT pg_sleep(10)",
)
QUERY_OVERRIDE_NAMES = (
    "host",
    "hostaddr",
    "dbname",
    "database",
    "service",
    "servicefile",
    "user",
    "password",
    "port",
    "options",
    "sslmode",
)


def _validated_database_url(raw: str) -> URL:
    try:
        url = make_url(raw)
    except Exception:
        pytest.fail("Dedicated B1-06 database configuration is invalid")
    if url.drivername not in {"postgresql", "postgresql+psycopg"}:
        pytest.fail("Dedicated B1-06 database must use PostgreSQL")
    if url.query:
        pytest.fail("Dedicated B1-06 database URL query parameters are forbidden")
    host = (url.host or "").strip("[]").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("Dedicated B1-06 database must be loopback-only")
    if host == "localhost":
        try:
            addresses = {
                ipaddress.ip_address(result[4][0])
                for result in socket.getaddrinfo(host, url.port or 5432)
            }
        except (OSError, ValueError):
            pytest.fail("Dedicated B1-06 database host could not be resolved safely")
        if not addresses or not all(address.is_loopback for address in addresses):
            pytest.fail("Dedicated B1-06 database must resolve only to loopback")
    database = url.database or ""
    if not database.startswith("b106_test_"):
        pytest.fail("Dedicated B1-06 database name must use the disposable prefix")
    if any(label in database.casefold() for label in ("staging", "production", "prod")):
        pytest.fail("Staging and production database names are forbidden")
    return url.set(drivername="postgresql+psycopg")


def _database_url() -> URL:
    raw = os.getenv(DATABASE_ENV)
    if not raw:
        pytest.skip(f"{DATABASE_ENV} is not configured")
    return _validated_database_url(raw)


@contextmanager
def _database_url_environment(url: URL):
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url.render_as_string(hide_password=False)
    get_settings.cache_clear()
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
        get_settings.cache_clear()


def _reset_schema(engine: sa.Engine) -> None:
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")


@pytest.fixture(scope="module")
def pg_engine():
    url = _database_url()
    engine = sa.create_engine(url, poolclass=sa.pool.NullPool)
    try:
        with engine.connect() as connection:
            version = int(connection.exec_driver_sql("SHOW server_version_num").scalar_one())
        assert 170000 <= version < 180000, "B1-06 acceptance requires PostgreSQL 17"
        _reset_schema(engine)
        with _database_url_environment(url):
            config = Config(str(ALEMBIC_INI))
            config.set_main_option(
                "sqlalchemy.url", url.render_as_string(hide_password=False)
            )
            command.upgrade(config, HEAD)
        yield engine
    finally:
        try:
            _reset_schema(engine)
        finally:
            engine.dispose()


@pytest.fixture()
def populated_session(pg_engine):
    with Session(pg_engine) as session:
        _clear_test_rows(session)
        source = IntelligenceSource(
            name="B1-06 Test Source",
            slug="b1-06-test-source",
            source_type="rss",
            base_url="https://example.invalid/",
            is_enabled=True,
            checkpoint_value=CHECKPOINT_CANARY,
            last_successful_fetch_at=NOW,
        )
        active = IntelligenceItem(
            item_type="vulnerability",
            canonical_title="B1-06 active vulnerability",
            summary="Safe public summary",
            canonical_url="https://example.invalid/active",
            source_published_at=NOW,
            source_modified_at=NOW,
            collected_at=NOW,
            last_seen_at=NOW,
            status="active",
            data_confidence=Decimal("0.900"),
            geographic_scope="global",
            uae_relevance_status="unknown",
            uae_relevance_reason="internal UAE reason canary",
            uae_relevance_method="automatic",
            analyst_review_status="pending",
        )
        vulnerability = Vulnerability(
            intelligence_item=active,
            severity="high",
            cvss_score=Decimal("8.1"),
            kev_status="not_listed",
            kev_required_action="internal KEV action canary",
            affected_products_json=[{"canary": "affected-products-canary"}],
        )
        identifier = IntelligenceItemIdentifier(
            intelligence_item=active,
            source=None,
            source_record=None,
            namespace="cve",
            identifier_value="CVE-2026-10001",
            normalized_value="CVE-2026-10001",
            is_primary=True,
        )
        active_record = SourceRecord(
            source=source,
            intelligence_item=active,
            source_external_id="active-record",
            source_url="https://example.invalid/active",
            canonical_url_hash="a" * 64,
            content_hash="b" * 64,
            is_primary_reference=True,
            raw_payload={"canary": RAW_CANARY},
            payload_collected_at=NOW,
            first_seen_at=NOW,
            last_seen_at=NOW,
            source_published_at=NOW,
            source_modified_at=NOW,
            processing_status="processed",
            safe_error_summary="diagnostic canary",
            upstream_status="present",
        )
        article_titles = ("Literal % article", "Literal _ article", "Literal \\ article")
        for index, title in enumerate(article_titles, start=1):
            article = IntelligenceItem(
                item_type="cyber_news",
                canonical_title=title,
                summary="Article used for literal wildcard tests",
                canonical_url=f"https://example.invalid/article-{index}",
                source_published_at=NOW,
                collected_at=NOW,
                last_seen_at=NOW,
                status="active",
                geographic_scope="global",
                uae_relevance_status="unknown",
                uae_relevance_method="automatic",
                analyst_review_status="pending",
            )
            session.add(article)
        inactive: dict[str, IntelligenceItem] = {}
        for status in ("archived", "merged", "superseded"):
            item = IntelligenceItem(
                item_type="vulnerability",
                canonical_title=f"B1-06 {status} vulnerability",
                collected_at=NOW,
                last_seen_at=NOW,
                status=status,
                geographic_scope="global",
                uae_relevance_status="unknown",
                uae_relevance_method="automatic",
                analyst_review_status="pending",
            )
            if status == "merged":
                item.merged_into = active
            elif status == "superseded":
                item.superseded_by = active
            inactive[status] = item
            session.add(item)
        run = IngestionRun(
            source=source,
            trigger_type="manual",
            status="succeeded",
            started_at=NOW,
            completed_at=NOW,
            records_fetched=1,
            records_created=1,
            records_updated=0,
            records_unchanged=0,
            records_skipped=0,
            records_failed=0,
            error_count=0,
            checkpoint_before=CHECKPOINT_CANARY,
            checkpoint_after=CHECKPOINT_CANARY,
            safe_summary=SUMMARY_CANARY,
        )
        session.add_all([source, active, vulnerability, identifier, active_record, run])
        session.commit()
        try:
            yield session, active.public_id, {
                key: value.public_id for key, value in inactive.items()
            }
        finally:
            session.rollback()
            _clear_test_rows(session)


def _clear_test_rows(session: Session) -> None:
    for model in (
        IngestionRun,
        IntelligenceItemIdentifier,
        SourceRecord,
        Vulnerability,
        IntelligenceItem,
        IntelligenceSource,
    ):
        session.execute(sa.delete(model))
    session.commit()


def _capture_sql(engine: sa.Engine):
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    sa.event.listen(engine, "before_cursor_execute", capture)
    return statements, capture


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///b106_test_database",
        "postgresql://user:password@192.0.2.1/b106_test_database",
        "postgresql://user:password@127.0.0.1/staging",
        "postgresql://user:password@127.0.0.1/production",
        "postgresql://user:password@127.0.0.1/not_disposable",
    ],
)
def test_database_url_guard_rejects_unsafe_targets(url: str) -> None:
    with pytest.raises(pytest.fail.Exception):
        _validated_database_url(url)


@pytest.mark.parametrize("query_name", QUERY_OVERRIDE_NAMES)
def test_database_url_guard_rejects_query_overrides_before_connection(
    query_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection_attempted = False

    def unexpected_create_engine(*args, **kwargs):
        nonlocal connection_attempted
        connection_attempted = True
        raise AssertionError("database connection must not be attempted")

    monkeypatch.setattr(sa, "create_engine", unexpected_create_engine)
    submitted = (
        "postgresql://synthetic-user:query-password-canary@127.0.0.1/"
        f"b106_test_guard?{query_name}=query-override-canary"
    )
    with pytest.raises(pytest.fail.Exception) as exc_info:
        _validated_database_url(submitted)

    assert connection_attempted is False
    message = str(exc_info.value)
    assert "query-password-canary" not in message
    assert "query-override-canary" not in message


def test_database_url_guard_accepts_clean_loopback_url() -> None:
    url = _validated_database_url(
        "postgresql://synthetic-user:synthetic-password@127.0.0.1/"
        "b106_test_guard"
    )

    assert url.drivername == "postgresql+psycopg"
    assert url.host == "127.0.0.1"
    assert url.database == "b106_test_guard"
    assert not url.query


def test_malicious_searches_remain_data_and_tables_survive(populated_session, pg_engine) -> None:
    session, _, _ = populated_session
    initial_count = session.scalar(sa.select(sa.func.count()).select_from(IntelligenceItem))
    for payload in PAYLOADS:
        response = ArticleQueryService(session).list_articles(
            ArticleQueryFilters(q=payload, limit=25)
        )
        if payload in {"%", "_", "\\"}:
            assert response.total == 1
        else:
            assert response.total == 0
        assert sa.inspect(pg_engine).has_table("intelligence_items")
        assert session.scalar(sa.select(sa.func.count()).select_from(IntelligenceItem)) == initial_count


def test_active_only_intelligence_and_projected_sql(populated_session, pg_engine) -> None:
    session, active_public_id, inactive_ids = populated_session
    statements, listener = _capture_sql(pg_engine)
    try:
        response = IntelligenceQueryService(session).list_items(
            IntelligenceQueryFilters(limit=25)
        )
        assert response.total == 1
        assert response.items[0].public_id == active_public_id
        assert IntelligenceQueryService(session).get_item(active_public_id).public_id == active_public_id
        for public_id in inactive_ids.values():
            with pytest.raises(IntelligenceNotFoundError, match="Intelligence item not found"):
                IntelligenceQueryService(session).get_item(public_id)
    finally:
        sa.event.remove(pg_engine, "before_cursor_execute", listener)
    sql = "\n".join(statements).casefold()
    assert "intelligence_items.status" in sql
    for column in PROHIBITED_COLUMNS:
        assert column not in sql
    for canary in (RAW_CANARY, CHECKPOINT_CANARY, SUMMARY_CANARY):
        assert canary not in response.model_dump_json()


def test_prohibited_fields_raise_instead_of_lazy_loading(populated_session) -> None:
    session, active_public_id, _ = populated_session
    session.expunge_all()
    item = session.execute(
        sa.select(IntelligenceItem)
        .where(IntelligenceItem.public_id == active_public_id)
        .options(*IntelligenceQueryService._public_load_options())
    ).scalar_one()
    assert item.canonical_title == "B1-06 active vulnerability"
    with pytest.raises(InvalidRequestError):
        _ = item.uae_relevance_reason
    with pytest.raises(InvalidRequestError):
        _ = item.vulnerability.affected_products_json
    with pytest.raises(InvalidRequestError):
        _ = item.source_records[0].raw_payload
    with pytest.raises(InvalidRequestError):
        _ = item.source_records[0].source.checkpoint_value


def test_article_and_dashboard_sql_omit_internal_columns(populated_session, pg_engine) -> None:
    session, _, _ = populated_session
    statements, listener = _capture_sql(pg_engine)
    try:
        articles = ArticleQueryService(session).list_articles(ArticleQueryFilters(limit=10))
        dashboard = DashboardSummaryService(session, clock=lambda: NOW).get_summary()
    finally:
        sa.event.remove(pg_engine, "before_cursor_execute", listener)
    assert articles.total == 3
    serialized = articles.model_dump_json() + dashboard.model_dump_json()
    assert RAW_CANARY not in serialized
    assert CHECKPOINT_CANARY not in serialized
    assert SUMMARY_CANARY not in serialized
    sql = "\n".join(statements).casefold()
    for column in PROHIBITED_COLUMNS:
        assert column not in sql
