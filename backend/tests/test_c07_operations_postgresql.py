"""Disposable PostgreSQL concurrency acceptance for C07 operator controls."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
import os
from pathlib import Path
from threading import Barrier
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.ingestion.services.operational_persistence_service import (
    OperationalPersistenceService,
    RunCounters,
)
from app.ingestion.source_registry import get_source_definition
from app.models import AuditEvent, IngestionError, IngestionRun, IntelligenceSource
from app.security.authorization import permissions_for_role
from app.security.contracts import AuthenticatedPrincipal, RoleKey
from app.services.operator_control_service import OperatorControlService


DATABASE_ENV = "B103_POSTGRESQL_TEST_DATABASE_URL"
BACKEND = Path(__file__).resolve().parents[1]
HEAD = "c07a01b02c03"
SOURCE_SLUG = "cisa-kev"
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _database_url() -> URL:
    raw = os.getenv(DATABASE_ENV)
    if not raw:
        pytest.skip(f"{DATABASE_ENV} is not configured")
    try:
        url = make_url(raw)
    except Exception:
        pytest.fail("C07 test database URL is invalid.")
    if url.drivername not in {"postgresql", "postgresql+psycopg"} or url.query:
        pytest.fail("C07 tests require PostgreSQL without URL query overrides.")
    try:
        address = ip_address((url.host or "").strip("[]"))
    except ValueError:
        pytest.fail("C07 test database must use a literal loopback address.")
    if not address.is_loopback or not (url.database or "").startswith("b103_test_"):
        pytest.fail("C07 test database must be disposable and loopback-only.")
    if any(token in (url.database or "").casefold() for token in ("staging", "production", "prod")):
        pytest.fail("C07 tests may not use staging or production databases.")
    return url.set(drivername="postgresql+psycopg")


@pytest.fixture(scope="module")
def pg_engine():
    url = _database_url()
    prior = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url.render_as_string(hide_password=False)
    get_settings.cache_clear()
    engine = sa.create_engine(url, poolclass=NullPool)
    config = Config(str(BACKEND / "alembic.ini"))
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")
        command.upgrade(config, HEAD)
        yield engine
    finally:
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")
        engine.dispose()
        if prior is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = prior
        get_settings.cache_clear()


@pytest.fixture(autouse=True)
def isolated_source(pg_engine):
    metadata = sa.MetaData()
    metadata.reflect(bind=pg_engine)
    with pg_engine.begin() as connection:
        for table in reversed(metadata.sorted_tables):
            connection.execute(table.delete())
        definition = get_source_definition(SOURCE_SLUG)
        connection.execute(
            IntelligenceSource.__table__.insert().values(
                public_id=uuid4(), name=definition.display_name, slug=definition.slug,
                source_type=definition.source_type, base_url=definition.base_url,
                is_enabled=True, operator_state="enabled",
                rate_limit_notes=definition.rate_limit_notes,
                last_successful_fetch_at=None, checkpoint_value=None,
                created_at=NOW, updated_at=NOW,
            )
        )


def _principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=1, user_public_id=uuid4(), display_name="C07 operator",
        role=RoleKey.ADMINISTRATOR,
        permissions=permissions_for_role(RoleKey.ADMINISTRATOR),
        account_expires_at=None, session_id=1, session_public_id=uuid4(),
        session_absolute_expires_at=NOW + timedelta(hours=8),
        csrf_token_hash="a" * 64,
    )


def _manual(engine, key: str, barrier: Barrier | None = None):
    if barrier is not None:
        barrier.wait()
    with Session(engine) as session, session.begin():
        return OperatorControlService(session, execution_slugs={SOURCE_SLUG}).request_manual_run(
            source_slug=SOURCE_SLUG, idempotency_key=key, actor=_principal(),
            correlation_id=uuid4(), occurred_at=NOW,
        )


def test_manual_acceptance_is_durable_secret_free_and_sequentially_idempotent(pg_engine) -> None:
    key = "c07-manual-request-0001"
    first = _manual(pg_engine, key)
    replay = _manual(pg_engine, key)
    assert first.run_public_id == replay.run_public_id
    assert first.cycle_public_id == replay.cycle_public_id
    assert first.replayed is False
    assert replay.replayed is True
    with Session(pg_engine) as session:
        assert session.scalar(sa.select(sa.func.count(IngestionRun.id))) == 1
        audit_text = " ".join(
            str(value) for value in session.scalars(sa.select(AuditEvent.safe_detail)).all()
        )
        assert key not in audit_text


def test_concurrent_manual_replay_creates_one_cycle_and_one_run(pg_engine) -> None:
    barrier = Barrier(2)
    key = "c07-concurrent-manual-0001"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: _manual(pg_engine, key, barrier), range(2)))
    assert len({result.run_public_id for result in results}) == 1
    assert sorted(result.replayed for result in results) == [False, True]
    with Session(pg_engine) as session:
        assert session.scalar(sa.select(sa.func.count(IngestionRun.id))) == 1


def _failed_parent(engine):
    with Session(engine) as session, session.begin():
        persistence = OperationalPersistenceService(session)
        cycle = persistence.acquire_cycle(
            trigger_type="manual", manual_request_key="c07-retry-parent-0001",
            sources_expected=1, occurred_at=NOW,
        )
        run = persistence.acquire_source_run(cycle_id=cycle.id, source_slug=SOURCE_SLUG, occurred_at=NOW)
        persistence.complete_partial_or_failure(
            run_id=run.id, expected_state_version=run.state_version,
            status="failed", counters=RunCounters(0, 0, 0, 0, 0, 0, 0),
            run_level_error=True, safe_summary="A retryable source failure occurred.",
            occurred_at=NOW + timedelta(seconds=1),
        )
        session.add(IngestionError(
            ingestion_run_id=run.id, ingestion_run_record_id=None, source_record_id=None,
            error_type="temporary_source_failure", safe_message="Temporary source failure.",
            failure_stage="request", diagnostic_fingerprint=None, safe_context=None,
            retryable=True, retry_count=0, occurred_at=NOW + timedelta(seconds=1),
        ))
        session.flush()
        return run.public_id


def _retry(engine, parent_public_id, barrier: Barrier | None = None):
    if barrier is not None:
        barrier.wait()
    with Session(engine) as session, session.begin():
        return OperatorControlService(session, execution_slugs={SOURCE_SLUG}).request_retry(
            run_public_id=parent_public_id, actor=_principal(), correlation_id=uuid4(),
            occurred_at=NOW + timedelta(seconds=2),
        )


def test_retry_replay_and_concurrency_produce_one_nonbranching_child(pg_engine) -> None:
    parent = _failed_parent(pg_engine)
    barrier = Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: _retry(pg_engine, parent, barrier), range(2)))
    assert len({result.run_public_id for result in results}) == 1
    assert sorted(result.replayed for result in results) == [False, True]
    replay = _retry(pg_engine, parent)
    assert replay.run_public_id == results[0].run_public_id
    assert replay.replayed is True
    with Session(pg_engine) as session:
        parent_id = session.scalar(sa.select(IngestionRun.id).where(IngestionRun.public_id == parent))
        children = session.scalars(sa.select(IngestionRun).where(IngestionRun.retry_of_run_id == parent_id)).all()
        assert len(children) == 1
        assert children[0].attempt_number == 1


def test_source_transition_updates_both_projections_and_audit_atomically(pg_engine) -> None:
    actor = _principal()
    with Session(pg_engine) as session, session.begin():
        paused = OperatorControlService(session).transition_source(
            source_slug=SOURCE_SLUG, operation="pause", actor=actor,
            correlation_id=uuid4(), occurred_at=NOW,
        )
        assert paused.changed is True
    with Session(pg_engine) as session:
        source = session.scalar(sa.select(IntelligenceSource).where(IntelligenceSource.slug == SOURCE_SLUG))
        assert source.operator_state == "paused"
        assert source.is_enabled is False
        event = session.scalar(sa.select(AuditEvent).where(AuditEvent.action == "source.paused"))
        assert event is not None
        assert event.outcome == "success"
