from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import socket
from threading import Barrier
import time
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool
from sqlalchemy.orm import Session

from app.core.config import get_settings
import app.models  # noqa: F401
from app.ingestion.source_registry import get_source_definition
from app.ingestion.services.operational_idempotency import build_scheduled_cycle_key
from app.ingestion.services.operational_persistence_service import (
    DeferReason,
    OperationalConflictError,
    OperationalLockUnavailableError,
    OperationalStaleStateError,
    OperationalValidationError,
    OperationalPersistenceService,
    RunCounters,
)
from app.models import (
    AuditEvent,
    IngestionCycle,
    IngestionRun,
    IngestionRunEvent,
    IntelligenceSource,
    SourceCheckpoint,
    SourceRateLimitState,
    SourceWatermark,
)


BACKEND = Path(__file__).resolve().parents[1]
TEST_URL_ENV = "B104_POSTGRESQL_TEST_DATABASE_URL"
HISTORICAL_HEAD = "b103a71d2e4f"
CURRENT_HEAD = "c07a01b02c03"
TEST_SOURCE_SLUGS = ("censys-arc-research", "cisa-kev", "nvd")
HISTORICAL_OPERATIONAL_TABLES = frozenset(
    {
        "audit_events",
        "ingestion_cycles",
        "ingestion_errors",
        "ingestion_run_events",
        "ingestion_runs",
        "source_checkpoints",
        "source_rate_limit_states",
        "source_watermarks",
    }
)
_historical_tables_observed: frozenset[str] = frozenset()
_historical_source_columns_observed: frozenset[str] = frozenset()
NOW = datetime.now(UTC).replace(microsecond=0)
ZERO = RunCounters(0, 0, 0, 0, 0, 0, 0)
CREATED = RunCounters(1, 1, 0, 0, 0, 0, 0)
UNCHANGED = RunCounters(1, 0, 0, 1, 0, 0, 0)
UNSAFE_SUMMARY_CANARIES = (
    "postgresql://service:secret@localhost:5432/database",
    "mysql://service:secret@localhost/database",
    "Authorization: Bearer secret-token",
    "Authorization=Basic dXNlcjpwYXNz",
    "Basic dXNlcjpwYXNz",
    "password=hunter2",
    "api_key=secret-value",
    "access-token=secret-value",
    "cookie=session=secret-value",
    "-----BEGIN PRIVATE KEY-----",
    "Traceback (most recent call last):",
    "Stack trace: internal application frame",
    "SELECT secret_value FROM credentials;",
    "SQL: SELECT secret_value FROM credentials;",
    "Query failed: DELETE FROM source_records;",
    "Statement: INSERT INTO audit_events VALUES (...);",
    "Database statement was DROP TABLE source_records;",
    "Raw query: ALTER TABLE ingestion_runs ADD COLUMN x integer;",
    "Executed query: UPDATE intelligence_sources SET is_enabled = false;",
    "Diagnostic: CREATE TABLE leaked_records (id integer);",
    "summary\x00secret",
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
        pytest.fail("Dedicated B1-04 database configuration is invalid")
    if url.drivername not in {"postgresql", "postgresql+psycopg"}:
        pytest.fail("Dedicated B1-04 database must use PostgreSQL")
    if url.query:
        pytest.fail("Dedicated B1-04 database URL query parameters are forbidden")
    host = (url.host or "").strip("[]").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("Dedicated B1-04 database must be loopback-only")
    if host == "localhost":
        try:
            addresses = {
                ipaddress.ip_address(result[4][0])
                for result in socket.getaddrinfo(host, url.port or 5432)
            }
        except (OSError, ValueError):
            pytest.fail("Dedicated B1-04 database host could not be resolved safely")
        if not addresses or not all(address.is_loopback for address in addresses):
            pytest.fail("Dedicated B1-04 database must resolve only to loopback")
    database = url.database or ""
    if not database.startswith("b104_test_"):
        pytest.fail("Dedicated B1-04 database name must use the disposable prefix")
    if any(label in database.casefold() for label in ("staging", "production", "prod")):
        pytest.fail("Staging and production database names are forbidden")
    return url.set(drivername="postgresql+psycopg")


def _database_url() -> URL:
    raw = os.environ.get(TEST_URL_ENV)
    if not raw:
        pytest.skip(f"{TEST_URL_ENV} is not configured")
    return _validated_database_url(raw)


@pytest.mark.parametrize("query_name", QUERY_OVERRIDE_NAMES)
def test_database_url_guard_rejects_query_overrides_before_connection(
    query_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection_attempted = False

    def unexpected_create_engine(*args, **kwargs):
        nonlocal connection_attempted
        connection_attempted = True
        raise AssertionError("database connection must not be attempted")

    monkeypatch.setitem(globals(), "create_engine", unexpected_create_engine)
    submitted = (
        "postgresql://synthetic-user:query-password-canary@127.0.0.1/"
        f"b104_test_guard?{query_name}=query-override-canary"
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
        "b104_test_guard"
    )

    assert url.drivername == "postgresql+psycopg"
    assert url.host == "127.0.0.1"
    assert url.database == "b104_test_guard"
    assert not url.query


@pytest.fixture(scope="session")
def pg_engine():
    global _historical_source_columns_observed, _historical_tables_observed
    url = _database_url()

    prior = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url.render_as_string(hide_password=False)
    get_settings.cache_clear()
    probe = create_engine(url, poolclass=NullPool)
    ready = False
    for _ in range(30):
        try:
            with probe.connect() as connection:
                connection.execute(select(1))
            ready = True
            break
        except OperationalError:
            time.sleep(1)
    probe.dispose()
    if not ready:
        pytest.fail("The disposable PostgreSQL database did not become ready.")
    reset_engine = create_engine(url, poolclass=NullPool)
    try:
        with reset_engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")
    finally:
        reset_engine.dispose()
    config = Config(str(BACKEND / "alembic.ini"))
    command.upgrade(config, "base")
    command.upgrade(config, HISTORICAL_HEAD)
    historical_inspector = sa.inspect(probe)
    _historical_tables_observed = frozenset(historical_inspector.get_table_names())
    _historical_source_columns_observed = frozenset(
        column["name"]
        for column in historical_inspector.get_columns("intelligence_sources")
    )
    command.upgrade(config, CURRENT_HEAD)
    engine = create_engine(url, poolclass=NullPool)
    try:
        yield engine
    finally:
        engine.dispose()
        if prior is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = prior
        get_settings.cache_clear()


@pytest.fixture(autouse=True)
def isolated_rows(request: pytest.FixtureRequest):
    if request.node.name.startswith("test_database_url_guard_"):
        return
    pg_engine = request.getfixturevalue("pg_engine")
    with pg_engine.begin() as connection:
        existing_metadata = sa.MetaData()
        existing_metadata.reflect(bind=connection)
        for table in reversed(existing_metadata.sorted_tables):
            connection.execute(table.delete())
        for source_slug in TEST_SOURCE_SLUGS:
            definition = get_source_definition(source_slug)
            connection.execute(
                IntelligenceSource.__table__.insert().values(
                    name=definition.display_name,
                    slug=definition.slug,
                    source_type=definition.source_type,
                    base_url=definition.base_url,
                    is_enabled=definition.enabled,
                    operator_state=("enabled" if definition.enabled else "disabled"),
                    rate_limit_notes=definition.rate_limit_notes,
                    last_successful_fetch_at=None,
                    checkpoint_value=None,
                    created_at=NOW,
                    updated_at=NOW,
                )
            )


def cycle(service: OperationalPersistenceService, *, expected: int = 1):
    return service.acquire_cycle(
        trigger_type="manual",
        manual_request_key=f"request-{uuid4()}",
        sources_expected=expected,
        occurred_at=NOW,
    )


def committed_cycle(engine, *, expected: int = 1):
    with Session(engine) as session, session.begin():
        row = cycle(OperationalPersistenceService(session), expected=expected)
        row_id = row.id
    return row_id


def committed_run(engine, slug: str):
    cycle_id = committed_cycle(engine)
    with Session(engine) as session, session.begin():
        row = OperationalPersistenceService(session).acquire_source_run(
            cycle_id=cycle_id, source_slug=slug, occurred_at=NOW
        )
        row_id = row.id
    return row_id


def pending_run(engine, slug: str, counters: RunCounters = CREATED):
    run_id = committed_run(engine, slug)
    with Session(engine) as session, session.begin():
        row = OperationalPersistenceService(session).record_persistence_commit(
            run_id=run_id, expected_state_version=1, counters=counters, occurred_at=NOW
        )
        assert row.status == "checkpoint_pending"
    return run_id


def counts(session, model):
    return session.scalar(select(func.count()).select_from(model))


def run_evidence(session, run_id):
    run = session.get(IngestionRun, run_id)
    return (
        run.status,
        run.state_version,
        run.safe_summary,
        session.scalar(
            select(func.count())
            .select_from(IngestionRunEvent)
            .where(IngestionRunEvent.ingestion_run_id == run_id)
        ),
        counts(session, SourceCheckpoint),
        counts(session, SourceWatermark),
    )


def test_cycle_and_initial_audit_commit_atomically(pg_engine) -> None:
    committed_cycle(pg_engine)
    with Session(pg_engine) as session:
        assert counts(session, IngestionCycle) == 1
        assert counts(session, AuditEvent) == 1


def test_cycle_rollback_leaves_neither_row(pg_engine) -> None:
    with Session(pg_engine) as session:
        transaction = session.begin()
        cycle(OperationalPersistenceService(session))
        transaction.rollback()
    with Session(pg_engine) as session:
        assert counts(session, IngestionCycle) == counts(session, AuditEvent) == 0


def test_duplicate_cycle_returns_one_row_after_commit(pg_engine) -> None:
    request = f"request-{uuid4()}"
    with Session(pg_engine) as session, session.begin():
        first = OperationalPersistenceService(session).acquire_cycle(
            trigger_type="manual", manual_request_key=request,
            sources_expected=1, occurred_at=NOW,
        )
        first_id = first.id
    with Session(pg_engine) as session, session.begin():
        second = OperationalPersistenceService(session).acquire_cycle(
            trigger_type="manual", manual_request_key=request,
            sources_expected=1, occurred_at=NOW + timedelta(minutes=1),
        )
        assert second.id == first_id
        assert counts(session, AuditEvent) == 1


def test_conflicting_duplicate_cycle_inputs_are_rejected(pg_engine) -> None:
    request = f"request-{uuid4()}"
    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).acquire_cycle(
            trigger_type="manual", manual_request_key=request, sources_expected=1
        )
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalConflictError):
            OperationalPersistenceService(session).acquire_cycle(
                trigger_type="manual", manual_request_key=request, sources_expected=2
            )


def test_historical_b103_revision_remains_explicitly_verified(pg_engine) -> None:
    """Preserve B1-03 schema evidence before current service tests use C07A."""

    assert HISTORICAL_OPERATIONAL_TABLES.issubset(_historical_tables_observed)
    assert "operator_state" not in _historical_source_columns_observed
    assert sa.inspect(pg_engine).get_table_names()


def test_cycle_finalization_is_evidence_backed_and_exactly_idempotent(pg_engine) -> None:
    cycle_id = committed_cycle(pg_engine)
    with Session(pg_engine) as session, session.begin():
        run = OperationalPersistenceService(session).acquire_source_run(
            cycle_id=cycle_id,
            source_slug="censys-arc-research",
            occurred_at=NOW,
        )
        run_id = run.id
    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).record_persistence_commit(
            run_id=run_id,
            expected_state_version=1,
            counters=CREATED,
            occurred_at=NOW + timedelta(seconds=1),
        )

    kwargs = dict(
        cycle_id=cycle_id,
        status="success",
        sources_started=1,
        sources_completed=1,
        sources_successful=1,
        sources_non_successful=0,
        safe_summary="Parent cycle completed with bounded results.",
        occurred_at=NOW + timedelta(seconds=2),
    )
    with Session(pg_engine) as session, session.begin():
        first = OperationalPersistenceService(session).finalize_cycle(**kwargs)
        assert (first.status, first.sources_completed) == ("success", 1)
    with Session(pg_engine) as session, session.begin():
        second = OperationalPersistenceService(session).finalize_cycle(**kwargs)
        assert second.id == cycle_id

    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalConflictError):
            OperationalPersistenceService(session).finalize_cycle(
                **{**kwargs, "safe_summary": "A conflicting completion summary."}
            )


def test_cycle_finalization_rejects_fabricated_counters_and_rolls_back(pg_engine) -> None:
    cycle_id = committed_cycle(pg_engine)
    with Session(pg_engine) as session:
        transaction = session.begin()
        with pytest.raises(OperationalConflictError, match="source-run evidence"):
            OperationalPersistenceService(session).finalize_cycle(
                cycle_id=cycle_id,
                status="success",
                sources_started=1,
                sources_completed=1,
                sources_successful=1,
                sources_non_successful=0,
                occurred_at=NOW + timedelta(seconds=1),
            )
        transaction.rollback()
    with Session(pg_engine) as session:
        cycle_row = session.get(IngestionCycle, cycle_id)
        assert (cycle_row.status, cycle_row.completed_at) == ("running", None)


def test_all_success_evidence_cannot_finalize_as_cancelled(pg_engine) -> None:
    cycle_id = committed_cycle(pg_engine)
    with Session(pg_engine) as session, session.begin():
        run = OperationalPersistenceService(session).acquire_source_run(
            cycle_id=cycle_id,
            source_slug="censys-arc-research",
            occurred_at=NOW,
        )
        run_id = run.id
    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).record_persistence_commit(
            run_id=run_id,
            expected_state_version=1,
            counters=CREATED,
            occurred_at=NOW + timedelta(seconds=1),
        )
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalValidationError, match="Cancelled"):
            OperationalPersistenceService(session).finalize_cycle(
                cycle_id=cycle_id,
                status="cancelled",
                sources_started=1,
                sources_completed=1,
                sources_successful=1,
                sources_non_successful=0,
                occurred_at=NOW + timedelta(seconds=2),
            )


def test_cancelled_cycle_is_evidence_backed_exactly_idempotent_and_conflict_safe(
    pg_engine,
) -> None:
    cycle_id = committed_cycle(pg_engine)
    with Session(pg_engine) as session, session.begin():
        run = OperationalPersistenceService(session).acquire_source_run(
            cycle_id=cycle_id,
            source_slug="censys-arc-research",
            occurred_at=NOW,
        )
        run_id = run.id
    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).complete_partial_or_failure(
            run_id=run_id,
            expected_state_version=1,
            status="cancelled",
            counters=ZERO,
            safe_summary="Source execution was cancelled safely.",
            occurred_at=NOW + timedelta(seconds=1),
        )

    arguments = dict(
        cycle_id=cycle_id,
        status="cancelled",
        sources_started=1,
        sources_completed=1,
        sources_successful=0,
        sources_non_successful=1,
        safe_summary="Parent cycle retained committed cancellation evidence.",
        occurred_at=NOW + timedelta(seconds=2),
    )
    with Session(pg_engine) as session, session.begin():
        first = OperationalPersistenceService(session).finalize_cycle(**arguments)
        assert first.status == "cancelled"
    with Session(pg_engine) as session, session.begin():
        repeated = OperationalPersistenceService(session).finalize_cycle(**arguments)
        assert repeated.id == cycle_id
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalConflictError):
            OperationalPersistenceService(session).finalize_cycle(
                **{
                    **arguments,
                    "safe_summary": "Conflicting cancellation evidence.",
                }
            )


def test_cancelled_cycle_rejects_non_cancelled_terminal_run_evidence(pg_engine) -> None:
    cycle_id = committed_cycle(pg_engine)
    with Session(pg_engine) as session, session.begin():
        run = OperationalPersistenceService(session).acquire_source_run(
            cycle_id=cycle_id,
            source_slug="censys-arc-research",
            occurred_at=NOW,
        )
        run_id = run.id
    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).complete_partial_or_failure(
            run_id=run_id,
            expected_state_version=1,
            status="failed",
            counters=ZERO,
            run_level_error=True,
            occurred_at=NOW + timedelta(seconds=1),
        )
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalConflictError, match="Cancelled cycle evidence"):
            OperationalPersistenceService(session).finalize_cycle(
                cycle_id=cycle_id,
                status="cancelled",
                sources_started=1,
                sources_completed=1,
                sources_successful=0,
                sources_non_successful=1,
                occurred_at=NOW + timedelta(seconds=2),
            )


def test_scheduled_cycle_acquisition_is_exactly_idempotent_and_conflict_safe(
    pg_engine,
) -> None:
    deployment = "alpha-data-ingestion-cycle"
    slot = NOW
    with Session(pg_engine) as session, session.begin():
        first = OperationalPersistenceService(session).acquire_cycle(
            trigger_type="scheduled",
            scheduled_for=slot,
            deployment_ref=deployment,
            sources_expected=1,
            occurred_at=slot,
        )
        first_id = first.id

    with Session(pg_engine) as session, session.begin():
        repeated = OperationalPersistenceService(session).acquire_cycle(
            trigger_type="scheduled",
            scheduled_for=slot,
            deployment_ref=deployment,
            sources_expected=1,
            occurred_at=slot + timedelta(minutes=1),
        )
        assert repeated.id == first_id
        assert counts(session, IngestionCycle) == 1
        assert counts(session, AuditEvent) == 1

    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalConflictError, match="identity conflicts"):
            OperationalPersistenceService(session).acquire_cycle(
                trigger_type="scheduled",
                scheduled_for=slot,
                deployment_ref=deployment,
                sources_expected=2,
                occurred_at=slot + timedelta(minutes=2),
            )

    with Session(pg_engine) as session:
        assert counts(session, IngestionCycle) == 1
        assert counts(session, AuditEvent) == 1


def test_running_scheduled_cycle_rejects_new_slot_without_partial_evidence(
    pg_engine,
) -> None:
    deployment = "alpha-data-ingestion-cycle"
    first_slot = NOW
    with Session(pg_engine) as session, session.begin():
        first = OperationalPersistenceService(session).acquire_cycle(
            trigger_type="scheduled",
            scheduled_for=first_slot,
            deployment_ref=deployment,
            sources_expected=0,
            occurred_at=first_slot,
        )
        first_id = first.id

    with Session(pg_engine) as session:
        transaction = session.begin()
        with pytest.raises(OperationalConflictError, match="already active"):
            OperationalPersistenceService(session).acquire_cycle(
                trigger_type="scheduled",
                scheduled_for=first_slot + timedelta(hours=2),
                deployment_ref=deployment,
                sources_expected=0,
                occurred_at=first_slot + timedelta(hours=2),
            )
        assert counts(session, IngestionCycle) == 1
        assert counts(session, AuditEvent) == 1
        assert counts(session, IngestionRun) == 0
        transaction.rollback()

    with Session(pg_engine) as session:
        original = session.get(IngestionCycle, first_id)
        assert original is not None
        assert (
            original.status,
            original.scheduled_for,
            original.completed_at,
            original.sources_expected,
        ) == ("running", first_slot, None, 0)
        assert counts(session, IngestionCycle) == 1
        assert counts(session, AuditEvent) == 1


def test_terminal_scheduled_cycle_allows_next_slot_and_manual_is_independent(
    pg_engine,
) -> None:
    deployment = "alpha-data-ingestion-cycle"
    first_slot = NOW
    with Session(pg_engine) as session, session.begin():
        service = OperationalPersistenceService(session)
        first = service.acquire_cycle(
            trigger_type="scheduled",
            scheduled_for=first_slot,
            deployment_ref=deployment,
            sources_expected=0,
            occurred_at=first_slot,
        )
        manual = service.acquire_cycle(
            trigger_type="manual",
            manual_request_key=f"request-{uuid4()}",
            sources_expected=0,
            occurred_at=first_slot,
        )
        assert manual.id != first.id
        first_id = first.id
        manual_id = manual.id

    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).finalize_cycle(
            cycle_id=first_id,
            status="success",
            sources_started=0,
            sources_completed=0,
            sources_successful=0,
            sources_non_successful=0,
            occurred_at=first_slot + timedelta(minutes=1),
        )

    with Session(pg_engine) as session, session.begin():
        next_cycle = OperationalPersistenceService(session).acquire_cycle(
            trigger_type="scheduled",
            scheduled_for=first_slot + timedelta(hours=2),
            deployment_ref=deployment,
            sources_expected=0,
            occurred_at=first_slot + timedelta(hours=2),
        )
        assert next_cycle.id not in {first_id, manual_id}
        assert next_cycle.status == "running"


def test_scheduled_finalization_overlap_guard_remains_defensive(pg_engine) -> None:
    deployment = "alpha-data-ingestion-cycle"
    first_slot = NOW
    second_slot = NOW + timedelta(hours=2)
    with Session(pg_engine) as session, session.begin():
        service = OperationalPersistenceService(session)
        first = service.acquire_cycle(
            trigger_type="scheduled",
            scheduled_for=first_slot,
            deployment_ref=deployment,
            sources_expected=0,
            occurred_at=first_slot,
        )
        overlapping = IngestionCycle(
            idempotency_key=build_scheduled_cycle_key(deployment, second_slot),
            trigger_type="scheduled",
            status="running",
            scheduled_for=second_slot,
            started_at=second_slot,
            completed_at=None,
            sources_expected=0,
            sources_started=0,
            sources_completed=0,
            sources_successful=0,
            sources_non_successful=0,
            safe_summary=None,
            created_at=second_slot,
        )
        session.add(overlapping)
        session.flush()

        with pytest.raises(OperationalConflictError, match="overlapping"):
            service.finalize_cycle(
                cycle_id=first.id,
                status="success",
                sources_started=0,
                sources_completed=0,
                sources_successful=0,
                sources_non_successful=0,
                occurred_at=second_slot + timedelta(hours=1),
            )
        assert first.status == overlapping.status == "running"


def test_concurrent_different_slot_scheduled_acquisitions_cannot_both_start(
    pg_engine,
) -> None:
    start = Barrier(2)
    hold_winner = Barrier(2)

    def worker(slot: datetime) -> str:
        with Session(pg_engine) as session, session.begin():
            start.wait(timeout=10)
            try:
                OperationalPersistenceService(session).acquire_cycle(
                    trigger_type="scheduled",
                    scheduled_for=slot,
                    deployment_ref="alpha-data-ingestion-cycle",
                    sources_expected=0,
                    occurred_at=slot,
                )
                outcome = "started"
            except (OperationalLockUnavailableError, OperationalConflictError):
                outcome = "blocked"
            hold_winner.wait(timeout=10)
            return outcome

    slots = (NOW, NOW + timedelta(hours=2))
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(worker, slots))

    assert sorted(outcomes) == ["blocked", "started"]
    with Session(pg_engine) as session:
        assert counts(session, IngestionCycle) == 1
        assert counts(session, AuditEvent) == 1


def test_initial_operational_run_has_complete_identity_and_acquired_event(pg_engine) -> None:
    run_id = committed_run(pg_engine, "censys-arc-research")
    with Session(pg_engine) as session:
        run = session.get(IngestionRun, run_id)
        assert run is not None
        assert (run.cycle_id is not None and run.idempotency_key is not None)
        assert (run.attempt_number, run.retry_of_run_id, run.state_version, run.status) == (0, None, 1, "running")
        events = session.scalars(select(IngestionRunEvent).where(IngestionRunEvent.ingestion_run_id == run_id)).all()
        assert [(event.sequence_number, event.event_type) for event in events] == [(1, "acquired")]


def test_exact_duplicate_run_returns_same_row_without_duplicate_event(pg_engine) -> None:
    cycle_id = committed_cycle(pg_engine)
    with Session(pg_engine) as session, session.begin():
        first = OperationalPersistenceService(session).acquire_source_run(cycle_id=cycle_id, source_slug="censys-arc-research")
        first_id = first.id
    with Session(pg_engine) as session, session.begin():
        second = OperationalPersistenceService(session).acquire_source_run(cycle_id=cycle_id, source_slug="censys-arc-research")
        assert second.id == first_id
        assert counts(session, IngestionRunEvent) == 1


def test_active_same_source_run_prevents_another_start(pg_engine) -> None:
    committed_run(pg_engine, "censys-arc-research")
    other_cycle = committed_cycle(pg_engine)
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalConflictError, match="active"):
            OperationalPersistenceService(session).acquire_source_run(cycle_id=other_cycle, source_slug="censys-arc-research")


def test_lock_contention_fails_promptly(pg_engine) -> None:
    cycle_one = committed_cycle(pg_engine)
    cycle_two = committed_cycle(pg_engine)
    with Session(pg_engine) as first, first.begin():
        OperationalPersistenceService(first).acquire_source_run(cycle_id=cycle_one, source_slug="censys-arc-research")
        with Session(pg_engine) as second, second.begin():
            with pytest.raises(OperationalLockUnavailableError):
                OperationalPersistenceService(second).acquire_source_run(cycle_id=cycle_two, source_slug="censys-arc-research")


def test_concurrent_source_acquisitions_cannot_both_start(pg_engine) -> None:
    cycle_ids = (committed_cycle(pg_engine), committed_cycle(pg_engine))
    def worker(cycle_id):
        with Session(pg_engine) as session, session.begin():
            try:
                OperationalPersistenceService(session).acquire_source_run(cycle_id=cycle_id, source_slug="censys-arc-research")
                return "started"
            except (OperationalLockUnavailableError, OperationalConflictError):
                return "blocked"
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(worker, cycle_ids))
    assert sorted(outcomes) == ["blocked", "started"]


def test_transitional_active_run_prevents_operational_start(pg_engine) -> None:
    with Session(pg_engine) as session, session.begin():
        source = session.scalar(select(IntelligenceSource).where(IntelligenceSource.slug == "censys-arc-research"))
        session.add(IngestionRun(source_id=source.id, trigger_type="manual", status="running", records_fetched=0, records_created=0, records_updated=0, records_unchanged=0, records_skipped=0, records_failed=0, error_count=0))
    cycle_id = committed_cycle(pg_engine)
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalConflictError):
            OperationalPersistenceService(session).acquire_source_run(cycle_id=cycle_id, source_slug="censys-arc-research")


def test_retry_creates_next_attempt_with_immediate_ancestry(pg_engine) -> None:
    prior_id = committed_run(pg_engine, "censys-arc-research")
    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).complete_partial_or_failure(run_id=prior_id, expected_state_version=1, status="failed", counters=ZERO, run_level_error=True)
    with Session(pg_engine) as session, session.begin():
        retry = OperationalPersistenceService(session).acquire_retry(prior_run_id=prior_id)
        assert (retry.attempt_number, retry.retry_of_run_id, retry.trigger_type) == (1, prior_id, "retry")


def test_duplicate_retry_returns_existing_retry(pg_engine) -> None:
    prior_id = committed_run(pg_engine, "censys-arc-research")
    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).complete_partial_or_failure(run_id=prior_id, expected_state_version=1, status="failed", counters=ZERO, run_level_error=True)
    with Session(pg_engine) as session, session.begin():
        first = OperationalPersistenceService(session).acquire_retry(prior_run_id=prior_id)
        first_id = first.id
        OperationalPersistenceService(session).complete_partial_or_failure(run_id=first_id, expected_state_version=1, status="failed", counters=ZERO, run_level_error=True)
    with Session(pg_engine) as session, session.begin():
        second = OperationalPersistenceService(session).acquire_retry(prior_run_id=prior_id)
        assert second.id == first_id


def test_retry_stale_parent_is_rejected(pg_engine) -> None:
    prior_id = committed_run(pg_engine, "censys-arc-research")
    with Session(pg_engine) as session, session.begin():
        service = OperationalPersistenceService(session)
        service.complete_partial_or_failure(run_id=prior_id, expected_state_version=1, status="failed", counters=ZERO, run_level_error=True)
        retry = service.acquire_retry(prior_run_id=prior_id)
        service.complete_partial_or_failure(run_id=retry.id, expected_state_version=1, status="failed", counters=ZERO, run_level_error=True)
        service.acquire_retry(prior_run_id=retry.id)
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalConflictError):
            OperationalPersistenceService(session).acquire_retry(prior_run_id=prior_id)


def test_attempt_eleven_is_rejected(pg_engine) -> None:
    prior_id = committed_run(pg_engine, "censys-arc-research")
    for attempt in range(1, 11):
        with Session(pg_engine) as session, session.begin():
            service = OperationalPersistenceService(session)
            service.complete_partial_or_failure(run_id=prior_id, expected_state_version=1, status="failed", counters=ZERO, run_level_error=True)
            prior_id = service.acquire_retry(prior_run_id=prior_id).id
    with Session(pg_engine) as session, session.begin():
        service = OperationalPersistenceService(session)
        service.complete_partial_or_failure(run_id=prior_id, expected_state_version=1, status="failed", counters=ZERO, run_level_error=True)
        with pytest.raises(OperationalValidationError):
            service.acquire_retry(prior_run_id=prior_id)


def test_stale_run_state_version_is_rejected(pg_engine) -> None:
    run_id = committed_run(pg_engine, "censys-arc-research")
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalStaleStateError):
            OperationalPersistenceService(session).record_persistence_commit(run_id=run_id, expected_state_version=2, counters=CREATED)


def test_rollback_preserves_prior_status_version_and_events(pg_engine) -> None:
    run_id = committed_run(pg_engine, "censys-arc-research")
    with Session(pg_engine) as session:
        transaction = session.begin()
        OperationalPersistenceService(session).record_persistence_commit(run_id=run_id, expected_state_version=1, counters=CREATED)
        transaction.rollback()
    with Session(pg_engine) as session:
        run = session.get(IngestionRun, run_id)
        assert (run.status, run.state_version) == ("running", 1)
        assert counts(session, IngestionRunEvent) == 1


def test_none_source_completes_directly_and_atomically(pg_engine) -> None:
    run_id = committed_run(pg_engine, "censys-arc-research")
    with Session(pg_engine) as session, session.begin():
        run = OperationalPersistenceService(session).record_persistence_commit(run_id=run_id, expected_state_version=1, counters=CREATED)
        assert (run.status, run.state_version, run.completed_at is not None) == ("success", 2, True)
        assert [event.event_type for event in session.scalars(select(IngestionRunEvent).where(IngestionRunEvent.ingestion_run_id == run_id).order_by(IngestionRunEvent.sequence_number))] == ["acquired", "persistence_committed", "completed"]
        assert counts(session, SourceCheckpoint) == counts(session, SourceWatermark) == 0


def test_none_source_no_change_is_truthful(pg_engine) -> None:
    run_id = committed_run(pg_engine, "censys-arc-research")
    with Session(pg_engine) as session, session.begin():
        run = OperationalPersistenceService(session).record_persistence_commit(run_id=run_id, expected_state_version=1, counters=ZERO)
        assert run.status == "no_change"


@pytest.mark.parametrize("slug", ["cisa-kev", "nvd"])
def test_progress_sources_become_pending_after_persistence(pg_engine, slug) -> None:
    run_id = committed_run(pg_engine, slug)
    with Session(pg_engine) as session, session.begin():
        run = OperationalPersistenceService(session).record_persistence_commit(run_id=run_id, expected_state_version=1, counters=CREATED)
        assert (run.status, run.state_version, run.completed_at) == ("checkpoint_pending", 2, None)


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        ("skipped", None), ("deferred_quota", DeferReason.QUOTA),
        ("approval_pending", DeferReason.APPROVAL), ("disabled", DeferReason.SOURCE_DISABLED),
        ("credentials_missing", DeferReason.CREDENTIALS), ("licence_required", DeferReason.LICENCE),
        ("rate_limited", DeferReason.RATE_LIMIT),
    ],
)
def test_non_request_outcomes_are_zero_and_do_not_advance_progress(pg_engine, status, reason) -> None:
    run_id = committed_run(pg_engine, "cisa-kev")
    with Session(pg_engine) as session, session.begin():
        run = OperationalPersistenceService(session).complete_non_request(run_id=run_id, expected_state_version=1, status=status, defer_reason=reason)
        assert run.status == status
        assert counts(session, SourceCheckpoint) == 0


def test_partial_requires_completed_and_failed_or_skipped_work(pg_engine) -> None:
    run_id = committed_run(pg_engine, "censys-arc-research")
    counters = RunCounters(2, 1, 0, 0, 0, 1, 1)
    with Session(pg_engine) as session, session.begin():
        run = OperationalPersistenceService(session).complete_partial_or_failure(run_id=run_id, expected_state_version=1, status="partial", counters=counters)
        assert run.status == "partial"


@pytest.mark.parametrize(
    "summary_path",
    (
        "acquire_cycle",
        "record_persistence_commit",
        "complete_non_request",
        "complete_partial_or_failure",
        "abandon_pending_progress",
    ),
)
@pytest.mark.parametrize("canary", UNSAFE_SUMMARY_CANARIES)
def test_every_safe_summary_path_rejects_unsafe_content_without_mutation(
    pg_engine, summary_path, canary
) -> None:
    run_id = None
    if summary_path == "abandon_pending_progress":
        run_id = pending_run(pg_engine, "cisa-kev")
    elif summary_path != "acquire_cycle":
        run_id = committed_run(pg_engine, "censys-arc-research")

    with Session(pg_engine) as session:
        transaction = session.begin()
        before = None if run_id is None else run_evidence(session, run_id)
        service = OperationalPersistenceService(session)
        with pytest.raises(OperationalValidationError) as exc_info:
            if summary_path == "acquire_cycle":
                service.acquire_cycle(
                    trigger_type="manual",
                    manual_request_key=f"request-{uuid4()}",
                    sources_expected=1,
                    safe_summary=canary,
                )
            elif summary_path == "record_persistence_commit":
                service.record_persistence_commit(
                    run_id=run_id,
                    expected_state_version=1,
                    counters=CREATED,
                    safe_summary=canary,
                )
            elif summary_path == "complete_non_request":
                service.complete_non_request(
                    run_id=run_id,
                    expected_state_version=1,
                    status="skipped",
                    safe_summary=canary,
                )
            elif summary_path == "complete_partial_or_failure":
                service.complete_partial_or_failure(
                    run_id=run_id,
                    expected_state_version=1,
                    status="failed",
                    counters=ZERO,
                    run_level_error=True,
                    safe_summary=canary,
                )
            else:
                service.abandon_pending_progress(
                    run_id=run_id,
                    expected_state_version=2,
                    status="failed",
                    safe_summary=canary,
                )
        assert canary not in str(exc_info.value)
        transaction.rollback()

    with Session(pg_engine) as session:
        if run_id is None:
            assert counts(session, IngestionCycle) == counts(session, AuditEvent) == 0
        else:
            assert run_evidence(session, run_id) == before


@pytest.mark.parametrize(
    "summary_path",
    (
        "acquire_cycle",
        "record_persistence_commit",
        "complete_non_request",
        "complete_partial_or_failure",
        "abandon_pending_progress",
    ),
)
def test_every_safe_summary_path_accepts_ordinary_prose(pg_engine, summary_path) -> None:
    prose = "Bounded ingestion outcome recorded for operator review."
    if summary_path == "acquire_cycle":
        with Session(pg_engine) as session, session.begin():
            row = OperationalPersistenceService(session).acquire_cycle(
                trigger_type="manual",
                manual_request_key=f"request-{uuid4()}",
                sources_expected=1,
                safe_summary=prose,
            )
            assert row.safe_summary == prose
        return

    run_id = (
        pending_run(pg_engine, "cisa-kev")
        if summary_path == "abandon_pending_progress"
        else committed_run(pg_engine, "censys-arc-research")
    )
    with Session(pg_engine) as session, session.begin():
        service = OperationalPersistenceService(session)
        if summary_path == "record_persistence_commit":
            row = service.record_persistence_commit(
                run_id=run_id, expected_state_version=1, counters=CREATED,
                safe_summary=prose,
            )
        elif summary_path == "complete_non_request":
            row = service.complete_non_request(
                run_id=run_id, expected_state_version=1, status="skipped",
                safe_summary=prose,
            )
        elif summary_path == "complete_partial_or_failure":
            row = service.complete_partial_or_failure(
                run_id=run_id, expected_state_version=1, status="failed",
                counters=ZERO, run_level_error=True, safe_summary=prose,
            )
        else:
            row = service.abandon_pending_progress(
                run_id=run_id, expected_state_version=2, status="failed",
                safe_summary=prose,
            )
        assert row.safe_summary == prose


def test_checkpoint_advances_from_committed_pending_run(pg_engine) -> None:
    run_id = pending_run(pg_engine, "cisa-kev")
    with Session(pg_engine) as session, session.begin():
        checkpoint = OperationalPersistenceService(session).advance_checkpoint(run_id=run_id, expected_run_state_version=2, scope_kind="source", partition_key=None, checkpoint_name="catalog", checkpoint_value="v1", expected_previous_version=0, committed_at=NOW + timedelta(seconds=1))
        assert (checkpoint.version, checkpoint.previous_checkpoint_id) == (1, None)
        assert session.get(IngestionRun, run_id).status == "success"


def test_same_transaction_checkpoint_advancement_fails_closed(pg_engine) -> None:
    run_id = committed_run(pg_engine, "cisa-kev")
    with Session(pg_engine) as session, session.begin():
        service = OperationalPersistenceService(session)
        service.record_persistence_commit(
            run_id=run_id, expected_state_version=1, counters=CREATED,
            occurred_at=NOW,
        )
        with pytest.raises(OperationalConflictError, match="Committed persistence"):
            service.advance_checkpoint(
                run_id=run_id,
                expected_run_state_version=2,
                scope_kind="source",
                partition_key=None,
                checkpoint_name="catalog",
                checkpoint_value="v1",
                expected_previous_version=0,
                committed_at=NOW + timedelta(seconds=1),
            )
        assert run_evidence(session, run_id) == (
            "checkpoint_pending", 2, None, 2, 0, 0
        )

    with Session(pg_engine) as session, session.begin():
        checkpoint = OperationalPersistenceService(session).advance_checkpoint(
            run_id=run_id,
            expected_run_state_version=2,
            scope_kind="source",
            partition_key=None,
            checkpoint_name="catalog",
            checkpoint_value="v1",
            expected_previous_version=0,
            committed_at=NOW + timedelta(seconds=1),
        )
        assert checkpoint.version == 1


@pytest.mark.parametrize(
    "checkpoint_value",
    (
        "   ",
        "postgresql://service:secret@localhost/database",
        "mysql://service:secret@localhost/database",
        "mssql://service:secret@localhost/database",
        "redis://service:secret@localhost/0",
        "Authorization: Bearer secret-token",
        "Basic dXNlcjpwYXNz",
        "api_key=secret-value",
        "-----BEGIN PRIVATE KEY-----",
    ),
)
def test_checkpoint_rejection_preserves_pending_run_and_history(
    pg_engine, checkpoint_value
) -> None:
    run_id = pending_run(pg_engine, "cisa-kev")
    with Session(pg_engine) as session, session.begin():
        before = run_evidence(session, run_id)
        with pytest.raises(OperationalValidationError) as exc_info:
            OperationalPersistenceService(session).advance_checkpoint(
                run_id=run_id,
                expected_run_state_version=2,
                scope_kind="source",
                partition_key=None,
                checkpoint_name="catalog",
                checkpoint_value=checkpoint_value,
                expected_previous_version=0,
            )
        assert checkpoint_value not in str(exc_info.value)
        assert run_evidence(session, run_id) == before


def test_checkpoint_preserves_an_ordinary_opaque_value(pg_engine) -> None:
    run_id = pending_run(pg_engine, "cisa-kev")
    opaque_value = "  cursor::opaque/segment==  "
    with Session(pg_engine) as session, session.begin():
        checkpoint = OperationalPersistenceService(session).advance_checkpoint(
            run_id=run_id,
            expected_run_state_version=2,
            scope_kind="source",
            partition_key=None,
            checkpoint_name="catalog",
            checkpoint_value=opaque_value,
            expected_previous_version=0,
        )
        assert checkpoint.checkpoint_value == opaque_value


def test_checkpoint_chain_is_monotonic_and_linear(pg_engine) -> None:
    first_run = pending_run(pg_engine, "cisa-kev")
    with Session(pg_engine) as session, session.begin():
        first = OperationalPersistenceService(session).advance_checkpoint(run_id=first_run, expected_run_state_version=2, scope_kind="source", partition_key=None, checkpoint_name="catalog", checkpoint_value="v1", expected_previous_version=0, committed_at=NOW + timedelta(seconds=1))
        first_id = first.id
    second_run = pending_run(pg_engine, "cisa-kev")
    with Session(pg_engine) as session, session.begin():
        second = OperationalPersistenceService(session).advance_checkpoint(run_id=second_run, expected_run_state_version=2, scope_kind="source", partition_key=None, checkpoint_name="catalog", checkpoint_value="v2", expected_previous_version=1, committed_at=NOW + timedelta(seconds=2))
        assert (second.version, second.previous_checkpoint_id) == (2, first_id)


def test_duplicate_checkpoint_finalization_is_idempotent(pg_engine) -> None:
    run_id = pending_run(pg_engine, "cisa-kev")
    kwargs = dict(run_id=run_id, expected_run_state_version=2, scope_kind="source", partition_key=None, checkpoint_name="catalog", checkpoint_value="v1", expected_previous_version=0, committed_at=NOW + timedelta(seconds=1))
    with Session(pg_engine) as session, session.begin():
        first_id = OperationalPersistenceService(session).advance_checkpoint(**kwargs).id
    with Session(pg_engine) as session, session.begin():
        second = OperationalPersistenceService(session).advance_checkpoint(**kwargs)
        assert second.id == first_id
        assert counts(session, SourceCheckpoint) == 1
        assert counts(session, IngestionRunEvent) == 4


def test_stale_checkpoint_advancement_is_rejected(pg_engine) -> None:
    first_run = pending_run(pg_engine, "cisa-kev")
    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).advance_checkpoint(run_id=first_run, expected_run_state_version=2, scope_kind="source", partition_key=None, checkpoint_name="catalog", checkpoint_value="v1", expected_previous_version=0)
    second_run = pending_run(pg_engine, "cisa-kev")
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalStaleStateError):
            OperationalPersistenceService(session).advance_checkpoint(run_id=second_run, expected_run_state_version=2, scope_kind="source", partition_key=None, checkpoint_name="catalog", checkpoint_value="v2", expected_previous_version=0)


def test_checkpoint_rollback_leaves_run_pending(pg_engine) -> None:
    run_id = pending_run(pg_engine, "cisa-kev")
    with Session(pg_engine) as session:
        transaction = session.begin()
        OperationalPersistenceService(session).advance_checkpoint(run_id=run_id, expected_run_state_version=2, scope_kind="source", partition_key=None, checkpoint_name="catalog", checkpoint_value="v1", expected_previous_version=0)
        transaction.rollback()
    with Session(pg_engine) as session:
        run = session.get(IngestionRun, run_id)
        assert (run.status, run.state_version) == ("checkpoint_pending", 2)
        assert counts(session, SourceCheckpoint) == 0


def test_watermark_values_must_increase(pg_engine) -> None:
    first_run = pending_run(pg_engine, "nvd")
    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).advance_watermark(run_id=first_run, expected_run_state_version=2, scope_kind="source", partition_key=None, watermark_name="modified", watermark_value=NOW, expected_previous_version=0)
    second_run = pending_run(pg_engine, "nvd")
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalConflictError):
            OperationalPersistenceService(session).advance_watermark(run_id=second_run, expected_run_state_version=2, scope_kind="source", partition_key=None, watermark_name="modified", watermark_value=NOW, expected_previous_version=1)


def test_same_transaction_watermark_advancement_fails_closed(pg_engine) -> None:
    run_id = committed_run(pg_engine, "nvd")
    with Session(pg_engine) as session, session.begin():
        service = OperationalPersistenceService(session)
        service.record_persistence_commit(
            run_id=run_id, expected_state_version=1, counters=CREATED,
            occurred_at=NOW,
        )
        with pytest.raises(OperationalConflictError, match="Committed persistence"):
            service.advance_watermark(
                run_id=run_id,
                expected_run_state_version=2,
                scope_kind="source",
                partition_key=None,
                watermark_name="modified",
                watermark_value=NOW,
                expected_previous_version=0,
                committed_at=NOW + timedelta(seconds=1),
            )
        assert run_evidence(session, run_id) == (
            "checkpoint_pending", 2, None, 2, 0, 0
        )

    with Session(pg_engine) as session, session.begin():
        watermark = OperationalPersistenceService(session).advance_watermark(
            run_id=run_id,
            expected_run_state_version=2,
            scope_kind="source",
            partition_key=None,
            watermark_name="modified",
            watermark_value=NOW,
            expected_previous_version=0,
            committed_at=NOW + timedelta(seconds=1),
        )
        assert watermark.version == 1


@pytest.mark.parametrize("watermark_value", [None, datetime(2026, 8, 1, 12, 0)])
def test_missing_or_naive_watermark_rejection_preserves_pending_state(
    pg_engine, watermark_value
) -> None:
    run_id = pending_run(pg_engine, "nvd")
    with Session(pg_engine) as session, session.begin():
        before = run_evidence(session, run_id)
        with pytest.raises(OperationalValidationError) as exc_info:
            OperationalPersistenceService(session).advance_watermark(
                run_id=run_id,
                expected_run_state_version=2,
                scope_kind="source",
                partition_key=None,
                watermark_name="modified",
                watermark_value=watermark_value,
                expected_previous_version=0,
            )
        assert str(watermark_value) not in str(exc_info.value)
        assert run_evidence(session, run_id) == before


def test_offset_aware_watermark_normalizes_to_utc(pg_engine) -> None:
    run_id = pending_run(pg_engine, "nvd")
    offset_value = NOW.astimezone(timezone(timedelta(hours=4)))
    with Session(pg_engine) as session, session.begin():
        watermark = OperationalPersistenceService(session).advance_watermark(
            run_id=run_id,
            expected_run_state_version=2,
            scope_kind="source",
            partition_key=None,
            watermark_name="modified",
            watermark_value=offset_value,
            expected_previous_version=0,
        )
        assert watermark.watermark_value == NOW


def test_watermark_rollback_and_duplicate_behavior(pg_engine) -> None:
    run_id = pending_run(pg_engine, "nvd")
    kwargs = dict(run_id=run_id, expected_run_state_version=2, scope_kind="source", partition_key=None, watermark_name="modified", watermark_value=NOW, expected_previous_version=0)
    with Session(pg_engine) as session:
        transaction = session.begin()
        OperationalPersistenceService(session).advance_watermark(**kwargs)
        transaction.rollback()
    with Session(pg_engine) as session, session.begin():
        first = OperationalPersistenceService(session).advance_watermark(**kwargs)
        first_id = first.id
    with Session(pg_engine) as session, session.begin():
        assert OperationalPersistenceService(session).advance_watermark(**kwargs).id == first_id
        assert counts(session, SourceWatermark) == 1


def test_rate_state_create_and_exact_version_update(pg_engine) -> None:
    with Session(pg_engine) as session, session.begin():
        created = OperationalPersistenceService(session).update_rate_limit_state(source_slug="nvd", policy_key="public-api", expected_state_version=None, state="available", request_limit=10, remaining=9, window_seconds=60, updated_at=NOW)
        assert created.state_version == 1
    with Session(pg_engine) as session, session.begin():
        updated = OperationalPersistenceService(session).update_rate_limit_state(source_slug="nvd", policy_key="public-api", expected_state_version=1, state="limited", request_limit=10, remaining=0, window_seconds=60, updated_at=NOW)
        assert updated.state_version == 2


def test_stale_rate_state_update_is_rejected(pg_engine) -> None:
    with Session(pg_engine) as session, session.begin():
        OperationalPersistenceService(session).update_rate_limit_state(source_slug="nvd", policy_key="public-api", expected_state_version=None, state="unknown")
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalStaleStateError):
            OperationalPersistenceService(session).update_rate_limit_state(source_slug="nvd", policy_key="public-api", expected_state_version=2, state="available")


def test_rate_state_source_matched_updater_is_enforced(pg_engine) -> None:
    run_id = committed_run(pg_engine, "nvd")
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalConflictError):
            OperationalPersistenceService(session).update_rate_limit_state(source_slug="cisa-kev", policy_key="catalog", expected_state_version=None, state="unknown", updated_by_run_id=run_id)


def test_sanitized_exceptions_do_not_disclose_database_or_inputs(pg_engine) -> None:
    canary = "Bearer very-secret-value"
    run_id = pending_run(pg_engine, "cisa-kev")
    with Session(pg_engine) as session, session.begin():
        with pytest.raises(OperationalValidationError) as exc_info:
            OperationalPersistenceService(session).advance_checkpoint(run_id=run_id, expected_run_state_version=2, scope_kind="source", partition_key=None, checkpoint_name="catalog", checkpoint_value=canary, expected_previous_version=0)
        message = str(exc_info.value)
        assert canary not in message
        assert "SELECT" not in message
        assert "postgresql" not in message.casefold()
