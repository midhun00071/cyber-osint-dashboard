from __future__ import annotations

from datetime import UTC, datetime, timedelta
import ipaddress
import os
from pathlib import Path
import socket
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.db.base import Base
import app.models  # noqa: F401
from app.models import IngestionCycle, IngestionRun, IntelligenceSource


DATABASE_ENV = "B103_POSTGRESQL_TEST_DATABASE_URL"
BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
HISTORICAL_OPERATIONAL_REVISION = "b103a71d2e4f"
CURRENT_HEAD_REVISION = "c07a01b02c03"
BASELINE_HEAD = "c4e8b2a91d30"
EXPECTED_TABLES = set(Base.metadata.tables)
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
        pytest.fail("Dedicated B1-03 database configuration is invalid")
    if url.drivername not in {"postgresql", "postgresql+psycopg"}:
        pytest.fail("Dedicated B1-03 database must use PostgreSQL")
    if url.query:
        pytest.fail("Dedicated B1-03 database URL query parameters are forbidden")
    host = (url.host or "").strip("[]").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("Dedicated B1-03 database must be loopback-only")
    if host == "localhost":
        try:
            addresses = {
                ipaddress.ip_address(result[4][0])
                for result in socket.getaddrinfo(host, url.port or 5432)
            }
        except (OSError, ValueError):
            pytest.fail("Dedicated B1-03 database host could not be resolved safely")
        if not addresses or not all(address.is_loopback for address in addresses):
            pytest.fail("Dedicated B1-03 database must resolve only to loopback")
    database = url.database or ""
    if not database.startswith("b103_test_"):
        pytest.fail("Dedicated B1-03 database name must use the disposable prefix")
    if any(label in database.casefold() for label in ("staging", "production", "prod")):
        pytest.fail("Staging and production database names are forbidden")
    return url.set(drivername="postgresql+psycopg")


def _database_url() -> URL:
    raw = os.getenv(DATABASE_ENV)
    if not raw:
        pytest.skip(f"{DATABASE_ENV} is not configured")
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

    monkeypatch.setattr(sa, "create_engine", unexpected_create_engine)
    submitted = (
        "postgresql://synthetic-user:query-password-canary@127.0.0.1/"
        f"b103_test_guard?{query_name}=query-override-canary"
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
        "b103_test_guard"
    )

    assert url.drivername == "postgresql+psycopg"
    assert url.host == "127.0.0.1"
    assert url.database == "b103_test_guard"
    assert not url.query


def _configure_database(url: URL) -> Config:
    os.environ["DATABASE_URL"] = url.render_as_string(hide_password=False)
    get_settings.cache_clear()
    return Config(str(ALEMBIC_INI))


@pytest.fixture(scope="module")
def pg_database():
    url = _database_url()
    previous_database_url = os.environ.get("DATABASE_URL")
    config = _configure_database(url)
    engine = sa.create_engine(url, poolclass=NullPool)
    try:
        yield engine, config
    finally:
        try:
            _reset_disposable_database(engine)
        finally:
            engine.dispose()
            if previous_database_url is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = previous_database_url
            get_settings.cache_clear()


@pytest.fixture
def current_pg(pg_database):
    engine, config = pg_database
    _reset_disposable_database(engine)
    command.upgrade(config, CURRENT_HEAD_REVISION)
    try:
        yield engine, config
    finally:
        _reset_disposable_database(engine)


@pytest.fixture
def historical_pg(pg_database):
    engine, config = pg_database
    _reset_disposable_database(engine)
    command.upgrade(config, HISTORICAL_OPERATIONAL_REVISION)
    try:
        yield engine, config
    finally:
        _reset_disposable_database(engine)


def _reflect(engine, *names):
    metadata = sa.MetaData()
    return tuple(sa.Table(name, metadata, autoload_with=engine) for name in names)


def _reset_disposable_database(engine):
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")


def _expect_rejected(engine, table, values):
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(sa.insert(table).values(**values))


def _source_values(index, now, **overrides):
    values = {
        "public_id": uuid4(),
        "name": f"B1-03 source {index}",
        "slug": f"b1-03-source-{index}",
        "source_type": "api",
        "base_url": None,
        "is_enabled": True,
        "rate_limit_notes": None,
        "last_successful_fetch_at": None,
        "checkpoint_value": None,
        "created_at": now,
        "updated_at": now,
    }
    values.update(overrides)
    return values


def _cycle_values(index, now, **overrides):
    values = {
        "public_id": uuid4(),
        "idempotency_key": f"cycle-{index}",
        "trigger_type": "manual",
        "status": "running",
        "scheduled_for": None,
        "started_at": now,
        "completed_at": None,
        "sources_expected": 1,
        "sources_started": 1,
        "sources_completed": 0,
        "sources_successful": 0,
        "sources_non_successful": 0,
        "safe_summary": None,
        "created_at": now,
    }
    values.update(overrides)
    return values


def _run_values(index, source_id, cycle_id, now, **overrides):
    values = {
        "public_id": uuid4(),
        "source_id": source_id,
        "cycle_id": cycle_id,
        "idempotency_key": f"run-{index}",
        "attempt_number": 0,
        "retry_of_run_id": None,
        "state_version": 1,
        "defer_reason": None,
        "trigger_type": "manual",
        "status": "running",
        "started_at": now,
        "completed_at": None,
        "records_fetched": 0,
        "records_created": 0,
        "records_updated": 0,
        "records_unchanged": 0,
        "records_skipped": 0,
        "records_failed": 0,
        "error_count": 0,
        "checkpoint_before": None,
        "checkpoint_after": None,
        "safe_summary": None,
        "created_at": now,
    }
    values.update(overrides)
    return values


def _compatibility_run_values(index, source_id, now, **overrides):
    values = _run_values(index, source_id, None, now, **overrides)
    for column_name in (
        "cycle_id",
        "idempotency_key",
        "attempt_number",
        "retry_of_run_id",
        "state_version",
        "defer_reason",
    ):
        values.pop(column_name)
    return values


def test_fresh_upgrade_has_one_head_and_exact_tables(current_pg):
    engine, _ = current_pg
    inspector = sa.inspect(engine)
    tables = set(inspector.get_table_names()) - {"alembic_version"}
    assert tables == EXPECTED_TABLES
    with engine.connect() as connection:
        assert connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one() == CURRENT_HEAD_REVISION
    assert len(EXPECTED_TABLES) == 30


def test_model_metadata_reconciles_columns_constraints_indexes_and_deletes(current_pg):
    engine, _ = current_pg
    inspector = sa.inspect(engine)
    for table_name in EXPECTED_TABLES:
        assert {column["name"] for column in inspector.get_columns(table_name)} == set(Base.metadata.tables[table_name].c.keys())
    expected_fks = {
        ("source_checkpoints", "fk_source_checkpoints_advanced_run_source"): "RESTRICT",
        ("source_watermarks", "fk_source_watermarks_advanced_run_source"): "RESTRICT",
        ("source_rate_limit_states", "fk_source_rate_limit_states_run_source"): "RESTRICT",
        ("quarantined_records", "fk_quarantined_records_event_run"): "RESTRICT",
        ("audit_events", "fk_audit_events_run_cycle"): "SET NULL",
    }
    for (table_name, name), ondelete in expected_fks.items():
        fk = next(item for item in inspector.get_foreign_keys(table_name) if item["name"] == name)
        assert fk["options"].get("ondelete") == ondelete
    for table_name, names in {
        "source_checkpoints": {
            "uq_source_checkpoints_source_identity_version",
            "uq_source_checkpoints_partition_identity_version",
        },
        "source_watermarks": {
            "uq_source_watermarks_source_identity_version",
            "uq_source_watermarks_partition_identity_version",
        },
    }.items():
        indexes = {item["name"]: item for item in inspector.get_indexes(table_name)}
        assert names <= set(indexes)
        assert all(indexes[name]["unique"] for name in names)
        assert all(indexes[name]["dialect_options"]["postgresql_where"] for name in names)


def test_current_writer_orm_shape_remains_compatible_without_fabrication(current_pg):
    engine, _ = current_pg
    now = datetime.now(UTC).replace(microsecond=0)
    completed = now + timedelta(seconds=1)
    with Session(engine) as session:
        source = IntelligenceSource(**_source_values(50, now))
        session.add(source)
        session.flush()
        run = IngestionRun(
            source=source,
            trigger_type="manual",
            status="running",
            started_at=now,
            completed_at=None,
            records_fetched=1,
            records_created=1,
            records_updated=0,
            records_unchanged=0,
            records_skipped=0,
            records_failed=0,
            error_count=0,
            checkpoint_before=None,
            checkpoint_after="cursor-safe",
            safe_summary="Compatibility writer test completed safely.",
            created_at=now,
        )
        session.add(run)
        session.flush()
        assert run.cycle_id is None
        assert run.idempotency_key is None
        assert run.attempt_number is None
        assert run.state_version is None
        run.status = "succeeded"
        run.completed_at = completed
        session.commit()
        run_id = run.id

    with Session(engine) as session:
        persisted = session.get(IngestionRun, run_id)
        assert persisted is not None
        assert persisted.status == "succeeded"
        assert persisted.completed_at == completed
        assert persisted.cycle_id is None
        assert persisted.idempotency_key is None
        assert persisted.attempt_number is None
        assert persisted.state_version is None
        assert persisted.cycle is None
        assert session.scalar(sa.select(sa.func.count()).select_from(IngestionCycle)) == 0


def test_compatibility_shape_rejects_mixed_and_target_only_rows(historical_pg):
    engine, _ = historical_pg
    sources, cycles, runs = _reflect(
        engine, "intelligence_sources", "ingestion_cycles", "ingestion_runs"
    )
    now = datetime.now(UTC).replace(microsecond=0)
    completed = now + timedelta(seconds=1)
    with engine.begin() as connection:
        source_id = connection.execute(
            sa.insert(sources).values(**_source_values(60, now)).returning(sources.c.id)
        ).scalar_one()
        cycle_id = connection.execute(
            sa.insert(cycles).values(**_cycle_values(60, now)).returning(cycles.c.id)
        ).scalar_one()
        target_run_id = connection.execute(
            sa.insert(runs)
            .values(
                **_run_values(
                    60,
                    source_id,
                    cycle_id,
                    now,
                    status="success",
                    completed_at=completed,
                )
            )
            .returning(runs.c.id)
        ).scalar_one()
        assert target_run_id > 0

    _expect_rejected(
        engine,
        runs,
        {
            **_compatibility_run_values(61, source_id, now),
            "cycle_id": cycle_id,
        },
    )
    _expect_rejected(
        engine,
        runs,
        _compatibility_run_values(
            62, source_id, now, status="checkpoint_pending"
        ),
    )
    _expect_rejected(
        engine,
        runs,
        _compatibility_run_values(
            63, source_id, now, status="success", completed_at=completed
        ),
    )


def test_postgresql_constraints_and_null_semantics(historical_pg):
    engine, _ = historical_pg
    (
        sources, cycles, runs, events, checkpoints, watermarks, rate_states,
        quarantines, audits, credentials,
    ) = _reflect(
        engine,
        "intelligence_sources", "ingestion_cycles", "ingestion_runs",
        "ingestion_run_events", "source_checkpoints", "source_watermarks",
        "source_rate_limit_states", "quarantined_records", "audit_events",
        "source_credential_references",
    )
    now = datetime.now(UTC)
    with engine.begin() as connection:
        source_one = connection.execute(sa.insert(sources).values(**_source_values(100, now)).returning(sources.c.id)).scalar_one()
        source_two = connection.execute(sa.insert(sources).values(**_source_values(101, now)).returning(sources.c.id)).scalar_one()
        cycle_one = connection.execute(sa.insert(cycles).values(**_cycle_values(100, now)).returning(cycles.c.id)).scalar_one()
        cycle_two = connection.execute(sa.insert(cycles).values(**_cycle_values(101, now)).returning(cycles.c.id)).scalar_one()
        cycle_three = connection.execute(sa.insert(cycles).values(**_cycle_values(103, now)).returning(cycles.c.id)).scalar_one()
        run_one = connection.execute(sa.insert(runs).values(**_run_values(100, source_one, cycle_one, now)).returning(runs.c.id)).scalar_one()
        run_two = connection.execute(sa.insert(runs).values(**_run_values(101, source_two, cycle_two, now)).returning(runs.c.id)).scalar_one()
        connection.execute(sa.insert(runs).values(**_run_values(106, source_one, cycle_three, now, status="checkpoint_pending")))
        event_one = connection.execute(sa.insert(events).values(ingestion_run_id=run_one, sequence_number=1, event_type="acquired", from_status=None, to_status=None, safe_message=None, occurred_at=now, created_at=now).returning(events.c.id)).scalar_one()

    _expect_rejected(engine, cycles, _cycle_values(102, now, sources_completed=1, sources_successful=0, sources_non_successful=0))
    _expect_rejected(engine, cycles, _cycle_values(104, now, idempotency_key="cycle-100"))
    _expect_rejected(engine, runs, _run_values(102, source_one, cycle_one, now, status="success", completed_at=None))
    _expect_rejected(engine, runs, _run_values(103, source_one, cycle_one, now, status="checkpoint_pending", completed_at=now))
    _expect_rejected(engine, runs, _run_values(104, source_one, cycle_one, now, idempotency_key="run-100"))
    _expect_rejected(engine, runs, _run_values(100, source_one, cycle_one, now))
    _expect_rejected(engine, runs, _run_values(105, source_two, cycle_two, now, attempt_number=1, retry_of_run_id=run_one))
    _expect_rejected(engine, runs, _run_values(107, source_one, cycle_two, now, attempt_number=1, retry_of_run_id=run_one))
    _expect_rejected(engine, runs, _run_values(108, source_one, cycle_one, now, attempt_number=11, retry_of_run_id=run_one))

    checkpoint = dict(source_id=source_one, scope_kind="source", partition_key=None, checkpoint_name="cursor", version=1, checkpoint_value="v1", previous_checkpoint_id=None, advanced_by_run_id=run_one, persistence_committed_at=now, committed_at=now)
    partition_checkpoint = {**checkpoint, "scope_kind": "partition", "partition_key": "p1", "checkpoint_name": "cursor-p"}
    watermark = dict(source_id=source_one, scope_kind="source", partition_key=None, watermark_name="observed", version=1, watermark_value=now, previous_watermark_id=None, advanced_by_run_id=run_one, persistence_committed_at=now, committed_at=now)
    partition_watermark = {**watermark, "scope_kind": "partition", "partition_key": "p1", "watermark_name": "observed-p"}
    with engine.begin() as connection:
        checkpoint_id = connection.execute(sa.insert(checkpoints).values(**checkpoint).returning(checkpoints.c.id)).scalar_one()
        connection.execute(sa.insert(checkpoints).values(**partition_checkpoint))
        connection.execute(sa.insert(watermarks).values(**watermark))
        connection.execute(sa.insert(watermarks).values(**partition_watermark))
    for table, values in ((checkpoints, checkpoint), (checkpoints, partition_checkpoint), (watermarks, watermark), (watermarks, partition_watermark)):
        _expect_rejected(engine, table, values)
    _expect_rejected(engine, checkpoints, {**checkpoint, "checkpoint_name": "wrong-source", "version": 2, "source_id": source_two})
    _expect_rejected(engine, checkpoints, {**checkpoint, "checkpoint_name": "wrong-predecessor", "version": 2, "source_id": source_two, "advanced_by_run_id": run_two, "previous_checkpoint_id": checkpoint_id})
    _expect_rejected(engine, watermarks, {**watermark, "watermark_name": "wrong-source", "version": 2, "source_id": source_two})
    _expect_rejected(engine, rate_states, dict(source_id=source_two, policy_key="p", request_limit=10, remaining=1, window_seconds=60, reset_at=None, backoff_until=None, last_observed_at=now, state="available", state_version=1, updated_by_run_id=run_one, updated_at=now))
    _expect_rejected(engine, quarantines, dict(public_id=uuid4(), source_id=source_two, ingestion_run_id=run_two, ingestion_run_event_id=event_one, quarantine_key="a" * 64, reason_code="invalid", safe_excerpt="safe", safe_metadata=None, original_byte_count=4, stored_byte_count=4, status="pending", quarantined_at=now, reviewed_at=None))
    _expect_rejected(engine, audits, dict(public_id=uuid4(), idempotency_key="audit-wrong-cycle", actor_type="system", actor_ref="test", action="test.action", target_type="run", target_ref="safe", outcome="failed", cycle_id=cycle_two, ingestion_run_id=run_one, correlation_id=None, safe_detail=None, occurred_at=now, created_at=now))
    _expect_rejected(engine, quarantines, dict(public_id=uuid4(), source_id=source_one, ingestion_run_id=run_one, ingestion_run_event_id=event_one, quarantine_key="b" * 64, reason_code="invalid", safe_excerpt="é", safe_metadata=None, original_byte_count=2, stored_byte_count=1, status="pending", quarantined_at=now, reviewed_at=None))
    with engine.begin() as connection:
        connection.execute(sa.insert(quarantines).values(public_id=uuid4(), source_id=source_one, ingestion_run_id=run_one, ingestion_run_event_id=event_one, quarantine_key="c" * 64, reason_code="invalid", safe_excerpt="é", safe_metadata="ok", original_byte_count=4, stored_byte_count=4, status="pending", quarantined_at=now, reviewed_at=None))
        connection.execute(sa.insert(credentials).values(source_id=source_one, reference_name="configured", purpose="source_auth", external_reference_id="reference-1", configuration_state="configured", owner_ref="team", last_rotated_at=now, expires_at=now, created_at=now, updated_at=now))
        connection.execute(sa.insert(credentials).values(source_id=source_one, reference_name="missing", purpose="source_auth", external_reference_id=None, configuration_state="not_configured", owner_ref=None, last_rotated_at=None, expires_at=None, created_at=now, updated_at=now))
    _expect_rejected(engine, quarantines, dict(public_id=uuid4(), source_id=source_one, ingestion_run_id=run_one, ingestion_run_event_id=event_one, quarantine_key="d" * 64, reason_code="invalid", safe_excerpt="é" * 1000, safe_metadata="é" * 2000, original_byte_count=6000, stored_byte_count=6000, status="pending", quarantined_at=now, reviewed_at=None))
    _expect_rejected(engine, credentials, dict(source_id=source_one, reference_name="auth", purpose="source_auth", external_reference_id=None, configuration_state="configured", owner_ref=None, last_rotated_at=None, expires_at=None, created_at=now, updated_at=now))


def test_existing_head_backfill_controlled_downgrade_fail_closed_and_reupgrade(historical_pg):
    engine, config = historical_pg
    _reset_disposable_database(engine)
    command.upgrade(config, BASELINE_HEAD)
    sources, runs = _reflect(engine, "intelligence_sources", "ingestion_runs")
    now = datetime.now(UTC).replace(microsecond=0)
    completed = now + timedelta(minutes=1)
    with engine.begin() as connection:
        source_id = connection.execute(sa.insert(sources).values(**_source_values(200, now, checkpoint_value="cursor-1", last_successful_fetch_at=completed)).returning(sources.c.id)).scalar_one()
        running_public_id = uuid4()
        success_public_id = uuid4()
        connection.execute(sa.insert(runs).values(**{key: value for key, value in _run_values(200, source_id, 0, now, public_id=running_public_id, trigger_type="manual").items() if key not in {"cycle_id", "idempotency_key", "attempt_number", "retry_of_run_id", "state_version", "defer_reason"}}))
        connection.execute(sa.insert(runs).values(**{key: value for key, value in _run_values(201, source_id, 0, now, public_id=success_public_id, trigger_type="scheduled", status="succeeded", completed_at=completed, checkpoint_after="cursor-1").items() if key not in {"cycle_id", "idempotency_key", "attempt_number", "retry_of_run_id", "state_version", "defer_reason"}}))
    command.upgrade(config, HISTORICAL_OPERATIONAL_REVISION)
    runs, cycles, events, checkpoints, watermarks = _reflect(engine, "ingestion_runs", "ingestion_cycles", "ingestion_run_events", "source_checkpoints", "source_watermarks")
    with engine.connect() as connection:
        run_rows = connection.execute(sa.select(runs.c.public_id, runs.c.trigger_type, runs.c.status, runs.c.attempt_number, runs.c.retry_of_run_id, runs.c.idempotency_key)).mappings().all()
        assert {row["trigger_type"] for row in run_rows} == {"manual", "scheduled"}
        assert {row["status"] for row in run_rows} == {"running", "success"}
        assert all(row["attempt_number"] == 0 and row["retry_of_run_id"] is None for row in run_rows)
        assert {row["idempotency_key"] for row in run_rows} == {f"legacy-run:{running_public_id}", f"legacy-run:{success_public_id}"}
        assert connection.scalar(sa.select(sa.func.count()).select_from(cycles)) == 2
        assert connection.scalar(sa.select(sa.func.count()).select_from(events)) == 3
        assert connection.scalar(sa.select(sa.func.count()).select_from(checkpoints)) == 1
        assert connection.scalar(sa.select(sa.func.count()).select_from(watermarks)) == 1
        assert connection.scalar(sa.select(sa.func.count()).select_from(cycles).where(cycles.c.scheduled_for.is_not(None))) == 0
        cycle_rows = connection.execute(sa.select(cycles.c.status, cycles.c.sources_expected, cycles.c.sources_started, cycles.c.sources_completed, cycles.c.sources_successful, cycles.c.sources_non_successful)).all()
        assert set(cycle_rows) == {
            ("running", 1, 1, 0, 0, 0),
            ("success", 1, 1, 1, 1, 0),
        }
        assert set(connection.execute(sa.select(events.c.event_type)).scalars()) == {"acquired", "completed"}
    command.downgrade(config, BASELINE_HEAD)
    sources, runs = _reflect(engine, "intelligence_sources", "ingestion_runs")
    with engine.connect() as connection:
        assert set(connection.execute(sa.select(runs.c.status)).scalars()) == {"running", "succeeded"}
        source = connection.execute(sa.select(sources.c.checkpoint_value, sources.c.last_successful_fetch_at)).one()
        assert source.checkpoint_value == "cursor-1"
        assert source.last_successful_fetch_at == completed
    command.upgrade(config, HISTORICAL_OPERATIONAL_REVISION)
    runs = _reflect(engine, "ingestion_runs")[0]
    with engine.begin() as connection:
        success_run = connection.execute(sa.select(runs.c.id).where(runs.c.status == "success")).scalar_one()
        connection.execute(sa.update(runs).where(runs.c.id == success_run).values(status="checkpoint_pending", completed_at=None))
    with pytest.raises(RuntimeError, match="checkpoint_pending_run"):
        command.downgrade(config, BASELINE_HEAD)
    with engine.begin() as connection:
        connection.execute(sa.update(runs).where(runs.c.id == success_run).values(status="success", completed_at=completed))
    audits = _reflect(engine, "audit_events")[0]
    with engine.begin() as connection:
        connection.execute(sa.insert(audits).values(public_id=uuid4(), idempotency_key="target-only-audit", actor_type="system", actor_ref="test", action="test.action", target_type="run", target_ref="safe", outcome="success", cycle_id=None, ingestion_run_id=None, correlation_id=None, safe_detail=None, occurred_at=now, created_at=now))
    with pytest.raises(RuntimeError, match="target_only_audit_events"):
        command.downgrade(config, BASELINE_HEAD)
    with engine.begin() as connection:
        connection.execute(sa.delete(audits))
        transitional_public_id = uuid4()
        connection.execute(
            sa.insert(runs).values(
                **_compatibility_run_values(
                    202,
                    source_id,
                    now,
                    public_id=transitional_public_id,
                    status="succeeded",
                    completed_at=completed,
                )
            )
        )
    command.downgrade(config, BASELINE_HEAD)
    runs = _reflect(engine, "ingestion_runs")[0]
    with engine.connect() as connection:
        transitional = connection.execute(
            sa.select(runs.c.status).where(runs.c.public_id == transitional_public_id)
        ).one()
        assert transitional.status == "succeeded"
    command.upgrade(config, HISTORICAL_OPERATIONAL_REVISION)


def test_downgrade_preserves_ingestion_error_extension_evidence(historical_pg):
    engine, config = historical_pg
    sources, runs, errors = _reflect(
        engine, "intelligence_sources", "ingestion_runs", "ingestion_errors"
    )
    now = datetime.now(UTC).replace(microsecond=0)
    with engine.begin() as connection:
        source_id = connection.execute(
            sa.insert(sources)
            .values(**_source_values(300, now))
            .returning(sources.c.id)
        ).scalar_one()
        run_id = connection.execute(
            sa.insert(runs)
            .values(**_compatibility_run_values(300, source_id, now))
            .returning(runs.c.id)
        ).scalar_one()

    base_error = {
        "ingestion_run_id": run_id,
        "ingestion_run_record_id": None,
        "source_record_id": None,
        "error_type": "compatibility_test_error",
        "safe_message": "Sanitized downgrade evidence test.",
        "failure_stage": None,
        "diagnostic_fingerprint": None,
        "safe_context": None,
        "retryable": False,
        "retry_count": 0,
        "occurred_at": now,
    }
    for field_name, field_value in (
        ("failure_stage", "persistence"),
        ("diagnostic_fingerprint", "a" * 64),
        ("safe_context", "bounded-safe-context"),
    ):
        with engine.begin() as connection:
            error_id = connection.execute(
                sa.insert(errors)
                .values(**{**base_error, field_name: field_value})
                .returning(errors.c.id)
            ).scalar_one()
        with pytest.raises(RuntimeError, match="target_only_ingestion_error_metadata"):
            command.downgrade(config, BASELINE_HEAD)
        with engine.connect() as connection:
            assert connection.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalar_one() == HISTORICAL_OPERATIONAL_REVISION
            assert connection.execute(
                sa.select(errors.c[field_name]).where(errors.c.id == error_id)
            ).scalar_one() == field_value
        with engine.begin() as connection:
            connection.execute(sa.delete(errors).where(errors.c.id == error_id))

    with engine.begin() as connection:
        retained_error_id = connection.execute(
            sa.insert(errors).values(**base_error).returning(errors.c.id)
        ).scalar_one()
    command.downgrade(config, BASELINE_HEAD)
    baseline_errors = _reflect(engine, "ingestion_errors")[0]
    assert not {
        "failure_stage", "diagnostic_fingerprint", "safe_context"
    }.intersection(baseline_errors.c.keys())
    with engine.connect() as connection:
        assert connection.execute(
            sa.select(baseline_errors.c.id).where(
                baseline_errors.c.id == retained_error_id
            )
        ).scalar_one() == retained_error_id
    command.upgrade(config, HISTORICAL_OPERATIONAL_REVISION)
    upgraded_errors = _reflect(engine, "ingestion_errors")[0]
    with engine.connect() as connection:
        row = connection.execute(
            sa.select(
                upgraded_errors.c.failure_stage,
                upgraded_errors.c.diagnostic_fingerprint,
                upgraded_errors.c.safe_context,
            ).where(upgraded_errors.c.id == retained_error_id)
        ).one()
        assert tuple(row) == (None, None, None)
