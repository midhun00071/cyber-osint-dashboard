from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import ipaddress
import os
from pathlib import Path
import socket
from uuid import uuid4

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.models import IntelligenceSource


DATABASE_ENV = "B103_POSTGRESQL_TEST_DATABASE_URL"
BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
C06_REVISION = "f4a1c2d3e5b6"
C07A_REVISION = "c07a01b02c03"
C05_DISABLED_SLUGS = (
    "mitre-attack-enterprise",
    "cert-fr-security-alerts",
    "cert-fr-security-advisories",
    "uk-ncsc-threat-reports",
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
        pytest.fail("Dedicated C07A database configuration is invalid")
    if url.drivername not in {"postgresql", "postgresql+psycopg"}:
        pytest.fail("Dedicated C07A database must use PostgreSQL")
    if url.query:
        pytest.fail("Dedicated C07A database URL query parameters are forbidden")
    host = (url.host or "").strip("[]").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("Dedicated C07A database must be loopback-only")
    if host == "localhost":
        try:
            addresses = {
                ipaddress.ip_address(result[4][0])
                for result in socket.getaddrinfo(host, url.port or 5432)
            }
        except (OSError, ValueError):
            pytest.fail("Dedicated C07A database host could not be resolved safely")
        if not addresses or not all(address.is_loopback for address in addresses):
            pytest.fail("Dedicated C07A database must resolve only to loopback")
    database = url.database or ""
    if not database.startswith("b103_test_"):
        pytest.fail("C07A reuses the disposable B1-03 database prefix")
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
def pg():
    url = _database_url()
    engine = sa.create_engine(url, poolclass=NullPool)
    config = Config(str(ALEMBIC_INI))
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.select(sa.literal(1))) == 1
        with _database_url_environment(url):
            _reset_schema(engine)
            command.upgrade(config, C06_REVISION)
            yield engine, config
    finally:
        try:
            _reset_schema(engine)
        finally:
            engine.dispose()


def _reflect(engine: sa.Engine, *names: str) -> tuple[sa.Table, ...]:
    metadata = sa.MetaData()
    return tuple(sa.Table(name, metadata, autoload_with=engine) for name in names)


def _source_values(
    index: int,
    enabled: bool,
    **overrides: object,
) -> dict[str, object]:
    now = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    values: dict[str, object] = {
        "public_id": uuid4(),
        "name": f"C07A source {index}",
        "slug": f"c07a-source-{index}",
        "source_type": "api",
        "base_url": None,
        "is_enabled": enabled,
        "rate_limit_notes": f"bounded-note-{index}",
        "last_successful_fetch_at": now,
        "checkpoint_value": f"source-cursor-{index}",
        "created_at": now,
        "updated_at": now,
    }
    values.update(overrides)
    return values


def _rows(
    connection: sa.Connection,
    table: sa.Table,
    columns: list[sa.Column] | None = None,
) -> list[dict[str, object]]:
    selected = columns if columns is not None else list(table.c)
    return [
        dict(row)
        for row in connection.execute(
            sa.select(*selected).order_by(table.c.id)
        ).mappings()
    ]


def _expect_rejected(
    engine: sa.Engine,
    table: sa.Table,
    values: dict[str, object],
) -> None:
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(sa.insert(table).values(**values))


@pytest.mark.parametrize("query_name", QUERY_OVERRIDE_NAMES)
def test_database_guard_rejects_connection_overrides(query_name: str) -> None:
    submitted = (
        "postgresql://synthetic-user:query-password-canary@127.0.0.1/"
        f"b103_test_guard?{query_name}=query-override-canary"
    )
    with pytest.raises(pytest.fail.Exception) as exc_info:
        _validated_database_url(submitted)
    message = str(exc_info.value)
    assert "query-password-canary" not in message
    assert "query-override-canary" not in message


def test_model_constructor_derives_only_missing_operator_state() -> None:
    enabled = IntelligenceSource(is_enabled=True)
    disabled = IntelligenceSource(is_enabled=False)
    partial = IntelligenceSource(checkpoint_value=None)
    inconsistent = IntelligenceSource(is_enabled=False, operator_state="enabled")

    assert enabled.operator_state == "enabled"
    assert disabled.operator_state == "disabled"
    assert partial.operator_state == "enabled"
    assert IntelligenceSource.__table__.c.is_enabled.default.arg is True
    assert inconsistent.is_enabled is False
    assert inconsistent.operator_state == "enabled"


def test_alembic_has_exactly_one_c07a_head_and_parent() -> None:
    scripts = ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))
    revision = scripts.get_revision(C07A_REVISION)

    assert scripts.get_heads() == [C07A_REVISION]
    assert revision is not None
    assert revision.down_revision == C06_REVISION


def test_upgrade_constraints_durability_integrity_downgrade_and_reupgrade(pg) -> None:
    engine, config = pg
    (
        sources,
        runs,
        checkpoints,
        watermarks,
        rate_states,
        credentials,
    ) = _reflect(
        engine,
        "intelligence_sources",
        "ingestion_runs",
        "source_checkpoints",
        "source_watermarks",
        "source_rate_limit_states",
        "source_credential_references",
    )
    now = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)

    with engine.begin() as connection:
        enabled_id = connection.execute(
            sa.insert(sources)
            .values(**_source_values(1, True))
            .returning(sources.c.id)
        ).scalar_one()
        disabled_id = connection.execute(
            sa.insert(sources)
            .values(**_source_values(2, False))
            .returning(sources.c.id)
        ).scalar_one()
        c05_ids: dict[str, int] = {}
        for index, slug in enumerate(C05_DISABLED_SLUGS, start=10):
            c05_ids[slug] = connection.execute(
                sa.insert(sources)
                .values(
                    **_source_values(
                        index,
                        False,
                        slug=slug,
                        name=f"C05 disabled source {index}",
                    )
                )
                .returning(sources.c.id)
            ).scalar_one()
        run_id = connection.execute(
            sa.insert(runs)
            .values(
                public_id=uuid4(),
                source_id=enabled_id,
                trigger_type="manual",
                status="running",
                started_at=now,
                completed_at=None,
                records_fetched=0,
                records_created=0,
                records_updated=0,
                records_unchanged=0,
                records_skipped=0,
                records_failed=0,
                error_count=0,
                checkpoint_before=None,
                checkpoint_after=None,
                safe_summary="C07A migration fixture",
                created_at=now,
            )
            .returning(runs.c.id)
        ).scalar_one()
        connection.execute(
            sa.insert(checkpoints).values(
                source_id=enabled_id,
                scope_kind="source",
                partition_key=None,
                checkpoint_name="cursor",
                version=1,
                checkpoint_value="opaque-checkpoint",
                previous_checkpoint_id=None,
                advanced_by_run_id=run_id,
                persistence_committed_at=now,
                committed_at=now,
            )
        )
        connection.execute(
            sa.insert(watermarks).values(
                source_id=enabled_id,
                scope_kind="source",
                partition_key=None,
                watermark_name="published",
                version=1,
                watermark_value=now,
                previous_watermark_id=None,
                advanced_by_run_id=run_id,
                persistence_committed_at=now,
                committed_at=now,
            )
        )
        connection.execute(
            sa.insert(rate_states).values(
                source_id=enabled_id,
                policy_key="c07a-policy",
                request_limit=100,
                remaining=75,
                window_seconds=3600,
                reset_at=now,
                backoff_until=None,
                last_observed_at=now,
                state="available",
                state_version=1,
                updated_by_run_id=None,
                updated_at=now,
            )
        )
        connection.execute(
            sa.insert(credentials).values(
                source_id=enabled_id,
                reference_name="c07a-reference",
                purpose="source_auth",
                external_reference_id="bounded-reference",
                configuration_state="configured",
                owner_ref="security-team",
                last_rotated_at=now,
                expires_at=now,
                created_at=now,
                updated_at=now,
            )
        )

    source_columns = list(sources.c)
    with engine.connect() as connection:
        source_before = _rows(connection, sources, source_columns)
        checkpoint_before = _rows(connection, checkpoints)
        watermark_before = _rows(connection, watermarks)
        rate_before = _rows(connection, rate_states)
        credential_before = _rows(connection, credentials)

    command.upgrade(config, C07A_REVISION)
    upgraded_sources = _reflect(engine, "intelligence_sources")[0]
    inspector = sa.inspect(engine)
    columns = {
        item["name"]: item
        for item in inspector.get_columns("intelligence_sources")
    }
    checks = {
        item["name"]: item["sqltext"]
        for item in inspector.get_check_constraints("intelligence_sources")
    }
    assert columns["operator_state"]["nullable"] is False
    assert {
        "ck_intelligence_sources_operator_state",
        "ck_intelligence_sources_operator_state_enabled_consistency",
    } <= set(checks)

    with engine.connect() as connection:
        backfilled = dict(
            connection.execute(
                sa.select(upgraded_sources.c.id, upgraded_sources.c.operator_state)
                .where(upgraded_sources.c.id.in_([enabled_id, disabled_id]))
            ).all()
        )
        assert backfilled == {enabled_id: "enabled", disabled_id: "disabled"}
        assert dict(
            connection.execute(
                sa.select(upgraded_sources.c.slug, upgraded_sources.c.operator_state)
                .where(upgraded_sources.c.id.in_(c05_ids.values()))
            ).all()
        ) == {slug: "disabled" for slug in C05_DISABLED_SLUGS}
        assert set(
            connection.execute(
                sa.select(upgraded_sources.c.is_enabled)
                .where(upgraded_sources.c.id.in_(c05_ids.values()))
            ).scalars()
        ) == {False}
        assert _rows(
            connection,
            upgraded_sources,
            [upgraded_sources.c[column.name] for column in source_columns],
        ) == source_before
        assert _rows(connection, checkpoints) == checkpoint_before
        assert _rows(connection, watermarks) == watermark_before
        assert _rows(connection, rate_states) == rate_before
        assert _rows(connection, credentials) == credential_before

    _expect_rejected(
        engine,
        upgraded_sources,
        _source_values(100, True, operator_state=None),
    )
    for index, is_enabled, operator_state in (
        (101, False, "unknown"),
        (102, False, "enabled"),
        (103, True, "paused"),
        (104, True, "disabled"),
    ):
        _expect_rejected(
            engine,
            upgraded_sources,
            _source_values(
                index,
                is_enabled,
                operator_state=operator_state,
            ),
        )

    with Session(engine) as session:
        durable = [
            IntelligenceSource(
                **_source_values(200, True), operator_state="enabled"
            ),
            IntelligenceSource(
                **_source_values(201, False), operator_state="paused"
            ),
            IntelligenceSource(
                **_source_values(202, False), operator_state="disabled"
            ),
            IntelligenceSource(**_source_values(203, True)),
            IntelligenceSource(**_source_values(204, False)),
        ]
        partial = IntelligenceSource(checkpoint_value=None)
        partial.name = "C07A partial source"
        partial.slug = "c07a-partial-source"
        partial.source_type = "api"
        partial.base_url = None
        partial.rate_limit_notes = None
        partial.last_successful_fetch_at = None
        durable.append(partial)
        inconsistent = IntelligenceSource(
            **_source_values(205, False), operator_state="enabled"
        )
        assert inconsistent.is_enabled is False
        assert inconsistent.operator_state == "enabled"
        session.add_all(durable)
        session.commit()
        durable_ids = [source.id for source in durable]

    with Session(engine) as session:
        persisted = {
            source.id: (source.operator_state, source.is_enabled)
            for source in session.scalars(
                sa.select(IntelligenceSource).where(
                    IntelligenceSource.id.in_(durable_ids)
                )
            )
        }
        assert [persisted[source_id] for source_id in durable_ids] == [
            ("enabled", True),
            ("paused", False),
            ("disabled", False),
            ("enabled", True),
            ("disabled", False),
            ("enabled", True),
        ]

    with pytest.raises(IntegrityError):
        with Session(engine) as session:
            session.add(inconsistent)
            session.commit()

    with engine.connect() as connection:
        preserved_projection = dict(
            connection.execute(
                sa.select(upgraded_sources.c.id, upgraded_sources.c.is_enabled)
                .where(upgraded_sources.c.id.in_(durable_ids))
            ).all()
        )

    command.downgrade(config, C06_REVISION)
    downgraded_sources = _reflect(engine, "intelligence_sources")[0]
    assert "operator_state" not in downgraded_sources.c
    with engine.connect() as connection:
        assert dict(
            connection.execute(
                sa.select(downgraded_sources.c.id, downgraded_sources.c.is_enabled)
                .where(downgraded_sources.c.id.in_(durable_ids))
            ).all()
        ) == preserved_projection
        assert _rows(
            connection,
            downgraded_sources,
            [downgraded_sources.c[column.name] for column in source_columns],
        )[: len(source_before)] == source_before
        (
            downgraded_checkpoints,
            downgraded_watermarks,
            downgraded_rates,
            downgraded_credentials,
        ) = _reflect(
            engine,
            "source_checkpoints",
            "source_watermarks",
            "source_rate_limit_states",
            "source_credential_references",
        )
        assert _rows(connection, downgraded_checkpoints) == checkpoint_before
        assert _rows(connection, downgraded_watermarks) == watermark_before
        assert _rows(connection, downgraded_rates) == rate_before
        assert _rows(connection, downgraded_credentials) == credential_before

    command.upgrade(config, C07A_REVISION)
    reupgraded_sources = _reflect(engine, "intelligence_sources")[0]
    assert "operator_state" in reupgraded_sources.c
    with engine.connect() as connection:
        assert connection.scalar(
            sa.select(sa.func.count())
            .select_from(reupgraded_sources)
            .where(reupgraded_sources.c.operator_state.is_(None))
        ) == 0
        assert connection.scalar(
            sa.text("SELECT version_num FROM alembic_version")
        ) == C07A_REVISION
