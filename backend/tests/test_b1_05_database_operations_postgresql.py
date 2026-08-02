from __future__ import annotations

from contextlib import contextmanager
from itertools import combinations
import os
from pathlib import Path
import time

from alembic import command
from alembic.config import Config
import psycopg
from psycopg import sql
import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import DBAPIError, TimeoutError as SQLAlchemyTimeoutError

from app.core.config import get_settings


DATABASE_ENV = "B105_POSTGRESQL_TEST_DATABASE_URL"
BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
GRANTS_SQL = REPO_ROOT / "database" / "init" / "11-apply-database-grants.sql"
PROVISION_SCRIPT = (
    REPO_ROOT / "database" / "init" / "10-provision-database-roles.sh"
)
HEAD = "d7a9e51c2f40"
PREVIOUS_HEAD = "b103a71d2e4f"

APP_ROLE = "b105_app_test"
MIGRATION_ROLE = "b105_migration_test"
READONLY_ROLE = "b105_readonly_test"
BACKUP_ROLE = "b105_backup_test"
RETENTION_ROLE = "b105_retention_test"
APP_PASSWORD = "synthetic-b105-app-password"
MIGRATION_PASSWORD = "synthetic-b105-migration-password"
MANAGED_ROLE_SETTINGS = (
    "b105.bootstrap_role",
    "b105.app_login",
    "b105.migration_login",
    "b105.readonly_role",
    "b105.backup_role",
    "b105.retention_role",
)


def _database_url() -> URL:
    raw = os.getenv(DATABASE_ENV)
    if not raw:
        pytest.skip(f"{DATABASE_ENV} is not configured")
    try:
        url = make_url(raw)
    except Exception:
        pytest.fail("Dedicated B1-05 database configuration is invalid")
    if url.drivername not in {"postgresql", "postgresql+psycopg"}:
        pytest.fail("Dedicated B1-05 database must use PostgreSQL")
    if url.host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("Dedicated B1-05 database must be loopback-only")
    if not url.database or not url.database.startswith("b105_test_"):
        pytest.fail("Dedicated B1-05 database name must use the disposable prefix")
    return url.set(drivername="postgresql+psycopg")


def _alembic_config(url: URL) -> Config:
    os.environ["DATABASE_URL"] = url.render_as_string(hide_password=False)
    get_settings.cache_clear()
    return Config(str(ALEMBIC_INI))


def _psycopg_conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _reset_schema(url: URL) -> None:
    engine = sa.create_engine(url, poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")
    finally:
        engine.dispose()


def _drop_test_roles(url: URL) -> None:
    with psycopg.connect(_psycopg_conninfo(url), autocommit=True) as conn:
        for role in (APP_ROLE, MIGRATION_ROLE, READONLY_ROLE, BACKUP_ROLE, RETENTION_ROLE):
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                conn.execute(sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(role)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def _create_test_roles(url: URL) -> None:
    with psycopg.connect(_psycopg_conninfo(url), autocommit=True) as conn:
        conn.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            ).format(sql.Identifier(APP_ROLE), sql.Literal(APP_PASSWORD))
        )
        conn.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            ).format(sql.Identifier(MIGRATION_ROLE), sql.Literal(MIGRATION_PASSWORD))
        )
        for role in (READONLY_ROLE, BACKUP_ROLE, RETENTION_ROLE):
            conn.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS"
                ).format(sql.Identifier(role))
            )


def _grant_body() -> str:
    lines = GRANTS_SQL.read_text(encoding="utf-8").splitlines()
    retained: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("\\set") or stripped in {"BEGIN;", "COMMIT;"}:
            continue
        if stripped.startswith("SELECT set_config('b105."):
            continue
        retained.append(line)
    return "\n".join(retained)


def _apply_grants(url: URL) -> None:
    settings = {
        "b105.bootstrap_role": url.username,
        "b105.app_schema": "public",
        "b105.app_login": APP_ROLE,
        "b105.migration_login": MIGRATION_ROLE,
        "b105.readonly_role": READONLY_ROLE,
        "b105.backup_role": BACKUP_ROLE,
        "b105.retention_role": RETENTION_ROLE,
    }
    with psycopg.connect(_psycopg_conninfo(url)) as conn:
        for name, value in settings.items():
            conn.execute("SELECT set_config(%s, %s, false)", (name, value))
        conn.execute(_grant_body(), prepare=False)


@pytest.mark.parametrize(
    ("first_setting", "second_setting"),
    list(combinations(MANAGED_ROLE_SETTINGS, 2)),
)
def test_every_pairwise_managed_role_name_collision_fails_in_postgresql(
    pg_roles,
    first_setting: str,
    second_setting: str,
) -> None:
    admin_url, _, _ = pg_roles
    settings = {
        "b105.bootstrap_role": admin_url.username,
        "b105.app_schema": "public",
        "b105.app_login": APP_ROLE,
        "b105.migration_login": MIGRATION_ROLE,
        "b105.readonly_role": READONLY_ROLE,
        "b105.backup_role": BACKUP_ROLE,
        "b105.retention_role": RETENTION_ROLE,
    }
    settings[second_setting] = settings[first_setting]

    with psycopg.connect(_psycopg_conninfo(admin_url)) as conn:
        for name, value in settings.items():
            conn.execute("SELECT set_config(%s, %s, false)", (name, value))
        with pytest.raises(
            psycopg.Error,
            match="managed database role identifiers must be pairwise distinct",
        ):
            conn.execute(_grant_body(), prepare=False)


def _membership_guard_body() -> str:
    shell = PROVISION_SCRIPT.read_text(encoding="utf-8")
    body = shell.split("DO $b105$", 1)[1].split("$b105$;", 1)[0]
    return f"DO $b105${body}$b105$;"


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


@pytest.fixture(scope="module")
def pg_roles():
    admin_url = _database_url()
    app_url = admin_url.set(username=APP_ROLE, password=APP_PASSWORD)
    migration_url = admin_url.set(
        username=MIGRATION_ROLE,
        password=MIGRATION_PASSWORD,
    )

    _reset_schema(admin_url)
    _drop_test_roles(admin_url)
    _create_test_roles(admin_url)

    # Fresh database path: grants/default privileges first, then Alembic as the
    # migration identity. Completion proves fresh provisioning is usable.
    _apply_grants(admin_url)
    with _database_url_environment(migration_url):
        command.upgrade(_alembic_config(migration_url), HEAD)
    _apply_grants(admin_url)
    fresh_engine = sa.create_engine(admin_url, poolclass=sa.pool.NullPool)
    try:
        with fresh_engine.connect() as connection:
            assert connection.scalar(
                sa.text(
                    "SELECT has_table_privilege(:role, "
                    "'public.intelligence_sources', 'UPDATE')"
                ),
                {"role": APP_ROLE},
            ) is True
            assert connection.scalar(
                sa.text(
                    "SELECT has_table_privilege(:role, "
                    "'public.ingestion_run_events', 'UPDATE')"
                ),
                {"role": APP_ROLE},
            ) is False
    finally:
        fresh_engine.dispose()

    # Existing B1-04 path: reconstruct the previous head as bootstrap owner,
    # transfer ownership/grants twice, then apply B1-05 as migration identity.
    _reset_schema(admin_url)
    with _database_url_environment(admin_url):
        command.upgrade(_alembic_config(admin_url), PREVIOUS_HEAD)
    _apply_grants(admin_url)
    _apply_grants(admin_url)
    with _database_url_environment(migration_url):
        command.upgrade(_alembic_config(migration_url), HEAD)

    yield admin_url, app_url, migration_url

    _reset_schema(admin_url)
    _drop_test_roles(admin_url)


def _expect_denied(url: URL, statement: str) -> None:
    engine = sa.create_engine(url, poolclass=sa.pool.NullPool)
    try:
        with pytest.raises(DBAPIError):
            with engine.begin() as connection:
                connection.exec_driver_sql(statement)
    finally:
        engine.dispose()


def test_fresh_existing_and_idempotent_provisioning_reach_one_head(pg_roles) -> None:
    admin_url, _, _ = pg_roles
    engine = sa.create_engine(admin_url, poolclass=sa.pool.NullPool)
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == HEAD
            owners = connection.execute(
                sa.text(
                    "SELECT DISTINCT tableowner FROM pg_tables "
                    "WHERE schemaname = 'public'"
                )
            ).scalars().all()
            assert owners == [MIGRATION_ROLE]
    finally:
        engine.dispose()


def test_role_attributes_are_exact_and_non_administrative(pg_roles) -> None:
    admin_url, _, _ = pg_roles
    engine = sa.create_engine(admin_url, poolclass=sa.pool.NullPool)
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                sa.text(
                    "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, "
                    "rolcreaterole, rolinherit, rolreplication, rolbypassrls "
                    "FROM pg_roles WHERE rolname = ANY(:roles) ORDER BY rolname"
                ),
                {"roles": [APP_ROLE, MIGRATION_ROLE, READONLY_ROLE, BACKUP_ROLE, RETENTION_ROLE]},
            ).mappings().all()
    finally:
        engine.dispose()

    assert len(rows) == 5
    for row in rows:
        assert row["rolcanlogin"] is (row["rolname"] in {APP_ROLE, MIGRATION_ROLE})
        assert row["rolsuper"] is False
        assert row["rolcreatedb"] is False
        assert row["rolcreaterole"] is False
        assert row["rolinherit"] is True
        assert row["rolreplication"] is False
        assert row["rolbypassrls"] is False


@pytest.mark.parametrize(
    "managed_role",
    [APP_ROLE, MIGRATION_ROLE, READONLY_ROLE, BACKUP_ROLE, RETENTION_ROLE],
)
@pytest.mark.parametrize("managed_role_is_member", [True, False])
def test_managed_role_membership_collisions_fail_closed(
    pg_roles,
    managed_role: str,
    managed_role_is_member: bool,
) -> None:
    admin_url, _, _ = pg_roles
    unrelated_role = "b105_unrelated_membership_test"
    with psycopg.connect(_psycopg_conninfo(admin_url), autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(unrelated_role))
        )
        if managed_role_is_member:
            conn.execute(
                sql.SQL("GRANT {} TO {}").format(
                    sql.Identifier(unrelated_role), sql.Identifier(managed_role)
                )
            )
        else:
            conn.execute(
                sql.SQL("GRANT {} TO {}").format(
                    sql.Identifier(managed_role), sql.Identifier(unrelated_role)
                )
            )
        try:
            settings = {
                "b105.bootstrap_role": admin_url.username,
                "b105.app_login": APP_ROLE,
                "b105.migration_login": MIGRATION_ROLE,
                "b105.readonly_role": READONLY_ROLE,
                "b105.backup_role": BACKUP_ROLE,
                "b105.retention_role": RETENTION_ROLE,
            }
            with psycopg.connect(_psycopg_conninfo(admin_url)) as policy_conn:
                for name, value in settings.items():
                    policy_conn.execute("SELECT set_config(%s, %s, false)", (name, value))
                with pytest.raises(psycopg.Error) as exc_info:
                    policy_conn.execute(_membership_guard_body(), prepare=False)
            message = str(exc_info.value)
            assert managed_role in message
            assert unrelated_role not in message
        finally:
            conn.execute(
                sql.SQL("REVOKE {} FROM {}").format(
                    sql.Identifier(
                        unrelated_role if managed_role_is_member else managed_role
                    ),
                    sql.Identifier(
                        managed_role if managed_role_is_member else unrelated_role
                    ),
                )
            )
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(unrelated_role)))


def test_application_role_can_use_runtime_dml_but_not_privileged_operations(pg_roles) -> None:
    admin_url, app_url, _ = pg_roles
    engine = sa.create_engine(app_url, poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            source_id = connection.scalar(
                sa.text(
                    "INSERT INTO intelligence_sources "
                    "(public_id, name, slug, source_type, is_enabled, created_at, updated_at) "
                    "VALUES (gen_random_uuid(), 'B1-05 role test', 'b1-05-role-test', "
                    "'api', true, now(), now()) RETURNING id"
                )
            )
            assert source_id is not None
            connection.execute(
                sa.text("UPDATE intelligence_sources SET is_enabled = false WHERE id = :id"),
                {"id": source_id},
            )
            assert connection.scalar(
                sa.text("SELECT count(*) FROM intelligence_sources WHERE id = :id"),
                {"id": source_id},
            ) == 1
            connection.rollback()
    finally:
        engine.dispose()

    for statement in (
        "CREATE TABLE b105_forbidden(id integer)",
        "CREATE SCHEMA b105_forbidden",
        "CREATE ROLE b105_forbidden",
        "TRUNCATE intelligence_sources",
        "DELETE FROM ingestion_runs",
        "UPDATE ingestion_run_events SET event_type = event_type",
        "UPDATE source_checkpoints SET version = version",
        "UPDATE source_watermarks SET version = version",
        "UPDATE audit_events SET outcome = outcome",
        "UPDATE ingestion_errors SET retry_count = retry_count",
    ):
        _expect_denied(app_url, statement)

    # PostgreSQL reports a warning rather than an error when a non-owner issues
    # a GRANT without grant option. Prove the attempted escalation has no effect.
    engine = sa.create_engine(app_url, poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT SELECT ON intelligence_sources TO {RETENTION_ROLE}"
            )
    finally:
        engine.dispose()
    engine = sa.create_engine(admin_url, poolclass=sa.pool.NullPool)
    try:
        with engine.connect() as connection:
            assert connection.scalar(
                sa.text(
                    "SELECT has_table_privilege(:role, "
                    "'public.intelligence_sources', 'SELECT')"
                ),
                {"role": RETENTION_ROLE},
            ) is False
    finally:
        engine.dispose()


def test_readonly_backup_and_retention_roles_are_non_mutating(pg_roles) -> None:
    admin_url, _, _ = pg_roles
    with psycopg.connect(_psycopg_conninfo(admin_url)) as conn:
        for role in (READONLY_ROLE, BACKUP_ROLE):
            conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
            assert conn.execute("SELECT count(*) FROM intelligence_sources").fetchone()
            with pytest.raises(psycopg.Error):
                conn.execute(
                    "INSERT INTO intelligence_sources "
                    "(public_id, name, slug, source_type, is_enabled, created_at, updated_at) "
                    "VALUES (gen_random_uuid(), 'denied', 'denied', 'api', true, now(), now())"
                )
            conn.rollback()

        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(RETENTION_ROLE)))
        assert conn.execute("SELECT count(*) FROM ingestion_runs").fetchone()
        with pytest.raises(psycopg.Error):
            conn.execute("SELECT count(*) FROM intelligence_sources")
        conn.rollback()
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(RETENTION_ROLE)))
        with pytest.raises(psycopg.Error):
            conn.execute("DELETE FROM ingestion_runs")
        conn.rollback()


def test_public_and_managed_roles_cannot_access_unknown_future_objects(pg_roles) -> None:
    admin_url, _, migration_url = pg_roles
    with psycopg.connect(_psycopg_conninfo(admin_url)) as conn:
        assert conn.execute(
            "SELECT has_schema_privilege('public', 'public', 'CREATE')"
        ).fetchone()[0] is False

    engine = sa.create_engine(migration_url, poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE b105_future_default_test(id bigint)")
            connection.exec_driver_sql("CREATE SEQUENCE b105_future_default_test_seq")

        _apply_grants(admin_url)

        admin_engine = sa.create_engine(admin_url, poolclass=sa.pool.NullPool)
        try:
            with admin_engine.connect() as connection:
                table_privileges = connection.execute(
                    sa.text(
                        "SELECT role_name, privilege_name, "
                        "has_table_privilege(role_name, "
                        "'public.b105_future_default_test', privilege_name) "
                        "FROM unnest(CAST(:roles AS text[])) AS role_name "
                        "CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', "
                        "'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) "
                        "AS privilege_name"
                    ),
                    {
                        "roles": [
                            "public",
                            APP_ROLE,
                            READONLY_ROLE,
                            BACKUP_ROLE,
                            RETENTION_ROLE,
                        ]
                    },
                ).all()
                sequence_privileges = connection.execute(
                    sa.text(
                        "SELECT role_name, privilege_name, "
                        "has_sequence_privilege(role_name, "
                        "'public.b105_future_default_test_seq', privilege_name) "
                        "FROM unnest(CAST(:roles AS text[])) AS role_name "
                        "CROSS JOIN unnest(ARRAY['SELECT', 'USAGE', 'UPDATE']) "
                        "AS privilege_name"
                    ),
                    {
                        "roles": [
                            "public",
                            APP_ROLE,
                            READONLY_ROLE,
                            BACKUP_ROLE,
                            RETENTION_ROLE,
                        ]
                    },
                ).all()
        finally:
            admin_engine.dispose()

        assert table_privileges
        assert sequence_privileges
        assert all(has_privilege is False for _, _, has_privilege in table_privileges)
        assert all(has_privilege is False for _, _, has_privilege in sequence_privileges)
    finally:
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql("DROP TABLE IF EXISTS b105_future_default_test")
                connection.exec_driver_sql(
                    "DROP SEQUENCE IF EXISTS b105_future_default_test_seq"
                )
        finally:
            engine.dispose()


def test_migration_role_can_downgrade_and_reupgrade_b1_05(pg_roles) -> None:
    _, _, migration_url = pg_roles
    with _database_url_environment(migration_url):
        config = _alembic_config(migration_url)
        command.downgrade(config, PREVIOUS_HEAD)
        command.upgrade(config, HEAD)

    engine = sa.create_engine(migration_url, poolclass=sa.pool.NullPool)
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == HEAD
    finally:
        engine.dispose()


def test_pool_exhaustion_fails_within_timeout_and_recovers_without_leaks(pg_roles) -> None:
    admin_url, _, _ = pg_roles
    engine = sa.create_engine(
        admin_url,
        pool_size=1,
        max_overflow=1,
        pool_timeout=1,
        pool_pre_ping=True,
    )
    first = second = recovered = None
    try:
        first = engine.connect()
        second = engine.connect()
        started = time.monotonic()
        with pytest.raises(SQLAlchemyTimeoutError):
            engine.connect()
        elapsed = time.monotonic() - started
        assert 0.8 <= elapsed < 2.5

        first.close()
        first = None
        recovered = engine.connect()
        assert recovered.scalar(sa.text("SELECT 1")) == 1
    finally:
        for connection in (recovered, second, first):
            if connection is not None:
                connection.close()
        assert engine.pool.checkedout() == 0
        engine.dispose()


def test_query_indexes_are_exact_and_no_speculative_indexes_exist(pg_roles) -> None:
    admin_url, _, _ = pg_roles
    engine = sa.create_engine(admin_url, poolclass=sa.pool.NullPool)
    try:
        with engine.connect() as connection:
            indexes = dict(
                connection.execute(
                    sa.text(
                        "SELECT indexname, indexdef FROM pg_indexes "
                        "WHERE schemaname = 'public' AND tablename = 'ingestion_runs'"
                    )
                ).all()
            )
    finally:
        engine.dispose()

    assert "ix_ingestion_runs_source_id_started_at_id_desc" in indexes
    assert "(source_id, started_at DESC, id DESC)" in indexes[
        "ix_ingestion_runs_source_id_started_at_id_desc"
    ]
    assert "ix_ingestion_runs_started_at_id_desc" in indexes
    assert "(started_at DESC, id DESC)" in indexes[
        "ix_ingestion_runs_started_at_id_desc"
    ]
    assert "ix_ingestion_runs_source_id_started_at_desc" not in indexes
    assert not any("checkpoint" in name or "watermark" in name for name in indexes)


def _plan_index_names(value) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        index_name = value.get("Index Name")
        if isinstance(index_name, str):
            names.add(index_name)
        for nested in value.values():
            names.update(_plan_index_names(nested))
    elif isinstance(value, list):
        for nested in value:
            names.update(_plan_index_names(nested))
    return names


def _plan_node_types(value) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        node_type = value.get("Node Type")
        if isinstance(node_type, str):
            names.add(node_type)
        for nested in value.values():
            names.update(_plan_node_types(nested))
    elif isinstance(value, list):
        for nested in value:
            names.update(_plan_node_types(nested))
    return names


def _explain_json(connection, query: str):
    return connection.exec_driver_sql(
        f"EXPLAIN (FORMAT JSON, COSTS TRUE) {query}"
    ).scalar_one()


def _insert_representative_plan_data(connection) -> int:
    connection.exec_driver_sql(
        "INSERT INTO intelligence_sources "
        "(public_id, name, slug, source_type, is_enabled, created_at, updated_at) "
        "SELECT gen_random_uuid(), 'B1-05 plan source ' || source_number, "
        "'b105-plan-source-' || source_number, 'api', true, now(), now() "
        "FROM generate_series(1, 20) AS source_number"
    )
    source_id = connection.exec_driver_sql(
        "SELECT id FROM intelligence_sources "
        "WHERE slug = 'b105-plan-source-1'"
    ).scalar_one()
    connection.exec_driver_sql(
        "WITH plan_sources AS ("
        "  SELECT id FROM intelligence_sources "
        "  WHERE slug LIKE 'b105-plan-source-%%'"
        ") "
        "INSERT INTO ingestion_runs "
        "(public_id, source_id, trigger_type, status, started_at, completed_at, "
        "records_fetched, records_created, records_updated, records_unchanged, "
        "records_skipped, records_failed, error_count, created_at) "
        "SELECT gen_random_uuid(), plan_sources.id, 'manual', 'succeeded', "
        "TIMESTAMPTZ '2026-01-01 00:00:00+00' + "
        "((run_number / 2) * INTERVAL '1 second'), "
        "TIMESTAMPTZ '2026-01-01 00:00:00+00' + "
        "((run_number / 2) * INTERVAL '1 second'), "
        "0, 0, 0, 0, 0, 0, 0, "
        "TIMESTAMPTZ '2026-01-01 00:00:00+00' + "
        "((run_number / 2) * INTERVAL '1 second') "
        "FROM plan_sources CROSS JOIN generate_series(1, 5000) AS run_number"
    )
    connection.exec_driver_sql(
        "INSERT INTO ingestion_cycles "
        "(public_id, idempotency_key, trigger_type, status, scheduled_for, "
        "started_at, completed_at, sources_expected, sources_started, "
        "sources_completed, sources_successful, sources_non_successful, created_at) "
        "SELECT gen_random_uuid(), 'b105-plan-cycle-' || cycle_number, 'manual', "
        "CASE WHEN cycle_number %% 5 = 0 THEN 'running' ELSE 'success' END, NULL, "
        "TIMESTAMPTZ '2026-01-01 00:00:00+00' + "
        "(cycle_number * INTERVAL '1 second'), "
        "CASE WHEN cycle_number %% 5 = 0 THEN NULL ELSE "
        "TIMESTAMPTZ '2026-01-01 00:00:00+00' + "
        "(cycle_number * INTERVAL '1 second') END, "
        "0, 0, 0, 0, 0, "
        "TIMESTAMPTZ '2026-01-01 00:00:00+00' + "
        "(cycle_number * INTERVAL '1 second') "
        "FROM generate_series(1, 25000) AS cycle_number"
    )
    connection.exec_driver_sql(
        "WITH source_runs AS ("
        "  SELECT id, row_number() OVER (ORDER BY id) AS version "
        "  FROM ingestion_runs WHERE source_id = " + str(source_id) + " LIMIT 5000"
        ") "
        "INSERT INTO source_checkpoints "
        "(source_id, scope_kind, partition_key, checkpoint_name, version, "
        "checkpoint_value, previous_checkpoint_id, advanced_by_run_id, "
        "persistence_committed_at, committed_at) "
        "SELECT " + str(source_id) + ", 'source', NULL, 'cursor', version, "
        "'cursor-' || version, NULL, id, now(), now() FROM source_runs"
    )
    connection.exec_driver_sql(
        "WITH source_runs AS ("
        "  SELECT id, row_number() OVER (ORDER BY id) AS version "
        "  FROM ingestion_runs WHERE source_id = " + str(source_id) + " LIMIT 5000"
        ") "
        "INSERT INTO source_watermarks "
        "(source_id, scope_kind, partition_key, watermark_name, version, "
        "watermark_value, previous_watermark_id, advanced_by_run_id, "
        "persistence_committed_at, committed_at) "
        "SELECT " + str(source_id) + ", 'source', NULL, 'published', version, "
        "TIMESTAMPTZ '2026-01-01 00:00:00+00' + "
        "(version * INTERVAL '1 second'), NULL, id, now(), now() FROM source_runs"
    )
    connection.exec_driver_sql(
        "INSERT INTO audit_events "
        "(public_id, idempotency_key, actor_type, actor_ref, action, target_type, "
        "target_ref, outcome, occurred_at, created_at) "
        "SELECT gen_random_uuid(), 'b105-plan-audit-' || audit_number, 'system', "
        "'b105-plan', 'database.plan', 'run', 'run-' || audit_number, 'success', "
        "TIMESTAMPTZ '2026-01-01 00:00:00+00' + "
        "(audit_number * INTERVAL '1 second'), "
        "TIMESTAMPTZ '2026-01-01 00:00:00+00' + "
        "(audit_number * INTERVAL '1 second') "
        "FROM generate_series(1, 40000) AS audit_number"
    )
    for table_name in (
        "ingestion_runs",
        "ingestion_cycles",
        "source_checkpoints",
        "source_watermarks",
        "audit_events",
    ):
        connection.exec_driver_sql(f"ANALYZE {table_name}")
    return source_id


def test_required_queries_use_natural_representative_postgresql_plans(pg_roles) -> None:
    admin_url, _, _ = pg_roles
    engine = sa.create_engine(admin_url, poolclass=sa.pool.NullPool)
    connection = engine.connect()
    transaction = connection.begin()
    try:
        source_id = _insert_representative_plan_data(connection)
        source_query = (
            "SELECT id FROM ingestion_runs WHERE source_id = "
            f"{source_id} ORDER BY started_at DESC, id DESC LIMIT 1"
        )
        global_query = (
            "SELECT id FROM ingestion_runs "
            "ORDER BY started_at DESC, id DESC LIMIT 1"
        )
        candidate_indexes = {
            "source_latest": "ix_ingestion_runs_source_id_started_at_id_desc",
            "global_latest": "ix_ingestion_runs_started_at_id_desc",
        }
        for index_name in candidate_indexes.values():
            connection.exec_driver_sql(f"DROP INDEX {index_name}")
        connection.exec_driver_sql("ANALYZE ingestion_runs")

        before_plans = {
            "source_latest": _explain_json(connection, source_query),
            "global_latest": _explain_json(connection, global_query),
        }
        for label, plan in before_plans.items():
            assert candidate_indexes[label] not in _plan_index_names(plan), label
            assert "Sort" in _plan_node_types(plan), label
        assert "Bitmap Heap Scan" in _plan_node_types(
            before_plans["source_latest"]
        )
        assert any(
            node_type.endswith("Seq Scan")
            for node_type in _plan_node_types(before_plans["global_latest"])
        )

        connection.exec_driver_sql(
            "CREATE INDEX ix_ingestion_runs_source_id_started_at_id_desc "
            "ON ingestion_runs (source_id, started_at DESC, id DESC)"
        )
        connection.exec_driver_sql(
            "CREATE INDEX ix_ingestion_runs_started_at_id_desc "
            "ON ingestion_runs (started_at DESC, id DESC)"
        )
        connection.exec_driver_sql("ANALYZE ingestion_runs")

        after_plans = {
            "source_latest": _explain_json(connection, source_query),
            "global_latest": _explain_json(connection, global_query),
        }
        for label, plan in after_plans.items():
            node_types = _plan_node_types(plan)
            assert candidate_indexes[label] in _plan_index_names(plan), label
            assert node_types & {"Index Scan", "Index Only Scan"}, label
            assert not any(node_type.endswith("Seq Scan") for node_type in node_types), label
            assert "Bitmap Heap Scan" not in node_types, label
            assert "Sort" not in node_types, label
            assert "Incremental Sort" not in node_types, label

        existing_statements = {
            "cycle_history": (
                "SELECT id FROM ingestion_cycles WHERE status = 'running' "
                "ORDER BY started_at DESC, id DESC LIMIT 50",
                "ix_ingestion_cycles_status_started_at_id_desc",
            ),
            "current_checkpoint": (
                "SELECT id FROM source_checkpoints "
                f"WHERE source_id = {source_id} AND scope_kind = 'source' "
                "AND partition_key IS NULL AND checkpoint_name = 'cursor' "
                "ORDER BY version DESC LIMIT 1 FOR UPDATE",
                "uq_source_checkpoints_source_identity_version",
            ),
            "current_watermark": (
                "SELECT id FROM source_watermarks "
                f"WHERE source_id = {source_id} AND scope_kind = 'source' "
                "AND partition_key IS NULL AND watermark_name = 'published' "
                "ORDER BY version DESC LIMIT 1 FOR UPDATE",
                "uq_source_watermarks_source_identity_version",
            ),
            "audit_history": (
                "SELECT id FROM audit_events "
                "ORDER BY occurred_at DESC, id DESC LIMIT 100",
                "ix_audit_events_occurred_at_id_desc",
            ),
        }
        for label, (query, expected_index) in existing_statements.items():
            plan = _explain_json(connection, query)
            assert expected_index in _plan_index_names(plan), label
    finally:
        transaction.rollback()
        connection.close()
        engine.dispose()
