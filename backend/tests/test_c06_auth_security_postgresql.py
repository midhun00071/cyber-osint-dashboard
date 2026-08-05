"""Disposable PostgreSQL acceptance for the C06 authentication boundary."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
from ipaddress import ip_address
import os
from pathlib import Path
import re
from uuid import uuid4

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
import psycopg
import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.models import AuthSession
from app.security.sessions import SessionSecurityService
from tests.c06_auth_test_support import settings


DATABASE_ENV = "C06_TEST_DATABASE_URL"
SKIP_REASON = (
    "C06_TEST_DATABASE_URL is not configured for a dedicated disposable "
    "loopback-only PostgreSQL database."
)
BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = BACKEND_ROOT.parent
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"
GRANTS_SQL = REPOSITORY_ROOT / "database" / "init" / "11-apply-database-grants.sql"
VERSIONS_DIR = BACKEND_ROOT / "alembic" / "versions"
HEAD = "f4a1c2d3e5b6"
PREDECESSOR = "e91f4c2a7b60"
AUTH_TABLES = (
    "auth_users",
    "auth_identities",
    "auth_local_credentials",
    "auth_user_roles",
    "auth_sessions",
    "auth_login_throttles",
)
MUTABLE_AUTH_TABLES = AUTH_TABLES[:1] + AUTH_TABLES[2:]
NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$", flags=re.ASCII)
_PREDECESSOR_HASHES = {
    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
    for path in VERSIONS_DIR.glob("*.py")
    if not path.name.startswith(f"{HEAD}_")
}


def _validated_database_url(raw: str) -> URL:
    try:
        url = make_url(raw)
    except Exception:
        pytest.fail("C06 test database URL is invalid.")
    if url.drivername not in {
        "postgresql",
        "postgresql+psycopg",
        "postgresql+psycopg2",
    }:
        pytest.fail("C06 test database must use PostgreSQL.")
    if url.query:
        pytest.fail("C06 test database URL query parameters are forbidden.")
    host = url.host
    if host is None:
        pytest.fail("C06 test database host is required.")
    try:
        parsed_host = ip_address(host)
    except ValueError:
        pytest.fail("C06 test database host must be a literal loopback address.")
    if not parsed_host.is_loopback:
        pytest.fail("C06 test database must use a loopback host.")
    database_name = url.database or ""
    if not database_name.startswith("alpha_data_c06_test_"):
        pytest.fail(
            "C06 test database name must use the disposable "
            "'alpha_data_c06_test_' prefix."
        )
    normal_database_url = os.getenv("DATABASE_URL")
    if normal_database_url and raw == normal_database_url:
        pytest.fail("C06 test database must not reuse the application DATABASE_URL.")
    return url.set(drivername="postgresql+psycopg")


def _database_url() -> URL:
    raw = os.getenv(DATABASE_ENV)
    if not raw:
        pytest.skip(SKIP_REASON)
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


def _alembic_config(url: URL) -> Config:
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", url.render_as_string(hide_password=False))
    return config


def _migrate(url: URL, revision: str) -> None:
    with _database_url_environment(url):
        command.upgrade(_alembic_config(url), revision)


def _reset_schema(engine: sa.Engine) -> None:
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")


def _role_names() -> dict[str, str]:
    roles = {
        "app": os.getenv("C06_TEST_APP_ROLE", "alpha_data_c06_test_app"),
        "migration": os.getenv(
            "C06_TEST_MIGRATION_ROLE", "alpha_data_c06_test_migration"
        ),
        "readonly": os.getenv(
            "C06_TEST_READONLY_ROLE", "alpha_data_c06_test_readonly"
        ),
        "backup": os.getenv("C06_TEST_BACKUP_ROLE", "alpha_data_c06_test_backup"),
        "retention": os.getenv(
            "C06_TEST_RETENTION_ROLE", "alpha_data_c06_test_retention"
        ),
    }
    if any(_IDENTIFIER.fullmatch(value) is None for value in roles.values()):
        pytest.fail("C06 test database role identifiers are invalid.")
    if any(not value.startswith("alpha_data_c06_test_") for value in roles.values()):
        pytest.fail("C06 database roles must use dedicated disposable names.")
    if len(set(roles.values())) != len(roles):
        pytest.fail("C06 test database role identifiers must be pairwise distinct.")
    return roles


def _psycopg_conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _production_grant_body() -> str:
    retained: list[str] = []
    for line in GRANTS_SQL.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("\\set") or stripped in {"BEGIN;", "COMMIT;"}:
            continue
        if stripped.startswith("SELECT set_config('b105."):
            continue
        retained.append(line)
    body = "\n".join(retained)
    if "application_tables constant text[]" not in body:
        pytest.fail("Production database grant SQL body is incomplete.")
    return body


def _apply_production_grants(engine: sa.Engine, url: URL) -> None:
    roles = _role_names()
    bootstrap_role = url.username or ""
    if _IDENTIFIER.fullmatch(bootstrap_role) is None:
        pytest.fail("C06 test database bootstrap role is invalid.")
    if bootstrap_role in roles.values():
        pytest.fail("C06 bootstrap and managed database roles must be distinct.")
    with engine.connect() as connection:
        rows = connection.execute(
            sa.text(
                "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls FROM pg_roles WHERE rolname = ANY(:roles)"
            ),
            {"roles": list(roles.values())},
        ).mappings().all()
    if {row["rolname"] for row in rows} != set(roles.values()):
        pytest.fail("Dedicated C06 database roles are not provisioned.")
    for row in rows:
        expected_login = row["rolname"] in {roles["app"], roles["migration"]}
        if row["rolcanlogin"] is not expected_login or any(
            row[name]
            for name in (
                "rolsuper",
                "rolcreatedb",
                "rolcreaterole",
                "rolreplication",
                "rolbypassrls",
            )
        ):
            pytest.fail("Dedicated C06 database roles are provisioned unsafely.")
    configured = {
        "b105.app_schema": "public",
        "b105.bootstrap_role": bootstrap_role,
        "b105.app_login": roles["app"],
        "b105.migration_login": roles["migration"],
        "b105.readonly_role": roles["readonly"],
        "b105.backup_role": roles["backup"],
        "b105.retention_role": roles["retention"],
    }
    with psycopg.connect(_psycopg_conninfo(url)) as connection:
        for name, value in configured.items():
            connection.execute("SELECT set_config(%s, %s, false)", (name, value))
        connection.execute(_production_grant_body(), prepare=False)


@pytest.fixture(scope="module")
def pg_engine():
    url = _database_url()
    engine = sa.create_engine(url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT current_database()")) == url.database
        _reset_schema(engine)
        _migrate(url, PREDECESSOR)
        _migrate(url, HEAD)
        _apply_production_grants(engine, url)
        yield engine, url
    finally:
        try:
            _reset_schema(engine)
            _migrate(url, HEAD)
            _apply_production_grants(engine, url)
        finally:
            engine.dispose()


@pytest.mark.parametrize(
    "raw",
    [
        "sqlite:///:memory:",
        "postgresql://user:password@localhost/alpha_data_c06_test_guard",
        "postgresql://user:password@192.0.2.10/alpha_data_c06_test_guard",
        "postgresql://user:password@127.0.0.1/cyber_osint",
        "postgresql://user:password@127.0.0.1/alpha_data_c06_test_guard?host=192.0.2.10",
        "postgresql://user:password@127.0.0.1/",
    ],
)
def test_database_url_guard_rejects_every_unsafe_target(raw: str) -> None:
    with pytest.raises(pytest.fail.Exception):
        _validated_database_url(raw)


@pytest.mark.parametrize("host", ["127.0.0.1", "[::1]"])
def test_database_url_guard_accepts_literal_loopback_disposable_database(host: str) -> None:
    url = _validated_database_url(
        f"postgresql://synthetic-user:synthetic-password@{host}/alpha_data_c06_test_guard"
    )
    assert ip_address(url.host).is_loopback
    assert url.database == "alpha_data_c06_test_guard"
    assert url.drivername == "postgresql+psycopg"


def test_absent_database_uses_the_single_exact_skip_reason(monkeypatch) -> None:
    monkeypatch.delenv(DATABASE_ENV, raising=False)
    with pytest.raises(pytest.skip.Exception) as exc_info:
        _database_url()
    assert str(exc_info.value) == SKIP_REASON


def test_configured_grant_path_retains_the_actual_production_sql_body() -> None:
    body = _production_grant_body()
    assert GRANTS_SQL == REPOSITORY_ROOT / "database" / "init" / "11-apply-database-grants.sql"
    assert "ALTER TABLE %I.%I OWNER TO %I" in body
    assert "GRANT SELECT, INSERT ON TABLE %I.%I TO %I" in body
    assert "runtime_update_tables constant text[]" in body
    assert "retention_read_tables constant text[]" in body
    assert "\\set" not in body
    assert "SELECT set_config('b105." not in body


def test_migration_upgrade_downgrade_cycle_and_single_head(pg_engine) -> None:
    engine, url = pg_engine
    with _database_url_environment(url):
        command.downgrade(_alembic_config(url), PREDECESSOR)
    try:
        inspector = sa.inspect(engine)
        assert set(AUTH_TABLES).isdisjoint(inspector.get_table_names())
        _migrate(url, HEAD)
        assert set(AUTH_TABLES).issubset(sa.inspect(engine).get_table_names())
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == HEAD
        script = ScriptDirectory.from_config(_alembic_config(url))
        assert script.get_heads() == [HEAD]
        assert script.get_revision(HEAD).down_revision == PREDECESSOR
    finally:
        with engine.connect() as connection:
            current = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
        if current != HEAD:
            _migrate(url, HEAD)
        _apply_production_grants(engine, url)


def test_predecessor_migration_bytes_remain_unchanged(pg_engine) -> None:
    assert _PREDECESSOR_HASHES
    assert {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in VERSIONS_DIR.glob("*.py")
        if not path.name.startswith(f"{HEAD}_")
    } == _PREDECESSOR_HASHES


def test_exact_auth_schema_constraints_and_indexes(pg_engine) -> None:
    engine, _url = pg_engine
    inspector = sa.inspect(engine)
    assert set(AUTH_TABLES).issubset(inspector.get_table_names())
    expected_primary_keys = {
        "auth_users": "pk_auth_users",
        "auth_identities": "pk_auth_identities",
        "auth_local_credentials": "pk_auth_local_credentials",
        "auth_user_roles": "pk_auth_user_roles",
        "auth_sessions": "pk_auth_sessions",
        "auth_login_throttles": "pk_auth_login_throttles",
    }
    for table, name in expected_primary_keys.items():
        assert inspector.get_pk_constraint(table)["name"] == name
    expected_foreign_keys = {
        "fk_auth_identities_user_id_auth_users",
        "fk_auth_local_credentials_identity_id_auth_identities",
        "fk_auth_user_roles_user_id_auth_users",
        "fk_auth_user_roles_assigned_by_user_id_auth_users",
        "fk_auth_sessions_user_id_auth_users",
    }
    actual_foreign_keys = {
        key["name"]
        for table in AUTH_TABLES
        for key in inspector.get_foreign_keys(table)
    }
    assert expected_foreign_keys == actual_foreign_keys
    expected_unique = {
        "uq_auth_users_public_id",
        "uq_auth_identities_provider_subject",
        "uq_auth_identities_user_provider",
        "uq_auth_sessions_public_id",
        "uq_auth_sessions_token_hash",
        "uq_auth_login_throttles_login_key_hash",
    }
    actual_unique = {
        constraint["name"]
        for table in AUTH_TABLES
        for constraint in inspector.get_unique_constraints(table)
    }
    assert expected_unique == actual_unique
    checks = {
        constraint["name"]: constraint["sqltext"]
        for table in AUTH_TABLES
        for constraint in inspector.get_check_constraints(table)
    }
    for required in (
        "ck_auth_users_status_allowed",
        "ck_auth_users_session_version_positive",
        "ck_auth_local_credentials_argon2id_prefix",
        "ck_auth_user_roles_role_key_allowed",
        "ck_auth_sessions_token_hash_format",
        "ck_auth_sessions_csrf_token_hash_format",
        "ck_auth_sessions_expiry_order",
        "ck_auth_sessions_rotated_at_order",
        "ck_auth_sessions_revocation_shape",
        "ck_auth_sessions_revocation_reason_allowed",
        "ck_auth_login_throttles_failure_count_bounded",
        "ck_auth_login_throttles_blocked_until_order",
    ):
        assert required in checks
    index_names = {
        index["name"]
        for table in ("auth_sessions", "auth_login_throttles")
        for index in inspector.get_indexes(table)
    }
    assert {
        "ix_auth_sessions_user_active_expiry",
        "ix_auth_sessions_retention_expiry",
        "ix_auth_login_throttles_blocked_until",
        "ix_auth_login_throttles_window_updated",
    }.issubset(index_names)
    assert all(role in checks["ck_auth_user_roles_role_key_allowed"] for role in ("viewer", "analyst", "ingestion_operator", "administrator"))
    assert all(status in checks["ck_auth_users_status_allowed"] for status in ("active", "disabled"))


def _insert_user(connection, *, suffix: str = "base") -> tuple[int, int]:
    user_id = connection.execute(
        sa.text("INSERT INTO auth_users (public_id, display_name, status, account_expires_at, session_version, last_authenticated_at, disabled_at, created_at, updated_at) VALUES (:public_id, 'C06 Test User', 'active', NULL, 1, NULL, NULL, :now, :now) RETURNING id"),
        {"public_id": str(uuid4()), "now": NOW},
    ).scalar_one()
    identity_id = connection.execute(
        sa.text("INSERT INTO auth_identities (user_id, provider_key, subject_key, created_at) VALUES (:user_id, 'local', :subject, :now) RETURNING id"),
        {"user_id": user_id, "subject": f"user.{suffix}", "now": NOW},
    ).scalar_one()
    return user_id, identity_id


def test_database_rejects_duplicate_identity_role_and_credential_shapes(pg_engine) -> None:
    engine, _url = pg_engine
    cases = ("duplicate_subject", "duplicate_provider", "unknown_role", "plaintext", "non_argon")
    for case in cases:
        with engine.connect() as connection:
            transaction = connection.begin()
            user_id, identity_id = _insert_user(connection, suffix=case)
            if case == "duplicate_subject":
                statement = sa.text("INSERT INTO auth_identities (user_id, provider_key, subject_key, created_at) VALUES (:user_id, 'local', :subject, :now)")
                parameters = {"user_id": user_id, "subject": f"user.{case}", "now": NOW}
            elif case == "duplicate_provider":
                statement = sa.text("INSERT INTO auth_identities (user_id, provider_key, subject_key, created_at) VALUES (:user_id, 'local', :subject, :now)")
                parameters = {"user_id": user_id, "subject": f"other.{case}", "now": NOW}
            elif case == "unknown_role":
                statement = sa.text("INSERT INTO auth_user_roles (user_id, role_key, assigned_by_user_id, assigned_at, updated_at) VALUES (:user_id, 'owner', NULL, :now, :now)")
                parameters = {"user_id": user_id, "now": NOW}
            else:
                statement = sa.text("INSERT INTO auth_local_credentials (identity_id, password_hash, password_changed_at, created_at, updated_at) VALUES (:identity_id, :password_hash, :now, :now, :now)")
                parameters = {"identity_id": identity_id, "password_hash": "plaintext-password" if case == "plaintext" else "$argon2i$invalid", "now": NOW}
            with pytest.raises(IntegrityError):
                connection.execute(statement, parameters)
            transaction.rollback()


@pytest.mark.parametrize(
    "changes",
    [
        {"token_hash": "a" * 63},
        {"token_hash": "A" * 64},
        {"csrf_token_hash": "b" * 63},
        {"user_session_version": 0},
        {"expires_at": NOW},
        {"absolute_expires_at": NOW + timedelta(minutes=30)},
        {"rotated_at": NOW + timedelta(hours=9)},
        {"revoked_at": NOW, "revocation_reason": "invalid_reason"},
        {"revoked_at": None, "revocation_reason": "logout"},
        {"revoked_at": NOW, "revocation_reason": None},
        {"revoked_at": NOW - timedelta(seconds=1), "revocation_reason": "logout"},
    ],
)
def test_database_rejects_invalid_session_shapes(pg_engine, changes) -> None:
    engine, _url = pg_engine
    with engine.connect() as connection:
        transaction = connection.begin()
        user_id, _identity_id = _insert_user(connection, suffix=uuid4().hex[:8])
        values = {
            "public_id": str(uuid4()),
            "user_id": user_id,
            "token_hash": uuid4().hex * 2,
            "csrf_token_hash": uuid4().hex * 2,
            "user_session_version": 1,
            "issued_at": NOW,
            "expires_at": NOW + timedelta(hours=1),
            "absolute_expires_at": NOW + timedelta(hours=8),
            "rotated_at": None,
            "revoked_at": None,
            "revocation_reason": None,
            "created_at": NOW,
            "updated_at": NOW,
        }
        values.update(changes)
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.text("INSERT INTO auth_sessions (public_id, user_id, token_hash, csrf_token_hash, user_session_version, issued_at, expires_at, absolute_expires_at, rotated_at, revoked_at, revocation_reason, created_at, updated_at) VALUES (:public_id, :user_id, :token_hash, :csrf_token_hash, :user_session_version, :issued_at, :expires_at, :absolute_expires_at, :rotated_at, :revoked_at, :revocation_reason, :created_at, :updated_at)"),
                values,
            )
        transaction.rollback()


@pytest.mark.parametrize(
    ("login_key_hash", "failure_count"),
    [("a" * 63, 0), ("A" * 64, 0), ("a" * 64, -1), ("a" * 64, 1001)],
)
def test_database_rejects_invalid_throttle_shapes(pg_engine, login_key_hash, failure_count) -> None:
    engine, _url = pg_engine
    with engine.connect() as connection:
        transaction = connection.begin()
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.text("INSERT INTO auth_login_throttles (login_key_hash, failure_count, window_started_at, blocked_until, updated_at) VALUES (:login_key_hash, :failure_count, :now, NULL, :now)"),
                {"login_key_hash": login_key_hash, "failure_count": failure_count, "now": NOW},
            )
        transaction.rollback()


def test_password_change_revokes_absolute_expired_session_without_rotation_violation(pg_engine) -> None:
    engine, _url = pg_engine
    with Session(engine) as session:
        user_id = session.execute(
            sa.text("INSERT INTO auth_users (public_id, display_name, status, account_expires_at, session_version, last_authenticated_at, disabled_at, created_at, updated_at) VALUES (:public_id, 'Password Change User', 'active', NULL, 2, NULL, NULL, :created, :created) RETURNING id"),
            {"public_id": str(uuid4()), "created": NOW - timedelta(days=1)},
        ).scalar_one()
        row = AuthSession(
            public_id=uuid4(),
            user_id=user_id,
            token_hash=uuid4().hex * 2,
            csrf_token_hash=uuid4().hex * 2,
            user_session_version=1,
            issued_at=NOW - timedelta(hours=4),
            expires_at=NOW - timedelta(hours=2),
            absolute_expires_at=NOW - timedelta(hours=1),
            created_at=NOW - timedelta(hours=4),
            updated_at=NOW - timedelta(hours=4),
        )
        session.add(row)
        session.flush()
        SessionSecurityService(session, settings()).revoke_all(user_id, "password_change", now=NOW)
        session.flush()
        session.commit()
        session.refresh(row)
        assert row.revoked_at == NOW
        assert row.revocation_reason == "password_change"
        assert row.rotated_at is None
        session.execute(sa.delete(AuthSession).where(AuthSession.user_id == user_id))
        session.execute(sa.text("DELETE FROM auth_users WHERE id = :user_id"), {"user_id": user_id})
        session.commit()


def _has_table_privilege(connection, role: str, table: str, privilege: str) -> bool:
    return bool(
        connection.scalar(
            sa.text("SELECT has_table_privilege(:role, :table, :privilege)"),
            {"role": role, "table": f"public.{table}", "privilege": privilege},
        )
    )


def test_runtime_readonly_backup_and_retention_grants_are_exact(pg_engine) -> None:
    engine, url = pg_engine
    roles = _role_names()
    with engine.connect() as connection:
        for table in (*AUTH_TABLES, "audit_events"):
            assert _has_table_privilege(connection, roles["app"], table, "SELECT")
            assert _has_table_privilege(connection, roles["app"], table, "INSERT")
            assert _has_table_privilege(connection, roles["app"], table, "UPDATE") is (
                table in MUTABLE_AUTH_TABLES
            )
            assert not _has_table_privilege(connection, roles["app"], table, "DELETE")
            assert not _has_table_privilege(connection, roles["app"], table, "TRUNCATE")
            for read_role in (roles["readonly"], roles["backup"]):
                assert _has_table_privilege(connection, read_role, table, "SELECT")
                for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
                    assert not _has_table_privilege(connection, read_role, table, privilege)
        for table in ("auth_local_credentials", "auth_sessions", "auth_login_throttles"):
            assert not _has_table_privilege(connection, roles["retention"], table, "SELECT")
        assert _has_table_privilege(connection, roles["retention"], "audit_events", "SELECT")
        for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert not _has_table_privilege(
                connection, roles["retention"], "audit_events", privilege
            )
        for role in (roles["app"], roles["readonly"], roles["backup"], roles["retention"]):
            assert not connection.scalar(
                sa.text("SELECT has_schema_privilege(:role, 'public', 'CREATE')"),
                {"role": role},
            )
        assert not connection.scalar(
            sa.text("SELECT has_database_privilege(:role, :database, 'CREATE')"),
            {"role": roles["app"], "database": url.database},
        )
        assert connection.scalar(
            sa.text(
                "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' "
                "AND tableowner = :role"
            ),
            {"role": roles["app"]},
        ) == 0
        attributes = connection.execute(
            sa.text(
                "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls FROM pg_roles WHERE rolname = ANY(:roles)"
            ),
            {"roles": list(roles.values())},
        ).all()
        assert len(attributes) == len(roles)
        assert all(not any(row[1:]) for row in attributes)
        assert connection.scalar(
            sa.text(
                "SELECT count(*) FROM pg_auth_members AS membership "
                "JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid "
                "JOIN pg_roles AS member_role ON member_role.oid = membership.member "
                "WHERE granted_role.rolname = ANY(:roles) "
                "OR member_role.rolname = ANY(:roles)"
            ),
            {"roles": list(roles.values())},
        ) == 0
