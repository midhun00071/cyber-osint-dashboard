import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import pool
from sqlalchemy.engine import URL

from app.db.base import Base
from app.db import session as db_session


BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
ALEMBIC_DIR = BACKEND_DIR / "alembic"
VERSIONS_DIR = ALEMBIC_DIR / "versions"


def load_alembic_env_module():
    spec = importlib.util.spec_from_file_location(
        "test_alembic_env",
        ALEMBIC_DIR / "env.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeSettings:
    def __init__(self, sqlalchemy_database_url: URL) -> None:
        self.sqlalchemy_database_url = sqlalchemy_database_url


class FakeConnectionContext:
    def __init__(self, connection: object, enter_error: Exception | None = None) -> None:
        self.connection = connection
        self.enter_error = enter_error
        self.entered = False
        self.exited = False

    def __enter__(self) -> object:
        self.entered = True
        if self.enter_error is not None:
            raise self.enter_error
        return self.connection

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.exited = True
        return False


class FakeMigrationEngine:
    def __init__(self, connection_context: FakeConnectionContext) -> None:
        self.connection_context = connection_context
        self.connect_calls = 0
        self.dispose_calls = 0

    def connect(self) -> FakeConnectionContext:
        self.connect_calls += 1
        return self.connection_context

    def dispose(self) -> None:
        self.dispose_calls += 1


class FakeTransaction:
    def __init__(self) -> None:
        self.entered = False
        self.exited = False
        self.inside = False

    def __enter__(self) -> "FakeTransaction":
        self.entered = True
        self.inside = True
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.exited = True
        self.inside = False
        return False


def make_migration_url() -> URL:
    return URL.create(
        "postgresql+psycopg",
        username="cyber_osint_app",
        password="synthetic-password",
        host="localhost",
        port=5432,
        database="cyber_osint",
    )


def configure_online_migration_fakes(
    monkeypatch: pytest.MonkeyPatch,
    module,
    *,
    run_error: Exception | None = None,
    enter_error: Exception | None = None,
) -> tuple[dict, FakeMigrationEngine, object, FakeTransaction]:
    url = make_migration_url()
    connection = object()
    connection_context = FakeConnectionContext(connection, enter_error=enter_error)
    engine = FakeMigrationEngine(connection_context)
    transaction = FakeTransaction()
    captured_create_engine: dict = {}

    def fake_create_engine(*args, **kwargs):
        captured_create_engine["args"] = args
        captured_create_engine["kwargs"] = kwargs
        return engine

    def fake_run_migrations() -> None:
        captured_create_engine["run_inside_transaction"] = transaction.inside
        if run_error is not None:
            raise run_error

    monkeypatch.setattr(module, "get_settings", lambda: FakeSettings(url))
    monkeypatch.setattr(module, "create_engine", fake_create_engine)
    monkeypatch.setattr(module.context, "configure", MagicMock())
    monkeypatch.setattr(module.context, "begin_transaction", lambda: transaction)
    monkeypatch.setattr(module.context, "run_migrations", fake_run_migrations)
    monkeypatch.setattr(
        db_session,
        "get_engine",
        MagicMock(side_effect=AssertionError("application engine must not be used")),
    )

    return captured_create_engine, engine, connection, transaction


def test_alembic_ini_loads_with_expected_script_location():
    config = Config(str(ALEMBIC_INI))

    assert Path(config.get_main_option("script_location")).resolve() == ALEMBIC_DIR


def test_script_directory_loads_migration_environment():
    config = Config(str(ALEMBIC_INI))
    script_directory = ScriptDirectory.from_config(config)

    assert Path(script_directory.dir).resolve() == ALEMBIC_DIR


def test_versions_directory_exists():
    assert VERSIONS_DIR.is_dir()


def test_alembic_ini_does_not_store_database_url_or_credentials():
    content = ALEMBIC_INI.read_text(encoding="utf-8")

    assert "sqlalchemy.url" not in content
    assert "postgresql://" not in content
    assert "postgresql+psycopg://" not in content
    assert "password" not in content.lower()
    assert "username" not in content.lower()


def test_alembic_target_metadata_uses_application_base_metadata():
    module = load_alembic_env_module()

    assert module.target_metadata is Base.metadata


def test_offline_database_url_preserves_percent_password_without_logging(
    monkeypatch,
    capsys,
):
    module = load_alembic_env_module()
    url = URL.create(
        "postgresql+psycopg",
        username="cyber_osint_app",
        password="safe%password",
        host="localhost",
        port=5432,
        database="cyber_osint",
    )

    class FakeSettings:
        sqlalchemy_database_url = url

    monkeypatch.setattr(module, "get_settings", lambda: FakeSettings())
    configure = MagicMock()
    monkeypatch.setattr(module.context, "configure", configure)
    monkeypatch.setattr(module.context, "begin_transaction", MagicMock())
    monkeypatch.setattr(module.context, "run_migrations", MagicMock())

    module.run_migrations_offline()

    configured_url = configure.call_args.kwargs["url"]
    assert isinstance(configured_url, URL)
    assert configured_url.password == "safe%password"
    captured = capsys.readouterr()
    assert "safe%password" not in captured.out
    assert "safe%password" not in captured.err


def test_online_migrations_use_dedicated_nullpool_engine(monkeypatch):
    module = load_alembic_env_module()
    captured_create_engine, engine, connection, transaction = (
        configure_online_migration_fakes(monkeypatch, module)
    )

    module.run_migrations_online()

    assert engine.connect_calls == 1
    assert engine.connection_context.entered is True
    assert engine.connection_context.exited is True
    assert engine.dispose_calls == 1
    assert captured_create_engine["args"] == (make_migration_url(),)
    assert captured_create_engine["kwargs"] == {"poolclass": pool.NullPool}
    module.context.configure.assert_called_once_with(
        connection=connection,
        target_metadata=Base.metadata,
        compare_type=True,
    )
    assert transaction.entered is True
    assert transaction.exited is True
    assert captured_create_engine["run_inside_transaction"] is True
    assert db_session.get_engine.call_count == 0


def test_online_migrations_dispose_engine_when_migrations_fail(monkeypatch):
    module = load_alembic_env_module()
    error = RuntimeError("synthetic migration failure")
    _, engine, _, transaction = configure_online_migration_fakes(
        monkeypatch,
        module,
        run_error=error,
    )

    with pytest.raises(RuntimeError, match="synthetic migration failure"):
        module.run_migrations_online()

    assert engine.connect_calls == 1
    assert engine.connection_context.entered is True
    assert engine.connection_context.exited is True
    assert engine.dispose_calls == 1
    assert transaction.entered is True
    assert transaction.exited is True
    assert db_session.get_engine.call_count == 0


def test_online_migrations_dispose_engine_when_connection_entry_fails(monkeypatch):
    module = load_alembic_env_module()
    error = RuntimeError("synthetic connection failure")
    _, engine, _, transaction = configure_online_migration_fakes(
        monkeypatch,
        module,
        enter_error=error,
    )

    with pytest.raises(RuntimeError, match="synthetic connection failure"):
        module.run_migrations_online()

    assert engine.connect_calls == 1
    assert engine.connection_context.entered is True
    assert engine.connection_context.exited is False
    assert engine.dispose_calls == 1
    module.context.configure.assert_not_called()
    assert transaction.entered is False
    assert transaction.exited is False
    assert db_session.get_engine.call_count == 0


def test_no_migration_revisions_exist():
    config = Config(str(ALEMBIC_INI))
    script_directory = ScriptDirectory.from_config(config)

    assert list(script_directory.walk_revisions()) == []
