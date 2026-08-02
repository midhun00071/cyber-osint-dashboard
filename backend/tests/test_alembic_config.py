import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import pool
from sqlalchemy.engine import URL

from app.db import session as db_session
from app.db.base import Base


APPROVED_TABLES = {
    "audit_events",
    "indicator_provenances",
    "indicators",
    "ingestion_cycles",
    "ingestion_errors",
    "ingestion_run_records",
    "ingestion_runs",
    "ingestion_run_events",
    "intelligence_item_identifiers",
    "intelligence_item_indicators",
    "intelligence_item_tags",
    "intelligence_items",
    "intelligence_sources",
    "quarantined_records",
    "source_checkpoints",
    "source_credential_references",
    "source_rate_limit_states",
    "source_records",
    "source_watermarks",
    "tags",
    "vulnerabilities",
}


BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
ALEMBIC_DIR = BACKEND_DIR / "alembic"
VERSIONS_DIR = ALEMBIC_DIR / "versions"
SCRIPT_TEMPLATE = ALEMBIC_DIR / "script.py.mako"


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


def test_revision_template_preserves_generated_content_placeholders():
    content = SCRIPT_TEMPLATE.read_text(encoding="utf-8")
    imports_placeholder = '${imports if imports else ""}'
    upgrades_placeholder = '${upgrades if upgrades else "pass"}'
    downgrades_placeholder = '${downgrades if downgrades else "pass"}'

    sqlalchemy_import_index = content.index("import sqlalchemy as sa")
    imports_placeholder_index = content.index(imports_placeholder)
    upgrade_function_index = content.index("def upgrade() -> None:")
    upgrades_placeholder_index = content.index(upgrades_placeholder)
    downgrade_function_index = content.index("def downgrade() -> None:")
    downgrades_placeholder_index = content.index(downgrades_placeholder)

    assert sqlalchemy_import_index < imports_placeholder_index
    assert imports_placeholder_index < content.index("revision: str =")
    assert upgrade_function_index < upgrades_placeholder_index
    assert upgrades_placeholder_index < downgrade_function_index
    assert downgrade_function_index < downgrades_placeholder_index


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
    assert set(module.target_metadata.tables) == APPROVED_TABLES


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


def test_migration_chain_is_linear_with_one_head_and_known_base():
    config = Config(str(ALEMBIC_INI))
    script_directory = ScriptDirectory.from_config(config)
    revisions = list(script_directory.walk_revisions())

    assert len(revisions) == 5
    assert script_directory.get_heads() == ["d7a9e51c2f40"]
    assert [revision.revision for revision in revisions] == [
        "d7a9e51c2f40",
        "b103a71d2e4f",
        "c4e8b2a91d30",
        "a6c9d4e2f107",
        "f8d739439ed0",
    ]
    assert revisions[0].down_revision == "b103a71d2e4f"
    assert revisions[1].down_revision == "c4e8b2a91d30"
    assert revisions[2].down_revision == "a6c9d4e2f107"
    assert revisions[3].down_revision == "f8d739439ed0"
    assert revisions[4].down_revision is None
    for revision in revisions:
        assert revision.is_branch_point is False
        assert revision.is_merge_point is False
        assert Path(revision.path).parent.resolve() == VERSIONS_DIR


def test_gitkeep_is_not_required_after_initial_revision_exists():
    assert not (VERSIONS_DIR / ".gitkeep").exists()


def test_initial_revision_file_does_not_store_database_url_or_credentials():
    config = Config(str(ALEMBIC_INI))
    script_directory = ScriptDirectory.from_config(config)
    revision = script_directory.get_revision("f8d739439ed0")
    assert revision is not None
    content = Path(revision.path).read_text(encoding="utf-8").lower()

    assert "postgresql://" not in content
    assert "postgresql+psycopg://" not in content
    assert "database_url" not in content
    assert "password" not in content
    assert "api_key" not in content
    assert "authorization" not in content
    assert "cookie" not in content
