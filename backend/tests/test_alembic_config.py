import importlib.util
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.engine import URL

from app.db.base import Base


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


def test_offline_database_url_rendering_escapes_percent_without_logging(monkeypatch):
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

    rendered_url = module._database_url_for_offline_mode()

    assert "safe%%25password" in rendered_url


def test_no_migration_revisions_exist():
    config = Config(str(ALEMBIC_INI))
    script_directory = ScriptDirectory.from_config(config)

    assert list(script_directory.walk_revisions()) == []
