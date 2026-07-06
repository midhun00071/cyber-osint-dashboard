import logging

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Settings, get_settings


def make_settings(**values: object) -> Settings:
    get_settings.cache_clear()
    return Settings(_env_file=None, **values)


def test_component_database_url_uses_psycopg_driver() -> None:
    settings = make_settings(
        POSTGRES_HOST="localhost",
        POSTGRES_PORT=5432,
        POSTGRES_DB="cyber_osint",
        POSTGRES_USER="cyber_osint_app",
        POSTGRES_PASSWORD="local-secret",
    )

    url = settings.sqlalchemy_database_url

    assert url.drivername == "postgresql+psycopg"
    assert url.host == "localhost"
    assert url.port == 5432
    assert url.database == "cyber_osint"
    assert url.username == "cyber_osint_app"


def test_component_database_url_preserves_reserved_password_characters() -> None:
    password = "p@ss:/?#[]@!"
    settings = make_settings(
        POSTGRES_HOST="localhost",
        POSTGRES_PORT=5432,
        POSTGRES_DB="cyber_osint",
        POSTGRES_USER="cyber_osint_app",
        POSTGRES_PASSWORD=password,
    )

    assert settings.sqlalchemy_database_url.drivername == "postgresql+psycopg"
    assert settings.sqlalchemy_database_url.password == password


def test_component_password_is_masked_in_normal_logging(caplog) -> None:
    password = "p@ss:/%#?synthetic-only"
    settings = make_settings(
        POSTGRES_HOST="localhost",
        POSTGRES_PORT=5432,
        POSTGRES_DB="cyber_osint",
        POSTGRES_USER="cyber_osint_app",
        POSTGRES_PASSWORD=password,
    )
    logger = logging.getLogger("tests.database_config")

    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.info("Loaded settings: %s", settings)

    logged_output = "\n".join(record.getMessage() for record in caplog.records)

    assert password not in logged_output
    assert "**********" in logged_output


def test_database_url_override_takes_precedence() -> None:
    settings = make_settings(
        DATABASE_URL="postgresql+psycopg://override_user:override_pass@db:5432/override_db",
        POSTGRES_HOST="localhost",
        POSTGRES_PORT=5432,
        POSTGRES_DB="component_db",
        POSTGRES_USER="component_user",
        POSTGRES_PASSWORD="component_pass",
    )

    url = settings.sqlalchemy_database_url

    assert url.host == "db"
    assert url.database == "override_db"
    assert url.username == "override_user"


def test_postgresql_override_is_normalized_to_psycopg_driver() -> None:
    settings = make_settings(
        DATABASE_URL="postgresql://user:password@localhost:5432/cyber_osint",
    )

    assert settings.sqlalchemy_database_url.drivername == "postgresql+psycopg"


def test_unsupported_database_scheme_is_rejected() -> None:
    settings = make_settings(
        DATABASE_URL="sqlite:///local.db",
    )

    with pytest.raises(ValueError, match="Unsupported database scheme"):
        _ = settings.sqlalchemy_database_url


def test_missing_components_report_variable_names_without_secret_values() -> None:
    settings = make_settings(POSTGRES_PASSWORD="do-not-leak-this")

    with pytest.raises(ValueError) as exc_info:
        _ = settings.sqlalchemy_database_url

    message = str(exc_info.value)

    assert "POSTGRES_HOST" in message
    assert "POSTGRES_PORT" in message
    assert "POSTGRES_DB" in message
    assert "POSTGRES_USER" in message
    assert "do-not-leak-this" not in message


def test_settings_representation_does_not_reveal_password() -> None:
    settings = make_settings(
        POSTGRES_HOST="localhost",
        POSTGRES_PORT=5432,
        POSTGRES_DB="cyber_osint",
        POSTGRES_USER="cyber_osint_app",
        POSTGRES_PASSWORD="do-not-leak-this",
    )

    representation = repr(settings)

    assert "do-not-leak-this" not in representation
    assert "SecretStr" in representation


def test_nvd_api_key_uses_secret_str_and_masks_representation(monkeypatch) -> None:
    secret_value = "synthetic-nvd-test-key-do-not-use"
    monkeypatch.setenv("NVD_API_KEY", secret_value)
    get_settings.cache_clear()

    settings = Settings(_env_file=None)

    assert isinstance(settings.nvd_api_key, SecretStr)
    assert settings.nvd_api_key.get_secret_value() == secret_value

    representation = repr(settings)

    assert secret_value not in representation
    assert "SecretStr" in representation
    assert "**********" in representation


def test_nvd_api_key_is_masked_in_normal_logging(monkeypatch, caplog) -> None:
    secret_value = "synthetic-nvd-test-key-do-not-use"
    monkeypatch.setenv("NVD_API_KEY", secret_value)
    get_settings.cache_clear()
    settings = Settings(_env_file=None)

    logger = logging.getLogger("tests.database_config")

    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.info("Loaded settings: %s", settings)

    logged_output = "\n".join(record.getMessage() for record in caplog.records)

    assert secret_value not in logged_output
    assert "**********" in logged_output


@pytest.mark.parametrize("port", [0, 65536])
def test_postgres_port_outside_valid_range_is_rejected(port: int) -> None:
    with pytest.raises(ValidationError):
        make_settings(POSTGRES_PORT=port)


def test_existing_non_database_settings_still_behave_correctly() -> None:
    settings = make_settings(
        APP_NAME="  Custom Dashboard  ",
        APP_VERSION="  1.2.3  ",
        APP_ENV="  test  ",
        DEBUG=True,
        BACKEND_CORS_ORIGINS=" http://localhost:3000, http://127.0.0.1:3000 ",
    )

    assert settings.app_name == "Custom Dashboard"
    assert settings.app_version == "1.2.3"
    assert settings.app_env == "test"
    assert settings.debug is True
    assert settings.cors_origins_list == [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


def test_default_app_version_is_safe_public_value(monkeypatch) -> None:
    monkeypatch.delenv("APP_VERSION", raising=False)
    get_settings.cache_clear()

    settings = Settings(_env_file=None)

    assert settings.app_version == "0.1.0"


def test_app_version_environment_override_is_supported(monkeypatch) -> None:
    monkeypatch.setenv("APP_VERSION", "2.3.4")
    get_settings.cache_clear()

    settings = Settings(_env_file=None)

    assert settings.app_version == "2.3.4"


def test_app_version_longer_than_64_characters_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(APP_VERSION="v" * 65)
