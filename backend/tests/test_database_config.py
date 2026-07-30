import logging
from pathlib import Path

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


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_password_file_builds_url_and_removes_only_terminal_line_endings(
    tmp_path: Path,
    environment: str,
) -> None:
    password_file = tmp_path / "postgres-password"
    password_file.write_bytes(b"first\nsecond\r\n")
    settings = make_settings(
        APP_ENV=environment,
        POSTGRES_HOST="db.example.invalid",
        POSTGRES_PORT=5432,
        POSTGRES_DB="cyber_osint",
        POSTGRES_USER="cyber_osint_app",
        POSTGRES_PASSWORD_FILE=str(password_file),
        BACKEND_CORS_ALLOWED_ORIGINS="https://dashboard.example.invalid",
        BACKEND_TRUSTED_HOSTS="api.example.invalid",
    )

    assert settings.sqlalchemy_database_url.password == "first\nsecond"


@pytest.mark.parametrize("content", [b"", b"\r\n", b"contains\x00nul"])
def test_password_file_rejects_empty_or_nul_content(
    tmp_path: Path,
    content: bytes,
) -> None:
    password_file = tmp_path / "postgres-password"
    password_file.write_bytes(content)
    settings = make_settings(
        POSTGRES_HOST="localhost",
        POSTGRES_PORT=5432,
        POSTGRES_DB="cyber_osint",
        POSTGRES_USER="cyber_osint_app",
        POSTGRES_PASSWORD_FILE=str(password_file),
    )

    with pytest.raises(ValueError, match="invalid secret content"):
        _ = settings.sqlalchemy_database_url


def test_password_file_rejects_non_file_missing_and_oversized_references(
    tmp_path: Path,
) -> None:
    oversized_file = tmp_path / "oversized-password"
    oversized_file.write_bytes(b"x" * 4097)
    base = {
        "POSTGRES_HOST": "localhost",
        "POSTGRES_PORT": 5432,
        "POSTGRES_DB": "cyber_osint",
        "POSTGRES_USER": "cyber_osint_app",
    }

    for reference, expected in (
        (tmp_path / "missing", "readable regular file"),
        (tmp_path, "readable regular file"),
        (oversized_file, "permitted size"),
    ):
        settings = make_settings(**base, POSTGRES_PASSWORD_FILE=str(reference))
        with pytest.raises(ValueError, match=expected) as exc_info:
            _ = settings.sqlalchemy_database_url
        assert str(reference) not in str(exc_info.value)


def test_password_file_secret_is_not_exposed_in_repr_dump_or_error(
    tmp_path: Path,
) -> None:
    secret = "synthetic-password-file-canary"
    password_file = tmp_path / "postgres-password"
    password_file.write_text(secret, encoding="utf-8")
    settings = make_settings(
        POSTGRES_PORT=5432,
        POSTGRES_DB="cyber_osint",
        POSTGRES_USER="cyber_osint_app",
        POSTGRES_PASSWORD_FILE=str(password_file),
    )

    with pytest.raises(ValueError) as exc_info:
        _ = settings.sqlalchemy_database_url

    material = "\n".join(
        (str(exc_info.value), repr(settings), str(settings.model_dump()))
    )
    assert secret not in material


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_protected_environments_reject_direct_database_secrets(
    environment: str,
) -> None:
    network = {
        "APP_ENV": environment,
        "BACKEND_CORS_ALLOWED_ORIGINS": "https://dashboard.example.invalid",
        "BACKEND_TRUSTED_HOSTS": "api.example.invalid",
    }

    with pytest.raises(ValidationError, match="DATABASE_URL is not permitted"):
        make_settings(
            **network,
            DATABASE_URL="postgresql://user:secret@db.example.invalid/app_db",
        )
    with pytest.raises(ValidationError, match="POSTGRES_PASSWORD is not permitted"):
        make_settings(**network, POSTGRES_PASSWORD="synthetic-secret")


def test_direct_password_and_password_file_are_never_ambiguous(tmp_path: Path) -> None:
    password_file = tmp_path / "postgres-password"
    password_file.write_text("synthetic-file-secret", encoding="utf-8")

    with pytest.raises(ValidationError, match="Configure only one"):
        make_settings(
            POSTGRES_PASSWORD="synthetic-direct-secret",
            POSTGRES_PASSWORD_FILE=str(password_file),
        )


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


def test_database_url_has_explicit_precedence_over_component_settings() -> None:
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

    with pytest.raises(ValueError, match="unsupported database scheme"):
        _ = settings.sqlalchemy_database_url


def test_malformed_database_url_is_rejected_without_exposing_it() -> None:
    canary = "synthetic-test-secret"
    settings = make_settings(DATABASE_URL=f"malformed-{canary}")

    with pytest.raises(ValueError) as exc_info:
        _ = settings.sqlalchemy_database_url

    assert "DATABASE_URL" in str(exc_info.value)
    assert canary not in str(exc_info.value)


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


@pytest.mark.parametrize(
    "host",
    [
        "https://db.example.invalid",
        "db.example.invalid:5432",
        "user@db.example.invalid",
        "db.example.invalid/name",
        "db.example.invalid?x=1",
        "db.example.invalid#fragment",
        "db.example.invalid\n",
        "2130706433",
        "0x7f000001",
        "017700000001",
        "127.1",
    ],
)
def test_invalid_postgres_hosts_are_rejected_without_echoing_value(host: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        make_settings(POSTGRES_HOST=host)

    assert "POSTGRES_HOST" in str(exc_info.value)
    assert host not in str(exc_info.value)


@pytest.mark.parametrize("field", ["POSTGRES_DB", "POSTGRES_USER"])
@pytest.mark.parametrize("value", ["bad/name", "bad name", "bad@name", "bad\nname"])
def test_invalid_database_identifiers_are_rejected(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        make_settings(**{field: value})

    assert field in str(exc_info.value)
    assert value not in str(exc_info.value)


@pytest.mark.parametrize(
    "host",
    ["db.example.invalid", "192.0.2.10", "2001:db8::10", "[2001:db8::10]"],
)
def test_valid_database_hosts_render_safely(host: str) -> None:
    settings = make_settings(
        POSTGRES_HOST=host,
        POSTGRES_PORT=5432,
        POSTGRES_DB="cyber_osint",
        POSTGRES_USER="cyber_osint_app",
        POSTGRES_PASSWORD="synthetic-secret",
    )

    rendered_url = settings.sqlalchemy_database_url.render_as_string(
        hide_password=False
    )
    assert "@/" not in rendered_url
    assert "?" not in rendered_url
    assert "#" not in rendered_url


def test_existing_non_database_settings_still_behave_correctly() -> None:
    settings = make_settings(
        APP_NAME="  Custom Dashboard  ",
        APP_VERSION="  1.2.3  ",
        APP_ENV="  test  ",
        DEBUG=True,
        BACKEND_CORS_ALLOWED_ORIGINS=(
            " http://localhost:3000, http://127.0.0.1:3000 "
        ),
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
