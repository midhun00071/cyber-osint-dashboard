import logging

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings


VALID_DATABASE = {
    "POSTGRES_HOST": "localhost",
    "POSTGRES_PORT": 5432,
    "POSTGRES_DB": "cyber_osint",
    "POSTGRES_USER": "cyber_osint_app",
    "POSTGRES_PASSWORD": "synthetic-test-secret",
}
PROTECTED_NETWORK = {
    "BACKEND_CORS_ALLOWED_ORIGINS": "https://dashboard.example.invalid",
    "BACKEND_TRUSTED_HOSTS": "api.example.invalid",
    "AUTH_COOKIE_SECURE": True,
}


def make_settings(**values: object) -> Settings:
    get_settings.cache_clear()
    if str(values.get("APP_ENV", "local")).strip().lower() in {"staging", "production"}:
        values.setdefault("AUTH_COOKIE_SECURE", True)
    return Settings(_env_file=None, **values)


def test_c06_auth_defaults_and_protected_cookie_requirement() -> None:
    local = make_settings(APP_ENV="test")
    assert (local.auth_cookie_secure, local.auth_session_ttl_minutes, local.auth_session_absolute_ttl_minutes, local.auth_max_active_sessions) == (False, 60, 480, 5)
    assert (local.auth_login_failure_limit, local.auth_login_failure_window_seconds, local.auth_login_block_seconds) == (5, 900, 900)
    protected = Settings(
        _env_file=None,
        APP_ENV="production",
        BACKEND_CORS_ALLOWED_ORIGINS="https://dashboard.example.invalid",
        BACKEND_TRUSTED_HOSTS="api.example.invalid",
        AUTH_COOKIE_SECURE=False,
    )
    with pytest.raises(ValueError, match="AUTH_COOKIE_SECURE"):
        protected.validate_startup()


@pytest.mark.parametrize("environment", ["local", "test", "staging", "production"])
def test_supported_environment_identities(environment: str) -> None:
    values: dict[str, object] = {"APP_ENV": environment}
    if environment in {"staging", "production"}:
        values.update(PROTECTED_NETWORK)

    settings = make_settings(**values)

    assert settings.effective_environment == environment


def test_development_is_a_compatibility_alias_for_local() -> None:
    settings = make_settings(APP_ENV=" DeVeLoPmEnT ")

    assert settings.app_env == "development"
    assert settings.effective_environment == "local"


@pytest.mark.parametrize(
    ("configured", "expected"),
    [(" LOCAL ", "local"), (" TeSt ", "test"), (" STAGING ", "staging")],
)
def test_environment_case_and_whitespace_are_deterministic(
    configured: str,
    expected: str,
) -> None:
    values: dict[str, object] = {"APP_ENV": configured}
    if expected == "staging":
        values.update(PROTECTED_NETWORK)

    assert make_settings(**values).effective_environment == expected


@pytest.mark.parametrize("configured", ["", "   ", "preview", "prod"])
def test_blank_and_unsupported_environments_are_rejected_without_fallback(
    configured: str,
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        make_settings(APP_ENV=configured)

    message = str(exc_info.value)
    assert "APP_ENV" in message
    assert "input_value" not in message


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_protected_environments_require_explicit_network_boundaries(
    environment: str,
) -> None:
    with pytest.raises(ValidationError, match="BACKEND_CORS_ALLOWED_ORIGINS"):
        make_settings(APP_ENV=environment)

    with pytest.raises(ValidationError, match="BACKEND_TRUSTED_HOSTS"):
        make_settings(
            APP_ENV=environment,
            BACKEND_CORS_ALLOWED_ORIGINS="https://dashboard.example.invalid",
        )


@pytest.mark.parametrize("environment", ["staging", "production"])
@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        ("DEBUG", True, "DEBUG"),
        ("ENABLE_ADMIN_INGESTION", True, "ENABLE_ADMIN_INGESTION"),
    ],
)
def test_protected_environments_reject_development_controls(
    environment: str,
    setting: str,
    value: bool,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        make_settings(
            APP_ENV=environment,
            **PROTECTED_NETWORK,
            **{setting: value},
        )


def test_startup_validation_requires_database_configuration() -> None:
    settings = make_settings()

    with pytest.raises(ValueError, match="Missing database configuration"):
        settings.validate_startup()


def test_startup_validation_accepts_complete_component_configuration() -> None:
    settings = make_settings(**VALID_DATABASE)

    settings.validate_startup()


def test_optional_nvd_credential_absence_is_not_a_startup_failure() -> None:
    settings = make_settings(**VALID_DATABASE)

    assert settings.nvd_api_key is None
    settings.validate_startup()


def test_synthetic_canary_is_masked_from_settings_errors_repr_dump_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "synthetic-test-secret"
    settings = make_settings(
        **VALID_DATABASE,
        DATABASE_URL=f"not-a-database-url-{canary}",
        NVD_API_KEY=canary,
    )

    with pytest.raises(ValueError) as exc_info:
        settings.validate_startup()

    logger = logging.getLogger("tests.environment_configuration")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.info("settings=%s", settings)

    material = "\n".join(
        (
            str(exc_info.value),
            repr(settings),
            str(settings.model_dump()),
            settings.model_dump_json(),
            "\n".join(record.getMessage() for record in caplog.records),
        )
    )
    assert canary not in material
    assert "DATABASE_URL" in str(exc_info.value)
