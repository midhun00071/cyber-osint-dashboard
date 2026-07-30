from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_compose_config() -> dict:
    compose_path = REPO_ROOT / "docker-compose.yml"
    with compose_path.open(encoding="utf-8") as compose_file:
        return yaml.safe_load(compose_file)


def test_backend_compose_uses_component_database_settings() -> None:
    compose_config = load_compose_config()
    backend_environment = compose_config["services"]["backend"]["environment"]

    assert "DATABASE_URL" not in backend_environment
    assert backend_environment["POSTGRES_HOST"] == "db"
    assert backend_environment["POSTGRES_PORT"] == 5432
    assert backend_environment["POSTGRES_DB"] == "${POSTGRES_DB:-alpha_data_db}"
    assert backend_environment["POSTGRES_USER"] == "${POSTGRES_USER:-alpha_data_user}"
    assert (
        backend_environment["POSTGRES_PASSWORD"]
        == "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set for local Compose}"
    )


def test_backend_compose_uses_explicit_cors_allow_list_setting() -> None:
    compose_config = load_compose_config()
    backend_environment = compose_config["services"]["backend"]["environment"]

    assert "BACKEND_CORS_ORIGINS" not in backend_environment
    assert backend_environment["BACKEND_CORS_ALLOWED_ORIGINS"] == (
        "${BACKEND_CORS_ALLOWED_ORIGINS:-http://localhost:3000,"
        "http://127.0.0.1:3000}"
    )
    assert backend_environment["BACKEND_TRUSTED_HOSTS"] == (
        "${BACKEND_TRUSTED_HOSTS:-localhost,127.0.0.1,[::1],testserver}"
    )


def test_local_compose_uses_safe_runtime_controls() -> None:
    compose_config = load_compose_config()
    backend_environment = compose_config["services"]["backend"]["environment"]

    assert backend_environment["APP_ENV"] == "${APP_ENV:-local}"
    assert backend_environment["DEBUG"] == "${DEBUG:-false}"
    assert backend_environment["ENABLE_ADMIN_INGESTION"] == (
        "${ENABLE_ADMIN_INGESTION:-false}"
    )


def test_local_frontend_identity_and_api_url_are_build_arguments() -> None:
    compose_config = load_compose_config()
    frontend = compose_config["services"]["frontend"]

    assert frontend["build"]["args"] == {
        "APP_ENV": "local",
        "NEXT_PUBLIC_API_BASE_URL": "${NEXT_PUBLIC_API_BASE_URL:-}",
    }
    assert "environment" not in frontend
