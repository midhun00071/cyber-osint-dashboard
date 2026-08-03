from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_compose_config() -> dict:
    compose_path = REPO_ROOT / "docker-compose.yml"
    with compose_path.open(encoding="utf-8") as compose_file:
        return yaml.safe_load(compose_file)


def test_local_compose_has_exact_expected_service_set() -> None:
    assert set(load_compose_config()["services"]) == {
        "db",
        "backend",
        "migrate",
        "frontend",
        "prefect-server",
        "prefect-worker",
    }


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


def test_local_compose_separates_database_identities_and_pool_controls() -> None:
    compose = load_compose_config()
    database = compose["services"]["db"]
    backend = compose["services"]["backend"]
    migration = compose["services"]["migrate"]

    assert database["environment"]["POSTGRES_USER"] == (
        "${POSTGRES_BOOTSTRAP_USER:-alpha_data_bootstrap}"
    )
    assert backend["environment"]["POSTGRES_USER"] == (
        "${POSTGRES_USER:-alpha_data_user}"
    )
    assert migration["environment"]["POSTGRES_USER"] == (
        "${POSTGRES_MIGRATION_USER:-alpha_data_migration}"
    )
    assert migration["profiles"] == ["migration"]
    assert database["volumes"][1:] == [
        "./database/init/10-provision-database-roles.sh:"
        "/docker-entrypoint-initdb.d/10-provision-database-roles.sh:ro",
        "./database/init/11-apply-database-grants.sql:"
        "/opt/alpha-data/database/11-apply-database-grants.sql:ro",
    ]
    for name, expected in (
        ("DATABASE_POOL_SIZE", "${DATABASE_POOL_SIZE:-5}"),
        ("DATABASE_MAX_OVERFLOW", "${DATABASE_MAX_OVERFLOW:-5}"),
        ("DATABASE_POOL_TIMEOUT_SECONDS", "${DATABASE_POOL_TIMEOUT_SECONDS:-30}"),
        ("DATABASE_POOL_RECYCLE_SECONDS", "${DATABASE_POOL_RECYCLE_SECONDS:-1800}"),
        ("DATABASE_CONNECT_TIMEOUT_SECONDS", "${DATABASE_CONNECT_TIMEOUT_SECONDS:-10}"),
    ):
        assert backend["environment"][name] == expected


def test_local_database_has_one_automatic_init_script_and_separate_sql() -> None:
    volumes = load_compose_config()["services"]["db"]["volumes"]
    automatic_targets = [
        volume for volume in volumes if ":/docker-entrypoint-initdb.d/" in volume
    ]

    assert automatic_targets == [
        "./database/init/10-provision-database-roles.sh:"
        "/docker-entrypoint-initdb.d/10-provision-database-roles.sh:ro"
    ]
    assert volumes.count(
        "./database/init/11-apply-database-grants.sql:"
        "/opt/alpha-data/database/11-apply-database-grants.sql:ro"
    ) == 1


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
