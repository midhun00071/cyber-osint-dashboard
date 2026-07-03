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
        == "${POSTGRES_PASSWORD:-change_me_locally}"
    )
