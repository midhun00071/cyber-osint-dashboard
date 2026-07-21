from pathlib import Path
import re

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_COMPOSE = REPO_ROOT / "compose.prod.yml"
DEVELOPMENT_COMPOSE = REPO_ROOT / "docker-compose.yml"
BACKEND_DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile.prod"
FRONTEND_DOCKERFILE = REPO_ROOT / "frontend" / "Dockerfile.prod"
PRODUCTION_ENV_EXAMPLE = REPO_ROOT / ".env.production.example"
BACKEND_DOCKERIGNORE = REPO_ROOT / "backend" / ".dockerignore"


def load_production_compose() -> dict:
    with PRODUCTION_COMPOSE.open(encoding="utf-8") as compose_file:
        return yaml.safe_load(compose_file)


def test_production_compose_has_only_expected_runtime_and_manual_services() -> None:
    compose = load_production_compose()

    assert set(compose["services"]) == {"db", "backend", "frontend", "migrate"}
    assert "container_name" not in PRODUCTION_COMPOSE.read_text(encoding="utf-8")


def test_production_services_do_not_bind_mount_application_source() -> None:
    compose = load_production_compose()

    assert "volumes" not in compose["services"]["backend"]
    assert "volumes" not in compose["services"]["frontend"]
    assert "volumes" not in compose["services"]["migrate"]
    assert compose["services"]["db"]["volumes"] == [
        "postgres_data:/var/lib/postgresql/data"
    ]


def test_production_commands_exclude_development_and_ingestion_modes() -> None:
    compose_text = PRODUCTION_COMPOSE.read_text(encoding="utf-8").lower()
    backend_dockerfile = BACKEND_DOCKERFILE.read_text(encoding="utf-8").lower()
    frontend_dockerfile = FRONTEND_DOCKERFILE.read_text(encoding="utf-8").lower()

    assert "--reload" not in compose_text + backend_dockerfile
    assert "next dev" not in compose_text + frontend_dockerfile
    assert "pytest" not in compose_text
    assert not re.search(r"(?:command|entrypoint):.*ingest", compose_text)
    assert "enable_admin_ingestion: \"false\"" in compose_text


def test_database_is_private_persistent_and_healthy() -> None:
    compose = load_production_compose()
    database = compose["services"]["db"]

    assert "ports" not in database
    assert database["volumes"] == ["postgres_data:/var/lib/postgresql/data"]
    assert "postgres_data" in compose["volumes"]
    assert "pg_isready" in " ".join(database["healthcheck"]["test"])


def test_every_runtime_service_has_a_bounded_local_healthcheck() -> None:
    compose = load_production_compose()

    for service_name in ("db", "backend", "frontend"):
        healthcheck = compose["services"][service_name]["healthcheck"]
        assert healthcheck["interval"]
        assert healthcheck["timeout"]
        assert healthcheck["retries"] > 0

    backend_test = " ".join(compose["services"]["backend"]["healthcheck"]["test"])
    frontend_test = " ".join(
        compose["services"]["frontend"]["healthcheck"]["test"]
    )
    assert "127.0.0.1:8000/api/health" in backend_test
    assert "127.0.0.1:3000/" in frontend_test


def test_application_images_run_as_non_root_users() -> None:
    backend = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
    frontend = FRONTEND_DOCKERFILE.read_text(encoding="utf-8")

    assert re.search(r"(?m)^USER appuser$", backend)
    assert re.search(r"(?m)^USER nextjs$", frontend)
    assert not re.search(r"(?m)^USER (?:0|root)$", backend + frontend)


def test_sensitive_production_values_are_required_without_weak_defaults() -> None:
    compose_text = PRODUCTION_COMPOSE.read_text(encoding="utf-8")
    environment_example = PRODUCTION_ENV_EXAMPLE.read_text(encoding="utf-8")

    for variable in (
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "BACKEND_CORS_ALLOWED_ORIGINS",
        "NEXT_PUBLIC_API_BASE_URL",
    ):
        assert f"${{{variable}:?" in compose_text

    assert re.search(r"(?m)^POSTGRES_PASSWORD=$", environment_example)
    combined = (compose_text + environment_example).lower()
    for weak_value in ("change_me", "changeme", "password123", "admin123"):
        assert weak_value not in combined


def test_production_cors_is_explicit_and_not_wildcarded() -> None:
    compose = load_production_compose()
    backend_environment = compose["services"]["backend"]["environment"]

    assert backend_environment["APP_ENV"] == "production"
    assert backend_environment["DEBUG"] == "false"
    assert backend_environment["BACKEND_CORS_ALLOWED_ORIGINS"].startswith(
        "${BACKEND_CORS_ALLOWED_ORIGINS:?"
    )
    assert "*" not in backend_environment["BACKEND_CORS_ALLOWED_ORIGINS"]


def test_migration_is_a_manual_one_shot_profile() -> None:
    compose = load_production_compose()
    migration = compose["services"]["migrate"]

    assert migration["profiles"] == ["migration"]
    assert migration["restart"] == "no"
    assert migration["command"] == [
        "alembic",
        "-c",
        "/app/alembic.ini",
        "upgrade",
        "head",
    ]
    assert migration["depends_on"]["db"]["condition"] == "service_healthy"


def test_runtime_services_have_restart_and_bounded_logging_policies() -> None:
    compose = load_production_compose()

    for service_name in ("db", "backend", "frontend"):
        service = compose["services"][service_name]
        assert service["restart"] == "unless-stopped"
        assert service["logging"] == {
            "driver": "local",
            "options": {"max-size": "10m", "max-file": "3"},
        }


def test_application_services_use_compatible_container_hardening() -> None:
    compose = load_production_compose()

    for service_name in ("backend", "frontend", "migrate"):
        service = compose["services"][service_name]
        assert service["init"] is True
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["cap_drop"] == ["ALL"]

    for service in compose["services"].values():
        assert service.get("privileged") is not True
        assert service.get("network_mode") != "host"
        assert "/var/run/docker.sock" not in str(service.get("volumes", []))


def test_database_network_is_internal_and_frontend_cannot_join_it() -> None:
    compose = load_production_compose()

    assert compose["networks"]["database"]["internal"] is True
    assert set(compose["services"]["backend"]["networks"]) == {
        "application",
        "database",
    }
    assert compose["services"]["db"]["networks"] == ["database"]
    assert compose["services"]["frontend"]["networks"] == ["application"]


def test_backend_production_image_is_narrow_and_packages_alembic() -> None:
    dockerfile = BACKEND_DOCKERFILE.read_text(encoding="utf-8")

    assert not re.search(r"(?m)^COPY(?:\s+--\S+)*\s+\.\s", dockerfile)
    assert "app ./app" in dockerfile
    assert "alembic.ini ./alembic.ini" in dockerfile
    assert "alembic ./alembic" in dockerfile
    assert "--reload" not in dockerfile
    assert "HEALTHCHECK" in dockerfile


def test_backend_build_context_excludes_nested_python_caches() -> None:
    dockerignore = BACKEND_DOCKERIGNORE.read_text(encoding="utf-8")

    assert "**/__pycache__/" in dockerignore
    assert "**/*.py[cod]" in dockerignore


def test_frontend_production_image_uses_deterministic_standalone_build() -> None:
    dockerfile = FRONTEND_DOCKERFILE.read_text(encoding="utf-8")
    next_config = (REPO_ROOT / "frontend" / "next.config.mjs").read_text(
        encoding="utf-8"
    )

    assert "RUN npm ci" in dockerfile
    assert 'output: "standalone"' in next_config
    assert "/app/.next/standalone" in dockerfile
    assert 'CMD ["node", "server.js"]' in dockerfile
    assert "next dev" not in dockerfile
    assert "node_modules" not in dockerfile.split("FROM node:24-alpine AS runner", 1)[1]


def test_frontend_public_api_url_is_a_required_build_time_value() -> None:
    compose = load_production_compose()
    frontend = compose["services"]["frontend"]

    assert frontend["build"]["args"]["NEXT_PUBLIC_API_BASE_URL"].startswith(
        "${NEXT_PUBLIC_API_BASE_URL:?"
    )
    assert "environment" not in frontend


def test_production_dockerfiles_never_explicitly_copy_environment_files() -> None:
    for dockerfile_path in (BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE):
        copy_lines = [
            line.lower()
            for line in dockerfile_path.read_text(encoding="utf-8").splitlines()
            if line.strip().lower().startswith("copy ")
        ]
        assert not any(".env" in line for line in copy_lines)


def test_development_compose_and_dev_runner_contract_remain_present() -> None:
    compose = yaml.safe_load(DEVELOPMENT_COMPOSE.read_text(encoding="utf-8"))
    run_script = (REPO_ROOT / "run.ps1").read_text(encoding="utf-8")

    assert compose["services"]["db"]["container_name"] == "alpha-data-db"
    assert compose["services"]["db"]["ports"] == ["${POSTGRES_PORT:-5432}:5432"]
    assert '"dev" {' in run_script
    assert 'ArgumentList @("run", "dev", "--", "--port", "3000")' in run_script
