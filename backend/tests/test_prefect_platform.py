from pathlib import Path
import re

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
LOCAL_COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"
PRODUCTION_COMPOSE_PATH = REPO_ROOT / "compose.prod.yml"
PREFECT_DOCKERFILE = REPO_ROOT / "prefect" / "Dockerfile"
REQUIREMENTS = REPO_ROOT / "backend" / "requirements.txt"
PINNED_UPSTREAM_IMAGE = "prefecthq/prefect:3.8.1-python3.13"
PROJECT_IMAGE = "alpha-data-prefect:3.8.1-python3.13"
POOL_NAME = "alpha-data-process"


def load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def prefect_services(compose: dict) -> tuple[dict, dict]:
    services = compose["services"]
    return services["prefect-server"], services["prefect-worker"]


def test_prefect_dockerfile_uses_only_the_exact_pinned_base() -> None:
    dockerfile = PREFECT_DOCKERFILE.read_text(encoding="utf-8")
    from_lines = [
        line.strip() for line in dockerfile.splitlines() if line.startswith("FROM ")
    ]

    assert from_lines == [f"FROM {PINNED_UPSTREAM_IMAGE}"]
    assert "COPY " not in dockerfile
    assert "pip install" not in dockerfile
    assert "apt-get" not in dockerfile
    assert "PREFECT_HOME=/var/lib/prefect" in dockerfile


def test_prefect_image_has_a_fixed_unprivileged_identity() -> None:
    dockerfile = PREFECT_DOCKERFILE.read_text(encoding="utf-8")

    assert "groupadd --gid 10001 prefect" in dockerfile
    assert "useradd --uid 10001 --gid 10001" in dockerfile
    assert "install -d --owner prefect --group prefect --mode 0750" in dockerfile
    assert re.search(r"(?m)^USER 10001:10001$", dockerfile)
    assert not re.search(r"(?m)^USER (?:0|root)(?::(?:0|root))?$", dockerfile)


def test_local_and_production_use_the_same_project_built_image() -> None:
    for compose_path in (LOCAL_COMPOSE_PATH, PRODUCTION_COMPOSE_PATH):
        server, worker = prefect_services(load_yaml(compose_path))
        assert server["image"] == worker["image"] == PROJECT_IMAGE
        assert server["build"] == worker["build"] == {
            "context": ".",
            "dockerfile": "prefect/Dockerfile",
        }

    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (PREFECT_DOCKERFILE, LOCAL_COMPOSE_PATH, PRODUCTION_COMPOSE_PATH)
    )
    assert ":latest" not in combined
    assert "prefecthq/prefect:latest" not in combined
    assert "prefecthq/prefect:3\n" not in combined


def test_exact_compose_service_sets_include_one_server_and_worker() -> None:
    local = load_yaml(LOCAL_COMPOSE_PATH)
    production = load_yaml(PRODUCTION_COMPOSE_PATH)

    assert set(local["services"]) == {
        "db",
        "backend",
        "migrate",
        "frontend",
        "prefect-server",
        "prefect-worker",
    }
    assert set(production["services"]) == {
        "db",
        "backend",
        "frontend",
        "migrate",
        "prefect-server",
        "prefect-worker",
    }


def test_worker_uses_fixed_process_pool_and_idempotent_creation() -> None:
    for compose_path in (LOCAL_COMPOSE_PATH, PRODUCTION_COMPOSE_PATH):
        _, worker = prefect_services(load_yaml(compose_path))
        command = worker["command"]
        assert isinstance(command, list)
        assert command == [
            "prefect",
            "worker",
            "start",
            "--pool",
            POOL_NAME,
            "--type",
            "process",
            "--with-healthcheck",
            "--create-pool-if-not-found",
        ]
        assert worker["environment"]["PREFECT_API_URL"] == (
            "http://prefect-server:4200/api"
        )


def test_healthchecks_reach_the_real_prefect_endpoints() -> None:
    for compose_path in (LOCAL_COMPOSE_PATH, PRODUCTION_COMPOSE_PATH):
        server, worker = prefect_services(load_yaml(compose_path))
        server_health = server["healthcheck"]
        worker_health = worker["healthcheck"]
        server_test = " ".join(server_health["test"])
        worker_test = " ".join(worker_health["test"])

        assert "http://127.0.0.1:4200/api/health" in server_test
        assert "http://127.0.0.1:8080/health" in worker_test
        assert "urllib.request.urlopen" in server_test
        assert "urllib.request.urlopen" in worker_test
        assert "|| true" not in server_test + worker_test
        for healthcheck in (server_health, worker_health):
            assert healthcheck["interval"] == "10s"
            assert healthcheck["timeout"] == "5s"
            assert healthcheck["retries"] > 0
            assert healthcheck["start_period"] == "20s"


def test_worker_waits_for_a_healthy_server() -> None:
    for compose_path in (LOCAL_COMPOSE_PATH, PRODUCTION_COMPOSE_PATH):
        _, worker = prefect_services(load_yaml(compose_path))
        dependency = worker["depends_on"]["prefect-server"]
        assert dependency["condition"] == "service_healthy"


def test_prefect_state_is_server_owned_and_worker_isolated() -> None:
    for compose_path in (LOCAL_COMPOSE_PATH, PRODUCTION_COMPOSE_PATH):
        compose = load_yaml(compose_path)
        server, worker = prefect_services(compose)
        assert set(compose["volumes"]) == {"postgres_data", "prefect_data"}
        assert server["volumes"] == ["prefect_data:/var/lib/prefect"]
        assert "volumes" not in worker
        assert server["environment"]["PREFECT_HOME"] == "/var/lib/prefect"
        assert worker["environment"]["PREFECT_HOME"] == "/var/lib/prefect"


def test_local_prefect_admin_is_loopback_only_and_worker_is_not_published() -> None:
    server, worker = prefect_services(load_yaml(LOCAL_COMPOSE_PATH))

    assert server["ports"] == ["127.0.0.1:${PREFECT_PORT:-4200}:4200"]
    assert "ports" not in worker
    assert not any(port.startswith("0.0.0.0:") for port in server["ports"])


def test_production_prefect_is_private_and_has_no_host_publication() -> None:
    compose = load_yaml(PRODUCTION_COMPOSE_PATH)
    server, worker = prefect_services(compose)

    assert compose["networks"]["orchestration"] == {
        "driver": "bridge",
        "internal": True,
    }
    assert server["networks"] == worker["networks"] == ["orchestration"]
    assert "ports" not in server
    assert "ports" not in worker


def test_production_prefect_runtime_is_hardened_and_logs_are_bounded() -> None:
    compose = load_yaml(PRODUCTION_COMPOSE_PATH)
    server, worker = prefect_services(compose)

    for service in (server, worker):
        assert service["user"] == "10001:10001"
        assert service["init"] is True
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["cap_drop"] == ["ALL"]
        assert service["restart"] == "unless-stopped"
        assert service["logging"] == {
            "driver": "local",
            "options": {"max-size": "10m", "max-file": "3"},
        }
        assert service.get("privileged") is not True
        assert service.get("network_mode") != "host"
        assert "/var/run/docker.sock" not in str(service.get("volumes", []))


def test_production_prefect_has_no_source_or_host_bind_mounts() -> None:
    server, worker = prefect_services(load_yaml(PRODUCTION_COMPOSE_PATH))

    assert server["volumes"] == ["prefect_data:/var/lib/prefect"]
    assert "volumes" not in worker
    assert not any(volume.startswith(("./", "../", "/")) for volume in server["volumes"])


def test_prefect_configuration_has_no_cloud_or_default_credentials() -> None:
    prefect_configurations = [
        PREFECT_DOCKERFILE.read_text(encoding="utf-8"),
        yaml.safe_dump(
            {
                name: service
                for name, service in load_yaml(LOCAL_COMPOSE_PATH)["services"].items()
                if name.startswith("prefect-")
            }
        ),
        yaml.safe_dump(
            {
                name: service
                for name, service in load_yaml(PRODUCTION_COMPOSE_PATH)[
                    "services"
                ].items()
                if name.startswith("prefect-")
            }
        ),
    ]
    combined = "\n".join(prefect_configurations)
    lower = combined.lower()

    assert "prefect_cloud" not in lower
    assert "prefect_api_key" not in lower
    assert "api.prefect.cloud" not in lower
    assert "username" not in lower
    assert "password" not in lower
    assert "authorization" not in lower


def test_apscheduler_is_removed_and_has_no_runtime_import() -> None:
    requirements = {
        line.strip().lower()
        for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    runtime_python = "\n".join(
        path.read_text(encoding="utf-8").lower()
        for path in (REPO_ROOT / "backend" / "app").rglob("*.py")
    )

    assert "apscheduler" not in requirements
    assert "apscheduler" not in runtime_python


def test_existing_application_and_database_network_boundaries_remain_intact() -> None:
    compose = load_yaml(PRODUCTION_COMPOSE_PATH)

    assert compose["networks"]["database"]["internal"] is True
    assert compose["services"]["db"]["networks"] == ["database"]
    assert set(compose["services"]["backend"]["networks"]) == {
        "application",
        "database",
    }
    assert compose["services"]["frontend"]["networks"] == ["application"]
    assert compose["services"]["migrate"]["networks"] == ["database"]
    assert "ports" not in compose["services"]["db"]
