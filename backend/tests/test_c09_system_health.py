from collections.abc import Iterator

from fastapi.testclient import TestClient
import pytest

from app.api.v1.schemas.system import HealthComponentResponse
from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.main import app
from app.security.contracts import RoleKey
from app.security.dependencies import require_source_read
from app.services.system_health_service import (
    PREFECT_SERVER_HEALTH_URL,
    PREFECT_WORKER_HEALTH_URL,
    SystemHealthService,
)
from tests.c06_auth_test_support import principal, settings


def component(name: str, state: str) -> HealthComponentResponse:
    return HealthComponentResponse(name=name, status=state, summary="Synthetic bounded state.")


def test_probes_are_fixed_internal_urls() -> None:
    assert PREFECT_SERVER_HEALTH_URL == "http://prefect-server:4200/api/health"
    assert PREFECT_WORKER_HEALTH_URL == "http://prefect-worker:8080/health"


def test_overall_health_semantics_keep_failures_unknown_and_stale_visible() -> None:
    healthy = [
        component(name, "healthy")
        for name in (
            "backend", "database", "prefect_server", "prefect_worker",
            "ingestion_operations", "source_freshness", "storage", "deployment_identity",
        )
    ]
    assert SystemHealthService._overall(healthy) == "healthy"
    healthy[1] = component("database", "unhealthy")
    assert SystemHealthService._overall(healthy) == "unhealthy"
    healthy[1] = component("database", "healthy")
    healthy[2] = component("prefect_server", "unhealthy")
    assert SystemHealthService._overall(healthy) == "degraded"
    healthy[2] = component("prefect_server", "healthy")
    healthy[5] = component("source_freshness", "stale")
    assert SystemHealthService._overall(healthy) == "degraded"
    healthy[5] = component("source_freshness", "healthy")
    healthy[6] = component("storage", "unknown")
    assert SystemHealthService._overall(healthy) == "degraded"


def test_protected_configuration_requires_valid_commit() -> None:
    values = {
        "APP_ENV": "production",
        "AUTH_COOKIE_SECURE": True,
        "BACKEND_CORS_ALLOWED_ORIGINS": "https://dashboard.example.invalid",
        "BACKEND_TRUSTED_HOSTS": "api.example.invalid",
    }
    missing = Settings(_env_file=None, **values)
    with pytest.raises(ValueError, match="APP_COMMIT_SHA"):
        missing.validate_startup()
    with pytest.raises(ValueError, match="APP_COMMIT_SHA"):
        Settings(_env_file=None, APP_COMMIT_SHA="bad", **values)
    configured = Settings(_env_file=None, APP_COMMIT_SHA="A" * 40, **values)
    assert configured.app_commit_sha == "a" * 40


@pytest.fixture
def authorized_health(monkeypatch) -> Iterator[None]:
    viewer = principal(RoleKey.VIEWER)
    app.dependency_overrides[require_source_read] = lambda: viewer
    app.dependency_overrides[get_db_session] = lambda: object()
    app.dependency_overrides[get_settings] = lambda: settings(APP_VERSION="1.2.3", APP_COMMIT_SHA="b" * 40)
    monkeypatch.setattr(
        SystemHealthService,
        "snapshot",
        lambda _self, **_kwargs: {
            "status": "degraded",
            "generated_at": "2026-08-09T00:00:00Z",
            "version": "1.2.3",
            "commit_sha": "b" * 40,
            "components": [
                {"name": name, "status": "unknown" if name == "storage" else "healthy", "summary": "Safe state.", "observations": {}}
                for name in (
                    "backend", "database", "prefect_server", "prefect_worker",
                    "ingestion_operations", "source_freshness", "storage", "deployment_identity",
                )
            ],
        },
    )
    yield
    app.dependency_overrides.clear()


def test_system_health_is_authorized_no_store_and_exposes_identity(authorized_health) -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/system/health")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["commit_sha"] == "b" * 40
    assert response.json()["components"][6]["status"] == "unknown"


def test_system_health_rejects_anonymous() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/system/health")
    assert response.status_code == 401


def test_system_health_materializes_at_most_one_hundred_sources(monkeypatch) -> None:
    captured = []
    monkeypatch.setattr(
        "app.services.system_health_service.OperationsQueryService.operations_summary",
        lambda _self: {
            "configured_handler_count": 0,
            "active_cycle_count": 0,
            "active_run_count": 0,
            "source_attention_count": 0,
        },
    )
    monkeypatch.setattr(
        "app.services.system_health_service.OperationsQueryService.list_sources",
        lambda _self, **kwargs: captured.append(kwargs) or ([], 0),
    )
    SystemHealthService(object(), settings())._operations(frozenset())
    assert captured == [{"permissions": frozenset(), "limit": 100, "offset": 0}]
