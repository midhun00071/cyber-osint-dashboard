from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.api.v1.schemas.system import HealthComponentResponse, SystemHealthResponse
from app.core.config import get_settings
from app.db.session import get_db_session
from app.main import app
from app.services.metrics_service import MetricsService
from app.services.system_health_service import SystemHealthService
from tests.c06_auth_test_support import settings


class Scalar:
    def scalar_one(self):
        return 0


class Session:
    def execute(self, _statement):
        return Scalar()


def health() -> SystemHealthResponse:
    names = (
        "backend", "database", "prefect_server", "prefect_worker",
        "ingestion_operations", "source_freshness", "storage", "deployment_identity",
    )
    return SystemHealthResponse(
        status="degraded",
        generated_at=datetime.now(UTC),
        version="1.0.0",
        commit_sha=None,
        components=[
            HealthComponentResponse(
                name=name,
                status="disabled" if name in {"ingestion_operations", "source_freshness"} else "unknown" if name in {"storage", "deployment_identity"} else "healthy",
                summary="Safe fixed state.",
                observations=(
                    {"disabled": 4, "never": 4}
                    if name == "source_freshness"
                    else {"attention_count": 4}
                    if name == "ingestion_operations"
                    else {}
                ),
            )
            for name in names
        ],
    )


def test_metrics_use_fixed_labels_and_missing_backup_is_not_green(monkeypatch) -> None:
    monkeypatch.setattr(SystemHealthService, "snapshot", lambda _self: health())
    body = MetricsService(Session(), settings()).render()
    assert 'component="database",state="healthy"' in body
    assert 'state="disabled"} 4' in body
    assert 'state="never"} 4' in body
    assert "alpha_data_source_attention_count 4" in body
    assert "alpha_data_backup_evidence_available 0" in body
    assert "secret-canary" not in body


def test_internal_metrics_is_not_in_openapi_and_has_prometheus_content_type(monkeypatch) -> None:
    app.dependency_overrides[get_db_session] = lambda: Session()
    app.dependency_overrides[get_settings] = lambda: settings()
    monkeypatch.setattr(SystemHealthService, "snapshot", lambda _self: health())
    try:
        with TestClient(app) as client:
            response = client.get("/internal/metrics")
        assert response.status_code == 200
        assert response.headers["Content-Type"].startswith("text/plain; version=0.0.4")
        assert "/internal/metrics" not in app.openapi()["paths"]
    finally:
        app.dependency_overrides.clear()
