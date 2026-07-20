from fastapi.testclient import TestClient

from app.api.v1.query_validation import VALIDATION_ERROR_DETAIL
from app.main import app

client = TestClient(app)


def test_root_endpoint_returns_safe_metadata() -> None:
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "Cyber OSINT Dashboard"
    assert data["status"] == "running"
    assert data["health_url"] == "/api/health"


def test_health_endpoint_returns_ok_status() -> None:
    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"
    assert data["service"] == "Cyber OSINT Dashboard"
    assert data["environment"] == "development"
    assert "timestamp" in data


def test_health_and_root_reject_query_parameters() -> None:
    for path in ("/?unknown=x", "/api/health?unknown=x"):
        response = client.get(path)

        assert response.status_code == 422
        assert response.json() == {"detail": VALIDATION_ERROR_DETAIL}
