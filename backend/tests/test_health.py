from fastapi.testclient import TestClient

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
