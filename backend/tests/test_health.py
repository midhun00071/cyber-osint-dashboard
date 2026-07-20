from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.api.v1.query_validation import VALIDATION_ERROR_DETAIL
from app.core.request_context import REQUEST_ID_HEADER
from app.core.security_headers import API_CONTENT_SECURITY_POLICY, SECURITY_HEADERS
from app.db import session as db_session_module
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


@pytest.mark.parametrize(
    ("path", "expected_fields"),
    [
        ("/", {"service", "status", "health_url"}),
        ("/api/health", {"status", "service", "environment", "timestamp"}),
        ("/api/version", {"service", "version"}),
    ],
)
def test_public_metadata_endpoints_are_database_independent_and_use_api_headers(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    expected_fields: set[str],
) -> None:
    def fail_if_database_is_used():
        raise AssertionError("Public metadata endpoints must not access the database.")

    monkeypatch.setattr(
        db_session_module,
        "get_session_factory",
        fail_if_database_is_used,
    )

    response = client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].split(";", maxsplit=1)[0] == "application/json"
    assert set(response.json()) == expected_fields
    request_id = UUID(response.headers[REQUEST_ID_HEADER])
    assert request_id.version == 4
    assert str(request_id) == response.headers[REQUEST_ID_HEADER]
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert response.headers["Content-Security-Policy"] == API_CONTENT_SECURITY_POLICY
    assert "Access-Control-Allow-Origin" not in response.headers
