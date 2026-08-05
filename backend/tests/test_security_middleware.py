from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.query_validation import VALIDATION_ERROR_DETAIL
from app.core.request_context import REQUEST_ID_HEADER
from app.core.security_headers import API_CONTENT_SECURITY_POLICY, SECURITY_HEADERS
from app.db.session import get_db_session
from app.main import app
from app.security.dependencies import require_content_read
from tests.c06_auth_test_support import principal


ALLOWED_ORIGIN = "http://localhost:3000"


class EmptyScalarResult:
    def all(self) -> list:
        return []

    def one_or_none(self):
        return None


class EmptyExecuteResult:
    def scalars(self) -> EmptyScalarResult:
        return EmptyScalarResult()


class EmptySession:
    def execute(self, _statement) -> EmptyExecuteResult:
        return EmptyExecuteResult()


class FailingSession:
    def execute(self, _statement):
        raise SQLAlchemyError("synthetic database detail")


@pytest.fixture
def client() -> Iterator[TestClient]:
    app.dependency_overrides[get_db_session] = lambda: EmptySession()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def assert_api_security_headers(response) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert response.headers["Content-Security-Policy"] == API_CONTENT_SECURITY_POLICY
    assert "Strict-Transport-Security" not in response.headers


def assert_request_id(response) -> UUID:
    request_id = UUID(response.headers[REQUEST_ID_HEADER])
    assert request_id.version == 4
    assert str(request_id) == response.headers[REQUEST_ID_HEADER]
    return request_id


def test_allowed_origin_get_uses_exact_credentialed_cors(client: TestClient) -> None:
    response = client.get("/api/health", headers={"Origin": ALLOWED_ORIGIN})

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["Access-Control-Allow-Origin"] == ALLOWED_ORIGIN
    assert response.headers["Access-Control-Allow-Origin"] != "*"
    assert "Origin" in response.headers["Vary"]
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert_request_id(response)
    assert_api_security_headers(response)


def test_allowed_preflight_is_restricted_and_has_security_headers(
    client: TestClient,
) -> None:
    response = client.options(
        "/api/health",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Accept",
        },
    )

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == ALLOWED_ORIGIN
    assert response.headers["Access-Control-Allow-Methods"] == (
        "GET, POST, PATCH, OPTIONS"
    )
    allowed_headers = {
        header.strip().lower()
        for header in response.headers["Access-Control-Allow-Headers"].split(",")
    }
    assert allowed_headers == {
        "accept",
        "accept-language",
        "content-language",
        "content-type",
        "x-csrf-token",
    }
    assert {"authorization", "x-unsupported", "*"}.isdisjoint(allowed_headers)
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert_request_id(response)
    assert_api_security_headers(response)


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:3000.evil.test",
        "http://evil-localhost:3000",
        "https://localhost:3000",
        "http://localhost:3001",
        "not-an-origin",
    ],
)
def test_disallowed_or_deceptive_origins_receive_no_cors_grant(
    client: TestClient,
    origin: str,
) -> None:
    response = client.get("/api/health", headers={"Origin": origin})

    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers
    assert_api_security_headers(response)


def test_disallowed_preflight_fails_without_origin_grant(client: TestClient) -> None:
    response = client.options(
        "/api/health",
        headers={
            "Origin": "https://dashboard.example.com.evil.test",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Accept",
        },
    )

    assert response.status_code == 400
    assert "Access-Control-Allow-Origin" not in response.headers
    assert_api_security_headers(response)


def test_request_without_origin_remains_an_ordinary_client_request(
    client: TestClient,
) -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers
    assert_api_security_headers(response)


@pytest.mark.parametrize("method", ["GET", "POST", "PATCH", "OPTIONS"])
def test_c06_methods_are_granted_by_preflight(
    client: TestClient,
    method: str,
) -> None:
    response = client.options(
        "/api/health",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": method,
        },
    )

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == ALLOWED_ORIGIN
    assert response.headers["Access-Control-Allow-Methods"] == (
        "GET, POST, PATCH, OPTIONS"
    )
    assert response.headers["Access-Control-Allow-Credentials"] == "true"


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
def test_unsupported_methods_are_not_granted_by_preflight(
    client: TestClient,
    method: str,
) -> None:
    response = client.options(
        "/api/health",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": method,
        },
    )

    assert response.status_code == 400
    assert response.headers["Access-Control-Allow-Methods"] == (
        "GET, POST, PATCH, OPTIONS"
    )
    assert method not in response.headers["Access-Control-Allow-Methods"]


def test_unsupported_header_is_not_granted_by_preflight(client: TestClient) -> None:
    response = client.options(
        "/api/health",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Unsupported",
        },
    )

    assert response.status_code == 400
    assert "*" not in response.headers["Access-Control-Allow-Headers"]
    assert "X-Unsupported" not in response.headers["Access-Control-Allow-Headers"]


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/api/health",
        "/api/version",
    ],
)
def test_public_get_endpoints_remain_available_with_security_headers(
    client: TestClient,
    path: str,
) -> None:
    response = client.get(path)

    assert response.status_code == 200
    assert_request_id(response)
    assert_api_security_headers(response)
    assert "server" not in response.headers


def test_login_remains_public_subject_to_origin_and_request_validation(
    client: TestClient,
) -> None:
    canary = "do-not-echo-password"
    missing_origin = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": canary},
    )
    invalid_request = client.post(
        "/api/v1/auth/login",
        headers={"Origin": ALLOWED_ORIGIN},
        json={
            "username": "analyst",
            "password": canary,
            "provider_key": "local",
        },
    )

    assert missing_origin.status_code == 403
    assert invalid_request.status_code == 422
    assert invalid_request.json() == {"detail": VALIDATION_ERROR_DETAIL}
    assert canary not in missing_origin.text
    assert canary not in invalid_request.text
    assert "provider_key" not in invalid_request.text
    assert invalid_request.headers["Access-Control-Allow-Origin"] == ALLOWED_ORIGIN
    assert invalid_request.headers["Access-Control-Allow-Credentials"] == "true"
    for response in (missing_origin, invalid_request):
        assert_request_id(response)
        assert_api_security_headers(response)


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/articles",
        f"/api/v1/articles/{uuid4()}",
        "/api/v1/dashboard/summary",
        "/api/v1/intelligence/items",
        f"/api/v1/intelligence/items/{uuid4()}",
    ],
)
def test_anonymous_content_requests_receive_fixed_authentication_response(
    client: TestClient,
    path: str,
) -> None:
    response = client.get(path)

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}
    assert_request_id(response)
    assert_api_security_headers(response)
    assert "server" not in response.headers


def test_handled_500_is_sanitized_and_keeps_cors_and_security_headers(
    client: TestClient,
) -> None:
    app.dependency_overrides[get_db_session] = lambda: FailingSession()
    app.dependency_overrides[require_content_read] = lambda: principal()

    try:
        response = client.get(
            "/api/v1/intelligence/items",
            headers={"Origin": ALLOWED_ORIGIN},
        )
    finally:
        app.dependency_overrides.pop(require_content_read, None)

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to load intelligence items."}
    assert response.headers["Access-Control-Allow-Origin"] == ALLOWED_ORIGIN
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert_request_id(response)
    assert_api_security_headers(response)
    for prohibited in (
        "synthetic database detail",
        "traceback",
        "postgresql://",
        "DATABASE_URL",
    ):
        assert prohibited not in response.text


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_enabled_documentation_routes_remain_renderable(path: str) -> None:
    with TestClient(app) as test_client:
        response = test_client.get(path)

    assert response.status_code == 200
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert "Content-Security-Policy" not in response.headers
