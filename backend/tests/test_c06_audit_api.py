from collections.abc import Iterator

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import get_db_session
from app.main import app
from app.security.dependencies import require_audit_read
from app.services.audit_query_service import AuditQueryError, AuditQueryService
from tests.c06_auth_test_support import principal


class _FailingAuditSession:
    def execute(self, _statement):
        raise SQLAlchemyError("SELECT audit_secret FROM audit_events postgresql://host-canary")


@pytest.fixture
def authorized_audit() -> Iterator[None]:
    app.dependency_overrides[require_audit_read] = principal
    yield
    app.dependency_overrides.clear()


def test_audit_search_is_administrator_protected_and_has_no_mutation_route() -> None:
    operations = app.openapi()["paths"]["/api/v1/audit/events"]
    assert set(operations) == {"get"}
    with TestClient(app) as client:
        response = client.get("/api/v1/audit/events")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}


@pytest.mark.parametrize(
    "query",
    [
        "action=not.allowed",
        "outcome=unknown",
        "correlation_id=not-a-uuid",
        "occurred_from=not-a-time",
        "occurred_from=2026-08-05T10:00:00",
        "occurred_from=2026-08-05T12:00:00Z&occurred_to=2026-08-05T11:00:00Z",
        "occurred_from=2025-01-01T00:00:00Z&occurred_to=2026-08-05T00:00:00Z",
        "limit=not-an-integer",
        f"limit={'9' * 5000}",
        "limit=0",
        "limit=101",
        "offset=-1",
        "offset=100001",
    ],
)
def test_invalid_audit_filters_receive_fixed_400_without_query(monkeypatch, authorized_audit, query) -> None:
    called = False

    def unexpected_query(_self, _filters):
        nonlocal called
        called = True
        raise AssertionError("query service must not run")

    monkeypatch.setattr(AuditQueryService, "list_events", unexpected_query)
    with TestClient(app) as client:
        response = client.get(f"/api/v1/audit/events?{query}")
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid audit query."}
    assert response.headers["Cache-Control"] == "no-store"
    assert called is False


def test_audit_sqlalchemy_failure_is_fixed_sanitized_500(authorized_audit) -> None:
    app.dependency_overrides[get_db_session] = lambda: _FailingAuditSession()
    with TestClient(app) as client:
        response = client.get("/api/v1/audit/events")
    assert response.status_code == 500
    assert response.json() == {"detail": "An unexpected server error occurred."}
    assert response.headers["Cache-Control"] == "no-store"
    for prohibited in ("SELECT", "audit_secret", "postgresql://", "host-canary", "traceback"):
        assert prohibited not in response.text


def test_injected_audit_query_service_failure_is_fixed_sanitized_500(monkeypatch, authorized_audit) -> None:
    canary = "query-service-canary SELECT password FROM auth_users"
    monkeypatch.setattr(AuditQueryService, "list_events", lambda _self, _filters: (_ for _ in ()).throw(AuditQueryError(canary)))
    with TestClient(app) as client:
        response = client.get("/api/v1/audit/events")
    assert response.status_code == 500
    assert response.json() == {"detail": "An unexpected server error occurred."}
    assert response.headers["Cache-Control"] == "no-store"
    assert canary not in response.text and "SELECT password" not in response.text


def test_audit_authorization_precedes_query_execution(monkeypatch) -> None:
    called = False

    def query(_self, _filters):
        nonlocal called
        called = True
        return [], 0

    monkeypatch.setattr(AuditQueryService, "list_events", query)
    with TestClient(app) as client:
        response = client.get("/api/v1/audit/events")
    assert response.status_code == 401
    assert called is False


def test_valid_audit_query_is_bounded_ordered_and_no_store(monkeypatch, authorized_audit) -> None:
    captured = []
    monkeypatch.setattr(AuditQueryService, "list_events", lambda _self, filters: captured.append(filters) or ([], 0))
    with TestClient(app) as client:
        response = client.get("/api/v1/audit/events?limit=25&offset=5&action=auth.login&outcome=success&correlation_id=11111111-1111-4111-8111-111111111111&occurred_from=2026-08-05T10:00:00Z&occurred_to=2026-08-05T11:00:00Z")
    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "limit": 25, "offset": 5}
    assert response.headers["Cache-Control"] == "no-store"
    assert len(captured) == 1
    assert captured[0].limit == 25 and captured[0].offset == 5
