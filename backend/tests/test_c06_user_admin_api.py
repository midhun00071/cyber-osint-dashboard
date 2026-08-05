from collections.abc import Iterator
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import get_db_session
from app.main import app
from app.security.dependencies import require_csrf_json, require_user_manage, require_user_read
from app.services.user_admin_service import UserAdminService, UserAdminServiceError, UserConflictError, UserInputError, UserNotFoundError
from app.security.contracts import RoleKey
from tests.c06_auth_test_support import NOW, principal


VALID_CREATE = {
    "username": "new.user",
    "display_name": "New User",
    "password": "MassAssignmentPassword!",
    "role": "viewer",
}


class _RouteSession:
    def __init__(self):
        self.rollbacks = 0
        self.commits = 0
        self.pending = ["pending-canary"]
        self.fail_commit = False

    def rollback(self):
        self.rollbacks += 1
        self.pending.clear()

    def commit(self):
        self.commits += 1
        if self.fail_commit:
            raise SQLAlchemyError("transaction-failure-canary")


@pytest.fixture
def route_session() -> Iterator[_RouteSession]:
    db = _RouteSession()

    def override_db():
        try:
            yield db
        finally:
            db.rollback()

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[require_user_manage] = principal
    app.dependency_overrides[require_user_read] = principal
    app.dependency_overrides[require_csrf_json] = principal
    yield db
    app.dependency_overrides.clear()


def test_admin_create_rejects_mass_assignment_before_service_lookup() -> None:
    app.dependency_overrides[require_user_manage] = principal
    app.dependency_overrides[require_csrf_json] = principal
    canary = "MassAssignmentPassword!"
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/admin/users", headers={"Origin": "http://localhost:3000", "X-CSRF-Token": "x" * 43}, cookies={"alpha_csrf": "x" * 43}, json={"username": "new.user", "display_name": "New User", "password": canary, "role": "viewer", "status": "active"})
        assert response.status_code == 422
        assert canary not in response.text and "status" not in response.text
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_detail"),
    [
        (UserInputError("Invalid administrator input."), 400, "Invalid request."),
        (UserConflictError("safe conflict"), 409, "The user could not be created."),
        (UserAdminServiceError("database-url-canary"), 500, "An unexpected server error occurred."),
        (SQLAlchemyError("SELECT secret FROM auth_users database-url-canary"), 500, "An unexpected server error occurred."),
    ],
)
def test_admin_create_maps_controlled_errors_and_rolls_back(monkeypatch, route_session, error, expected_status, expected_detail) -> None:
    monkeypatch.setattr(UserAdminService, "create_user", lambda _self, **_kwargs: (_ for _ in ()).throw(error))
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/api/v1/admin/users", headers={"Origin": "http://localhost:3000", "X-CSRF-Token": "x" * 43}, cookies={"alpha_csrf": "x" * 43}, json=VALID_CREATE)

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}
    assert response.headers["Cache-Control"] == "no-store"
    assert route_session.rollbacks >= 1 and route_session.pending == []
    assert "database-url-canary" not in response.text
    assert "SELECT secret" not in response.text


def test_admin_missing_user_remains_generic_404(monkeypatch, route_session) -> None:
    monkeypatch.setattr(UserAdminService, "get_user", lambda _self, _public_id: (_ for _ in ()).throw(UserNotFoundError("target-user-canary")))
    with TestClient(app) as client:
        response = client.get("/api/v1/admin/users/11111111-1111-4111-8111-111111111111")
    assert response.status_code == 404
    assert response.json() == {"detail": "The requested user was not found."}
    assert "target-user-canary" not in response.text


def test_unexpected_admin_programming_failure_is_sanitized_and_dependency_rolls_back(monkeypatch, route_session) -> None:
    canary = "programming-error database-url-canary password-canary"
    monkeypatch.setattr(UserAdminService, "create_user", lambda _self, **_kwargs: (_ for _ in ()).throw(RuntimeError(canary)))
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/api/v1/admin/users", headers={"Origin": "http://localhost:3000", "X-CSRF-Token": "x" * 43}, cookies={"alpha_csrf": "x" * 43}, json=VALID_CREATE)
    assert response.status_code == 500
    assert response.json() == {"detail": "An unexpected server error occurred."}
    assert canary not in response.text
    assert route_session.rollbacks >= 1 and route_session.pending == []


def test_expiry_change_commit_failure_rolls_back_partial_mutation(monkeypatch, route_session) -> None:
    target_public_id = uuid4()
    route_session.fail_commit = True

    def changed_expiry(_self, **_kwargs):
        route_session.pending.append("expiry-mutation")
        return SimpleNamespace(
            public_id=target_public_id,
            display_name="Expiry Test User",
            username="expiry.user",
            status="active",
            role=RoleKey.VIEWER,
            permissions=("content.read", "source.read"),
            account_expires_at=NOW + timedelta(days=1),
            last_authenticated_at=None,
            created_at=NOW - timedelta(days=30),
            updated_at=NOW,
        )

    monkeypatch.setattr(UserAdminService, "change_expiry", changed_expiry)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.patch(
            f"/api/v1/admin/users/{target_public_id}/expiry",
            headers={
                "Origin": "http://localhost:3000",
                "X-CSRF-Token": "x" * 43,
            },
            cookies={"alpha_csrf": "x" * 43},
            json={"account_expires_at": (NOW + timedelta(days=1)).isoformat()},
        )

    assert response.status_code == 500
    assert response.json() == {"detail": "An unexpected server error occurred."}
    assert "transaction-failure-canary" not in response.text
    assert route_session.commits == 1
    assert route_session.rollbacks >= 1
    assert route_session.pending == []
