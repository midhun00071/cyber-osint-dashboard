from collections.abc import Iterator

from fastapi.testclient import TestClient
import pytest

from app.db.session import get_db_session
from app.main import app
from app.security.dependencies import require_csrf_json
from app.services.authentication_service import AuthenticationService
from tests.c06_auth_test_support import principal


def test_public_and_protected_route_boundary() -> None:
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/health").status_code == 200
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401
        assert response.json() == {"detail": "Authentication required."}


def test_login_requires_exact_origin_json_and_forbids_unknown_fields() -> None:
    canary = "do-not-echo-password"
    with TestClient(app) as client:
        denied = client.post("/api/v1/auth/login", json={"username": "analyst", "password": canary})
        assert denied.status_code == 403
        response = client.post("/api/v1/auth/login", headers={"Origin": "http://localhost:3000"}, json={"username": "analyst", "password": canary, "provider_key": "local"})
        assert response.status_code == 422
        assert canary not in response.text and "provider_key" not in response.text
        assert response.headers["cache-control"] == "no-store"


class _PasswordPolicyRouteSession:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0
        self.pending = ["mutation-canary"]

    def execute(self, _statement):
        raise AssertionError("password-policy rejection must precede database access")

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1
        self.pending.clear()


@pytest.mark.parametrize(
    "new_password",
    [
        "ValidPrefix!234\x00password-canary",
        "ValidPrefix!234\npassword-canary",
        "ValidPrefix!234\x01password-canary",
    ],
)
def test_password_policy_violations_are_real_safe_http_400_rejections(new_password, caplog) -> None:
    db = _PasswordPolicyRouteSession()

    def override_db() -> Iterator[_PasswordPolicyRouteSession]:
        try:
            yield db
        finally:
            db.rollback()

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[require_csrf_json] = principal
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post(
                "/api/v1/auth/change-password",
                headers={
                    "Origin": "http://localhost:3000",
                    "X-CSRF-Token": "x" * 43,
                },
                cookies={"alpha_csrf": "x" * 43},
                json={
                    "current_password": "CurrentPassword!234",
                    "new_password": new_password,
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert response.json() == {"detail": "The password could not be changed."}
    assert response.headers["Cache-Control"] == "no-store"
    assert db.commits == 0
    assert db.rollbacks >= 1
    assert db.pending == []
    rendered = response.text + caplog.text
    assert "password-canary" not in rendered
    assert new_password not in rendered


def test_unexpected_password_hashing_failure_remains_sanitized_http_500(monkeypatch) -> None:
    db = _PasswordPolicyRouteSession()
    canary = "unexpected-hashing-failure password-canary"

    def override_db() -> Iterator[_PasswordPolicyRouteSession]:
        try:
            yield db
        finally:
            db.rollback()

    monkeypatch.setattr(
        AuthenticationService,
        "change_password",
        lambda _self, *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(canary)),
    )
    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[require_csrf_json] = principal
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post(
                "/api/v1/auth/change-password",
                headers={
                    "Origin": "http://localhost:3000",
                    "X-CSRF-Token": "x" * 43,
                },
                cookies={"alpha_csrf": "x" * 43},
                json={
                    "current_password": "CurrentPassword!234",
                    "new_password": "ReplacementPassword!567",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 500
    assert response.json() == {"detail": "The password could not be changed."}
    assert response.headers["Cache-Control"] == "no-store"
    assert canary not in response.text
    assert db.commits == 0
    assert db.rollbacks >= 1
    assert db.pending == []
