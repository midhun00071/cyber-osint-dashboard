from collections.abc import Iterator

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.schemas.reports import ReportFormat, ReportType
from app.db.session import get_db_session
from app.main import app
from app.security.contracts import RoleKey
from app.security.dependencies import require_csrf_json, require_report_export, require_report_read
from app.services.report_service import GeneratedReport, ReportService
from app.services.security_audit_service import SecurityAuditService
from tests.c06_auth_test_support import principal


class Session:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


@pytest.fixture
def authorized(monkeypatch) -> Iterator[Session]:
    session = Session()
    analyst = principal(RoleKey.ANALYST)
    app.dependency_overrides[require_report_read] = lambda: analyst
    app.dependency_overrides[require_report_export] = lambda: analyst
    app.dependency_overrides[require_csrf_json] = lambda: analyst
    app.dependency_overrides[get_db_session] = lambda: session
    monkeypatch.setattr(
        ReportService,
        "generate",
        lambda *_args, **_kwargs: GeneratedReport(b"safe\n", "text/csv; charset=utf-8", "cyber-sentinel-safe.csv"),
    )
    monkeypatch.setattr(SecurityAuditService, "append", lambda *_args, **_kwargs: object())
    yield session
    app.dependency_overrides.clear()


def test_report_routes_reject_anonymous_requests() -> None:
    with TestClient(app) as client:
        assert client.get("/api/v1/reports/catalog").status_code == 401
        assert client.post("/api/v1/reports/export", json={"report_type": "uae_intelligence", "format": "csv", "limit": 1}).status_code == 401


def test_catalog_is_bounded_and_no_store(authorized) -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/reports/catalog")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["maximum_rows"] == 100
    assert {item["report_type"] for item in response.json()["reports"]} == {"uae_intelligence", "source_operations"}


def test_export_has_safe_headers_and_commits_audit(authorized) -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/reports/export", json={"report_type": "uae_intelligence", "format": "csv", "limit": 25})
    assert response.status_code == 200
    assert response.headers["Content-Disposition"] == 'attachment; filename="cyber-sentinel-safe.csv"'
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert authorized.commits == 1


def test_export_exposes_content_disposition_only_to_approved_origin(authorized) -> None:
    payload = {"report_type": "uae_intelligence", "format": "csv", "limit": 10}
    with TestClient(app) as client:
        approved = client.post(
            "/api/v1/reports/export",
            json=payload,
            headers={"Origin": "http://localhost:3000"},
        )
        unapproved = client.post(
            "/api/v1/reports/export",
            json=payload,
            headers={"Origin": "https://dashboard.example.com.evil.test"},
        )

    assert approved.status_code == 200
    assert approved.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"
    assert approved.headers["Access-Control-Expose-Headers"] == "Content-Disposition"
    assert approved.headers["Content-Disposition"] == (
        'attachment; filename="cyber-sentinel-safe.csv"'
    )
    assert unapproved.status_code == 200
    assert "Access-Control-Allow-Origin" not in unapproved.headers


@pytest.mark.parametrize(
    "payload",
    [
        {"report_type": "other", "format": "csv", "limit": 1},
        {"report_type": "uae_intelligence", "format": "html", "limit": 1},
        {"report_type": "uae_intelligence", "format": "csv", "limit": 0},
        {"report_type": "uae_intelligence", "format": "csv", "limit": 101},
        {"report_type": "uae_intelligence", "format": "csv", "limit": 1, "filename": "caller.csv"},
    ],
)
def test_export_rejects_unapproved_or_extra_input_before_generation(monkeypatch, authorized, payload) -> None:
    generated = False

    def unexpected(*_args, **_kwargs):
        nonlocal generated
        generated = True

    monkeypatch.setattr(ReportService, "generate", unexpected)
    with TestClient(app) as client:
        response = client.post("/api/v1/reports/export", json=payload)
    assert response.status_code == 422
    assert response.json() == {"detail": "Request validation failed."}
    assert generated is False


def test_audit_failure_fails_closed(monkeypatch, authorized) -> None:
    monkeypatch.setattr(SecurityAuditService, "append", lambda *_args, **_kwargs: (_ for _ in ()).throw(SQLAlchemyError("secret canary")))
    with TestClient(app) as client:
        response = client.post("/api/v1/reports/export", json={"report_type": "source_operations", "format": "pdf", "limit": 1})
    assert response.status_code == 500
    assert response.json() == {"detail": "The report could not be generated safely."}
    assert "secret canary" not in response.text
    assert authorized.rollbacks == 1
