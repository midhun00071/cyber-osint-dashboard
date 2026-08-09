from fastapi.testclient import TestClient

from app.main import app
from app.security.contracts import Permission, ROLE_PERMISSIONS, RoleKey


def test_exact_role_permission_matrix() -> None:
    assert ROLE_PERMISSIONS[RoleKey.VIEWER] == {Permission.CONTENT_READ, Permission.SOURCE_READ}
    assert ROLE_PERMISSIONS[RoleKey.ANALYST] == {Permission.CONTENT_READ, Permission.SOURCE_READ, Permission.ANALYSIS_USE, Permission.REPORT_READ, Permission.REPORT_EXPORT}
    assert ROLE_PERMISSIONS[RoleKey.INGESTION_OPERATOR] == {Permission.CONTENT_READ, Permission.SOURCE_READ, Permission.INGESTION_READ, Permission.INGESTION_RUN, Permission.INGESTION_RETRY, Permission.INGESTION_PAUSE}
    assert ROLE_PERMISSIONS[RoleKey.ADMINISTRATOR] == frozenset(Permission)


def test_complete_frozen_route_inventory_and_anonymous_denial() -> None:
    paths = app.openapi()["paths"]
    expected = {"/", "/api/health", "/api/version", "/api/v1/auth/login", "/api/v1/auth/me", "/api/v1/auth/logout", "/api/v1/auth/refresh", "/api/v1/auth/change-password", "/api/v1/articles", "/api/v1/articles/{public_id}", "/api/v1/dashboard/summary", "/api/v1/intelligence/items", "/api/v1/intelligence/items/{item_public_id}", "/api/v1/analysis/threat-entities", "/api/v1/analysis/threat-entities/{public_id}", "/api/v1/analysis/indicators", "/api/v1/analysis/indicators/{public_id}", "/api/v1/analysis/items/{public_id}/provenance", "/api/v1/analysis/uae-intelligence", "/api/v1/admin/users", "/api/v1/admin/users/{user_public_id}", "/api/v1/admin/users/{user_public_id}/status", "/api/v1/admin/users/{user_public_id}/role", "/api/v1/admin/users/{user_public_id}/expiry", "/api/v1/admin/users/{user_public_id}/sessions/revoke", "/api/v1/audit/events", "/api/v1/reports/catalog", "/api/v1/reports/export", "/api/v1/system/health", "/api/v1/sources", "/api/v1/sources/{source_slug}", "/api/v1/ingestion/operations/summary", "/api/v1/ingestion/cycles", "/api/v1/ingestion/runs", "/api/v1/ingestion/runs/{run_public_id}", "/api/v1/ingestion/runs/{run_public_id}/events", "/api/v1/sources/{source_slug}/runs", "/api/v1/ingestion/runs/{run_public_id}/retry", "/api/v1/sources/{source_slug}/pause", "/api/v1/sources/{source_slug}/resume", "/api/v1/sources/{source_slug}/disable", "/api/v1/sources/{source_slug}/enable"}
    assert set(paths) == expected
    with TestClient(app) as client:
        for path in ("/api/v1/articles", "/api/v1/dashboard/summary", "/api/v1/intelligence/items", "/api/v1/analysis/threat-entities", "/api/v1/analysis/indicators", "/api/v1/analysis/uae-intelligence", "/api/v1/admin/users", "/api/v1/audit/events", "/api/v1/reports/catalog", "/api/v1/system/health", "/api/v1/sources", "/api/v1/ingestion/operations/summary", "/api/v1/ingestion/runs"):
            assert client.get(path).status_code == 401
