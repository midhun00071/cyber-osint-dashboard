from fastapi.testclient import TestClient

from app.main import app


def test_c07_routes_are_anonymous_deny_by_default_and_no_store() -> None:
    with TestClient(app) as client:
        for path in (
            "/api/v1/sources",
            "/api/v1/ingestion/operations/summary",
            "/api/v1/ingestion/cycles",
            "/api/v1/ingestion/runs",
        ):
            response = client.get(path)
            assert response.status_code == 401
            assert response.headers["cache-control"] == "no-store"


def test_c07_openapi_freezes_empty_mutation_bodies_and_manual_idempotency() -> None:
    document = app.openapi()
    manual = document["paths"]["/api/v1/sources/{source_slug}/runs"]["post"]
    retry = document["paths"]["/api/v1/ingestion/runs/{run_public_id}/retry"]["post"]
    header = next(item for item in manual["parameters"] if item["name"] == "Idempotency-Key")
    assert header["required"] is True
    assert header["schema"]["minLength"] == 16
    assert "Idempotency-Key" not in {item["name"] for item in retry["parameters"]}
    assert manual["requestBody"]["required"] is True
    assert retry["requestBody"]["required"] is True


def test_c07_query_rejects_unknown_and_repeated_parameters_before_database_use() -> None:
    with TestClient(app) as client:
        assert client.get("/api/v1/sources?unknown=value").status_code == 422
        assert client.get("/api/v1/sources?limit=1&limit=2").status_code == 422
