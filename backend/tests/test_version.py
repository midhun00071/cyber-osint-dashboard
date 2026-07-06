import importlib

from fastapi.testclient import TestClient

from app.core.config import get_settings


def test_version_endpoint_returns_safe_public_metadata(monkeypatch) -> None:
    import app.main as main_module

    with monkeypatch.context() as environment:
        environment.setenv("APP_NAME", "Cyber OSINT Dashboard")
        environment.setenv("APP_VERSION", "0.1.0")
        get_settings.cache_clear()

        reloaded_main = importlib.reload(main_module)

        response = TestClient(reloaded_main.app).get("/api/version")

        assert response.status_code == 200
        assert response.json() == {
            "service": "Cyber OSINT Dashboard",
            "version": "0.1.0",
        }

    get_settings.cache_clear()
    importlib.reload(main_module)


def test_version_endpoint_does_not_return_sensitive_fields() -> None:
    from app.main import app

    response = TestClient(app).get("/api/version")

    assert response.status_code == 200

    data = response.json()

    assert set(data) == {"service", "version"}

    sensitive_fields = {
        "database_url",
        "postgres_user",
        "postgres_password",
        "nvd_api_key",
        "environment",
        "hostname",
        "ip_address",
        "git_remote",
        "commit",
        "path",
        "dependencies",
    }
    assert sensitive_fields.isdisjoint(data)


def test_fastapi_metadata_uses_configured_version(monkeypatch) -> None:
    import app.main as main_module

    with monkeypatch.context() as environment:
        environment.setenv("APP_VERSION", "9.8.7")
        get_settings.cache_clear()

        reloaded_main = importlib.reload(main_module)

        assert reloaded_main.app.version == "9.8.7"

        response = TestClient(reloaded_main.app).get("/api/version")

        assert response.status_code == 200
        assert response.json()["version"] == "9.8.7"

    get_settings.cache_clear()
    importlib.reload(main_module)
