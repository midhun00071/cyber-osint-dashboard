import logging
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.routes import health as health_route_module
from app.api.v1.query_validation import VALIDATION_ERROR_DETAIL
from app.core.config import Settings
from app.core.request_context import REQUEST_ID_HEADER, RequestContextMiddleware
from app.core.security_headers import (
    API_CONTENT_SECURITY_POLICY,
    SECURITY_HEADERS,
    SecurityHeadersMiddleware,
)
from app.db import session as db_session_module
from app.main import ExactHostMiddleware, INVALID_HOST_RESPONSE, app

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
    assert data["environment"] == "not-disclosed"
    assert data["environment"] not in {"local", "test", "staging", "production"}
    assert "timestamp" in data


def build_exact_host_application(configured_hosts: str) -> FastAPI:
    protected_settings = Settings(
        _env_file=None,
        APP_ENV="production",
        BACKEND_CORS_ALLOWED_ORIGINS="https://dashboard.example.invalid",
        BACKEND_TRUSTED_HOSTS=configured_hosts,
    )
    protected_app = FastAPI()
    protected_app.include_router(health_route_module.router, prefix="/api")
    protected_app.add_middleware(
        ExactHostMiddleware,
        allowed_hosts=protected_settings.trusted_hosts_list,
    )
    protected_app.add_middleware(RequestContextMiddleware)
    protected_app.add_middleware(SecurityHeadersMiddleware)
    return protected_app


async def invoke_raw_asgi_request(
    application: FastAPI,
    headers: list[tuple[bytes, bytes]],
) -> tuple[int, bytes, dict[bytes, bytes]]:
    sent_messages: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        sent_messages.append(message)

    await application(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/health",
            "raw_path": b"/api/health",
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "client": ("127.0.0.1", 40000),
            "server": ("127.0.0.1", 8000),
            "state": {},
        },
        receive,
        send,
    )

    start = next(message for message in sent_messages if message["type"] == "http.response.start")
    body = b"".join(
        message.get("body", b"")
        for message in sent_messages
        if message["type"] == "http.response.body"
    )
    response_headers = {name.lower(): value for name, value in start["headers"]}
    return start["status"], body, response_headers


def assert_fixed_host_rejection(
    status_code: int,
    body: bytes,
    headers: dict[bytes, bytes],
) -> None:
    assert status_code == 400
    assert body == INVALID_HOST_RESPONSE.encode("ascii")
    assert b"location" not in headers
    assert REQUEST_ID_HEADER.lower().encode("ascii") in headers
    for name, value in SECURITY_HEADERS.items():
        assert headers[name.lower().encode("ascii")] == value.encode("ascii")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("configured_host", "requested_host"),
    [
        ("api.example.invalid", b"api.example.invalid"),
        ("api.example.invalid", b"API.EXAMPLE.INVALID"),
        ("api.example.invalid", b"api.example.invalid:1"),
        ("api.example.invalid", b"Api.Example.Invalid:8000"),
        ("api.example.invalid", b"api.example.invalid:65535"),
        ("192.0.2.10", b"192.0.2.10"),
        ("192.0.2.10", b"192.0.2.10:8000"),
        ("2001:db8::10", b"[2001:db8::10]"),
        ("2001:db8::10", b"[2001:db8::10]:8000"),
    ],
)
async def test_runtime_exact_host_boundary_accepts_normalized_hosts(
    configured_host: str,
    requested_host: bytes,
) -> None:
    protected_app = build_exact_host_application(configured_host)

    status_code, _body, _headers = await invoke_raw_asgi_request(
        protected_app,
        [(b"host", requested_host)],
    )

    assert status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "requested_host",
    [
        b"",
        b"unconfigured.example.invalid",
        b"sub.api.example.invalid",
        b"api.example.invalid:",
        b"api.example.invalid:0",
        b"api.example.invalid:65536",
        b"api.example.invalid:evil",
        b"api.example.invalid:443:evil",
        b"user@api.example.invalid",
        b"https://api.example.invalid",
        b"api.example.invalid/path",
        b"api.example.invalid,evil.example.invalid",
        b"2001:db8::10",
        b"[2001:db8::zz]",
        b"[2001:db8::10",
        b"127.1",
        b"2130706433",
        b"0x7f000001",
        b"api.example.invalid\r.evil",
        b"api.example.invalid\n.evil",
        b"api.example.invalid\t.evil",
        b"api.example.invalid\x00.evil",
        "api.example.invalid\u200b.evil".encode("utf-8"),
        b"a" * 260,
    ],
)
async def test_runtime_exact_host_boundary_rejects_malformed_values_safely(
    requested_host: bytes,
    caplog: pytest.LogCaptureFixture,
) -> None:
    protected_app = build_exact_host_application("api.example.invalid")

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="app.request"):
        status_code, body, headers = await invoke_raw_asgi_request(
            protected_app,
            [(b"host", requested_host)],
        )

    assert_fixed_host_rejection(status_code, body, headers)
    captured_logs = "\n".join(record.getMessage() for record in caplog.records)
    rejected_text = requested_host.decode("utf-8", errors="ignore")
    if rejected_text:
        assert rejected_text not in body.decode("ascii")
        assert rejected_text not in captured_logs


@pytest.mark.asyncio
async def test_runtime_exact_host_boundary_rejects_missing_and_duplicate_headers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    protected_app = build_exact_host_application("api.example.invalid")

    for raw_headers, prohibited_values in (
        ([], []),
        (
            [
                (b"host", b"api.example.invalid"),
                (b"Host", b"duplicate.example.invalid"),
            ],
            ["api.example.invalid", "duplicate.example.invalid"],
        ),
    ):
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="app.request"):
            status_code, body, headers = await invoke_raw_asgi_request(
                protected_app,
                raw_headers,
            )

        assert_fixed_host_rejection(status_code, body, headers)
        captured_logs = "\n".join(record.getMessage() for record in caplog.records)
        for prohibited_value in prohibited_values:
            assert prohibited_value not in body.decode("ascii")
            assert prohibited_value not in captured_logs


@pytest.mark.asyncio
async def test_runtime_exact_host_boundary_never_redirects_to_www(
    caplog: pytest.LogCaptureFixture,
) -> None:
    protected_app = build_exact_host_application("www.api.example.invalid")

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="app.request"):
        status_code, body, headers = await invoke_raw_asgi_request(
            protected_app,
            [(b"host", b"api.example.invalid")],
        )

    assert_fixed_host_rejection(status_code, body, headers)
    assert "api.example.invalid" not in "\n".join(
        record.getMessage() for record in caplog.records
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "configured_host",
    ["api.example.invalid", "192.0.2.10", "[2001:db8::10]"],
)
async def test_healthcheck_first_normalized_trusted_host_reaches_health_route(
    configured_host: str,
) -> None:
    protected_settings = Settings(
        _env_file=None,
        APP_ENV="production",
        BACKEND_CORS_ALLOWED_ORIGINS="https://dashboard.example.invalid",
        BACKEND_TRUSTED_HOSTS=configured_host,
    )
    protected_app = build_exact_host_application(configured_host)

    status_code, _body, _headers = await invoke_raw_asgi_request(
        protected_app,
        [
            (
                b"host",
                protected_settings.trusted_hosts_list[0].encode("ascii"),
            )
        ],
    )

    assert status_code == 200


def test_health_endpoint_never_exposes_configured_secret_canary(monkeypatch) -> None:
    canary = "synthetic-test-secret"
    secret_settings = Settings(
        _env_file=None,
        APP_NAME="Synthetic Service",
        NVD_API_KEY=canary,
        POSTGRES_PASSWORD=canary,
    )
    monkeypatch.setattr(
        health_route_module,
        "get_settings",
        lambda: secret_settings,
    )

    response = client.get("/api/health")

    assert response.status_code == 200
    assert canary not in response.text


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
