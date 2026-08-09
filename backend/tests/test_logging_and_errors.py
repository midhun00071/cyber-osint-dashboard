from __future__ import annotations

import logging
import json
from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.query_validation import VALIDATION_ERROR_DETAIL
from app.core.config import Settings, get_settings
from app.core.logging_config import (
    APPLICATION_HANDLER_MARKER,
    APPLICATION_LOGGER_NAME,
    configure_logging,
    UtcJsonFormatter,
)
from app.core.request_context import REQUEST_ID_HEADER, UNEXPECTED_ERROR_DETAIL
from app.core.security_headers import API_CONTENT_SECURITY_POLICY, SECURITY_HEADERS
from app.db.session import get_db_session
from app.main import app
from app.security.dependencies import require_content_read


ALLOWED_ORIGIN = "http://localhost:3000"
ATTACKER_REQUEST_ID = "attacker-request-id-canary"
API_KEY_CANARY = "SUPER_SECRET_API_KEY_CANARY"
DATABASE_URL_CANARY = "postgresql://user:password@example.invalid/db"
TOKEN_CANARY = "Bearer TOP_SECRET_TOKEN_CANARY"
PAYLOAD_CANARY = "<script>alert(1)</script>"
FILESYSTEM_PATH_CANARY = r"C:\sensitive\internal\path"
EXCEPTION_CANARY = (
    f"unexpected {DATABASE_URL_CANARY} {API_KEY_CANARY} "
    f"{TOKEN_CANARY} {FILESYSTEM_PATH_CANARY} {PAYLOAD_CANARY}"
)


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
        raise SQLAlchemyError(DATABASE_URL_CANARY)


@pytest.fixture
def client() -> Iterator[TestClient]:
    app.dependency_overrides[get_db_session] = lambda: EmptySession()
    app.dependency_overrides[require_content_read] = lambda: None
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@contextmanager
def capture_application_logs(caplog):
    request_logger = logging.getLogger("app.request")
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=request_logger.name):
        yield


def application_request_records(caplog) -> list[logging.LogRecord]:
    return [
        record
        for record in caplog.records
        if record.name == "app.request"
        and record.getMessage().startswith("event=request_")
    ]


def captured_application_text(caplog) -> str:
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == APPLICATION_LOGGER_NAME
        or record.name.startswith(f"{APPLICATION_LOGGER_NAME}.")
    )


def assert_request_id(response) -> UUID:
    request_id = UUID(response.headers[REQUEST_ID_HEADER])
    assert request_id.version == 4
    assert str(request_id) == response.headers[REQUEST_ID_HEADER]
    return request_id


def assert_api_security_headers(response) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert response.headers["Content-Security-Policy"] == API_CONTENT_SECURITY_POLICY


def test_success_uses_unique_server_generated_request_ids(
    client: TestClient,
) -> None:
    first = client.get(
        "/api/health",
        headers={REQUEST_ID_HEADER: ATTACKER_REQUEST_ID},
    )
    second = client.get("/api/health")

    first_id = assert_request_id(first)
    second_id = assert_request_id(second)
    assert first_id != second_id
    assert first.headers[REQUEST_ID_HEADER] != ATTACKER_REQUEST_ID
    assert_api_security_headers(first)


@pytest.mark.parametrize(
    ("path", "expected_status", "expected_body"),
    [
        (
            "/api/v1/articles?published_from=2026-02-01&published_to=2026-01-01",
            400,
            {"detail": "Invalid article date range."},
        ),
        (
            f"/api/v1/intelligence/items/{uuid4()}",
            404,
            {"detail": "The requested intelligence item was not found."},
        ),
        (
            "/api/health?unknown=value",
            422,
            {"detail": VALIDATION_ERROR_DETAIL},
        ),
    ],
)
def test_expected_errors_keep_body_security_headers_and_request_id(
    client: TestClient,
    path: str,
    expected_status: int,
    expected_body: dict[str, str],
) -> None:
    response = client.get(path)

    assert response.status_code == expected_status
    assert response.json() == expected_body
    assert_request_id(response)
    assert_api_security_headers(response)


def test_handled_500_keeps_sanitized_body_and_headers(client: TestClient) -> None:
    app.dependency_overrides[get_db_session] = lambda: FailingSession()

    response = client.get(
        "/api/v1/intelligence/items",
        headers={"Origin": ALLOWED_ORIGIN},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to load intelligence items."}
    assert_request_id(response)
    assert_api_security_headers(response)
    assert response.headers["Access-Control-Allow-Origin"] == ALLOWED_ORIGIN
    assert DATABASE_URL_CANARY not in response.text


def test_allowed_preflight_receives_request_id_and_preserves_cors(
    client: TestClient,
) -> None:
    response = client.options(
        "/api/health",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Accept",
            REQUEST_ID_HEADER: ATTACKER_REQUEST_ID,
        },
    )

    assert response.status_code == 200
    assert_request_id(response)
    assert response.headers[REQUEST_ID_HEADER] != ATTACKER_REQUEST_ID
    assert response.headers["Access-Control-Allow-Origin"] == ALLOWED_ORIGIN
    assert response.headers["Access-Control-Allow-Methods"] == "GET, POST, PATCH, OPTIONS"
    assert_api_security_headers(response)


def test_completion_log_uses_allow_list_and_excludes_request_data(
    client: TestClient,
    caplog,
) -> None:
    raw_public_id = str(uuid4())
    with capture_application_logs(caplog):
        response = client.request(
            "GET",
            f"/api/v1/intelligence/items/{raw_public_id}?unknown={API_KEY_CANARY}",
            headers={
                "Authorization": TOKEN_CANARY,
                "Cookie": f"session={API_KEY_CANARY}",
                "X-Database-Canary": DATABASE_URL_CANARY,
                REQUEST_ID_HEADER: ATTACKER_REQUEST_ID,
            },
            content=PAYLOAD_CANARY,
        )

    assert response.status_code == 422
    records = application_request_records(caplog)
    assert len(records) == 1
    message = records[0].getMessage()
    assert "event=request_completed" in message
    assert f"request_id={response.headers[REQUEST_ID_HEADER]}" in message
    assert "method=GET" in message
    assert "route=/api/v1/intelligence/items/{item_public_id}" in message
    assert "status_code=422" in message
    assert "duration_ms=" in message
    application_text = captured_application_text(caplog)
    for prohibited in (
        raw_public_id,
        ATTACKER_REQUEST_ID,
        API_KEY_CANARY,
        DATABASE_URL_CANARY,
        TOKEN_CANARY,
        PAYLOAD_CANARY,
        "unknown=",
        "Authorization",
        "Cookie",
    ):
        assert prohibited not in application_text
        assert prohibited not in response.text


def test_handled_server_failure_logs_one_safe_completion_event(
    client: TestClient,
    caplog,
) -> None:
    app.dependency_overrides[get_db_session] = lambda: FailingSession()

    with capture_application_logs(caplog):
        response = client.get("/api/v1/intelligence/items")

    records = application_request_records(caplog)
    assert len(records) == 1
    message = records[0].getMessage()
    assert "event=request_completed" in message
    assert "status_code=500" in message
    assert "error_category=handled_server_error" in message
    assert f"request_id={response.headers[REQUEST_ID_HEADER]}" in message
    assert DATABASE_URL_CANARY not in captured_application_text(caplog)


def test_unexpected_exception_is_sanitized_correlated_and_logged_once(
    client: TestClient,
    caplog,
) -> None:
    def fail_dependency():
        raise RuntimeError(EXCEPTION_CANARY)

    app.dependency_overrides[get_db_session] = fail_dependency

    with capture_application_logs(caplog):
        response = client.get(
            "/api/v1/articles",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Authorization": TOKEN_CANARY,
                REQUEST_ID_HEADER: ATTACKER_REQUEST_ID,
            },
        )

    assert response.status_code == 500
    assert response.json() == {"detail": UNEXPECTED_ERROR_DETAIL}
    request_id = assert_request_id(response)
    assert_api_security_headers(response)
    assert response.headers["Access-Control-Allow-Origin"] == ALLOWED_ORIGIN

    records = application_request_records(caplog)
    assert len(records) == 1
    message = records[0].getMessage()
    assert "event=request_failed" in message
    assert f"request_id={request_id}" in message
    assert "method=GET" in message
    assert "route=/api/v1/articles" in message
    assert "status_code=500" in message
    assert "error_category=unexpected_exception" in message
    application_text = captured_application_text(caplog)

    for prohibited in (
        EXCEPTION_CANARY,
        DATABASE_URL_CANARY,
        API_KEY_CANARY,
        TOKEN_CANARY,
        FILESYSTEM_PATH_CANARY,
        PAYLOAD_CANARY,
        ATTACKER_REQUEST_ID,
        "RuntimeError",
        "Traceback",
    ):
        assert prohibited not in response.text
        assert prohibited not in application_text


def test_log_level_defaults_and_supported_values_are_normalized(
    monkeypatch,
) -> None:
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.delenv("DEBUG", raising=False)
    get_settings.cache_clear()

    assert Settings(_env_file=None).log_level == "INFO"
    assert Settings(_env_file=None, LOG_LEVEL=" warning ").log_level == "WARNING"
    production = Settings(
        _env_file=None,
        APP_ENV="production",
        BACKEND_CORS_ALLOWED_ORIGINS="https://dashboard.example.com",
        BACKEND_TRUSTED_HOSTS="api.example.invalid",
        AUTH_COOKIE_SECURE=True,
    )
    assert production.log_level == "INFO"
    assert production.debug is False


def test_invalid_log_level_is_rejected_without_echoing_value() -> None:
    invalid_value = f"VERBOSE-{API_KEY_CANARY}"

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None, LOG_LEVEL=invalid_value)

    message = str(exc_info.value)
    assert "LOG_LEVEL" in message
    assert invalid_value not in message
    assert API_KEY_CANARY not in message


def test_production_rejects_debug_error_pages() -> None:
    with pytest.raises(ValidationError, match="DEBUG must be disabled"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            DEBUG=True,
            BACKEND_CORS_ALLOWED_ORIGINS="https://dashboard.example.com",
            BACKEND_TRUSTED_HOSTS="api.example.invalid",
            AUTH_COOKIE_SECURE=True,
        )


def test_repeated_logging_configuration_keeps_one_managed_handler() -> None:
    first = configure_logging("INFO")
    second = configure_logging("warning")
    third = configure_logging("INFO")

    managed_handlers = [
        handler
        for handler in third.handlers
        if getattr(handler, APPLICATION_HANDLER_MARKER, False)
    ]
    assert first is second is third
    assert len(managed_handlers) == 1
    assert third.level == logging.INFO
    assert managed_handlers[0].level == logging.INFO
    assert third.propagate is False
    assert logging.getLogger("uvicorn.access").disabled is True


def test_json_formatter_emits_only_allow_listed_structured_fields() -> None:
    record = logging.LogRecord(
        "app.request",
        logging.INFO,
        __file__,
        1,
        (
            "event=request_completed request_id=00000000-0000-4000-8000-000000000000 "
            "method=GET route=/api/health status_code=200 duration_ms=1.25 "
            f"authorization={TOKEN_CANARY}"
        ),
        (),
        None,
    )

    document = json.loads(UtcJsonFormatter().format(record))

    assert document == {
        "duration_ms": "1.25",
        "event": "request_completed",
        "level": "INFO",
        "logger": "app.request",
        "method": "GET",
        "request_id": "00000000-0000-4000-8000-000000000000",
        "route": "/api/health",
        "status_code": "200",
        "timestamp": document["timestamp"],
    }
    assert document["timestamp"].endswith("Z")
    assert TOKEN_CANARY not in json.dumps(document)


def test_invalid_logging_configuration_does_not_change_handlers_or_leak() -> None:
    application_logger = logging.getLogger(APPLICATION_LOGGER_NAME)
    managed_before = [
        handler
        for handler in application_logger.handlers
        if getattr(handler, APPLICATION_HANDLER_MARKER, False)
    ]
    invalid_value = f"TRACE-{API_KEY_CANARY}"

    with pytest.raises(ValueError) as exc_info:
        configure_logging(invalid_value)

    managed_after = [
        handler
        for handler in application_logger.handlers
        if getattr(handler, APPLICATION_HANDLER_MARKER, False)
    ]
    assert managed_after == managed_before
    assert invalid_value not in str(exc_info.value)
    assert API_KEY_CANARY not in str(exc_info.value)


def test_middleware_order_preserves_security_request_context_and_cors() -> None:
    middleware_names = [middleware.cls.__name__ for middleware in app.user_middleware]

    assert middleware_names[:5] == [
        "SecurityHeadersMiddleware",
        "RequestContextMiddleware",
        "ExactHostMiddleware",
        "CORSMiddleware",
        "UnexpectedExceptionMiddleware",
    ]
