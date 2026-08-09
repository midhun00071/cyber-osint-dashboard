"""C10 API inventory, request-bound, and strict-schema regressions."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.api.v1.schemas.admin_users import CreateAdminUserRequest
from app.api.v1.schemas.auth import LoginRequest
from app.api.v1.schemas.reports import ReportExportRequest
from app.main import (
    MAX_REQUEST_BODY_BYTES,
    MAX_REQUEST_BODY_MESSAGES,
    RequestBodyLimitMiddleware,
    app,
)


def test_imported_application_has_expected_complete_route_inventory() -> None:
    schema = app.openapi()
    operation_count = sum(
        method in {"get", "post", "put", "patch", "delete", "head", "options"}
        for operations in schema["paths"].values()
        for method in operations
    )
    assert len(schema["paths"]) == 42
    assert operation_count == 43
    assert "/internal/metrics" not in schema["paths"]


@pytest.mark.parametrize(
    ("model_type", "payload"),
    (
        (LoginRequest, {"username": "viewer", "password": "long-test-password", "role": "administrator"}),
        (
            CreateAdminUserRequest,
            {
                "username": "viewer",
                "display_name": "Viewer",
                "password": "long-test-password",
                "role": "viewer",
                "session_version": 1,
            },
        ),
        (ReportExportRequest, {"report_type": "uae_intelligence", "format": "csv", "limit": 10, "public_id": "unexpected"}),
    ),
)
def test_sensitive_request_schemas_forbid_unexpected_properties(
    model_type: type,
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        model_type.model_validate(payload)


def test_backend_rejects_declared_and_streamed_bodies_over_its_private_limit() -> None:
    bounded = FastAPI()
    bounded.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=16)

    @bounded.post("/echo")
    async def echo() -> dict[str, str]:
        return {"status": "unexpected"}

    with TestClient(bounded) as client:
        declared = client.post("/echo", content=b"x" * 17)
        assert declared.status_code == 413
        assert declared.json() == {"detail": "The request body exceeds the configured limit."}

    assert MAX_REQUEST_BODY_BYTES == 1_000_000


@pytest.mark.asyncio
async def test_backend_counts_chunked_body_bytes_without_content_length() -> None:
    downstream_called = False

    async def downstream(_scope, _receive, _send) -> None:
        nonlocal downstream_called
        downstream_called = True

    messages = iter(
        (
            {"type": "http.request", "body": b"1234567890", "more_body": True},
            {"type": "http.request", "body": b"1234567", "more_body": False},
        )
    )
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return next(messages)

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=16)
    await middleware(
        {"type": "http", "method": "POST", "path": "/echo", "headers": []},
        receive,
        send,
    )

    assert downstream_called is False
    assert sent[0]["status"] == 413


async def _run_body_middleware(
    messages: list[dict[str, object]],
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    max_body_bytes: int = 8,
    max_body_messages: int = 4,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    downstream_messages: list[dict[str, object]] = []
    sent: list[dict[str, object]] = []
    pending = iter(messages)

    async def receive() -> dict[str, object]:
        return next(pending)

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    async def downstream(_scope, replay, _send) -> None:
        downstream_messages.append(await replay())
        downstream_messages.append(await replay())

    middleware = RequestBodyLimitMiddleware(
        downstream,
        max_body_bytes=max_body_bytes,
        max_body_messages=max_body_messages,
    )
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/echo",
            "headers": headers or [],
        },
        receive,
        send,
    )
    return downstream_messages, sent


@pytest.mark.asyncio
async def test_body_limit_accepts_exact_bytes_and_reconstructs_chunks() -> None:
    downstream, sent = await _run_body_middleware(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"defgh", "more_body": False},
        ],
        headers=[(b"content-length", b"8")],
    )

    assert sent == []
    assert downstream == [
        {"type": "http.request", "body": b"abcdefgh", "more_body": False},
        {"type": "http.request", "body": b"", "more_body": False},
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("chunk", (b"", b"x"))
async def test_body_limit_rejects_excessive_message_fragmentation(
    chunk: bytes,
) -> None:
    downstream, sent = await _run_body_middleware(
        [
            {"type": "http.request", "body": chunk, "more_body": True},
            {"type": "http.request", "body": chunk, "more_body": True},
            {"type": "http.request", "body": chunk, "more_body": True},
            {"type": "http.request", "body": chunk, "more_body": False},
        ],
        max_body_messages=3,
    )

    assert downstream == []
    assert sent[0]["status"] == 413


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "messages"),
    (
        (
            [(b"content-length", b"1"), (b"content-length", b"1")],
            [{"type": "http.request", "body": b"x", "more_body": False}],
        ),
        (
            [(b"content-length", b"invalid")],
            [{"type": "http.request", "body": b"x", "more_body": False}],
        ),
        (
            [(b"content-length", b"2")],
            [{"type": "http.request", "body": b"x", "more_body": False}],
        ),
    ),
)
async def test_body_limit_rejects_invalid_or_contradictory_content_length(
    headers: list[tuple[bytes, bytes]],
    messages: list[dict[str, object]],
) -> None:
    downstream, sent = await _run_body_middleware(messages, headers=headers)

    assert downstream == []
    assert sent[0]["status"] == 400


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal_message",
    (
        {"type": "http.disconnect"},
        {"type": "websocket.receive", "bytes": b"unexpected"},
    ),
)
async def test_incomplete_or_invalid_asgi_body_never_invokes_downstream(
    terminal_message: dict[str, object],
) -> None:
    downstream, sent = await _run_body_middleware(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            terminal_message,
        ]
    )

    assert downstream == []
    assert sent[0]["status"] == 400


def test_production_body_message_limit_is_fixed_and_bounded() -> None:
    assert MAX_REQUEST_BODY_MESSAGES == 1_024
