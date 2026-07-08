from __future__ import annotations

import httpx
import pytest

from app.ingestion.collectors.epss_client import (
    DEFAULT_TIMEOUT,
    EpssClient,
    EpssHttpError,
    EpssRateLimitError,
    EpssRequestError,
    EpssResponseError,
    MAX_CVE_QUERY_CHARS,
)


def make_client(handler):
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    return EpssClient(http_client=http_client), http_client


def test_valid_single_request_sets_cve_and_limit_params() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={"data": [{"cve": "CVE-2026-0001", "epss": "0.1", "percentile": "0.2", "date": "2026-07-08"}]},
            request=request,
        )

    client, http_client = make_client(handler)
    try:
        batch = client.fetch_batch(["cve-2026-0001"])
    finally:
        http_client.close()

    assert batch.requested_cves == ("CVE-2026-0001",)
    assert batch.records[0]["cve"] == "CVE-2026-0001"
    assert captured[0].url.params["cve"] == "CVE-2026-0001"
    assert captured[0].url.params["limit"] == "1"


def test_deduplicates_and_batches_deterministically() -> None:
    with EpssClient() as client:
        batches = client.build_batches(
            ["cve-2026-0002", "CVE-2026-0001", "CVE-2026-0002"],
            max_batch_size=1,
        )

    assert batches == [("CVE-2026-0002",), ("CVE-2026-0001",)]


def test_batches_respect_query_character_limit() -> None:
    cves = [f"CVE-2026-{index:04d}" for index in range(200)]

    with EpssClient() as client:
        batches = client.build_batches(cves, max_batch_size=200)

    assert len(batches) > 1
    assert all(len(",".join(batch)) <= MAX_CVE_QUERY_CHARS for batch in batches)


def test_owned_client_uses_bounded_timeout() -> None:
    client = EpssClient()
    try:
        assert client._http_client.timeout == DEFAULT_TIMEOUT
    finally:
        client.close()


@pytest.mark.parametrize("cve_ids", [["bad"], ["CVE-2026-123"], [True]])
def test_invalid_cve_is_rejected_before_request(cve_ids: list[object]) -> None:
    with EpssClient() as client:
        with pytest.raises(EpssResponseError, match="invalid CVE ID"):
            client.fetch_batch(cve_ids)  # type: ignore[arg-type]


def test_invalid_batch_size_is_rejected() -> None:
    with EpssClient() as client:
        with pytest.raises(EpssResponseError, match="positive integer"):
            client.build_batches(["CVE-2026-0001"], max_batch_size=True)  # type: ignore[arg-type]


def test_invalid_json_is_response_error() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(200, content=b"not-json", request=request)
    )
    try:
        with pytest.raises(EpssResponseError, match="invalid JSON"):
            client.fetch_batch(["CVE-2026-0001"])
    finally:
        http_client.close()


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ([], "JSON object"),
        ({"data": "bad"}, "data field"),
        ({"data": [False]}, "data field"),
    ],
)
def test_malformed_envelope_is_response_error(payload: object, message: str) -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(200, json=payload, request=request)
    )
    try:
        with pytest.raises(EpssResponseError, match=message):
            client.fetch_batch(["CVE-2026-0001"])
    finally:
        http_client.close()


def test_http_429_is_rate_limit_error_without_body() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(429, text="private body", request=request)
    )
    try:
        with pytest.raises(EpssRateLimitError) as exc_info:
            client.fetch_batch(["CVE-2026-0001"])
    finally:
        http_client.close()

    assert "private body" not in str(exc_info.value)


def test_http_error_omits_response_body() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(500, text="secret-response-body", request=request)
    )
    try:
        with pytest.raises(EpssHttpError, match="HTTP 500") as exc_info:
            client.fetch_batch(["CVE-2026-0001"])
    finally:
        http_client.close()

    assert "secret-response-body" not in str(exc_info.value)


@pytest.mark.parametrize("error_type", [httpx.ReadTimeout, httpx.ConnectError])
def test_network_errors_are_sanitized(error_type) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error_type("private transport detail", request=request)

    client, http_client = make_client(handler)
    try:
        with pytest.raises(EpssRequestError) as exc_info:
            client.fetch_batch(["CVE-2026-0001"])
    finally:
        http_client.close()

    assert "private transport detail" not in str(exc_info.value)


def test_close_does_not_close_injected_client() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(200, json={"data": []}, request=request)
    )

    client.close()

    assert not http_client.is_closed
    http_client.close()


def test_context_manager_closes_owned_client() -> None:
    client = EpssClient()

    with client:
        assert not client._http_client.is_closed

    assert client._http_client.is_closed
