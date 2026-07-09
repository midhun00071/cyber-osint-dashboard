from __future__ import annotations

import httpx
import pytest

from app.ingestion.collectors.cisa_kev_client import (
    CISA_KEV_CATALOG_URL,
    DEFAULT_TIMEOUT,
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    USER_AGENT,
    CisaKevClient,
    CisaKevContentTypeError,
    CisaKevFetchResult,
    CisaKevHttpError,
    CisaKevRateLimitError,
    CisaKevRedirectError,
    CisaKevRequestError,
    CisaKevResponseError,
    CisaKevResponseTooLargeError,
)


CATALOG_BYTES = b'{"vulnerabilities":[]}'


def client_for(handler) -> CisaKevClient:
    return CisaKevClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_fetches_only_approved_cisa_catalog_with_static_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == CISA_KEV_CATALOG_URL
        assert request.headers["user-agent"] == USER_AGENT
        assert "application/json" in request.headers["accept"]
        return httpx.Response(
            200,
            headers={"content-type": "application/json; charset=utf-8"},
            content=CATALOG_BYTES,
        )

    result = client_for(handler).fetch_catalog()

    assert isinstance(result, CisaKevFetchResult)
    assert result.catalog == {"vulnerabilities": []}
    assert result.source_url == CISA_KEV_CATALOG_URL
    assert result.final_url == CISA_KEV_CATALOG_URL
    assert result.content_type == "application/json"
    assert result.byte_count == len(CATALOG_BYTES)


def test_default_timeout_is_bounded() -> None:
    client = CisaKevClient()
    try:
        assert client._http_client.timeout == DEFAULT_TIMEOUT
    finally:
        client.close()


def test_same_host_redirect_is_followed_safely() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if len(seen) == 1:
            return httpx.Response(302, headers={"location": "/sites/default/files/feeds/kev.json"})
        return httpx.Response(200, headers={"content-type": "application/json"}, content=CATALOG_BYTES)

    result = client_for(handler).fetch_catalog()

    assert result.final_url == "https://www.cisa.gov/sites/default/files/feeds/kev.json"
    assert seen == [
        CISA_KEV_CATALOG_URL,
        "https://www.cisa.gov/sites/default/files/feeds/kev.json",
    ]


@pytest.mark.parametrize(
    "location",
    [
        "http://www.cisa.gov/feed.json",
        "https://example.com/feed.json",
        "https://user:pass@www.cisa.gov/feed.json",
        "https://www.cisa.gov:444/feed.json",
        "https://www.cisa.gov/feed.json#frag",
    ],
)
def test_unsafe_redirect_targets_are_rejected(location: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(302, headers={"location": location})

    with pytest.raises(CisaKevRedirectError):
        client_for(handler).fetch_catalog()


@pytest.mark.parametrize(
    "location",
    [
        "https://www.cisa.gov:bad/feed",
        "https://www.cisa.gov:999999/feed",
        "https://[invalid/feed",
    ],
)
def test_malformed_redirect_targets_are_rejected_safely(location: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(302, headers={"location": location})

    with pytest.raises(CisaKevRedirectError) as exc_info:
        client_for(handler).fetch_catalog()
    assert location not in str(exc_info.value)


def test_redirect_limit_is_enforced() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": str(request.url)})

    with pytest.raises(CisaKevRedirectError, match="limit"):
        client_for(handler).fetch_catalog()
    assert MAX_REDIRECTS == 3


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [(429, CisaKevRateLimitError), (500, CisaKevHttpError)],
)
def test_http_errors_are_sanitized(status_code: int, expected: type[Exception]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(status_code, content=b"private upstream payload")

    with pytest.raises(expected) as exc_info:
        client_for(handler).fetch_catalog()
    assert "private upstream payload" not in str(exc_info.value)


def test_transport_errors_are_sanitized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("private host detail", request=request)

    with pytest.raises(CisaKevRequestError) as exc_info:
        client_for(handler).fetch_catalog()
    assert "private host detail" not in str(exc_info.value)


def test_rejects_invalid_json_safely() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, headers={"content-type": "application/json"}, content=b"{")

    with pytest.raises(CisaKevResponseError):
        client_for(handler).fetch_catalog()


def test_rejects_unsupported_content_type() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, headers={"content-type": "text/html"}, content=CATALOG_BYTES)

    with pytest.raises(CisaKevContentTypeError):
        client_for(handler).fetch_catalog()


def test_rejects_oversized_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b"x" * (MAX_RESPONSE_BYTES + 1),
        )

    with pytest.raises(CisaKevResponseTooLargeError):
        client_for(handler).fetch_catalog()
