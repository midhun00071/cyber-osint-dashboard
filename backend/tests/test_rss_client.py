from __future__ import annotations

import httpx
import pytest

from app.ingestion.collectors.rss_client import (
    CERT_EU_FEED_URL,
    DEFAULT_TIMEOUT,
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    USER_AGENT,
    RssClient,
    RssContentTypeError,
    RssFetchResult,
    RssHttpError,
    RssRateLimitError,
    RssRedirectError,
    RssRequestError,
    RssResponseTooLargeError,
)


RSS_BYTES = b"<?xml version='1.0'?><rss><channel><title>CERT-EU</title></channel></rss>"


def client_for(handler) -> RssClient:
    return RssClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_fetches_only_approved_cert_eu_feed_with_static_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == CERT_EU_FEED_URL
        assert request.headers["user-agent"] == USER_AGENT
        assert "application/rss+xml" in request.headers["accept"]
        return httpx.Response(
            200,
            headers={"content-type": "application/rss+xml; charset=utf-8"},
            content=RSS_BYTES,
        )

    result = client_for(handler).fetch_cert_eu_security_advisories()

    assert isinstance(result, RssFetchResult)
    assert result.feed_bytes == RSS_BYTES
    assert result.source_url == CERT_EU_FEED_URL
    assert result.final_url == CERT_EU_FEED_URL
    assert result.content_type == "application/rss+xml"
    assert result.byte_count == len(RSS_BYTES)


def test_default_timeout_is_bounded() -> None:
    client = RssClient()
    try:
        assert client._http_client.timeout == DEFAULT_TIMEOUT
    finally:
        client.close()


def test_same_host_redirect_is_followed_safely() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if len(seen) == 1:
            return httpx.Response(302, headers={"location": "/publications/feed.xml"})
        return httpx.Response(200, headers={"content-type": "application/xml"}, content=RSS_BYTES)

    result = client_for(handler).fetch_cert_eu_security_advisories()

    assert result.final_url == "https://cert.europa.eu/publications/feed.xml"
    assert seen == [CERT_EU_FEED_URL, "https://cert.europa.eu/publications/feed.xml"]


@pytest.mark.parametrize(
    "location",
    [
        "http://cert.europa.eu/feed.xml",
        "https://example.com/feed.xml",
        "https://user:pass@cert.europa.eu/feed.xml",
        "https://cert.europa.eu:444/feed.xml",
        "https://cert.europa.eu/feed.xml#frag",
    ],
)
def test_unsafe_redirect_targets_are_rejected(location: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(302, headers={"location": location})

    with pytest.raises(RssRedirectError):
        client_for(handler).fetch_cert_eu_security_advisories()


@pytest.mark.parametrize(
    "location",
    [
        "https://cert.europa.eu:bad/feed",
        "https://cert.europa.eu:999999/feed",
        "https://[invalid/feed",
    ],
)
def test_malformed_redirect_targets_are_rejected_safely(location: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(302, headers={"location": location})

    with pytest.raises(RssRedirectError) as exc_info:
        client_for(handler).fetch_cert_eu_security_advisories()
    assert location not in str(exc_info.value)


def test_redirect_limit_is_enforced() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": str(request.url)})

    with pytest.raises(RssRedirectError, match="limit"):
        client_for(handler).fetch_cert_eu_security_advisories()
    assert MAX_REDIRECTS == 3


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [(429, RssRateLimitError), (500, RssHttpError)],
)
def test_http_errors_are_sanitized(status_code: int, expected: type[Exception]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(status_code, content=b"private upstream payload")

    with pytest.raises(expected) as exc_info:
        client_for(handler).fetch_cert_eu_security_advisories()
    assert "private upstream payload" not in str(exc_info.value)


def test_transport_errors_are_sanitized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("private host detail", request=request)

    with pytest.raises(RssRequestError) as exc_info:
        client_for(handler).fetch_cert_eu_security_advisories()
    assert "private host detail" not in str(exc_info.value)


def test_rejects_unsupported_content_type() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, headers={"content-type": "text/html"}, content=RSS_BYTES)

    with pytest.raises(RssContentTypeError):
        client_for(handler).fetch_cert_eu_security_advisories()


def test_rejects_oversized_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            headers={"content-type": "application/rss+xml"},
            content=b"x" * (MAX_RESPONSE_BYTES + 1),
        )

    with pytest.raises(RssResponseTooLargeError):
        client_for(handler).fetch_cert_eu_security_advisories()
