from __future__ import annotations

import httpx
import pytest

from app.ingestion.collectors.google_threat_intelligence_rss_client import (
    DEFAULT_TIMEOUT,
    GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    USER_AGENT,
    GoogleThreatIntelligenceRssClient,
    GoogleThreatRssContentTypeError,
    GoogleThreatRssFetchResult,
    GoogleThreatRssHttpError,
    GoogleThreatRssRateLimitError,
    GoogleThreatRssRedirectError,
    GoogleThreatRssRequestError,
    GoogleThreatRssResponseTooLargeError,
)


RSS_BYTES = b"<?xml version='1.0'?><rss><channel><title>GTI</title></channel></rss>"


class ChunkedByteStream(httpx.SyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self._chunks = chunks

    def __iter__(self):
        yield from self._chunks


def client_for(handler) -> GoogleThreatIntelligenceRssClient:
    return GoogleThreatIntelligenceRssClient(
        http_client=httpx.Client(transport=httpx.MockTransport(handler))
    )


def test_fetches_only_fixed_google_threat_feed_with_static_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == GOOGLE_THREAT_INTELLIGENCE_FEED_URL
        assert request.headers["user-agent"] == USER_AGENT
        assert "application/rss+xml" in request.headers["accept"]
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        return httpx.Response(
            200,
            headers={"content-type": "application/rss+xml; charset=utf-8"},
            content=RSS_BYTES,
        )

    result = client_for(handler).fetch_publications()

    assert isinstance(result, GoogleThreatRssFetchResult)
    assert result.feed_bytes == RSS_BYTES
    assert result.source_url == GOOGLE_THREAT_INTELLIGENCE_FEED_URL
    assert result.final_url == GOOGLE_THREAT_INTELLIGENCE_FEED_URL
    assert result.content_type == "application/rss+xml"
    assert result.byte_count == len(RSS_BYTES)


def test_default_timeout_is_bounded() -> None:
    client = GoogleThreatIntelligenceRssClient()
    try:
        assert client._http_client.timeout == DEFAULT_TIMEOUT
    finally:
        client.close()


def test_response_limit_is_exactly_two_mebibytes() -> None:
    assert MAX_RESPONSE_BYTES == 2 * 1024 * 1024


@pytest.mark.parametrize(
    "size",
    [len(RSS_BYTES), MAX_RESPONSE_BYTES - 1, MAX_RESPONSE_BYTES],
)
def test_responses_at_or_below_two_mebibytes_are_accepted(size: int) -> None:
    response_bytes = b"x" * size

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            headers={"content-type": "application/rss+xml"},
            content=response_bytes,
        )

    result = client_for(handler).fetch_publications()

    assert result.feed_bytes == response_bytes
    assert result.byte_count == size


def test_response_one_byte_over_two_mebibytes_is_rejected_without_disclosure() -> None:
    private_response_bytes = b"private-feed-content" + b"x" * (
        MAX_RESPONSE_BYTES + 1 - len(b"private-feed-content")
    )

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            headers={"content-type": "application/rss+xml"},
            content=private_response_bytes,
        )

    with pytest.raises(GoogleThreatRssResponseTooLargeError) as exc_info:
        client_for(handler).fetch_publications()

    assert exc_info.type is GoogleThreatRssResponseTooLargeError
    assert "private-feed-content" not in str(exc_info.value)


def test_chunked_response_crossing_two_mebibytes_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            headers={"content-type": "application/rss+xml"},
            stream=ChunkedByteStream((b"x" * MAX_RESPONSE_BYTES, b"overflow")),
        )

    with pytest.raises(GoogleThreatRssResponseTooLargeError) as exc_info:
        client_for(handler).fetch_publications()

    assert exc_info.type is GoogleThreatRssResponseTooLargeError
    assert "overflow" not in str(exc_info.value)


def test_same_feedburner_host_redirect_is_followed_safely() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if len(seen) == 1:
            return httpx.Response(302, headers={"location": "/threatintelligence/next"})
        return httpx.Response(200, headers={"content-type": "application/xml"}, content=RSS_BYTES)

    result = client_for(handler).fetch_publications()

    assert result.final_url == "https://feeds.feedburner.com/threatintelligence/next"
    assert seen == [
        GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
        "https://feeds.feedburner.com/threatintelligence/next",
    ]


@pytest.mark.parametrize(
    "content_type",
    ["application/atom+xml", "application/vnd.example.feed+xml", "text/xml"],
)
def test_xml_compatible_content_types_are_accepted(content_type: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            headers={"content-type": content_type},
            content=RSS_BYTES,
        )

    result = client_for(handler).fetch_publications()

    assert result.content_type == content_type
    assert result.feed_bytes == RSS_BYTES


@pytest.mark.parametrize(
    "location",
    [
        "http://feeds.feedburner.com/threatintelligence/next",
        "https://cloud.google.com/blog/topics/threat-intelligence/post",
        "https://example.com/feed.xml",
        "https://user:pass@feeds.feedburner.com/feed.xml",
        "https://@feeds.feedburner.com/feed.xml",
        "https://feeds.feedburner.com:444/feed.xml",
        "https://feeds.feedburner.com/feed.xml#frag",
        "https://feeds.feedburner.com/feed.xml?token=secret",
    ],
)
def test_unsafe_redirect_targets_are_rejected(location: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(302, headers={"location": location})

    with pytest.raises(GoogleThreatRssRedirectError) as exc_info:
        client_for(handler).fetch_publications()
    assert location not in str(exc_info.value)


def test_sensitive_redirect_query_is_rejected_without_disclosure() -> None:
    location = "https://feeds.feedburner.com/feed.xml?token=private-secret"

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(302, headers={"location": location})

    with pytest.raises(GoogleThreatRssRedirectError) as exc_info:
        client_for(handler).fetch_publications()

    assert "private-secret" not in str(exc_info.value)


def test_missing_redirect_location_and_redirect_limit_are_rejected() -> None:
    def missing_location(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(302)

    with pytest.raises(GoogleThreatRssRedirectError, match="destination"):
        client_for(missing_location).fetch_publications()

    def loop(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": str(request.url)})

    with pytest.raises(GoogleThreatRssRedirectError, match="limit"):
        client_for(loop).fetch_publications()
    assert MAX_REDIRECTS == 3


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [(429, GoogleThreatRssRateLimitError), (500, GoogleThreatRssHttpError)],
)
def test_http_errors_are_sanitized(status_code: int, expected: type[Exception]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(status_code, content=b"private upstream payload")

    with pytest.raises(expected) as exc_info:
        client_for(handler).fetch_publications()
    assert "private upstream payload" not in str(exc_info.value)


def test_transport_timeout_content_type_and_size_errors_are_sanitized() -> None:
    def transport_error(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("private host detail", request=request)

    with pytest.raises(GoogleThreatRssRequestError) as exc_info:
        client_for(transport_error).fetch_publications()
    assert "private host detail" not in str(exc_info.value)

    def html_response(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, headers={"content-type": "text/html"}, content=RSS_BYTES)

    with pytest.raises(GoogleThreatRssContentTypeError):
        client_for(html_response).fetch_publications()

    def missing_content_type(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, content=RSS_BYTES)

    with pytest.raises(GoogleThreatRssContentTypeError):
        client_for(missing_content_type).fetch_publications()

    def octet_stream(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            headers={"content-type": "application/octet-stream"},
            content=RSS_BYTES,
        )

    with pytest.raises(GoogleThreatRssContentTypeError):
        client_for(octet_stream).fetch_publications()

    def oversized(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            headers={"content-type": "application/rss+xml"},
            content=b"x" * (MAX_RESPONSE_BYTES + 1),
        )

    with pytest.raises(GoogleThreatRssResponseTooLargeError):
        client_for(oversized).fetch_publications()


def test_httpx_timeout_is_sanitized() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("private timeout detail", request=request)

    with pytest.raises(GoogleThreatRssRequestError) as exc_info:
        client_for(timeout).fetch_publications()

    assert "private timeout detail" not in str(exc_info.value)


def test_close_and_context_manager_close_owned_client() -> None:
    with GoogleThreatIntelligenceRssClient() as client:
        http_client = client._http_client

    assert http_client.is_closed
