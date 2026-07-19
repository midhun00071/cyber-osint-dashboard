from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
import inspect
import json
import math

import httpx
import pytest

from app.ingestion.adapters.anomali_publications import (
    ANOMALI_SOURCE_SLUG,
    MAX_ANOMALI_AUTHORS,
    MAX_ANOMALI_CATEGORIES,
)
from app.ingestion.collectors import anomali_publications_client as collector_module
from app.ingestion.collectors.anomali_publications_client import (
    ACCEPT_HEADER,
    DISCOVERY_URL,
    MAX_JSON_LD_BLOCKS,
    MAX_JSON_LD_DEPTH,
    MAX_JSON_LD_NODES,
    MAX_JSON_LD_STRING_LENGTH,
    MAX_RESPONSE_BYTES,
    REQUEST_DELAY_SECONDS,
    TOTAL_REQUEST_TIMEOUT_SECONDS,
    USER_AGENT,
    AnomaliCollectionResult,
    AnomaliCollectorConfigurationError,
    AnomaliDiscoveryCollectionError,
    AnomaliFailureReason,
    AnomaliMetadataError,
    AnomaliPacingError,
    AnomaliPublicationsClient,
    AnomaliRequestStateIsolationError,
    AnomaliTransportError,
    _validate_url,
)


ARTICLE_ONE = "https://www.anomali.com/blog/anomali-cyber-watch-one"
ARTICLE_TWO = "https://www.anomali.com/blog/anomali-cyber-watch-two"
ARTICLE_THREE = "https://www.anomali.com/blog/anomali-cyber-watch-three"


class FakeClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value
        self.sleeps: list[float] = []
        self.reads: list[float] = []

    def __call__(self) -> float:
        self.reads.append(self.value)
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


class SequenceClock:
    def __init__(self, values: list[object]) -> None:
        self.values = list(values)

    def __call__(self) -> object:
        if not self.values:
            raise RuntimeError("private clock exhausted")
        return self.values.pop(0)


class TrackingStream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes], error: BaseException | None = None) -> None:
        self.chunks = chunks
        self.error = error
        self.iterated = False
        self.closed = False

    def __iter__(self):
        self.iterated = True
        yield from self.chunks
        if self.error is not None:
            raise self.error

    def close(self) -> None:
        self.closed = True


class TimedStream(httpx.SyncByteStream):
    def __init__(
        self,
        clock: FakeClock,
        chunks: list[tuple[float, bytes]],
    ) -> None:
        self.clock = clock
        self.chunks = chunks
        self.closed = False

    def __iter__(self):
        for elapsed, chunk in self.chunks:
            self.clock.value += elapsed
            yield chunk

    def close(self) -> None:
        self.closed = True


class CountingTransport(httpx.BaseTransport):
    def __init__(self, handler, close_error: BaseException | None = None) -> None:
        self.handler = handler
        self.close_error = close_error
        self.close_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self.handler(request)

    def close(self) -> None:
        self.close_count += 1
        if self.close_error is not None:
            raise self.close_error


class AsyncOnlyTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request)


def discovery_html(*hrefs: str, wrapper: str = "main") -> str:
    links = "".join(f'<a href="{href}">publication</a>' for href in hrefs)
    return f"<html><body><{wrapper}>{links}</{wrapper}></body></html>"


def article_html(
    url: str,
    *,
    title: str = "Anomali Cyber Watch: Example publication",
    published_at: str = "2026-01-27T00:00:00Z",
    modified_at: str | None = None,
    summary: str | None = "Metadata-only summary.",
    canonical_url: str | None = None,
    json_ld: object | str | None = None,
    body: str = "Ignored article body.",
) -> str:
    canonical = url if canonical_url is None else canonical_url
    head = [
        f'<link rel="canonical" href="{canonical}">',
        f'<meta property="og:url" content="{canonical}">',
        f'<meta property="og:title" content="{title}">',
        f'<meta property="article:published_time" content="{published_at}">',
        '<meta name="author" content="Anomali Cyber Watch">',
        '<meta property="article:section" content="Cyber Watch">',
    ]
    if modified_at is not None:
        head.append(
            f'<meta property="article:modified_time" content="{modified_at}">'
        )
    if summary is not None:
        head.append(f'<meta name="description" content="{summary}">')
    if json_ld is not None:
        payload = json_ld if isinstance(json_ld, str) else json.dumps(json_ld)
        head.append(f'<script type="application/ld+json">{payload}</script>')
    return f"<html><head>{''.join(head)}</head><body>{body}</body></html>"


def response(
    request: httpx.Request,
    body: str | bytes,
    *,
    status: int = 200,
    content_type: str | None = "text/html; charset=utf-8",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    final_headers = dict(headers or {})
    if content_type is not None:
        final_headers["content-type"] = content_type
    return httpx.Response(
        status,
        headers=final_headers,
        content=body.encode() if isinstance(body, str) else body,
        request=request,
    )


def client_for(handler, *, clock: FakeClock | None = None) -> AnomaliPublicationsClient:
    active_clock = clock or FakeClock()
    return AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(handler),
        monotonic_clock=active_clock,
        sleeper=active_clock.sleep,
    )


def successful_handler(request: httpx.Request) -> httpx.Response:
    if str(request.url) == DISCOVERY_URL:
        return response(request, discovery_html(ARTICLE_ONE))
    if str(request.url) == ARTICLE_ONE:
        return response(request, article_html(ARTICLE_ONE))
    raise AssertionError("unexpected request")


def metadata_article(mode: str, field: str, value: str) -> str:
    if mode == "json-ld":
        payload: dict[str, object] = {
            "@type": "BlogPosting",
            "url": ARTICLE_ONE,
            "headline": "Anomali Cyber Watch: Safe defensive research",
            "description": "Analysts shared a bounded defensive summary.",
            "datePublished": "2026-02-01T00:00:00Z",
            "author": [{"@type": "Person", "name": "Anomali Research Team"}],
            "articleSection": "Cyber Watch",
            "keywords": ["Threat Research"],
        }
        target = "headline" if field == "title" else field
        if target == "author":
            payload[target] = [{"@type": "Person", "name": value}]
        elif target == "keywords":
            payload[target] = [value]
        else:
            payload[target] = value
        return article_html(ARTICLE_ONE, json_ld=payload)

    if mode != "head":
        raise AssertionError("unexpected metadata mode")
    if field == "title":
        return article_html(ARTICLE_ONE, title=value)
    if field == "description":
        return article_html(ARTICLE_ONE, summary=value)
    article = article_html(ARTICLE_ONE)
    if field == "author":
        return article.replace(
            '<meta name="author" content="Anomali Cyber Watch">',
            f'<meta name="author" content="{value}">',
        )
    if field == "articleSection":
        return article.replace(
            '<meta property="article:section" content="Cyber Watch">',
            f'<meta property="article:section" content="{value}">',
        )
    metadata = {
        "keywords": f'<meta name="keywords" content="{value}">',
        "tag": f'<meta property="article:tag" content="{value}">',
        "category": f'<meta name="category" content="{value}">',
    }
    return article.replace("</head>", metadata[field] + "</head>")


def collect_article(article: str) -> AnomaliCollectionResult:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        return client.fetch_publications(max_records=1)


def test_fixed_discovery_url_safe_headers_and_static_http_configuration() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return successful_handler(request)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
        http_client = client._http_client
        assert http_client.follow_redirects is False
        assert getattr(http_client, "_trust_env") is False
        assert len(http_client.cookies) == 0

    assert result.source_slug == ANOMALI_SOURCE_SLUG
    assert [str(item.url) for item in requests] == [DISCOVERY_URL, ARTICLE_ONE]
    for request in requests:
        assert request.method == "GET"
        assert request.headers["user-agent"] == USER_AGENT
        assert request.headers["accept"] == ACCEPT_HEADER
        assert "authorization" not in request.headers
        assert "proxy-authorization" not in request.headers
        assert "cookie" not in request.headers


def test_discovery_uses_only_the_exact_canonical_no_slash_url() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return response(request, discovery_html())

    with client_for(handler) as client:
        result = client.fetch_publications()

    assert DISCOVERY_URL == "https://www.anomali.com/blog"
    assert collector_module.DISCOVERY_PATH == "/blog"
    assert requested == ["https://www.anomali.com/blog"]
    assert "https://www.anomali.com/blog/" not in requested
    assert collector_module.DISCOVERY_LINK_RESOLUTION_BASE not in requested
    assert result.discovered_approved_link_count == 0


def test_path_relative_article_link_resolves_beneath_fixed_blog_base() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requested.append(url)
        if url == DISCOVERY_URL:
            return response(
                request,
                discovery_html("anomali-cyber-watch-one"),
            )
        return response(request, article_html(ARTICLE_ONE))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)

    assert requested == [DISCOVERY_URL, ARTICLE_ONE]
    assert len(result.candidates) == 1


def test_unapproved_discovery_redirect_is_sanitized_and_never_followed() -> None:
    secret_location = "/private-discovery-secret"
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return response(
            request,
            b"private redirect body",
            status=302,
            content_type=None,
            headers={"location": secret_location},
        )

    with client_for(handler) as client:
        with pytest.raises(AnomaliDiscoveryCollectionError) as exc_info:
            client.fetch_publications()

    public_error = repr(exc_info.value)
    assert requested == [DISCOVERY_URL]
    assert secret_location not in public_error
    assert DISCOVERY_URL not in public_error
    assert collector_module.DISCOVERY_LINK_RESOLUTION_BASE not in public_error


@pytest.mark.parametrize("void_tag", ["img", "br", "input", "meta", "source"])
def test_discovery_void_elements_do_not_break_deterministic_main(
    void_tag: str,
) -> None:
    article = (
        f'<html><body><main><{void_tag} data-safe="value">'
        f'<a href="{ARTICLE_ONE}"><{void_tag}>Article</a>'
        "</main></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, article)
        return response(request, article_html(ARTICLE_ONE))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)

    assert len(result.candidates) == 1
    assert result.failure_reasons == ()


def test_discovery_response_cookie_is_not_sent_to_article_and_jar_is_empty() -> None:
    secret = "discovery-cookie-secret"

    def handler(request: httpx.Request) -> httpx.Response:
        assert "cookie" not in request.headers
        if str(request.url) == DISCOVERY_URL:
            return response(
                request,
                discovery_html(ARTICLE_ONE),
                headers={"set-cookie": f"session={secret}; Path=/"},
            )
        return response(request, article_html(ARTICLE_ONE))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
        assert len(client._http_client.cookies) == 0

    assert len(result.candidates) == 1
    assert secret not in repr(result)


def test_redirect_response_cookie_is_not_sent_to_redirect_target() -> None:
    secret = "redirect-cookie-secret"
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        assert "cookie" not in request.headers
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        if str(request.url) == ARTICLE_ONE:
            return response(
                request,
                b"",
                status=302,
                content_type=None,
                headers={
                    "location": ARTICLE_TWO,
                    "set-cookie": f"redirect={secret}; Path=/",
                },
            )
        return response(request, article_html(ARTICLE_TWO))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
        assert len(client._http_client.cookies) == 0

    assert requested == [DISCOVERY_URL, ARTICLE_ONE, ARTICLE_TWO]
    assert len(result.candidates) == 1
    assert secret not in repr(result)


def test_article_response_cookie_is_not_sent_to_later_article() -> None:
    secret = "article-cookie-secret"

    def handler(request: httpx.Request) -> httpx.Response:
        assert "cookie" not in request.headers
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE, ARTICLE_TWO))
        if str(request.url) == ARTICLE_ONE:
            return response(
                request,
                article_html(ARTICLE_ONE),
                headers={"set-cookie": f"article={secret}; Path=/"},
            )
        return response(request, article_html(ARTICLE_TWO))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=2)
        assert len(client._http_client.cookies) == 0

    assert len(result.candidates) == 2
    assert secret not in repr(result)


def test_cookie_jar_is_empty_after_discovery_and_article_failures() -> None:
    discovery_secret = "discovery-failure-cookie-secret"

    def discovery_failure(request: httpx.Request) -> httpx.Response:
        assert "cookie" not in request.headers
        return response(
            request,
            b"private discovery failure",
            status=500,
            headers={"set-cookie": f"failure={discovery_secret}; Path=/"},
        )

    with client_for(discovery_failure) as client:
        with pytest.raises(AnomaliDiscoveryCollectionError) as exc_info:
            client.fetch_publications()
        assert len(client._http_client.cookies) == 0
    assert discovery_secret not in str(exc_info.value)

    article_secret = "article-failure-cookie-secret"

    def article_failure(request: httpx.Request) -> httpx.Response:
        assert "cookie" not in request.headers
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(
            request,
            b"private article failure",
            status=500,
            headers={"set-cookie": f"failure={article_secret}; Path=/"},
        )

    with client_for(article_failure) as client:
        result = client.fetch_publications(max_records=1)
        assert len(client._http_client.cookies) == 0
    assert result.failure_reasons == (AnomaliFailureReason.HTTP_FAILURE,)
    assert article_secret not in repr(result)


@pytest.mark.parametrize(
    "system_error",
    [MemoryError(), KeyboardInterrupt(), SystemExit(), GeneratorExit()],
)
def test_active_system_exception_survives_normal_cookie_cleanup_failure(
    system_error: BaseException,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_secret = "private cookie cleanup failure"
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        raise system_error

    client = client_for(handler)
    clear_calls = 0

    def fail_second_clear() -> None:
        nonlocal clear_calls
        clear_calls += 1
        if clear_calls == 2:
            raise RuntimeError(cleanup_secret)

    monkeypatch.setattr(client, "_clear_cookies", fail_second_clear)
    try:
        with pytest.raises(type(system_error)) as exc_info:
            client.fetch_publications()
    finally:
        client.close()

    assert exc_info.value is system_error
    assert requests == [DISCOVERY_URL]
    assert clear_calls == 2
    assert cleanup_secret not in repr(exc_info.value)


def test_normal_cookie_cleanup_failure_fails_closed_before_later_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_secret = "private normal cleanup failure"
    cookie_secret = "private contaminated cookie"
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return response(
            request,
            discovery_html(ARTICLE_ONE),
            headers={"set-cookie": f"session={cookie_secret}; Path=/"},
        )

    client = client_for(handler)
    clear_calls = 0

    def fail_second_clear() -> None:
        nonlocal clear_calls
        clear_calls += 1
        if clear_calls == 2:
            raise RuntimeError(cleanup_secret)

    monkeypatch.setattr(client, "_clear_cookies", fail_second_clear)
    try:
        with pytest.raises(AnomaliDiscoveryCollectionError) as exc_info:
            client.fetch_publications(max_records=1)
    finally:
        client.close()

    public_error = repr(exc_info.value)
    assert requests == [DISCOVERY_URL]
    assert clear_calls == 2
    assert cleanup_secret not in public_error
    assert cookie_secret not in public_error


def test_pre_request_cookie_isolation_failure_issues_no_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_secret = "private pre-request cleanup failure"
    requests: list[str] = []
    client = client_for(
        lambda request: requests.append(str(request.url))
        or response(request, discovery_html())
    )

    def fail_clear() -> None:
        raise RuntimeError(cleanup_secret)

    monkeypatch.setattr(client, "_clear_cookies", fail_clear)
    try:
        with pytest.raises(AnomaliDiscoveryCollectionError) as exc_info:
            client.fetch_publications()
    finally:
        client.close()

    assert requests == []
    assert cleanup_secret not in repr(exc_info.value)


def test_article_post_response_isolation_failure_is_terminal_and_poisons_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_secret = "private article cleanup detail"
    cookie_secret = "private article cookie value"
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requests.append(url)
        if url == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE, ARTICLE_TWO))
        return response(
            request,
            article_html(ARTICLE_ONE),
            headers={"set-cookie": f"session={cookie_secret}; Path=/"},
        )

    client = client_for(handler)
    original_clear = client._clear_cookies
    clear_calls = 0

    def fail_article_post_clear() -> None:
        nonlocal clear_calls
        clear_calls += 1
        if clear_calls == 4:
            raise RuntimeError(cleanup_secret)
        original_clear()

    monkeypatch.setattr(client, "_clear_cookies", fail_article_post_clear)
    try:
        with pytest.raises(AnomaliRequestStateIsolationError) as exc_info:
            client.fetch_publications(max_records=2)
        first_error = repr(exc_info.value)
        with pytest.raises(AnomaliRequestStateIsolationError) as second_exc_info:
            client.fetch_publications(max_records=2)
    finally:
        client.close()

    assert requests == [DISCOVERY_URL, ARTICLE_ONE]
    assert cleanup_secret not in first_error
    assert cookie_secret not in first_error
    assert cleanup_secret not in repr(second_exc_info.value)
    assert cookie_secret not in repr(second_exc_info.value)


def test_pre_request_isolation_failure_before_later_article_is_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_secret = "private later pre-request cleanup detail"
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requests.append(url)
        if url == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE, ARTICLE_TWO))
        return response(request, article_html(ARTICLE_ONE))

    client = client_for(handler)
    original_clear = client._clear_cookies
    clear_calls = 0

    def fail_later_pre_clear() -> None:
        nonlocal clear_calls
        clear_calls += 1
        if clear_calls == 5:
            raise RuntimeError(cleanup_secret)
        original_clear()

    monkeypatch.setattr(client, "_clear_cookies", fail_later_pre_clear)
    try:
        with pytest.raises(AnomaliRequestStateIsolationError) as exc_info:
            client.fetch_publications(max_records=2)
    finally:
        client.close()

    assert requests == [DISCOVERY_URL, ARTICLE_ONE]
    assert cleanup_secret not in repr(exc_info.value)


def test_redirect_post_response_isolation_failure_prevents_target_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_secret = "private redirect cleanup detail"
    cookie_secret = "private redirect cookie value"
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requests.append(url)
        if url == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        if url == ARTICLE_ONE:
            return response(
                request,
                b"",
                status=302,
                content_type=None,
                headers={
                    "location": ARTICLE_TWO,
                    "set-cookie": f"redirect={cookie_secret}; Path=/",
                },
            )
        raise AssertionError("redirect target must not be requested")

    client = client_for(handler)
    original_clear = client._clear_cookies
    clear_calls = 0

    def fail_redirect_post_clear() -> None:
        nonlocal clear_calls
        clear_calls += 1
        if clear_calls == 4:
            raise RuntimeError(cleanup_secret)
        original_clear()

    monkeypatch.setattr(client, "_clear_cookies", fail_redirect_post_clear)
    try:
        with pytest.raises(AnomaliRequestStateIsolationError) as exc_info:
            client.fetch_publications(max_records=1)
    finally:
        client.close()

    public_error = repr(exc_info.value)
    assert requests == [DISCOVERY_URL, ARTICLE_ONE]
    assert cleanup_secret not in public_error
    assert cookie_secret not in public_error


def test_public_interface_is_closed_and_default_maximum_is_five() -> None:
    signature = inspect.signature(AnomaliPublicationsClient.fetch_publications)
    assert tuple(signature.parameters) == ("self", "max_records")
    assert signature.parameters["max_records"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["max_records"].default == 5
    constructor = inspect.signature(AnomaliPublicationsClient)
    assert "http_client" not in constructor.parameters
    assert "url" not in constructor.parameters

    hrefs = [
        f"/blog/anomali-cyber-watch-item-{index}" for index in range(1, 7)
    ]
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(*hrefs))
        return response(request, article_html(str(request.url)))

    with client_for(handler) as client:
        result = client.fetch_publications()

    assert len(result.candidates) == 5
    assert result.discovered_approved_link_count == 5
    assert result.capped is True
    assert len(requested) == 6


@pytest.mark.parametrize("maximum", [1, 20])
def test_max_records_accepts_closed_boundaries(maximum: int) -> None:
    with client_for(lambda request: response(request, discovery_html())) as client:
        result = client.fetch_publications(max_records=maximum)
    assert result.candidates == ()


@pytest.mark.parametrize(
    "invalid",
    [0, 21, -1, -20, "5", 5.0, True, False, None],
)
def test_invalid_max_records_fail_before_requests(invalid: object) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return response(request, discovery_html())

    with client_for(handler) as client:
        with pytest.raises(AnomaliCollectorConfigurationError):
            client.fetch_publications(max_records=invalid)  # type: ignore[arg-type]
    assert calls == 0


@pytest.mark.parametrize("transport", [object(), AsyncOnlyTransport()])
def test_invalid_or_async_transport_is_rejected(transport: object) -> None:
    with pytest.raises(AnomaliCollectorConfigurationError):
        AnomaliPublicationsClient(http_transport=transport)  # type: ignore[arg-type]


def test_relative_and_absolute_approved_links_are_ordered_and_deduplicated() -> None:
    discovered = (
        "/blog/anomali-cyber-watch-one",
        ARTICLE_ONE + "/",
        "anomali-cyber-watch-two",
        ARTICLE_THREE,
    )
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requests.append(url)
        if url == DISCOVERY_URL:
            return response(request, discovery_html(*discovered))
        return response(request, article_html(url))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=5)

    assert [candidate.canonical_url for candidate in result.candidates] == [
        ARTICLE_ONE,
        ARTICLE_TWO,
        ARTICLE_THREE,
    ]
    assert requests == [DISCOVERY_URL, ARTICLE_ONE, ARTICLE_TWO, ARTICLE_THREE]
    assert result.discovered_approved_link_count == 3
    assert result.capped is False


def test_general_external_marketing_media_feed_and_query_links_are_ignored() -> None:
    ignored = (
        "/blog/general-security-post",
        "https://evil.example/blog/anomali-cyber-watch-one",
        "/products/",
        "/login/",
        "/report.pdf",
        "/media/video.mp4",
        "/feed/",
        "/blog/anomali-cyber-watch-one?page=2",
        "/blog/anomali-cyber-watch-one#fragment",
    )

    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requests.append(url)
        if url == DISCOVERY_URL:
            return response(request, discovery_html(*ignored, ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=5)

    assert result.discovered_approved_link_count == 1
    assert len(result.candidates) == 1
    assert result.failure_reasons == ()
    assert requests == [DISCOVERY_URL, ARTICLE_ONE]


def test_links_outside_main_and_in_excluded_subtrees_are_not_discovered() -> None:
    html = f"""
    <html><body>
      <header><a href="{ARTICLE_ONE}">header</a></header>
      <main>
        <nav><a href="{ARTICLE_ONE}">nav</a></nav>
        <aside><a href="{ARTICLE_ONE}">aside</a></aside>
        <form><a href="{ARTICLE_ONE}">form</a></form>
        <footer><a href="{ARTICLE_ONE}">footer</a></footer>
        <section><a href="{ARTICLE_TWO}">accepted</a></section>
      </main>
      <a href="{ARTICLE_THREE}">outside</a>
    </body></html>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, html)
        return response(request, article_html(str(request.url)))

    with client_for(handler) as client:
        result = client.fetch_publications()

    assert [candidate.canonical_url for candidate in result.candidates] == [
        ARTICLE_TWO
    ]


@pytest.mark.parametrize(
    "html",
    [
        f'<html><body><a href="{ARTICLE_ONE}">outside</a></body></html>',
        f'<html><body><main><a href="{ARTICLE_ONE}">unclosed</a></body></html>',
        "<html><body><main></main><main></main></body></html>",
        "<html><body></main></body></html>",
    ],
)
def test_malformed_or_missing_main_fails_discovery_without_regex_fallback(
    html: str,
) -> None:
    secret = "private-discovery-body"

    with client_for(lambda request: response(request, html + secret)) as client:
        with pytest.raises(AnomaliDiscoveryCollectionError) as exc_info:
            client.fetch_publications()
    assert str(exc_info.value) == "Anomali discovery collection failed."
    assert secret not in str(exc_info.value)
    assert ARTICLE_ONE not in str(exc_info.value)


def test_capped_requires_one_additional_unique_approved_link() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requested.append(url)
        if url == DISCOVERY_URL:
            return response(
                request,
                discovery_html(ARTICLE_ONE, ARTICLE_ONE + "/", ARTICLE_TWO),
            )
        return response(request, article_html(url))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)

    assert result.capped is True
    assert result.discovered_approved_link_count == 1
    assert requested == [DISCOVERY_URL, ARTICLE_ONE]


@pytest.mark.parametrize(
    "unsafe",
    [
        "http://www.anomali.com/blog/anomali-cyber-watch-one",
        "https://anomali.com/blog/anomali-cyber-watch-one",
        "https://sub.www.anomali.com/blog/anomali-cyber-watch-one",
        "https://www.anomali.com:444/blog/anomali-cyber-watch-one",
        "https://user:secret@www.anomali.com/blog/anomali-cyber-watch-one",
        "https://www.anomali.com/blog/anomali-cyber-watch-one#secret",
        "https://www.anomali.com/blog/anomali-cyber-watch-one;param",
        "https://www.anomali.com/blog/anomali-cyber-watch-%zz",
        "https://www.anomali.com/blog/anomali-cyber-watch-%2fone",
        "https://www.anomali.com/blog/anomali-cyber-watch-%5Cone",
        "https://www.anomali.com/blog/anomali-cyber-watch-one?feed=rss",
        "https://www.anomali.com/blog/anomali-cyber-watch-one?",
        "https://www.anomali.com/blog/anomali-cyber-watch-one#",
        "https://www.anomali.com/blog/anomali-cyber-watch-one;",
        "https://127.0.0.1/blog/anomali-cyber-watch-one",
        "https://www.anomali.com/blog/anomali-cyber-watch-one/two",
    ],
)
def test_publication_url_policy_rejects_unsafe_destinations_without_disclosure(
    unsafe: str,
) -> None:
    with pytest.raises(Exception) as exc_info:
        _validate_url(unsafe, request_kind="publication")
    assert unsafe not in str(exc_info.value)
    assert "secret" not in str(exc_info.value).lower()


@pytest.mark.parametrize(
    "rejected_href",
    [
        "/blog/anomali-cyber-watch-one?",
        "/blog/anomali-cyber-watch-one#",
        "/blog/anomali-cyber-watch-one;",
        "anomali-cyber-watch-one;",
        "https:/blog/anomali-cyber-watch-one",
        "https:blog/anomali-cyber-watch-one",
        "https:///blog/anomali-cyber-watch-one",
    ],
)
def test_rejected_raw_discovery_syntax_never_issues_article_request(
    rejected_href: str,
) -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return response(request, discovery_html(rejected_href))

    with client_for(handler) as client:
        result = client.fetch_publications()

    assert result.discovered_approved_link_count == 0
    assert result.candidates == ()
    assert requests == [DISCOVERY_URL]


@pytest.mark.parametrize(
    "rejected_location",
    [
        ARTICLE_TWO + "?",
        ARTICLE_TWO + "#",
        ARTICLE_TWO + ";",
        "/blog/anomali-cyber-watch-two;",
        "anomali-cyber-watch-two;",
        "https:/blog/anomali-cyber-watch-two",
        "https:blog/anomali-cyber-watch-two",
        "https:///blog/anomali-cyber-watch-two",
    ],
)
def test_rejected_raw_redirect_syntax_issues_no_target_request(
    rejected_location: str,
) -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requests.append(url)
        if url == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(
            request,
            b"private redirect body",
            status=302,
            headers={"location": rejected_location},
            content_type=None,
        )

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)

    assert result.failure_reasons == (AnomaliFailureReason.REDIRECT_REJECTED,)
    assert requests == [DISCOVERY_URL, ARTICLE_ONE]
    assert rejected_location not in repr(result)


def test_default_https_port_is_canonicalized() -> None:
    assert _validate_url(
        "https://www.anomali.com:443/blog/anomali-cyber-watch-one/",
        request_kind="publication",
    ) == ARTICLE_ONE


def test_safe_article_redirect_succeeds_and_remains_paced() -> None:
    clock = FakeClock()
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requested.append(url)
        if url == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        if url == ARTICLE_ONE:
            return response(
                request,
                b"",
                status=302,
                headers={"location": ARTICLE_TWO},
                content_type=None,
            )
        return response(request, article_html(ARTICLE_TWO))

    with client_for(handler, clock=clock) as client:
        result = client.fetch_publications(max_records=1)

    assert requested == [DISCOVERY_URL, ARTICLE_ONE, ARTICLE_TWO]
    assert result.candidates[0].canonical_url == ARTICLE_TWO
    assert clock.sleeps == [10.0, 10.0]


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/blog/anomali-cyber-watch-two",
        "https://www.anomali.com/blog/general-article",
        "http://www.anomali.com/blog/anomali-cyber-watch-two",
        "https://www.anomali.com:444/blog/anomali-cyber-watch-two",
        "/blog/anomali-cyber-watch-two?tracking=1",
    ],
)
def test_unsafe_article_redirect_is_one_sanitized_page_failure(location: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(
            request,
            b"private-body",
            status=302,
            headers={"location": location},
            content_type=None,
        )

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)

    assert result.candidates == ()
    assert result.failure_reasons == (AnomaliFailureReason.REDIRECT_REJECTED,)
    assert location not in repr(result)
    assert "private-body" not in repr(result)


@pytest.mark.parametrize("mode", ["missing", "loop", "too-many"])
def test_missing_location_loop_and_redirect_limit_are_rejected(mode: str) -> None:
    chain = {
        ARTICLE_ONE: ARTICLE_TWO,
        ARTICLE_TWO: ARTICLE_THREE,
        ARTICLE_THREE: "https://www.anomali.com/blog/anomali-cyber-watch-four",
        "https://www.anomali.com/blog/anomali-cyber-watch-four": (
            "https://www.anomali.com/blog/anomali-cyber-watch-five"
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        if mode == "missing":
            return response(request, b"", status=302, content_type=None)
        if mode == "loop":
            target = ARTICLE_TWO if url == ARTICLE_ONE else ARTICLE_ONE
        else:
            target = chain[url]
        return response(
            request,
            b"",
            status=302,
            headers={"location": target},
            content_type=None,
        )

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.REDIRECT_REJECTED,)


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (429, AnomaliFailureReason.RATE_LIMITED),
        (400, AnomaliFailureReason.HTTP_FAILURE),
        (404, AnomaliFailureReason.HTTP_FAILURE),
        (500, AnomaliFailureReason.HTTP_FAILURE),
        (503, AnomaliFailureReason.HTTP_FAILURE),
    ],
)
def test_article_http_failures_are_classified(status: int, reason: AnomaliFailureReason) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, b"private", status=status)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (reason,)


@pytest.mark.parametrize("content_type", [None, "application/json", "text/plain"])
def test_missing_or_unsupported_article_content_type_is_rejected(
    content_type: str | None,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE), content_type=content_type)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.CONTENT_TYPE_REJECTED,)


@pytest.mark.parametrize("content_type", ["text/html", "application/xhtml+xml; charset=utf-8"])
def test_approved_html_content_types_are_accepted(content_type: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE), content_type=content_type)
        return response(request, article_html(ARTICLE_ONE), content_type=content_type)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert len(result.candidates) == 1


def test_discovery_and_article_have_independent_streaming_size_limits() -> None:
    oversized = b"x" * (MAX_RESPONSE_BYTES + 1)
    with client_for(lambda request: response(request, oversized)) as client:
        with pytest.raises(AnomaliDiscoveryCollectionError):
            client.fetch_publications()

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, oversized)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.RESPONSE_TOO_LARGE,)


def test_every_response_is_streamed_and_closed() -> None:
    streams: list[TrackingStream] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = (
            discovery_html(ARTICLE_ONE)
            if str(request.url) == DISCOVERY_URL
            else article_html(ARTICLE_ONE)
        ).encode()
        stream = TrackingStream([body[:10], body[10:]])
        streams.append(stream)
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            stream=stream,
            request=request,
        )

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert len(result.candidates) == 1
    assert all(stream.iterated and stream.closed for stream in streams)


def test_response_headers_after_total_deadline_are_rejected() -> None:
    clock = FakeClock()

    def discovery_handler(request: httpx.Request) -> httpx.Response:
        clock.value += TOTAL_REQUEST_TIMEOUT_SECONDS + 1
        return response(request, discovery_html())

    with client_for(discovery_handler, clock=clock) as client:
        with pytest.raises(AnomaliDiscoveryCollectionError) as exc_info:
            client.fetch_publications()
    assert str(exc_info.value) == "Anomali discovery collection failed."


def test_article_header_total_timeout_is_classified_without_detail_leak() -> None:
    clock = FakeClock()
    secret = "private response after deadline"

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        clock.value += TOTAL_REQUEST_TIMEOUT_SECONDS + 1
        return response(request, secret)

    with client_for(handler, clock=clock) as client:
        result = client.fetch_publications(max_records=1)

    assert result.failure_reasons == (AnomaliFailureReason.TIMEOUT,)
    assert secret not in repr(result)
    assert ARTICLE_ONE not in repr(result)


def test_multiple_timely_chunks_cannot_exceed_total_request_deadline() -> None:
    clock = FakeClock()
    stream: TimedStream | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal stream
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        body = article_html(ARTICLE_ONE).encode()
        third = len(body) // 3
        stream = TimedStream(
            clock,
            [
                (8.0, body[:third]),
                (8.0, body[third : third * 2]),
                (8.0, body[third * 2 :]),
            ],
        )
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            stream=stream,
            request=request,
        )

    with client_for(handler, clock=clock) as client:
        result = client.fetch_publications(max_records=1)

    assert result.failure_reasons == (AnomaliFailureReason.TIMEOUT,)
    assert stream is not None and stream.closed is True


def test_ordinary_bounded_response_remains_within_total_deadline() -> None:
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        clock.value += 1.0
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE))

    with client_for(handler, clock=clock) as client:
        result = client.fetch_publications(max_records=1)
    assert len(result.candidates) == 1
    assert result.failure_reasons == ()


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (httpx.ReadTimeout("private timeout"), AnomaliFailureReason.TIMEOUT),
        (httpx.ConnectError("private transport"), AnomaliFailureReason.TRANSPORT_FAILURE),
        (RuntimeError("private runtime"), AnomaliFailureReason.TRANSPORT_FAILURE),
    ],
)
def test_article_transport_failures_are_sanitized_and_classified(
    error: Exception,
    reason: AnomaliFailureReason,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        raise error

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (reason,)
    assert "private" not in repr(result)


def test_discovery_transport_failure_returns_no_partial_result() -> None:
    secret = "private discovery transport"

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(secret)

    with client_for(handler) as client:
        with pytest.raises(AnomaliDiscoveryCollectionError) as exc_info:
            client.fetch_publications()
    assert secret not in str(exc_info.value)


def test_ten_second_pacing_has_no_initial_delay() -> None:
    clock = FakeClock()
    with client_for(successful_handler, clock=clock) as client:
        result = client.fetch_publications(max_records=1)
    assert len(result.candidates) == 1
    assert clock.sleeps == [REQUEST_DELAY_SECONDS]
    assert clock.value == REQUEST_DELAY_SECONDS

    empty_clock = FakeClock()
    with client_for(
        lambda request: response(request, discovery_html()),
        clock=empty_clock,
    ) as client:
        client.fetch_publications()
    assert empty_clock.sleeps == []


def test_elapsed_time_avoids_unnecessary_sleep() -> None:
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            clock.value += 12
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE))

    with client_for(handler, clock=clock) as client:
        client.fetch_publications(max_records=1)
    assert clock.sleeps == []


@pytest.mark.parametrize("invalid", [math.nan, math.inf, -math.inf, "0", True])
def test_invalid_clock_values_fail_closed(invalid: object) -> None:
    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(successful_handler),
        monotonic_clock=lambda: invalid,  # type: ignore[return-value]
        sleeper=lambda seconds: None,
    ) as client:
        with pytest.raises(AnomaliDiscoveryCollectionError):
            client.fetch_publications()


def test_clock_rollback_and_broken_sleeper_abort_collection() -> None:
    rollback = SequenceClock([10.0] * 7 + [9.0])
    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(successful_handler),
        monotonic_clock=rollback,  # type: ignore[arg-type]
        sleeper=lambda seconds: None,
    ) as client:
        with pytest.raises(AnomaliPacingError):
            client.fetch_publications(max_records=1)

    clock = FakeClock()

    def broken_sleep(seconds: float) -> None:
        raise RuntimeError("private sleeper")

    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(successful_handler),
        monotonic_clock=clock,
        sleeper=broken_sleep,
    ) as client:
        with pytest.raises(AnomaliPacingError) as exc_info:
            client.fetch_publications(max_records=1)
    assert "private" not in str(exc_info.value)


def test_clock_rollback_above_request_start_fails_closed() -> None:
    clock = SequenceClock([100.0] * 7 + [115.0, 110.0])
    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(successful_handler),
        monotonic_clock=clock,  # type: ignore[arg-type]
        sleeper=lambda seconds: None,
    ) as client:
        with pytest.raises(AnomaliPacingError) as exc_info:
            client.fetch_publications(max_records=1)

    assert str(exc_info.value) == "Anomali request pacing failed."
    assert "100" not in str(exc_info.value)
    assert "115" not in str(exc_info.value)
    assert "110" not in str(exc_info.value)


def test_clock_rollback_during_response_headers_fails_closed() -> None:
    clock = SequenceClock([100.0] * 7 + [115.0, 115.0, 115.0, 110.0])
    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(successful_handler),
        monotonic_clock=clock,  # type: ignore[arg-type]
        sleeper=lambda seconds: None,
    ) as client:
        with pytest.raises(AnomaliPacingError):
            client.fetch_publications(max_records=1)


def test_clock_rollback_between_body_chunks_fails_closed() -> None:
    clock = SequenceClock([100.0] * 7 + [115.0] * 6 + [110.0])

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        body = article_html(ARTICLE_ONE).encode()
        midpoint = len(body) // 2
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            stream=TrackingStream([body[:midpoint], body[midpoint:]]),
            request=request,
        )

    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(handler),
        monotonic_clock=clock,  # type: ignore[arg-type]
        sleeper=lambda seconds: None,
    ) as client:
        with pytest.raises(AnomaliPacingError):
            client.fetch_publications(max_records=1)


@pytest.mark.parametrize(
    "values",
    [
        [100.0] * 7 + [110.0] * 7,
        [100.0, 101.0, 102.0, 103.0, 104.0, 105.0, 106.0]
        + [111.0, 112.0, 113.0, 114.0, 115.0, 116.0, 117.0],
    ],
    ids=["equal-readings", "increasing-readings"],
)
def test_equal_and_increasing_clock_readings_remain_accepted(
    values: list[float],
) -> None:
    clock = SequenceClock(values)
    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(successful_handler),
        monotonic_clock=clock,  # type: ignore[arg-type]
        sleeper=lambda seconds: None,
    ) as client:
        result = client.fetch_publications(max_records=1)

    assert len(result.candidates) == 1
    assert result.failure_reasons == ()


def test_clock_values_do_not_leak_through_errors_or_results() -> None:
    secret_start = 987654.321
    secret_later = 987669.321
    secret_rollback = 987668.321
    clock = SequenceClock(
        [secret_start] * 7 + [secret_later, secret_rollback]
    )
    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(successful_handler),
        monotonic_clock=clock,  # type: ignore[arg-type]
        sleeper=lambda seconds: None,
    ) as client:
        with pytest.raises(AnomaliPacingError) as exc_info:
            client.fetch_publications(max_records=1)

    public_error = repr(exc_info.value)
    for timing_value in (secret_start, secret_later, secret_rollback):
        assert str(timing_value) not in public_error

    accepted_start = 123456.789
    accepted_later = 123466.789
    accepted_clock = SequenceClock(
        [accepted_start] * 7 + [accepted_later] * 7
    )
    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(successful_handler),
        monotonic_clock=accepted_clock,  # type: ignore[arg-type]
        sleeper=lambda seconds: None,
    ) as client:
        result = client.fetch_publications(max_records=1)

    assert str(accepted_start) not in repr(result)
    assert str(accepted_later) not in repr(result)


@pytest.mark.parametrize("publication_type", ["BlogPosting", "Article", "NewsArticle", "TechArticle"])
def test_identity_matched_json_ld_publication_is_extracted(publication_type: str) -> None:
    payload = {
        "@context": "https://schema.org",
        "@type": publication_type,
        "url": ARTICLE_ONE,
        "headline": "Anomali Cyber Watch: JSON-LD publication",
        "description": "JSON-LD summary.",
        "datePublished": "2026-02-01T00:00:00Z",
        "dateModified": "2026-02-02T00:00:00Z",
        "author": [{"@type": "Person", "name": "Anomali Research"}],
        "articleSection": "Cyber Watch",
        "keywords": ["Threat Research"],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE, json_ld=payload))

    with client_for(handler) as client:
        candidate = client.fetch_publications(max_records=1).candidates[0]
    assert candidate.canonical_title == "Anomali Cyber Watch: JSON-LD publication"
    assert candidate.summary == "JSON-LD summary."
    assert candidate.safe_source_payload == {
        "authors": ("Anomali Research",),
        "categories": ("Cyber Watch", "Threat Research"),
    }


def test_open_graph_and_standard_head_metadata_fallback() -> None:
    with client_for(successful_handler) as client:
        candidate = client.fetch_publications(max_records=1).candidates[0]
    assert candidate.canonical_title == "Anomali Cyber Watch: Example publication"
    assert candidate.summary == "Metadata-only summary."
    assert candidate.safe_source_payload == {
        "authors": ("Anomali Cyber Watch",),
        "categories": ("Cyber Watch",),
    }


def test_unclosed_head_title_cannot_absorb_article_body_text() -> None:
    body_secret = "private body title suffix"
    article = (
        f'<html><head><link rel="canonical" href="{ARTICLE_ONE}">'
        '<meta property="article:published_time" content="2026-01-27T00:00:00Z">'
        '<title>Anomali Cyber Watch: Safe title'
        f'<body>{body_secret}</body></html>'
    )

    result = collect_article(article)

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)
    assert result.candidates == ()
    assert body_secret not in repr(result)


def test_head_close_with_active_title_is_rejected() -> None:
    article = (
        f'<html><head><link rel="canonical" href="{ARTICLE_ONE}">'
        '<meta property="article:published_time" content="2026-01-27T00:00:00Z">'
        '<title>Anomali Cyber Watch: Unclosed title</head><body></body></html>'
    )

    result = collect_article(article)

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_end_of_input_with_active_title_is_rejected() -> None:
    article = (
        f'<html><head><link rel="canonical" href="{ARTICLE_ONE}">'
        '<meta property="article:published_time" content="2026-01-27T00:00:00Z">'
        '<title>Anomali Cyber Watch: EOF title'
    )

    result = collect_article(article)

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


@pytest.mark.parametrize(
    "titles",
    [
        (
            "<title>Anomali Cyber Watch: First</title>"
            "<title>Anomali Cyber Watch: Second</title>"
        ),
        (
            "<title>Anomali Cyber Watch: Outer"
            "<title>Anomali Cyber Watch: Nested</title></title>"
        ),
    ],
    ids=["duplicate", "nested"],
)
def test_duplicate_and_nested_head_titles_are_rejected(titles: str) -> None:
    article = (
        f'<html><head><link rel="canonical" href="{ARTICLE_ONE}">'
        '<meta property="article:published_time" content="2026-01-27T00:00:00Z">'
        f"{titles}</head><body></body></html>"
    )

    result = collect_article(article)

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_head_and_body_title_elements_are_rejected_as_multiple() -> None:
    article = (
        f'<html><head><link rel="canonical" href="{ARTICLE_ONE}">'
        '<meta property="article:published_time" content="2026-01-27T00:00:00Z">'
        '<title>Anomali Cyber Watch: Head title</title></head>'
        '<body><title>Anomali Cyber Watch: Body title</title></body></html>'
    )

    result = collect_article(article)

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_unclosed_json_ld_cannot_be_ignored_in_favor_of_head_fallback() -> None:
    article = article_html(ARTICLE_ONE).replace(
        "</head>",
        '<script type="application/ld+json">{"@type":"BlogPosting"}'
        "</head>",
    )

    result = collect_article(article)

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)
    assert result.candidates == ()


def test_unclosed_json_ld_at_end_of_input_is_rejected() -> None:
    article = (
        f'<html><head><link rel="canonical" href="{ARTICLE_ONE}">'
        '<meta property="og:title" content="Anomali Cyber Watch: Safe fallback">'
        '<meta property="article:published_time" content="2026-01-27T00:00:00Z">'
        '<script type="application/ld+json">{"@type":"BlogPosting"'
    )

    result = collect_article(article)

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_well_formed_head_and_closed_json_ld_metadata_remain_accepted() -> None:
    head_result = collect_article(article_html(ARTICLE_ONE))
    json_ld_result = collect_article(
        article_html(
            ARTICLE_ONE,
            json_ld={
                "@type": "BlogPosting",
                "url": ARTICLE_ONE,
                "headline": "Anomali Cyber Watch: Closed JSON-LD",
                "datePublished": "2026-02-01T00:00:00Z",
            },
        )
    )
    body_json_ld = {
        "@type": "BlogPosting",
        "url": ARTICLE_ONE,
        "headline": "Anomali Cyber Watch: Closed body JSON-LD",
        "datePublished": "2026-02-01T00:00:00Z",
    }
    body_json_ld_result = collect_article(
        f'<html><head><link rel="canonical" href="{ARTICLE_ONE}"></head>'
        '<body><script type="application/ld+json">'
        f"{json.dumps(body_json_ld)}</script></body></html>"
    )

    assert head_result.candidates[0].canonical_title == (
        "Anomali Cyber Watch: Example publication"
    )
    assert json_ld_result.candidates[0].canonical_title == (
        "Anomali Cyber Watch: Closed JSON-LD"
    )
    assert body_json_ld_result.candidates[0].canonical_title == (
        "Anomali Cyber Watch: Closed body JSON-LD"
    )


@pytest.mark.parametrize("script_body", ["", "  \n\t  "], ids=["empty", "whitespace"])
def test_empty_json_ld_is_rejected_instead_of_using_head_fallback(
    script_body: str,
) -> None:
    article = article_html(ARTICLE_ONE).replace(
        "</head>",
        f'<script type="application/ld+json">{script_body}</script></head>',
    )

    result = collect_article(article)

    assert result.candidates == ()
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_empty_json_ld_src_is_rejected_without_requesting_source() -> None:
    source_secret = "https://private-json-source.example/data"
    article = article_html(ARTICLE_ONE).replace(
        "</head>",
        f'<script type="application/ld+json" src="{source_secret}"></script>'
        "</head>",
    )
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        requested.append(url)
        if url == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)

    assert requested == [DISCOVERY_URL, ARTICLE_ONE]
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)
    assert source_secret not in repr(result)


def test_absent_json_ld_fallback_and_valid_json_ld_remain_accepted() -> None:
    fallback_result = collect_article(article_html(ARTICLE_ONE))
    valid_result = collect_article(
        article_html(
            ARTICLE_ONE,
            json_ld={
                "@type": "BlogPosting",
                "url": ARTICLE_ONE,
                "headline": "Anomali Cyber Watch: Valid JSON-LD",
                "datePublished": "2026-02-01T00:00:00Z",
            },
        )
    )

    assert fallback_result.candidates[0].canonical_title == (
        "Anomali Cyber Watch: Example publication"
    )
    assert valid_result.candidates[0].canonical_title == (
        "Anomali Cyber Watch: Valid JSON-LD"
    )


def test_malformed_json_ld_content_is_sanitized() -> None:
    content_secret = "private malformed JSON-LD content"
    article = article_html(ARTICLE_ONE).replace(
        "</head>",
        f'<script type="application/ld+json">{content_secret}</script></head>',
    )

    result = collect_article(article)

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)
    assert content_secret not in repr(result)


@pytest.mark.parametrize("mode", ["json-ld", "head"])
@pytest.mark.parametrize(
    "unsafe",
    [
        "Review http://external.example/story for context.",
        "Review https://external.example/story for context.",
        "Review www.external.example/story for context.",
        "Observed IPv4 value:198.51.100.7.",
        "Observed IPv6 value:2001:db8::7.",
        "Observed domain malware.example in the report.",
        *(
            f"Observed digest {'a' * length} in the report."
            for length in (32, 40, 56, 64, 96, 128)
        ),
    ],
    ids=[
        "http-url",
        "https-url",
        "www-url",
        "ipv4",
        "ipv6",
        "domain",
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
    ],
)
def test_json_ld_and_head_descriptions_reject_ioc_like_values_before_adapter(
    mode: str,
    unsafe: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[object] = []
    original_adapter = collector_module.adapt_anomali_publication

    def capture(record: object):
        captured.append(record)
        return original_adapter(record)

    monkeypatch.setattr(collector_module, "adapt_anomali_publication", capture)
    article = metadata_article(mode, "description", unsafe)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)

    assert result.candidates == ()
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)
    assert captured == []
    assert unsafe not in repr(result)


@pytest.mark.parametrize(
    ("mode", "field"),
    [
        ("json-ld", "keywords"),
        ("json-ld", "articleSection"),
        ("head", "keywords"),
        ("head", "tag"),
        ("head", "category"),
    ],
)
def test_json_ld_and_head_category_metadata_reject_ioc_like_values(
    mode: str,
    field: str,
) -> None:
    secret = f"private-{field} malware.example"
    article = metadata_article(mode, field, secret)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)
    assert secret not in repr(result)


@pytest.mark.parametrize("mode", ["json-ld", "head"])
@pytest.mark.parametrize("field", ["author", "title"])
def test_json_ld_and_head_author_and_title_metadata_reject_ioc_like_values(
    mode: str,
    field: str,
) -> None:
    secret = (
        "Anomali Cyber Watch: private malware.example"
        if field == "title"
        else "Private malware.example Researcher"
    )
    article = metadata_article(mode, field, secret)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)
    assert secret not in repr(result)


@pytest.mark.parametrize("mode", ["json-ld", "head"])
def test_safe_ordinary_narrative_metadata_remains_accepted(mode: str) -> None:
    article = metadata_article(
        mode,
        "description",
        "Analysts reviewed a defensive campaign and shared general lessons.",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)

    assert len(result.candidates) == 1
    assert result.failure_reasons == ()
    assert result.candidates[0].summary == (
        "Analysts reviewed a defensive campaign and shared general lessons."
    )


def test_rejected_metadata_is_sanitized_in_exception_text() -> None:
    secret = "private-prefix https://external.example/story private-suffix"
    with pytest.raises(AnomaliMetadataError) as exc_info:
        collector_module._validate_untrusted_metadata(
            title="Anomali Cyber Watch: Safe title",
            summary=secret,
            authors=[],
            categories=[],
        )

    public_error = repr(exc_info.value)
    assert secret not in public_error
    assert "external.example" not in public_error


@pytest.mark.parametrize("mode", ["json-ld", "head"])
@pytest.mark.parametrize("field", ["title", "description", "author", "category"])
@pytest.mark.parametrize(
    "unsafe",
    [
        "198.51.100.7:443",
        "[2001:db8::1]:443",
        "evil.xn--p1ai",
        "пример.рф",
        "evil.example:8443",
        "evil.example/path",
    ],
    ids=[
        "ipv4-port",
        "bracketed-ipv6-port",
        "punycode-domain",
        "unicode-domain",
        "domain-port",
        "domain-path",
    ],
)
def test_extended_ioc_values_are_rejected_across_all_untrusted_metadata_fields(
    mode: str,
    field: str,
    unsafe: str,
) -> None:
    if field == "title":
        value = f"Anomali Cyber Watch: Report mentioning {unsafe}"
        target = field
    elif field == "category":
        value = f"Threat research {unsafe}"
        target = "keywords" if mode == "json-ld" else "category"
    else:
        value = f"Defensive research mentioning {unsafe}"
        target = field
    result = collect_article(metadata_article(mode, target, value))

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)
    assert result.candidates == ()
    assert unsafe not in repr(result)


def test_extended_ioc_rejection_errors_are_sanitized() -> None:
    secrets = (
        "private 198.51.100.7:443 context",
        "private [2001:db8::1]:443 context",
        "private evil.xn--p1ai context",
        "private пример.рф context",
    )
    for secret in secrets:
        with pytest.raises(AnomaliMetadataError) as exc_info:
            collector_module._validate_untrusted_metadata(
                title="Anomali Cyber Watch: Safe title",
                summary=secret,
                authors=[],
                categories=[],
            )
        assert secret not in repr(exc_info.value)


@pytest.mark.parametrize("mode", ["json-ld", "head"])
@pytest.mark.parametrize("field", ["title", "description", "author", "category"])
@pytest.mark.parametrize(
    "unsafe",
    [
        "evil[.]example",
        "evil(.)example",
        "evil{.}example",
        "evil[dot]example",
        "evil(dot)example",
        "evil{dot}example",
        "198[.]51[.]100[.]7",
        "evil[ DoT ]example",
        "hXxPs[ : ]//evil{ DoT }example/path",
    ],
    ids=[
        "square-dot",
        "round-dot",
        "brace-dot",
        "square-word-dot",
        "round-word-dot",
        "brace-word-dot",
        "defanged-ipv4",
        "mixed-case-dot",
        "defanged-scheme-and-colon",
    ],
)
def test_defanged_iocs_are_rejected_across_json_ld_and_head_metadata(
    mode: str,
    field: str,
    unsafe: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[object] = []
    original_adapter = collector_module.adapt_anomali_publication

    def capture(record: object):
        captured.append(record)
        return original_adapter(record)

    monkeypatch.setattr(collector_module, "adapt_anomali_publication", capture)
    if field == "title":
        value = f"Anomali Cyber Watch: Report mentioning {unsafe}"
        target = field
    elif field == "category":
        value = f"Threat research {unsafe}"
        target = "keywords" if mode == "json-ld" else "category"
    else:
        value = f"Defensive research mentioning {unsafe}"
        target = field

    result = collect_article(metadata_article(mode, target, value))

    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)
    assert result.candidates == ()
    assert captured == []
    assert unsafe not in repr(result)


@pytest.mark.parametrize("mode", ["json-ld", "head"])
def test_safe_ordinary_bracketed_prose_remains_accepted(mode: str) -> None:
    summary = (
        "Analysts compared [baseline], (control), and {review} groups "
        "while explaining a [dot product] operation."
    )

    result = collect_article(metadata_article(mode, "description", summary))

    assert result.failure_reasons == ()
    assert result.candidates[0].summary == summary


def test_defanged_ioc_errors_are_sanitized() -> None:
    secrets = (
        "private evil[.]example context",
        "private 198[.]51[.]100[.]7 context",
        "private hxxps[:]//evil[dot]example context",
    )
    for secret in secrets:
        with pytest.raises(AnomaliMetadataError) as exc_info:
            collector_module._validate_untrusted_metadata(
                title="Anomali Cyber Watch: Safe title",
                summary=secret,
                authors=[],
                categories=[],
            )
        assert secret not in repr(exc_info.value)


def test_body_meta_after_implicitly_closed_head_cannot_supply_required_fields() -> None:
    article = f"""
    <html><head><link rel="canonical" href="{ARTICLE_ONE}">
    <body>
      <meta property="og:title" content="Anomali Cyber Watch: Body metadata">
      <meta property="article:published_time" content="2026-01-27T00:00:00Z">
      <meta name="description" content="Body description">
    </body></html>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_body_title_never_supplies_document_title() -> None:
    article = f"""
    <html><head>
      <link rel="canonical" href="{ARTICLE_ONE}">
      <meta property="article:published_time" content="2026-01-27T00:00:00Z">
    </head><body><title>Anomali Cyber Watch: Body title</title></body></html>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


@pytest.mark.parametrize(
    "head_markup",
    [
        "<head><head></head></head>",
        "<head></head><head></head>",
        "<body></body><head></head>",
    ],
)
def test_nested_multiple_or_post_body_head_regions_are_rejected(
    head_markup: str,
) -> None:
    article = (
        "<html>"
        + head_markup
        + '<meta property="og:title" content="Anomali Cyber Watch: Ambiguous">'
        + '<meta property="article:published_time" content="2026-01-27T00:00:00Z">'
        + "</html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_complete_metadata_passes_as_exact_seven_field_adapter_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_adapter = collector_module.adapt_anomali_publication
    captured: list[object] = []

    def capture(record: object):
        captured.append(record)
        return original_adapter(record)

    monkeypatch.setattr(collector_module, "adapt_anomali_publication", capture)
    with client_for(successful_handler) as client:
        result = client.fetch_publications(max_records=1)

    assert len(result.candidates) == 1
    assert len(captured) == 1
    assert isinstance(captured[0], dict)
    assert set(captured[0]) == {
        "title",
        "url",
        "summary",
        "published_at",
        "modified_at",
        "authors",
        "categories",
    }


@pytest.mark.parametrize(
    "article",
    [
        article_html(ARTICLE_ONE, canonical_url=ARTICLE_TWO),
        article_html(
            ARTICLE_ONE,
            json_ld={
                "@type": "BlogPosting",
                "url": ARTICLE_TWO,
                "headline": "Anomali Cyber Watch: Wrong identity",
                "datePublished": "2026-01-27T00:00:00Z",
            },
        ),
        article_html(
            ARTICLE_ONE,
            json_ld=[
                {
                    "@type": "BlogPosting",
                    "headline": "Anomali Cyber Watch: One",
                    "datePublished": "2026-01-27T00:00:00Z",
                },
                {
                    "@type": "Article",
                    "headline": "Anomali Cyber Watch: Two",
                    "datePublished": "2026-01-27T00:00:00Z",
                },
            ],
        ),
    ],
)
def test_conflicting_canonical_and_ambiguous_json_ld_are_rejected(article: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


@pytest.mark.parametrize(
    "main_entity",
    [
        "https://external.example/story",
        ARTICLE_TWO,
        "https:/blog/anomali-cyber-watch-one",
        "http://www.anomali.com/blog/anomali-cyber-watch-one",
        "https://www.anomali.com/blog/general-article",
    ],
)
def test_matching_json_ld_url_cannot_hide_invalid_second_identity(
    main_entity: str,
) -> None:
    payload = {
        "@type": "BlogPosting",
        "url": ARTICLE_ONE,
        "mainEntityOfPage": {"@id": main_entity},
        "headline": "Anomali Cyber Watch: Conflicting identity",
        "datePublished": "2026-01-27T00:00:00Z",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE, json_ld=payload))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_matching_json_ld_url_and_main_entity_are_accepted_together() -> None:
    payload = {
        "@type": "BlogPosting",
        "url": ARTICLE_ONE,
        "mainEntityOfPage": {"@id": ARTICLE_ONE},
        "headline": "Anomali Cyber Watch: Matching identities",
        "datePublished": "2026-01-27T00:00:00Z",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE, json_ld=payload))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.candidates[0].canonical_title == (
        "Anomali Cyber Watch: Matching identities"
    )


def test_genuinely_identity_free_sole_json_ld_publication_remains_allowed() -> None:
    payload = {
        "@type": "BlogPosting",
        "headline": "Anomali Cyber Watch: Identity-free metadata",
        "datePublished": "2026-01-27T00:00:00Z",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE, json_ld=payload))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.candidates[0].canonical_title == (
        "Anomali Cyber Watch: Identity-free metadata"
    )


@pytest.mark.parametrize(
    "unsafe_json",
    [
        '{"@type":"BlogPosting","headline":"one","headline":"two"}',
        '{"@type":"BlogPosting","headline":NaN}',
    ],
)
def test_duplicate_json_keys_and_nonstandard_constants_are_rejected(
    unsafe_json: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE, json_ld=unsafe_json))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_json_ld_depth_nodes_blocks_and_string_limits_fail_closed() -> None:
    deep: object = "leaf"
    for _ in range(MAX_JSON_LD_DEPTH + 2):
        deep = {"nested": deep}
    excessive_nodes = {
        "@type": "BlogPosting",
        "nodes": [None] * (MAX_JSON_LD_NODES + 1),
    }
    long_string = {
        "@type": "BlogPosting",
        "headline": "x" * (MAX_JSON_LD_STRING_LENGTH + 1),
    }
    too_many_blocks = "".join(
        '<script type="application/ld+json">{}</script>'
        for _ in range(MAX_JSON_LD_BLOCKS + 1)
    )
    articles = [
        article_html(ARTICLE_ONE, json_ld=deep),
        article_html(ARTICLE_ONE, json_ld=excessive_nodes),
        article_html(ARTICLE_ONE, json_ld=long_string),
        article_html(ARTICLE_ONE).replace("</head>", too_many_blocks + "</head>"),
        article_html(
            ARTICLE_ONE,
            json_ld=" " * (collector_module.MAX_JSON_LD_BLOCK_CHARS + 1),
        ),
    ]

    for article in articles:
        def handler(request: httpx.Request, content: str = article) -> httpx.Response:
            if str(request.url) == DISCOVERY_URL:
                return response(request, discovery_html(ARTICLE_ONE))
            return response(request, content)

        with client_for(handler) as client:
            result = client.fetch_publications(max_records=1)
        assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


@pytest.mark.parametrize(
    "bounded_field",
    [
        {
            "author": [f"Author {index}" for index in range(MAX_ANOMALI_AUTHORS + 1)]
        },
        {
            "keywords": [
                f"Category {index}" for index in range(MAX_ANOMALI_CATEGORIES + 1)
            ]
        },
    ],
)
def test_json_ld_author_and_category_counts_fail_closed(
    bounded_field: dict[str, object],
) -> None:
    payload = {
        "@type": "BlogPosting",
        "url": ARTICLE_ONE,
        "headline": "Anomali Cyber Watch: Bounded metadata",
        "datePublished": "2026-01-27T00:00:00Z",
        **bounded_field,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE, json_ld=payload))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


@pytest.mark.parametrize(
    "article",
    [
        article_html(ARTICLE_ONE, title="", published_at="2026-01-27T00:00:00Z"),
        article_html(ARTICLE_ONE, published_at=""),
        article_html(ARTICLE_ONE, title="General Anomali publication"),
    ],
)
def test_missing_required_metadata_and_unapproved_title_use_adapter_rejection(
    article: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_article_body_iocs_and_external_story_links_are_never_metadata() -> None:
    body = (
        '<article><h1>Anomali Cyber Watch: Body-only title</h1>'
        '<p>198.51.100.7 malware.example d41d8cd98f00b204e9800998ecf8427e</p>'
        '<a href="https://external.example/story">external story</a>'
        '<img src="https://media.example/image.png"></article>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article_html(ARTICLE_ONE, body=body))

    with client_for(handler) as client:
        candidate = client.fetch_publications(max_records=1).candidates[0]
    serialized = repr(candidate.safe_source_payload)
    assert "198.51.100.7" not in serialized
    assert "malware.example" not in serialized
    assert "d41d8" not in serialized
    assert "external.example" not in serialized
    assert set(candidate.safe_source_payload) == {"authors", "categories"}


def test_body_text_cannot_supply_missing_head_metadata() -> None:
    article = (
        "<html><head><link rel=\"canonical\" href=\""
        + ARTICLE_ONE
        + "\"></head><body><h1>Anomali Cyber Watch: Body title</h1>"
        "<time>2026-01-27T00:00:00Z</time></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE))
        return response(request, article)

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=1)
    assert result.failure_reasons == (AnomaliFailureReason.METADATA_REJECTED,)


def test_one_article_failure_does_not_prevent_later_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == DISCOVERY_URL:
            return response(request, discovery_html(ARTICLE_ONE, ARTICLE_TWO))
        if url == ARTICLE_ONE:
            return response(request, b"private", status=500)
        return response(request, article_html(ARTICLE_TWO))

    with client_for(handler) as client:
        result = client.fetch_publications(max_records=2)
    assert [candidate.canonical_url for candidate in result.candidates] == [ARTICLE_TWO]
    assert result.failure_reasons == (AnomaliFailureReason.HTTP_FAILURE,)
    assert result.failure_count == 1


def test_result_is_immutable_and_has_only_allow_listed_fields() -> None:
    with client_for(successful_handler) as client:
        result = client.fetch_publications(max_records=1)
    assert {field.name for field in fields(result)} == {
        "source_slug",
        "candidates",
        "failure_count",
        "failure_reasons",
        "discovered_approved_link_count",
        "capped",
    }
    assert isinstance(result.candidates, tuple)
    assert isinstance(result.failure_reasons, tuple)
    with pytest.raises(FrozenInstanceError):
        result.capped = True  # type: ignore[misc]
    assert "raw" not in repr(result).lower()
    assert "header" not in repr(result).lower()
    assert "cookie" not in repr(result).lower()


def test_client_owns_closes_and_idempotently_closes_injected_transport() -> None:
    transport = CountingTransport(
        lambda request: response(request, discovery_html())
    )
    clock = FakeClock()
    client = AnomaliPublicationsClient(
        http_transport=transport,
        monotonic_clock=clock,
        sleeper=clock.sleep,
    )
    with client as entered:
        assert entered is client
        entered.fetch_publications()
    client.close()
    assert transport.close_count == 1
    with pytest.raises(AnomaliCollectorConfigurationError):
        client.fetch_publications()


def test_normal_close_failure_is_sanitized_and_active_error_is_preserved() -> None:
    secret = "private close detail"
    transport = CountingTransport(
        lambda request: response(request, discovery_html()),
        close_error=RuntimeError(secret),
    )
    clock = FakeClock()
    client = AnomaliPublicationsClient(
        http_transport=transport,
        monotonic_clock=clock,
        sleeper=clock.sleep,
    )
    with pytest.raises(AnomaliTransportError) as exc_info:
        client.close()
    assert secret not in str(exc_info.value)
    assert transport.close_count == 1

    active_transport = CountingTransport(
        lambda request: (_ for _ in ()).throw(RuntimeError("request secret")),
        close_error=RuntimeError("close secret"),
    )
    active_clock = FakeClock()
    with pytest.raises(AnomaliDiscoveryCollectionError):
        with AnomaliPublicationsClient(
            http_transport=active_transport,
            monotonic_clock=active_clock,
            sleeper=active_clock.sleep,
        ) as active_client:
            active_client.fetch_publications()


@pytest.mark.parametrize(
    "system_error",
    [MemoryError(), KeyboardInterrupt(), SystemExit(), GeneratorExit()],
)
def test_system_exceptions_propagate_from_transport(system_error: BaseException) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise system_error

    with client_for(handler) as client:
        with pytest.raises(type(system_error)):
            client.fetch_publications()


def test_system_exceptions_propagate_from_discovery_and_metadata_parsers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def discovery_failure(self, data: str) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(collector_module._DiscoveryParser, "feed", discovery_failure)
    with client_for(lambda request: response(request, discovery_html())) as client:
        with pytest.raises(KeyboardInterrupt):
            client.fetch_publications()

    monkeypatch.undo()

    def metadata_failure(self, data: str) -> None:
        raise SystemExit

    monkeypatch.setattr(
        collector_module._PublicationMetadataParser,
        "feed",
        metadata_failure,
    )
    with client_for(successful_handler) as client:
        with pytest.raises(SystemExit):
            client.fetch_publications(max_records=1)


def test_system_exceptions_propagate_from_clock_sleeper_stream_and_close() -> None:
    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(successful_handler),
        monotonic_clock=lambda: (_ for _ in ()).throw(MemoryError()),
        sleeper=lambda seconds: None,
    ) as client:
        with pytest.raises(MemoryError):
            client.fetch_publications()

    clock = FakeClock()
    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(successful_handler),
        monotonic_clock=clock,
        sleeper=lambda seconds: (_ for _ in ()).throw(GeneratorExit()),
    ) as client:
        with pytest.raises(GeneratorExit):
            client.fetch_publications(max_records=1)

    stream_clock = FakeClock()

    def stream_handler(request: httpx.Request) -> httpx.Response:
        stream = TrackingStream([], KeyboardInterrupt())
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            stream=stream,
            request=request,
        )

    with AnomaliPublicationsClient(
        http_transport=httpx.MockTransport(stream_handler),
        monotonic_clock=stream_clock,
        sleeper=stream_clock.sleep,
    ) as client:
        with pytest.raises(KeyboardInterrupt):
            client.fetch_publications()

    close_transport = CountingTransport(
        lambda request: response(request, discovery_html()),
        close_error=SystemExit(),
    )
    close_clock = FakeClock()
    client = AnomaliPublicationsClient(
        http_transport=close_transport,
        monotonic_clock=close_clock,
        sleeper=close_clock.sleep,
    )
    with pytest.raises(SystemExit):
        client.close()
