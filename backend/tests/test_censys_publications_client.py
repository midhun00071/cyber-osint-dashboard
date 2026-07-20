from __future__ import annotations

import inspect
import json
from typing import Callable

import httpx
import pytest

from app.ingestion.collectors import censys_publications_client as client_module
from app.ingestion.collectors.censys_publications_client import (
    ACCEPT_HEADER,
    ALLOWED_CONTENT_TYPES,
    DEFAULT_TIMEOUT,
    MAX_JSON_LD_AUTHORS,
    MAX_JSON_LD_BLOCK_CHARS,
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    REQUEST_DELAY_SECONDS,
    SOURCE_POLICIES,
    USER_AGENT,
    CensysCollectionResult,
    CensysCollectorConfigurationError,
    CensysDiscoveryCollectionError,
    CensysFailureReason,
    CensysPacingError,
    CensysPublicationSource,
    CensysPublicationsClient,
    CensysRedirectError,
    CensysTransportError,
)


ARC = CensysPublicationSource.ARC
RAPID = CensysPublicationSource.RAPID_RESPONSE
ARC_DISCOVERY_URL = "https://censys.com/censys-arc/security-research/"
RAPID_DISCOVERY_URL = (
    "https://censys.com/censys-arc/rapid-response-advisories/"
)


class FakeClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


class ChunkedByteStream(httpx.SyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self._chunks = chunks

    def __iter__(self):
        yield from self._chunks


class RaisingTransport(httpx.BaseTransport):
    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.seen: list[str] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(str(request.url))
        raise self.error


class RaisingAfterChunkStream(httpx.SyncByteStream):
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def __iter__(self):
        yield b"<html>bounded-first-chunk"
        raise self.error


class AsyncOnlyTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        del request
        raise AssertionError("Async transport must never be used.")


class CountingCloseTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self.close_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        del request
        raise AssertionError("No request expected.")

    def close(self) -> None:
        self.close_count += 1


class CloseFailingTransport(httpx.BaseTransport):
    def __init__(self, *, request_error: BaseException | None = None) -> None:
        self.request_error = request_error

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        del request
        if self.request_error is not None:
            raise self.request_error
        raise AssertionError("No request expected.")

    def close(self) -> None:
        raise RuntimeError("SECRET-TRANSPORT-CLOSE")


def listing_html(
    source: CensysPublicationSource,
    hrefs: list[str],
    *,
    outside: str = "",
) -> bytes:
    entries = "".join(
        f'<article class="publication-card"><a href="{href}">item</a></article>'
        for href in hrefs
    )
    return (
        "<html><body>"
        f"{outside}<main><section data-censys-listing=\"{source.value}\">"
        f"{entries}</section></main></body></html>"
    ).encode()


def listing_entries_html(
    source: CensysPublicationSource,
    entries: list[list[str]],
) -> bytes:
    cards = "".join(
        "<article class=\"publication-card\">"
        + "".join(f'<a href="{href}">link</a>' for href in hrefs)
        + "</article>"
        for hrefs in entries
    )
    return (
        "<html><body><main>"
        f'<section data-censys-listing="{source.value}">{cards}</section>'
        "</main></body></html>"
    ).encode()


def publication_html(
    *,
    json_ld: object | str | None = None,
    head: str = "",
    body: str = "",
) -> bytes:
    script = ""
    if json_ld is not None:
        payload = json_ld if isinstance(json_ld, str) else json.dumps(json_ld)
        script = f'<script type="application/ld+json">{payload}</script>'
    return f"<html><head>{head}{script}</head><body>{body}</body></html>".encode()


def article_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "@type": "Article",
        "headline": "ARC headline",
        "description": "Bounded summary",
        "datePublished": "2026-07-01T08:00:00Z",
        "dateModified": "2026-07-02T08:00:00Z",
        "author": [{"name": "Researcher"}],
    }
    payload.update(overrides)
    return payload


def response(
    status: int = 200,
    *,
    content: bytes = b"",
    content_type: str | None = "text/html; charset=utf-8",
    headers: dict[str, str] | None = None,
    stream: httpx.SyncByteStream | None = None,
) -> httpx.Response:
    response_headers = dict(headers or {})
    if content_type is not None:
        response_headers["content-type"] = content_type
    if stream is not None:
        return httpx.Response(status, headers=response_headers, stream=stream)
    return httpx.Response(status, headers=response_headers, content=content)


def client_for(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    clock: FakeClock | None = None,
) -> tuple[CensysPublicationsClient, FakeClock]:
    fake = clock or FakeClock()
    return (
        CensysPublicationsClient(
            http_transport=httpx.MockTransport(handler),
            monotonic_clock=fake,
            sleeper=fake.sleep,
        ),
        fake,
    )


def successful_handler(
    source: CensysPublicationSource = ARC,
    hrefs: list[str] | None = None,
    *,
    publication: bytes | None = None,
    seen: list[str] | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    selected = hrefs or ["/blog/one/"]
    page = publication or publication_html(json_ld=article_payload())

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(str(request.url))
        policy = SOURCE_POLICIES[source]
        if request.url.path == policy.discovery_path:
            return response(content=listing_html(source, selected))
        return response(content=page)

    return handler


def collect(
    handler: Callable[[httpx.Request], httpx.Response],
    source: CensysPublicationSource = ARC,
    *,
    max_records: int = 5,
    clock: FakeClock | None = None,
) -> CensysCollectionResult:
    client, _ = client_for(handler, clock=clock)
    return client.fetch_publications(source, max_records=max_records)


def test_fixed_discovery_mapping_and_static_http_configuration() -> None:
    assert SOURCE_POLICIES[ARC].discovery_url == ARC_DISCOVERY_URL
    assert SOURCE_POLICIES[RAPID].discovery_url == RAPID_DISCOVERY_URL
    assert SOURCE_POLICIES[ARC].publication_prefix == "/blog/"
    assert SOURCE_POLICIES[RAPID].publication_prefix == "/advisory/"
    assert MAX_RESPONSE_BYTES == 2 * 1024 * 1024
    assert MAX_REDIRECTS == 3
    assert ALLOWED_CONTENT_TYPES == {"text/html", "application/xhtml+xml"}

    client = CensysPublicationsClient()
    try:
        assert client._http_client.timeout == DEFAULT_TIMEOUT
        assert client._http_client.follow_redirects is False
        assert client._http_client._trust_env is False
        assert len(client._http_client.cookies) == 0
        assert client._http_client._auth is None
        assert dict(client._http_client.headers) == {
            "user-agent": USER_AGENT,
            "accept": ACCEPT_HEADER,
        }
    finally:
        client.close()


def test_public_api_is_closed_and_max_records_defaults_to_five() -> None:
    signature = inspect.signature(CensysPublicationsClient.fetch_publications)
    assert list(signature.parameters) == ["self", "source", "max_records"]
    assert signature.parameters["max_records"].default == 5
    forbidden = {"url", "discovery_url", "publication_url", "host", "path_prefix"}
    assert forbidden.isdisjoint(signature.parameters)

    constructor = inspect.signature(CensysPublicationsClient)
    assert "http_transport" in constructor.parameters
    assert "http_client" not in constructor.parameters
    for forbidden_configuration in [
        {"http_client": object()},
        {"headers": {"X-Unrelated-Default": "private"}},
        {"cookies": {"session": "private"}},
        {"auth": ("private", "private")},
        {"timeout": None},
        {"trust_env": True},
    ]:
        with pytest.raises(TypeError):
            CensysPublicationsClient(**forbidden_configuration)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_transport",
    [object(), "SECRET-TRANSPORT", 7, True, AsyncOnlyTransport()],
)
def test_invalid_and_async_transports_are_rejected_before_client_construction(
    invalid_transport: object,
) -> None:
    with pytest.raises(CensysCollectorConfigurationError) as exc_info:
        CensysPublicationsClient(
            http_transport=invalid_transport,  # type: ignore[arg-type]
        )

    assert str(exc_info.value) == "The Censys collector transport is invalid."
    assert "SECRET-TRANSPORT" not in str(exc_info.value)
    assert "handle_request" not in str(exc_info.value)
    assert repr(invalid_transport) not in str(exc_info.value)


@pytest.mark.parametrize("maximum", [1, 20])
def test_max_records_accepts_closed_boundary_values(maximum: int) -> None:
    result = collect(successful_handler(), max_records=maximum)
    assert result.discovered_approved_link_count == 1


@pytest.mark.parametrize("invalid", [0, -1, True, False, "5", 21, 100, 1.0])
def test_max_records_rejects_invalid_types_and_ranges(invalid: object) -> None:
    client, _ = client_for(lambda request: response())
    with pytest.raises(CensysCollectorConfigurationError, match="1 through 20"):
        client.fetch_publications(ARC, max_records=invalid)  # type: ignore[arg-type]


def test_source_selector_rejects_open_strings() -> None:
    client, _ = client_for(lambda request: response())
    with pytest.raises(CensysCollectorConfigurationError):
        client.fetch_publications("arc")  # type: ignore[arg-type]


def test_fixed_headers_and_arc_request_order_are_enforced() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        assert request.method == "GET"
        assert request.headers["user-agent"] == USER_AGENT
        assert request.headers["accept"] == ACCEPT_HEADER
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        assert "x-unrelated-default" not in request.headers
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(
                content=listing_html(
                    ARC,
                    ["/blog/newest/", "/blog/older/", "/blog/newest/"],
                )
            )
        return response(content=publication_html(json_ld=article_payload()))

    result = collect(handler)

    assert seen == [
        ARC_DISCOVERY_URL,
        "https://censys.com/blog/newest/",
        "https://censys.com/blog/older/",
    ]
    assert [item.canonical_url for item in result.candidates] == [
        "https://censys.com/blog/newest/",
        "https://censys.com/blog/older/",
    ]
    assert result.discovered_approved_link_count == 2
    assert result.capped is False


def test_rapid_response_uses_only_advisory_family_and_fixed_category() -> None:
    seen: list[str] = []
    result = collect(
        successful_handler(RAPID, ["/advisory/current/"], seen=seen),
        RAPID,
    )

    assert seen == [RAPID_DISCOVERY_URL, "https://censys.com/advisory/current/"]
    assert result.source is RAPID
    assert result.source_slug == "censys-rapid-response-advisories"
    assert result.candidates[0].safe_source_payload["categories"] == (
        "Rapid Response",
    )


def test_max_records_caps_requests_and_reports_additional_approved_links() -> None:
    seen: list[str] = []
    result = collect(
        successful_handler(
            ARC,
            ["/blog/one/", "/blog/two/", "/blog/three/"],
            seen=seen,
        ),
        max_records=2,
    )

    assert seen == [
        ARC_DISCOVERY_URL,
        "https://censys.com/blog/one/",
        "https://censys.com/blog/two/",
    ]
    assert result.discovered_approved_link_count == 2
    assert result.capped is True


def test_only_trusted_listing_entries_are_discovered() -> None:
    outside = (
        '<nav><a href="/blog/navigation/">nav</a></nav>'
        '<header><a href="/blog/header/">header</a></header>'
        '<div class="product-marketing"><a href="/blog/marketing/">demo</a></div>'
        '<footer><a href="/blog/footer/">footer</a></footer>'
    )
    discovery = listing_html(ARC, ["/blog/approved/"], outside=outside).decode()
    discovery = discovery.replace(
        "</section>",
        '<a href="/blog/direct-marketing/">marketing</a>'
        '<article><a href="/advisory/wrong-family/">wrong</a></article>'
        '<form><article><a href="/blog/form/">form</a></article></form>'
        "</section>",
    ).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(content=discovery)
        assert request.url.path == "/blog/approved/"
        return response(content=publication_html(json_ld=article_payload()))

    result = collect(handler)
    assert [item.canonical_url for item in result.candidates] == [
        "https://censys.com/blog/approved/"
    ]


@pytest.mark.parametrize(
    "raw_reference",
    [
        "/blog/a/../b/",
        "/blog/./b/",
        "../blog/b/",
        " /blog/b/",
        "/blog/b/ ",
        "//censys.com/blog/b/",
    ],
)
def test_raw_discovery_references_are_rejected_before_resolution(
    raw_reference: str,
) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return response(content=listing_html(ARC, [raw_reference]))

    result = collect(handler)

    assert seen == [ARC_DISCOVERY_URL]
    assert result.discovered_approved_link_count == 0
    assert result.candidates == ()
    assert raw_reference not in repr(result)


@pytest.mark.parametrize(
    "raw_reference",
    [
        "/blog/a/../b/",
        "/blog/./b/",
        "../blog/b/",
        " /blog/b/",
        "/blog/b/ ",
        "//censys.com/blog/b/",
    ],
)
def test_raw_redirect_references_are_rejected_before_resolution(
    raw_reference: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(content=listing_html(ARC, ["/blog/start/"]))
        return response(302, headers={"location": raw_reference})

    result = collect(handler)

    assert result.failure_reasons == (CensysFailureReason.REDIRECT_REJECTED,)
    assert raw_reference not in repr(result)


@pytest.mark.parametrize(
    "raw_reference",
    [
        "/blog/a/../b/",
        "/blog/./b/",
        "../blog/b/",
        " /blog/b/",
        "/blog/b/ ",
        "//censys.com/blog/b/",
    ],
)
def test_raw_canonical_references_are_rejected_before_resolution(
    raw_reference: str,
) -> None:
    page = publication_html(
        json_ld=article_payload(),
        head=f'<link rel="canonical" href="{raw_reference}">',
    )
    result = collect(successful_handler(publication=page))

    assert result.failure_reasons == (CensysFailureReason.METADATA_REJECTED,)
    assert raw_reference not in repr(result)


def test_repeated_links_within_one_entry_are_accepted_once() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(
                content=listing_entries_html(
                    ARC,
                    [["/blog/repeated/", "/blog/repeated/"]],
                )
            )
        return response(content=publication_html(json_ld=article_payload()))

    result = collect(handler)

    assert result.discovered_approved_link_count == 1
    assert seen == [ARC_DISCOVERY_URL, "https://censys.com/blog/repeated/"]


def test_category_link_cannot_replace_the_publication_link_in_a_card() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(
                content=listing_entries_html(
                    ARC,
                    [["/blog/category/research/", "/blog/publication/"]],
                )
            )
        assert request.url.path == "/blog/publication/"
        return response(content=publication_html(json_ld=article_payload()))

    result = collect(handler)

    assert [candidate.canonical_url for candidate in result.candidates] == [
        "https://censys.com/blog/publication/"
    ]


def test_ambiguous_entry_is_skipped_and_later_valid_entry_is_processed() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(
                content=listing_entries_html(
                    ARC,
                    [
                        ["/blog/first/", "/blog/second/"],
                        ["/blog/later-valid/"],
                    ],
                )
            )
        return response(content=publication_html(json_ld=article_payload()))

    result = collect(handler)

    assert result.discovered_approved_link_count == 1
    assert seen == [ARC_DISCOVERY_URL, "https://censys.com/blog/later-valid/"]


def test_max_records_counts_only_accepted_unique_entries() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(
                content=listing_entries_html(
                    ARC,
                    [
                        ["/blog/ambiguous-one/", "/blog/ambiguous-two/"],
                        ["/blog/accepted/", "/blog/accepted/"],
                        ["/blog/capped/"],
                    ],
                )
            )
        return response(content=publication_html(json_ld=article_payload()))

    result = collect(handler, max_records=1)

    assert result.discovered_approved_link_count == 1
    assert result.capped is True
    assert seen == [ARC_DISCOVERY_URL, "https://censys.com/blog/accepted/"]


def test_discovery_fails_without_a_trustworthy_listing_region() -> None:
    private_url = "https://censys.com/blog/private-detail/"

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return response(
            content=f'<main><article><a href="{private_url}">item</a></article></main>'.encode()
        )

    with pytest.raises(CensysDiscoveryCollectionError) as exc_info:
        collect(handler)
    assert str(exc_info.value) == "Censys discovery collection failed."
    assert private_url not in str(exc_info.value)


@pytest.mark.parametrize(
    "url",
    [
        "http://censys.com/blog/example/",
        "https://example.com/blog/example/",
        "https://www.censys.com/blog/example/",
        "https://127.0.0.1/blog/example/",
        "https://user:secret@censys.com/blog/example/",
        "https://@censys.com/blog/example/",
        "https://censys.com:444/blog/example/",
        "https://censys.com:/blog/example/",
        "https://censys.com/blog/example/?page=1",
        "https://censys.com/blog/example/#fragment",
        "https://censys.com\\blog\\example/",
        "https://censys.com/blog%2Fexample/",
        "https://censys.com/blog/%5cexample/",
        "https://censys.com/blog/../advisory/example/",
        "https://censys.com/blog/./example/",
        "https://censys.com/blog/%ZZ/",
        "https://censys.com/blog/%2/",
        "https://censys.com/blog/space here/",
        "https://censys.com/blog/unicode-\u2603/",
        "https://censys.com/blog/example;parameter/",
        "https://censys.com/advisory/wrong-family/",
    ],
)
def test_publication_url_policy_rejects_unsafe_destinations_without_disclosure(
    url: str,
) -> None:
    with pytest.raises(CensysRedirectError) as exc_info:
        client_module._validate_url(
            url,
            policy=SOURCE_POLICIES[ARC],
            request_kind="publication",
        )
    assert url not in str(exc_info.value)
    assert "secret" not in str(exc_info.value)


def test_explicit_default_port_is_accepted_and_canonicalized() -> None:
    canonical = client_module._validate_url(
        "https://censys.com:443/blog/example/",
        policy=SOURCE_POLICIES[ARC],
        request_kind="publication",
    )
    assert canonical == "https://censys.com/blog/example/"


@pytest.mark.parametrize(
    ("source", "url"),
    [
        (ARC, "https://censys.com/blog/category/research/"),
        (ARC, "https://censys.com/blog/author/researcher/"),
        (ARC, "https://censys.com/blog/example"),
        (ARC, "https://censys.com/blog/example_slug/"),
        (RAPID, "https://censys.com/advisory/category/current/"),
        (RAPID, "https://censys.com/advisory/example/details/"),
        (RAPID, "https://censys.com/advisory/example"),
    ],
)
def test_live_publication_paths_require_one_ascii_slug_and_trailing_slash(
    source: CensysPublicationSource,
    url: str,
) -> None:
    with pytest.raises(CensysRedirectError) as exc_info:
        client_module._validate_url(
            url,
            policy=SOURCE_POLICIES[source],
            request_kind="publication",
        )
    assert url not in str(exc_info.value)


def test_same_host_same_family_redirect_works_and_is_paced() -> None:
    seen: list[tuple[str, float]] = []
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), clock.value))
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(content=listing_html(ARC, ["/blog/old/"]))
        if request.url.path == "/blog/old/":
            return response(302, headers={"location": "/blog/new/"})
        return response(content=publication_html(json_ld=article_payload()))

    result = collect(handler, clock=clock)

    assert result.candidates[0].canonical_url == "https://censys.com/blog/new/"
    assert [started for _, started in seen] == [0.0, 10.0, 20.0]
    assert clock.sleeps == [10.0, 10.0]


@pytest.mark.parametrize(
    ("location", "reason"),
    [
        ("https://example.com/blog/new/", CensysFailureReason.REDIRECT_REJECTED),
        ("/advisory/new/", CensysFailureReason.REDIRECT_REJECTED),
        ("http://censys.com/blog/new/", CensysFailureReason.REDIRECT_REJECTED),
        ("/blog/new/?token=secret", CensysFailureReason.REDIRECT_REJECTED),
    ],
)
def test_unsafe_publication_redirects_become_safe_page_failures(
    location: str,
    reason: CensysFailureReason,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(content=listing_html(ARC, ["/blog/old/"]))
        return response(302, headers={"location": location})

    result = collect(handler)
    assert result.failure_reasons == (reason,)
    assert location not in repr(result.failure_reasons)


def test_redirect_loop_limit_and_missing_location_fail_safely() -> None:
    modes = ["loop", "limit", "missing"]
    for mode in modes:
        def handler(request: httpx.Request, mode: str = mode) -> httpx.Response:
            if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
                return response(content=listing_html(ARC, ["/blog/r0/"]))
            if mode == "missing":
                return response(302)
            if mode == "loop":
                return response(302, headers={"location": str(request.url)})
            number = int(request.url.path.rstrip("/").rsplit("r", 1)[1])
            return response(302, headers={"location": f"/blog/r{number + 1}/"})

        result = collect(handler)
        assert result.failure_reasons == (CensysFailureReason.REDIRECT_REJECTED,)


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (429, CensysFailureReason.RATE_LIMITED),
        (404, CensysFailureReason.HTTP_FAILURE),
        (500, CensysFailureReason.HTTP_FAILURE),
    ],
)
def test_publication_http_failures_are_sanitized(
    status: int,
    reason: CensysFailureReason,
) -> None:
    private_body = b"private upstream body with https://private.example/"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(content=listing_html(ARC, ["/blog/failure/"]))
        return response(status, content=private_body)

    result = collect(handler)
    assert result.failure_reasons == (reason,)
    assert "private" not in repr(result.failure_reasons)


def test_discovery_http_403_fails_safely_without_bypass_or_alternate_request() -> None:
    seen: list[str] = []
    private_body = b"SUPER_SECRET_FETCHER_CANARY"

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return response(403, content=private_body)

    client, _ = client_for(handler)
    with client:
        with pytest.raises(CensysDiscoveryCollectionError) as exc_info:
            client.fetch_publications(ARC, max_records=1)

    assert seen == [ARC_DISCOVERY_URL]
    assert str(exc_info.value) == "Censys discovery collection failed."
    assert "SUPER_SECRET_FETCHER_CANARY" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("exception_type", "reason"),
    [
        (httpx.ConnectError, CensysFailureReason.TRANSPORT_FAILURE),
        (httpx.ReadTimeout, CensysFailureReason.TIMEOUT),
    ],
)
def test_transport_and_timeout_details_are_sanitized(
    exception_type: type[httpx.TransportError],
    reason: CensysFailureReason,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(content=listing_html(ARC, ["/blog/failure/"]))
        raise exception_type("private transport detail", request=request)

    result = collect(handler)
    assert result.failure_reasons == (reason,)
    assert "private transport detail" not in repr(result)


def test_discovery_transport_failure_returns_no_partial_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("private discovery detail", request=request)

    with pytest.raises(CensysDiscoveryCollectionError) as exc_info:
        collect(handler)
    assert str(exc_info.value) == "Censys discovery collection failed."
    assert "private discovery detail" not in str(exc_info.value)


def test_unexpected_discovery_transport_runtime_error_is_sanitized() -> None:
    private_detail = "SECRET-TRANSPORT"
    transport = RaisingTransport(RuntimeError(private_detail))
    clock = FakeClock()
    client = CensysPublicationsClient(
        http_transport=transport,
        monotonic_clock=clock,
        sleeper=clock.sleep,
    )

    with pytest.raises(CensysDiscoveryCollectionError) as exc_info:
        client.fetch_publications(ARC)

    assert str(exc_info.value) == "Censys discovery collection failed."
    assert private_detail not in str(exc_info.value)
    assert transport.seen == [ARC_DISCOVERY_URL]


def test_unexpected_discovery_stream_runtime_error_is_sanitized() -> None:
    private_detail = "SECRET-STREAM"
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return response(stream=RaisingAfterChunkStream(RuntimeError(private_detail)))

    with pytest.raises(CensysDiscoveryCollectionError) as exc_info:
        collect(handler)

    assert str(exc_info.value) == "Censys discovery collection failed."
    assert private_detail not in str(exc_info.value)
    assert seen == [ARC_DISCOVERY_URL]


def test_unexpected_publication_transport_failure_allows_later_success() -> None:
    private_detail = "SECRET-PUBLICATION-TRANSPORT"
    failed_path = "/blog/private-failed-url/"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(
                content=listing_html(ARC, [failed_path, "/blog/later-valid/"])
            )
        if request.url.path == failed_path:
            raise RuntimeError(private_detail)
        return response(content=publication_html(json_ld=article_payload()))

    result = collect(handler)

    assert result.failure_count == 1
    assert result.failure_reasons == (CensysFailureReason.TRANSPORT_FAILURE,)
    assert [candidate.canonical_url for candidate in result.candidates] == [
        "https://censys.com/blog/later-valid/"
    ]
    assert private_detail not in repr(result)
    assert failed_path not in repr(result)


def test_unexpected_publication_stream_failure_allows_later_success() -> None:
    private_detail = "SECRET-PUBLICATION-STREAM"
    failed_path = "/blog/private-stream-url/"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(
                content=listing_html(ARC, [failed_path, "/blog/later-stream-valid/"])
            )
        if request.url.path == failed_path:
            return response(
                stream=RaisingAfterChunkStream(RuntimeError(private_detail))
            )
        return response(content=publication_html(json_ld=article_payload()))

    result = collect(handler)

    assert result.failure_count == 1
    assert result.failure_reasons == (CensysFailureReason.TRANSPORT_FAILURE,)
    assert [candidate.canonical_url for candidate in result.candidates] == [
        "https://censys.com/blog/later-stream-valid/"
    ]
    assert private_detail not in repr(result)
    assert failed_path not in repr(result)


@pytest.mark.parametrize(
    "system_error",
    [KeyboardInterrupt(), SystemExit(7), GeneratorExit(), MemoryError("private")],
)
def test_system_level_transport_exceptions_propagate(
    system_error: BaseException,
) -> None:
    transport = RaisingTransport(system_error)
    clock = FakeClock()
    client = CensysPublicationsClient(
        http_transport=transport,
        monotonic_clock=clock,
        sleeper=clock.sleep,
    )

    with pytest.raises(type(system_error)) as exc_info:
        client.fetch_publications(ARC)

    assert exc_info.value is system_error


def test_independent_discovery_and_publication_streaming_limits() -> None:
    overflow = ChunkedByteStream((b"x" * MAX_RESPONSE_BYTES, b"private-overflow"))

    def oversized_discovery(request: httpx.Request) -> httpx.Response:
        del request
        return response(stream=overflow)

    with pytest.raises(CensysDiscoveryCollectionError):
        collect(oversized_discovery)

    def oversized_publication(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(content=listing_html(ARC, ["/blog/large/"]))
        return response(
            stream=ChunkedByteStream(
                (b"x" * MAX_RESPONSE_BYTES, b"private-publication-overflow")
            )
        )

    result = collect(oversized_publication)
    assert result.failure_reasons == (CensysFailureReason.RESPONSE_TOO_LARGE,)
    assert "private" not in repr(result)


@pytest.mark.parametrize(
    "content_type",
    [None, "application/json", "application/rss+xml", "text/plain", "image/png"],
)
def test_missing_and_unsupported_publication_content_types_are_rejected(
    content_type: str | None,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(content=listing_html(ARC, ["/blog/type/"]))
        return response(
            content=publication_html(json_ld=article_payload()),
            content_type=content_type,
        )

    result = collect(handler)
    assert result.failure_reasons == (CensysFailureReason.CONTENT_TYPE_REJECTED,)


@pytest.mark.parametrize(
    "content_type",
    ["text/html; charset=utf-8", "application/xhtml+xml; charset=UTF-8"],
)
def test_html_content_type_parameters_are_accepted(content_type: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(content=listing_html(ARC, ["/blog/type/"]))
        return response(
            content=publication_html(json_ld=article_payload()),
            content_type=content_type,
        )

    assert collect(handler).failure_count == 0


def test_ten_second_delay_uses_fake_clock_without_real_waiting() -> None:
    starts: list[float] = []
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        starts.append(clock.value)
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(
                content=listing_html(ARC, ["/blog/one/", "/blog/two/"])
            )
        return response(content=publication_html(json_ld=article_payload()))

    collect(handler, clock=clock)

    assert starts == [0.0, 10.0, 20.0]
    assert clock.sleeps == [REQUEST_DELAY_SECONDS, REQUEST_DELAY_SECONDS]


def test_no_unnecessary_sleep_after_more_than_ten_seconds_elapsed() -> None:
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            clock.value += 11.0
            return response(content=listing_html(ARC, ["/blog/one/"]))
        return response(content=publication_html(json_ld=article_payload()))

    collect(handler, clock=clock)
    assert clock.sleeps == []


def test_pacing_failure_aborts_without_attempting_later_pages() -> None:
    clock = FakeClock()
    seen: list[str] = []

    def broken_sleeper(seconds: float) -> None:
        del seconds
        raise RuntimeError("private sleeper detail")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return response(
            content=listing_html(ARC, ["/blog/one/", "/blog/two/"])
        )

    client = CensysPublicationsClient(
        http_transport=httpx.MockTransport(handler),
        monotonic_clock=clock,
        sleeper=broken_sleeper,
    )
    with pytest.raises(CensysPacingError) as exc_info:
        client.fetch_publications(ARC)

    assert str(exc_info.value) == "Censys request pacing failed."
    assert "private sleeper detail" not in str(exc_info.value)
    assert seen == [SOURCE_POLICIES[ARC].discovery_path]


@pytest.mark.parametrize(
    "payload",
    [
        article_payload(**{"@type": "Article"}),
        article_payload(**{"@type": "BlogPosting"}),
        article_payload(**{"@type": "NewsArticle"}),
        article_payload(**{"@type": ["Thing", "Article"]}),
        {"@graph": [{"@type": "Organization", "name": "Censys"}, article_payload()]},
        [{"@type": "Organization"}, article_payload()],
    ],
)
def test_supported_json_ld_shapes_are_extracted(payload: object) -> None:
    result = collect(
        successful_handler(publication=publication_html(json_ld=payload))
    )
    candidate = result.candidates[0]
    assert candidate.canonical_title == "ARC headline"
    assert candidate.summary == "Bounded summary"
    assert candidate.safe_source_payload["authors"] == ("Researcher",)


def test_later_matching_json_ld_object_wins_over_related_first_article() -> None:
    payload = [
        article_payload(
            url="https://censys.com/blog/related/",
            headline="Related headline",
        ),
        article_payload(
            url="https://censys.com/blog/one/",
            headline="Matching headline",
        ),
    ]

    candidate = collect(
        successful_handler(publication=publication_html(json_ld=payload))
    ).candidates[0]

    assert candidate.canonical_title == "Matching headline"


@pytest.mark.parametrize(
    "identity_fields",
    [
        {"url": "https://censys.com/blog/one/"},
        {"mainEntityOfPage": "https://censys.com/blog/one/"},
        {"mainEntityOfPage": {"@id": "https://censys.com/blog/one/"}},
    ],
)
def test_json_ld_identity_forms_select_the_matching_object(
    identity_fields: dict[str, object],
) -> None:
    payload = [
        article_payload(
            url="https://censys.com/blog/unrelated/",
            headline="Unrelated headline",
        ),
        article_payload(headline="Identity match", **identity_fields),
    ]

    candidate = collect(
        successful_handler(publication=publication_html(json_ld=payload))
    ).candidates[0]

    assert candidate.canonical_title == "Identity match"


def test_multiple_unmatched_json_ld_objects_use_head_fallback() -> None:
    payload = [
        article_payload(
            url="https://censys.com/blog/unmatched-one/",
            headline="First unrelated headline",
        ),
        article_payload(
            url="https://censys.com/blog/unmatched-two/",
            headline="Second unrelated headline",
        ),
    ]
    head = (
        '<meta property="og:title" content="Head fallback">'
        '<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
    )

    candidate = collect(
        successful_handler(publication=publication_html(json_ld=payload, head=head))
    ).candidates[0]

    assert candidate.canonical_title == "Head fallback"


def test_conflicting_matching_json_ld_objects_use_head_fallback() -> None:
    payload = [
        article_payload(
            url="https://censys.com/blog/one/",
            headline="First matching headline",
        ),
        article_payload(
            mainEntityOfPage={"@id": "https://censys.com/blog/one/"},
            headline="Conflicting matching headline",
        ),
    ]
    head = (
        '<meta property="og:title" content="Conflict fallback">'
        '<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
    )

    candidate = collect(
        successful_handler(publication=publication_html(json_ld=payload, head=head))
    ).candidates[0]

    assert candidate.canonical_title == "Conflict fallback"


def test_single_identity_free_json_ld_object_remains_supported() -> None:
    candidate = collect(
        successful_handler(publication=publication_html(json_ld=article_payload()))
    ).candidates[0]
    assert candidate.canonical_title == "ARC headline"


def test_invalid_json_ld_identity_is_ignored_safely() -> None:
    invalid_identity = "/blog/a/../one/"
    payload = article_payload(url=invalid_identity, headline="Unsafe identity title")
    head = (
        '<meta property="og:title" content="Safe identity fallback">'
        '<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
    )

    result = collect(
        successful_handler(publication=publication_html(json_ld=payload, head=head))
    )

    assert result.candidates[0].canonical_title == "Safe identity fallback"
    assert invalid_identity not in repr(result)


def test_oversized_early_json_ld_block_consumes_block_count_allowance() -> None:
    fallback_head = (
        '<meta property="og:title" content="Block-count fallback">'
        '<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
    )
    oversized = (
        '<script type="application/ld+json">'
        + (" " * (MAX_JSON_LD_BLOCK_CHARS + 1))
        + "</script>"
    )
    malformed = '<script type="application/ld+json">{malformed</script>' * 9
    late_valid = (
        '<script type="application/ld+json">'
        + json.dumps(article_payload(headline="Too-late JSON-LD"))
        + "</script>"
    )
    page = (
        f"<html><head>{fallback_head}{oversized}{malformed}{late_valid}"
        "</head><body></body></html>"
    ).encode()

    candidate = collect(successful_handler(publication=page)).candidates[0]

    assert candidate.canonical_title == "Block-count fallback"


def test_unrelated_and_malformed_json_ld_are_ignored_for_safe_fallbacks() -> None:
    fallback_head = (
        "<title>Document fallback</title>"
        '<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
    )
    for json_ld in [
        {"@type": "Organization", "name": "Censys"},
        "{malformed private json",
    ]:
        result = collect(
            successful_handler(
                publication=publication_html(json_ld=json_ld, head=fallback_head)
            )
        )
        assert result.candidates[0].canonical_title == "Document fallback"


def test_oversized_and_deep_json_ld_are_safely_ignored() -> None:
    fallback_head = (
        '<meta property="og:title" content="Safe fallback">'
        '<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
        '<meta name="author" content="Fallback Author">'
    )
    deep: object = "leaf"
    for _ in range(12):
        deep = {"nested": deep}
    payloads: list[object | str] = [
        json.dumps(article_payload()) + (" " * (MAX_JSON_LD_BLOCK_CHARS + 1)),
        article_payload(extra=deep),
    ]
    for payload in payloads:
        result = collect(
            successful_handler(
                publication=publication_html(json_ld=payload, head=fallback_head)
            )
        )
        candidate = result.candidates[0]
        assert candidate.canonical_title == "Safe fallback"
        assert candidate.safe_source_payload["authors"] == ("Fallback Author",)


def test_excessive_json_ld_authors_are_bounded_with_safe_meta_fallback() -> None:
    head = (
        '<meta property="og:title" content="Safe fallback">'
        '<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
        '<meta name="author" content="Fallback Author">'
    )
    result = collect(
        successful_handler(
            publication=publication_html(
                json_ld=article_payload(
                    author=["author"] * (MAX_JSON_LD_AUTHORS + 1)
                ),
                head=head,
            )
        )
    )

    candidate = result.candidates[0]
    assert candidate.canonical_title == "ARC headline"
    assert candidate.safe_source_payload["authors"] == ("Fallback Author",)


def test_json_ld_and_head_metadata_precedence_is_deterministic() -> None:
    head = (
        "<title>Document title</title>"
        '<meta property="og:title" content="OG title">'
        '<meta name="description" content="Meta description">'
        '<meta property="og:description" content="OG description">'
        '<meta property="article:published_time" content="2020-01-01T00:00:00Z">'
        '<meta property="article:modified_time" content="2020-01-02T00:00:00Z">'
        '<meta name="author" content="Meta Author">'
    )
    result = collect(
        successful_handler(
            publication=publication_html(json_ld=article_payload(), head=head)
        )
    )
    candidate = result.candidates[0]
    assert candidate.canonical_title == "ARC headline"
    assert candidate.summary == "Bounded summary"
    assert candidate.source_published_at.isoformat() == "2026-07-01T08:00:00+00:00"
    assert candidate.source_modified_at.isoformat() == "2026-07-02T08:00:00+00:00"
    assert candidate.safe_source_payload["authors"] == ("Researcher",)


def test_open_graph_standard_description_and_document_title_fallbacks() -> None:
    head = (
        "<title>Document title</title>"
        '<meta property="og:title" content="OG title">'
        '<meta name="description" content="Standard description">'
        '<meta property="og:description" content="OG description">'
        '<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
        '<meta property="article:modified_time" content="2026-07-02T08:00:00Z">'
        '<meta name="author" content="Meta Author">'
    )
    result = collect(successful_handler(publication=publication_html(head=head)))
    candidate = result.candidates[0]
    assert candidate.canonical_title == "OG title"
    assert candidate.summary == "Standard description"
    assert candidate.source_modified_at is not None
    assert candidate.safe_source_payload["authors"] == ("Meta Author",)

    document_only = (
        "<title>Only document title</title>"
        '<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
    )
    candidate = collect(
        successful_handler(publication=publication_html(head=document_only))
    ).candidates[0]
    assert candidate.canonical_title == "Only document title"
    assert candidate.summary is None


def test_canonical_link_precedes_final_url_and_final_url_is_fallback() -> None:
    canonical_head = '<link rel="canonical" href="/blog/canonical/">'
    candidate = collect(
        successful_handler(
            hrefs=["/blog/requested/"],
            publication=publication_html(json_ld=article_payload(), head=canonical_head),
        )
    ).candidates[0]
    assert candidate.canonical_url == "https://censys.com/blog/canonical/"

    fallback = collect(
        successful_handler(
            hrefs=["/blog/final-fallback/"],
            publication=publication_html(json_ld=article_payload()),
        )
    ).candidates[0]
    assert fallback.canonical_url == "https://censys.com/blog/final-fallback/"


@pytest.mark.parametrize(
    "page",
    [
        publication_html(
            head='<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
        ),
        publication_html(head="<title>Missing date</title>"),
        publication_html(
            json_ld=article_payload(),
            head='<link rel="canonical" href="https://example.com/blog/private/">',
        ),
    ],
)
def test_missing_required_metadata_and_invalid_canonical_are_page_failures(
    page: bytes,
) -> None:
    result = collect(successful_handler(publication=page))
    assert result.failure_reasons == (CensysFailureReason.METADATA_REJECTED,)
    assert result.candidates == ()


def test_one_failed_publication_does_not_block_later_pages() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == SOURCE_POLICIES[ARC].discovery_path:
            return response(
                content=listing_html(ARC, ["/blog/bad/", "/blog/good/"])
            )
        if request.url.path == "/blog/bad/":
            return response(content=publication_html(head="<title>No date</title>"))
        return response(content=publication_html(json_ld=article_payload()))

    result = collect(handler)
    assert seen[-2:] == ["/blog/bad/", "/blog/good/"]
    assert result.failure_count == 1
    assert len(result.candidates) == 1
    assert result.candidates[0].canonical_url.endswith("/blog/good/")


def test_body_scripts_styles_code_and_iocs_are_never_used_or_returned() -> None:
    private_body = (
        "<article>PRIVATE FULL BODY 203.0.113.9</article>"
        "<script>dangerousCommand()</script><style>.private{}</style>"
        "<pre><code>scan --target private.example</code></pre>"
        "<!-- private comment -->"
    )
    head = (
        "<title>Safe title</title>"
        '<meta property="article:published_time" content="2026-07-01T08:00:00Z">'
    )
    result = collect(
        successful_handler(publication=publication_html(head=head, body=private_body))
    )
    candidate = result.candidates[0]
    assert candidate.summary is None
    serialized = repr(result)
    for forbidden in [
        "PRIVATE FULL BODY",
        "203.0.113.9",
        "dangerousCommand",
        "scan --target",
        "<article>",
        "application/ld+json",
    ]:
        assert forbidden not in serialized


@pytest.mark.parametrize(
    "exception_type",
    [AssertionError, RecursionError, UnicodeError, ValueError],
)
def test_unexpected_discovery_parser_failures_are_sanitized(
    exception_type: type[Exception],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_detail = "private discovery parser detail <html>"

    def fail_parser(self: object, data: str) -> None:
        del self, data
        raise exception_type(private_detail)

    monkeypatch.setattr(client_module._DiscoveryParser, "feed", fail_parser)

    with pytest.raises(CensysDiscoveryCollectionError) as exc_info:
        collect(successful_handler())

    assert str(exc_info.value) == "Censys discovery collection failed."
    assert private_detail not in str(exc_info.value)


@pytest.mark.parametrize(
    "exception_type",
    [AssertionError, RecursionError, UnicodeError, ValueError],
)
def test_unexpected_metadata_parser_failures_are_sanitized(
    exception_type: type[Exception],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_detail = "private metadata parser detail <html>"

    def fail_parser(self: object, data: str) -> None:
        del self, data
        raise exception_type(private_detail)

    monkeypatch.setattr(
        client_module._PublicationMetadataParser,
        "feed",
        fail_parser,
    )

    result = collect(successful_handler())

    assert result.failure_reasons == (CensysFailureReason.METADATA_REJECTED,)
    assert private_detail not in repr(result)


def test_every_complete_record_passes_through_existing_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []
    real_adapter = client_module.adapt_censys_publication

    def recording_adapter(source_slug: str, record: object):
        calls.append((source_slug, record))
        return real_adapter(source_slug, record)

    monkeypatch.setattr(client_module, "adapt_censys_publication", recording_adapter)
    result = collect(successful_handler())

    assert len(calls) == 1
    assert calls[0][0] == "censys-arc-research"
    assert result.candidates[0].source_external_id.startswith("censys:arc-research:")
    assert "<html" not in repr(result).lower()


def test_context_manager_closes_collector_owned_http_client() -> None:
    with CensysPublicationsClient() as owned:
        owned_http_client = owned._http_client
    assert owned_http_client.is_closed


def test_close_is_idempotent_and_closes_transport_once() -> None:
    transport = CountingCloseTransport()
    client = CensysPublicationsClient(http_transport=transport)

    client.close()
    client.close()

    assert transport.close_count == 1
    assert client._closed is True


def test_fetch_after_close_raises_static_configuration_error() -> None:
    transport = CountingCloseTransport()
    client = CensysPublicationsClient(http_transport=transport)
    client.close()

    with pytest.raises(CensysCollectorConfigurationError) as exc_info:
        client.fetch_publications(ARC)

    assert str(exc_info.value) == "The Censys collector is closed."
    assert "Cannot send a request" not in str(exc_info.value)
    assert transport.close_count == 1


def test_transport_close_failure_is_sanitized_and_remains_idempotent() -> None:
    private_detail = "SECRET-TRANSPORT-CLOSE"
    client = CensysPublicationsClient(http_transport=CloseFailingTransport())

    with pytest.raises(CensysTransportError) as exc_info:
        client.close()

    assert str(exc_info.value) == "The Censys collector could not close safely."
    assert private_detail not in str(exc_info.value)
    assert client._closed is True
    client.close()


def test_context_manager_preserves_active_collection_error_over_close_failure() -> None:
    request_detail = "SECRET-PRIMARY-TRANSPORT"
    close_detail = "SECRET-TRANSPORT-CLOSE"
    transport = CloseFailingTransport(
        request_error=RuntimeError(request_detail),
    )
    clock = FakeClock()
    client = CensysPublicationsClient(
        http_transport=transport,
        monotonic_clock=clock,
        sleeper=clock.sleep,
    )

    with pytest.raises(CensysDiscoveryCollectionError) as exc_info:
        with client:
            client.fetch_publications(ARC)

    assert str(exc_info.value) == "Censys discovery collection failed."
    assert request_detail not in str(exc_info.value)
    assert close_detail not in str(exc_info.value)


def test_context_manager_close_failure_without_active_error_is_sanitized() -> None:
    private_detail = "SECRET-TRANSPORT-CLOSE"
    client = CensysPublicationsClient(http_transport=CloseFailingTransport())

    with pytest.raises(CensysTransportError) as exc_info:
        with client:
            pass

    assert str(exc_info.value) == "The Censys collector could not close safely."
    assert private_detail not in str(exc_info.value)
