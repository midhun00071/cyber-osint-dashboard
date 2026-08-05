from dataclasses import replace
import logging
from types import MappingProxyType

import httpx
import pytest

from app.ingestion.collectors.official_rss_client import (
    ACCEPT_ENCODING_HEADER,
    ACCEPT_HEADER,
    C05_OFFICIAL_RSS_POLICIES,
    MAX_RESPONSE_BYTES,
    OfficialRssClient,
    OfficialRssConfigurationError,
    OfficialRssContentEncodingError,
    OfficialRssContentTypeError,
    OfficialRssRedirectError,
    OfficialRssResponseTooLargeError,
    OfficialRssSourcePolicy,
    USER_AGENT,
)


SOURCE_CASES = tuple(
    (slug, policy.feed_url, policy.feed_host, policy.feed_path)
    for slug, policy in C05_OFFICIAL_RSS_POLICIES.items()
)


def response(request, body=b"<rss><channel/></rss>", *, headers=None, status=200):
    values = {"Content-Type": "application/rss+xml; charset=UTF-8"}
    values.update(headers or {})
    return httpx.Response(
        status,
        headers=values,
        stream=httpx.ByteStream(body),
        request=request,
    )


@pytest.mark.parametrize("source_slug,feed_url,host,path", SOURCE_CASES)
def test_exact_feed_request_has_closed_headers_and_no_auth(
    source_slug, feed_url, host, path
):
    requests = []

    def handler(request):
        requests.append(request)
        return response(request)

    result = OfficialRssClient(
        http_transport=httpx.MockTransport(handler)
    ).fetch(source_slug)
    request = requests[0]
    assert str(request.url) == feed_url
    assert request.url.host == host
    assert request.url.path == path
    assert not request.url.query
    assert request.method == "GET"
    assert request.headers["accept"] == ACCEPT_HEADER
    assert request.headers["accept-encoding"] == ACCEPT_ENCODING_HEADER
    assert request.headers["user-agent"] == USER_AGENT
    assert "authorization" not in request.headers
    assert "cookie" not in request.headers
    assert result.request_count == 1
    assert result.response_bytes == len(result.body)


@pytest.mark.parametrize(
    "content_type",
    [
        "application/rss+xml",
        "application/xml; charset=utf-8",
        'text/xml; charset="UTF-8"',
    ],
)
def test_strict_media_type_allow_list_accepts_only_supported_xml(content_type):
    client = OfficialRssClient(
        http_transport=httpx.MockTransport(
            lambda request: response(
                request,
                headers={"Content-Type": content_type},
            )
        )
    )
    assert client.fetch("cert-fr-security-alerts").body.startswith(b"<rss")


@pytest.mark.parametrize(
    "content_type",
    [
        "application/octet-stream",
        "text/html",
        "application/json",
        "application/atom+xml",
        "application/rss+xml; charset=not-a-real-charset",
        "application/rss+xml; charset",
        "application/rss+xml; charset=utf-8; boundary=x",
    ],
)
def test_unsupported_or_malformed_media_types_fail_closed(content_type):
    client = OfficialRssClient(
        http_transport=httpx.MockTransport(
            lambda request: response(
                request,
                headers={"Content-Type": content_type},
            )
        )
    )
    with pytest.raises(OfficialRssContentTypeError):
        client.fetch("cert-fr-security-alerts")


def test_missing_or_conflicting_content_type_fails_closed():
    def missing(request):
        return httpx.Response(
            200,
            stream=httpx.ByteStream(b"<rss/>"),
            request=request,
        )

    with pytest.raises(OfficialRssContentTypeError):
        OfficialRssClient(
            http_transport=httpx.MockTransport(missing)
        ).fetch("cert-fr-security-alerts")

    def conflicting(request):
        return httpx.Response(
            200,
            headers=[
                ("Content-Type", "application/rss+xml"),
                ("Content-Type", "text/xml"),
            ],
            stream=httpx.ByteStream(b"<rss/>"),
            request=request,
        )

    with pytest.raises(OfficialRssContentTypeError):
        OfficialRssClient(
            http_transport=httpx.MockTransport(conflicting)
        ).fetch("cert-fr-security-alerts")


def test_redirect_compression_and_oversized_response_are_rejected():
    with pytest.raises(OfficialRssRedirectError):
        OfficialRssClient(
            http_transport=httpx.MockTransport(
                lambda request: response(
                    request,
                    status=302,
                    headers={"Location": "https://example.invalid/other"},
                )
            )
        ).fetch("cert-fr-security-alerts")

    with pytest.raises(OfficialRssContentEncodingError):
        OfficialRssClient(
            http_transport=httpx.MockTransport(
                lambda request: response(
                    request,
                    headers={"Content-Encoding": "gzip"},
                )
            )
        ).fetch("cert-fr-security-alerts")

    with pytest.raises(OfficialRssResponseTooLargeError):
        OfficialRssClient(
            http_transport=httpx.MockTransport(
                lambda request: response(request, b"x" * (MAX_RESPONSE_BYTES + 1))
            )
        ).fetch("cert-fr-security-alerts")


def test_client_constructor_disables_environment_trust_and_redirects(monkeypatch):
    captured = {}
    real_client = httpx.Client

    class CapturingClient(real_client):
        def __init__(self, *args, **kwargs):
            captured["trust_env"] = kwargs.get("trust_env")
            captured["follow_redirects"] = kwargs.get("follow_redirects")
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", CapturingClient)
    OfficialRssClient(
        http_transport=httpx.MockTransport(lambda request: response(request))
    ).fetch("cert-fr-security-alerts")
    assert captured == {"trust_env": False, "follow_redirects": False}


@pytest.mark.parametrize(
    "changes",
    (
        {
            "feed_url": "https://substituted.invalid/alerte/feed/",
            "feed_host": "substituted.invalid",
        },
        {
            "feed_url": "https://www.cert.ssi.gouv.fr/substituted/feed/",
            "feed_path": "/substituted/feed/",
        },
    ),
)
def test_altered_same_slug_policy_fails_before_transport_with_sanitized_error(
    changes,
    caplog,
):
    called = False

    def forbidden_transport(request):
        nonlocal called
        called = True
        raise AssertionError("transport must not run")

    policies = dict(C05_OFFICIAL_RSS_POLICIES)
    policies["cert-fr-security-alerts"] = replace(
        policies["cert-fr-security-alerts"],
        **changes,
    )
    with caplog.at_level(logging.DEBUG), pytest.raises(
        OfficialRssConfigurationError
    ) as caught:
        OfficialRssClient(
            policy_registry=MappingProxyType(policies),
            http_transport=httpx.MockTransport(forbidden_transport),
        )

    assert called is False
    assert str(caught.value) == "The official RSS policy registry is invalid."
    assert "substituted.invalid" not in str(caught.value)
    assert "substituted.invalid" not in caplog.text


def test_exact_copied_policy_mapping_is_accepted_with_mock_transport():
    copied = MappingProxyType(dict(C05_OFFICIAL_RSS_POLICIES))
    client = OfficialRssClient(
        policy_registry=copied,
        http_transport=httpx.MockTransport(lambda request: response(request)),
    )
    assert (
        client._policies["cert-fr-security-alerts"]
        is C05_OFFICIAL_RSS_POLICIES["cert-fr-security-alerts"]
    )
    assert client.fetch("cert-fr-security-alerts").request_count == 1


@pytest.mark.parametrize("change", ("missing", "additional"))
def test_missing_or_additional_policy_entry_fails_before_transport(change):
    called = False

    def forbidden_transport(request):
        nonlocal called
        called = True
        raise AssertionError("transport must not run")

    policies = dict(C05_OFFICIAL_RSS_POLICIES)
    if change == "missing":
        policies.pop("uk-ncsc-threat-reports")
    else:
        policies["additional-source"] = policies["cert-fr-security-alerts"]
    with pytest.raises(OfficialRssConfigurationError):
        OfficialRssClient(
            policy_registry=MappingProxyType(policies),
            http_transport=httpx.MockTransport(forbidden_transport),
        )
    assert called is False


class _AlwaysEqualRssPolicy(OfficialRssSourcePolicy):
    def __eq__(self, other):
        del other
        return True


class _StringSubclass(str):
    pass


def _adversarial_rss_registry(kind):
    policies = dict(C05_OFFICIAL_RSS_POLICIES)
    canonical = policies["cert-fr-security-alerts"]
    if kind == "policy_subclass":
        policies["cert-fr-security-alerts"] = _AlwaysEqualRssPolicy(
            source_slug=canonical.source_slug,
            feed_url="https://evil.example/feed",
            feed_host="evil.example",
            feed_path="/feed",
            canonical_hosts=canonical.canonical_hosts,
            canonical_kind=canonical.canonical_kind,
            source_language=canonical.source_language,
        )
    elif kind == "field_subclass":
        policies["cert-fr-security-alerts"] = OfficialRssSourcePolicy(
            source_slug=canonical.source_slug,
            feed_url=_StringSubclass("https://evil.example/feed"),
            feed_host=canonical.feed_host,
            feed_path=canonical.feed_path,
            canonical_hosts=canonical.canonical_hosts,
            canonical_kind=canonical.canonical_kind,
            source_language=canonical.source_language,
        )
    else:
        del policies["cert-fr-security-alerts"]
        policies[_StringSubclass("cert-fr-security-alerts")] = canonical
    return MappingProxyType(policies)


@pytest.mark.parametrize(
    "kind",
    ("policy_subclass", "field_subclass", "key_subclass"),
)
def test_adversarial_equality_or_string_subclasses_fail_before_transport(
    kind,
    caplog,
):
    called = False

    def forbidden_transport(request):
        nonlocal called
        called = True
        raise AssertionError("transport must not run")

    with caplog.at_level(logging.DEBUG), pytest.raises(
        OfficialRssConfigurationError
    ) as caught:
        OfficialRssClient(
            policy_registry=_adversarial_rss_registry(kind),
            http_transport=httpx.MockTransport(forbidden_transport),
        )
    assert called is False
    assert str(caught.value) == "The official RSS policy registry is invalid."
    assert "evil.example" not in str(caught.value)
    assert "evil.example" not in caplog.text
