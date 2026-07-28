from dataclasses import FrozenInstanceError, replace
import inspect
import json
import logging
from io import StringIO
import threading

import httpx
import pytest

from app.ingestion.stix_taxii.import_service import StixBundleImportService
from app.ingestion.stix_taxii.bounded_json import (
    StixDocumentFormat,
    parse_stix_json_bytes,
)
from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    ApprovedTaxiiCollectionPolicy,
    StixInputTransport,
    UnknownStixSourceError,
    build_taxii_policy_registry,
    validate_taxii_collection_policy,
)
from app.ingestion.stix_taxii.taxii_client import (
    ACCEPT_HEADER,
    ACCEPT_ENCODING_HEADER,
    USER_AGENT,
    TaxiiCollectionClient,
    TaxiiConfigurationError,
    TaxiiContentEncodingError,
    TaxiiContentTypeError,
    TaxiiEnvelopeError,
    TaxiiHttpStatusError,
    TaxiiPaginationError,
    TaxiiRateLimitError,
    TaxiiRedirectError,
    TaxiiRequestPolicyError,
    TaxiiResponseTooLargeError,
    TaxiiStixValidationError,
    TaxiiTimeoutError,
    TaxiiTransportError,
    collect_production_taxii_collection,
)


OBJECT_1 = {
    "type": "ipv4-addr",
    "spec_version": "2.1",
    "id": "ipv4-addr--89a9b3aa-12ac-4e13-a93b-6dd09d95fa00",
    "value": "8.8.8.8",
}
OBJECT_2 = {
    "type": "domain-name",
    "spec_version": "2.1",
    "id": "domain-name--11111111-1111-4111-8111-111111111111",
    "value": "example.org",
}
IDENTITY_1 = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--11111111-1111-4111-8111-111111111111",
    "created": "2026-01-01T00:00:00Z",
    "modified": "2026-01-01T00:00:00Z",
    "name": "Synthetic One",
    "identity_class": "organization",
}
IDENTITY_2 = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--22222222-2222-4222-8222-222222222222",
    "created": "2026-01-01T00:00:00Z",
    "modified": "2026-01-01T00:00:00Z",
    "name": "Synthetic Two",
    "identity_class": "organization",
}
RELATIONSHIP = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--33333333-3333-4333-8333-333333333333",
    "created": "2026-01-01T00:00:00Z",
    "modified": "2026-01-01T00:00:00Z",
    "relationship_type": "related-to",
    "source_ref": IDENTITY_1["id"],
    "target_ref": IDENTITY_2["id"],
}
HTTP_LOGGER_NAMES = (
    "httpx",
    "httpcore",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
)


@pytest.fixture
def enabled_http_loggers():
    loggers = tuple(logging.getLogger(name) for name in HTTP_LOGGER_NAMES)
    original = tuple(
        (
            logger.level,
            tuple(logger.handlers),
            logger.propagate,
            logger.disabled,
            tuple(logger.filters),
        )
        for logger in loggers
    )
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    for logger in loggers:
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        logger.propagate = False
        logger.disabled = False
    configured = tuple(
        (
            logger.level,
            tuple(logger.handlers),
            logger.propagate,
            logger.disabled,
            tuple(logger.filters),
        )
        for logger in loggers
    )
    try:
        yield loggers, stream, configured
    finally:
        for logger, state in zip(loggers, original, strict=True):
            level, handlers, propagate, disabled, filters = state
            logger.setLevel(level)
            logger.handlers[:] = handlers
            logger.propagate = propagate
            logger.disabled = disabled
            logger.filters[:] = filters


def policy(**changes):
    stix_policy = ApprovedStixSourcePolicy(
        source_slug="synthetic-taxii",
        allowed_transport=StixInputTransport.TAXII_21_COLLECTION,
        policy_base_url="https://stix.example/objects",
    )
    base = ApprovedTaxiiCollectionPolicy(
        stix_policy=stix_policy,
        api_root_url="https://taxii.example/api/root-1",
        collection_id="11111111-1111-4111-8111-111111111111",
    )
    return validate_taxii_collection_policy(replace(base, **changes))


def envelope(objects=(), *, more=None, next_token=None):
    payload = {"objects": list(objects)}
    if more is not None:
        payload["more"] = more
    if next_token is not None:
        payload["next"] = next_token
    return json.dumps(payload, separators=(",", ":")).encode()


def response(
    request,
    body=None,
    *,
    status=200,
    content_type=ACCEPT_HEADER,
    headers=None,
    stream=None,
):
    if headers is None:
        response_headers = []
    elif isinstance(headers, dict):
        response_headers = list(headers.items())
    else:
        response_headers = list(headers)
    if content_type is not None:
        response_headers.append(("Content-Type", content_type))
    kwargs = {"status_code": status, "headers": response_headers, "request": request}
    if stream is not None:
        kwargs["stream"] = stream
    else:
        kwargs["stream"] = httpx.ByteStream(body if body is not None else b"")
    return httpx.Response(**kwargs)


def client(handler, approved=None, **kwargs):
    approved = approved or policy()
    registry = build_taxii_policy_registry((approved,))
    return TaxiiCollectionClient(
        policy_registry=registry,
        http_transport=httpx.MockTransport(handler),
        **kwargs,
    )


def test_valid_one_page_collection_uses_exact_endpoint_headers_and_safe_result():
    approved = policy()
    seen = []

    def handler(request):
        seen.append(request)
        return response(request, envelope((OBJECT_1,)))

    result = client(handler, approved).collect("synthetic-taxii")

    assert len(seen) == 1
    request = seen[0]
    assert request.method == "GET"
    assert str(request.url) == approved.objects_endpoint
    assert request.headers["accept"] == ACCEPT_HEADER
    assert request.headers["user-agent"] == USER_AGENT
    assert request.headers["accept-encoding"] == ACCEPT_ENCODING_HEADER
    assert "cookie" not in request.headers
    assert result.pages_collected == 1
    assert result.objects_received == result.objects_validated == 1
    assert result.pagination_complete is True
    assert result.validated_document.objects[0].stix_id == OBJECT_1["id"]
    with pytest.raises(FrozenInstanceError):
        result.pages_collected = 2  # type: ignore[misc]


def test_valid_multi_page_collection_uses_same_endpoint_and_opaque_next_query():
    approved = policy()
    opaque = "https://elsewhere.example/path?x=1&y=2"
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return response(
                request,
                envelope((OBJECT_1,), more=True, next_token=opaque),
                headers={"Set-Cookie": "upstream-secret=value"},
            )
        assert request.url.scheme == "https"
        assert request.url.host == "taxii.example"
        assert request.url.path == httpx.URL(approved.objects_endpoint).path
        assert dict(request.url.params) == {"next": opaque}
        assert "cookie" not in request.headers
        return response(request, envelope((OBJECT_2,), more=False))

    result = client(handler, approved).collect("synthetic-taxii")

    assert result.pages_collected == 2
    assert result.objects_received == 2
    assert all(request.method == "GET" for request in requests)


def test_collection_thread_http_logs_are_suppressed_without_affecting_other_threads(
    enabled_http_loggers,
):
    loggers, stream, _ = enabled_http_loggers
    approved = policy()
    token = "opaque-pagination-token-secret"
    credentials = ("basic-user-secret", "basic-password-secret")
    calls = 0

    def unrelated_log():
        logging.getLogger("httpcore.http11").info("unrelated-thread-marker")

    def handler(request):
        nonlocal calls
        calls += 1
        for logger in loggers:
            logger.debug(
                "current-thread-secret %s %s %s %s %s %s",
                str(request.url),
                request.headers.get("Authorization"),
                "Set-Cookie: upstream-cookie-secret=value",
                "X-Upstream-Secret: response-header-secret",
                "response-body-secret",
                token,
            )
        worker = threading.Thread(target=unrelated_log)
        worker.start()
        worker.join()
        if calls == 1:
            return response(
                request,
                envelope((OBJECT_1,), more=True, next_token=token),
                headers={
                    "Set-Cookie": "upstream-cookie-secret=value",
                    "X-Upstream-Secret": "response-header-secret",
                },
            )
        return response(request, envelope((OBJECT_2,), more=False))

    configured = tuple(
        (
            logger.level,
            tuple(logger.handlers),
            logger.propagate,
            logger.disabled,
            tuple(logger.filters),
        )
        for logger in loggers
    )
    result = client(
        handler,
        approved,
        auth=httpx.BasicAuth(*credentials),
    ).collect("synthetic-taxii")

    output = stream.getvalue()
    assert result.pages_collected == 2
    assert "unrelated-thread-marker" in output
    for secret in (
        token,
        approved.objects_endpoint,
        "?next=",
        "basic-user-secret",
        "basic-password-secret",
        "Authorization",
        "upstream-cookie-secret",
        "response-header-secret",
        "response-body-secret",
        "current-thread-secret",
    ):
        assert secret not in output
    assert tuple(
        (
            logger.level,
            tuple(logger.handlers),
            logger.propagate,
            logger.disabled,
            tuple(logger.filters),
        )
        for logger in loggers
    ) == configured


def test_http_log_filters_are_removed_after_all_collection_failure_families():
    loggers = tuple(logging.getLogger(name) for name in HTTP_LOGGER_NAMES)
    baseline = tuple(tuple(logger.filters) for logger in loggers)

    def failure_handler(case):
        def handler(request):
            if case == "transport":
                raise httpx.ConnectError("transport-secret", request=request)
            if case == "timeout":
                raise httpx.ReadTimeout("timeout-secret", request=request)
            if case == "pagination":
                return response(
                    request,
                    envelope((OBJECT_1,), more=True),
                )
            if case == "content_type":
                return response(request, b"body-secret", content_type="text/plain")
            if case == "encoding":
                return response(
                    request,
                    b"body-secret",
                    headers={"Content-Encoding": "gzip"},
                )
            invalid_stix = {**OBJECT_1, "spec_version": "2.0"}
            return response(request, envelope((invalid_stix,)))

        return handler

    cases = (
        ("transport", TaxiiTransportError),
        ("timeout", TaxiiTimeoutError),
        ("pagination", TaxiiPaginationError),
        ("content_type", TaxiiContentTypeError),
        ("encoding", TaxiiContentEncodingError),
        ("stix", TaxiiStixValidationError),
    )
    for case, error_type in cases:
        with pytest.raises(error_type):
            client(failure_handler(case)).collect("synthetic-taxii")
        assert tuple(tuple(logger.filters) for logger in loggers) == baseline


def test_repeated_collections_do_not_accumulate_http_log_filters():
    loggers = tuple(logging.getLogger(name) for name in HTTP_LOGGER_NAMES)
    baseline = tuple(tuple(logger.filters) for logger in loggers)
    observed_counts = []

    def handler(request):
        observed_counts.append(
            tuple(
                sum(
                    type(item).__name__ == "_CollectionThreadLogFilter"
                    for item in logger.filters
                )
                for logger in loggers
            )
        )
        return response(request, envelope((OBJECT_1,)))

    collector = client(handler)
    collector.collect("synthetic-taxii")
    collector.collect("synthetic-taxii")

    assert observed_counts == [(1,) * len(loggers), (1,) * len(loggers)]
    assert tuple(tuple(logger.filters) for logger in loggers) == baseline


def test_http_log_filter_setup_and_cleanup_fail_closed_without_leaking_filters(
    monkeypatch,
):
    loggers = tuple(logging.getLogger(name) for name in HTTP_LOGGER_NAMES)
    baseline = tuple(tuple(logger.filters) for logger in loggers)
    setup_target = loggers[2]

    def setup_failure(filter_instance):
        del filter_instance
        raise RuntimeError("logger-setup-secret")

    with monkeypatch.context() as setup_patch:
        setup_patch.setattr(setup_target, "addFilter", setup_failure)
        with pytest.raises(TaxiiConfigurationError) as caught:
            client(lambda request: response(request, envelope((OBJECT_1,)))).collect(
                "synthetic-taxii"
            )
        assert "logger-setup-secret" not in str(caught.value)
    assert tuple(tuple(logger.filters) for logger in loggers) == baseline

    cleanup_target = loggers[-1]
    original_remove = cleanup_target.removeFilter

    def cleanup_failure(filter_instance):
        original_remove(filter_instance)
        raise RuntimeError("logger-cleanup-secret")

    with monkeypatch.context() as cleanup_patch:
        cleanup_patch.setattr(cleanup_target, "removeFilter", cleanup_failure)
        with pytest.raises(TaxiiTransportError) as caught:
            client(lambda request: response(request, envelope((OBJECT_1,)))).collect(
                "synthetic-taxii"
            )
        assert "logger-cleanup-secret" not in str(caught.value)
    assert tuple(tuple(logger.filters) for logger in loggers) == baseline


def test_cross_page_relationships_are_validated_as_one_document():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return response(
                request,
                envelope((IDENTITY_1,), more=True, next_token="page-2"),
            )
        return response(
            request,
            envelope((IDENTITY_2, RELATIONSHIP), more=False),
        )

    result = client(handler).collect("synthetic-taxii")

    assert result.objects_validated == 3
    assert result.validated_document.relationships_validated == 1


def aggregate_policy(maximum_json_nodes):
    approved = policy()
    stix_policy = replace(
        approved.stix_policy,
        maximum_json_nodes=maximum_json_nodes,
        maximum_objects=2,
    )
    return validate_taxii_collection_policy(
        replace(
            approved,
            stix_policy=stix_policy,
            maximum_total_objects=2,
        )
    )


def test_combined_pages_reenforce_aggregate_json_node_limit_before_semantics(
    monkeypatch,
):
    from app.ingestion.stix_taxii import taxii_client

    approved = aggregate_policy(10)
    first = envelope((OBJECT_1,), more=True, next_token="page-2")
    second = envelope((OBJECT_2,), more=False)
    assert parse_stix_json_bytes(
        first,
        approved.stix_policy,
        StixDocumentFormat.TAXII_ENVELOPE,
    )
    assert parse_stix_json_bytes(
        second,
        approved.stix_policy,
        StixDocumentFormat.TAXII_ENVELOPE,
    )
    semantic_calls = 0

    def semantic_validator(*args, **kwargs):
        nonlocal semantic_calls
        semantic_calls += 1
        raise AssertionError("semantic validator must not run")

    monkeypatch.setattr(taxii_client, "validate_stix_document", semantic_validator)
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return response(request, first if calls == 1 else second)

    with pytest.raises(TaxiiEnvelopeError) as caught:
        client(handler, approved).collect("synthetic-taxii")

    assert semantic_calls == 0
    assert OBJECT_1["id"] not in str(caught.value)
    assert OBJECT_1["value"] not in str(caught.value)
    assert OBJECT_2["id"] not in str(caught.value)
    assert OBJECT_2["value"] not in str(caught.value)


def test_exact_combined_json_node_boundary_succeeds():
    approved = aggregate_policy(12)
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return response(
                request,
                envelope((OBJECT_1,), more=True, next_token="page-2"),
            )
        return response(request, envelope((OBJECT_2,), more=False))

    result = client(handler, approved).collect("synthetic-taxii")

    assert result.pages_collected == 2
    assert result.objects_validated == 2


def test_controlled_client_disables_redirects_and_environment_trust(monkeypatch):
    from app.ingestion.stix_taxii import taxii_client

    captured = {}
    real_client = httpx.Client

    def client_factory(*args, **kwargs):
        captured.update(kwargs)
        captured["log_filters_installed"] = all(
            any(
                type(item).__name__ == "_CollectionThreadLogFilter"
                for item in logging.getLogger(name).filters
            )
            for name in HTTP_LOGGER_NAMES
        )
        return real_client(*args, **kwargs)

    monkeypatch.setattr(taxii_client.httpx, "Client", client_factory)
    client(lambda request: response(request, envelope((OBJECT_1,)))).collect(
        "synthetic-taxii"
    )

    assert captured["follow_redirects"] is False
    assert captured["trust_env"] is False
    assert captured["headers"] == {
        "User-Agent": USER_AGENT,
        "Accept": ACCEPT_HEADER,
        "Accept-Encoding": ACCEPT_ENCODING_HEADER,
    }
    assert len(captured["event_hooks"]["request"]) == 1
    assert captured["log_filters_installed"] is True


def test_exact_basic_auth_is_allowed_without_disclosing_credentials():
    requests = []
    auth = httpx.BasicAuth("synthetic-user", "synthetic-password")

    result = client(
        lambda request: (
            requests.append(request)
            or response(request, envelope((OBJECT_1,)))
        ),
        auth=auth,
    ).collect("synthetic-taxii")

    assert result.objects_validated == 1
    assert len(requests) == 1
    assert requests[0].headers["authorization"].startswith("Basic ")
    assert "synthetic-user" not in repr(result)
    assert "synthetic-password" not in repr(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "url",
        "query",
        "method",
        "host",
        "accept",
        "user_agent",
        "accept_encoding",
        "cookie",
        "secret_header",
        "timeout_modified",
        "timeout_removed",
        "extra_extension",
    ],
)
def test_hostile_auth_mutations_fail_before_transport_with_sanitized_error(
    mutation,
    monkeypatch,
):
    transport_calls = 0
    original_flow = httpx.BasicAuth.auth_flow

    def hostile_flow(self, request):
        for authenticated in original_flow(self, request):
            if mutation == "url":
                authenticated.url = httpx.URL(
                    "https://hostile.example/secret?credential=value"
                )
            elif mutation == "query":
                authenticated.url = authenticated.url.copy_with(
                    query=b"next=credential-value"
                )
            elif mutation == "method":
                authenticated.method = "POST"
            elif mutation == "host":
                authenticated.headers["Host"] = "hostile.example"
            elif mutation == "accept":
                authenticated.headers["Accept"] = "application/json"
            elif mutation == "user_agent":
                authenticated.headers["User-Agent"] = "credential-agent"
            elif mutation == "accept_encoding":
                authenticated.headers["Accept-Encoding"] = "gzip"
            elif mutation == "cookie":
                authenticated.headers["Cookie"] = "cookie-secret"
            elif mutation == "secret_header":
                authenticated.headers["X-Secret"] = "header-secret"
            elif mutation == "timeout_modified":
                authenticated.extensions["timeout"]["read"] = 999_999.0
            elif mutation == "timeout_removed":
                authenticated.extensions.pop("timeout", None)
            else:
                authenticated.extensions["credential-extension"] = "secret"
            yield authenticated

    def handler(request):
        nonlocal transport_calls
        transport_calls += 1
        return response(request, envelope((OBJECT_1,)))

    monkeypatch.setattr(httpx.BasicAuth, "auth_flow", hostile_flow)
    auth = httpx.BasicAuth("credential-user", "credential-secret")

    with pytest.raises(TaxiiRequestPolicyError) as caught:
        client(handler, auth=auth).collect("synthetic-taxii")

    message = str(caught.value)
    assert transport_calls == 0
    for secret in (
        "hostile.example",
        "credential-user",
        "credential-secret",
        "credential-value",
        "credential-agent",
        "credential-extension",
        "cookie-secret",
        "header-secret",
    ):
        assert secret not in message


def test_custom_auth_subclasses_are_rejected_before_transport():
    transport_calls = 0

    class CustomAuth(httpx.Auth):
        def auth_flow(self, request):
            request.url = httpx.URL("https://hostile.example/secret")
            yield request

    def handler(request):
        nonlocal transport_calls
        transport_calls += 1
        return response(request, envelope((OBJECT_1,)))

    with pytest.raises(TaxiiConfigurationError) as caught:
        client(handler, auth=CustomAuth()).collect("synthetic-taxii")

    assert transport_calls == 0
    assert "hostile.example" not in str(caught.value)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_are_always_rejected_without_following(status):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return response(
            request,
            status=status,
            headers={"Location": "https://elsewhere.example/secret?token=value"},
        )

    with pytest.raises(TaxiiRedirectError) as caught:
        client(handler).collect("synthetic-taxii")
    assert calls == 1
    assert "elsewhere" not in str(caught.value)
    assert "token" not in str(caught.value)


def test_rate_limit_and_unsuccessful_status_are_typed_and_sanitized():
    with pytest.raises(TaxiiRateLimitError):
        client(lambda request: response(request, b"secret", status=429)).collect(
            "synthetic-taxii"
        )
    with pytest.raises(TaxiiHttpStatusError) as caught:
        client(
            lambda request: response(
                request,
                b"secret body",
                status=500,
                headers={"X-Secret": "header-secret"},
            )
        ).collect("synthetic-taxii")
    assert "secret" not in str(caught.value)


def test_transport_and_operation_timeout_failures_do_not_disclose_raw_errors():
    def transport_failure(request):
        raise httpx.ConnectError(
            "secret https://user:password@taxii.example/?token=value",
            request=request,
        )

    with pytest.raises(TaxiiTransportError) as caught:
        client(transport_failure).collect("synthetic-taxii")
    assert "secret" not in str(caught.value)
    assert "password" not in str(caught.value)

    def timeout(request):
        raise httpx.ReadTimeout("secret-timeout", request=request)

    with pytest.raises(TaxiiTimeoutError) as caught:
        client(timeout).collect("synthetic-taxii")
    assert "secret-timeout" not in str(caught.value)


class IncrementingClock:
    def __init__(self, step):
        self.value = 0.0
        self.step = step

    def __call__(self):
        value = self.value
        self.value += self.step
        return value


class Chunks(httpx.SyncByteStream):
    def __init__(self, *chunks):
        self.chunks = chunks

    def __iter__(self):
        yield from self.chunks


def test_total_deadline_is_enforced_across_request_and_stream_reads():
    approved = policy(total_collection_deadline_seconds=0.5)

    def handler(request):
        body = envelope((OBJECT_1,))
        return response(
            request,
            headers={"Content-Type": ACCEPT_HEADER},
            content_type=None,
            stream=Chunks(body[:10], body[10:]),
        )

    with pytest.raises(TaxiiTimeoutError, match="deadline"):
        client(
            handler,
            approved,
            monotonic_clock=IncrementingClock(0.15),
        ).collect("synthetic-taxii")


@pytest.mark.parametrize(
    "content_type",
    [
        "application/taxii+json;version=2.1",
        " Application/TAXII+JSON ; VERSION = 2.1 ",
        'application/taxii+json; version="2.1"',
    ],
)
def test_valid_taxii_21_media_type_equivalents_are_accepted(content_type):
    result = client(
        lambda request: response(
            request, envelope((OBJECT_1,)), content_type=content_type
        )
    ).collect("synthetic-taxii")
    assert result.objects_validated == 1


@pytest.mark.parametrize("content_encoding", [None, "identity", " Identity "])
def test_absent_or_identity_content_encoding_is_accepted(content_encoding):
    headers = (
        {}
        if content_encoding is None
        else {"Content-Encoding": content_encoding}
    )

    result = client(
        lambda request: response(
            request,
            envelope((OBJECT_1,)),
            headers=headers,
        )
    ).collect("synthetic-taxii")

    assert result.objects_validated == 1


@pytest.mark.parametrize(
    "content_encoding",
    [
        "gzip",
        "deflate",
        "br",
        "gzip, identity",
        "identity;level=0",
        "identity identity",
        "identity\n",
        "",
    ],
)
def test_compressed_multiple_or_malformed_content_encodings_fail_closed(
    content_encoding,
):
    with pytest.raises(TaxiiContentEncodingError) as caught:
        client(
            lambda request: response(
                request,
                b"secret encoded response body",
                headers={
                    "Content-Encoding": content_encoding,
                    "X-Secret": "response-header-secret",
                },
            )
        ).collect("synthetic-taxii")

    message = str(caught.value)
    assert "encoded response body" not in message
    assert "response-header-secret" not in message
    if content_encoding:
        assert content_encoding not in message


def test_duplicate_content_encoding_values_fail_closed():
    with pytest.raises(TaxiiContentEncodingError):
        client(
            lambda request: response(
                request,
                envelope((OBJECT_1,)),
                headers=[
                    ("Content-Encoding", "identity"),
                    ("Content-Encoding", "gzip"),
                ],
            )
        ).collect("synthetic-taxii")


def test_invalid_content_encoding_is_rejected_before_stream_iteration():
    class UnreadStream(httpx.SyncByteStream):
        def __init__(self):
            self.iterations = 0

        def __iter__(self):
            self.iterations += 1
            yield b"secret compressed body"

    stream = UnreadStream()

    with pytest.raises(TaxiiContentEncodingError):
        client(
            lambda request: response(
                request,
                headers={"Content-Encoding": "gzip"},
                stream=stream,
            )
        ).collect("synthetic-taxii")

    assert stream.iterations == 0


@pytest.mark.parametrize(
    "content_type",
    [
        None,
        "application/json",
        "application/taxii+json",
        "application/taxii+json;version=2.0",
        "application/taxii+json;version=2.1;version=2.1",
        "application/taxii+json;version=2.1;profile=x",
        "application/taxii+json;version",
        "application/taxii+json;version=2.1=extra",
        'application/taxii+json;version="2.1',
        "application/taxii+json;version=2.1\n",
    ],
)
def test_missing_incorrect_conflicting_or_malformed_media_types_are_rejected(content_type):
    with pytest.raises(TaxiiContentTypeError):
        client(
            lambda request: response(
                request, envelope((OBJECT_1,)), content_type=content_type
            )
        ).collect("synthetic-taxii")


def test_content_length_streamed_body_and_total_byte_limits_are_enforced():
    small = policy(maximum_response_bytes=128, maximum_total_response_bytes=256)
    with pytest.raises(TaxiiResponseTooLargeError):
        client(
            lambda request: response(
                request,
                b"{}",
                headers={"Content-Length": "129"},
            ),
            small,
        ).collect("synthetic-taxii")

    with pytest.raises(TaxiiResponseTooLargeError):
        client(
            lambda request: response(
                request,
                content_type=ACCEPT_HEADER,
                stream=Chunks(b"x" * 80, b"y" * 80),
            ),
            small,
        ).collect("synthetic-taxii")

    first = envelope((OBJECT_1,), more=True, next_token="page-2")
    second = envelope((OBJECT_2,), more=False)
    response_limit = max(len(first), len(second))
    total = response_limit
    bounded = policy(
        maximum_response_bytes=response_limit,
        maximum_total_response_bytes=total,
    )
    calls = 0

    def total_handler(request):
        nonlocal calls
        calls += 1
        body = first if calls == 1 else second
        return response(request, body)

    with pytest.raises(TaxiiResponseTooLargeError):
        client(total_handler, bounded).collect("synthetic-taxii")


@pytest.mark.parametrize(
    "first_page",
    [
        {"objects": [OBJECT_1], "more": True},
        {"objects": [OBJECT_1], "more": False, "next": "page-2"},
        {"objects": [OBJECT_1], "next": "page-2"},
        {"objects": [OBJECT_1], "more": "true"},
    ],
)
def test_more_next_invariant_failures_are_pagination_errors(first_page):
    with pytest.raises(TaxiiPaginationError):
        client(
            lambda request: response(request, json.dumps(first_page).encode())
        ).collect("synthetic-taxii")


def test_repeated_token_repeated_page_and_empty_continuation_fail_closed():
    pages = [
        envelope((OBJECT_1,), more=True, next_token="same"),
        envelope((OBJECT_2,), more=True, next_token="same"),
    ]
    calls = 0

    def repeated_token(request):
        nonlocal calls
        body = pages[calls]
        calls += 1
        return response(request, body)

    with pytest.raises(TaxiiPaginationError, match="token"):
        client(repeated_token).collect("synthetic-taxii")

    calls = 0

    def repeated_page(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return response(
                request,
                envelope((OBJECT_1,), more=True, next_token="page-2"),
            )
        return response(request, envelope((OBJECT_1,), more=False))

    with pytest.raises(TaxiiPaginationError, match="page"):
        client(repeated_page).collect("synthetic-taxii")

    calls = 0

    def reordered_no_progress(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return response(
                request,
                envelope(
                    (OBJECT_1, OBJECT_2),
                    more=True,
                    next_token="page-2",
                ),
            )
        return response(request, envelope((OBJECT_2, OBJECT_1), more=False))

    with pytest.raises(TaxiiPaginationError, match="progress"):
        client(reordered_no_progress).collect("synthetic-taxii")

    calls = 0

    def empty_continuation(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return response(
                request,
                envelope((OBJECT_1,), more=True, next_token="page-2"),
            )
        return response(request, envelope((), more=False))

    with pytest.raises(TaxiiPaginationError, match="progress"):
        client(empty_continuation).collect("synthetic-taxii")


def test_page_object_and_token_bounds_are_enforced():
    page_limited = policy(maximum_pages=1)
    with pytest.raises(TaxiiPaginationError, match="page limit"):
        client(
            lambda request: response(
                request,
                envelope((OBJECT_1,), more=True, next_token="page-2"),
            ),
            page_limited,
        ).collect("synthetic-taxii")

    object_limited = policy(maximum_total_objects=1)
    with pytest.raises(TaxiiPaginationError, match="object limit"):
        client(
            lambda request: response(request, envelope((OBJECT_1, OBJECT_2))),
            object_limited,
        ).collect("synthetic-taxii")

    token_limited = policy(maximum_pagination_token_length=4)
    with pytest.raises(TaxiiPaginationError, match="metadata"):
        client(
            lambda request: response(
                request,
                envelope((OBJECT_1,), more=True, next_token="12345"),
            ),
            token_limited,
        ).collect("synthetic-taxii")
    with pytest.raises(TaxiiPaginationError, match="metadata"):
        client(
            lambda request: response(
                request,
                envelope((OBJECT_1,), more=True, next_token="bad\n"),
            )
        ).collect("synthetic-taxii")


def test_envelope_and_complete_stix_validation_errors_are_typed():
    with pytest.raises(TaxiiEnvelopeError):
        client(lambda request: response(request, b'{"objects":[')).collect(
            "synthetic-taxii"
        )
    invalid_stix = {**OBJECT_1, "spec_version": "2.0"}
    with pytest.raises(TaxiiStixValidationError):
        client(
            lambda request: response(request, envelope((invalid_stix,)))
        ).collect("synthetic-taxii")


def test_registry_auth_and_production_entrypoint_are_closed_and_sanitized():
    with pytest.raises(TaxiiConfigurationError):
        TaxiiCollectionClient(policy_registry={})  # type: ignore[arg-type]
    with pytest.raises(TaxiiConfigurationError):
        TaxiiCollectionClient(
            policy_registry=build_taxii_policy_registry((policy(),)),
            auth="Basic secret",  # type: ignore[arg-type]
        )
    with pytest.raises(UnknownStixSourceError) as caught:
        collect_production_taxii_collection("https://taxii.example/secret")
    assert "taxii.example" not in str(caught.value)


def test_client_output_reuses_existing_import_service_without_transaction_ownership():
    result = client(
        lambda request: response(request, envelope((OBJECT_1,)))
    ).collect("synthetic-taxii")

    parameters = inspect.signature(StixBundleImportService.import_document).parameters
    assert "document" in parameters
    assert result.validated_document.objects_validated == 1
    source = inspect.getsource(StixBundleImportService.import_document)
    assert ".commit(" not in source
    assert ".rollback(" not in source


def test_no_out_of_scope_taxii_packages_or_interfaces_were_added():
    import app.ingestion.stix_taxii.taxii_client as module

    source = inspect.getsource(module)
    assert "taxii2client" not in source.lower()
    assert "staxx" not in source.lower()
    names = set(inspect.signature(TaxiiCollectionClient.collect).parameters)
    assert names == {"self", "source_slug"}
