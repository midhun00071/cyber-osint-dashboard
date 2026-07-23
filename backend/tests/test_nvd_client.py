from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone, tzinfo
import json
import secrets

import httpx
import pytest
from pydantic import SecretStr

from app.ingestion.collectors import nvd_client as nvd_client_module
from app.ingestion.collectors.nvd_client import (
    AUTHENTICATED_DELAY_SECONDS,
    NvdClient,
    NvdHttpError,
    NvdPage,
    NvdRateLimitError,
    NvdRequestError,
    NvdResponseError,
    UNAUTHENTICATED_DELAY_SECONDS,
)


START = datetime(2026, 1, 1, tzinfo=UTC)
END = datetime(2026, 1, 2, tzinfo=UTC)


class NoOffsetTimezone(tzinfo):
    def utcoffset(self, value: datetime | None) -> None:
        return None

    def dst(self, value: datetime | None) -> None:
        return None

    def tzname(self, value: datetime | None) -> str:
        return "no-offset"


class TrackingStream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.chunks_consumed = 0

    def __iter__(self):
        for chunk in self.chunks:
            self.chunks_consumed += 1
            yield chunk


def make_payload(
    *,
    vulnerabilities: list[dict] | None = None,
    start_index: int = 0,
    results_per_page: int = 2000,
    total_results: int | None = None,
) -> dict:
    records = (
        vulnerabilities
        if vulnerabilities is not None
        else [{"cve": {"id": "CVE-2026-0001"}}]
    )
    return {
        "vulnerabilities": records,
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
        "totalResults": len(records) if total_results is None else total_results,
    }


def make_client(handler, **kwargs) -> tuple[NvdClient, httpx.Client]:
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    return NvdClient(http_client=http_client, **kwargs), http_client


def assert_secret_absent(value: object, secret: str) -> None:
    if secret in str(value):
        pytest.fail("A synthetic API key appeared in sanitized output.")


def test_fetch_page_success_returns_nvd_page() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(200, json=make_payload(), request=request)
    )
    try:
        page = client.fetch_page(START, END)
    finally:
        http_client.close()

    assert page == NvdPage(
        vulnerabilities=[{"cve": {"id": "CVE-2026-0001"}}],
        start_index=0,
        results_per_page=2000,
        total_results=1,
    )


def test_request_omits_api_key_header_when_missing() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json=make_payload(), request=request)

    client, http_client = make_client(handler)
    try:
        client.fetch_page(START, END)
    finally:
        http_client.close()

    assert "apiKey" not in captured[0].headers


def test_request_sends_configured_api_key_only_as_header() -> None:
    secret = "synthetic-nvd-key-do-not-use"
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json=make_payload(), request=request)

    client, http_client = make_client(handler, api_key=SecretStr(secret))
    try:
        client.fetch_page(START, END)
    finally:
        http_client.close()

    request = captured[0]
    if not secrets.compare_digest(request.headers["apiKey"], secret):
        pytest.fail("The configured API key header was not preserved.")
    assert_secret_absent(request.url, secret)


def test_api_key_is_absent_from_repr_and_exception_text() -> None:
    secret = "synthetic-nvd-key-do-not-use"
    client, http_client = make_client(
        lambda request: httpx.Response(500, text=secret, request=request),
        api_key=SecretStr(secret),
    )
    try:
        with pytest.raises(NvdHttpError) as exc_info:
            client.fetch_page(START, END)
    finally:
        http_client.close()

    assert_secret_absent(repr(client), secret)
    assert_secret_absent(exc_info.value, secret)


def test_query_params_are_complete_and_datetimes_are_utc() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json=make_payload(start_index=25, results_per_page=50),
            request=request,
        )

    client, http_client = make_client(handler)
    offset = timezone(timedelta(hours=4))
    try:
        client.fetch_page(
            datetime(2026, 1, 1, 4, tzinfo=offset),
            datetime(2026, 1, 2, 4, tzinfo=offset),
            start_index=25,
            results_per_page=50,
        )
    finally:
        http_client.close()

    params = captured[0].url.params
    assert params["lastModStartDate"] == "2026-01-01T00:00:00.000Z"
    assert params["lastModEndDate"] == "2026-01-02T00:00:00.000Z"
    assert params["startIndex"] == "25"
    assert params["resultsPerPage"] == "50"


@pytest.mark.parametrize(
    ("filter_name", "argument_name"),
    [
        ("cvssV3Severity", "cvss_v3_severity"),
        ("cvssV4Severity", "cvss_v4_severity"),
    ],
)
def test_publication_page_uses_allow_listed_cvss_severity_filter(
    filter_name: str,
    argument_name: str,
) -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json=make_payload(), request=request)

    client, http_client = make_client(handler)
    try:
        page = client.fetch_publication_page(
            START,
            END,
            start_index=25,
            results_per_page=50,
            **{argument_name: "high"},
        )
    finally:
        http_client.close()

    assert page.total_results == 1
    params = captured[0].url.params
    assert params["pubStartDate"] == "2026-01-01T00:00:00.000Z"
    assert params["pubEndDate"] == "2026-01-02T00:00:00.000Z"
    assert params["startIndex"] == "25"
    assert params["resultsPerPage"] == "50"
    assert params[filter_name] == "HIGH"
    other_filter = (
        "cvssV4Severity" if filter_name == "cvssV3Severity" else "cvssV3Severity"
    )
    assert other_filter not in params


def test_publication_page_supports_presence_only_kev_filter() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json=make_payload(), request=request)

    client, http_client = make_client(handler)
    try:
        client.fetch_publication_page(START, END, has_kev=True)
    finally:
        http_client.close()

    assert "hasKev" in captured[0].url.params
    assert captured[0].url.params["hasKev"] == ""


@pytest.mark.parametrize("severity", ["", "unknown", "extreme", 7])
def test_publication_page_rejects_invalid_severity_filter(severity: object) -> None:
    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="severity filter is invalid"):
            client.fetch_publication_page(
                START,
                END,
                cvss_v3_severity=severity,  # type: ignore[arg-type]
            )


def test_publication_page_rejects_two_cvss_version_filters() -> None:
    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="Only one"):
            client.fetch_publication_page(
                START,
                END,
                cvss_v3_severity="HIGH",
                cvss_v4_severity="HIGH",
            )


def test_publication_page_rejects_non_boolean_kev_filter() -> None:
    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="KEV filter must be a boolean"):
            client.fetch_publication_page(
                START,
                END,
                has_kev="true",  # type: ignore[arg-type]
            )


def test_rejects_naive_datetimes() -> None:
    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="timezone-aware"):
            client.fetch_page(START.replace(tzinfo=None), END)


def test_rejects_timezone_without_utc_offset() -> None:
    invalid_start = datetime(2026, 1, 1, tzinfo=NoOffsetTimezone())

    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="timezone-aware"):
            client.fetch_page(invalid_start, END)


def test_rejects_start_date_after_end_date() -> None:
    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="must not be after"):
            client.fetch_page(END, START)


def test_rejects_date_window_greater_than_120_days() -> None:
    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="120 days"):
            client.fetch_page(START, START + timedelta(days=120, seconds=1))


@pytest.mark.parametrize("results_per_page", [0, 2001])
def test_rejects_invalid_results_per_page(results_per_page: int) -> None:
    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="between 1 and 2000"):
            client.fetch_page(START, END, results_per_page=results_per_page)


def test_rejects_negative_start_index() -> None:
    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="zero or greater"):
            client.fetch_page(START, END, start_index=-1)


@pytest.mark.parametrize("start_index", [True, False, "0", 1.5])
def test_rejects_bool_and_non_integer_start_index(start_index: object) -> None:
    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="must be an integer"):
            client.fetch_page(START, END, start_index=start_index)  # type: ignore[arg-type]


@pytest.mark.parametrize("results_per_page", [True, False, "100", 1.5])
def test_rejects_bool_and_non_integer_results_per_page(
    results_per_page: object,
) -> None:
    with NvdClient() as client:
        with pytest.raises(NvdResponseError, match="must be an integer"):
            client.fetch_page(
                START,
                END,
                results_per_page=results_per_page,  # type: ignore[arg-type]
            )


@pytest.mark.parametrize(
    ("api_key", "expected_delay"),
    [
        (None, UNAUTHENTICATED_DELAY_SECONDS),
        (SecretStr("synthetic-key"), AUTHENTICATED_DELAY_SECONDS),
    ],
)
def test_iteration_paginates_and_sleeps_only_between_pages(
    api_key: SecretStr | None,
    expected_delay: float,
) -> None:
    starts: list[int] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        start_index = int(request.url.params["startIndex"])
        starts.append(start_index)
        record_number = start_index + 1
        return httpx.Response(
            200,
            json=make_payload(
                vulnerabilities=[{"cve": {"id": f"CVE-2026-{record_number:04d}"}}],
                start_index=start_index,
                results_per_page=1,
                total_results=2,
            ),
            request=request,
        )

    client, http_client = make_client(handler, api_key=api_key, sleeper=sleeps.append)
    try:
        records = list(client.iter_vulnerabilities(START, END, results_per_page=1))
    finally:
        http_client.close()

    assert starts == [0, 1]
    assert [record["cve"]["id"] for record in records] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]
    assert sleeps == [expected_delay]


def test_iteration_rejects_empty_page_before_total_is_reached() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(
            200,
            json=make_payload(vulnerabilities=[], total_results=1),
            request=request,
        )
    )
    try:
        with pytest.raises(NvdResponseError, match="stopped making progress"):
            list(client.iter_vulnerabilities(START, END))
    finally:
        http_client.close()


def test_iteration_rejects_mismatched_response_start_index() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(
            200,
            json=make_payload(start_index=1, total_results=2),
            request=request,
        )
    )
    try:
        with pytest.raises(NvdResponseError, match="did not match"):
            list(client.iter_vulnerabilities(START, END))
    finally:
        http_client.close()


def test_invalid_json_is_response_error() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(200, content=b"not-json", request=request)
    )
    try:
        with pytest.raises(NvdResponseError, match="invalid JSON"):
            client.fetch_page(START, END)
    finally:
        http_client.close()


def test_oversized_content_length_is_rejected_before_body_consumption(
    monkeypatch,
) -> None:
    monkeypatch.setattr(nvd_client_module, "MAX_RESPONSE_BYTES", 10)
    stream = TrackingStream([b'{"private":"payload"}'])
    client, http_client = make_client(
        lambda request: httpx.Response(
            200,
            headers={"Content-Length": "11"},
            stream=stream,
            request=request,
        )
    )
    try:
        with pytest.raises(NvdResponseError, match="approved size limit") as exc_info:
            client.fetch_page(START, END)
    finally:
        http_client.close()

    assert stream.chunks_consumed == 0
    assert "private" not in str(exc_info.value)


def test_incrementally_oversized_body_stops_before_all_chunks_are_consumed(
    monkeypatch,
) -> None:
    monkeypatch.setattr(nvd_client_module, "MAX_RESPONSE_BYTES", 10)
    stream = TrackingStream([b"12345", b"67890", b"x", b"not-consumed"])
    client, http_client = make_client(
        lambda request: httpx.Response(200, stream=stream, request=request)
    )
    try:
        with pytest.raises(NvdResponseError, match="approved size limit"):
            client.fetch_page(START, END)
    finally:
        http_client.close()

    assert stream.chunks_consumed == 3
    assert stream.chunks_consumed < len(stream.chunks)


def test_bounded_streamed_body_parses_after_complete_read() -> None:
    encoded = json.dumps(make_payload()).encode("utf-8")
    split_at = len(encoded) // 2
    stream = TrackingStream([encoded[:split_at], encoded[split_at:]])
    client, http_client = make_client(
        lambda request: httpx.Response(200, stream=stream, request=request)
    )
    try:
        parsed = client.fetch_page(START, END)
    finally:
        http_client.close()

    assert parsed.total_results == 1
    assert parsed.vulnerabilities[0]["cve"]["id"] == "CVE-2026-0001"
    assert stream.chunks_consumed == 2


@pytest.mark.parametrize("payload", [[], "invalid", False])
def test_invalid_top_level_schema_is_response_error(payload: object) -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(200, json=payload, request=request)
    )
    try:
        with pytest.raises(NvdResponseError, match="JSON object"):
            client.fetch_page(START, END)
    finally:
        http_client.close()


@pytest.mark.parametrize("vulnerabilities", [None, "invalid", [False]])
def test_invalid_vulnerability_collection_is_response_error(
    vulnerabilities: object,
) -> None:
    payload = make_payload()
    payload["vulnerabilities"] = vulnerabilities
    client, http_client = make_client(
        lambda request: httpx.Response(200, json=payload, request=request)
    )
    try:
        with pytest.raises(NvdResponseError, match="list of objects"):
            client.fetch_page(START, END)
    finally:
        http_client.close()


@pytest.mark.parametrize(
    "field",
    ["startIndex", "resultsPerPage", "totalResults"],
)
def test_invalid_pagination_fields_are_response_errors(field: str) -> None:
    payload = make_payload()
    payload[field] = "invalid"
    client, http_client = make_client(
        lambda request: httpx.Response(200, json=payload, request=request)
    )
    try:
        with pytest.raises(NvdResponseError, match="pagination metadata"):
            client.fetch_page(START, END)
    finally:
        http_client.close()


@pytest.mark.parametrize(
    "field",
    ["startIndex", "resultsPerPage", "totalResults"],
)
def test_negative_pagination_fields_are_response_errors(field: str) -> None:
    payload = make_payload()
    payload[field] = -1
    client, http_client = make_client(
        lambda request: httpx.Response(200, json=payload, request=request)
    )
    try:
        with pytest.raises(NvdResponseError, match="negative pagination"):
            client.fetch_page(START, END)
    finally:
        http_client.close()


def test_http_500_is_http_error_without_response_body() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(
            500,
            text="private upstream detail",
            request=request,
        )
    )
    try:
        with pytest.raises(NvdHttpError, match="HTTP 500") as exc_info:
            client.fetch_page(START, END)
    finally:
        http_client.close()

    assert "private upstream detail" not in str(exc_info.value)


def test_http_429_is_rate_limit_error() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(429, request=request)
    )
    try:
        with pytest.raises(NvdRateLimitError, match="HTTP 429"):
            client.fetch_page(START, END)
    finally:
        http_client.close()


@pytest.mark.parametrize("error_type", [httpx.ReadTimeout, httpx.ConnectError])
def test_timeout_and_transport_failures_are_request_errors(error_type) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error_type("sensitive transport detail", request=request)

    client, http_client = make_client(handler)
    try:
        with pytest.raises(NvdRequestError) as exc_info:
            client.fetch_page(START, END)
    finally:
        http_client.close()

    assert "sensitive transport detail" not in str(exc_info.value)


def test_close_does_not_close_injected_http_client() -> None:
    client, http_client = make_client(
        lambda request: httpx.Response(200, json=make_payload(), request=request)
    )

    client.close()

    assert not http_client.is_closed
    http_client.close()


def test_context_manager_closes_owned_http_client() -> None:
    client = NvdClient()

    with client:
        assert not client._http_client.is_closed

    assert client._http_client.is_closed
