"""C10 regressions for immutable outbound transport and response policy."""

from __future__ import annotations

from datetime import UTC, datetime
import json

import httpx
import pytest

from app.ingestion.collectors.cisa_kev_client import (
    CISA_KEV_CATALOG_URL,
    CisaKevClient,
    CisaKevRedirectError,
)
from app.ingestion.collectors.epss_client import EpssClient, EpssResponseError
from app.ingestion.collectors.google_threat_intelligence_rss_client import (
    GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
    GoogleThreatIntelligenceRssClient,
    GoogleThreatRssRedirectError,
)
from app.ingestion.collectors.nvd_client import NvdClient, NvdResponseError
from app.ingestion.collectors.rss_client import (
    CERT_EU_FEED_URL,
    RssClient,
    RssRedirectError,
)


@pytest.mark.parametrize(
    "client_type",
    (
        CisaKevClient,
        EpssClient,
        GoogleThreatIntelligenceRssClient,
        NvdClient,
        RssClient,
    ),
)
def test_owned_clients_disable_redirects_and_environment_proxies(
    monkeypatch: pytest.MonkeyPatch,
    client_type: type,
) -> None:
    captured: dict[str, object] = {}

    class SentinelClient:
        def close(self) -> None:
            pass

    sentinel = SentinelClient()

    def build_client(**kwargs: object) -> SentinelClient:
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(httpx, "Client", build_client)
    client = client_type()
    try:
        assert captured["follow_redirects"] is False
        assert captured["trust_env"] is False
    finally:
        client.close()


@pytest.mark.parametrize("status_code", (301, 302, 303, 307, 308))
@pytest.mark.parametrize(
    ("client_type", "method_name", "source_url", "error_type"),
    (
        (CisaKevClient, "fetch_catalog", CISA_KEV_CATALOG_URL, CisaKevRedirectError),
        (
            RssClient,
            "fetch_cert_eu_security_advisories",
            CERT_EU_FEED_URL,
            RssRedirectError,
        ),
        (
            GoogleThreatIntelligenceRssClient,
            "fetch_publications",
            GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
            GoogleThreatRssRedirectError,
        ),
    ),
)
def test_fixed_feed_clients_reject_redirects_without_a_second_request(
    status_code: int,
    client_type: type,
    method_name: str,
    source_url: str,
    error_type: type[Exception],
) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            status_code,
            headers={
                "location": "https://redirect.example.invalid/?token=REDIRECT_SECRET_CANARY"
            },
        )

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        trust_env=False,
        follow_redirects=False,
    ) as http_client:
        with client_type(http_client=http_client) as client:
            with pytest.raises(error_type) as exc_info:
                getattr(client, method_name)()

    assert seen == [source_url]
    assert "REDIRECT_SECRET_CANARY" not in str(exc_info.value)


def test_epss_rejects_explicit_non_json_media_type() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            content=json.dumps({"data": []}).encode(),
            request=request,
        )
    )
    with httpx.Client(transport=transport, trust_env=False) as http_client:
        with EpssClient(http_client=http_client) as client:
            with pytest.raises(EpssResponseError, match="unsupported content type"):
                client.fetch_batch(("CVE-2026-1234",))


def test_nvd_rejects_explicit_non_json_media_type() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            content=json.dumps(
                {
                    "vulnerabilities": [],
                    "startIndex": 0,
                    "resultsPerPage": 1,
                    "totalResults": 0,
                }
            ).encode(),
            request=request,
        )
    )
    start = datetime(2026, 8, 8, tzinfo=UTC)
    end = datetime(2026, 8, 9, tzinfo=UTC)
    with httpx.Client(transport=transport, trust_env=False) as http_client:
        with NvdClient(http_client=http_client, sleeper=lambda _seconds: None) as client:
            with pytest.raises(NvdResponseError, match="unsupported content type"):
                client.fetch_page(start, end, results_per_page=1)
