"""Synchronous collector for the approved Google Cloud Threat Intelligence RSS feed."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.ingestion.source_registry import (
    get_required_source_base_url,
    get_source_definition,
)


GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG = "google-threat-intelligence-public-research"
MANDIANT_THREAT_RESEARCH_SOURCE_SLUG = "mandiant-public-threat-research"
GOOGLE_THREAT_INTELLIGENCE_FEED_URL = get_required_source_base_url(
    GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG
)
GOOGLE_THREAT_INTELLIGENCE_ALLOWED_HOST = get_source_definition(
    GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG
).allowed_hosts[0]
DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=5.0, read=10.0, write=5.0, pool=5.0)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
USER_AGENT = "AlphaDataCyberOSINT/1.0 (+defensive-google-threat-rss)"
ACCEPT_HEADER = "application/rss+xml, application/atom+xml, application/xml, text/xml, */*;q=0.1"
ALLOWED_CONTENT_TYPES = {
    "application/rss+xml",
    "application/atom+xml",
    "application/xml",
    "text/xml",
}


class GoogleThreatRssClientError(Exception):
    """Base class for sanitized Google Threat RSS client failures."""


class GoogleThreatRssRequestError(GoogleThreatRssClientError):
    """The RSS request could not be completed."""


class GoogleThreatRssHttpError(GoogleThreatRssClientError):
    """The RSS feed returned an unsuccessful HTTP status."""


class GoogleThreatRssRateLimitError(GoogleThreatRssHttpError):
    """The RSS feed rejected a request because of rate limiting."""


class GoogleThreatRssRedirectError(GoogleThreatRssClientError):
    """The RSS request encountered an unsafe redirect."""


class GoogleThreatRssResponseTooLargeError(GoogleThreatRssClientError):
    """The RSS response exceeded the approved size limit."""


class GoogleThreatRssContentTypeError(GoogleThreatRssClientError):
    """The RSS response content type was not acceptable."""


@dataclass(frozen=True)
class GoogleThreatRssFetchResult:
    """Bounded feed bytes and safe collection metadata."""

    feed_bytes: bytes
    source_url: str
    final_url: str
    content_type: str | None
    byte_count: int


class GoogleThreatIntelligenceRssClient:
    """Fetch the approved shared Google/Mandiant feed with strict bounds."""

    def __init__(self, *, http_client: httpx.Client | None = None) -> None:
        self._owns_http_client = http_client is None
        self._http_client = http_client or httpx.Client(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        )

    def fetch_publications(self) -> GoogleThreatRssFetchResult:
        """Fetch the fixed official Google Cloud Threat Intelligence RSS feed."""

        try:
            with self._http_client.stream(
                "GET",
                GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
                headers={"User-Agent": USER_AGENT, "Accept": ACCEPT_HEADER},
                follow_redirects=False,
            ) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    raise GoogleThreatRssRedirectError(
                        "The RSS feed does not permit redirects."
                    )
                if response.status_code == 429:
                    raise GoogleThreatRssRateLimitError(
                        "The RSS feed rate limit was reached (HTTP 429)."
                    )
                if not response.is_success:
                    raise GoogleThreatRssHttpError(
                        f"The RSS feed returned HTTP {response.status_code}."
                    )

                content_type = _content_type(response.headers.get("content-type"))
                if not _acceptable_content_type(content_type):
                    raise GoogleThreatRssContentTypeError(
                        "The RSS feed returned an unsupported content type."
                    )
                body = _read_bounded(response)
                return GoogleThreatRssFetchResult(
                    feed_bytes=body,
                    source_url=GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
                    final_url=GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
                    content_type=content_type,
                    byte_count=len(body),
                )
        except GoogleThreatRssClientError:
            raise
        except httpx.TimeoutException as exc:
            raise GoogleThreatRssRequestError("The RSS request timed out.") from exc
        except httpx.TransportError as exc:
            raise GoogleThreatRssRequestError(
                "The RSS request failed during transport."
            ) from exc

    def close(self) -> None:
        """Close the HTTP client only when this instance created it."""

        if self._owns_http_client:
            self._http_client.close()

    def __enter__(self) -> GoogleThreatIntelligenceRssClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _read_bounded(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise GoogleThreatRssResponseTooLargeError(
                "The RSS response exceeded the approved size limit."
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _content_type(value: str | None) -> str | None:
    if value is None:
        return None
    return value.split(";", 1)[0].strip().lower() or None


def _acceptable_content_type(value: str | None) -> bool:
    if value is None:
        return False
    return value in ALLOWED_CONTENT_TYPES or value.endswith("+xml")
