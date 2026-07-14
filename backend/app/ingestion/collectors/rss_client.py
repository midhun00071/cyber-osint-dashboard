"""Synchronous locked-down collector for the approved CERT-EU RSS feed."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from urllib.parse import urljoin, urlparse

import httpx

from app.ingestion.source_registry import (
    get_required_source_base_url,
    get_source_definition,
    source_allows_hostname,
)


CERT_EU_SOURCE_SLUG = "cert-eu-security-advisories"
CERT_EU_FEED_URL = get_required_source_base_url(CERT_EU_SOURCE_SLUG)
CERT_EU_ALLOWED_SCHEME = "https"
CERT_EU_ALLOWED_HOST = get_source_definition(CERT_EU_SOURCE_SLUG).allowed_hosts[0]
DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=5.0, read=10.0, write=5.0, pool=5.0)
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REDIRECTS = 3
USER_AGENT = "AlphaDataCyberOSINT/1.0 (+defensive-rss-ingestion)"
ACCEPT_HEADER = "application/rss+xml, application/atom+xml, application/xml, text/xml, */*;q=0.1"
ALLOWED_CONTENT_TYPES = {
    "application/rss+xml",
    "application/atom+xml",
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/octet-stream",
}


class RssClientError(Exception):
    """Base class for sanitized RSS client failures."""


class RssRequestError(RssClientError):
    """The RSS request could not be completed."""


class RssHttpError(RssClientError):
    """The RSS feed returned an unsuccessful HTTP status."""


class RssRateLimitError(RssHttpError):
    """The RSS feed rejected a request because of rate limiting."""


class RssRedirectError(RssClientError):
    """The RSS request encountered an unsafe redirect."""


class RssResponseTooLargeError(RssClientError):
    """The RSS response exceeded the approved size limit."""


class RssContentTypeError(RssClientError):
    """The RSS response content type was not acceptable."""


@dataclass(frozen=True)
class RssFetchResult:
    """Bounded feed bytes and safe collection metadata."""

    feed_bytes: bytes
    source_url: str
    final_url: str
    content_type: str | None
    byte_count: int


class RssClient:
    """Fetch the approved CERT-EU feed with strict URL and response bounds."""

    def __init__(self, *, http_client: httpx.Client | None = None) -> None:
        self._owns_http_client = http_client is None
        self._http_client = http_client or httpx.Client(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
        )

    def fetch_cert_eu_security_advisories(self) -> RssFetchResult:
        """Fetch the approved CERT-EU security-advisories feed."""

        current_url = CERT_EU_FEED_URL
        for redirect_count in range(MAX_REDIRECTS + 1):
            _validate_approved_url(current_url)
            try:
                with self._http_client.stream(
                    "GET",
                    current_url,
                    headers={"User-Agent": USER_AGENT, "Accept": ACCEPT_HEADER},
                    follow_redirects=False,
                ) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        if redirect_count >= MAX_REDIRECTS:
                            raise RssRedirectError("The RSS redirect limit was exceeded.")
                        current_url = self._redirect_target(current_url, response)
                        continue
                    if response.status_code == 429:
                        raise RssRateLimitError(
                            "The RSS feed rate limit was reached (HTTP 429)."
                        )
                    if not response.is_success:
                        raise RssHttpError(
                            f"The RSS feed returned HTTP {response.status_code}."
                        )

                    content_type = _content_type(response.headers.get("content-type"))
                    if not _acceptable_content_type(content_type):
                        raise RssContentTypeError(
                            "The RSS feed returned an unsupported content type."
                        )
                    body = _read_bounded(response)
                    return RssFetchResult(
                        feed_bytes=body,
                        source_url=CERT_EU_FEED_URL,
                        final_url=current_url,
                        content_type=content_type,
                        byte_count=len(body),
                    )
            except RssClientError:
                raise
            except httpx.TimeoutException as exc:
                raise RssRequestError("The RSS request timed out.") from exc
            except httpx.RemoteProtocolError as exc:
                if "Invalid URL in location header" in str(exc):
                    raise RssRedirectError(
                        "The RSS redirect destination is invalid."
                    ) from exc
                raise RssRequestError("The RSS request failed during transport.") from exc
            except httpx.TransportError as exc:
                raise RssRequestError("The RSS request failed during transport.") from exc

        raise RssRedirectError("The RSS redirect limit was exceeded.")

    def close(self) -> None:
        """Close the HTTP client only when this instance created it."""

        if self._owns_http_client:
            self._http_client.close()

    def __enter__(self) -> RssClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @staticmethod
    def _redirect_target(current_url: str, response: httpx.Response) -> str:
        location = response.headers.get("location")
        if not location:
            raise RssRedirectError("The RSS redirect did not include a destination.")
        try:
            target = urljoin(str(response.url) if response.url else current_url, location)
        except (TypeError, ValueError) as exc:
            raise RssRedirectError("The RSS redirect destination is invalid.") from exc
        _validate_approved_url(target)
        return target


def _read_bounded(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise RssResponseTooLargeError(
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
        return True
    return value in ALLOWED_CONTENT_TYPES or value.endswith("+xml")


def _validate_approved_url(url: str) -> None:
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        username = parsed.username
        password = parsed.password
        fragment = parsed.fragment
        port = parsed.port
        host = (parsed.hostname or "").lower()
    except ValueError as exc:
        raise RssRedirectError("The RSS feed URL is invalid.") from exc
    if scheme != CERT_EU_ALLOWED_SCHEME:
        raise RssRedirectError("The RSS feed URL must use HTTPS.")
    if "@" in netloc or username or password:
        raise RssRedirectError("The RSS feed URL must not contain credentials.")
    if fragment:
        raise RssRedirectError("The RSS feed URL must not contain a fragment.")
    if port not in (None, 443):
        raise RssRedirectError("The RSS feed URL uses an unexpected port.")
    if not source_allows_hostname(CERT_EU_SOURCE_SLUG, host):
        raise RssRedirectError("The RSS feed URL host is not approved.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise RssRedirectError("The RSS feed URL host is not approved.")
