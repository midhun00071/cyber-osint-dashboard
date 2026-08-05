"""Strict fixed-policy transport for C05 official RSS metadata feeds."""

from __future__ import annotations

import codecs
from dataclasses import dataclass
import math
import time
from types import MappingProxyType
from typing import Callable, Mapping

import httpx

from app.ingestion.source_registry import (
    ImplementationStatus,
    get_source_definition,
)


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 15.0
WRITE_TIMEOUT_SECONDS = 5.0
POOL_TIMEOUT_SECONDS = 5.0
TOTAL_DEADLINE_SECONDS = 30.0
USER_AGENT = "AlphaDataCyberOSINT/1.0 (+official-rss-metadata)"
ACCEPT_HEADER = "application/rss+xml, application/xml, text/xml"
ACCEPT_ENCODING_HEADER = "identity"
ALLOWED_MEDIA_TYPES = frozenset(
    {"application/rss+xml", "application/xml", "text/xml"}
)
_REDIRECT_STATUS_CODES = frozenset({300, 301, 302, 303, 304, 305, 306, 307, 308})


class OfficialRssClientError(RuntimeError):
    """Base class for sanitized official RSS transport failures."""


class OfficialRssConfigurationError(OfficialRssClientError, ValueError):
    """The immutable source or client configuration was invalid."""


class OfficialRssTransportError(OfficialRssClientError):
    """The fixed official feed request failed during transport."""


class OfficialRssTimeoutError(OfficialRssTransportError):
    """The feed operation exceeded a request or total deadline."""


class OfficialRssHttpError(OfficialRssClientError):
    """The official feed returned an unsuccessful response."""


class OfficialRssRateLimitError(OfficialRssHttpError):
    """The official feed returned HTTP 429."""


class OfficialRssRedirectError(OfficialRssClientError):
    """A redirect response or changed response URL was rejected."""


class OfficialRssContentTypeError(OfficialRssClientError):
    """The response media type was missing, conflicting, or unsupported."""


class OfficialRssContentEncodingError(OfficialRssClientError):
    """The response used unsupported compression."""


class OfficialRssResponseTooLargeError(OfficialRssClientError):
    """The decoded identity response exceeded the fixed byte limit."""


class OfficialRssRequestPolicyError(OfficialRssClientError):
    """A prepared request differed from the immutable policy."""


@dataclass(frozen=True, slots=True)
class OfficialRssSourcePolicy:
    source_slug: str
    feed_url: str
    feed_host: str
    feed_path: str
    canonical_hosts: tuple[str, ...]
    canonical_kind: str
    source_language: str


@dataclass(frozen=True, slots=True)
class OfficialRssFetchResult:
    source_slug: str
    body: bytes
    response_bytes: int
    request_count: int = 1


_POLICIES = (
    OfficialRssSourcePolicy(
        source_slug="cert-fr-security-alerts",
        feed_url="https://www.cert.ssi.gouv.fr/alerte/feed/",
        feed_host="www.cert.ssi.gouv.fr",
        feed_path="/alerte/feed/",
        canonical_hosts=("www.cert.ssi.gouv.fr", "cert.ssi.gouv.fr"),
        canonical_kind="cert-fr-alert",
        source_language="fr",
    ),
    OfficialRssSourcePolicy(
        source_slug="cert-fr-security-advisories",
        feed_url="https://cert.ssi.gouv.fr/avis/feed/",
        feed_host="cert.ssi.gouv.fr",
        feed_path="/avis/feed/",
        canonical_hosts=("www.cert.ssi.gouv.fr", "cert.ssi.gouv.fr"),
        canonical_kind="cert-fr-advisory",
        source_language="fr",
    ),
    OfficialRssSourcePolicy(
        source_slug="uk-ncsc-threat-reports",
        feed_url="https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        feed_host="www.ncsc.gov.uk",
        feed_path="/api/1/services/v1/report-rss-feed.xml",
        canonical_hosts=("www.ncsc.gov.uk",),
        canonical_kind="uk-ncsc-report",
        source_language="en-GB",
    ),
)


def _build_policy_registry() -> MappingProxyType[str, OfficialRssSourcePolicy]:
    registry: dict[str, OfficialRssSourcePolicy] = {}
    for policy in _POLICIES:
        source = get_source_definition(policy.source_slug)
        if (
            source.implementation_status is not ImplementationStatus.IMPLEMENTED
            or source.enabled is not False
            or source.authentication_required is not False
            or source.base_url != policy.feed_url
            or source.allowed_hosts != (policy.feed_host,)
            or source.canonical_publication_hosts != policy.canonical_hosts
            or policy.source_slug in registry
        ):
            raise RuntimeError("The C05 official RSS policy registry is invalid.")
        registry[policy.source_slug] = policy
    return MappingProxyType(registry)


C05_OFFICIAL_RSS_POLICIES = _build_policy_registry()
C05_OFFICIAL_RSS_SOURCE_SLUGS = frozenset(C05_OFFICIAL_RSS_POLICIES)


def validate_c05_official_rss_policy_registry(
    policy_registry: object,
) -> MappingProxyType[str, OfficialRssSourcePolicy]:
    """Snapshot an exact copy of the immutable C05 endpoint policy."""

    if not isinstance(policy_registry, MappingProxyType) or len(
        policy_registry
    ) != len(C05_OFFICIAL_RSS_POLICIES):
        raise OfficialRssConfigurationError(
            "The official RSS policy registry is invalid."
        )
    trusted: dict[str, OfficialRssSourcePolicy] = {}
    for source_slug, policy in policy_registry.items():
        if type(source_slug) is not str or source_slug not in C05_OFFICIAL_RSS_POLICIES:
            raise OfficialRssConfigurationError(
                "The official RSS policy registry is invalid."
            )
        canonical = C05_OFFICIAL_RSS_POLICIES[source_slug]
        if (
            type(policy) is not OfficialRssSourcePolicy
            or type(policy.source_slug) is not str
            or type(policy.feed_url) is not str
            or type(policy.feed_host) is not str
            or type(policy.feed_path) is not str
            or type(policy.canonical_kind) is not str
            or type(policy.source_language) is not str
            or type(policy.canonical_hosts) is not tuple
            or any(type(host) is not str for host in policy.canonical_hosts)
            or policy.source_slug != canonical.source_slug
            or policy.feed_url != canonical.feed_url
            or policy.feed_host != canonical.feed_host
            or policy.feed_path != canonical.feed_path
            or policy.canonical_hosts != canonical.canonical_hosts
            or policy.canonical_kind != canonical.canonical_kind
            or policy.source_language != canonical.source_language
        ):
            raise OfficialRssConfigurationError(
                "The official RSS policy registry is invalid."
            )
        trusted[source_slug] = canonical
    if frozenset(trusted) != C05_OFFICIAL_RSS_SOURCE_SLUGS:
        raise OfficialRssConfigurationError(
            "The official RSS policy registry is invalid."
        )
    return MappingProxyType(trusted)


class _RequestGuard:
    def __init__(self, policy: OfficialRssSourcePolicy) -> None:
        self._policy = policy
        self._armed = False

    def arm(self) -> None:
        if self._armed:
            raise OfficialRssRequestPolicyError(
                "The official RSS request failed fixed-policy validation."
            )
        self._armed = True

    def __call__(self, request: httpx.Request) -> None:
        if not self._armed:
            raise OfficialRssRequestPolicyError(
                "The official RSS request failed fixed-policy validation."
            )
        expected_url = httpx.URL(self._policy.feed_url)
        expected_headers = {
            "host": self._policy.feed_host,
            "accept": ACCEPT_HEADER,
            "user-agent": USER_AGENT,
            "accept-encoding": ACCEPT_ENCODING_HEADER,
        }
        pairs = request.headers.multi_items()
        if (
            request.method != "GET"
            or request.url != expected_url
            or request.url.query
            or len(pairs) != len(expected_headers)
            or {name for name, _ in pairs} != set(expected_headers)
            or any(value != expected_headers[name] for name, value in pairs)
            or "authorization" in request.headers
            or "cookie" in request.headers
        ):
            raise OfficialRssRequestPolicyError(
                "The official RSS request failed fixed-policy validation."
            )
        self._armed = False


class OfficialRssClient:
    """Fetch one exact official feed without discovery, redirects, or auth."""

    def __init__(
        self,
        *,
        policy_registry: Mapping[str, OfficialRssSourcePolicy] = (
            C05_OFFICIAL_RSS_POLICIES
        ),
        http_transport: httpx.BaseTransport | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        approved_registry = validate_c05_official_rss_policy_registry(
            policy_registry
        )
        if http_transport is not None and not isinstance(
            http_transport, httpx.BaseTransport
        ):
            raise OfficialRssConfigurationError(
                "The official RSS transport is invalid."
            )
        if not callable(monotonic_clock):
            raise OfficialRssConfigurationError(
                "The official RSS clock is invalid."
            )
        self._policies = approved_registry
        self._transport = http_transport
        self._clock = monotonic_clock
        self._last_clock: float | None = None

    def fetch(self, source_slug: str) -> OfficialRssFetchResult:
        try:
            policy = self._policies[source_slug]
        except (KeyError, TypeError):
            raise OfficialRssConfigurationError(
                "The official RSS source is not approved."
            ) from None
        started = self._read_clock()
        deadline = started + TOTAL_DEADLINE_SECONDS
        guard = _RequestGuard(policy)
        timeout = httpx.Timeout(
            READ_TIMEOUT_SECONDS,
            connect=CONNECT_TIMEOUT_SECONDS,
            read=READ_TIMEOUT_SECONDS,
            write=WRITE_TIMEOUT_SECONDS,
            pool=POOL_TIMEOUT_SECONDS,
        )
        try:
            with httpx.Client(
                timeout=timeout,
                follow_redirects=False,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": ACCEPT_HEADER,
                    "Accept-Encoding": ACCEPT_ENCODING_HEADER,
                },
                event_hooks={"request": [guard]},
                transport=self._transport,
                trust_env=False,
            ) as client:
                client.headers.pop("Connection", None)
                guard.arm()
                with client.stream(
                    "GET",
                    policy.feed_url,
                    follow_redirects=False,
                    timeout=timeout,
                ) as response:
                    self._remaining(deadline)
                    if response.url != httpx.URL(policy.feed_url):
                        raise OfficialRssRedirectError(
                            "The official RSS response URL was rejected."
                        )
                    if response.status_code in _REDIRECT_STATUS_CODES:
                        raise OfficialRssRedirectError(
                            "An official RSS redirect response was rejected."
                        )
                    if response.status_code == 429:
                        raise OfficialRssRateLimitError(
                            "The official RSS feed rate limited the request."
                        )
                    if response.status_code != 200:
                        raise OfficialRssHttpError(
                            "The official RSS feed returned an unsuccessful response."
                        )
                    _validate_content_encoding(response.headers)
                    _validate_content_type(response.headers)
                    declared = _content_length(response.headers)
                    if declared is not None and declared > MAX_RESPONSE_BYTES:
                        raise OfficialRssResponseTooLargeError(
                            "The official RSS response exceeded the byte limit."
                        )
                    chunks: list[bytes] = []
                    size = 0
                    for chunk in response.iter_raw():
                        self._remaining(deadline)
                        size += len(chunk)
                        if size > MAX_RESPONSE_BYTES:
                            raise OfficialRssResponseTooLargeError(
                                "The official RSS response exceeded the byte limit."
                            )
                        chunks.append(chunk)
                    self._remaining(deadline)
                    body = b"".join(chunks)
                client.cookies.clear()
            return OfficialRssFetchResult(
                source_slug=source_slug,
                body=body,
                response_bytes=len(body),
            )
        except OfficialRssClientError:
            raise
        except httpx.TimeoutException:
            raise OfficialRssTimeoutError(
                "The official RSS request timed out."
            ) from None
        except httpx.TransportError:
            raise OfficialRssTransportError(
                "The official RSS request failed during transport."
            ) from None
        except Exception:
            raise OfficialRssTransportError(
                "The official RSS request failed during transport."
            ) from None

    def _read_clock(self) -> float:
        try:
            value = self._clock()
        except Exception:
            raise OfficialRssTimeoutError(
                "The official RSS deadline could not be enforced."
            ) from None
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or self._last_clock is not None
            and float(value) < self._last_clock
        ):
            raise OfficialRssTimeoutError(
                "The official RSS deadline could not be enforced."
            )
        self._last_clock = float(value)
        return self._last_clock

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._read_clock()
        if not math.isfinite(remaining) or remaining <= 0:
            raise OfficialRssTimeoutError(
                "The official RSS operation exceeded its total deadline."
            )
        return remaining


def _validate_content_type(headers: httpx.Headers) -> None:
    values = headers.get_list("content-type")
    if len(values) != 1 or "," in values[0]:
        raise OfficialRssContentTypeError(
            "The official RSS response media type was invalid."
        )
    value = values[0]
    if (
        not value
        or not value.isascii()
        or any(ord(character) < 0x20 and character != "\t" for character in value)
        or "\x7f" in value
    ):
        raise OfficialRssContentTypeError(
            "The official RSS response media type was invalid."
        )
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].lower() not in ALLOWED_MEDIA_TYPES:
        raise OfficialRssContentTypeError(
            "The official RSS response media type was invalid."
        )
    if len(parts) > 2:
        raise OfficialRssContentTypeError(
            "The official RSS response media type was invalid."
        )
    if len(parts) == 2:
        parameter = parts[1]
        if parameter.count("=") != 1:
            raise OfficialRssContentTypeError(
                "The official RSS response media type was invalid."
            )
        name, charset = (item.strip() for item in parameter.split("=", 1))
        if name.lower() != "charset" or not charset:
            raise OfficialRssContentTypeError(
                "The official RSS response media type was invalid."
            )
        if charset.startswith('"') or charset.endswith('"'):
            if len(charset) < 3 or not (
                charset.startswith('"') and charset.endswith('"')
            ):
                raise OfficialRssContentTypeError(
                    "The official RSS response media type was invalid."
                )
            charset = charset[1:-1]
        if not charset.isascii() or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for character in charset
        ):
            raise OfficialRssContentTypeError(
                "The official RSS response media type was invalid."
            )
        try:
            codecs.lookup(charset)
        except LookupError:
            raise OfficialRssContentTypeError(
                "The official RSS response media type was invalid."
            ) from None


def _validate_content_encoding(headers: httpx.Headers) -> None:
    values = headers.get_list("content-encoding")
    if not values:
        return
    if len(values) != 1 or values[0].strip().lower() != "identity":
        raise OfficialRssContentEncodingError(
            "The official RSS response used unsupported compression."
        )


def _content_length(headers: httpx.Headers) -> int | None:
    values = headers.get_list("content-length")
    if not values:
        return None
    if len(values) != 1 or not values[0].isascii() or not values[0].isdigit():
        raise OfficialRssTransportError(
            "The official RSS response metadata was invalid."
        )
    return int(values[0])


__all__ = [
    "ACCEPT_ENCODING_HEADER",
    "ACCEPT_HEADER",
    "ALLOWED_MEDIA_TYPES",
    "C05_OFFICIAL_RSS_POLICIES",
    "C05_OFFICIAL_RSS_SOURCE_SLUGS",
    "MAX_RESPONSE_BYTES",
    "OfficialRssClient",
    "OfficialRssClientError",
    "OfficialRssFetchResult",
    "OfficialRssSourcePolicy",
    "USER_AGENT",
    "validate_c05_official_rss_policy_registry",
]
