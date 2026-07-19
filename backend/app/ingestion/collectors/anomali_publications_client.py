"""Secure synchronous collector for fixed public Anomali Cyber Watch pages."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from enum import Enum
from html import unescape
from html.parser import HTMLParser
import ipaddress
import json
import math
import re
import sys
import time
from typing import Callable
import unicodedata
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from app.ingestion.adapters.anomali_publications import (
    ANOMALI_PATH_PREFIX,
    ANOMALI_PUBLICATION_HOST,
    ANOMALI_SOURCE_SLUG,
    MAX_ANOMALI_AUTHORS,
    MAX_ANOMALI_CATEGORIES,
    MAX_ANOMALI_AUTHOR_LENGTH,
    MAX_ANOMALI_CATEGORY_LENGTH,
    MAX_ANOMALI_ENTITY_DECODE_PASSES,
    AnomaliPublicationRecordError,
    adapt_anomali_publication,
)
from app.ingestion.publication_pipeline import PublicationCandidate


DISCOVERY_URL = "https://www.anomali.com/blog"
DISCOVERY_PATH = "/blog"
DISCOVERY_LINK_RESOLUTION_BASE = "https://www.anomali.com/blog/"
DEFAULT_TIMEOUT = httpx.Timeout(
    20.0,
    connect=5.0,
    read=10.0,
    write=5.0,
    pool=5.0,
)
TOTAL_REQUEST_TIMEOUT_SECONDS = 20.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
MIN_RECORDS = 1
MAX_RECORDS = 20
REQUEST_DELAY_SECONDS = 10.0
USER_AGENT = "AlphaDataCyberOSINT/1.0 (+defensive-anomali-publications)"
ACCEPT_HEADER = "text/html, application/xhtml+xml;q=0.9"
ALLOWED_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

MAX_JSON_LD_BLOCKS = 10
MAX_JSON_LD_BLOCK_CHARS = 64 * 1024
MAX_JSON_LD_DEPTH = 8
MAX_JSON_LD_NODES = 1_000
MAX_JSON_LD_STRING_LENGTH = 10_000
MAX_TIMESTAMP_LENGTH = 64
MAX_URL_LENGTH = 2_048

_MALFORMED_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ARTICLE_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SYSTEM_EXCEPTIONS = (MemoryError, KeyboardInterrupt, SystemExit, GeneratorExit)
_COMMON_HEX_DIGEST_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})
_MAX_DEFANG_TOKEN_CHARS = 16
_ASCII_ALPHANUMERIC = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)
_IP_CANDIDATE_CHARACTERS = frozenset("0123456789abcdefABCDEF:.[]")


class AnomaliFailureReason(str, Enum):
    """Allow-listed per-publication failure categories."""

    TRANSPORT_FAILURE = "transport_failure"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    HTTP_FAILURE = "http_failure"
    REDIRECT_REJECTED = "redirect_rejected"
    CONTENT_TYPE_REJECTED = "content_type_rejected"
    RESPONSE_TOO_LARGE = "response_too_large"
    METADATA_REJECTED = "metadata_rejected"


@dataclass(frozen=True, slots=True)
class AnomaliCollectionResult:
    """Safe immutable collector output without raw upstream material."""

    source_slug: str
    candidates: tuple[PublicationCandidate, ...]
    failure_count: int
    failure_reasons: tuple[AnomaliFailureReason, ...]
    discovered_approved_link_count: int
    capped: bool


class AnomaliCollectorError(Exception):
    """Base class for sanitized Anomali collector failures."""


class AnomaliCollectorConfigurationError(AnomaliCollectorError, ValueError):
    """The closed collector interface received invalid configuration."""


class AnomaliDiscoveryCollectionError(AnomaliCollectorError):
    """The mandatory fixed discovery page failed safe collection."""


class AnomaliTransportError(AnomaliCollectorError):
    """A request failed during transport."""


class AnomaliRequestStateIsolationError(AnomaliCollectorError):
    """Request state could not be isolated and the client is unusable."""


class AnomaliTimeoutError(AnomaliTransportError):
    """A request exceeded a configured timeout."""


class AnomaliRateLimitError(AnomaliCollectorError):
    """Anomali returned HTTP 429."""


class AnomaliHttpError(AnomaliCollectorError):
    """Anomali returned another unsuccessful status."""


class AnomaliRedirectError(AnomaliCollectorError):
    """A redirect or URL identity failed the fixed policy."""


class AnomaliContentTypeError(AnomaliCollectorError):
    """A response did not identify approved HTML content."""


class AnomaliResponseTooLargeError(AnomaliCollectorError):
    """A streamed response exceeded the independent two-MiB limit."""


class AnomaliMetadataError(AnomaliCollectorError):
    """Discovery or publication metadata failed safe validation."""


class AnomaliPacingError(AnomaliCollectorError):
    """The configured clock or sleeper could not enforce safe pacing."""


@dataclass(frozen=True, slots=True)
class _HtmlResponse:
    body: bytes
    final_url: str
    encoding: str


@dataclass(frozen=True, slots=True)
class _DiscoveryElement:
    tag: str
    in_main: bool
    in_excluded: bool
    begins_main: bool


class _DiscoveryParser(HTMLParser):
    """Collect approved anchors only from one closed ``main`` subtree."""

    _EXCLUDED_TAGS = frozenset({"nav", "header", "footer", "aside", "form"})
    _VOID_ELEMENTS = frozenset(
        {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }
    )

    def __init__(self, *, maximum: int) -> None:
        super().__init__(convert_charrefs=True)
        self._maximum = maximum
        self._stack: list[_DiscoveryElement] = []
        self._seen: set[str] = set()
        self._main_count = 0
        self._main_closed = False
        self._malformed = False
        self.urls: list[str] = []
        self.capped = False

    @property
    def has_deterministic_main(self) -> bool:
        return (
            self._main_count == 1
            and self._main_closed
            and not self._malformed
            and not any(element.in_main for element in self._stack)
        )

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        tag = tag.lower()
        parent = self._stack[-1] if self._stack else None
        begins_main = tag == "main"
        if begins_main:
            self._main_count += 1
            if self._main_count > 1 or bool(parent and parent.in_main):
                self._malformed = True
        in_main = begins_main or bool(parent and parent.in_main)
        in_excluded = tag in self._EXCLUDED_TAGS or bool(
            parent and parent.in_excluded
        )
        if tag not in self._VOID_ELEMENTS:
            self._stack.append(
                _DiscoveryElement(
                    tag=tag,
                    in_main=in_main,
                    in_excluded=in_excluded,
                    begins_main=begins_main,
                )
            )
        if tag == "a" and in_main and not in_excluded:
            self._consider_href(_attributes(attrs).get("href"))

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index].tag == tag:
                removed = self._stack[index:]
                if any(element.begins_main for element in removed):
                    if (
                        tag == "main"
                        and removed[0].begins_main
                        and len(removed) == 1
                    ):
                        self._main_closed = True
                    else:
                        self._malformed = True
                del self._stack[index:]
                return
        if tag == "main":
            self._malformed = True

    def _consider_href(self, href: str | None) -> None:
        if self.capped or href is None:
            return
        try:
            canonical = _resolve_reference(
                href,
                base_url=DISCOVERY_LINK_RESOLUTION_BASE,
                request_kind="publication",
            )
        except (AnomaliRedirectError, TypeError, ValueError):
            return
        if canonical in self._seen:
            return
        self._seen.add(canonical)
        if len(self.urls) < self._maximum:
            self.urls.append(canonical)
        else:
            self.capped = True


class _PublicationMetadataParser(HTMLParser):
    """Extract bounded head fields and JSON-LD, never body prose."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[str] = []
        self._head_active = False
        self._head_seen = False
        self._body_started = False
        self._title_parts: list[str] = []
        self._title_size = 0
        self._in_title = False
        self._title_elements_encountered = 0
        self._capturing_json_ld = False
        self._json_ld_parts: list[str] = []
        self._json_ld_size = 0
        self._json_ld_blocks_encountered = 0
        self.json_ld_blocks: list[str] = []
        self.json_ld_rejected = False
        self.identity_rejected = False
        self.metadata_rejected = False
        self.canonical_hrefs: list[str] = []
        self.og_urls: list[str] = []
        self.og_title: str | None = None
        self.meta_description: str | None = None
        self.og_description: str | None = None
        self.article_published_time: str | None = None
        self.article_modified_time: str | None = None
        self.meta_authors: list[str] = []
        self.meta_categories: list[str] = []

    @property
    def document_title(self) -> str | None:
        value = "".join(self._title_parts).strip()
        return value or None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        tag = tag.lower()
        attributes = _attributes(attrs)
        if tag == "head":
            if self._head_seen or self._head_active or self._body_started:
                self.metadata_rejected = True
            else:
                self._head_seen = True
                self._head_active = True
        elif tag == "body":
            # HTML parsers implicitly close an omitted </head> when <body>
            # starts. Model that transition directly and never allow later
            # body elements to be mistaken for head metadata.
            self._reject_open_title()
            self._reject_open_json_ld()
            self._body_started = True
            self._head_active = False
        in_head = self._head_active and not self._body_started
        self._stack.append(tag)
        if tag == "title":
            self._title_elements_encountered += 1
            if self._title_elements_encountered > 1 or self._in_title:
                self.metadata_rejected = True
                self._in_title = False
            elif in_head:
                self._in_title = True
        elif tag == "script" and _is_json_ld_media_type(attributes.get("type")):
            self._json_ld_blocks_encountered += 1
            if self._capturing_json_ld:
                self._reject_open_json_ld()
            if (
                self._json_ld_blocks_encountered > MAX_JSON_LD_BLOCKS
                or self.json_ld_rejected
            ):
                self.json_ld_rejected = True
                self._capturing_json_ld = False
            else:
                self._capturing_json_ld = True
                self._json_ld_parts = []
                self._json_ld_size = 0
        elif tag == "link" and in_head:
            rel_tokens = (attributes.get("rel") or "").lower().split()
            if "canonical" in rel_tokens and attributes.get("href"):
                self._append_identity(self.canonical_hrefs, attributes["href"])
        elif tag == "meta" and in_head:
            self._capture_meta(attributes)

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "head":
            self._reject_open_title()
            self._reject_open_json_ld()
            self._head_active = False
        elif tag == "body":
            self._reject_open_json_ld()
        if tag == "script" and self._capturing_json_ld:
            if not self.json_ld_rejected:
                self.json_ld_blocks.append("".join(self._json_ld_parts))
            self._capturing_json_ld = False
            self._json_ld_parts = []
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index] == tag:
                del self._stack[index:]
                return

    def close(self) -> None:
        super().close()
        self._reject_open_title()
        self._reject_open_json_ld()

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_size += len(data)
            if self._title_size > MAX_JSON_LD_STRING_LENGTH:
                self.metadata_rejected = True
                self._title_parts = []
            elif not self.metadata_rejected:
                self._title_parts.append(data)
        if self._capturing_json_ld and not self.json_ld_rejected:
            self._json_ld_size += len(data)
            if self._json_ld_size > MAX_JSON_LD_BLOCK_CHARS:
                self.json_ld_rejected = True
                self._json_ld_parts = []
            else:
                self._json_ld_parts.append(data)

    def _reject_open_title(self) -> None:
        if self._in_title:
            self.metadata_rejected = True
            self._in_title = False

    def _reject_open_json_ld(self) -> None:
        if self._capturing_json_ld:
            self.json_ld_rejected = True
            self._capturing_json_ld = False
            self._json_ld_parts = []
            self._json_ld_size = 0

    def _append_identity(self, collection: list[str], value: str) -> None:
        if value in collection:
            return
        if len(collection) >= 2:
            self.identity_rejected = True
            return
        collection.append(value)

    def _append_metadata(self, collection: list[str], value: str) -> None:
        if value in collection:
            return
        if len(collection) >= MAX_ANOMALI_CATEGORIES:
            self.metadata_rejected = True
            return
        collection.append(value)

    def _capture_meta(self, attributes: dict[str, str]) -> None:
        content = attributes.get("content")
        if content is None:
            return
        name = (attributes.get("name") or "").strip().lower()
        prop = (attributes.get("property") or "").strip().lower()
        itemprop = (attributes.get("itemprop") or "").strip().lower()
        if prop == "og:url":
            self._append_identity(self.og_urls, content)
        elif prop == "og:title" and self.og_title is None:
            self.og_title = content
        elif name == "description" and self.meta_description is None:
            self.meta_description = content
        elif prop == "og:description" and self.og_description is None:
            self.og_description = content
        elif (
            prop == "article:published_time"
            or name in {"date", "datepublished", "publish-date"}
            or itemprop == "datepublished"
        ) and self.article_published_time is None:
            self.article_published_time = content
        elif (
            prop == "article:modified_time" or itemprop == "datemodified"
        ) and self.article_modified_time is None:
            self.article_modified_time = content
        elif name == "author":
            if len(self.meta_authors) >= MAX_ANOMALI_AUTHORS:
                self.metadata_rejected = True
            else:
                self.meta_authors.append(content)
        elif prop in {"article:section", "article:tag"} or name in {
            "category",
            "keywords",
        }:
            self._append_metadata(self.meta_categories, content)


@dataclass(frozen=True, slots=True)
class _JsonLdMetadata:
    headline: str | None = None
    description: str | None = None
    published_at: str | None = None
    modified_at: str | None = None
    authors: tuple[str, ...] | None = None
    categories: tuple[str, ...] | None = None


class _UnsafeJsonLd(ValueError):
    pass


class _DuplicateJsonKey(ValueError):
    pass


class AnomaliPublicationsClient:
    """Fetch safe metadata from the fixed public Anomali blog listing."""

    def __init__(
        self,
        *,
        http_transport: httpx.BaseTransport | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not callable(monotonic_clock) or not callable(sleeper):
            raise AnomaliCollectorConfigurationError(
                "Anomali collector timing callables are invalid."
            )
        if http_transport is not None and not isinstance(
            http_transport,
            httpx.BaseTransport,
        ):
            raise AnomaliCollectorConfigurationError(
                "The Anomali collector transport is invalid."
            )
        try:
            self._http_client = httpx.Client(
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=False,
                headers={"User-Agent": USER_AGENT, "Accept": ACCEPT_HEADER},
                transport=http_transport,
                trust_env=False,
            )
            self._http_client.headers.pop("Accept-Encoding", None)
            self._http_client.headers.pop("Connection", None)
        except _SYSTEM_EXCEPTIONS:
            raise
        except Exception:
            raise AnomaliCollectorConfigurationError(
                "The Anomali collector could not be configured safely."
            ) from None
        self._clock = monotonic_clock
        self._sleeper = sleeper
        self._last_request_started: float | None = None
        self._last_clock_observed: float | None = None
        self._request_state_isolation_failed = False
        self._closed = False

    def fetch_publications(self, *, max_records: int = 5) -> AnomaliCollectionResult:
        """Collect bounded Cyber Watch metadata through the closed interface."""

        if self._closed:
            raise AnomaliCollectorConfigurationError(
                "The Anomali collector is closed."
            )
        if self._request_state_isolation_failed:
            raise AnomaliRequestStateIsolationError(
                "Anomali request-state isolation failed."
            )
        _validate_max_records(max_records)
        try:
            discovery_response = self._fetch_html(
                DISCOVERY_URL,
                request_kind="discovery",
            )
            parser = _DiscoveryParser(maximum=max_records)
            parser.feed(_decode_html(discovery_response))
            parser.close()
            if not parser.has_deterministic_main:
                raise AnomaliMetadataError(
                    "The Anomali discovery main content could not be identified."
                )
        except _SYSTEM_EXCEPTIONS:
            raise
        except AnomaliCollectorConfigurationError:
            raise
        except Exception:
            raise AnomaliDiscoveryCollectionError(
                "Anomali discovery collection failed."
            ) from None

        candidates: list[PublicationCandidate] = []
        failure_reasons: list[AnomaliFailureReason] = []
        for publication_url in parser.urls:
            try:
                response = self._fetch_html(
                    publication_url,
                    request_kind="publication",
                )
                candidates.append(_parse_publication_candidate(response))
            except _SYSTEM_EXCEPTIONS:
                raise
            except AnomaliRequestStateIsolationError:
                raise
            except AnomaliPacingError:
                raise
            except AnomaliCollectorError as exc:
                failure_reasons.append(_failure_reason(exc))
            except Exception:
                failure_reasons.append(AnomaliFailureReason.METADATA_REJECTED)

        return AnomaliCollectionResult(
            source_slug=ANOMALI_SOURCE_SLUG,
            candidates=tuple(candidates),
            failure_count=len(failure_reasons),
            failure_reasons=tuple(failure_reasons),
            discovered_approved_link_count=len(parser.urls),
            capped=parser.capped,
        )

    def _fetch_html(self, url: str, *, request_kind: str) -> _HtmlResponse:
        current_url = _validate_url(url, request_kind=request_kind)
        seen = {current_url}
        for redirect_count in range(MAX_REDIRECTS + 1):
            _validate_url(current_url, request_kind=request_kind)
            self._pace_request()
            if self._last_request_started is None:
                raise AnomaliPacingError("Anomali request pacing failed.")
            deadline = self._last_request_started + TOTAL_REQUEST_TIMEOUT_SECONDS
            self._isolate_request_state()
            try:
                remaining = self._remaining_request_duration(deadline)
                with self._http_client.stream(
                    "GET",
                    current_url,
                    follow_redirects=False,
                    timeout=_request_timeout(remaining),
                ) as response:
                    self._remaining_request_duration(deadline)
                    final_url = _validate_url(
                        str(response.url),
                        request_kind=request_kind,
                    )
                    if final_url != current_url:
                        raise AnomaliRedirectError(
                            "An Anomali response URL failed validation."
                        )
                    if response.status_code in REDIRECT_STATUS_CODES:
                        if redirect_count >= MAX_REDIRECTS:
                            raise AnomaliRedirectError(
                                "The Anomali redirect limit was exceeded."
                            )
                        target = _redirect_target(
                            response.headers.get("location"),
                            base_url=current_url,
                            request_kind=request_kind,
                        )
                        if target in seen:
                            raise AnomaliRedirectError(
                                "An Anomali redirect loop was rejected."
                            )
                        seen.add(target)
                        current_url = target
                        continue
                    if response.status_code == 429:
                        raise AnomaliRateLimitError(
                            "Anomali rate limited the collection request."
                        )
                    if not response.is_success:
                        raise AnomaliHttpError(
                            "Anomali returned an unsuccessful response."
                        )
                    content_type = _content_type(
                        response.headers.get("content-type")
                    )
                    if content_type not in ALLOWED_CONTENT_TYPES:
                        raise AnomaliContentTypeError(
                            "An Anomali response used an unsupported content type."
                        )
                    return _HtmlResponse(
                        body=_read_bounded(
                            response,
                            deadline_check=lambda: self._remaining_request_duration(
                                deadline
                            ),
                        ),
                        final_url=final_url,
                        encoding=response.encoding or "utf-8",
                    )
            except _SYSTEM_EXCEPTIONS:
                raise
            except AnomaliCollectorError:
                raise
            except httpx.InvalidURL:
                # HTTPX may reject a malformed Location while finalizing the
                # streamed response, before the explicit resolver sees it.
                raise AnomaliRedirectError(
                    "An Anomali redirect destination was rejected."
                ) from None
            except httpx.TimeoutException:
                raise AnomaliTimeoutError(
                    "An Anomali request timed out."
                ) from None
            except httpx.TransportError:
                raise AnomaliTransportError(
                    "An Anomali request failed during transport."
                ) from None
            except Exception:
                raise AnomaliTransportError(
                    "An Anomali request failed during transport."
                ) from None
            finally:
                self._clear_cookies_after_attempt(sys.exception())
        raise AnomaliRedirectError("The Anomali redirect limit was exceeded.")

    def _pace_request(self) -> None:
        now = self._read_clock()
        if self._last_request_started is not None:
            remaining = REQUEST_DELAY_SECONDS - (now - self._last_request_started)
            attempts = 0
            while remaining > 0 and attempts < 3:
                try:
                    self._sleeper(remaining)
                except _SYSTEM_EXCEPTIONS:
                    raise
                except Exception:
                    raise AnomaliPacingError(
                        "Anomali request pacing failed."
                    ) from None
                now = self._read_clock()
                remaining = REQUEST_DELAY_SECONDS - (
                    now - self._last_request_started
                )
                attempts += 1
            if remaining > 0:
                raise AnomaliPacingError("Anomali request pacing failed.")
        started = self._read_clock()
        if (
            self._last_request_started is not None
            and started - self._last_request_started < REQUEST_DELAY_SECONDS
        ):
            raise AnomaliPacingError("Anomali request pacing failed.")
        self._last_request_started = started

    def _read_clock(self) -> float:
        try:
            value = self._clock()
        except _SYSTEM_EXCEPTIONS:
            raise
        except Exception:
            raise AnomaliPacingError("Anomali request pacing failed.") from None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise AnomaliPacingError("Anomali request pacing failed.")
        result = float(value)
        if not math.isfinite(result):
            raise AnomaliPacingError("Anomali request pacing failed.")
        if self._last_clock_observed is not None and result < self._last_clock_observed:
            raise AnomaliPacingError("Anomali request pacing failed.")
        self._last_clock_observed = result
        return result

    def _remaining_request_duration(self, deadline: float) -> float:
        remaining = deadline - self._read_clock()
        if not math.isfinite(remaining) or remaining <= 0:
            raise AnomaliTimeoutError(
                "An Anomali request exceeded the total duration limit."
            )
        return remaining

    def _clear_cookies(self) -> None:
        try:
            self._http_client.cookies.clear()
        except _SYSTEM_EXCEPTIONS:
            raise
        except Exception:
            raise AnomaliTransportError(
                "The Anomali collector could not isolate request state safely."
            ) from None

    def _isolate_request_state(self) -> None:
        if self._request_state_isolation_failed:
            raise AnomaliRequestStateIsolationError(
                "Anomali request-state isolation failed."
            )
        try:
            self._clear_cookies()
        except _SYSTEM_EXCEPTIONS:
            self._request_state_isolation_failed = True
            raise
        except Exception:
            self._request_state_isolation_failed = True
            raise AnomaliRequestStateIsolationError(
                "Anomali request-state isolation failed."
            ) from None

    def _clear_cookies_after_attempt(
        self,
        active_exception: BaseException | None,
    ) -> None:
        try:
            self._isolate_request_state()
        except _SYSTEM_EXCEPTIONS:
            if isinstance(active_exception, _SYSTEM_EXCEPTIONS):
                return
            raise
        except AnomaliCollectorError:
            if isinstance(active_exception, _SYSTEM_EXCEPTIONS):
                return
            raise
        except Exception:
            if isinstance(active_exception, _SYSTEM_EXCEPTIONS):
                return
            raise AnomaliTransportError(
                "The Anomali collector could not isolate request state safely."
            ) from None

    def close(self) -> None:
        """Close the synchronous HTTP client owned by this collector."""

        if self._closed:
            return
        try:
            self._http_client.close()
        except _SYSTEM_EXCEPTIONS:
            raise
        except Exception:
            raise AnomaliTransportError(
                "The Anomali collector could not close safely."
            ) from None
        finally:
            self._closed = True

    def __enter__(self) -> AnomaliPublicationsClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        del exc_value, traceback
        try:
            self.close()
        except AnomaliTransportError:
            if exc_type is None:
                raise


def _validate_max_records(value: object) -> None:
    if type(value) is not int or not MIN_RECORDS <= value <= MAX_RECORDS:
        raise AnomaliCollectorConfigurationError(
            "The Anomali maximum record count is invalid."
        )


def _attributes(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    values: dict[str, str] = {}
    for name, value in attrs:
        normalized = name.lower()
        if normalized not in values and value is not None:
            values[normalized] = value
    return values


def _resolve_reference(
    reference: str,
    *,
    base_url: str,
    request_kind: str,
) -> str:
    if (
        not isinstance(reference, str)
        or not reference
        or len(reference) > MAX_URL_LENGTH
        or reference != reference.strip()
        or not reference.isascii()
        or not reference.isprintable()
        or any(character.isspace() for character in reference)
        or "\\" in reference
        or "%" in reference
        or "?" in reference
        or "#" in reference
        or ";" in reference
        or _MALFORMED_PERCENT_ESCAPE.search(reference)
        or reference.startswith("//")
    ):
        raise AnomaliRedirectError("An Anomali URL reference failed validation.")
    try:
        parsed = urlparse(reference)
    except (TypeError, ValueError):
        raise AnomaliRedirectError(
            "An Anomali URL reference failed validation."
        ) from None
    if (
        parsed.query
        or parsed.fragment
        or parsed.params
        or "@" in parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or "//" in parsed.path
        or any(segment in {".", ".."} for segment in parsed.path.split("/"))
    ):
        raise AnomaliRedirectError("An Anomali URL reference failed validation.")
    if parsed.scheme:
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            raise AnomaliRedirectError(
                "An Anomali URL reference failed validation."
            )
    elif parsed.netloc:
        raise AnomaliRedirectError("An Anomali URL reference failed validation.")
    try:
        target = urljoin(base_url, reference)
    except (TypeError, ValueError):
        raise AnomaliRedirectError(
            "An Anomali URL reference failed validation."
        ) from None
    return _validate_url(target, request_kind=request_kind)


def _validate_url(url: str, *, request_kind: str) -> str:
    if (
        not isinstance(url, str)
        or not url
        or len(url) > MAX_URL_LENGTH
        or "\\" in url
        or "%" in url
        or "?" in url
        or "#" in url
        or ";" in url
        or _MALFORMED_PERCENT_ESCAPE.search(url)
        or not url.isascii()
        or not url.isprintable()
        or any(character.isspace() for character in url)
    ):
        raise AnomaliRedirectError("An Anomali URL failed validation.")
    try:
        parsed = urlparse(url)
        port = parsed.port
        hostname = parsed.hostname or ""
    except (TypeError, ValueError):
        raise AnomaliRedirectError("An Anomali URL failed validation.") from None
    if parsed.scheme.lower() != "https":
        raise AnomaliRedirectError("An Anomali URL failed validation.")
    expected_netlocs = {
        ANOMALI_PUBLICATION_HOST,
        f"{ANOMALI_PUBLICATION_HOST}:443",
    }
    if (
        hostname.lower() != ANOMALI_PUBLICATION_HOST
        or hostname.endswith(".")
        or parsed.netloc.lower() not in expected_netlocs
    ):
        raise AnomaliRedirectError("An Anomali URL failed validation.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise AnomaliRedirectError("An Anomali URL failed validation.")
    if (
        "@" in parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or parsed.params
    ):
        raise AnomaliRedirectError("An Anomali URL failed validation.")
    path = parsed.path
    if (
        not path.startswith("/")
        or "%" in path
        or ";" in path
        or "//" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        raise AnomaliRedirectError("An Anomali URL failed validation.")
    if request_kind == "discovery":
        if path != DISCOVERY_PATH:
            raise AnomaliRedirectError(
                "The Anomali discovery URL failed validation."
            )
        canonical_path = DISCOVERY_PATH
    elif request_kind == "publication":
        canonical_path = path[:-1] if path.endswith("/") else path
        suffix = (
            canonical_path[len(ANOMALI_PATH_PREFIX) :]
            if canonical_path.startswith(ANOMALI_PATH_PREFIX)
            else ""
        )
        if not suffix or "/" in suffix or _ARTICLE_SLUG.fullmatch(suffix) is None:
            raise AnomaliRedirectError(
                "The Anomali publication URL failed validation."
            )
    else:
        raise AnomaliRedirectError("An Anomali URL failed validation.")
    return urlunparse(
        ("https", ANOMALI_PUBLICATION_HOST, canonical_path, "", "", "")
    )


def _redirect_target(
    location: str | None,
    *,
    base_url: str,
    request_kind: str,
) -> str:
    if location is None:
        raise AnomaliRedirectError(
            "An Anomali redirect destination was rejected."
        )
    return _resolve_reference(
        location,
        base_url=base_url,
        request_kind=request_kind,
    )


def _content_type(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    return value.split(";", 1)[0].strip().lower() or None


def _request_timeout(remaining: float) -> httpx.Timeout:
    bounded = min(TOTAL_REQUEST_TIMEOUT_SECONDS, remaining)
    return httpx.Timeout(
        bounded,
        connect=min(5.0, bounded),
        read=min(10.0, bounded),
        write=min(5.0, bounded),
        pool=min(5.0, bounded),
    )


def _read_bounded(
    response: httpx.Response,
    *,
    deadline_check: Callable[[], float],
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        deadline_check()
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise AnomaliResponseTooLargeError(
                "An Anomali response exceeded the allowed size."
            )
        chunks.append(chunk)
        deadline_check()
    deadline_check()
    return b"".join(chunks)


def _decode_html(response: _HtmlResponse) -> str:
    try:
        return response.body.decode(response.encoding, errors="strict")
    except (LookupError, UnicodeError):
        raise AnomaliMetadataError(
            "Anomali HTML metadata could not be decoded safely."
        ) from None


def _is_json_ld_media_type(value: str | None) -> bool:
    if not isinstance(value, str):
        return False
    return value.split(";", 1)[0].strip().lower() == "application/ld+json"


def _parse_publication_candidate(response: _HtmlResponse) -> PublicationCandidate:
    try:
        parser = _PublicationMetadataParser()
        parser.feed(_decode_html(response))
        parser.close()
        if (
            parser.json_ld_rejected
            or parser.identity_rejected
            or parser.metadata_rejected
        ):
            raise AnomaliMetadataError(
                "Anomali publication metadata exceeded a safe bound."
            )
        declared_identities = parser.canonical_hrefs + parser.og_urls
        identities = {
            _resolve_reference(
                identity,
                base_url=response.final_url,
                request_kind="publication",
            )
            for identity in declared_identities
        }
        if len(identities) > 1 or (
            identities and identities != {response.final_url}
        ):
            raise AnomaliMetadataError(
                "Anomali publication identities conflicted."
            )
        json_ld = _select_json_ld_metadata(
            parser.json_ld_blocks,
            canonical_url=response.final_url,
        )
        title = json_ld.headline or parser.og_title or parser.document_title
        summary = (
            json_ld.description
            or parser.meta_description
            or parser.og_description
            or None
        )
        published_at = json_ld.published_at or parser.article_published_time
        modified_at = json_ld.modified_at or parser.article_modified_time or None
        authors = list(
            json_ld.authors
            if json_ld.authors is not None
            else parser.meta_authors
        )
        categories = list(
            json_ld.categories
            if json_ld.categories is not None
            else parser.meta_categories
        )
        if title is None or published_at is None:
            raise AnomaliMetadataError(
                "Anomali publication metadata could not be normalized safely."
            )
        _validate_untrusted_metadata(
            title=title,
            summary=summary,
            authors=authors,
            categories=categories,
        )
        return adapt_anomali_publication(
            {
                "title": title,
                "url": response.final_url,
                "summary": summary,
                "published_at": published_at,
                "modified_at": modified_at,
                "authors": authors,
                "categories": categories,
            }
        )
    except _SYSTEM_EXCEPTIONS:
        raise
    except AnomaliMetadataError:
        raise
    except (
        AnomaliPublicationRecordError,
        AnomaliRedirectError,
        AssertionError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        raise AnomaliMetadataError(
            "Anomali publication metadata could not be normalized safely."
        ) from None


def _select_json_ld_metadata(
    blocks: list[str],
    *,
    canonical_url: str,
) -> _JsonLdMetadata:
    publications: list[dict[str, object]] = []
    for block in blocks:
        if not block.strip():
            raise AnomaliMetadataError(
                "Anomali JSON-LD metadata was rejected safely."
            )
        try:
            payload = json.loads(
                block,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
            _validate_json_ld_shape(payload)
        except _SYSTEM_EXCEPTIONS:
            raise
        except (
            json.JSONDecodeError,
            _DuplicateJsonKey,
            _UnsafeJsonLd,
            RecursionError,
            TypeError,
            ValueError,
        ):
            raise AnomaliMetadataError(
                "Anomali JSON-LD metadata was rejected safely."
            ) from None
        publications.extend(_publication_objects(payload))

    if not publications:
        return _JsonLdMetadata()

    matching: list[dict[str, object]] = []
    identity_free: list[dict[str, object]] = []
    for publication in publications:
        identity, declared, valid = _json_ld_identity(publication)
        if valid and identity == canonical_url:
            matching.append(publication)
        elif valid and not declared:
            identity_free.append(publication)

    if len(matching) == 1:
        return _json_ld_metadata(matching[0])
    if len(publications) == 1 and len(identity_free) == 1:
        return _json_ld_metadata(identity_free[0])
    raise AnomaliMetadataError(
        "Anomali JSON-LD publication metadata was ambiguous."
    )


def _json_ld_identity(
    publication: dict[str, object],
) -> tuple[str | None, bool, bool]:
    raw_identities: list[object] = []
    declared = False
    if "url" in publication:
        declared = True
        raw_identities.append(publication["url"])
    if "mainEntityOfPage" in publication:
        declared = True
        main_entity = publication["mainEntityOfPage"]
        if isinstance(main_entity, dict):
            if "@id" not in main_entity:
                return None, declared, False
            raw_identities.append(main_entity["@id"])
        else:
            raw_identities.append(main_entity)
    if declared and not raw_identities:
        return None, declared, False
    validated: set[str] = set()
    for raw_identity in raw_identities:
        if not isinstance(raw_identity, str):
            return None, declared, False
        try:
            validated.add(
                _resolve_reference(
                    raw_identity,
                    base_url=DISCOVERY_LINK_RESOLUTION_BASE,
                    request_kind="publication",
                )
            )
        except AnomaliRedirectError:
            return None, declared, False
    if len(validated) == 1:
        return next(iter(validated)), declared, True
    if not declared:
        return None, False, True
    return None, declared, False


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    del value
    raise _UnsafeJsonLd


def _validate_json_ld_shape(payload: object) -> None:
    nodes = 0

    def walk(value: object, depth: int) -> None:
        nonlocal nodes
        if depth > MAX_JSON_LD_DEPTH:
            raise _UnsafeJsonLd
        nodes += 1
        if nodes > MAX_JSON_LD_NODES:
            raise _UnsafeJsonLd
        if isinstance(value, dict):
            for key, member in value.items():
                if len(key) > MAX_JSON_LD_STRING_LENGTH:
                    raise _UnsafeJsonLd
                walk(member, depth + 1)
        elif isinstance(value, list):
            for member in value:
                walk(member, depth + 1)
        elif isinstance(value, str):
            if len(value) > MAX_JSON_LD_STRING_LENGTH:
                raise _UnsafeJsonLd
        elif value is not None and not isinstance(value, (bool, int, float)):
            raise _UnsafeJsonLd
        elif isinstance(value, float) and not math.isfinite(value):
            raise _UnsafeJsonLd

    walk(payload, 0)


def _publication_objects(payload: object):
    roots = payload if isinstance(payload, list) else [payload]
    for root in roots:
        if not isinstance(root, dict):
            continue
        if _supported_publication_type(root.get("@type")):
            yield root
        graph = root.get("@graph")
        if isinstance(graph, list):
            for member in graph:
                if isinstance(member, dict) and _supported_publication_type(
                    member.get("@type")
                ):
                    yield member


def _supported_publication_type(value: object) -> bool:
    allowed = {"Article", "BlogPosting", "NewsArticle", "TechArticle"}
    if isinstance(value, str):
        return value in allowed
    return isinstance(value, list) and any(
        isinstance(member, str) and member in allowed for member in value
    )


def _json_ld_metadata(value: dict[str, object]) -> _JsonLdMetadata:
    return _JsonLdMetadata(
        headline=_bounded_metadata_string(value.get("headline")),
        description=_bounded_metadata_string(value.get("description")),
        published_at=_bounded_metadata_string(
            value.get("datePublished"),
            maximum=MAX_TIMESTAMP_LENGTH,
        ),
        modified_at=_bounded_metadata_string(
            value.get("dateModified"),
            maximum=MAX_TIMESTAMP_LENGTH,
        ),
        authors=_json_ld_authors(value.get("author")),
        categories=_json_ld_categories(value),
    )


def _bounded_metadata_string(
    value: object,
    *,
    maximum: int = MAX_JSON_LD_STRING_LENGTH,
) -> str | None:
    if not isinstance(value, str) or not value.isprintable():
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        return None
    return normalized


def _validate_untrusted_metadata(
    *,
    title: object,
    summary: object,
    authors: Sequence[object],
    categories: Sequence[object],
) -> None:
    for value in (title, summary, *authors, *categories):
        if value is None:
            continue
        if not isinstance(value, str) or len(value) > MAX_JSON_LD_STRING_LENGTH:
            raise AnomaliMetadataError(
                "Anomali publication metadata could not be normalized safely."
            )
        normalized = _normalize_metadata_for_indicator_check(value)
        detection_value = _normalize_indicator_defanging(normalized)
        if _contains_untrusted_indicator(detection_value):
            raise AnomaliMetadataError(
                "Anomali publication metadata contained a disallowed value."
            )


def _normalize_metadata_for_indicator_check(value: str) -> str:
    try:
        current = unicodedata.normalize("NFKC", value)
        for _ in range(MAX_ANOMALI_ENTITY_DECODE_PASSES):
            decoded = unescape(current)
            if len(decoded) > MAX_JSON_LD_STRING_LENGTH:
                raise AnomaliMetadataError(
                    "Anomali publication metadata could not be normalized safely."
                )
            if decoded == current:
                return current
            current = decoded
        if unescape(current) != current:
            raise AnomaliMetadataError(
                "Anomali publication metadata could not be normalized safely."
            )
        return current
    except _SYSTEM_EXCEPTIONS:
        raise
    except AnomaliMetadataError:
        raise
    except (TypeError, ValueError, UnicodeError):
        raise AnomaliMetadataError(
            "Anomali publication metadata could not be normalized safely."
        ) from None


def _contains_untrusted_indicator(value: str) -> bool:
    lowered = value.lower()
    if (
        "http://" in lowered
        or "https://" in lowered
        or "hxxp://" in lowered
        or "hxxps://" in lowered
    ):
        return True
    if _contains_common_hex_digest(value):
        return True
    if _contains_ip_address(value):
        return True
    return _contains_domain_like_hostname(value)


def _normalize_indicator_defanging(value: str) -> str:
    closing_delimiters = {"[": "]", "(": ")", "{": "}"}
    replacements = {
        ".": ".",
        "dot": ".",
        ":": ":",
        "colon": ":",
        "://": "://",
    }
    normalized: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        closing = closing_delimiters.get(character)
        if closing is not None:
            search_end = min(len(value), index + _MAX_DEFANG_TOKEN_CHARS)
            closing_index = value.find(closing, index + 1, search_end)
            if closing_index >= 0:
                inner = "".join(
                    member
                    for member in value[index + 1 : closing_index]
                    if not member.isspace()
                ).lower()
                replacement = replacements.get(inner)
                if replacement is not None:
                    normalized.append(replacement)
                    index = closing_index + 1
                    continue
        normalized.append(character)
        index += 1
    return "".join(normalized)


def _bounded_tokens(value: str, allowed: frozenset[str]) -> Iterator[str]:
    start: int | None = None
    for index, character in enumerate(value):
        if character in allowed:
            if start is None:
                start = index
        elif start is not None:
            yield value[start:index]
            start = None
    if start is not None:
        yield value[start:]


def _contains_common_hex_digest(value: str) -> bool:
    for token in _bounded_tokens(value, _ASCII_ALPHANUMERIC):
        if len(token) in _COMMON_HEX_DIGEST_LENGTHS and all(
            character in "0123456789abcdefABCDEF" for character in token
        ):
            return True
    return False


def _contains_ip_address(value: str) -> bool:
    for token in _bounded_tokens(value, _IP_CANDIDATE_CHARACTERS):
        candidate = token.strip("[].")
        opening_bracket = token.find("[")
        closing_bracket = token.find("]", opening_bracket + 1)
        if opening_bracket >= 0 and closing_bracket > opening_bracket:
            bracketed = token[opening_bracket + 1 : closing_bracket]
            try:
                if isinstance(ipaddress.ip_address(bracketed), ipaddress.IPv6Address):
                    return True
            except ValueError:
                pass
        for dotted_candidate in candidate.split(":"):
            if "." not in dotted_candidate:
                continue
            try:
                if isinstance(
                    ipaddress.ip_address(dotted_candidate.strip(".")),
                    ipaddress.IPv4Address,
                ):
                    return True
            except ValueError:
                pass
        candidates = [candidate]
        if ":" in candidate:
            candidates.append(candidate.split(":", 1)[1])
        for possible_address in candidates:
            if "." not in possible_address and ":" not in possible_address:
                continue
            try:
                ipaddress.ip_address(possible_address)
            except ValueError:
                continue
            return True
    return False


def _contains_domain_like_hostname(value: str) -> bool:
    for token in _hostname_tokens(value):
        candidate = token.strip(".")
        if not candidate or len(candidate) > 253:
            continue
        try:
            ascii_candidate = candidate.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            continue
        if len(ascii_candidate) > 253:
            continue
        labels = ascii_candidate.split(".")
        if len(labels) < 2:
            continue
        final_label = labels[-1]
        if (
            2 <= len(final_label) <= 63
            and (
                final_label.isalpha()
                or final_label.startswith("xn--")
            )
            and all(_is_hostname_label(label) for label in labels)
            and all(_is_valid_idna_label(label) for label in labels)
        ):
            return True
    return False


def _hostname_tokens(value: str) -> Iterator[str]:
    start: int | None = None
    for index, character in enumerate(value):
        category = unicodedata.category(character)
        is_hostname_character = (
            character in {"-", "."}
            or character.isalnum()
            or category.startswith("M")
        )
        if is_hostname_character:
            if start is None:
                start = index
        elif start is not None:
            yield value[start:index]
            start = None
    if start is not None:
        yield value[start:]


def _is_hostname_label(value: str) -> bool:
    return (
        1 <= len(value) <= 63
        and value[0].isalnum()
        and value[-1].isalnum()
        and all(
            character in _ASCII_ALPHANUMERIC or character == "-"
            for character in value
        )
    )


def _is_valid_idna_label(value: str) -> bool:
    if not value.startswith("xn--"):
        return True
    try:
        decoded = value.encode("ascii").decode("idna")
        return decoded.encode("idna").decode("ascii").lower() == value
    except (UnicodeError, UnicodeDecodeError):
        return False


def _json_ld_authors(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    members = value if isinstance(value, list) else [value]
    if len(members) > MAX_ANOMALI_AUTHORS:
        raise _UnsafeJsonLd
    authors: list[str] = []
    for member in members:
        raw_name = member.get("name") if isinstance(member, dict) else member
        name = _bounded_metadata_string(
            raw_name,
            maximum=MAX_ANOMALI_AUTHOR_LENGTH,
        )
        if name is None:
            raise _UnsafeJsonLd
        if name not in authors:
            authors.append(name)
    return tuple(authors)


def _json_ld_categories(value: dict[str, object]) -> tuple[str, ...] | None:
    raw_values: list[object] = []
    for key in ("articleSection", "keywords"):
        if key not in value:
            continue
        member = value[key]
        raw_values.extend(member if isinstance(member, list) else [member])
    if not raw_values:
        return None
    if len(raw_values) > MAX_ANOMALI_CATEGORIES:
        raise _UnsafeJsonLd
    categories: list[str] = []
    for raw_value in raw_values:
        category = _bounded_metadata_string(
            raw_value,
            maximum=MAX_ANOMALI_CATEGORY_LENGTH,
        )
        if category is None:
            raise _UnsafeJsonLd
        if category not in categories:
            categories.append(category)
    return tuple(categories)


def _failure_reason(error: AnomaliCollectorError) -> AnomaliFailureReason:
    if isinstance(error, AnomaliTimeoutError):
        return AnomaliFailureReason.TIMEOUT
    if isinstance(error, AnomaliTransportError):
        return AnomaliFailureReason.TRANSPORT_FAILURE
    if isinstance(error, AnomaliRateLimitError):
        return AnomaliFailureReason.RATE_LIMITED
    if isinstance(error, AnomaliHttpError):
        return AnomaliFailureReason.HTTP_FAILURE
    if isinstance(error, AnomaliRedirectError):
        return AnomaliFailureReason.REDIRECT_REJECTED
    if isinstance(error, AnomaliContentTypeError):
        return AnomaliFailureReason.CONTENT_TYPE_REJECTED
    if isinstance(error, AnomaliResponseTooLargeError):
        return AnomaliFailureReason.RESPONSE_TOO_LARGE
    return AnomaliFailureReason.METADATA_REJECTED
