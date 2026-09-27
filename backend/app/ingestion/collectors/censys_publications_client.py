"""Secure synchronous collector for fixed public Censys publication pages."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from html.parser import HTMLParser
import ipaddress
import json
import math
import re
import time
from types import MappingProxyType
from typing import Callable
from urllib.parse import urlparse, urlunparse

import httpx

from app.ingestion.adapters.censys_publications import (
    CENSYS_ARC_RESEARCH_SLUG,
    CENSYS_RAPID_RESPONSE_SLUG,
    CensysPublicationRecordError,
    adapt_censys_publication,
)
from app.ingestion.publication_pipeline import PublicationCandidate


DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=5.0, read=10.0, write=5.0, pool=5.0)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
MIN_RECORDS = 1
MAX_RECORDS = 20
REQUEST_DELAY_SECONDS = 10.0
USER_AGENT = "CyberSentinelOSINT/1.0 (+defensive-censys-publications)"
ACCEPT_HEADER = "text/html, application/xhtml+xml;q=0.9"
ALLOWED_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

MAX_JSON_LD_BLOCKS = 10
MAX_JSON_LD_BLOCK_CHARS = 64 * 1024
MAX_JSON_LD_DEPTH = 8
MAX_JSON_LD_NODES = 1_000
MAX_JSON_LD_STRING_LENGTH = 10_000
MAX_JSON_LD_AUTHORS = 20
MAX_JSON_LD_AUTHOR_NAME_LENGTH = 200
MAX_TIMESTAMP_LENGTH = 64
MAX_URL_LENGTH = 2_048

_MALFORMED_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ATTRIBUTE_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_PUBLICATION_SLUG = re.compile(r"^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$")
_RESERVED_PUBLICATION_SLUGS = frozenset(
    {"archive", "author", "category", "feed", "page", "pagination", "search", "tag"}
)


class CensysPublicationSource(str, Enum):
    """Closed selectors for the two approved Censys publication families."""

    ARC = "arc"
    RAPID_RESPONSE = "rapid-response"


@dataclass(frozen=True, slots=True)
class _SourcePolicy:
    discovery_url: str
    discovery_path: str
    publication_prefix: str
    source_slug: str
    category: str


SOURCE_POLICIES = MappingProxyType(
    {
        CensysPublicationSource.ARC: _SourcePolicy(
            discovery_url="https://censys.com/censys-arc/security-research/",
            discovery_path="/censys-arc/security-research/",
            publication_prefix="/blog/",
            source_slug=CENSYS_ARC_RESEARCH_SLUG,
            category="Censys ARC Research",
        ),
        CensysPublicationSource.RAPID_RESPONSE: _SourcePolicy(
            discovery_url="https://censys.com/censys-arc/rapid-response-advisories/",
            discovery_path="/censys-arc/rapid-response-advisories/",
            publication_prefix="/advisory/",
            source_slug=CENSYS_RAPID_RESPONSE_SLUG,
            category="Rapid Response",
        ),
    }
)


class CensysFailureReason(str, Enum):
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
class CensysCollectionResult:
    """Safe collector output with no raw response or exception material."""

    source: CensysPublicationSource
    source_slug: str
    candidates: tuple[PublicationCandidate, ...]
    failure_count: int
    failure_reasons: tuple[CensysFailureReason, ...]
    discovered_approved_link_count: int
    capped: bool


class CensysCollectorError(Exception):
    """Base class for sanitized Censys collection failures."""


class CensysCollectorConfigurationError(CensysCollectorError, ValueError):
    """The closed collector interface received an invalid argument."""


class CensysDiscoveryCollectionError(CensysCollectorError):
    """The mandatory fixed discovery page could not be collected safely."""


class CensysTransportError(CensysCollectorError):
    """A request failed during transport."""


class CensysTimeoutError(CensysTransportError):
    """A request exceeded a configured timeout."""


class CensysRateLimitError(CensysCollectorError):
    """Censys returned HTTP 429."""


class CensysHttpError(CensysCollectorError):
    """Censys returned another unsuccessful HTTP status."""


class CensysRedirectError(CensysCollectorError):
    """A redirect was missing, malformed, looping, or outside policy."""


class CensysContentTypeError(CensysCollectorError):
    """A response did not identify approved HTML content."""


class CensysResponseTooLargeError(CensysCollectorError):
    """A streamed response exceeded its independent two-MiB ceiling."""


class CensysMetadataError(CensysCollectorError):
    """Discovery or publication metadata failed deterministic validation."""


class CensysPacingError(CensysCollectorError):
    """The injected clock or sleeper could not enforce safe pacing."""


@dataclass(frozen=True, slots=True)
class _HtmlResponse:
    body: bytes
    final_url: str
    encoding: str


@dataclass(frozen=True, slots=True)
class _ElementState:
    tag: str
    in_main: bool
    in_excluded: bool
    in_listing: bool
    in_entry: bool
    begins_entry: bool


class _DiscoveryParser(HTMLParser):
    """Collect links only from a source-marked listing inside ``main``.

    The trusted region must be a section/div/list whose id, class, aria-label,
    data-section, data-testid, or explicit ``data-censys-listing`` value names
    ARC security research or rapid-response advisories. Inside that region, a
    link must belong to an article, list item, or explicitly card/item-marked
    container. Each entry is accepted only when all of its approved anchors
    resolve to one unique publication URL; ambiguous entries are skipped.
    Navigation, header, footer, aside, and form subtrees are excluded. There is
    deliberately no whole-document matching fallback.
    """

    _REGION_TAGS = frozenset({"section", "div", "ul", "ol"})
    _EXCLUDED_TAGS = frozenset({"nav", "header", "footer", "aside", "form"})

    def __init__(
        self,
        *,
        source: CensysPublicationSource,
        policy: _SourcePolicy,
        maximum: int,
    ) -> None:
        super().__init__(convert_charrefs=True)
        self._source = source
        self._policy = policy
        self._maximum = maximum
        self._stack: list[_ElementState] = []
        self._seen: set[str] = set()
        self._entry_urls: dict[str, None] | None = None
        self.urls: list[str] = []
        self.capped = False
        self.found_trusted_region = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        tag = tag.lower()
        attributes = _attributes(attrs)
        parent = self._stack[-1] if self._stack else None
        in_main = tag == "main" or bool(parent and parent.in_main)
        in_excluded = tag in self._EXCLUDED_TAGS or bool(
            parent and parent.in_excluded
        )
        begins_listing = (
            in_main
            and not in_excluded
            and tag in self._REGION_TAGS
            and _is_source_listing_region(self._source, attributes)
        )
        in_listing = begins_listing or bool(parent and parent.in_listing)
        if begins_listing:
            self.found_trusted_region = True
        begins_entry = (
            in_listing
            and not in_excluded
            and not bool(parent and parent.in_entry)
            and _is_publication_entry(tag, attributes)
        )
        in_entry = begins_entry or bool(parent and parent.in_entry)
        state = _ElementState(
            tag=tag,
            in_main=in_main,
            in_excluded=in_excluded,
            in_listing=in_listing,
            in_entry=in_entry,
            begins_entry=begins_entry,
        )
        self._stack.append(state)
        if begins_entry:
            self._entry_urls = {}
        if tag == "a" and in_entry and not in_excluded:
            self._consider_href(attributes.get("href"))

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
                if any(state.begins_entry for state in self._stack[index:]):
                    self._finish_entry()
                del self._stack[index:]
                return

    def _consider_href(self, href: str | None) -> None:
        if self.capped or self._entry_urls is None or href is None:
            return
        try:
            canonical = _resolve_reference(
                href,
                policy=self._policy,
                request_kind="publication",
            )
        except (CensysRedirectError, TypeError, ValueError):
            return
        if canonical in self._entry_urls:
            return
        # Two distinct approved URLs already prove ambiguity; retaining more
        # provides no decision value and would make memory depend on card size.
        if len(self._entry_urls) < 2:
            self._entry_urls[canonical] = None

    def _finish_entry(self) -> None:
        entry_urls = self._entry_urls
        self._entry_urls = None
        if self.capped or entry_urls is None or len(entry_urls) != 1:
            return
        canonical = next(iter(entry_urls))
        if canonical in self._seen:
            return
        if len(self.urls) < self._maximum:
            self._seen.add(canonical)
            self.urls.append(canonical)
        else:
            # One extra unique approved link is enough to report capping. Stop
            # retaining or validating further anchors so parser memory remains
            # tied to max_records instead of link count within the two-MiB page.
            self.capped = True


class _PublicationMetadataParser(HTMLParser):
    """Extract only bounded head metadata and JSON-LD script text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[str] = []
        self._title_parts: list[str] = []
        self._in_title = False
        self._capturing_json_ld = False
        self._json_ld_parts: list[str] = []
        self._json_ld_size = 0
        self._json_ld_oversized = False
        self._json_ld_blocks_encountered = 0
        self.json_ld_blocks: list[str] = []
        self.canonical_href: str | None = None
        self.og_title: str | None = None
        self.meta_description: str | None = None
        self.og_description: str | None = None
        self.article_published_time: str | None = None
        self.article_modified_time: str | None = None
        self.meta_authors: list[str] = []

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
        in_head = "head" in self._stack or tag == "head"
        self._stack.append(tag)
        if tag == "title" and in_head:
            self._in_title = True
        elif tag == "script" and _is_json_ld_media_type(attributes.get("type")):
            self._json_ld_blocks_encountered += 1
            self._capturing_json_ld = (
                self._json_ld_blocks_encountered <= MAX_JSON_LD_BLOCKS
            )
            self._json_ld_parts = []
            self._json_ld_size = 0
            self._json_ld_oversized = False
        elif tag == "link" and in_head and self.canonical_href is None:
            rel_tokens = (attributes.get("rel") or "").lower().split()
            if "canonical" in rel_tokens and attributes.get("href"):
                self.canonical_href = attributes["href"]
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
        if tag == "script" and self._capturing_json_ld:
            if not self._json_ld_oversized:
                self.json_ld_blocks.append("".join(self._json_ld_parts))
            self._capturing_json_ld = False
            self._json_ld_parts = []
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index] == tag:
                del self._stack[index:]
                return

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)
        if self._capturing_json_ld and not self._json_ld_oversized:
            self._json_ld_size += len(data)
            if self._json_ld_size > MAX_JSON_LD_BLOCK_CHARS:
                self._json_ld_oversized = True
                self._json_ld_parts = []
            else:
                self._json_ld_parts.append(data)

    def _capture_meta(self, attributes: dict[str, str]) -> None:
        content = attributes.get("content")
        if content is None:
            return
        name = (attributes.get("name") or "").strip().lower()
        prop = (attributes.get("property") or "").strip().lower()
        if prop == "og:title" and self.og_title is None:
            self.og_title = content
        elif name == "description" and self.meta_description is None:
            self.meta_description = content
        elif prop == "og:description" and self.og_description is None:
            self.og_description = content
        elif prop == "article:published_time" and self.article_published_time is None:
            self.article_published_time = content
        elif prop == "article:modified_time" and self.article_modified_time is None:
            self.article_modified_time = content
        elif name == "author" and len(self.meta_authors) < MAX_JSON_LD_AUTHORS:
            self.meta_authors.append(content)


@dataclass(frozen=True, slots=True)
class _JsonLdMetadata:
    headline: str | None = None
    description: str | None = None
    published_at: str | None = None
    modified_at: str | None = None
    authors: tuple[str, ...] | None = None


class _UnsafeJsonLd(ValueError):
    pass


class _DuplicateJsonKey(ValueError):
    pass


class CensysPublicationsClient:
    """Fetch and normalize metadata from the two fixed Censys listings."""

    def __init__(
        self,
        *,
        http_transport: httpx.BaseTransport | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not callable(monotonic_clock) or not callable(sleeper):
            raise CensysCollectorConfigurationError(
                "Censys collector timing callables are invalid."
            )
        if http_transport is not None and not isinstance(
            http_transport,
            httpx.BaseTransport,
        ):
            raise CensysCollectorConfigurationError(
                "The Censys collector transport is invalid."
            )
        self._http_client = httpx.Client(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": ACCEPT_HEADER},
            transport=http_transport,
            trust_env=False,
        )
        # httpx adds these convenience defaults even when explicit headers are
        # supplied. Keep collector-level defaults limited to the two reviewed
        # defensive headers; protocol-required Host handling remains internal.
        self._http_client.headers.pop("Accept-Encoding", None)
        self._http_client.headers.pop("Connection", None)
        self._clock = monotonic_clock
        self._sleeper = sleeper
        self._last_request_started: float | None = None
        self._closed = False

    def fetch_publications(
        self,
        source: CensysPublicationSource,
        max_records: int = 5,
    ) -> CensysCollectionResult:
        """Collect bounded metadata from one closed Censys source selector."""

        if self._closed:
            raise CensysCollectorConfigurationError(
                "The Censys collector is closed."
            )
        policy = _require_policy(source)
        _validate_max_records(max_records)
        try:
            discovery_response = self._fetch_html(
                policy.discovery_url,
                policy=policy,
                request_kind="discovery",
            )
            discovery_text = _decode_html(discovery_response)
            parser = _DiscoveryParser(
                source=source,
                policy=policy,
                maximum=max_records,
            )
            parser.feed(discovery_text)
            parser.close()
            if not parser.found_trusted_region:
                raise CensysMetadataError(
                    "The Censys discovery listing could not be identified."
                )
        except CensysCollectorConfigurationError:
            raise
        except (
            CensysCollectorError,
            AssertionError,
            RecursionError,
            UnicodeError,
            ValueError,
        ):
            raise CensysDiscoveryCollectionError(
                "Censys discovery collection failed."
            ) from None

        candidates: list[PublicationCandidate] = []
        failure_reasons: list[CensysFailureReason] = []
        for publication_url in parser.urls:
            try:
                response = self._fetch_html(
                    publication_url,
                    policy=policy,
                    request_kind="publication",
                )
                candidate = _parse_publication_candidate(response, policy=policy)
            except CensysPacingError:
                # A broken clock/sleeper is collector-wide, not a page-local
                # problem. Abort rather than attempting later requests without
                # a trustworthy ten-second interval.
                raise
            except CensysCollectorError as exc:
                failure_reasons.append(_failure_reason(exc))
                continue
            except (UnicodeError, ValueError):
                failure_reasons.append(CensysFailureReason.METADATA_REJECTED)
                continue
            candidates.append(candidate)

        return CensysCollectionResult(
            source=source,
            source_slug=policy.source_slug,
            candidates=tuple(candidates),
            failure_count=len(failure_reasons),
            failure_reasons=tuple(failure_reasons),
            discovered_approved_link_count=len(parser.urls),
            capped=parser.capped,
        )

    def _fetch_html(
        self,
        url: str,
        *,
        policy: _SourcePolicy,
        request_kind: str,
    ) -> _HtmlResponse:
        current_url = _validate_url(url, policy=policy, request_kind=request_kind)
        seen = {current_url}
        for redirect_count in range(MAX_REDIRECTS + 1):
            _validate_url(current_url, policy=policy, request_kind=request_kind)
            self._pace_request()
            try:
                with self._http_client.stream(
                    "GET",
                    current_url,
                    follow_redirects=False,
                ) as response:
                    final_url = _validate_url(
                        str(response.url),
                        policy=policy,
                        request_kind=request_kind,
                    )
                    if final_url != current_url:
                        raise CensysRedirectError(
                            "A Censys response URL failed validation."
                        )
                    if response.status_code in REDIRECT_STATUS_CODES:
                        if redirect_count >= MAX_REDIRECTS:
                            raise CensysRedirectError(
                                "The Censys redirect limit was exceeded."
                            )
                        target = _redirect_target(
                            response.headers.get("location"),
                            policy=policy,
                            request_kind=request_kind,
                        )
                        if target in seen:
                            raise CensysRedirectError(
                                "A Censys redirect loop was rejected."
                            )
                        seen.add(target)
                        current_url = target
                        continue
                    if response.status_code == 429:
                        raise CensysRateLimitError(
                            "Censys rate limited the collection request."
                        )
                    if not response.is_success:
                        raise CensysHttpError(
                            "Censys returned an unsuccessful response."
                        )
                    content_type = _content_type(response.headers.get("content-type"))
                    if content_type not in ALLOWED_CONTENT_TYPES:
                        raise CensysContentTypeError(
                            "A Censys response used an unsupported content type."
                        )
                    body = _read_bounded(response)
                    return _HtmlResponse(
                        body=body,
                        final_url=final_url,
                        encoding=response.encoding or "utf-8",
                    )
            except CensysCollectorError:
                raise
            except httpx.TimeoutException:
                raise CensysTimeoutError("A Censys request timed out.") from None
            except httpx.TransportError:
                raise CensysTransportError(
                    "A Censys request failed during transport."
                ) from None
            except MemoryError:
                raise
            except Exception:
                raise CensysTransportError(
                    "A Censys request failed during transport."
                ) from None
        raise CensysRedirectError("The Censys redirect limit was exceeded.")

    def _pace_request(self) -> None:
        now = self._read_clock()
        if self._last_request_started is not None:
            remaining = REQUEST_DELAY_SECONDS - (now - self._last_request_started)
            attempts = 0
            while remaining > 0 and attempts < 3:
                try:
                    self._sleeper(remaining)
                except MemoryError:
                    raise
                except Exception:
                    raise CensysPacingError("Censys request pacing failed.") from None
                now = self._read_clock()
                remaining = REQUEST_DELAY_SECONDS - (
                    now - self._last_request_started
                )
                attempts += 1
            if remaining > 0:
                raise CensysPacingError("Censys request pacing failed.")
        start = self._read_clock()
        if (
            self._last_request_started is not None
            and start - self._last_request_started < REQUEST_DELAY_SECONDS
        ):
            raise CensysPacingError("Censys request pacing failed.")
        self._last_request_started = start

    def _read_clock(self) -> float:
        try:
            value = self._clock()
        except MemoryError:
            raise
        except Exception:
            raise CensysPacingError("Censys request pacing failed.") from None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CensysPacingError("Censys request pacing failed.")
        result = float(value)
        if not math.isfinite(result):
            raise CensysPacingError("Censys request pacing failed.")
        if self._last_request_started is not None and result < self._last_request_started:
            raise CensysPacingError("Censys request pacing failed.")
        return result

    def close(self) -> None:
        """Close the synchronous HTTP client owned by this collector."""

        if self._closed:
            return
        try:
            self._http_client.close()
        except MemoryError:
            raise
        except Exception:
            raise CensysTransportError(
                "The Censys collector could not close safely."
            ) from None
        finally:
            self._closed = True

    def __enter__(self) -> CensysPublicationsClient:
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
        except CensysTransportError:
            if exc_type is None:
                raise
            # Preserve an already-active collection failure. The secondary
            # close failure is deliberately discarded and never disclosed.


def _require_policy(source: CensysPublicationSource) -> _SourcePolicy:
    if not isinstance(source, CensysPublicationSource):
        raise CensysCollectorConfigurationError(
            "The Censys publication source selector is invalid."
        )
    return SOURCE_POLICIES[source]


def _validate_max_records(value: object) -> None:
    if type(value) is not int or not MIN_RECORDS <= value <= MAX_RECORDS:
        raise CensysCollectorConfigurationError(
            "max_records must be an integer from 1 through 20."
        )


def _attributes(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in attrs:
        normalized_key = key.lower()
        if normalized_key not in result and value is not None:
            result[normalized_key] = value
    return result


def _attribute_tokens(attributes: dict[str, str]) -> set[str]:
    values = " ".join(
        attributes.get(name, "")
        for name in ("id", "class", "aria-label", "data-section", "data-testid")
    ).lower()
    return {token for token in _ATTRIBUTE_TOKEN_SPLIT.split(values) if token}


def _is_source_listing_region(
    source: CensysPublicationSource,
    attributes: dict[str, str],
) -> bool:
    if attributes.get("data-censys-listing", "").strip().lower() == source.value:
        return True
    tokens = _attribute_tokens(attributes)
    listing_tokens = {"list", "listing", "grid", "posts", "articles", "cards"}
    if source is CensysPublicationSource.ARC:
        return (
            {"security", "research"} <= tokens
            or {"arc", "research"} <= tokens
            or ("research" in tokens and bool(tokens & listing_tokens))
        )
    return (
        {"rapid", "response"} <= tokens
        or ("advisory" in tokens and bool(tokens & listing_tokens))
        or ("advisories" in tokens and bool(tokens & listing_tokens))
    )


def _is_publication_entry(tag: str, attributes: dict[str, str]) -> bool:
    if tag in {"article", "li"}:
        return True
    if attributes.get("data-censys-publication") is not None:
        return True
    tokens = _attribute_tokens(attributes)
    exact = {"card", "item", "post", "article", "advisory"}
    return bool(tokens & exact) or any(
        token.endswith(("card", "item")) for token in tokens
    )


def _resolve_reference(
    reference: str,
    *,
    policy: _SourcePolicy,
    request_kind: str,
) -> str:
    """Validate raw reference syntax before performing any URL resolution."""

    if (
        not isinstance(reference, str)
        or not reference
        or len(reference) > MAX_URL_LENGTH
        or reference != reference.strip()
        or not reference.isprintable()
        or not reference.isascii()
        or any(character.isspace() for character in reference)
        or "\\" in reference
        or "%" in reference
        or _MALFORMED_PERCENT_ESCAPE.search(reference)
        or reference.startswith("//")
    ):
        raise CensysRedirectError("A Censys URL reference failed validation.")
    try:
        parsed = urlparse(reference)
    except (TypeError, ValueError):
        raise CensysRedirectError(
            "A Censys URL reference failed validation."
        ) from None
    if parsed.query or parsed.fragment or parsed.params:
        raise CensysRedirectError("A Censys URL reference failed validation.")
    path_segments = parsed.path.split("/")
    if (
        "//" in parsed.path
        or any(segment in {".", ".."} for segment in path_segments)
        or "@" in parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise CensysRedirectError("A Censys URL reference failed validation.")

    if reference.startswith("https://"):
        target = reference
    elif reference.startswith("/") and not parsed.scheme and not parsed.netloc:
        target = urlunparse(("https", "censys.com", parsed.path, "", "", ""))
    else:
        raise CensysRedirectError("A Censys URL reference failed validation.")
    return _validate_url(target, policy=policy, request_kind=request_kind)


def _validate_url(
    url: str,
    *,
    policy: _SourcePolicy,
    request_kind: str,
) -> str:
    if (
        not isinstance(url, str)
        or not url
        or len(url) > MAX_URL_LENGTH
        or "\\" in url
        or not url.isprintable()
        or not url.isascii()
        or any(character.isspace() for character in url)
        or _MALFORMED_PERCENT_ESCAPE.search(url)
    ):
        raise CensysRedirectError("A Censys URL failed validation.")
    try:
        parsed = urlparse(url)
        port = parsed.port
        hostname = parsed.hostname or ""
    except (TypeError, ValueError):
        raise CensysRedirectError("A Censys URL failed validation.") from None
    if parsed.scheme != "https":
        raise CensysRedirectError("A Censys URL failed validation.")
    if (
        hostname.lower() != "censys.com"
        or hostname.endswith(".")
        or parsed.netloc.lower() not in {"censys.com", "censys.com:443"}
    ):
        raise CensysRedirectError("A Censys URL failed validation.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise CensysRedirectError("A Censys URL failed validation.")
    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise CensysRedirectError("A Censys URL failed validation.")
    if port not in (None, 443) or parsed.query or parsed.fragment or parsed.params:
        raise CensysRedirectError("A Censys URL failed validation.")
    path = parsed.path
    if (
        not path.startswith("/")
        or "%" in path
        or ";" in path
        or "//" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        raise CensysRedirectError("A Censys URL failed validation.")
    if request_kind == "discovery":
        if path != policy.discovery_path:
            raise CensysRedirectError("A Censys discovery URL failed validation.")
    elif request_kind == "publication":
        if not path.startswith(policy.publication_prefix):
            raise CensysRedirectError("A Censys publication URL failed validation.")
        suffix = path[len(policy.publication_prefix) :]
        if (
            not suffix.endswith("/")
            or "/" in suffix[:-1]
            or _PUBLICATION_SLUG.fullmatch(suffix[:-1]) is None
            or suffix[:-1].lower() in _RESERVED_PUBLICATION_SLUGS
        ):
            raise CensysRedirectError("A Censys publication URL failed validation.")
    else:
        raise CensysRedirectError("A Censys URL failed validation.")
    return urlunparse(("https", "censys.com", path, "", "", ""))


def _redirect_target(
    location: str | None,
    *,
    policy: _SourcePolicy,
    request_kind: str,
) -> str:
    if location is None:
        raise CensysRedirectError("A Censys redirect destination was rejected.")
    return _resolve_reference(
        location,
        policy=policy,
        request_kind=request_kind,
    )


def _content_type(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    return value.split(";", 1)[0].strip().lower() or None


def _read_bounded(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise CensysResponseTooLargeError(
                "A Censys response exceeded the allowed size."
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _decode_html(response: _HtmlResponse) -> str:
    try:
        return response.body.decode(response.encoding, errors="strict")
    except (LookupError, UnicodeError):
        raise CensysMetadataError(
            "Censys HTML metadata could not be decoded safely."
        ) from None


def _is_json_ld_media_type(value: str | None) -> bool:
    if not isinstance(value, str):
        return False
    return value.split(";", 1)[0].strip().lower() == "application/ld+json"


def _parse_publication_candidate(
    response: _HtmlResponse,
    *,
    policy: _SourcePolicy,
) -> PublicationCandidate:
    try:
        parser = _PublicationMetadataParser()
        parser.feed(_decode_html(response))
        parser.close()
        if parser.canonical_href is not None:
            canonical_url = _resolve_reference(
                parser.canonical_href,
                policy=policy,
                request_kind="publication",
            )
        else:
            canonical_url = _validate_url(
                response.final_url,
                policy=policy,
                request_kind="publication",
            )
        json_ld = _select_json_ld_metadata(
            parser.json_ld_blocks,
            canonical_url=canonical_url,
            policy=policy,
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
        authors = (
            list(json_ld.authors)
            if json_ld.authors is not None
            else list(parser.meta_authors)
        )
        if title is None or published_at is None:
            raise CensysMetadataError(
                "Censys publication metadata could not be safely normalized."
            )
        record = {
            "title": title,
            "url": canonical_url,
            "summary": summary,
            "published_at": published_at,
            "modified_at": modified_at,
            "authors": authors,
            "categories": [policy.category],
        }
        return adapt_censys_publication(policy.source_slug, record)
    except CensysMetadataError:
        raise
    except (
        CensysPublicationRecordError,
        CensysRedirectError,
        AssertionError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        raise CensysMetadataError(
            "Censys publication metadata could not be safely normalized."
        ) from None


def _select_json_ld_metadata(
    blocks: list[str],
    *,
    canonical_url: str,
    policy: _SourcePolicy,
) -> _JsonLdMetadata:
    publications: list[dict[str, object]] = []
    for block in blocks:
        if not block.strip():
            continue
        try:
            payload = json.loads(
                block,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
            _validate_json_ld_shape(payload)
        except (
            json.JSONDecodeError,
            _DuplicateJsonKey,
            _UnsafeJsonLd,
            RecursionError,
            TypeError,
            ValueError,
        ):
            continue
        publications.extend(_publication_objects(payload))

    matching: list[_JsonLdMetadata] = []
    identities: list[tuple[str | None, bool]] = []
    for publication in publications:
        identity, identity_declared = _json_ld_identity(
            publication,
            policy=policy,
        )
        identities.append((identity, identity_declared))
        if identity == canonical_url:
            matching.append(_json_ld_metadata(publication))

    if matching:
        first = matching[0]
        if all(candidate == first for candidate in matching[1:]):
            return first
        return _JsonLdMetadata()
    if len(publications) == 1 and identities == [(None, False)]:
        return _json_ld_metadata(publications[0])
    return _JsonLdMetadata()


def _json_ld_identity(
    publication: dict[str, object],
    *,
    policy: _SourcePolicy,
) -> tuple[str | None, bool]:
    raw_identities: list[object] = []
    declared = False
    if "url" in publication:
        declared = True
        raw_identities.append(publication["url"])
    if "mainEntityOfPage" in publication:
        declared = True
        main_entity = publication["mainEntityOfPage"]
        if isinstance(main_entity, dict):
            raw_identities.append(main_entity.get("@id"))
        else:
            raw_identities.append(main_entity)

    validated: set[str] = set()
    for raw_identity in raw_identities:
        if not isinstance(raw_identity, str):
            continue
        try:
            validated.add(
                _resolve_reference(
                    raw_identity,
                    policy=policy,
                    request_kind="publication",
                )
            )
        except CensysRedirectError:
            continue
    if len(validated) == 1:
        return next(iter(validated)), declared
    return None, declared


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
    allowed = {"Article", "BlogPosting", "NewsArticle"}
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
            value.get("datePublished"), maximum=MAX_TIMESTAMP_LENGTH
        ),
        modified_at=_bounded_metadata_string(
            value.get("dateModified"), maximum=MAX_TIMESTAMP_LENGTH
        ),
        authors=_json_ld_authors(value.get("author")),
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


def _json_ld_authors(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    members = value if isinstance(value, list) else [value]
    if len(members) > MAX_JSON_LD_AUTHORS:
        return None
    authors: list[str] = []
    for member in members:
        raw_name = member.get("name") if isinstance(member, dict) else member
        name = _bounded_metadata_string(
            raw_name,
            maximum=MAX_JSON_LD_AUTHOR_NAME_LENGTH,
        )
        if name is None:
            return None
        authors.append(name)
    return tuple(authors)


def _failure_reason(error: CensysCollectorError) -> CensysFailureReason:
    if isinstance(error, CensysTimeoutError):
        return CensysFailureReason.TIMEOUT
    if isinstance(error, CensysTransportError):
        return CensysFailureReason.TRANSPORT_FAILURE
    if isinstance(error, CensysRateLimitError):
        return CensysFailureReason.RATE_LIMITED
    if isinstance(error, CensysHttpError):
        return CensysFailureReason.HTTP_FAILURE
    if isinstance(error, CensysRedirectError):
        return CensysFailureReason.REDIRECT_REJECTED
    if isinstance(error, CensysContentTypeError):
        return CensysFailureReason.CONTENT_TYPE_REJECTED
    if isinstance(error, CensysResponseTooLargeError):
        return CensysFailureReason.RESPONSE_TOO_LARGE
    return CensysFailureReason.METADATA_REJECTED
