"""Bounded metadata-only collector for the two assessed DESC listing pages."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha256
from html.parser import HTMLParser
import ipaddress
import re
from types import MappingProxyType
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from app.ingestion.publication_pipeline import (
    MAX_PUBLICATION_SUMMARY_LENGTH,
    MAX_PUBLICATION_TITLE_LENGTH,
    PublicationCandidate,
)
from app.ingestion.uae_source_policy import (
    assess_uae_source_url,
    automated_uae_access_is_approved,
)


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 50
MAX_DOM_NODES = 25_000
MAX_DOM_TEXT_CHARS = MAX_RESPONSE_BYTES
MAX_REJECTED_RECORDS = MAX_DOM_NODES
DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=5.0, read=10.0, write=5.0, pool=5.0)
USER_AGENT = "CyberSentinelOSINT/1.0 (+defensive-desc-publications)"
ACCEPT_HEADER = "text/html, application/xhtml+xml;q=0.9"
ALLOWED_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
RESEARCH_HOSTS = (
    "ieeexplore.ieee.org",
    "www.sciencedirect.com",
    "dl.acm.org",
    "www.researchgate.net",
)
_DIRECT_DELIVERY_SEGMENTS = frozenset(
    {
        "pdf",
        "pdfft",
        "epdf",
        "download",
        "downloadfile",
        "attachment",
        "attachments",
        "file",
        "files",
        "image",
        "images",
        "media",
        "stamp",
        "export",
    }
)
_DIRECT_DELIVERY_QUERY_KEYS = frozenset(
    {"download", "downloadfile", "pdf", "pdfft", "epdf", "attachment", "file", "export", "format"}
)


class DescPublicationSource(str, Enum):
    NEWS = "news"
    PUBLISHED_RESEARCH = "published_research"


@dataclass(frozen=True, slots=True)
class _SourcePolicy:
    slug: str
    listing_url: str


SOURCE_POLICIES = MappingProxyType(
    {
        DescPublicationSource.NEWS: _SourcePolicy(
            "desc-news", "https://www.desc.gov.ae/media-hub/news/"
        ),
        DescPublicationSource.PUBLISHED_RESEARCH: _SourcePolicy(
            "desc-published-research",
            "https://www.desc.gov.ae/research-innovation/published-research/",
        ),
    }
)


class DescRejectionCategory(str, Enum):
    STRUCTURE = "structure"
    AMBIGUOUS = "ambiguous"
    UNSAFE_URL = "unsafe_url"
    INVALID_DATE = "invalid_date"
    INVALID_TEXT = "invalid_text"
    DUPLICATE_CONFLICT = "duplicate_conflict"
    RECORD_LIMIT = "record_limit"


@dataclass(frozen=True, slots=True)
class DescCollectionResult:
    source: DescPublicationSource
    source_slug: str
    candidates: tuple[PublicationCandidate, ...]
    rejected_record_count: int
    rejection_categories: tuple[DescRejectionCategory, ...]
    fetched_listing_page_count: int
    record_limit_exceeded: bool

    def __post_init__(self) -> None:
        validate_desc_collection_result(self)


def validate_desc_collection_result(value: object) -> DescCollectionResult:
    """Validate immutable collection evidence without trusting its constructor."""

    if not isinstance(value, DescCollectionResult):
        raise ValueError("The DESC collection result is invalid.")
    if type(value.source) is not DescPublicationSource:
        raise ValueError("The DESC collection source is invalid.")
    policy = SOURCE_POLICIES[value.source]
    if value.source_slug != policy.slug:
        raise ValueError("The DESC collection source identity is invalid.")
    if type(value.candidates) is not tuple or not 1 <= len(value.candidates) <= MAX_RECORDS:
        raise ValueError("The DESC collection candidates are invalid.")
    if any(
        not isinstance(candidate, PublicationCandidate)
        or candidate.source_slug != value.source_slug
        for candidate in value.candidates
    ):
        raise ValueError("The DESC collection candidate identity is invalid.")
    external_ids = tuple(candidate.source_external_id for candidate in value.candidates)
    if any(type(external_id) is not str or not external_id for external_id in external_ids):
        raise ValueError("The DESC collection candidate identities are invalid.")
    if len(external_ids) != len(set(external_ids)):
        raise ValueError("The DESC collection candidate identities conflict.")
    if (
        type(value.rejected_record_count) is not int
        or not 0 <= value.rejected_record_count <= MAX_REJECTED_RECORDS
    ):
        raise ValueError("The DESC collection rejection count is invalid.")
    if type(value.rejection_categories) is not tuple or any(
        type(category) is not DescRejectionCategory
        for category in value.rejection_categories
    ):
        raise ValueError("The DESC collection rejection categories are invalid.")
    if len(value.rejection_categories) != len(set(value.rejection_categories)):
        raise ValueError("The DESC collection rejection categories conflict.")
    if value.rejection_categories != tuple(
        sorted(value.rejection_categories, key=lambda category: category.value)
    ):
        raise ValueError("The DESC collection rejection categories are unordered.")
    if (value.rejected_record_count == 0) != (not value.rejection_categories):
        raise ValueError("The DESC collection rejection evidence is inconsistent.")
    if (
        type(value.fetched_listing_page_count) is not int
        or value.fetched_listing_page_count not in {0, 1}
    ):
        raise ValueError("The DESC collection page count is invalid.")
    if type(value.record_limit_exceeded) is not bool:
        raise ValueError("The DESC collection limit flag is invalid.")
    has_limit_category = DescRejectionCategory.RECORD_LIMIT in value.rejection_categories
    if value.record_limit_exceeded:
        if value.rejected_record_count == 0 or not has_limit_category:
            raise ValueError("The DESC collection limit evidence is inconsistent.")
    elif has_limit_category:
        raise ValueError("The DESC collection limit evidence is inconsistent.")
    return value


class DescCollectorError(RuntimeError):
    """A DESC operation failed with sanitized diagnostics."""


class DescApprovalPendingError(DescCollectorError):
    pass


class DescTransportError(DescCollectorError):
    pass


class DescTimeoutError(DescTransportError):
    pass


class DescRateLimitError(DescCollectorError):
    pass


class DescHttpError(DescCollectorError):
    pass


class DescRedirectError(DescCollectorError):
    pass


class DescContentTypeError(DescCollectorError):
    pass


class DescResponseTooLargeError(DescCollectorError):
    pass


class DescMetadataError(DescCollectorError):
    pass


@dataclass(slots=True)
class _Node:
    tag: str
    attrs: dict[str, str]
    parent: _Node | None = None
    children: list[_Node] = field(default_factory=list)
    text_parts: list[str] = field(default_factory=list)
    content: list[str | _Node] = field(default_factory=list)


class _DomParser(HTMLParser):
    _VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("document", {})
        self._stack = [self.root]
        self._nodes = 1

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._nodes += 1
        if self._nodes > MAX_DOM_NODES:
            raise DescMetadataError("The DESC listing structure exceeds the safe bound.")
        node = _Node(tag.casefold(), {k.casefold(): v or "" for k, v in attrs}, self._stack[-1])
        self._stack[-1].children.append(node)
        self._stack[-1].content.append(node)
        if node.tag not in self._VOID:
            self._stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if self._stack[-1].tag == tag.casefold():
            self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        for index in range(len(self._stack) - 1, 0, -1):
            if self._stack[index].tag == tag:
                del self._stack[index:]
                return

    def handle_data(self, data: str) -> None:
        self._stack[-1].text_parts.append(data)
        self._stack[-1].content.append(data)


class DescPublicationsClient:
    """Fetch exactly one fixed DESC listing after the existing approval decision."""

    def __init__(
        self,
        source: DescPublicationSource,
        *,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not isinstance(source, DescPublicationSource):
            raise TypeError("The DESC source selector is invalid.")
        if not isinstance(timeout, httpx.Timeout):
            raise TypeError("The DESC timeout configuration is invalid.")
        _validate_timeout(timeout)
        if transport is not None and not isinstance(transport, httpx.MockTransport):
            raise TypeError("The DESC test transport is invalid.")
        self.source = source
        self._policy = SOURCE_POLICIES[source]
        _require_exact_listing_url(self._policy.listing_url, self._policy.slug)
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": USER_AGENT, "Accept": ACCEPT_HEADER},
            transport=transport,
        )
        self._closed = False

    def fetch(self) -> DescCollectionResult:
        if self._closed:
            raise DescTransportError("The DESC client is closed.")
        if not automated_uae_access_is_approved(self._policy.slug):
            raise DescApprovalPendingError("DESC automated access remains approval pending.")
        try:
            with self._client.stream("GET", self._policy.listing_url) as response:
                if 300 <= response.status_code < 400:
                    raise DescRedirectError("The DESC listing response redirected unexpectedly.")
                if response.status_code == 429:
                    raise DescRateLimitError("The DESC listing request was rate limited.")
                if not 200 <= response.status_code < 300:
                    raise DescHttpError("The DESC listing request was rejected.")
                media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
                if media_type not in ALLOWED_CONTENT_TYPES:
                    raise DescContentTypeError("The DESC listing media type is unsupported.")
                length = response.headers.get("content-length")
                if length is not None and length.isascii() and length.isdigit() and int(length) > MAX_RESPONSE_BYTES:
                    raise DescResponseTooLargeError("The DESC listing response exceeds the size limit.")
                body = _read_bounded(response)
        except DescCollectorError:
            raise
        except httpx.TimeoutException:
            raise DescTimeoutError("The DESC listing request timed out.") from None
        except httpx.HTTPError:
            raise DescTransportError("The DESC listing request failed safely.") from None
        return parse_desc_publications(self.source, body, fetched_listing_page_count=1)

    def close(self) -> None:
        if not self._closed:
            self._client.cookies.clear()
            self._client.close()
            self._closed = True

    def __enter__(self) -> DescPublicationsClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def parse_desc_publications(
    source: DescPublicationSource,
    html_bytes: bytes,
    *,
    max_records: int = MAX_RECORDS,
    fetched_listing_page_count: int = 0,
) -> DescCollectionResult:
    """Pure deterministic parsing for already-bounded fixture HTML."""

    if not isinstance(source, DescPublicationSource):
        raise TypeError("The DESC source selector is invalid.")
    if type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS:
        raise ValueError("The DESC record limit is invalid.")
    if type(fetched_listing_page_count) is not int or fetched_listing_page_count not in {0, 1}:
        raise ValueError("The DESC page count is invalid.")
    if not isinstance(html_bytes, bytes) or not html_bytes or len(html_bytes) > MAX_RESPONSE_BYTES:
        raise DescMetadataError("The DESC listing body is invalid or oversized.")
    try:
        html = html_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise DescMetadataError("The DESC listing encoding is invalid.") from None
    parser = _DomParser()
    try:
        parser.feed(html)
        parser.close()
    except DescCollectorError:
        raise
    except Exception:
        raise DescMetadataError("The DESC listing could not be parsed safely.") from None

    trusted_containers = (
        _trusted_news_containers(parser.root)
        if source is DescPublicationSource.NEWS
        else _trusted_research_containers(parser.root)
    )
    overflow_count = max(0, len(trusted_containers) - max_records)
    selected_containers = trusted_containers[:max_records]
    records = (
        _parse_news(selected_containers)
        if source is DescPublicationSource.NEWS
        else _parse_research(selected_containers)
    )
    candidates, rejected, categories = _deduplicate(records)
    exceeded = overflow_count > 0
    if exceeded:
        rejected += overflow_count
        categories.add(DescRejectionCategory.RECORD_LIMIT)
    if not candidates:
        raise DescMetadataError("The DESC listing contained no valid publication metadata.")
    policy = SOURCE_POLICIES[source]
    return DescCollectionResult(
        source=source,
        source_slug=policy.slug,
        candidates=tuple(candidates),
        rejected_record_count=rejected,
        rejection_categories=tuple(sorted(categories, key=lambda item: item.value)),
        fetched_listing_page_count=fetched_listing_page_count,
        record_limit_exceeded=exceeded,
    )


def _trusted_news_containers(root: _Node) -> list[_Node]:
    return [
        article
        for article in _descendants(root, "article")
        if {"post", "type-post", "category-news"}.issubset(_classes(article))
    ]


def _trusted_research_containers(root: _Node) -> list[_Node]:
    return [
        section
        for section in _descendants(root, "section")
        if {"elementor-section", "elementor-inner-section"}.issubset(
            _classes(section)
        )
    ]


def _parse_news(
    articles: list[_Node],
) -> list[PublicationCandidate | DescRejectionCategory]:
    results: list[PublicationCandidate | DescRejectionCategory] = []
    for article in articles:
        try:
            headings = [node for node in _descendants(article, "h2") if "entry-title" in _classes(node)]
            times = [node for node in _descendants(article, "time") if {"entry-date", "published"}.issubset(_classes(node))]
            summaries = [node for node in _descendants(article, "div") if "entry-summary" in _classes(node)]
            if len(headings) != 1 or len(times) != 1 or len(summaries) > 1:
                raise _Rejected(DescRejectionCategory.STRUCTURE)
            title_anchors = list(_descendants(headings[0], "a"))
            if len(title_anchors) != 1:
                raise _Rejected(DescRejectionCategory.AMBIGUOUS)
            canonical_url, slug = _canonical_news_url(title_anchors[0].attrs.get("href"))
            for anchor in _relevant_news_anchors(article, headings[0], times[0]):
                other_url, _ = _canonical_news_url(anchor.attrs.get("href"))
                if other_url != canonical_url:
                    raise _Rejected(DescRejectionCategory.AMBIGUOUS)
            title = _bounded_text(_text(headings[0]), MAX_PUBLICATION_TITLE_LENGTH)
            published = _aware_datetime(times[0].attrs.get("datetime"))
            summary = None
            if summaries:
                summary_text = re.sub(r"\bRead\s+More\b", " ", _text(summaries[0]), flags=re.IGNORECASE)
                summary = _bounded_text(summary_text, MAX_PUBLICATION_SUMMARY_LENGTH, optional=True)
            results.append(PublicationCandidate(
                source_slug="desc-news",
                source_external_id=f"desc-news:{slug}",
                canonical_title=title,
                canonical_url=canonical_url,
                summary=summary,
                source_published_at=published,
                safe_source_payload={"category": "DESC News"},
            ))
        except _Rejected as error:
            results.append(error.category)
    return results


def _parse_research(
    sections: list[_Node],
) -> list[PublicationCandidate | DescRejectionCategory]:
    results: list[PublicationCandidate | DescRejectionCategory] = []
    for section in sections:
        try:
            h4s = [node for node in _descendants(section, "h4") if "elementor-heading-title" in _classes(node)]
            h6s = [node for node in _descendants(section, "h6") if "elementor-heading-title" in _classes(node)]
            publisher_paragraphs = [node for node in _descendants(section, "p") if _publisher_text(node) is not None]
            visit_links = [node for node in _descendants(section, "a") if _normalize_text(_text(node)) == "Visit Publication"]
            if not all(len(items) == 1 for items in (h4s, h6s, publisher_paragraphs, visit_links)):
                raise _Rejected(DescRejectionCategory.AMBIGUOUS)
            title = _bounded_text(_text(h4s[0]), MAX_PUBLICATION_TITLE_LENGTH)
            statement = _bounded_text(_text(h6s[0]), MAX_PUBLICATION_SUMMARY_LENGTH)
            publishers = _bounded_text(_publisher_text(publisher_paragraphs[0]), MAX_PUBLICATION_SUMMARY_LENGTH)
            canonical_url, host = _canonical_research_url(visit_links[0].attrs.get("href"))
            summary = _bounded_text(f"{statement} Publishers: {publishers}", MAX_PUBLICATION_SUMMARY_LENGTH)
            identity = sha256(canonical_url.encode("utf-8")).hexdigest()
            results.append(PublicationCandidate(
                source_slug="desc-published-research",
                source_external_id=f"desc-published-research:{identity}",
                canonical_title=title,
                canonical_url=canonical_url,
                summary=summary,
                source_published_at=None,
                safe_source_payload={
                    "publication_statement": statement,
                    "publishers": publishers,
                    "publication_host": host,
                    "category": "DESC Published Research",
                },
            ))
        except _Rejected as error:
            results.append(error.category)
    return results


class _Rejected(Exception):
    def __init__(self, category: DescRejectionCategory) -> None:
        self.category = category


def _deduplicate(records: list[PublicationCandidate | DescRejectionCategory]) -> tuple[list[PublicationCandidate], int, set[DescRejectionCategory]]:
    grouped: dict[str, list[PublicationCandidate]] = {}
    rejected = 0
    categories: set[DescRejectionCategory] = set()
    for record in records:
        if isinstance(record, DescRejectionCategory):
            rejected += 1
            categories.add(record)
            continue
        grouped.setdefault(record.source_external_id, []).append(record)

    accepted: list[PublicationCandidate] = []
    for candidates in grouped.values():
        first = candidates[0]
        if all(candidate == first for candidate in candidates[1:]):
            accepted.append(first)
        else:
            rejected += len(candidates)
            categories.add(DescRejectionCategory.DUPLICATE_CONFLICT)
    return accepted, rejected, categories


def _require_exact_listing_url(url: str, slug: str) -> None:
    assessment = assess_uae_source_url(slug, url)
    if not assessment.matches_assessed_boundary or not assessment.assessed_request_target:
        raise RuntimeError("The fixed DESC listing target is invalid.")


def _validate_timeout(timeout: httpx.Timeout) -> None:
    values = (timeout.connect, timeout.read, timeout.write, timeout.pool)
    if any(type(value) not in {int, float} or not 0 < value <= 30 for value in values):
        raise ValueError("The DESC timeout configuration is outside the safe bound.")


def _read_bounded(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise DescResponseTooLargeError("The DESC listing response exceeds the size limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def _canonical_news_url(value: object) -> tuple[str, str]:
    if not _safe_ascii_url(value):
        raise _Rejected(DescRejectionCategory.UNSAFE_URL)
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise _Rejected(DescRejectionCategory.UNSAFE_URL) from None
    if parsed.scheme != "https" or parsed.netloc != "www.desc.gov.ae" or parsed.query or parsed.fragment:
        raise _Rejected(DescRejectionCategory.UNSAFE_URL)
    if re.fullmatch(r"/[a-z0-9]+(?:-[a-z0-9]+)*/", parsed.path, flags=re.ASCII) is None:
        raise _Rejected(DescRejectionCategory.UNSAFE_URL)
    slug = parsed.path[1:-1]
    if slug in {"api", "callback", "feed", "form", "forms", "page", "search", "wp-json", "wp-admin", "wp-content"}:
        raise _Rejected(DescRejectionCategory.UNSAFE_URL)
    return value, slug


def _canonical_research_url(value: object) -> tuple[str, str]:
    if not _safe_ascii_url(value):
        raise _Rejected(DescRejectionCategory.UNSAFE_URL)
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise _Rejected(DescRejectionCategory.UNSAFE_URL) from None
    host = parsed.hostname or ""
    if parsed.scheme != "https" or parsed.netloc != host or host not in RESEARCH_HOSTS or parsed.fragment:
        raise _Rejected(DescRejectionCategory.UNSAFE_URL)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise _Rejected(DescRejectionCategory.UNSAFE_URL)
    path_lower = parsed.path.casefold()
    segments = [part for part in parsed.path.split("/") if part]
    lowered_segments = [part.casefold() for part in segments]
    if (
        not parsed.path.startswith("/")
        or parsed.path in {"", "/"}
        or "//" in parsed.path
        or path_lower.endswith(".pdf")
        or any(segment in _DIRECT_DELIVERY_SEGMENTS for segment in lowered_segments)
        or "wp-content" in lowered_segments
        or any(segment in {".", ".."} for segment in segments)
        or not _research_path_is_allowed(host, parsed.path)
    ):
        raise _Rejected(DescRejectionCategory.UNSAFE_URL)
    canonical_path = parsed.path[:-1] if parsed.path.endswith("/") else parsed.path
    query: list[tuple[str, str]] = []
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise _Rejected(DescRejectionCategory.UNSAFE_URL) from None
    for key, item in pairs:
        normalized = "".join(character for character in key.casefold() if character.isalnum())
        if (
            any(normalized.startswith(prefix) for prefix in _DIRECT_DELIVERY_QUERY_KEYS)
            or normalized in {
            "token", "apikey", "accesstoken", "refreshtoken", "password",
            "secret", "signature", "credential", "credentials", "authorization",
            "xamzsignature", "xamzcredential", "xamzsecuritytoken",
            "xgoogsignature", "xgoogcredential", "xgoogsecuritytoken",
            "clientsecret", "sessiontoken", "sastoken", "bearertoken",
            }
        ):
            raise _Rejected(DescRejectionCategory.UNSAFE_URL)
        if not key.casefold().startswith("utm_") and key.casefold() not in {"gclid", "fbclid", "campaign"}:
            query.append((key, item))
    query.sort()
    return urlunsplit(("https", host, canonical_path, urlencode(query, doseq=True), "")), host


def _research_path_is_allowed(host: str, path: str) -> bool:
    if host == "ieeexplore.ieee.org":
        return re.fullmatch(r"/document/[0-9]{1,20}/?", path, flags=re.ASCII) is not None
    if host == "www.sciencedirect.com":
        return (
            re.fullmatch(
                r"/science/article/(?:abs/)?pii/[A-Za-z0-9._-]{1,128}/?",
                path,
                flags=re.ASCII,
            )
            is not None
        )
    if host == "dl.acm.org":
        return (
            re.fullmatch(
                r"/doi/(?:abs/)?10\.[0-9]{1,9}/[A-Za-z0-9._()+-]{1,160}/?",
                path,
                flags=re.ASCII,
            )
            is not None
        )
    if host == "www.researchgate.net":
        return (
            re.fullmatch(
                r"/publication/[0-9]{1,20}(?:_[A-Za-z0-9][A-Za-z0-9_-]{0,159})?/?",
                path,
                flags=re.ASCII,
            )
            is not None
        )
    return False


def _safe_ascii_url(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip() and value.isascii() and len(value) <= 2048 and not any(token in value for token in ("%", "\\", ";")) and not any(ord(char) < 33 or ord(char) == 127 for char in value)


def _aware_datetime(value: object) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise _Rejected(DescRejectionCategory.INVALID_DATE)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed
    except (TypeError, ValueError, OverflowError):
        raise _Rejected(DescRejectionCategory.INVALID_DATE) from None


def _bounded_text(value: object, maximum: int, *, optional: bool = False) -> str | None:
    if not isinstance(value, str) or any(ord(char) < 32 and char not in "\t\r\n" for char in value):
        raise _Rejected(DescRejectionCategory.INVALID_TEXT)
    normalized = _normalize_text(value)
    if not normalized:
        if optional:
            return None
        raise _Rejected(DescRejectionCategory.INVALID_TEXT)
    if len(normalized) > maximum:
        raise _Rejected(DescRejectionCategory.INVALID_TEXT)
    return normalized


def _publisher_text(node: _Node) -> str | None:
    strong = list(_descendants(node, "strong"))
    if len(strong) != 1 or re.fullmatch(r"Publishers\s*: ?", _normalize_text(_text(strong[0])), flags=re.IGNORECASE) is None:
        return None
    value = _normalize_text(" ".join(node.text_parts))
    return value or None


def _relevant_news_anchors(article: _Node, heading: _Node, time: _Node) -> list[_Node]:
    relevant = list(_descendants(heading, "a"))
    current = time.parent
    while current is not None and current is not article:
        if current.tag == "a":
            relevant.append(current)
        current = current.parent
    for anchor in _descendants(article, "a"):
        classes = _classes(anchor)
        if classes.intersection({"read-more", "more-link", "post-thumbnail"}) or any(True for _ in _descendants(anchor, "img")):
            relevant.append(anchor)
    unique: list[_Node] = []
    for anchor in relevant:
        if anchor not in unique:
            unique.append(anchor)
    return unique


def _descendants(node: _Node, tag: str):
    stack = list(reversed(node.children))
    visited = 0
    while stack:
        child = stack.pop()
        visited += 1
        if visited > MAX_DOM_NODES:
            raise DescMetadataError("The DESC listing structure exceeds the safe bound.")
        if child.tag == tag:
            yield child
        if child.children:
            stack.extend(reversed(child.children))


def _classes(node: _Node) -> set[str]:
    return {item for item in node.attrs.get("class", "").split() if item}


def _text(node: _Node) -> str:
    parts: list[str] = []
    stack: list[str | _Node] = [node]
    visited = 0
    text_length = 0
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            text_length += len(current)
            if text_length > MAX_DOM_TEXT_CHARS:
                raise DescMetadataError("The DESC listing text exceeds the safe bound.")
            parts.append(current)
            continue
        visited += 1
        if visited > MAX_DOM_NODES:
            raise DescMetadataError("The DESC listing structure exceeds the safe bound.")
        if current.content:
            stack.extend(reversed(current.content))
    return " ".join(parts)


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


__all__ = [
    "ACCEPT_HEADER", "DEFAULT_TIMEOUT", "DescApprovalPendingError",
    "DescCollectionResult", "DescCollectorError", "DescContentTypeError",
    "DescHttpError", "DescMetadataError", "DescPublicationSource",
    "DescPublicationsClient", "DescRateLimitError", "DescRedirectError",
    "DescRejectionCategory", "DescResponseTooLargeError", "DescTimeoutError",
    "DescTransportError", "MAX_DOM_NODES", "MAX_RECORDS", "MAX_RESPONSE_BYTES",
    "SOURCE_POLICIES", "USER_AGENT", "parse_desc_publications",
    "validate_desc_collection_result",
]
