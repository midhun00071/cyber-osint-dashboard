"""Strict XML normalization for the three inactive C05 official RSS feeds."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from hashlib import sha256
from html.parser import HTMLParser
import json
import re
from types import MappingProxyType
from typing import Mapping
import unicodedata
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from app.ingestion.collectors.official_rss_client import (
    C05_OFFICIAL_RSS_POLICIES,
    MAX_RESPONSE_BYTES,
    OfficialRssSourcePolicy,
)
from app.ingestion.publication_pipeline import (
    MAX_PUBLICATION_EXTERNAL_ID_LENGTH,
    MAX_PUBLICATION_SUMMARY_LENGTH,
    MAX_PUBLICATION_TITLE_LENGTH,
    MAX_PUBLICATION_URL_LENGTH,
    PublicationCandidate,
    normalize_publication_candidate,
)


MAX_FEED_ENTRIES = 100
MAX_PUBLICATION_RECORDS = 100
MAX_AUTHOR_LENGTH = 200
MAX_CATEGORY_LENGTH = 100
MAX_CATEGORIES = 20
MAX_LANGUAGE_LENGTH = 35
MAX_RETAINED_REJECTIONS = 20
MAX_XML_NODES = 25_000
MAX_XML_DEPTH = 32
MAX_NCSC_SLUG_LENGTH = 200
_ALERT_PATH = re.compile(r"^/alerte/(?P<id>CERTFR-[0-9]{4}-ALE-[0-9]{3})/$")
_ADVISORY_PATH = re.compile(r"^/avis/(?P<id>CERTFR-[0-9]{4}-AVI-[0-9]{4})/$")
_NCSC_PATH = re.compile(
    rf"^/report/(?P<id>[a-z0-9](?:[a-z0-9-]{{0,{MAX_NCSC_SLUG_LENGTH - 2}}}[a-z0-9])?)$"
)


class OfficialRssPublicationError(ValueError):
    """Base class for a sanitized official RSS normalization failure."""


class OfficialRssXmlError(OfficialRssPublicationError):
    """The feed failed strict XML safety or shape validation."""


class OfficialRssEntryError(OfficialRssPublicationError):
    """One feed entry failed bounded metadata validation."""


class OfficialRssConflictError(OfficialRssPublicationError):
    """The same feed contained conflicting immutable publication identities."""


@dataclass(frozen=True, slots=True)
class OfficialRssDocument:
    source_slug: str
    candidates: tuple[PublicationCandidate, ...]
    entries_received: int
    records_accepted: int
    records_rejected: int
    retained_rejections: tuple[str, ...]
    canonical_metadata_hash: str
    greatest_publication_timestamp: datetime | None


class _PlainTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        del attrs
        if tag.lower() in {"script", "style"}:
            self.ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style"} and self.ignored_depth:
            self.ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self.ignored_depth:
            self.parts.append(data)


def adapt_official_rss_feed(source_slug: str, body: bytes) -> OfficialRssDocument:
    """Parse and normalize one already-fetched official RSS response."""

    try:
        policy = C05_OFFICIAL_RSS_POLICIES[source_slug]
    except (KeyError, TypeError):
        raise OfficialRssPublicationError(
            "The official RSS source is not approved."
        ) from None
    if not isinstance(body, bytes) or not body or len(body) > MAX_RESPONSE_BYTES:
        raise OfficialRssXmlError("The official RSS document size is invalid.")
    _reject_unsafe_xml_declarations(body)
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError):
        raise OfficialRssXmlError("The official RSS XML is malformed.") from None
    _validate_xml_tree(root)
    if _local_name(root.tag).lower() != "rss":
        raise OfficialRssXmlError("The official RSS root element is invalid.")
    channels = [child for child in root if _local_name(child.tag).lower() == "channel"]
    if len(channels) != 1:
        raise OfficialRssXmlError("The official RSS channel is invalid.")
    entries = [
        child
        for child in channels[0]
        if _local_name(child.tag).lower() == "item"
    ]
    if len(entries) > MAX_FEED_ENTRIES:
        raise OfficialRssXmlError("The official RSS feed exceeds the entry limit.")

    candidates: list[PublicationCandidate] = []
    rejections: list[str] = []
    rejected = 0
    for entry in entries:
        try:
            candidates.append(_adapt_entry(entry, policy))
        except OfficialRssEntryError:
            rejected += 1
            if len(rejections) < MAX_RETAINED_REJECTIONS:
                rejections.append("invalid_entry")
    if len(candidates) > MAX_PUBLICATION_RECORDS:
        raise OfficialRssXmlError("The official RSS feed exceeds the record limit.")
    deduplicated = _deduplicate_candidates(candidates)
    canonical_hash = _canonical_metadata_hash(deduplicated)
    timestamps = [
        timestamp
        for candidate in deduplicated
        for timestamp in (
            candidate.source_published_at,
            candidate.source_modified_at,
        )
        if timestamp is not None
    ]
    greatest = max(timestamps) if timestamps else None
    return OfficialRssDocument(
        source_slug=source_slug,
        candidates=tuple(deduplicated),
        entries_received=len(entries),
        records_accepted=len(deduplicated),
        records_rejected=rejected,
        retained_rejections=tuple(rejections),
        canonical_metadata_hash=canonical_hash,
        greatest_publication_timestamp=greatest,
    )


def _adapt_entry(
    entry: ET.Element,
    policy: OfficialRssSourcePolicy,
) -> PublicationCandidate:
    fields: dict[str, list[str]] = {}
    for child in entry:
        name = _local_name(child.tag).lower()
        if name in {
            "title",
            "link",
            "description",
            "summary",
            "pubdate",
            "published",
            "updated",
            "date",
            "author",
            "creator",
            "category",
        }:
            fields.setdefault(name, []).append("".join(child.itertext()))
    title = _single_required(fields, "title")
    link = _single_required(fields, "link")
    canonical_url, external_id = _canonical_publication_identity(link, policy)
    canonical_title = _plain_text(title, MAX_PUBLICATION_TITLE_LENGTH, required=True)
    summary_values = fields.get("description", fields.get("summary", []))
    if len(summary_values) > 1:
        raise OfficialRssEntryError("The official RSS summary is ambiguous.")
    summary = (
        None
        if not summary_values
        else _plain_text(
            summary_values[0],
            MAX_PUBLICATION_SUMMARY_LENGTH,
            required=False,
        )
    )
    published_values = fields.get("pubdate", fields.get("published", []))
    if len(published_values) != 1:
        raise OfficialRssEntryError("The official RSS publication time is invalid.")
    published = _timestamp(published_values[0])
    updated_values = fields.get("updated", fields.get("date", []))
    if len(updated_values) > 1:
        raise OfficialRssEntryError("The official RSS update time is invalid.")
    updated = _timestamp(updated_values[0]) if updated_values else None
    if updated is not None and updated < published:
        raise OfficialRssEntryError("The official RSS timestamp order is invalid.")
    author_values = fields.get("author", fields.get("creator", []))
    if len(author_values) > 1:
        raise OfficialRssEntryError("The official RSS author is ambiguous.")
    author = (
        None
        if not author_values
        else _plain_text(author_values[0], MAX_AUTHOR_LENGTH, required=True)
    )
    categories = tuple(
        _plain_text(value, MAX_CATEGORY_LENGTH, required=True)
        for value in fields.get("category", [])
    )
    if len(categories) > MAX_CATEGORIES:
        raise OfficialRssEntryError("The official RSS categories exceed policy.")
    categories = tuple(dict.fromkeys(categories))
    if not policy.source_language or len(policy.source_language) > MAX_LANGUAGE_LENGTH:
        raise OfficialRssEntryError("The official RSS language is invalid.")
    safe_payload: Mapping[str, object] = MappingProxyType(
        {
            "metadata_only": True,
            "language": policy.source_language,
            **({"author": author} if author is not None else {}),
            **({"categories": list(categories)} if categories else {}),
        }
    )
    return PublicationCandidate(
        source_slug=policy.source_slug,
        source_external_id=_bounded_text(
            external_id,
            MAX_PUBLICATION_EXTERNAL_ID_LENGTH,
            "external identifier",
        ),
        canonical_title=canonical_title,
        canonical_url=_bounded_text(
            canonical_url,
            MAX_PUBLICATION_URL_LENGTH,
            "canonical URL",
        ),
        summary=summary,
        source_published_at=published,
        source_modified_at=updated,
        safe_source_payload=safe_payload,
    )


def _canonical_publication_identity(
    value: object,
    policy: OfficialRssSourcePolicy,
) -> tuple[str, str]:
    text = _bounded_text(value, MAX_PUBLICATION_URL_LENGTH, "canonical URL")
    if not text.isascii() or any(unicodedata.category(c) == "Cc" for c in text):
        raise OfficialRssEntryError("The official RSS canonical URL is invalid.")
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError:
        raise OfficialRssEntryError(
            "The official RSS canonical URL is invalid."
        ) from None
    submitted_host = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or not submitted_host
        or submitted_host != submitted_host.lower()
        or submitted_host not in policy.canonical_hosts
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or port is not None
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
        or "\\" in parsed.path
        or "//" in parsed.path
        or any(segment in {".", ".."} for segment in parsed.path.split("/"))
        or parsed.netloc != submitted_host
    ):
        raise OfficialRssEntryError("The official RSS canonical URL is invalid.")
    if policy.canonical_kind == "cert-fr-alert":
        match = _ALERT_PATH.fullmatch(parsed.path)
    elif policy.canonical_kind == "cert-fr-advisory":
        match = _ADVISORY_PATH.fullmatch(parsed.path)
    elif policy.canonical_kind == "uk-ncsc-report":
        match = _NCSC_PATH.fullmatch(parsed.path)
    else:
        match = None
    if match is None:
        raise OfficialRssEntryError("The official RSS canonical path is invalid.")
    canonical = urlunsplit(("https", submitted_host, parsed.path, "", ""))
    return canonical, match.group("id")


def _deduplicate_candidates(
    candidates: list[PublicationCandidate],
) -> list[PublicationCandidate]:
    by_external: dict[str, tuple[str, str]] = {}
    by_url: dict[str, tuple[str, str]] = {}
    accepted: list[PublicationCandidate] = []
    for candidate in candidates:
        normalized = normalize_publication_candidate(candidate)
        external = normalized.source_external_id
        url_hash = normalized.canonical_url_hash
        content_hash = normalized.content_hash
        external_match = by_external.get(external)
        url_match = by_url.get(url_hash)
        if external_match is None and url_match is None:
            by_external[external] = (url_hash, content_hash)
            by_url[url_hash] = (external, content_hash)
            accepted.append(candidate)
            continue
        if not (
            external_match == (url_hash, content_hash)
            and url_match == (external, content_hash)
        ):
            raise OfficialRssConflictError(
                "The official RSS feed contains conflicting duplicate metadata."
            )
    return accepted


def _canonical_metadata_hash(candidates: list[PublicationCandidate]) -> str:
    rows = []
    for candidate in candidates:
        normalized = normalize_publication_candidate(candidate)
        rows.append(
            {
                "external_id": normalized.source_external_id,
                "url_hash": normalized.canonical_url_hash,
                "content_hash": normalized.content_hash,
                "published": _timestamp_text(normalized.source_published_at),
                "updated": _timestamp_text(normalized.source_modified_at),
            }
        )
    rows.sort(key=lambda row: (row["external_id"], row["url_hash"]))
    encoded = json.dumps(
        rows,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


_DOCUMENT_TIMESTAMP = object()


def build_official_rss_cursor(
    document: OfficialRssDocument,
    *,
    effective_timestamp: datetime | None | object = _DOCUMENT_TIMESTAMP,
) -> str:
    if not isinstance(document, OfficialRssDocument):
        raise OfficialRssPublicationError("The official RSS document is invalid.")
    timestamp_value = (
        document.greatest_publication_timestamp
        if effective_timestamp is _DOCUMENT_TIMESTAMP
        else effective_timestamp
    )
    if timestamp_value is not None and (
        not isinstance(timestamp_value, datetime)
        or timestamp_value.tzinfo is None
        or timestamp_value.utcoffset() is None
    ):
        raise OfficialRssPublicationError(
            "The official RSS cursor timestamp is invalid."
        )
    timestamp = _timestamp_text(timestamp_value) or "-"
    cursor = f"v1:{document.canonical_metadata_hash}:{timestamp}"
    if len(cursor) > 500:
        raise OfficialRssPublicationError("The official RSS cursor exceeds policy.")
    return cursor


def parse_official_rss_cursor(value: object) -> tuple[str, datetime | None]:
    if not isinstance(value, str) or len(value) > 500:
        raise OfficialRssPublicationError("The official RSS cursor is invalid.")
    parts = value.split(":", 2)
    if (
        len(parts) != 3
        or parts[0] != "v1"
        or re.fullmatch(r"[0-9a-f]{64}", parts[1]) is None
    ):
        raise OfficialRssPublicationError("The official RSS cursor is invalid.")
    timestamp = None if parts[2] == "-" else _timestamp(parts[2])
    canonical = f"v1:{parts[1]}:{_timestamp_text(timestamp) or '-'}"
    if canonical != value:
        raise OfficialRssPublicationError("The official RSS cursor is invalid.")
    return parts[1], timestamp


def _reject_unsafe_xml_declarations(body: bytes) -> None:
    lowered = body.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise OfficialRssXmlError("The official RSS XML declaration is unsafe.")
    stripped = body.lstrip(b"\xef\xbb\xbf\x20\t\r\n")
    processing = re.findall(br"<\?\s*([A-Za-z][A-Za-z0-9._-]*)", body)
    if processing:
        if processing != [b"xml"] or not stripped.lower().startswith(b"<?xml"):
            raise OfficialRssXmlError(
                "The official RSS XML processing instruction is unsafe."
            )


def _validate_xml_tree(root: ET.Element) -> None:
    count = 0
    stack = [(root, 0)]
    while stack:
        element, depth = stack.pop()
        count += 1
        if count > MAX_XML_NODES or depth > MAX_XML_DEPTH:
            raise OfficialRssXmlError("The official RSS XML exceeds policy.")
        stack.extend((child, depth + 1) for child in list(element))


def _local_name(tag: object) -> str:
    if not isinstance(tag, str):
        raise OfficialRssXmlError("The official RSS XML element is invalid.")
    return tag.rsplit("}", 1)[-1]


def _single_required(fields: Mapping[str, list[str]], name: str) -> str:
    values = fields.get(name, [])
    if len(values) != 1:
        raise OfficialRssEntryError("The official RSS entry is missing metadata.")
    return values[0]


def _plain_text(value: object, maximum: int, *, required: bool) -> str | None:
    if not isinstance(value, str):
        raise OfficialRssEntryError("The official RSS text is invalid.")
    parser = _PlainTextParser()
    try:
        parser.feed(value)
        parser.close()
    except Exception:
        raise OfficialRssEntryError("The official RSS text is invalid.") from None
    normalized = " ".join(unicodedata.normalize("NFC", " ".join(parser.parts)).split())
    if (
        required and not normalized
        or len(normalized) > maximum
        or any(unicodedata.category(character) == "Cc" for character in normalized)
    ):
        raise OfficialRssEntryError("The official RSS text is invalid.")
    return normalized or None


def _bounded_text(value: object, maximum: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        raise OfficialRssEntryError(f"The official RSS {label} is invalid.")
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 100:
        raise OfficialRssEntryError("The official RSS timestamp is invalid.")
    try:
        if re.match(r"^[A-Za-z]{3},", value.strip()):
            parsed = parsedate_to_datetime(value)
        else:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        raise OfficialRssEntryError("The official RSS timestamp is invalid.") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OfficialRssEntryError("The official RSS timestamp is invalid.")
    return parsed.astimezone(UTC)


def _timestamp_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


__all__ = [
    "MAX_FEED_ENTRIES",
    "MAX_PUBLICATION_RECORDS",
    "OfficialRssConflictError",
    "OfficialRssDocument",
    "OfficialRssEntryError",
    "OfficialRssPublicationError",
    "OfficialRssXmlError",
    "adapt_official_rss_feed",
    "build_official_rss_cursor",
    "parse_official_rss_cursor",
]
