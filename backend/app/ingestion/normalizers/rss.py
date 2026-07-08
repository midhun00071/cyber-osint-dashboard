"""Pure normalization for approved RSS or Atom advisory feed entries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from html import unescape
from html.parser import HTMLParser
import json
import re
from time import struct_time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import calendar
import ipaddress

import feedparser


APPROVED_HOST = "cert.europa.eu"
MAX_TITLE_LENGTH = 500
MAX_SUMMARY_LENGTH = 10_000
MAX_ID_LENGTH = 300
MAX_URL_LENGTH = 2048
MAX_AUTHOR_LENGTH = 200
MAX_CATEGORY_LENGTH = 100
MAX_CATEGORIES = 20
TRACKING_PARAMS = {
    "gclid",
    "fbclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
    "campaign",
    "campaignid",
    "adgroupid",
    "creative",
}


class RssNormalizationError(ValueError):
    """An RSS feed or entry could not be safely normalized."""


@dataclass(frozen=True)
class NormalizedRssEntry:
    """Validated database-ready values derived from one feed entry."""

    source_external_id: str
    canonical_title: str
    summary: str | None
    canonical_url: str
    canonical_url_hash: str
    source_published_at: datetime | None
    source_modified_at: datetime | None
    content_hash: str
    raw_payload: dict[str, Any]


def parse_rss_feed_entries(feed_bytes: bytes) -> list[dict[str, Any]]:
    """Parse an RSS/Atom feed envelope and return raw feed entries."""

    if not isinstance(feed_bytes, bytes):
        raise RssNormalizationError("The RSS feed must be supplied as bytes.")
    parsed = feedparser.parse(feed_bytes)
    if parsed.bozo and not parsed.entries:
        raise RssNormalizationError("The RSS feed could not be parsed safely.")
    return list(parsed.entries)


def normalize_rss_feed(feed_bytes: bytes) -> list[NormalizedRssEntry]:
    """Parse and normalize RSS/Atom feed bytes without network or DB access."""

    records: list[NormalizedRssEntry] = []
    for entry in parse_rss_feed_entries(feed_bytes):
        records.append(normalize_rss_entry(entry))
    return records


def deduplicate_rss_entries(records: list[NormalizedRssEntry]) -> list[NormalizedRssEntry]:
    """Collapse exact duplicates and reject conflicting RSS duplicates."""

    by_external_id: dict[str, NormalizedRssEntry] = {}
    by_url_hash: dict[str, NormalizedRssEntry] = {}
    ordered: list[NormalizedRssEntry] = []
    for record in records:
        external_match = by_external_id.get(record.source_external_id)
        url_match = by_url_hash.get(record.canonical_url_hash)
        existing = external_match or url_match
        if existing is None:
            by_external_id[record.source_external_id] = record
            by_url_hash[record.canonical_url_hash] = record
            ordered.append(record)
            continue
        if (
            external_match is not None
            and external_match.canonical_url_hash != record.canonical_url_hash
        ) or (
            url_match is not None
            and url_match.source_external_id != record.source_external_id
        ) or existing.content_hash != record.content_hash:
            raise RssNormalizationError(
                "Conflicting duplicate RSS advisory entries were returned."
            )
    return ordered


def normalize_rss_entry(entry: object) -> NormalizedRssEntry:
    """Normalize one feedparser entry into a safe advisory record."""

    if not isinstance(entry, dict):
        raise RssNormalizationError("The RSS entry must be an object.")
    title = _required_text(entry.get("title"), "title", MAX_TITLE_LENGTH)
    canonical_url = canonicalize_advisory_url(_entry_link(entry))
    canonical_url_hash = sha256(canonical_url.encode("utf-8")).hexdigest()
    source_external_id = _source_external_id(entry, canonical_url)
    summary = _entry_summary(entry)
    published = _entry_datetime(entry, "published")
    modified = _entry_datetime(entry, "updated")
    raw_payload = _safe_payload(entry, source_external_id, published, modified)
    hash_payload = {
        "source_external_id": source_external_id,
        "canonical_title": title,
        "summary": summary,
        "canonical_url": canonical_url,
        "source_published_at": published.isoformat() if published else None,
        "source_modified_at": modified.isoformat() if modified else None,
        "raw_payload": raw_payload,
    }
    content_hash = sha256(_canonical_bytes(hash_payload)).hexdigest()
    return NormalizedRssEntry(
        source_external_id=source_external_id,
        canonical_title=title,
        summary=summary,
        canonical_url=canonical_url,
        canonical_url_hash=canonical_url_hash,
        source_published_at=published,
        source_modified_at=modified,
        content_hash=content_hash,
        raw_payload=raw_payload,
    )


def canonicalize_advisory_url(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RssNormalizationError("The RSS entry contains an invalid advisory URL.")
    try:
        parsed = urlparse(value.strip())
        scheme = parsed.scheme.lower()
        username = parsed.username
        password = parsed.password
        port = parsed.port
        host = (parsed.hostname or "").lower()
    except ValueError as exc:
        raise RssNormalizationError("The RSS advisory URL is invalid.") from exc
    if scheme != "https":
        raise RssNormalizationError("The RSS advisory URL must use HTTPS.")
    if username or password:
        raise RssNormalizationError("The RSS advisory URL must not contain credentials.")
    if port not in (None, 443):
        raise RssNormalizationError("The RSS advisory URL uses an unexpected port.")
    if host != APPROVED_HOST:
        raise RssNormalizationError("The RSS advisory URL host is not approved.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise RssNormalizationError("The RSS advisory URL host is not approved.")

    query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if not _is_tracking_param(key)
    ]
    query.sort()
    path = parsed.path or "/"
    canonical = urlunparse(
        (
            "https",
            host,
            path,
            "",
            urlencode(query, doseq=True),
            "",
        )
    )
    if len(canonical) > MAX_URL_LENGTH:
        raise RssNormalizationError("The RSS advisory URL exceeds the length limit.")
    return canonical


def _entry_link(entry: dict[str, Any]) -> object:
    link = entry.get("link")
    if link:
        return link
    links = entry.get("links")
    if isinstance(links, list):
        for candidate in links:
            if isinstance(candidate, dict) and candidate.get("href"):
                return candidate.get("href")
    raise RssNormalizationError("The RSS entry contains an invalid advisory URL.")


def _source_external_id(entry: dict[str, Any], canonical_url: str) -> str:
    for field_name in ("id", "guid"):
        value = entry.get(field_name)
        if isinstance(value, str) and value.strip():
            source_id = _bounded_text(_plain_text(value), MAX_ID_LENGTH)
            if source_id:
                return source_id
    return "url-sha256:" + sha256(canonical_url.encode("utf-8")).hexdigest()


def _entry_summary(entry: dict[str, Any]) -> str | None:
    for field_name in ("summary", "description"):
        value = entry.get(field_name)
        if isinstance(value, str) and value.strip():
            text = _bounded_text(_plain_text(value), MAX_SUMMARY_LENGTH)
            return text or None
    content = entry.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("value"), str):
                text = _bounded_text(_plain_text(item["value"]), MAX_SUMMARY_LENGTH)
                return text or None
    return None


def _entry_datetime(entry: dict[str, Any], field_name: str) -> datetime | None:
    entry_keys = set(entry.keys())
    if field_name not in entry_keys and f"{field_name}_parsed" not in entry_keys:
        return None
    parsed = entry.get(f"{field_name}_parsed")
    raw = entry.get(field_name)
    if parsed is None:
        if isinstance(raw, str) and raw.strip():
            raise RssNormalizationError("The RSS entry contains an invalid date.")
        return None
    if not isinstance(parsed, struct_time):
        raise RssNormalizationError("The RSS entry contains an invalid date.")
    try:
        timestamp = calendar.timegm(parsed)
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise RssNormalizationError("The RSS entry contains an invalid date.") from exc


def _safe_payload(
    entry: dict[str, Any],
    source_external_id: str,
    published: datetime | None,
    modified: datetime | None,
) -> dict[str, Any]:
    entry_keys = set(entry.keys())
    author = _optional_text(entry.get("author"), MAX_AUTHOR_LENGTH)
    categories = _categories(entry.get("tags"))
    payload: dict[str, Any] = {"source_id": source_external_id}
    if author is not None:
        payload["author"] = author
    if categories:
        payload["categories"] = categories
    if "published" in entry_keys and isinstance(entry.get("published"), str):
        payload["published"] = _bounded_text(_plain_text(entry["published"]), 100)
    if "updated" in entry_keys and isinstance(entry.get("updated"), str):
        payload["updated"] = _bounded_text(_plain_text(entry["updated"]), 100)
    if published is not None:
        payload["published_utc"] = published.isoformat()
    if modified is not None:
        payload["updated_utc"] = modified.isoformat()
    return json.loads(_canonical_bytes(payload))


def _categories(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    categories: list[str] = []
    for item in value[:MAX_CATEGORIES]:
        term = item.get("term") if isinstance(item, dict) else None
        text = _optional_text(term, MAX_CATEGORY_LENGTH)
        if text and text not in categories:
            categories.append(text)
    return categories


def _required_text(value: object, field_name: str, maximum_length: int) -> str:
    text = _optional_text(value, maximum_length)
    if not text:
        raise RssNormalizationError(f"The RSS entry {field_name} is required.")
    return text


def _optional_text(value: object, maximum_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = _bounded_text(_plain_text(value), maximum_length)
    return text or None


def _plain_text(value: str) -> str:
    parser = _PlainTextParser()
    parser.feed(value)
    parser.close()
    return re.sub(r"\s+", " ", unescape(parser.text)).strip()


def _bounded_text(value: str, maximum_length: int) -> str:
    return value[:maximum_length]


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RssNormalizationError("The RSS entry is not valid canonical JSON.") from exc


def _is_tracking_param(key: str) -> bool:
    lowered = key.lower()
    return lowered.startswith("utm_") or lowered in TRACKING_PARAMS


class _PlainTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._parts: list[str] = []

    @property
    def text(self) -> str:
        return " ".join(self._parts)

    def handle_starttag(self, tag: str, attrs) -> None:
        del attrs
        if tag.lower() in {"script", "style", "iframe", "object", "embed"}:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "iframe", "object", "embed"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._parts.append(data)
