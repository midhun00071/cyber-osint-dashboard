"""Adapter for the shared Google Cloud Threat Intelligence RSS publication feed."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from html import unescape
from html.parser import HTMLParser
import calendar
import re
from time import struct_time
from typing import Any
from urllib.parse import urlparse

import feedparser

from app.ingestion.collectors.google_threat_intelligence_rss_client import (
    GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
    MANDIANT_THREAT_RESEARCH_SOURCE_SLUG,
)
from app.ingestion.publication_pipeline import (
    MAX_PUBLICATION_EXTERNAL_ID_LENGTH,
    MAX_PUBLICATION_SUMMARY_LENGTH,
    MAX_PUBLICATION_TITLE_LENGTH,
    PublicationCandidate,
    PublicationCandidateError,
    PublicationSourceError,
    canonicalize_publication_url,
    normalize_publication_candidate,
)


MAX_GOOGLE_THREAT_FEED_ENTRIES = 100
MAX_GOOGLE_THREAT_AUTHORS = 20
MAX_GOOGLE_THREAT_CATEGORIES = 20
MAX_GOOGLE_THREAT_AUTHOR_LENGTH = 200
MAX_GOOGLE_THREAT_CATEGORY_LENGTH = 100
MAX_GOOGLE_THREAT_FEED_ID_LENGTH = 300
MAX_GOOGLE_THREAT_TIMESTAMP_LENGTH = 128
MAX_GOOGLE_THREAT_DIAGNOSTIC_BYTES = 65_536
MAX_GOOGLE_THREAT_DIAGNOSTIC_ITEMS = 512
MAX_GOOGLE_THREAT_DIAGNOSTIC_DEPTH = 8
GOOGLE_THREAT_PUBLICATION_HOST = "cloud.google.com"
GOOGLE_THREAT_PUBLICATION_PATH_PREFIX = "/blog/topics/threat-intelligence/"
GOOGLE_AUTHOR_NAME = "Google Threat Intelligence Group"
MANDIANT_AUTHOR_NAME = "Mandiant"
SUMMARY_HANDLING_UNSUPPORTED_MARKUP_OMITTED = "unsupported_markup_omitted"

_AUTHOR_TO_SOURCE_SLUG = {
    GOOGLE_AUTHOR_NAME: GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
    MANDIANT_AUTHOR_NAME: MANDIANT_THREAT_RESEARCH_SOURCE_SLUG,
}

GOOGLE_THREAT_VALIDATION_FAILURE_STAGES = frozenset(
    {
        "adapter.identity_invalid",
        "adapter.metadata_bounds_exceeded",
        "adapter.owner_unapproved",
        "adapter.record_invalid",
        "adapter.text_markup_unsupported",
        "adapter.text_too_long",
        "adapter.text_unsupported_characters",
        "adapter.timestamp_invalid",
        "adapter.title_required",
        "adapter.url_fields_conflict",
        "adapter.url_invalid",
        "adapter.url_path_unapproved",
        "pipeline.candidate_validation",
        "pipeline.source_policy",
    }
)
DEFAULT_GOOGLE_THREAT_VALIDATION_FAILURE_STAGE = "adapter.record_invalid"

_SKIPPED_CONTENT_TAGS = frozenset(
    {"script", "style", "iframe", "object", "embed", "svg", "math"}
)
_NON_VOID_SKIPPED_CONTENT_TAGS = frozenset(
    {"script", "style", "iframe", "object"}
)
_START_TAG_CONTENT = re.compile(
    r"""
    (?P<name>[A-Za-z][A-Za-z0-9:_-]*)
    (?:
        \s+
        [^\s\"'`=<>/]+
        (?:
            \s*=\s*
            (?:\"[^\"]*\"|'[^']*'|[^\s\"'`=<>]+)
        )?
    )*
    \s*(?P<self_closing>/)?\s*
    \Z
    """,
    re.VERBOSE,
)
_END_TAG_CONTENT = re.compile(
    r"\s*/\s*(?P<name>[A-Za-z][A-Za-z0-9:_-]*)\s*\Z"
)
_DECLARATION_CONTENT = re.compile(
    r"(?:DOCTYPE\s+[^<>]+|\[CDATA\[[^<>]*\]\])\Z",
    re.IGNORECASE,
)
_XML_WHITESPACE_CODEPOINTS = frozenset({0x09, 0x0A, 0x0D})


class GoogleThreatPublicationError(ValueError):
    """The Google/Mandiant publication feed could not be processed safely."""


class GoogleThreatFeedError(GoogleThreatPublicationError):
    """The shared publication feed envelope failed safe parsing."""


class GoogleThreatPublicationRecordError(GoogleThreatPublicationError):
    """One shared-feed publication record failed safe adaptation."""

    def __init__(
        self,
        message: str,
        *,
        source_slug: str | None = None,
        failure_stage: str = DEFAULT_GOOGLE_THREAT_VALIDATION_FAILURE_STAGE,
        diagnostic_fingerprint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.source_slug = source_slug
        self.failure_stage = (
            failure_stage
            if failure_stage in GOOGLE_THREAT_VALIDATION_FAILURE_STAGES
            else DEFAULT_GOOGLE_THREAT_VALIDATION_FAILURE_STAGE
        )
        self.diagnostic_fingerprint = (
            diagnostic_fingerprint
            if isinstance(diagnostic_fingerprint, str)
            and re.fullmatch(r"[0-9a-f]{64}", diagnostic_fingerprint)
            else None
        )


@dataclass(frozen=True, slots=True)
class GoogleThreatPublicationDocument:
    """Validated immutable feed entries awaiting per-entry adaptation."""

    entries: tuple[dict[str, Any], ...]
    was_truncated: bool = False


def parse_google_threat_feed_entries(
    feed_bytes: bytes,
    *,
    max_entries: int = MAX_GOOGLE_THREAT_FEED_ENTRIES,
) -> GoogleThreatPublicationDocument:
    """Parse bounded RSS/Atom feed bytes into raw feed entries."""

    if not isinstance(feed_bytes, bytes):
        raise GoogleThreatFeedError("The Google Threat feed must be supplied as bytes.")
    if (
        not isinstance(max_entries, int)
        or isinstance(max_entries, bool)
        or not 1 <= max_entries <= MAX_GOOGLE_THREAT_FEED_ENTRIES
    ):
        raise GoogleThreatFeedError("The Google Threat feed record limit is invalid.")
    parsed = feedparser.parse(feed_bytes)
    if parsed.bozo and not parsed.entries:
        raise GoogleThreatFeedError("The Google Threat feed could not be parsed safely.")
    entries = list(parsed.entries)
    return GoogleThreatPublicationDocument(
        entries=tuple(dict(entry) for entry in entries[:max_entries]),
        was_truncated=len(entries) > max_entries,
    )


def adapt_google_threat_publication(entry: object) -> PublicationCandidate:
    """Route one shared-feed entry to its exact GTIG or Mandiant source."""

    try:
        return _adapt_google_threat_publication(entry)
    except GoogleThreatPublicationRecordError as exc:
        if exc.diagnostic_fingerprint is None:
            exc.diagnostic_fingerprint = _diagnostic_entry_fingerprint(entry)
        raise
    except PublicationCandidateError as exc:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication record is invalid.",
            failure_stage="pipeline.candidate_validation",
            diagnostic_fingerprint=_diagnostic_entry_fingerprint(entry),
        ) from exc
    except PublicationSourceError as exc:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication record is invalid.",
            failure_stage="pipeline.source_policy",
            diagnostic_fingerprint=_diagnostic_entry_fingerprint(entry),
        ) from exc
    except (OverflowError, TypeError, UnicodeError, ValueError) as exc:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication record is invalid.",
            diagnostic_fingerprint=_diagnostic_entry_fingerprint(entry),
        ) from exc


def derive_google_threat_external_id(source_slug: str, canonical_url: str) -> str:
    """Derive a stable source-separated identifier from source slug and URL."""

    if source_slug not in _AUTHOR_TO_SOURCE_SLUG.values() or not isinstance(
        canonical_url, str
    ):
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication identity is invalid.",
            failure_stage="adapter.identity_invalid",
        )
    try:
        digest = sha256(
            f"{source_slug}\n{canonical_url}".encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication identity is invalid.",
            failure_stage="adapter.identity_invalid",
        ) from exc
    external_id = f"{source_slug}:url-sha256:{digest}"
    if len(external_id) > MAX_PUBLICATION_EXTERNAL_ID_LENGTH:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication identity is invalid.",
            failure_stage="adapter.identity_invalid",
        )
    return external_id


def _adapt_google_threat_publication(entry: object) -> PublicationCandidate:
    if not isinstance(entry, dict):
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication record is invalid."
        )
    source_slug, authoritative_author = _source_from_author(entry)
    try:
        title = _required_text(entry.get("title"), MAX_PUBLICATION_TITLE_LENGTH)
        canonical_url = _canonical_google_threat_url(source_slug, _entry_url_values(entry))
        summary, unsupported_summary_markup_omitted = _entry_summary(entry)
        published_at = _entry_datetime(entry, "published")
        modified_at = _entry_datetime(entry, "updated")
        authors = _bounded_unique_texts(
            _all_author_values(entry),
            maximum_items=MAX_GOOGLE_THREAT_AUTHORS,
            maximum_length=MAX_GOOGLE_THREAT_AUTHOR_LENGTH,
        )
        categories = _categories(entry.get("tags"))
        feed_id = _optional_text(
            entry.get("id") or entry.get("guid"),
            MAX_GOOGLE_THREAT_FEED_ID_LENGTH,
        )
        external_id = derive_google_threat_external_id(source_slug, canonical_url)
        payload: dict[str, object] = {
            "authoritative_author": authoritative_author,
            "authors": authors,
            "categories": categories,
        }
        if feed_id is not None:
            payload["feed_id"] = feed_id
        if unsupported_summary_markup_omitted:
            payload["summary_handling"] = (
                SUMMARY_HANDLING_UNSUPPORTED_MARKUP_OMITTED
            )
        candidate = PublicationCandidate(
            source_slug=source_slug,
            source_external_id=external_id,
            canonical_title=title,
            canonical_url=canonical_url,
            summary=summary,
            source_published_at=published_at,
            source_modified_at=modified_at,
            safe_source_payload=payload,
        )
        normalized = normalize_publication_candidate(candidate)
        return PublicationCandidate(
            source_slug=source_slug,
            source_external_id=normalized.source_external_id,
            canonical_title=normalized.canonical_title,
            canonical_url=normalized.canonical_url,
            summary=normalized.summary,
            source_published_at=normalized.source_published_at,
            source_modified_at=normalized.source_modified_at,
            safe_source_payload=normalized.raw_payload,
        )
    except GoogleThreatPublicationRecordError as exc:
        if exc.source_slug is None:
            raise GoogleThreatPublicationRecordError(
                str(exc),
                source_slug=source_slug,
                failure_stage=exc.failure_stage,
                diagnostic_fingerprint=exc.diagnostic_fingerprint,
            ) from exc
        raise
    except PublicationCandidateError as exc:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication record is invalid.",
            source_slug=source_slug,
            failure_stage="pipeline.candidate_validation",
        ) from exc
    except PublicationSourceError as exc:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication record is invalid.",
            source_slug=source_slug,
            failure_stage="pipeline.source_policy",
        ) from exc
    except (OverflowError, TypeError, UnicodeError, ValueError) as exc:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication record is invalid.",
            source_slug=source_slug,
        ) from exc


def _source_from_author(entry: dict[str, Any]) -> tuple[str, str]:
    owners = _authoritative_author_values(entry)
    approved = [owner for owner in owners if owner in _AUTHOR_TO_SOURCE_SLUG]
    if len(set(approved)) != 1 or len(set(owners)) != 1:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication author is not approved.",
            failure_stage="adapter.owner_unapproved",
        )
    owner = approved[0]
    return _AUTHOR_TO_SOURCE_SLUG[owner], owner


def _authoritative_author_values(entry: dict[str, Any]) -> list[str]:
    values: list[str] = []
    if "author" in entry:
        values.append(_normalize_author_field(entry.get("author")))
    if "author_detail" in entry:
        detail = entry.get("author_detail")
        if not isinstance(detail, dict) or "name" not in detail:
            raise GoogleThreatPublicationRecordError(
                "The Google Threat publication author is not approved.",
                failure_stage="adapter.owner_unapproved",
            )
        values.append(_normalize_author_field(detail.get("name")))
    if "authors" in entry:
        authors = entry.get("authors")
        if not isinstance(authors, list) or not authors:
            raise GoogleThreatPublicationRecordError(
                "The Google Threat publication author is not approved.",
                failure_stage="adapter.owner_unapproved",
            )
        for author in authors:
            if isinstance(author, dict):
                if "name" not in author:
                    raise GoogleThreatPublicationRecordError(
                        "The Google Threat publication author is not approved.",
                        failure_stage="adapter.owner_unapproved",
                    )
                values.append(_normalize_author_field(author.get("name")))
            elif isinstance(author, str):
                values.append(_normalize_author_field(author))
            else:
                raise GoogleThreatPublicationRecordError(
                    "The Google Threat publication author is not approved.",
                    failure_stage="adapter.owner_unapproved",
                )
    if not values:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication author is not approved.",
            failure_stage="adapter.owner_unapproved",
        )
    return values


def _all_author_values(entry: dict[str, Any]) -> list[object]:
    values = list(_authoritative_author_values(entry))
    creators = entry.get("contributors")
    if isinstance(creators, list):
        for creator in creators:
            if isinstance(creator, dict):
                values.append(creator.get("name"))
            else:
                values.append(creator)
    return values


def _normalize_author_field(value: object) -> str:
    if not isinstance(value, str):
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication author is not approved.",
            failure_stage="adapter.owner_unapproved",
        )
    normalized = re.sub(r"\s+", " ", value).strip()
    if not normalized:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication author is not approved.",
            failure_stage="adapter.owner_unapproved",
        )
    return normalized


def _entry_url_values(entry: dict[str, Any]) -> list[object]:
    values: list[object] = []
    for key in ("link", "feedburner_origlink", "feedburner_origLink", "origlink"):
        if key in entry:
            values.append(entry.get(key))
    links = entry.get("links")
    if isinstance(links, list):
        for link in links:
            if not isinstance(link, dict) or not link.get("href"):
                continue
            rel = link.get("rel")
            if rel is None or (isinstance(rel, str) and rel.strip().lower() in {"", "alternate"}):
                values.append(link.get("href"))
    return values


def _canonical_google_threat_url(source_slug: str, values: list[object]) -> str:
    accepted: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            raw_parsed = urlparse(value)
        except ValueError as exc:
            raise GoogleThreatPublicationRecordError(
                "The Google Threat publication URL is invalid.",
                failure_stage="adapter.url_invalid",
            ) from exc
        if raw_parsed.fragment or raw_parsed.params or ";" in raw_parsed.path:
            raise GoogleThreatPublicationRecordError(
                "The Google Threat publication URL is invalid.",
                failure_stage="adapter.url_invalid",
            )
        try:
            canonical = canonicalize_publication_url(source_slug, value)
        except PublicationCandidateError:
            if (raw_parsed.hostname or "").lower() == "feeds.feedburner.com":
                continue
            raise
        parsed = urlparse(canonical)
        path = parsed.path
        if (
            parsed.hostname != GOOGLE_THREAT_PUBLICATION_HOST
            or not path.startswith(GOOGLE_THREAT_PUBLICATION_PATH_PREFIX)
            or not path[len(GOOGLE_THREAT_PUBLICATION_PATH_PREFIX) :].strip("/")
            or "%"
            in path
            or "\\" in path
            or "\ufffd" in path
            or any(segment in {".", ".."} for segment in path.split("/"))
        ):
            raise GoogleThreatPublicationRecordError(
                "The Google Threat publication URL path is not approved.",
                failure_stage="adapter.url_path_unapproved",
            )
        accepted.append(canonical)
    unique = sorted(set(accepted))
    if not unique:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication URL is invalid.",
            failure_stage="adapter.url_invalid",
        )
    if len(unique) != 1:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication URL fields conflict.",
            failure_stage="adapter.url_fields_conflict",
        )
    return unique[0]


def _entry_summary(entry: dict[str, Any]) -> tuple[str | None, bool]:
    unsupported_markup_omitted = False
    for key in ("summary", "description"):
        try:
            text = _optional_summary_text(entry.get(key))
        except GoogleThreatPublicationRecordError as exc:
            if exc.failure_stage != "adapter.text_markup_unsupported":
                raise
            unsupported_markup_omitted = True
            continue
        if text:
            return text, unsupported_markup_omitted
    return None, unsupported_markup_omitted


def _entry_datetime(entry: dict[str, Any], field_name: str) -> datetime | None:
    entry_keys = set(entry.keys())
    if field_name not in entry_keys and f"{field_name}_parsed" not in entry_keys:
        return None
    parsed = entry.get(f"{field_name}_parsed")
    raw = entry.get(field_name)
    if parsed is None:
        if isinstance(raw, str) and raw.strip():
            raise GoogleThreatPublicationRecordError(
                "The Google Threat publication timestamp is invalid.",
                failure_stage="adapter.timestamp_invalid",
            )
        return None
    if not isinstance(parsed, struct_time):
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication timestamp is invalid.",
            failure_stage="adapter.timestamp_invalid",
        )
    if isinstance(raw, str) and len(raw) > MAX_GOOGLE_THREAT_TIMESTAMP_LENGTH:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication timestamp is invalid.",
            failure_stage="adapter.timestamp_invalid",
        )
    try:
        timestamp = calendar.timegm(parsed)
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication timestamp is invalid.",
            failure_stage="adapter.timestamp_invalid",
        ) from exc


def _categories(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    values: list[object] = []
    for item in value:
        values.append(item.get("term") if isinstance(item, dict) else item)
    return _bounded_unique_texts(
        values,
        maximum_items=MAX_GOOGLE_THREAT_CATEGORIES,
        maximum_length=MAX_GOOGLE_THREAT_CATEGORY_LENGTH,
    )


def _bounded_unique_texts(
    values: list[object],
    *,
    maximum_items: int,
    maximum_length: int,
) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        text = _optional_text(value, maximum_length)
        if text and text not in normalized:
            normalized.append(text)
    if len(normalized) > maximum_items:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication metadata list is too large.",
            failure_stage="adapter.metadata_bounds_exceeded",
        )
    return tuple(normalized)


def _required_text(value: object, maximum_length: int) -> str:
    text = _optional_text(value, maximum_length)
    if not text:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication title is required.",
            failure_stage="adapter.title_required",
        )
    return text


def _optional_text(value: object, maximum_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    _validate_safe_text(value)
    text = _plain_text(value)
    if len(text) > maximum_length:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication text is too long.",
            failure_stage="adapter.text_too_long",
        )
    _validate_safe_text(text)
    return text or None


def _optional_summary_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    _validate_safe_text(value)
    text = _plain_text(value)
    _validate_safe_text(text)
    return text[:MAX_PUBLICATION_SUMMARY_LENGTH] or None


def _plain_text(value: str) -> str:
    value = _unescape_repeated(value)
    _validate_markup_before_parsing(value)
    parser = _PlainTextParser()
    try:
        parser.feed(value)
        parser.close()
    except (AssertionError, ValueError) as exc:
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication text contains unsupported markup.",
            failure_stage="adapter.text_markup_unsupported",
        ) from exc
    text = re.sub(r"\s+", " ", _unescape_repeated(parser.text)).strip()
    if _contains_residual_markup(text):
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication text contains unsupported markup.",
            failure_stage="adapter.text_markup_unsupported",
        )
    return text


def _unescape_repeated(value: str) -> str:
    current = value
    for _ in range(3):
        next_value = unescape(current)
        if next_value == current:
            return current
        current = next_value
    return current


def _contains_residual_markup(value: str) -> bool:
    return bool(re.search(r"<\s*/?\s*[A-Za-z][^>]*>|<\s*[/!?]?\s*[A-Za-z]", value))


def _validate_markup_before_parsing(value: str) -> None:
    """Reject malformed tag-like input before HTMLParser can discard it."""

    active_tags: list[str] = []
    position = 0
    while position < len(value):
        opening = value.find("<", position)
        if opening == -1:
            break

        if value.startswith("<!--", opening):
            closing = value.find("-->", opening + 4)
            if closing == -1 or "--" in value[opening + 4 : closing]:
                _raise_unsupported_markup()
            position = closing + 3
            continue

        if value.startswith("<?", opening):
            closing = value.find("?>", opening + 2)
            if closing == -1 or not value[opening + 2 : closing].strip():
                _raise_unsupported_markup()
            position = closing + 2
            continue

        if value.startswith("<!", opening):
            closing = _find_tag_end(value, opening + 2)
            if closing is None or not _DECLARATION_CONTENT.fullmatch(
                value[opening + 2 : closing]
            ):
                _raise_unsupported_markup()
            position = closing + 1
            continue

        prefix = value[opening + 1 : opening + 2]
        closing_name = value[opening + 2 :].lstrip() if prefix == "/" else ""
        is_start_tag = prefix.isascii() and prefix.isalpha()
        is_end_tag = bool(
            closing_name
            and closing_name[0].isascii()
            and closing_name[0].isalpha()
        )
        if not is_start_tag and not is_end_tag:
            position = opening + 1
            continue

        closing = _find_tag_end(value, opening + 1)
        if closing is None:
            _raise_unsupported_markup()
        content = value[opening + 1 : closing]

        if content.startswith("/"):
            match = _END_TAG_CONTENT.fullmatch(content)
            if match is None:
                _raise_unsupported_markup()
            tag = match.group("name").lower()
            if tag in _SKIPPED_CONTENT_TAGS:
                if not active_tags or active_tags[-1] != tag:
                    _raise_unsupported_markup()
                active_tags.pop()
        else:
            match = _START_TAG_CONTENT.fullmatch(content)
            if match is None:
                _raise_unsupported_markup()
            tag = match.group("name").lower()
            is_self_closing = match.group("self_closing") is not None
            if tag in _NON_VOID_SKIPPED_CONTENT_TAGS and is_self_closing:
                _raise_unsupported_markup()
            if tag in _SKIPPED_CONTENT_TAGS and not is_self_closing:
                active_tags.append(tag)
        position = closing + 1

    if active_tags:
        _raise_unsupported_markup()


def _find_tag_end(value: str, position: int) -> int | None:
    quote: str | None = None
    for index in range(position, len(value)):
        character = value[index]
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "<":
            return None
        elif character == ">":
            return index
    return None


def _raise_unsupported_markup() -> None:
    raise GoogleThreatPublicationRecordError(
        "The Google Threat publication text contains unsupported markup.",
        failure_stage="adapter.text_markup_unsupported",
    )


def _validate_safe_text(value: str) -> None:
    if any(_is_unsupported_text_character(character) for character in value):
        raise GoogleThreatPublicationRecordError(
            "The Google Threat publication text contains unsupported characters.",
            failure_stage="adapter.text_unsupported_characters",
        )


def _diagnostic_entry_fingerprint(entry: object) -> str:
    """Return a bounded opaque fingerprint without retaining source values."""

    digest = sha256(b"google-threat-rejected-entry-v1\x00")
    remaining_bytes = MAX_GOOGLE_THREAT_DIAGNOSTIC_BYTES
    remaining_items = MAX_GOOGLE_THREAT_DIAGNOSTIC_ITEMS

    def add(value: bytes) -> None:
        nonlocal remaining_bytes
        digest.update(str(len(value)).encode("ascii"))
        digest.update(b":")
        if remaining_bytes <= 0:
            digest.update(b"limit")
            return
        bounded = value[:remaining_bytes]
        digest.update(bounded)
        remaining_bytes -= len(bounded)
        if len(bounded) != len(value):
            digest.update(b"truncated")

    def visit(value: object, depth: int) -> None:
        nonlocal remaining_items
        if remaining_items <= 0:
            add(b"item-limit")
            return
        remaining_items -= 1
        if depth > MAX_GOOGLE_THREAT_DIAGNOSTIC_DEPTH:
            add(b"depth-limit")
            return
        if value is None:
            add(b"none")
        elif isinstance(value, bool):
            add(b"bool:1" if value else b"bool:0")
        elif isinstance(value, str):
            add(b"str")
            add(str(len(value)).encode("ascii"))
            bounded_characters = value[: max(remaining_bytes, 1)]
            add(bounded_characters.encode("utf-8", errors="backslashreplace"))
        elif isinstance(value, bytes):
            add(b"bytes")
            add(value)
        elif isinstance(value, int):
            add(b"int")
            add(str(value).encode("ascii"))
        elif isinstance(value, float):
            add(b"float")
            add(value.hex().encode("ascii"))
        elif isinstance(value, dict):
            add(b"dict")
            for key, item in value.items():
                if remaining_items <= 0:
                    break
                visit(key, depth + 1)
                visit(item, depth + 1)
        elif isinstance(value, (list, tuple, struct_time)):
            add(b"sequence")
            for item in value:
                if remaining_items <= 0:
                    break
                visit(item, depth + 1)
        else:
            add(b"unsupported")
            add(type(value).__name__.encode("ascii", errors="backslashreplace"))

    try:
        visit(entry, 0)
    except Exception:
        digest.update(b"safe-fallback")
    return digest.hexdigest()


def _is_unsupported_text_character(character: str) -> bool:
    codepoint = ord(character)
    return (
        (codepoint < 0x20 and codepoint not in _XML_WHITESPACE_CODEPOINTS)
        or codepoint == 0x7F
        or 0xD800 <= codepoint <= 0xDFFF
    )


class _PlainTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._parts: list[str] = []

    @property
    def text(self) -> str:
        return "".join(self._parts)

    def handle_starttag(self, tag: str, attrs: object) -> None:
        del attrs
        if tag.lower() in _SKIPPED_CONTENT_TAGS:
            if not self._skip_depth:
                self._parts.append(" ")
            self._skip_depth += 1
        elif not self._skip_depth:
            self._parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in _SKIPPED_CONTENT_TAGS and self._skip_depth:
            self._skip_depth -= 1
            if not self._skip_depth:
                self._parts.append(" ")
        elif not self._skip_depth:
            self._parts.append(" ")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._parts.append(data)

    def handle_comment(self, data: str) -> None:
        del data
        if not self._skip_depth:
            self._parts.append(" ")

    def handle_decl(self, decl: str) -> None:
        del decl
        if not self._skip_depth:
            self._parts.append(" ")

    def unknown_decl(self, data: str) -> None:
        del data
        if not self._skip_depth:
            self._parts.append(" ")

    def handle_pi(self, data: str) -> None:
        del data
        if not self._skip_depth:
            self._parts.append(" ")
