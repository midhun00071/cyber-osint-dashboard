"""Strict local-file adapter for Anomali Cyber Watch publication metadata."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from html import unescape
import json
import math
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
import unicodedata
from urllib.parse import urlparse, urlunparse

from app.ingestion.publication_pipeline import (
    MAX_PUBLICATION_EXTERNAL_ID_LENGTH,
    MAX_PUBLICATION_SUMMARY_LENGTH,
    MAX_PUBLICATION_TITLE_LENGTH,
    MAX_PUBLICATION_URL_LENGTH,
    PublicationCandidate,
    PublicationCandidateError,
    PublicationSourceError,
    canonicalize_publication_url,
    normalize_publication_candidate,
)


ANOMALI_SCHEMA_VERSION = 1
ANOMALI_SOURCE_SLUG = "anomali-cyber-watch"
ANOMALI_PUBLICATION_HOST = "www.anomali.com"
ANOMALI_PATH_PREFIX = "/blog/anomali-cyber-watch-"
ANOMALI_TITLE_PREFIX = "Anomali Cyber Watch:"
MAX_ANOMALI_FILE_BYTES = 1024 * 1024
MAX_ANOMALI_PUBLICATIONS = 100
MAX_ANOMALI_JSON_DEPTH = 8
MAX_ANOMALI_JSON_STRING_LENGTH = MAX_PUBLICATION_SUMMARY_LENGTH
MAX_ANOMALI_AUTHORS = 20
MAX_ANOMALI_CATEGORIES = 20
MAX_ANOMALI_AUTHOR_LENGTH = 200
MAX_ANOMALI_CATEGORY_LENGTH = 100
MAX_ANOMALI_TIMESTAMP_LENGTH = 64
MAX_ANOMALI_PATH_COMPONENTS = 256
MAX_ANOMALI_ENTITY_DECODE_PASSES = 8

_TOP_LEVEL_FIELDS = frozenset({"schema_version", "source_slug", "publications"})
_PUBLICATION_FIELDS = frozenset(
    {
        "title",
        "url",
        "summary",
        "published_at",
        "modified_at",
        "authors",
        "categories",
    }
)
_ISO_DATETIME_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
_ARTICLE_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MARKUP_PATTERN = re.compile(
    r"<\s*/?\s*[A-Za-z][^>]*>|<\s*[/!?]?\s*[A-Za-z]|<!--|<!\[CDATA\[|<\?",
    re.IGNORECASE,
)
_EVENT_HANDLER_PATTERN = re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE)


class AnomaliPublicationError(ValueError):
    """Anomali Cyber Watch metadata could not be processed safely."""


class AnomaliPublicationFileError(AnomaliPublicationError):
    """The local Anomali catalogue failed bounded validation."""


class AnomaliPublicationRecordError(AnomaliPublicationError):
    """One Anomali Cyber Watch record failed safe adaptation."""


class _DuplicateJsonKeyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AnomaliPublicationDocument:
    """Validated immutable envelope with independently adaptable records."""

    source_slug: str
    publications: tuple[object, ...]


def load_anomali_publication_file(
    file_path: str | os.PathLike[str],
) -> AnomaliPublicationDocument:
    """Read one bounded local UTF-8 Anomali Cyber Watch catalogue."""

    raw_bytes = _read_bounded_regular_file(file_path)
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AnomaliPublicationFileError(
            "The Anomali publication file is not valid UTF-8 JSON."
        ) from exc

    try:
        payload = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        _validate_json_shape(payload)
    except (
        json.JSONDecodeError,
        _DuplicateJsonKeyError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise AnomaliPublicationFileError(
            "The Anomali publication file contains invalid JSON."
        ) from exc

    if not isinstance(payload, dict) or set(payload) != _TOP_LEVEL_FIELDS:
        raise AnomaliPublicationFileError(
            "The Anomali publication file schema is invalid."
        )
    if type(payload["schema_version"]) is not int or (
        payload["schema_version"] != ANOMALI_SCHEMA_VERSION
    ):
        raise AnomaliPublicationFileError(
            "The Anomali publication file schema version is unsupported."
        )
    if payload["source_slug"] != ANOMALI_SOURCE_SLUG:
        raise AnomaliPublicationFileError(
            "The Anomali publication source is not approved."
        )
    publications = payload["publications"]
    if not isinstance(publications, list):
        raise AnomaliPublicationFileError(
            "The Anomali publications value must be a list."
        )
    if len(publications) > MAX_ANOMALI_PUBLICATIONS:
        raise AnomaliPublicationFileError(
            "The Anomali publication file contains too many records."
        )
    return AnomaliPublicationDocument(
        source_slug=ANOMALI_SOURCE_SLUG,
        publications=tuple(_freeze_json_value(record) for record in publications),
    )


def adapt_anomali_publication(record: object) -> PublicationCandidate:
    """Convert one strict Cyber Watch record into a validated candidate."""

    try:
        return _adapt_anomali_publication(record)
    except AnomaliPublicationRecordError:
        raise
    except (
        PublicationCandidateError,
        PublicationSourceError,
        OverflowError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise AnomaliPublicationRecordError(
            "The Anomali publication record is invalid."
        ) from exc


def derive_anomali_external_id(canonical_url: str) -> str:
    """Derive the stable source-separated ID from the canonical article URL."""

    if not isinstance(canonical_url, str):
        raise AnomaliPublicationRecordError(
            "The Anomali publication identity is invalid."
        )
    try:
        digest = sha256(
            f"{ANOMALI_SOURCE_SLUG}\n{canonical_url}".encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AnomaliPublicationRecordError(
            "The Anomali publication identity is invalid."
        ) from exc
    external_id = f"{ANOMALI_SOURCE_SLUG}:url-sha256:{digest}"
    if len(external_id) > MAX_PUBLICATION_EXTERNAL_ID_LENGTH:
        raise AnomaliPublicationRecordError(
            "The Anomali publication identity is invalid."
        )
    return external_id


def _adapt_anomali_publication(record: object) -> PublicationCandidate:
    if not isinstance(record, Mapping) or set(record) != _PUBLICATION_FIELDS:
        raise AnomaliPublicationRecordError(
            "The Anomali publication record schema is invalid."
        )

    title = _required_plain_text(record["title"], MAX_PUBLICATION_TITLE_LENGTH)
    if not title.startswith(ANOMALI_TITLE_PREFIX) or not title[
        len(ANOMALI_TITLE_PREFIX) :
    ].strip():
        raise AnomaliPublicationRecordError(
            "The Anomali publication title family is not approved."
        )
    raw_url = _required_url_string(record["url"])
    canonical_url = _canonical_anomali_url(raw_url)
    summary = _optional_plain_text(record["summary"], MAX_PUBLICATION_SUMMARY_LENGTH)
    published_at = _required_timestamp(record["published_at"])
    modified_at = _optional_timestamp(record["modified_at"])
    if modified_at is not None and modified_at < published_at:
        raise AnomaliPublicationRecordError(
            "The Anomali publication timestamps are inconsistent."
        )
    authors = _plain_text_list(
        record["authors"],
        maximum_items=MAX_ANOMALI_AUTHORS,
        maximum_length=MAX_ANOMALI_AUTHOR_LENGTH,
    )
    categories = _plain_text_list(
        record["categories"],
        maximum_items=MAX_ANOMALI_CATEGORIES,
        maximum_length=MAX_ANOMALI_CATEGORY_LENGTH,
    )
    candidate = PublicationCandidate(
        source_slug=ANOMALI_SOURCE_SLUG,
        source_external_id=derive_anomali_external_id(canonical_url),
        canonical_title=title,
        canonical_url=canonical_url,
        summary=summary,
        source_published_at=published_at,
        source_modified_at=modified_at,
        safe_source_payload={"authors": authors, "categories": categories},
    )
    normalized = normalize_publication_candidate(candidate)
    return PublicationCandidate(
        source_slug=ANOMALI_SOURCE_SLUG,
        source_external_id=normalized.source_external_id,
        canonical_title=normalized.canonical_title,
        canonical_url=normalized.canonical_url,
        summary=normalized.summary,
        source_published_at=normalized.source_published_at,
        source_modified_at=normalized.source_modified_at,
        safe_source_payload=normalized.raw_payload,
    )


def _read_bounded_regular_file(file_path: str | os.PathLike[str]) -> bytes:
    try:
        raw_path = os.fspath(file_path)
    except TypeError as exc:
        raise AnomaliPublicationFileError(
            "The Anomali publication file path is invalid."
        ) from exc
    if (
        not isinstance(raw_path, str)
        or raw_path.casefold().startswith(("http://", "https://"))
        or _is_remote_or_device_path(raw_path)
    ):
        raise AnomaliPublicationFileError(
            "The Anomali publication file path must reference a local file."
        )

    descriptor = -1
    try:
        path = Path(os.path.abspath(raw_path))
        path_chain_before = _validate_local_path_chain(path)
        inspected = path_chain_before[-1]
        if not stat.S_ISREG(inspected.st_mode):
            raise AnomaliPublicationFileError(
                "The Anomali publication file must be a regular local file."
            )
        if inspected.st_size > MAX_ANOMALI_FILE_BYTES:
            raise AnomaliPublicationFileError(
                "The Anomali publication file exceeds the size limit."
            )

        open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        open_flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, open_flags)
        opened = os.fstat(descriptor)
        path_chain_opened = _validate_local_path_chain(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > MAX_ANOMALI_FILE_BYTES
            or not os.path.samestat(inspected, opened)
            or not _same_path_chain(path_chain_before, path_chain_opened)
        ):
            raise AnomaliPublicationFileError(
                "The Anomali publication file changed during safe validation."
            )

        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
        with stream:
            data = stream.read(MAX_ANOMALI_FILE_BYTES + 1)
            final = os.fstat(stream.fileno())
            path_chain_final = _validate_local_path_chain(path)
            if (
                not _same_file_snapshot(opened, final)
                or final.st_size > MAX_ANOMALI_FILE_BYTES
                or not _same_path_chain(path_chain_before, path_chain_final)
            ):
                raise AnomaliPublicationFileError(
                    "The Anomali publication file changed during safe reading."
                )
    except AnomaliPublicationFileError:
        raise
    except (OSError, ValueError) as exc:
        raise AnomaliPublicationFileError(
            "The Anomali publication file could not be read safely."
        ) from exc
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise AnomaliPublicationFileError(
                    "The Anomali publication file could not be read safely."
                ) from exc
    if len(data) > MAX_ANOMALI_FILE_BYTES:
        raise AnomaliPublicationFileError(
            "The Anomali publication file exceeds the size limit."
        )
    return data


def _is_remote_or_device_path(raw_path: str) -> bool:
    windows_path = raw_path.replace("/", "\\")
    folded_path = windows_path.casefold()
    return windows_path.startswith("\\\\") or folded_path.startswith(
        ("\\??\\", "\\device\\")
    )


def _validate_local_path_chain(path: Path) -> tuple[os.stat_result, ...]:
    parts = path.parts
    if len(parts) < 2 or len(parts) > MAX_ANOMALI_PATH_COMPONENTS:
        raise AnomaliPublicationFileError(
            "The Anomali publication file path is invalid."
        )
    current = Path(parts[0])
    metadata_chain: list[os.stat_result] = []
    for index, component in enumerate(parts[1:], start=1):
        current /= component
        metadata = current.lstat()
        if _is_link_or_reparse_point(metadata):
            raise AnomaliPublicationFileError(
                "The Anomali publication file path is not a direct local path."
            )
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise AnomaliPublicationFileError(
                "The Anomali publication file path is invalid."
            )
        metadata_chain.append(metadata)
    return tuple(metadata_chain)


def _is_link_or_reparse_point(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        reparse_flag and file_attributes & reparse_flag
    )


def _same_path_chain(
    before: tuple[os.stat_result, ...],
    after: tuple[os.stat_result, ...],
) -> bool:
    return len(before) == len(after) and all(
        os.path.samestat(before_item, after_item)
        for before_item, after_item in zip(before, after, strict=True)
    )


def _same_file_snapshot(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        os.path.samestat(before, after)
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError("Duplicate JSON key.")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    del value
    raise ValueError("Unsupported JSON constant.")


def _validate_json_shape(value: object, depth: int = 0) -> None:
    if depth > MAX_ANOMALI_JSON_DEPTH:
        raise ValueError("JSON nesting limit exceeded.")
    if isinstance(value, dict):
        for key, item in value.items():
            if len(key) > MAX_ANOMALI_JSON_STRING_LENGTH:
                raise ValueError("JSON key length limit exceeded.")
            _validate_json_shape(item, depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_shape(item, depth + 1)
        return
    if isinstance(value, str):
        if len(value) > MAX_ANOMALI_JSON_STRING_LENGTH:
            raise ValueError("JSON string length limit exceeded.")
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("JSON number is not finite.")
    if value is None or isinstance(value, (bool, int, float)):
        return
    raise TypeError("Unsupported JSON value.")


def _freeze_json_value(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_json_value(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json_value(item) for item in value)
    return value


def _required_string(value: object, maximum_length: int) -> str:
    if not isinstance(value, str):
        raise AnomaliPublicationRecordError(
            "The Anomali publication record contains invalid text."
        )
    _validate_safe_text(value)
    try:
        normalized = unicodedata.normalize("NFKC", value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AnomaliPublicationRecordError(
            "The Anomali publication record contains invalid text."
        ) from exc
    _validate_safe_text(normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    if not normalized or len(normalized) > maximum_length:
        raise AnomaliPublicationRecordError(
            "The Anomali publication record contains invalid text."
        )
    return normalized


def _required_url_string(value: object) -> str:
    if not isinstance(value, str):
        raise AnomaliPublicationRecordError(
            "The Anomali publication URL is invalid."
        )
    _validate_safe_text(value)
    normalized = value.strip(" ")
    if not normalized or len(normalized) > MAX_PUBLICATION_URL_LENGTH:
        raise AnomaliPublicationRecordError(
            "The Anomali publication URL is invalid."
        )
    return normalized


def _required_plain_text(value: object, maximum_length: int) -> str:
    text = _required_string(value, maximum_length)
    try:
        plain = unicodedata.normalize("NFKC", _unescape_repeated(text))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AnomaliPublicationRecordError(
            "The Anomali publication metadata must be plain text."
        ) from exc
    _validate_safe_text(plain)
    plain = re.sub(r"\s+", " ", plain).strip()
    if not plain or len(plain) > maximum_length:
        raise AnomaliPublicationRecordError(
            "The Anomali publication record contains invalid text."
        )
    if _MARKUP_PATTERN.search(plain) or _EVENT_HANDLER_PATTERN.search(plain):
        raise AnomaliPublicationRecordError(
            "The Anomali publication metadata must be plain text."
        )
    return plain


def _optional_plain_text(value: object, maximum_length: int) -> str | None:
    if value is None:
        return None
    return _required_plain_text(value, maximum_length)


def _unescape_repeated(value: str) -> str:
    current = value
    for _ in range(MAX_ANOMALI_ENTITY_DECODE_PASSES):
        next_value = unescape(current)
        if next_value == current:
            return current
        current = next_value
    if unescape(current) != current:
        raise AnomaliPublicationRecordError(
            "The Anomali publication metadata is excessively encoded."
        )
    return current


def _validate_safe_text(value: str) -> None:
    if "\ufffd" in value or any(
        ord(character) < 0x20
        or ord(character) == 0x7F
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        raise AnomaliPublicationRecordError(
            "The Anomali publication text contains unsupported characters."
        )


def _required_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise AnomaliPublicationRecordError(
            "The Anomali publication timestamp is invalid."
        )
    text = value.strip()
    if (
        not text
        or len(text) > MAX_ANOMALI_TIMESTAMP_LENGTH
        or _ISO_DATETIME_PATTERN.fullmatch(text) is None
    ):
        raise AnomaliPublicationRecordError(
            "The Anomali publication timestamp is invalid."
        )
    try:
        parsed = datetime.fromisoformat(
            f"{text[:-1]}+00:00" if text.endswith("Z") else text
        )
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("Naive timestamp.")
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise AnomaliPublicationRecordError(
            "The Anomali publication timestamp is invalid."
        ) from exc


def _optional_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    return _required_timestamp(value)


def _plain_text_list(
    value: object,
    *,
    maximum_items: int,
    maximum_length: int,
) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise AnomaliPublicationRecordError(
            "The Anomali publication metadata list is invalid."
        )
    if len(value) > maximum_items:
        raise AnomaliPublicationRecordError(
            "The Anomali publication metadata list is too large."
        )
    normalized: list[str] = []
    for item in value:
        text = _required_plain_text(item, maximum_length)
        if text not in normalized:
            normalized.append(text)
    return tuple(normalized)


def _canonical_anomali_url(raw_url: str) -> str:
    try:
        raw = urlparse(raw_url)
        raw_host = raw.hostname or ""
    except ValueError as exc:
        raise AnomaliPublicationRecordError(
            "The Anomali publication URL is invalid."
        ) from exc
    if (
        raw.fragment
        or raw.params
        or ";" in raw.path
        or "%" in raw.path
        or "//" in raw.path
        or "\\" in raw_url
        or raw_host.endswith(".")
    ):
        raise AnomaliPublicationRecordError(
            "The Anomali publication URL is invalid."
        )
    canonical = canonicalize_publication_url(ANOMALI_SOURCE_SLUG, raw_url)
    parsed = urlparse(canonical)
    if parsed.query or parsed.hostname != ANOMALI_PUBLICATION_HOST:
        raise AnomaliPublicationRecordError(
            "The Anomali publication URL contains unsupported query parameters."
        )
    path = parsed.path
    if path.endswith("/"):
        path = path[:-1]
    suffix = path[len(ANOMALI_PATH_PREFIX) :] if path.startswith(ANOMALI_PATH_PREFIX) else ""
    if (
        not suffix
        or _ARTICLE_SLUG_PATTERN.fullmatch(suffix) is None
        or "\\" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        raise AnomaliPublicationRecordError(
            "The Anomali publication URL path is not approved."
        )
    return urlunparse(("https", ANOMALI_PUBLICATION_HOST, path, "", "", ""))
