"""Strict local-file adapter for official public Censys publication metadata."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from urllib.parse import urlparse

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


CENSYS_SCHEMA_VERSION = 1
MAX_CENSYS_FILE_BYTES = 1024 * 1024
MAX_CENSYS_PUBLICATIONS = 100
MAX_CENSYS_JSON_DEPTH = 8
MAX_CENSYS_JSON_STRING_LENGTH = MAX_PUBLICATION_SUMMARY_LENGTH
MAX_CENSYS_AUTHORS = 20
MAX_CENSYS_CATEGORIES = 20
MAX_CENSYS_AUTHOR_LENGTH = 200
MAX_CENSYS_CATEGORY_LENGTH = 100
MAX_CENSYS_TIMESTAMP_LENGTH = 64
MAX_CENSYS_PATH_COMPONENTS = 256

CENSYS_ARC_RESEARCH_SLUG = "censys-arc-research"
CENSYS_RAPID_RESPONSE_SLUG = "censys-rapid-response-advisories"

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
_RAW_MARKUP_PATTERN = re.compile(
    r"<(?:"
    r"/?[A-Za-z][A-Za-z0-9:-]*(?=[\s/>])"
    r"|!--"
    r"|![A-Za-z][A-Za-z0-9:-]*(?=[\s\[>])"
    r"|!\[CDATA\["
    r"|\?[A-Za-z][A-Za-z0-9:_-]*(?=[\s?>])"
    r")",
    re.IGNORECASE,
)
@dataclass(frozen=True, slots=True)
class CensysSourcePolicy:
    """Fixed source-family rules that cannot be supplied by the JSON file."""

    path_prefix: str
    external_id_namespace: str


CENSYS_SOURCE_POLICIES = MappingProxyType(
    {
        CENSYS_ARC_RESEARCH_SLUG: CensysSourcePolicy(
            path_prefix="/blog/",
            external_id_namespace="arc-research",
        ),
        CENSYS_RAPID_RESPONSE_SLUG: CensysSourcePolicy(
            path_prefix="/advisory/",
            external_id_namespace="rapid-response",
        ),
    }
)


class CensysPublicationError(ValueError):
    """Censys publication metadata could not be processed safely."""


class CensysPublicationFileError(CensysPublicationError):
    """The local Censys metadata file failed bounded validation."""


class CensysPublicationRecordError(CensysPublicationError):
    """One Censys publication record failed safe adaptation."""


class _DuplicateJsonKeyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CensysPublicationDocument:
    """Validated immutable envelope with records left for per-item adaptation."""

    source_slug: str
    publications: tuple[object, ...]


def load_censys_publication_file(
    file_path: str | os.PathLike[str],
) -> CensysPublicationDocument:
    """Read and validate one bounded local UTF-8 Censys metadata file."""

    raw_bytes = _read_bounded_regular_file(file_path)
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CensysPublicationFileError(
            "The Censys publication file is not valid UTF-8 JSON."
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
        raise CensysPublicationFileError(
            "The Censys publication file contains invalid JSON."
        ) from exc

    if not isinstance(payload, dict) or set(payload) != _TOP_LEVEL_FIELDS:
        raise CensysPublicationFileError(
            "The Censys publication file schema is invalid."
        )
    if type(payload["schema_version"]) is not int or (
        payload["schema_version"] != CENSYS_SCHEMA_VERSION
    ):
        raise CensysPublicationFileError(
            "The Censys publication file schema version is unsupported."
        )
    source_slug = payload["source_slug"]
    if not isinstance(source_slug, str) or source_slug not in CENSYS_SOURCE_POLICIES:
        raise CensysPublicationFileError(
            "The Censys publication source is not approved."
        )
    publications = payload["publications"]
    if not isinstance(publications, list):
        raise CensysPublicationFileError(
            "The Censys publications value must be a list."
        )
    if len(publications) > MAX_CENSYS_PUBLICATIONS:
        raise CensysPublicationFileError(
            "The Censys publication file contains too many records."
        )
    return CensysPublicationDocument(
        source_slug=source_slug,
        publications=tuple(_freeze_json_value(record) for record in publications),
    )


def adapt_censys_publication(
    source_slug: str,
    record: object,
) -> PublicationCandidate:
    """Convert one strict Censys JSON record into a validated candidate."""

    try:
        return _adapt_censys_publication(source_slug, record)
    except CensysPublicationRecordError:
        raise
    except (
        PublicationCandidateError,
        PublicationSourceError,
        OverflowError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise CensysPublicationRecordError(
            "The Censys publication record is invalid."
        ) from exc


def derive_censys_external_id(source_slug: str, canonical_url: str) -> str:
    """Derive a stable source-family-separated identifier from a canonical URL."""

    policy = CENSYS_SOURCE_POLICIES.get(source_slug)
    if policy is None or not isinstance(canonical_url, str):
        raise CensysPublicationRecordError(
            "The Censys publication identity is invalid."
        )
    try:
        digest = sha256(canonical_url.encode("utf-8")).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CensysPublicationRecordError(
            "The Censys publication identity is invalid."
        ) from exc
    external_id = f"censys:{policy.external_id_namespace}:{digest}"
    if len(external_id) > MAX_PUBLICATION_EXTERNAL_ID_LENGTH:
        raise CensysPublicationRecordError(
            "The Censys publication identity is invalid."
        )
    return external_id


def _adapt_censys_publication(
    source_slug: str,
    record: object,
) -> PublicationCandidate:
    policy = CENSYS_SOURCE_POLICIES.get(source_slug)
    if policy is None or not isinstance(record, Mapping):
        raise CensysPublicationRecordError(
            "The Censys publication record is invalid."
        )
    if set(record) != _PUBLICATION_FIELDS:
        raise CensysPublicationRecordError(
            "The Censys publication record schema is invalid."
        )

    title = _required_plain_text(record["title"], MAX_PUBLICATION_TITLE_LENGTH)
    summary = _optional_summary(record["summary"])
    raw_url = _required_string(record["url"], MAX_PUBLICATION_URL_LENGTH)
    canonical_url = _canonical_censys_url(source_slug, raw_url, policy)
    published_at = _required_timestamp(record["published_at"])
    modified_at = _optional_timestamp(record["modified_at"])
    authors = _string_list(
        record["authors"],
        maximum_items=MAX_CENSYS_AUTHORS,
        maximum_length=MAX_CENSYS_AUTHOR_LENGTH,
    )
    categories = _string_list(
        record["categories"],
        maximum_items=MAX_CENSYS_CATEGORIES,
        maximum_length=MAX_CENSYS_CATEGORY_LENGTH,
    )
    external_id = derive_censys_external_id(source_slug, canonical_url)
    candidate = PublicationCandidate(
        source_slug=source_slug,
        source_external_id=external_id,
        canonical_title=title,
        canonical_url=canonical_url,
        summary=summary,
        source_published_at=published_at,
        source_modified_at=modified_at,
        safe_source_payload={
            "authors": authors,
            "categories": categories,
        },
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


def _read_bounded_regular_file(file_path: str | os.PathLike[str]) -> bytes:
    try:
        raw_path = os.fspath(file_path)
    except TypeError as exc:
        raise CensysPublicationFileError(
            "The Censys publication file path is invalid."
        ) from exc
    if (
        not isinstance(raw_path, str)
        or raw_path.casefold().startswith(("http://", "https://"))
        or _is_remote_or_device_path(raw_path)
    ):
        raise CensysPublicationFileError(
            "The Censys publication file path must reference a local file."
        )
    descriptor = -1
    try:
        path = Path(os.path.abspath(raw_path))
        path_chain_before = _validate_local_path_chain(path)
        metadata = path_chain_before[-1]
        if not stat.S_ISREG(metadata.st_mode):
            raise CensysPublicationFileError(
                "The Censys publication file must be a regular local file."
            )
        if metadata.st_size > MAX_CENSYS_FILE_BYTES:
            raise CensysPublicationFileError(
                "The Censys publication file exceeds the size limit."
            )

        open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        open_flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, open_flags)
        opened_metadata = os.fstat(descriptor)
        path_chain_after = _validate_local_path_chain(path)
        if (
            not stat.S_ISREG(opened_metadata.st_mode)
            or opened_metadata.st_size > MAX_CENSYS_FILE_BYTES
            or not os.path.samestat(metadata, opened_metadata)
            or not _same_path_chain(path_chain_before, path_chain_after)
        ):
            raise CensysPublicationFileError(
                "The Censys publication file changed during safe validation."
            )

        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
        with stream:
            data = stream.read(MAX_CENSYS_FILE_BYTES + 1)
    except CensysPublicationFileError:
        raise
    except (OSError, ValueError) as exc:
        raise CensysPublicationFileError(
            "The Censys publication file could not be read safely."
        ) from exc
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if len(data) > MAX_CENSYS_FILE_BYTES:
        raise CensysPublicationFileError(
            "The Censys publication file exceeds the size limit."
        )
    return data


def _is_remote_or_device_path(raw_path: str) -> bool:
    """Reject Windows remote/device namespaces before any filesystem traversal."""

    windows_path = raw_path.replace("/", "\\")
    folded_path = windows_path.casefold()
    return windows_path.startswith("\\\\") or folded_path.startswith(
        ("\\??\\", "\\device\\")
    )


def _validate_local_path_chain(path: Path) -> tuple[os.stat_result, ...]:
    parts = path.parts
    if len(parts) < 2 or len(parts) > MAX_CENSYS_PATH_COMPONENTS:
        raise CensysPublicationFileError(
            "The Censys publication file path is invalid."
        )

    current = Path(parts[0])
    metadata_chain: list[os.stat_result] = []
    for index, component in enumerate(parts[1:], start=1):
        current /= component
        metadata = current.lstat()
        if _is_link_or_reparse_point(metadata):
            raise CensysPublicationFileError(
                "The Censys publication file path is not a direct local path."
            )
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise CensysPublicationFileError(
                "The Censys publication file path is invalid."
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
    if depth > MAX_CENSYS_JSON_DEPTH:
        raise ValueError("JSON nesting limit exceeded.")
    if isinstance(value, dict):
        for key, item in value.items():
            if len(key) > MAX_CENSYS_JSON_STRING_LENGTH:
                raise ValueError("JSON key length limit exceeded.")
            _validate_json_shape(item, depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_shape(item, depth + 1)
        return
    if isinstance(value, str):
        if len(value) > MAX_CENSYS_JSON_STRING_LENGTH:
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
    if not isinstance(value, str) or not value.isprintable():
        raise CensysPublicationRecordError(
            "The Censys publication record contains invalid text."
        )
    normalized = value.strip()
    if not normalized or len(normalized) > maximum_length:
        raise CensysPublicationRecordError(
            "The Censys publication record contains invalid text."
        )
    return normalized


def _optional_summary(value: object) -> str | None:
    if value is None:
        return None
    return _required_plain_text(value, MAX_PUBLICATION_SUMMARY_LENGTH)


def _required_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.isprintable():
        raise CensysPublicationRecordError(
            "The Censys publication timestamp is invalid."
        )
    text = value.strip()
    if not text or len(text) > MAX_CENSYS_TIMESTAMP_LENGTH or "T" not in text.upper():
        raise CensysPublicationRecordError(
            "The Censys publication timestamp is invalid."
        )
    try:
        normalized = f"{text[:-1]}+00:00" if text.endswith("Z") else text
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("Naive timestamp.")
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise CensysPublicationRecordError(
            "The Censys publication timestamp is invalid."
        ) from exc


def _optional_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    return _required_timestamp(value)


def _string_list(
    value: object,
    *,
    maximum_items: int,
    maximum_length: int,
) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise CensysPublicationRecordError(
            "The Censys publication metadata list is invalid."
        )
    if len(value) > maximum_items:
        raise CensysPublicationRecordError(
            "The Censys publication metadata list is too large."
        )
    return [_required_plain_text(item, maximum_length) for item in value]


def _required_plain_text(value: object, maximum_length: int) -> str:
    text = _required_string(value, maximum_length)
    if _RAW_MARKUP_PATTERN.search(text):
        raise CensysPublicationRecordError(
            "The Censys publication metadata must be plain text."
        )
    return text


def _canonical_censys_url(
    source_slug: str,
    raw_url: str,
    policy: CensysSourcePolicy,
) -> str:
    try:
        raw_parsed = urlparse(raw_url)
    except ValueError as exc:
        raise CensysPublicationRecordError(
            "The Censys publication URL is invalid."
        ) from exc
    if raw_parsed.fragment or raw_parsed.params or ";" in raw_parsed.path:
        raise CensysPublicationRecordError(
            "The Censys publication URL is invalid."
        )
    canonical = canonicalize_publication_url(source_slug, raw_url)
    parsed = urlparse(canonical)
    if parsed.query:
        raise CensysPublicationRecordError(
            "The Censys publication URL contains unsupported query parameters."
        )
    canonical_path = parsed.path
    if (
        not canonical_path.startswith(policy.path_prefix)
        or not canonical_path[len(policy.path_prefix) :].strip("/")
        or "%" in canonical_path
        or ";" in canonical_path
        or parsed.params
    ):
        raise CensysPublicationRecordError(
            "The Censys publication URL path is not approved."
        )
    path_segments = canonical_path.split("/")
    if (
        not canonical_path.isprintable()
        or "\ufffd" in canonical_path
        or "\\" in canonical_path
        or any(segment in {".", ".."} for segment in path_segments)
    ):
        raise CensysPublicationRecordError(
            "The Censys publication URL path is not approved."
        )
    return canonical
