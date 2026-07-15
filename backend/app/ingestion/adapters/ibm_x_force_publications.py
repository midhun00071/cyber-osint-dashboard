"""Strict local-file adapters for approved IBM X-Force publication metadata."""

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


IBM_X_FORCE_SCHEMA_VERSION = 1
IBM_X_FORCE_RESEARCH_SOURCE_SLUG = "ibm-x-force-public-research"
IBM_X_FORCE_OSINT_SOURCE_SLUG = "ibm-x-force-public-osint-advisories"
IBM_X_FORCE_RESEARCH_HOST = "www.ibm.com"
IBM_X_FORCE_OSINT_HOST = "exchange.xforce.ibmcloud.com"
IBM_X_FORCE_RESEARCH_PATH_PREFIX = "/think/x-force/"
MAX_IBM_X_FORCE_FILE_BYTES = 1024 * 1024
MAX_IBM_X_FORCE_PUBLICATIONS = 100
MAX_IBM_X_FORCE_JSON_DEPTH = 8
MAX_IBM_X_FORCE_JSON_STRING_LENGTH = MAX_PUBLICATION_SUMMARY_LENGTH
MAX_IBM_X_FORCE_AUTHORS = 20
MAX_IBM_X_FORCE_CATEGORIES = 20
MAX_IBM_X_FORCE_AUTHOR_LENGTH = 200
MAX_IBM_X_FORCE_CATEGORY_LENGTH = 100
MAX_IBM_X_FORCE_TIMESTAMP_LENGTH = 64
MAX_IBM_X_FORCE_PATH_COMPONENTS = 256
MAX_IBM_X_FORCE_ENTITY_DECODE_PASSES = 8

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
_RESEARCH_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_OSINT_PATH_PATTERN = re.compile(
    r"^/osint/guid%3[aA]([0-9A-Fa-f]{32})(/?)$"
)
_MARKUP_PATTERN = re.compile(
    r"<\s*/?\s*[A-Za-z][^>]*>|<\s*[/!?]?\s*[A-Za-z]|<!--|<!\[CDATA\[|<\?",
    re.IGNORECASE,
)
_EVENT_HANDLER_PATTERN = re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE)
# Empty values remain valid because the common tracking policy accepts them.
_RAW_QUERY_COMPONENT_PATTERN = re.compile(
    r"^[A-Za-z0-9._~-]+=[A-Za-z0-9._~-]*$"
)


@dataclass(frozen=True, slots=True)
class IbmXForceSourcePolicy:
    source_slug: str
    canonical_host: str
    base_url: str


IBM_X_FORCE_RESEARCH_POLICY = IbmXForceSourcePolicy(
    source_slug=IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
    canonical_host=IBM_X_FORCE_RESEARCH_HOST,
    base_url="https://www.ibm.com/think/x-force/",
)
IBM_X_FORCE_OSINT_POLICY = IbmXForceSourcePolicy(
    source_slug=IBM_X_FORCE_OSINT_SOURCE_SLUG,
    canonical_host=IBM_X_FORCE_OSINT_HOST,
    base_url="https://exchange.xforce.ibmcloud.com/osint/",
)
IBM_X_FORCE_SOURCE_POLICIES = MappingProxyType(
    {
        IBM_X_FORCE_RESEARCH_SOURCE_SLUG: IBM_X_FORCE_RESEARCH_POLICY,
        IBM_X_FORCE_OSINT_SOURCE_SLUG: IBM_X_FORCE_OSINT_POLICY,
    }
)


class IbmXForcePublicationError(ValueError):
    """IBM X-Force metadata could not be processed safely."""


class IbmXForcePublicationFileError(IbmXForcePublicationError):
    """The local IBM X-Force catalogue failed bounded validation."""


class IbmXForcePublicationRecordError(IbmXForcePublicationError):
    """One IBM X-Force publication record failed safe adaptation."""


class _DuplicateJsonKeyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IbmXForcePublicationDocument:
    """Validated immutable envelope for exactly one approved IBM source."""

    source_slug: str
    publications: tuple[object, ...]


def load_ibm_x_force_publication_file(
    file_path: str | os.PathLike[str],
) -> IbmXForcePublicationDocument:
    """Read one bounded local UTF-8 IBM X-Force metadata catalogue."""

    raw_bytes = _read_bounded_regular_file(file_path)
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication file is not valid UTF-8 JSON."
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
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication file contains invalid JSON."
        ) from exc

    if not isinstance(payload, dict) or set(payload) != _TOP_LEVEL_FIELDS:
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication file schema is invalid."
        )
    if type(payload["schema_version"]) is not int or (
        payload["schema_version"] != IBM_X_FORCE_SCHEMA_VERSION
    ):
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication file schema version is unsupported."
        )
    source_slug = payload["source_slug"]
    if not isinstance(source_slug, str) or source_slug not in IBM_X_FORCE_SOURCE_POLICIES:
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication source is not approved."
        )
    publications = payload["publications"]
    if not isinstance(publications, list):
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publications value must be a list."
        )
    if len(publications) > MAX_IBM_X_FORCE_PUBLICATIONS:
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication file contains too many records."
        )
    return IbmXForcePublicationDocument(
        source_slug=source_slug,
        publications=tuple(_freeze_json_value(record) for record in publications),
    )


def adapt_ibm_x_force_research_publication(record: object) -> PublicationCandidate:
    """Adapt one record owned by the exact IBM public research policy."""

    return _adapt_publication(record, IBM_X_FORCE_RESEARCH_POLICY)


def adapt_ibm_x_force_osint_advisory(record: object) -> PublicationCandidate:
    """Adapt one record owned by the exact IBM public OSINT advisory policy."""

    return _adapt_publication(record, IBM_X_FORCE_OSINT_POLICY)


def adapt_ibm_x_force_publication(
    source_slug: str,
    record: object,
) -> PublicationCandidate:
    """Dispatch only from an already validated fixed document source slug."""

    if source_slug == IBM_X_FORCE_RESEARCH_SOURCE_SLUG:
        return adapt_ibm_x_force_research_publication(record)
    if source_slug == IBM_X_FORCE_OSINT_SOURCE_SLUG:
        return adapt_ibm_x_force_osint_advisory(record)
    raise IbmXForcePublicationRecordError(
        "The IBM X-Force publication source is not approved."
    )


def derive_ibm_x_force_external_id(source_slug: str, canonical_url: str) -> str:
    """Derive one deterministic source-separated URL identity."""

    if source_slug not in IBM_X_FORCE_SOURCE_POLICIES or not isinstance(
        canonical_url, str
    ):
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication identity is invalid."
        )
    try:
        digest = sha256(f"{source_slug}\n{canonical_url}".encode("utf-8")).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication identity is invalid."
        ) from exc
    external_id = f"{source_slug}:url-sha256:{digest}"
    if len(external_id) > MAX_PUBLICATION_EXTERNAL_ID_LENGTH:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication identity is invalid."
        )
    return external_id


def _adapt_publication(
    record: object,
    policy: IbmXForceSourcePolicy,
) -> PublicationCandidate:
    try:
        return _adapt_publication_inner(record, policy)
    except IbmXForcePublicationRecordError:
        raise
    except (
        PublicationCandidateError,
        PublicationSourceError,
        OverflowError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication record is invalid."
        ) from exc


def _adapt_publication_inner(
    record: object,
    policy: IbmXForceSourcePolicy,
) -> PublicationCandidate:
    if not isinstance(record, Mapping) or set(record) != _PUBLICATION_FIELDS:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication record schema is invalid."
        )
    title = _required_plain_text(record["title"], MAX_PUBLICATION_TITLE_LENGTH)
    raw_url = _required_url_string(record["url"])
    canonical_url = (
        _canonical_research_url(raw_url)
        if policy is IBM_X_FORCE_RESEARCH_POLICY
        else _canonical_osint_url(raw_url)
    )
    summary = _optional_plain_text(record["summary"], MAX_PUBLICATION_SUMMARY_LENGTH)
    published_at = _required_timestamp(record["published_at"])
    modified_at = _optional_timestamp(record["modified_at"])
    if modified_at is not None and modified_at < published_at:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication timestamps are inconsistent."
        )
    authors = _plain_text_list(
        record["authors"],
        maximum_items=MAX_IBM_X_FORCE_AUTHORS,
        maximum_length=MAX_IBM_X_FORCE_AUTHOR_LENGTH,
    )
    categories = _plain_text_list(
        record["categories"],
        maximum_items=MAX_IBM_X_FORCE_CATEGORIES,
        maximum_length=MAX_IBM_X_FORCE_CATEGORY_LENGTH,
    )
    candidate = PublicationCandidate(
        source_slug=policy.source_slug,
        source_external_id=derive_ibm_x_force_external_id(
            policy.source_slug, canonical_url
        ),
        canonical_title=title,
        canonical_url=canonical_url,
        summary=summary,
        source_published_at=published_at,
        source_modified_at=modified_at,
        safe_source_payload={"authors": authors, "categories": categories},
    )
    normalized = normalize_publication_candidate(candidate)
    return PublicationCandidate(
        source_slug=policy.source_slug,
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
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication file path is invalid."
        ) from exc
    if (
        not isinstance(raw_path, str)
        or raw_path.casefold().startswith(("http://", "https://"))
        or _is_remote_or_device_path(raw_path)
    ):
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication file path must reference a local file."
        )

    descriptor = -1
    try:
        path = Path(os.path.abspath(raw_path))
        path_chain_before = _validate_local_path_chain(path)
        inspected = path_chain_before[-1]
        if not stat.S_ISREG(inspected.st_mode):
            raise IbmXForcePublicationFileError(
                "The IBM X-Force publication file must be a regular local file."
            )
        if inspected.st_size > MAX_IBM_X_FORCE_FILE_BYTES:
            raise IbmXForcePublicationFileError(
                "The IBM X-Force publication file exceeds the size limit."
            )
        open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        open_flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, open_flags)
        opened = os.fstat(descriptor)
        path_chain_opened = _validate_local_path_chain(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > MAX_IBM_X_FORCE_FILE_BYTES
            or not os.path.samestat(inspected, opened)
            or not _same_path_chain(path_chain_before, path_chain_opened)
        ):
            raise IbmXForcePublicationFileError(
                "The IBM X-Force publication file changed during safe validation."
            )
        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
        with stream:
            data = stream.read(MAX_IBM_X_FORCE_FILE_BYTES + 1)
            final = os.fstat(stream.fileno())
            path_chain_final = _validate_local_path_chain(path)
            if (
                not _same_file_snapshot(opened, final)
                or final.st_size > MAX_IBM_X_FORCE_FILE_BYTES
                or not _same_path_chain(path_chain_before, path_chain_final)
            ):
                raise IbmXForcePublicationFileError(
                    "The IBM X-Force publication file changed during safe reading."
                )
    except IbmXForcePublicationFileError:
        raise
    except (OSError, ValueError) as exc:
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication file could not be read safely."
        ) from exc
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise IbmXForcePublicationFileError(
                    "The IBM X-Force publication file could not be read safely."
                ) from exc
    if len(data) > MAX_IBM_X_FORCE_FILE_BYTES:
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication file exceeds the size limit."
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
    if len(parts) < 2 or len(parts) > MAX_IBM_X_FORCE_PATH_COMPONENTS:
        raise IbmXForcePublicationFileError(
            "The IBM X-Force publication file path is invalid."
        )
    current = Path(parts[0])
    metadata_chain: list[os.stat_result] = []
    for index, component in enumerate(parts[1:], start=1):
        current /= component
        metadata = current.lstat()
        if _is_link_or_reparse_point(metadata):
            raise IbmXForcePublicationFileError(
                "The IBM X-Force publication file path is not a direct local path."
            )
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise IbmXForcePublicationFileError(
                "The IBM X-Force publication file path is invalid."
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
    if depth > MAX_IBM_X_FORCE_JSON_DEPTH:
        raise ValueError("JSON nesting limit exceeded.")
    if isinstance(value, dict):
        for key, item in value.items():
            if len(key) > MAX_IBM_X_FORCE_JSON_STRING_LENGTH:
                raise ValueError("JSON key length limit exceeded.")
            _validate_json_shape(item, depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_shape(item, depth + 1)
        return
    if isinstance(value, str):
        if len(value) > MAX_IBM_X_FORCE_JSON_STRING_LENGTH:
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
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication record contains invalid text."
        )
    _validate_safe_text(value)
    try:
        normalized = unicodedata.normalize("NFKC", value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication record contains invalid text."
        ) from exc
    _validate_safe_text(normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    if not normalized or len(normalized) > maximum_length:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication record contains invalid text."
        )
    return normalized


def _required_url_string(value: object) -> str:
    if not isinstance(value, str):
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication URL is invalid."
        )
    _validate_safe_text(value)
    normalized = value.strip(" ")
    if not normalized or len(normalized) > MAX_PUBLICATION_URL_LENGTH:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication URL is invalid."
        )
    return normalized


def _required_plain_text(value: object, maximum_length: int) -> str:
    text = _required_string(value, maximum_length)
    try:
        plain = unicodedata.normalize("NFKC", _unescape_repeated(text))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication metadata must be plain text."
        ) from exc
    _validate_safe_text(plain)
    plain = re.sub(r"\s+", " ", plain).strip()
    if not plain or len(plain) > maximum_length:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication record contains invalid text."
        )
    if _MARKUP_PATTERN.search(plain) or _EVENT_HANDLER_PATTERN.search(plain):
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication metadata must be plain text."
        )
    return plain


def _optional_plain_text(value: object, maximum_length: int) -> str | None:
    if value is None:
        return None
    return _required_plain_text(value, maximum_length)


def _unescape_repeated(value: str) -> str:
    current = value
    for _ in range(MAX_IBM_X_FORCE_ENTITY_DECODE_PASSES):
        next_value = unescape(current)
        if next_value == current:
            return current
        current = next_value
    if unescape(current) != current:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication metadata is excessively encoded."
        )
    return current


def _validate_safe_text(value: str) -> None:
    if "\ufffd" in value or any(
        ord(character) < 0x20
        or ord(character) == 0x7F
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication text contains unsupported characters."
        )


def _required_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication timestamp is invalid."
        )
    text = value.strip()
    if (
        not text
        or len(text) > MAX_IBM_X_FORCE_TIMESTAMP_LENGTH
        or _ISO_DATETIME_PATTERN.fullmatch(text) is None
    ):
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication timestamp is invalid."
        )
    try:
        parsed = datetime.fromisoformat(
            f"{text[:-1]}+00:00" if text.endswith("Z") else text
        )
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("Naive timestamp.")
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication timestamp is invalid."
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
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication metadata list is invalid."
        )
    if len(value) > maximum_items:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication metadata list is too large."
        )
    normalized: list[str] = []
    for item in value:
        text = _required_plain_text(item, maximum_length)
        if text not in normalized:
            normalized.append(text)
    return tuple(normalized)


def _validate_raw_url(raw_url: str, expected_host: str) -> None:
    try:
        parsed = urlparse(raw_url)
    except ValueError as exc:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication URL is invalid."
        ) from exc
    try:
        raw_authority = parsed.netloc.encode("ascii").decode("ascii").lower()
    except UnicodeError as exc:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication URL is invalid."
        ) from exc
    allowed_authorities = {expected_host, f"{expected_host}:443"}
    if raw_authority not in allowed_authorities:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication URL is invalid."
        )

    # Delimiter presence is security-significant even when urlparse exposes an
    # empty fragment value.
    if "#" in raw_url:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication URL is invalid."
        )
    _validate_raw_query_syntax(raw_url)
    if (
        parsed.params
        or ";" in parsed.path
        or "\\" in raw_url
        or parsed.hostname != expected_host
    ):
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication URL is invalid."
        )


def _validate_raw_query_syntax(raw_url: str) -> None:
    if "?" not in raw_url:
        return
    raw_query = raw_url.partition("?")[2]
    components = raw_query.split("&")
    if (
        not raw_query
        or "?" in raw_query
        or any(not component for component in components)
        or any(
            _RAW_QUERY_COMPONENT_PATTERN.fullmatch(component) is None
            for component in components
        )
    ):
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force publication URL is invalid."
        )


def _canonical_research_url(raw_url: str) -> str:
    _validate_raw_url(raw_url, IBM_X_FORCE_RESEARCH_HOST)
    raw = urlparse(raw_url)
    if "%" in raw.path or "//" in raw.path:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force research URL path is not approved."
        )
    canonical = canonicalize_publication_url(
        IBM_X_FORCE_RESEARCH_SOURCE_SLUG, raw_url
    )
    parsed = urlparse(canonical)
    if parsed.query or parsed.hostname != IBM_X_FORCE_RESEARCH_HOST:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force research URL contains unsupported query parameters."
        )
    path = parsed.path
    if path.endswith("/"):
        path = path[:-1]
    suffix = (
        path[len(IBM_X_FORCE_RESEARCH_PATH_PREFIX) :]
        if path.startswith(IBM_X_FORCE_RESEARCH_PATH_PREFIX)
        else ""
    )
    if (
        not suffix
        or _RESEARCH_SLUG_PATTERN.fullmatch(suffix) is None
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force research URL path is not approved."
        )
    return urlunparse(("https", IBM_X_FORCE_RESEARCH_HOST, path, "", "", ""))


def _canonical_osint_url(raw_url: str) -> str:
    _validate_raw_url(raw_url, IBM_X_FORCE_OSINT_HOST)
    raw = urlparse(raw_url)
    match = _OSINT_PATH_PATTERN.fullmatch(raw.path)
    if match is None:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force OSINT advisory URL path is not approved."
        )
    canonical = canonicalize_publication_url(IBM_X_FORCE_OSINT_SOURCE_SLUG, raw_url)
    parsed = urlparse(canonical)
    if parsed.query or parsed.hostname != IBM_X_FORCE_OSINT_HOST:
        raise IbmXForcePublicationRecordError(
            "The IBM X-Force OSINT advisory URL contains unsupported query parameters."
        )
    guid = match.group(1).lower()
    path = f"/osint/guid%3A{guid}"
    return urlunparse(("https", IBM_X_FORCE_OSINT_HOST, path, "", "", ""))
