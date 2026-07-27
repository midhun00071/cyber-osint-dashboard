"""Bounded immutable JSON loading for explicit offline STIX input formats."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import math
import os
from pathlib import Path
import stat
from types import MappingProxyType
from typing import Mapping
from uuid import RFC_4122, UUID

from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    StixInputTransport,
    validate_stix_source_policy,
)


MAX_PATH_COMPONENTS = 256


class StixBoundedJsonError(ValueError):
    """An offline STIX document failed bounded safe loading."""


class StixDocumentFormat(str, Enum):
    """Explicit JSON document shapes accepted by this unit."""

    STIX_BUNDLE = "stix_bundle"
    TAXII_ENVELOPE = "taxii_envelope"


@dataclass(frozen=True, slots=True)
class BoundedStixDocument:
    """Immutable bounded STIX objects plus safe envelope metadata."""

    document_format: StixDocumentFormat
    objects: tuple[Mapping[str, object], ...]
    bundle_id: str | None = None
    more: bool | None = None
    next_token: str | None = None


class _DuplicateKeyError(ValueError):
    pass


def load_stix_json_file(
    file_path: str | os.PathLike[str],
    policy: ApprovedStixSourcePolicy,
    document_format: StixDocumentFormat,
) -> BoundedStixDocument:
    """Read one explicit local file safely, then parse its bounded JSON."""

    approved = validate_stix_source_policy(policy)
    data = _read_bounded_regular_file(file_path, approved.maximum_file_bytes)
    return parse_stix_json_bytes(data, approved, document_format)


def parse_stix_json_bytes(
    data: bytes,
    policy: ApprovedStixSourcePolicy,
    document_format: StixDocumentFormat,
) -> BoundedStixDocument:
    """Parse already bounded bytes without accepting ambiguous document forms."""

    approved = validate_stix_source_policy(policy)
    if not isinstance(data, bytes):
        raise StixBoundedJsonError("STIX input must be bytes.")
    if len(data) > approved.maximum_file_bytes:
        raise StixBoundedJsonError("STIX input exceeds the byte limit.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise StixBoundedJsonError("STIX input is not valid UTF-8.") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_json_shape(parsed, approved)
    except (_DuplicateKeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise StixBoundedJsonError("STIX JSON is invalid or exceeds safe limits.") from exc
    if not isinstance(parsed, dict):
        raise StixBoundedJsonError("STIX document must be a JSON object.")
    try:
        explicit_format = (
            document_format
            if isinstance(document_format, StixDocumentFormat)
            else StixDocumentFormat(document_format)
        )
    except (TypeError, ValueError) as exc:
        raise StixBoundedJsonError("STIX document format is not supported.") from exc
    return _validate_document_shape(parsed, approved, explicit_format)


def thaw_json(value: object) -> object:
    """Return JSON-compatible mutable containers for parser/database boundaries."""

    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def _validate_document_shape(
    parsed: dict[str, object],
    policy: ApprovedStixSourcePolicy,
    document_format: StixDocumentFormat,
) -> BoundedStixDocument:
    if document_format is StixDocumentFormat.STIX_BUNDLE:
        if policy.allowed_transport is not StixInputTransport.LOCAL_BUNDLE:
            raise StixBoundedJsonError("Policy does not allow STIX bundle input.")
        if set(parsed) - {"type", "id", "objects"}:
            raise StixBoundedJsonError("STIX bundle contains unexpected properties.")
        if parsed.get("type") != "bundle":
            raise StixBoundedJsonError("STIX bundle type is invalid.")
        bundle_id = _validate_optional_bundle_id(parsed.get("id"))
        objects = parsed.get("objects")
        more = None
        next_token = None
    else:
        if policy.allowed_transport is not StixInputTransport.TAXII_ENVELOPE_FIXTURE:
            raise StixBoundedJsonError("Policy does not allow TAXII fixture input.")
        if set(parsed) - {"objects", "more", "next"}:
            raise StixBoundedJsonError("TAXII fixture contains unexpected properties.")
        objects = parsed.get("objects")
        more = parsed.get("more")
        if more is not None and type(more) is not bool:
            raise StixBoundedJsonError("TAXII more flag must be a boolean.")
        next_token = parsed.get("next")
        if next_token is not None and (
            not isinstance(next_token, str)
            or not next_token
            or len(next_token) > policy.maximum_json_string_length
            or more is not True
        ):
            raise StixBoundedJsonError("TAXII next token is invalid.")
        bundle_id = None
    if not isinstance(objects, list):
        raise StixBoundedJsonError("STIX objects must be a list.")
    if len(objects) > policy.maximum_objects:
        raise StixBoundedJsonError("STIX object count exceeds the policy limit.")
    if any(not isinstance(item, dict) for item in objects):
        raise StixBoundedJsonError("Every STIX object must be a JSON object.")
    frozen_objects = tuple(_freeze_json(item) for item in objects)
    return BoundedStixDocument(
        document_format=document_format,
        objects=frozen_objects,
        bundle_id=bundle_id,
        more=more,
        next_token=next_token,
    )


def _read_bounded_regular_file(
    file_path: str | os.PathLike[str],
    maximum_bytes: int,
) -> bytes:
    try:
        raw_path = os.fspath(file_path)
    except TypeError as exc:
        raise StixBoundedJsonError("STIX file path is invalid.") from exc
    if not isinstance(raw_path, str) or _is_remote_or_device_path(raw_path):
        raise StixBoundedJsonError("STIX file must be a direct local path.")

    descriptor = -1
    data = b""
    try:
        path = Path(os.path.abspath(raw_path))
        before_chain = _validate_path_chain(path)
        inspected = before_chain[-1]
        if not stat.S_ISREG(inspected.st_mode):
            raise StixBoundedJsonError("STIX file must be a regular local file.")
        if inspected.st_size > maximum_bytes:
            raise StixBoundedJsonError("STIX file exceeds the byte limit.")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        opened_chain = _validate_path_chain(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > maximum_bytes
            or not os.path.samestat(inspected, opened)
            or not _same_path_chain(before_chain, opened_chain)
        ):
            raise StixBoundedJsonError("STIX file changed during safe validation.")
        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
        with stream:
            data = stream.read(maximum_bytes + 1)
            final = os.fstat(stream.fileno())
            final_chain = _validate_path_chain(path)
            if (
                not _same_file_snapshot(opened, final)
                or final.st_size > maximum_bytes
                or not _same_path_chain(before_chain, final_chain)
            ):
                raise StixBoundedJsonError("STIX file changed during safe reading.")
    except StixBoundedJsonError:
        raise
    except (OSError, ValueError) as exc:
        raise StixBoundedJsonError("STIX file could not be read safely.") from exc
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise StixBoundedJsonError("STIX file could not be read safely.") from exc
    if len(data) > maximum_bytes:
        raise StixBoundedJsonError("STIX file exceeds the byte limit.")
    return data


def _validate_optional_bundle_id(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 44 or not value.startswith("bundle--"):
        raise StixBoundedJsonError("STIX bundle identifier is invalid.")
    uuid_text = value.removeprefix("bundle--")
    try:
        identifier = UUID(uuid_text)
    except ValueError as exc:
        raise StixBoundedJsonError("STIX bundle identifier is invalid.") from exc
    if str(identifier) != uuid_text or identifier.variant != RFC_4122:
        raise StixBoundedJsonError("STIX bundle identifier is invalid.")
    return value


def _is_remote_or_device_path(raw_path: str) -> bool:
    windows_path = raw_path.replace("/", "\\")
    folded = windows_path.casefold()
    return windows_path.startswith("\\\\") or folded.startswith(
        ("\\??\\", "\\device\\", "\\.\\")
    )


def _validate_path_chain(path: Path) -> tuple[os.stat_result, ...]:
    parts = path.parts
    if len(parts) < 2 or len(parts) > MAX_PATH_COMPONENTS:
        raise StixBoundedJsonError("STIX file path is invalid.")
    current = Path(parts[0])
    chain: list[os.stat_result] = []
    for index, component in enumerate(parts[1:], start=1):
        current /= component
        metadata = current.lstat()
        if _is_link_or_reparse(metadata):
            raise StixBoundedJsonError("STIX file path is not a direct local path.")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise StixBoundedJsonError("STIX file path is invalid.")
        chain.append(metadata)
    return tuple(chain)


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(reparse and attributes & reparse)


def _same_path_chain(
    before: tuple[os.stat_result, ...],
    after: tuple[os.stat_result, ...],
) -> bool:
    return len(before) == len(after) and all(
        os.path.samestat(left, right)
        for left, right in zip(before, after, strict=True)
    )


def _same_file_snapshot(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        os.path.samestat(before, after)
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError("Duplicate JSON key.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    del value
    raise ValueError("Non-standard JSON constant.")


def _validate_json_shape(value: object, policy: ApprovedStixSourcePolicy) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > policy.maximum_json_nodes:
            raise ValueError("JSON node limit exceeded.")
        if depth > policy.maximum_json_depth:
            raise ValueError("JSON depth limit exceeded.")
        if isinstance(current, dict):
            if len(current) > policy.maximum_json_nodes:
                raise ValueError("JSON object size limit exceeded.")
            for key, item in current.items():
                if len(key) > policy.maximum_json_string_length:
                    raise ValueError("JSON key length limit exceeded.")
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            if len(current) > policy.maximum_json_nodes:
                raise ValueError("JSON list size limit exceeded.")
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            if len(current) > policy.maximum_json_string_length:
                raise ValueError("JSON string length limit exceeded.")
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("JSON number must be finite.")
        elif current is not None and not isinstance(current, (bool, int)):
            raise TypeError("Unsupported JSON value.")


def _freeze_json(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value
