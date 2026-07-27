"""Strict observable and safe-payload mapping for validated STIX objects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
import json
import re
from types import MappingProxyType
from typing import Mapping

from app.indicators.value_normalization import (
    IndicatorValueError,
    NormalizedObservable,
    normalize_observable,
)
from app.ingestion.stix_taxii.bounded_json import thaw_json


_SIMPLE_PATTERN_RE = re.compile(
    r"^\[(?P<path>ipv4-addr:value|ipv6-addr:value|domain-name:value|url:value|"
    r"file:hashes\.'(?:MD5|SHA-1|SHA-256|SHA-512)')\s*=\s*"
    r"'(?P<value>[^'\\]{1,2048})'\]$"
)
_HASH_NAMES = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA-512": "sha512",
}
_PATH_TYPES = {
    "ipv4-addr:value": "ipv4",
    "ipv6-addr:value": "ipv6",
    "domain-name:value": "domain",
    "url:value": "url",
}


class StixObjectMappingError(ValueError):
    """A validated STIX object cannot be represented by the safe mapper."""


@dataclass(frozen=True, slots=True)
class StixMappedObservable:
    """One normalized P9-08 observable derived from a STIX object."""

    normalized: NormalizedObservable
    confidence: Decimal | None
    observed_at: datetime | None
    context_summary: str


@dataclass(frozen=True, slots=True)
class StagedStixObject:
    """Allow-listed immutable representation suitable for SourceRecord staging."""

    stix_type: str
    stix_id: str
    created: datetime | None
    modified: datetime | None
    safe_payload: Mapping[str, object]
    content_hash: str
    observables: tuple[StixMappedObservable, ...]


def direct_observables(
    obj: Mapping[str, object],
    *,
    confidence: Decimal | None,
    observed_at: datetime | None,
) -> tuple[StixMappedObservable, ...]:
    """Map one supported SCO without retrieving or evaluating anything."""

    stix_type = obj["type"]
    pairs: list[tuple[str, str, str | None]] = []
    if stix_type in {"ipv4-addr", "ipv6-addr", "domain-name", "url"}:
        value = obj.get("value")
        if not isinstance(value, str):
            raise StixObjectMappingError("STIX observable value is invalid.")
        observable_type = {
            "ipv4-addr": "ipv4",
            "ipv6-addr": "ipv6",
            "domain-name": "domain",
            "url": "url",
        }[stix_type]
        pairs.append((observable_type, value, None))
    elif stix_type == "file":
        hashes = obj.get("hashes")
        if not isinstance(hashes, Mapping) or not hashes:
            raise StixObjectMappingError("STIX file requires approved hashes.")
        unsupported = set(hashes) - set(_HASH_NAMES)
        if unsupported:
            raise StixObjectMappingError("STIX file hash algorithm is unsupported.")
        for name in sorted(hashes):
            value = hashes[name]
            if not isinstance(value, str):
                raise StixObjectMappingError("STIX file hash is invalid.")
            pairs.append(("file_hash", value, _HASH_NAMES[name]))
    else:
        return ()
    return tuple(
        _mapped_observable(
            observable_type,
            value,
            hash_algorithm,
            confidence,
            observed_at,
            f"STIX {stix_type} object",
        )
        for observable_type, value, hash_algorithm in pairs
    )


def indicator_pattern_observable(
    obj: Mapping[str, object],
    *,
    confidence: Decimal | None,
    observed_at: datetime | None,
) -> StixMappedObservable:
    """Enforce the project single-equality pattern subset after STIX validation."""

    pattern = obj.get("pattern")
    if not isinstance(pattern, str):
        raise StixObjectMappingError("STIX Indicator pattern is invalid.")
    match = _SIMPLE_PATTERN_RE.fullmatch(pattern)
    if match is None:
        raise StixObjectMappingError("STIX Indicator pattern is outside the safe subset.")
    path = match.group("path")
    value = match.group("value")
    if path in _PATH_TYPES:
        observable_type = _PATH_TYPES[path]
        hash_algorithm = None
    else:
        hash_name = path.split("'", 2)[1]
        observable_type = "file_hash"
        hash_algorithm = _HASH_NAMES[hash_name]
    return _mapped_observable(
        observable_type,
        value,
        hash_algorithm,
        confidence,
        observed_at,
        "STIX indicator pattern",
    )


def safe_payload_observables(
    payload: Mapping[str, object],
) -> tuple[StixMappedObservable, ...]:
    """Reconstruct mapped observables solely from a canonical safe payload."""

    stix_type = payload.get("type")
    pairs: list[tuple[str, str, str | None]] = []
    if stix_type in {"ipv4-addr", "ipv6-addr", "domain-name", "url"}:
        observable = payload.get("observable")
        if not isinstance(observable, Mapping):
            raise StixObjectMappingError("Canonical STIX observable is invalid.")
        observable_type = observable.get("observable_type")
        value = observable.get("normalized_value")
        hash_algorithm = observable.get("hash_algorithm")
        if not isinstance(observable_type, str) or not isinstance(value, str):
            raise StixObjectMappingError("Canonical STIX observable is invalid.")
        if hash_algorithm is not None:
            raise StixObjectMappingError("Canonical STIX observable is invalid.")
        pairs.append((observable_type, value, None))
    elif stix_type == "file":
        hashes = payload.get("hashes")
        if not isinstance(hashes, Mapping):
            raise StixObjectMappingError("Canonical STIX file hashes are invalid.")
        for algorithm in sorted(hashes):
            value = hashes[algorithm]
            if not isinstance(algorithm, str) or not isinstance(value, str):
                raise StixObjectMappingError("Canonical STIX file hashes are invalid.")
            pairs.append(("file_hash", value, algorithm))
    elif stix_type == "indicator":
        confidence_value = payload.get("confidence")
        if confidence_value is not None and type(confidence_value) is not int:
            raise StixObjectMappingError("Canonical STIX confidence is invalid.")
        confidence = (
            None
            if confidence_value is None
            else Decimal(confidence_value).scaleb(-2).quantize(Decimal("0.001"))
        )
        valid_from = payload.get("valid_from")
        if not isinstance(valid_from, str):
            raise StixObjectMappingError("Canonical STIX observation time is invalid.")
        try:
            observed_at = datetime.fromisoformat(
                valid_from.replace("Z", "+00:00")
            ).astimezone(UTC)
        except ValueError as exc:
            raise StixObjectMappingError(
                "Canonical STIX observation time is invalid."
            ) from exc
        return (
            indicator_pattern_observable(
                payload,
                confidence=confidence,
                observed_at=observed_at,
            ),
        )
    else:
        return ()

    return tuple(
        _mapped_observable(
            observable_type,
            value,
            hash_algorithm,
            None,
            None,
            f"STIX {stix_type} object",
        )
        for observable_type, value, hash_algorithm in pairs
    )


def canonical_safe_content_hash(payload: Mapping[str, object]) -> str:
    """Hash the safe staged representation, never the original STIX object."""

    encoded = json.dumps(
        thaw_json(payload),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def freeze_mapping(value: dict[str, object]) -> Mapping[str, object]:
    """Recursively freeze a safe JSON mapping."""

    def freeze(item: object) -> object:
        if isinstance(item, dict):
            return MappingProxyType({key: freeze(child) for key, child in item.items()})
        if isinstance(item, list):
            return tuple(freeze(child) for child in item)
        if isinstance(item, tuple):
            return tuple(freeze(child) for child in item)
        return item

    return freeze(value)  # type: ignore[return-value]


def _mapped_observable(
    observable_type: str,
    value: str,
    hash_algorithm: str | None,
    confidence: Decimal | None,
    observed_at: datetime | None,
    context_summary: str,
) -> StixMappedObservable:
    try:
        normalized = normalize_observable(
            observable_type,
            value,
            hash_algorithm=hash_algorithm,
        )
    except IndicatorValueError as exc:
        raise StixObjectMappingError("STIX observable failed safe normalization.") from exc
    return StixMappedObservable(
        normalized=normalized,
        confidence=confidence,
        observed_at=observed_at,
        context_summary=context_summary,
    )
