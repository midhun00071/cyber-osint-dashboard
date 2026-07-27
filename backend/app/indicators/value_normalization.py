"""Strict, offline normalization for defensive observable metadata."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ipaddress
import idna
import json
import re
import unicodedata
from urllib.parse import SplitResult, urlsplit, urlunsplit


OBSERVABLE_TYPES = frozenset({"ipv4", "ipv6", "domain", "url", "file_hash"})
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
MAX_CANONICAL_URL_LENGTH = 2048

_ASCII_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_HEX_VALUE = re.compile(r"[0-9a-fA-F]+\Z")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_PERCENT_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")


class IndicatorValueError(ValueError):
    """Safe validation failure without attacker-controlled value disclosure."""


@dataclass(frozen=True, slots=True)
class NormalizedObservable:
    """Canonical identity fields for one supported defensive observable."""

    observable_type: str
    normalized_value: str
    hash_algorithm: str | None
    identity_sha256: str


def normalize_observable(
    observable_type: str,
    value: str,
    *,
    hash_algorithm: str | None = None,
) -> NormalizedObservable:
    """Normalize one observable without DNS, HTTP, or other network activity."""

    normalized_type = _normalize_type(observable_type)
    normalized_algorithm = _normalize_hash_algorithm(hash_algorithm)

    if normalized_type == "file_hash":
        if normalized_algorithm is None:
            raise IndicatorValueError("A supported hash algorithm is required.")
        normalized_value = _normalize_file_hash(value, normalized_algorithm)
    else:
        if normalized_algorithm is not None:
            raise IndicatorValueError(
                "A hash algorithm is only valid for file-hash observables."
            )
        if normalized_type in {"ipv4", "ipv6"}:
            normalized_value = _normalize_ip(value, normalized_type)
        elif normalized_type == "domain":
            normalized_value = _normalize_domain(value)
        else:
            normalized_value = _normalize_url(value)

    identity_input = json.dumps(
        [normalized_type, normalized_algorithm, normalized_value],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return NormalizedObservable(
        observable_type=normalized_type,
        normalized_value=normalized_value,
        hash_algorithm=normalized_algorithm,
        identity_sha256=sha256(identity_input).hexdigest(),
    )


def _normalize_type(value: str) -> str:
    if not isinstance(value, str):
        raise IndicatorValueError("Observable type must be text.")
    normalized = value.strip().lower()
    if normalized not in OBSERVABLE_TYPES:
        raise IndicatorValueError("Observable type is not supported.")
    return normalized


def _normalize_hash_algorithm(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise IndicatorValueError("Hash algorithm must be text when provided.")
    normalized = value.strip().lower()
    if normalized not in HASH_LENGTHS:
        raise IndicatorValueError("Hash algorithm is not supported.")
    return normalized


def _require_text(value: str) -> str:
    if not isinstance(value, str):
        raise IndicatorValueError("Observable value must be text.")
    return value


def _contains_control(value: str) -> bool:
    return any(unicodedata.category(character) == "Cc" for character in value)


def _normalize_ip(value: str, observable_type: str) -> str:
    original = _require_text(value)
    if _contains_control(original):
        raise IndicatorValueError("IP address syntax is invalid.")
    candidate = original.strip()
    if not candidate or "%" in candidate:
        raise IndicatorValueError("IP address syntax is invalid.")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise IndicatorValueError("IP address syntax is invalid.") from exc

    expected_version = 4 if observable_type == "ipv4" else 6
    if address.version != expected_version:
        raise IndicatorValueError("IP address version does not match observable type.")
    return address.compressed


def _normalize_domain(value: str) -> str:
    original = _require_text(value)
    if _contains_control(original):
        raise IndicatorValueError("Domain syntax is invalid.")
    candidate = original.strip()
    if (
        not candidate
        or any(character.isspace() for character in candidate)
        or any(
            character in candidate
            for character in (":", "/", "\\", "@", "*", "?", "#", "[", "]")
        )
    ):
        raise IndicatorValueError("Domain syntax is invalid.")

    try:
        ascii_domain = idna.encode(
            candidate,
            uts46=True,
            std3_rules=True,
            transitional=False,
        ).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise IndicatorValueError("Domain syntax is invalid.") from exc

    if ascii_domain.endswith("."):
        ascii_domain = ascii_domain[:-1]

    labels = ascii_domain.split(".")
    if len(labels) < 2 or len(ascii_domain) > 253:
        raise IndicatorValueError("Domain syntax is invalid.")
    if any(not _ASCII_DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise IndicatorValueError("Domain syntax is invalid.")
    if labels[-1].isdigit():
        raise IndicatorValueError("Domain syntax is invalid.")

    try:
        ipaddress.ip_address(ascii_domain)
    except ValueError:
        return ascii_domain
    raise IndicatorValueError("Domain syntax is invalid.")


def _normalize_url(value: str) -> str:
    original = _require_text(value)
    if _contains_control(original):
        raise IndicatorValueError("URL syntax is invalid.")
    candidate = original.strip()
    if (
        not candidate
        or any(character.isspace() for character in candidate)
        or "\\" in candidate
    ):
        raise IndicatorValueError("URL syntax is invalid.")

    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise IndicatorValueError("URL syntax is invalid.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise IndicatorValueError("URL scheme is not supported.")
    if not parsed.hostname:
        raise IndicatorValueError("URL must include a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise IndicatorValueError("URL credentials are not allowed.")
    if parsed.netloc.endswith(":"):
        raise IndicatorValueError("URL port is invalid.")
    if port is not None and port == 0:
        raise IndicatorValueError("URL port is invalid.")
    if _INVALID_PERCENT_ESCAPE.search(parsed.path) or _INVALID_PERCENT_ESCAPE.search(
        parsed.query
    ):
        raise IndicatorValueError("URL syntax is invalid.")

    hostname = _normalize_url_hostname(parsed.hostname)
    rendered_hostname = f"[{hostname}]" if ":" in hostname else hostname
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    netloc = (
        rendered_hostname
        if port is None or default_port
        else f"{rendered_hostname}:{port}"
    )
    path = _canonicalize_percent_escapes(parsed.path or "/")
    query = _canonicalize_percent_escapes(parsed.query)

    canonical = urlunsplit(SplitResult(scheme, netloc, path, query, ""))
    if len(canonical) > MAX_CANONICAL_URL_LENGTH:
        raise IndicatorValueError("Canonical URL exceeds the allowed length.")
    return canonical


def _normalize_url_hostname(value: str) -> str:
    if "%" in value:
        raise IndicatorValueError("URL hostname is invalid.")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return _normalize_domain(value)


def _canonicalize_percent_escapes(value: str) -> str:
    return _PERCENT_ESCAPE.sub(lambda match: match.group(0).upper(), value)


def _normalize_file_hash(value: str, algorithm: str) -> str:
    candidate = _require_text(value)
    if len(candidate) != HASH_LENGTHS[algorithm] or not _HEX_VALUE.fullmatch(candidate):
        raise IndicatorValueError("File-hash syntax or length is invalid.")
    return candidate.lower()
