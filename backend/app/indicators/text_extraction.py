"""Deterministic offline extraction of defensive observable metadata."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

from app.indicators.value_normalization import (
    IndicatorValueError,
    NormalizedObservable,
    normalize_observable,
)


MAX_COMBINED_TEXT_LENGTH = 12_000
MAX_TOTAL_CANDIDATES = 100
MAX_CONTEXT_SUMMARY_LENGTH = 500
CONTEXT_WINDOW = 120
PER_TYPE_LIMITS = {
    "url": 20,
    "ipv4": 25,
    "ipv6": 20,
    "file_hash": 20,
    "domain": 25,
}

_URL_RE = re.compile(
    r"(?i)\b(?:https?|hxxps?)(?::|\[:\])//[^\s<>\"']+"
)
_URI_LIKE_RE = re.compile(
    r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}"
    r"(?::|\[:\])//[^\s<>\"']+"
)
_IPV4_RE = re.compile(
    r"(?<![\w.])(?:[0-9]{1,3}(?:\.|\[\.\]|\(\.\))){3}[0-9]{1,3}(?![\w.])"
)
_IPV6_RE = re.compile(
    r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])"
)
_HASH_RE = re.compile(
    r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{64}|"
    r"[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])"
)
_DOMAIN_RE = re.compile(
    r"(?<![@\w-])(?:[A-Za-z0-9\u0080-\uffff]"
    r"(?:[A-Za-z0-9\u0080-\uffff-]{0,61}[A-Za-z0-9\u0080-\uffff])?"
    r"(?:\.|\[\.\]|\(\.\))){1,}"
    r"[A-Za-z0-9\u0080-\uffff]"
    r"(?:[A-Za-z0-9\u0080-\uffff-]{0,61}[A-Za-z0-9\u0080-\uffff])?"
    r"(?![\w.-])"
)
_CONTEXT_PATTERNS = {
    "ipv4": re.compile(
        r"(?i)\b(?:ioc|indicator|observable|malicious|command[- ]and[- ]control|"
        r"c2|ip|address|host)\b"
    ),
    "ipv6": re.compile(
        r"(?i)\b(?:ioc|indicator|observable|malicious|command[- ]and[- ]control|"
        r"c2|ip|address|host)\b"
    ),
    "domain": re.compile(
        r"(?i)\b(?:ioc|indicator|observable|malicious|command[- ]and[- ]control|"
        r"c2|domain|host)\b"
    ),
    "file_hash": re.compile(
        r"(?i)\b(?:ioc|indicator|observable|malicious|hash|md5|sha-?1|"
        r"sha-?256|sha-?512)\b"
    ),
}
_ALGORITHM_RE = {
    "md5": re.compile(r"(?i)\bmd5\b"),
    "sha1": re.compile(r"(?i)\bsha-?1\b"),
    "sha256": re.compile(r"(?i)\bsha-?256\b"),
    "sha512": re.compile(r"(?i)\bsha-?512\b"),
}
_VERSION_PREFIX_RE = re.compile(
    r"(?i)(?:\b(?:version|release|build)\s*:?\s*|\bv)$"
)
_EXPLICIT_DOMAIN_PREFIX_RE = re.compile(
    r"(?i)\b(?:domain|host|c2|url)\s*:?\s*$"
)
_NON_DOMAIN_TOKEN_PREFIX_RE = re.compile(
    r"(?i)\b(?:package|module|library|dependency|import|filename|file|path)"
    r"\s*:?\s*$"
)
_RESERVED_HOSTS = {"example.com", "example.net", "example.org"}
_RESERVED_SUFFIXES = (
    ".example",
    ".invalid",
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".test",
)
_FILE_SUFFIXES = (
    ".exe",
    ".dll",
    ".zip",
    ".tar",
    ".gz",
    ".js",
    ".py",
    ".json",
    ".xml",
    ".pdf",
    ".doc",
    ".docx",
    ".rpm",
    ".deb",
    ".yaml",
    ".yml",
    ".bin",
)
_TRAILING_PUNCTUATION = ".,;!?)]}"
_URL_TRAILING_PUNCTUATION = ".,;!?)}"
_BRACKETED_IPV6_ROOT_RE = re.compile(
    r"(?i)^(?:https?|hxxps?)(?::|\[:\])//\[[0-9a-f:.]+\]$"
)


class IOCTextExtractionError(ValueError):
    """Safe extraction failure without publication-text disclosure."""


@dataclass(frozen=True, slots=True)
class ExtractedObservable:
    """One bounded normalized observable extracted from publication text."""

    normalized: NormalizedObservable
    source_field: str
    extraction_form: str
    confidence: Decimal
    context_summary: str
    match_start: int


@dataclass(frozen=True, slots=True)
class IOCTextExtractionResult:
    """Immutable bounded extraction output and safe counters."""

    observables: tuple[ExtractedObservable, ...]
    candidates_found: int
    rejected_candidates: int
    limit_reached: bool
    status: str


@dataclass(frozen=True, slots=True)
class _StoredObservable:
    first_position: int
    value: ExtractedObservable


def extract_iocs(
    canonical_title: str,
    summary: str | None = None,
    *,
    excluded_urls: tuple[str, ...] = (),
    excluded_hosts: tuple[str, ...] = (),
) -> IOCTextExtractionResult:
    """Extract normalized IOCs from title and summary without external access."""

    title = _validated_text(canonical_title, "title")
    summary_text = "" if summary is None else _validated_text(summary, "summary")
    if len(title) + len(summary_text) > MAX_COMBINED_TEXT_LENGTH:
        return IOCTextExtractionResult((), 0, 0, True, "rejected_text_limit")

    excluded_url_values, excluded_host_values = _normalized_exclusions(
        excluded_urls,
        excluded_hosts,
    )
    fields = (("title", title, 0), ("summary", summary_text, len(title) + 1))
    accepted_spans: dict[str, list[tuple[int, int]]] = {"title": [], "summary": []}
    protected_spans = {
        field_name: sorted(
            [
                (match.start(), match.end())
                for match in _URI_LIKE_RE.finditer(text)
            ]
            + _email_like_spans(text)
        )
        for field_name, text, _ in fields
    }
    stored: dict[str, _StoredObservable] = {}
    per_type_counts = {key: 0 for key in PER_TYPE_LIMITS}
    candidates_found = 0
    rejected = 0
    limit_reached = False
    total_limit_reached = False

    extractors = (
        ("url", _URL_RE, _accept_url),
        ("ipv4", _IPV4_RE, _accept_ip),
        ("ipv6", _IPV6_RE, _accept_ip),
        ("file_hash", _HASH_RE, _accept_hash),
        ("domain", _DOMAIN_RE, _accept_domain),
    )
    for observable_type, pattern, acceptor in extractors:
        type_limit_reached = False
        for field_name, text, field_offset in fields:
            for match in pattern.finditer(text):
                if candidates_found >= MAX_TOTAL_CANDIDATES:
                    total_limit_reached = True
                    limit_reached = True
                    break
                if per_type_counts[observable_type] >= PER_TYPE_LIMITS[observable_type]:
                    type_limit_reached = True
                    limit_reached = True
                    break
                candidates_found += 1
                per_type_counts[observable_type] += 1

                raw, end = _trim_candidate(
                    match.group(0),
                    match.end(),
                    observable_type,
                )
                start = match.start()
                if not raw or _contained(start, end, accepted_spans[field_name]):
                    rejected += 1
                    continue
                if observable_type != "url" and _contained(
                    start,
                    end,
                    protected_spans[field_name],
                ):
                    rejected += 1
                    continue

                accepted = acceptor(
                    raw,
                    observable_type,
                    text,
                    start,
                    end,
                    excluded_url_values,
                    excluded_host_values,
                )
                if accepted is None:
                    rejected += 1
                    continue

                normalized, extraction_form, confidence = accepted
                context = _context_summary(text, start, end)
                extracted = ExtractedObservable(
                    normalized=normalized,
                    source_field=field_name,
                    extraction_form=extraction_form,
                    confidence=confidence,
                    context_summary=context,
                    match_start=start,
                )
                accepted_spans[field_name].append((start, end))
                first_position = field_offset + start
                existing = stored.get(normalized.identity_sha256)
                if existing is None:
                    stored[normalized.identity_sha256] = _StoredObservable(
                        first_position,
                        extracted,
                    )
                    continue
                if _prefer(extracted, existing.value):
                    stored[normalized.identity_sha256] = _StoredObservable(
                        existing.first_position,
                        extracted,
                    )
            if total_limit_reached or type_limit_reached:
                break
        if total_limit_reached:
            break

    ordered = tuple(
        entry.value for entry in sorted(stored.values(), key=lambda entry: entry.first_position)
    )
    status = "bounded" if limit_reached else ("extracted" if ordered else "no_candidates")
    return IOCTextExtractionResult(
        ordered,
        candidates_found,
        rejected,
        limit_reached,
        status,
    )


def _validated_text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise IOCTextExtractionError(f"Publication {field_name} must be text.")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise IOCTextExtractionError("Publication text contains unsupported controls.")
    return value


def _email_like_spans(text: str) -> list[tuple[int, int]]:
    """Return bounded lexical suppression spans without parsing email data."""

    spans: list[tuple[int, int]] = []
    token_start: int | None = None
    for position in range(len(text) + 1):
        at_end = position == len(text)
        if not at_end and not text[position].isspace():
            if token_start is None:
                token_start = position
            continue
        if token_start is None:
            continue

        token_end = position
        token = text[token_start:token_end]
        if "@" in token[:-1]:
            spans.append((token_start, token_end))
        token_start = None
    return spans


def _normalized_exclusions(
    urls: tuple[str, ...],
    hosts: tuple[str, ...],
) -> tuple[set[str], set[str]]:
    url_values: set[str] = set()
    host_values: set[str] = set()
    for value in urls:
        try:
            normalized = normalize_observable("url", value)
        except (IndicatorValueError, TypeError):
            continue
        url_values.add(normalized.normalized_value)
        host = urlsplit(normalized.normalized_value).hostname
        if host:
            normalized_host = _normalize_excluded_host(host)
            if normalized_host is not None:
                host_values.add(normalized_host)
    for value in hosts:
        normalized_host = _normalize_excluded_host(value)
        if normalized_host is not None:
            host_values.add(normalized_host)
    return url_values, host_values


def _normalize_excluded_host(value: object) -> str | None:
    for observable_type in ("domain", "ipv4", "ipv6"):
        try:
            return normalize_observable(observable_type, value).normalized_value
        except (IndicatorValueError, TypeError):
            continue
    return None


def _accept_url(
    raw: str,
    observable_type: str,
    text: str,
    start: int,
    end: int,
    excluded_urls: set[str],
    excluded_hosts: set[str],
) -> tuple[NormalizedObservable, str, Decimal] | None:
    del observable_type, text, start, end
    refanged, form = _refang(raw)
    if refanged is None:
        return None
    try:
        normalized = normalize_observable("url", refanged)
    except IndicatorValueError:
        return None
    parsed = urlsplit(normalized.normalized_value)
    host = parsed.hostname
    if normalized.normalized_value in excluded_urls or not host:
        return None
    if host.lower() in excluded_hosts or _reserved_hostname(host):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not _is_automatic_global_address(address):
            return None
    confidence = Decimal("0.950") if form == "defanged" else Decimal("0.900")
    return normalized, form, confidence


def _accept_ip(
    raw: str,
    observable_type: str,
    text: str,
    start: int,
    end: int,
    excluded_urls: set[str],
    excluded_hosts: set[str],
) -> tuple[NormalizedObservable, str, Decimal] | None:
    del excluded_urls
    refanged, form = _refang(raw)
    if refanged is None:
        return None
    try:
        normalized = normalize_observable(observable_type, refanged)
        address = ipaddress.ip_address(normalized.normalized_value)
    except (IndicatorValueError, ValueError):
        return None
    if not _is_automatic_global_address(address):
        return None
    if normalized.normalized_value in excluded_hosts:
        return None
    if form == "literal" and _looks_like_software_version(text, start):
        return None
    if form != "defanged" and not _has_context(text, start, end, observable_type):
        return None
    confidence = Decimal("0.950") if form == "defanged" else Decimal("0.820")
    return normalized, form, confidence


def _accept_hash(
    raw: str,
    observable_type: str,
    text: str,
    start: int,
    end: int,
    excluded_urls: set[str],
    excluded_hosts: set[str],
) -> tuple[NormalizedObservable, str, Decimal] | None:
    del observable_type, excluded_urls, excluded_hosts
    if len(set(raw.lower())) == 1:
        return None
    algorithm = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(raw))
    if algorithm is None:
        return None
    nearby = _nearby_context(text, start, end)
    labeled = bool(_ALGORITHM_RE[algorithm].search(nearby))
    if not labeled and not _CONTEXT_PATTERNS["file_hash"].search(nearby):
        return None
    try:
        normalized = normalize_observable(
            "file_hash",
            raw,
            hash_algorithm=algorithm,
        )
    except IndicatorValueError:
        return None
    confidence = Decimal("0.900") if labeled else Decimal("0.840")
    return normalized, "literal", confidence


def _accept_domain(
    raw: str,
    observable_type: str,
    text: str,
    start: int,
    end: int,
    excluded_urls: set[str],
    excluded_hosts: set[str],
) -> tuple[NormalizedObservable, str, Decimal] | None:
    del observable_type, excluded_urls
    refanged, form = _refang(raw)
    if refanged is None:
        return None
    try:
        normalized = normalize_observable("domain", refanged)
    except IndicatorValueError:
        return None
    domain = normalized.normalized_value
    if domain in excluded_hosts or _reserved_hostname(domain):
        return None
    if domain.endswith(_FILE_SUFFIXES):
        return None
    if form == "literal" and _looks_like_non_domain_token(text, start):
        return None
    if form != "defanged" and not _has_context(text, start, end, "domain"):
        return None
    confidence = Decimal("0.900") if form == "defanged" else Decimal("0.780")
    return normalized, form, confidence


def _refang(value: str) -> tuple[str | None, str]:
    has_bracket_dot = "[.]" in value
    has_parenthesis_dot = "(.)" in value
    if has_bracket_dot and has_parenthesis_dot:
        return None, "defanged"
    defanged = has_bracket_dot or has_parenthesis_dot or "[:]" in value
    lower = value.lower()
    if lower.startswith("hxxp"):
        defanged = True
    refanged = value.replace("[.]", ".").replace("(.)", ".")
    refanged = re.sub(r"(?i)^hxxps(?=\:|\[:\])", "https", refanged)
    refanged = re.sub(r"(?i)^hxxp(?=\:|\[:\])", "http", refanged)
    refanged = re.sub(r"(?i)^(https?)\[:\]//", r"\1://", refanged)
    return refanged, "defanged" if defanged else "literal"


def _reserved_hostname(value: str) -> bool:
    host = value.lower().rstrip(".")
    return (
        host in _RESERVED_HOSTS
        or any(host.endswith(f".{reserved}") for reserved in _RESERVED_HOSTS)
        or host == "localhost"
        or host.endswith(_RESERVED_SUFFIXES)
    )


def _is_automatic_global_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return address.is_global and not any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_unspecified,
            address.is_reserved,
        )
    )


def _has_context(text: str, start: int, end: int, observable_type: str) -> bool:
    return bool(_CONTEXT_PATTERNS[observable_type].search(_nearby_context(text, start, end)))


def _looks_like_software_version(text: str, start: int) -> bool:
    prefix = text[max(0, start - 48):start]
    return bool(_VERSION_PREFIX_RE.search(prefix))


def _looks_like_non_domain_token(text: str, start: int) -> bool:
    prefix = text[max(0, start - 80):start]
    if _EXPLICIT_DOMAIN_PREFIX_RE.search(prefix):
        return False
    if start > 0 and text[start - 1] in "/\\":
        return True
    return bool(_NON_DOMAIN_TOKEN_PREFIX_RE.search(prefix))


def _nearby_context(text: str, start: int, end: int) -> str:
    before = text[max(0, start - CONTEXT_WINDOW):start]
    after = text[end:min(len(text), end + CONTEXT_WINDOW)]
    return f"{before} {after}"


def _context_summary(text: str, start: int, end: int) -> str:
    snippet = text[
        max(0, start - CONTEXT_WINDOW):min(len(text), end + CONTEXT_WINDOW)
    ]
    collapsed = " ".join(snippet.split())
    return collapsed[:MAX_CONTEXT_SUMMARY_LENGTH]


def _trim_candidate(
    value: str,
    end: int,
    observable_type: str,
) -> tuple[str, int]:
    if observable_type != "url":
        trimmed = value.rstrip(_TRAILING_PUNCTUATION)
        return trimmed, end - (len(value) - len(trimmed))

    trimmed = value.rstrip(_URL_TRAILING_PUNCTUATION)
    if trimmed.endswith("]") and not _BRACKETED_IPV6_ROOT_RE.fullmatch(trimmed):
        trimmed = trimmed.rstrip("]")
    return trimmed, end - (len(value) - len(trimmed))


def _contained(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start >= span_start and end <= span_end for span_start, span_end in spans)


def _prefer(candidate: ExtractedObservable, existing: ExtractedObservable) -> bool:
    if candidate.confidence != existing.confidence:
        return candidate.confidence > existing.confidence
    return candidate.source_field == "title" and existing.source_field == "summary"
