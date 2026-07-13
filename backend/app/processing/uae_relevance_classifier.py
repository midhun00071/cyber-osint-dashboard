"""Deterministic UAE relevance classification for normalized safe metadata."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import re
import unicodedata


MAX_TEXT_CHARS = 8000

APPROVED_UAE_SOURCE_SLUGS = frozenset(
    {
        "ae-cert",
        "uae-cert",
        "uae-cyber-security-council",
    }
)
UAE_RELEVANCE_CONFIDENCE_BY_RULE: dict[str, Decimal | None] = {
    "approved_uae_source": Decimal("0.950"),
    "direct_country_name": Decimal("0.950"),
    "direct_uae_acronym": Decimal("0.900"),
    "direct_emirate_name": Decimal("0.850"),
    "no_direct_uae_evidence": None,
}

_WHITESPACE_RE = re.compile(r"\s+")
_SEPARATOR_RE = re.compile(r"[\W_]+", flags=re.UNICODE)
_COUNTRY_RE = re.compile(r"\bunited\s+arab\s+emirates\b")
_UAE_ACRONYM_RE = re.compile(r"(?<![\w])u\s*\.?\s*a\s*\.?\s*e\.?(?![\w])")
_EMIRATE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Abu Dhabi", re.compile(r"\babu\s+dhabi\b")),
    ("Dubai", re.compile(r"\bdubai\b")),
    ("Sharjah", re.compile(r"\bsharjah\b")),
    ("Ajman", re.compile(r"\bajman\b")),
    ("Fujairah", re.compile(r"\bfujairah\b")),
    ("Ras Al Khaimah", re.compile(r"\bras\s+al\s+khaimah\b")),
    ("Umm Al Quwain", re.compile(r"\bumm\s+al\s+quwain\b")),
)


@dataclass(frozen=True)
class UaeClassificationInput:
    """Safe normalized fields used by the offline classifier."""

    title: str | None = None
    summary: str | None = None
    source_slugs: tuple[str, ...] = ()
    geographic_scope: str = "unknown"


@dataclass(frozen=True)
class UaeClassificationResult:
    """Database-compatible UAE relevance classification output."""

    geographic_scope: str
    uae_relevance_status: str
    uae_relevance_reason: str
    uae_relevance_method: str
    matched_rule_id: str
    uae_relevance_confidence: Decimal | None


def normalize_text(value: str | None) -> str:
    """Return bounded NFKC/casefolded text with punctuation-safe spacing."""

    if value is None:
        return ""
    normalized = unicodedata.normalize("NFKC", str(value))[:MAX_TEXT_CHARS]
    normalized = normalized.casefold()
    normalized = _SEPARATOR_RE.sub(" ", normalized)
    return _WHITESPACE_RE.sub(" ", normalized).strip()


def normalize_source_slug(value: str | None) -> str:
    """Normalize a controlled source slug without trusting display text or URLs."""

    if value is None:
        return ""
    normalized = unicodedata.normalize("NFKC", str(value))[:160]
    normalized = normalized.casefold().strip()
    return _WHITESPACE_RE.sub("", normalized)


def confidence_for_rule(rule_id: str) -> Decimal | None:
    """Return the fixed database-compatible confidence for a classifier rule."""

    try:
        value = UAE_RELEVANCE_CONFIDENCE_BY_RULE[rule_id]
    except KeyError as exc:
        raise ValueError("Unknown UAE relevance confidence rule.") from exc
    if value is None:
        return None
    if not isinstance(value, Decimal):
        raise ValueError("UAE relevance confidence mapping must be Decimal or None.")
    if not value.is_finite():
        raise ValueError("UAE relevance confidence mapping must be finite.")
    if not Decimal("0") <= value <= Decimal("1"):
        raise ValueError("UAE relevance confidence mapping is outside 0..1.")
    if value.as_tuple().exponent < -3:
        raise ValueError(
            "UAE relevance confidence mapping exceeds Numeric(4,3) precision."
        )
    return value


def _result(
    *,
    geographic_scope: str,
    uae_relevance_status: str,
    uae_relevance_reason: str,
    matched_rule_id: str,
) -> UaeClassificationResult:
    return UaeClassificationResult(
        geographic_scope=geographic_scope,
        uae_relevance_status=uae_relevance_status,
        uae_relevance_reason=uae_relevance_reason,
        uae_relevance_method="automatic",
        matched_rule_id=matched_rule_id,
        uae_relevance_confidence=confidence_for_rule(matched_rule_id),
    )


def classify_uae_relevance(
    fields: UaeClassificationInput,
) -> UaeClassificationResult:
    """Classify direct UAE relevance using ordered conservative rules."""

    source_slugs = {normalize_source_slug(slug) for slug in fields.source_slugs}
    if source_slugs & APPROVED_UAE_SOURCE_SLUGS:
        return _result(
            geographic_scope="uae",
            uae_relevance_status="confirmed",
            uae_relevance_reason="Matched approved UAE source.",
            matched_rule_id="approved_uae_source",
        )

    texts = tuple(
        part
        for part in (
            normalize_text(fields.title),
            normalize_text(fields.summary),
        )
        if part
    )

    if any(_COUNTRY_RE.search(text) for text in texts):
        return _result(
            geographic_scope="uae",
            uae_relevance_status="confirmed",
            uae_relevance_reason="Matched direct UAE country phrase.",
            matched_rule_id="direct_country_name",
        )

    if any(_UAE_ACRONYM_RE.search(text) for text in texts):
        return _result(
            geographic_scope="uae",
            uae_relevance_status="confirmed",
            uae_relevance_reason="Matched standalone UAE acronym.",
            matched_rule_id="direct_uae_acronym",
        )

    for emirate_name, pattern in _EMIRATE_PATTERNS:
        if any(pattern.search(text) for text in texts):
            return _result(
                geographic_scope="uae",
                uae_relevance_status="confirmed",
                uae_relevance_reason=f"Matched emirate name: {emirate_name}.",
                matched_rule_id="direct_emirate_name",
            )

    return _result(
        geographic_scope=fields.geographic_scope,
        uae_relevance_status="unknown",
        uae_relevance_reason="No direct UAE evidence found.",
        matched_rule_id="no_direct_uae_evidence",
    )
