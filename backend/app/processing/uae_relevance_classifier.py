"""Deterministic UAE relevance classification for normalized safe metadata."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import re
import unicodedata


MAX_TEXT_CHARS = 8000
MAX_CLASSIFICATION_TAGS = 16

# This is a classification trust boundary, not a source registry or network
# approval list. ``uae-cert`` is retained only as a legacy classification alias;
# adding a planned registry source does not add it here automatically.
UAE_CLASSIFICATION_SOURCE_SLUGS = frozenset(
    {
        "ae-cert",
        "desc-news",
        "desc-published-research",
        "uae-cert",
        "uae-cyber-security-council",
        "uae-cyber-security-council-nibras",
    }
)
UAE_RELEVANCE_CONFIDENCE_BY_RULE: dict[str, Decimal | None] = {
    "approved_uae_source": Decimal("0.950"),
    "structured_uae_scope": Decimal("0.800"),
    "text_country_mention": Decimal("0.650"),
    "text_uae_acronym_mention": Decimal("0.600"),
    "text_emirate_mention": Decimal("0.550"),
    "explicit_global_scope": Decimal("0.800"),
    "no_direct_uae_evidence": None,
    # Retained for older stored evidence and historical fixtures. New
    # classifications use the text_* identifiers below and never equate a
    # mention with confirmed attribution.
    "direct_country_name": Decimal("0.950"),
    "direct_uae_acronym": Decimal("0.900"),
    "direct_emirate_name": Decimal("0.850"),
}

_AUTHORITY_TAGS: dict[str, tuple[str, str]] = {
    "ae-cert": ("uae-authority-aecert", "TDRA / aeCERT"),
    "uae-cert": ("uae-authority-aecert", "TDRA / aeCERT"),
    "uae-cyber-security-council": (
        "uae-authority-cyber-security-council",
        "UAE Cyber Security Council",
    ),
    "uae-cyber-security-council-nibras": (
        "uae-authority-cyber-security-council",
        "UAE Cyber Security Council",
    ),
    "desc-news": (
        "uae-authority-desc",
        "Dubai Electronic Security Center",
    ),
    "desc-published-research": (
        "uae-authority-desc",
        "Dubai Electronic Security Center",
    ),
}

_WHITESPACE_RE = re.compile(r"\s+")
_SEPARATOR_RE = re.compile(r"[\W_]+", flags=re.UNICODE)
_COUNTRY_RE = re.compile(r"\bunited\s+arab\s+emirates\b")
_UAE_ACRONYM_RE = re.compile(r"(?<![\w])u\s*\.?\s*a\s*\.?\s*e\.?(?![\w])")
_EMIRATE_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("uae-emirate-abu-dhabi", "Abu Dhabi", re.compile(r"\babu\s+dhabi\b")),
    ("uae-emirate-dubai", "Dubai", re.compile(r"\bdubai\b")),
    ("uae-emirate-sharjah", "Sharjah", re.compile(r"\bsharjah\b")),
    ("uae-emirate-ajman", "Ajman", re.compile(r"\bajman\b")),
    ("uae-emirate-fujairah", "Fujairah", re.compile(r"\bfujairah\b")),
    (
        "uae-emirate-ras-al-khaimah",
        "Ras Al Khaimah",
        re.compile(r"\bras\s+al\s+khaimah\b"),
    ),
    (
        "uae-emirate-umm-al-quwain",
        "Umm Al Quwain",
        re.compile(r"\bumm\s+al\s+quwain\b"),
    ),
)
_SECTOR_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "uae-sector-financial-services",
        "Financial services",
        re.compile(r"\b(?:bank|banking|finance|financial)\b"),
    ),
    (
        "uae-sector-government",
        "Government",
        re.compile(r"\b(?:government|public\s+sector|ministry)\b"),
    ),
    (
        "uae-sector-energy",
        "Energy",
        re.compile(r"\b(?:energy|oil|gas|utility|utilities)\b"),
    ),
    (
        "uae-sector-healthcare",
        "Healthcare",
        re.compile(r"\b(?:healthcare|hospital|medical|health\s+sector)\b"),
    ),
    (
        "uae-sector-aviation-transport",
        "Aviation and transport",
        re.compile(r"\b(?:aviation|airline|airport|transport|logistics)\b"),
    ),
    (
        "uae-sector-telecommunications",
        "Telecommunications",
        re.compile(r"\b(?:telecom|telecommunications|mobile\s+network)\b"),
    ),
    (
        "uae-sector-technology",
        "Technology",
        re.compile(r"\b(?:cloud|technology|software|digital\s+service)\b"),
    ),
)
_ARABIC_RE = re.compile(r"[\u0600-\u06ff]")
_LATIN_WORD_RE = re.compile(r"\b[a-z]{2,}\b")


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
    tags: tuple["UaeEvidenceTag", ...]


@dataclass(frozen=True)
class UaeEvidenceTag:
    """One controlled classification tag with bounded evidence."""

    kind: str
    slug: str
    label: str
    confidence: Decimal
    evidence: str


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
    tags: tuple[UaeEvidenceTag, ...],
) -> UaeClassificationResult:
    return UaeClassificationResult(
        geographic_scope=geographic_scope,
        uae_relevance_status=uae_relevance_status,
        uae_relevance_reason=uae_relevance_reason,
        uae_relevance_method="automatic",
        matched_rule_id=matched_rule_id,
        uae_relevance_confidence=confidence_for_rule(matched_rule_id),
        tags=tags,
    )


def _classification_tags(
    *,
    source_slugs: set[str],
    texts: tuple[str, ...],
) -> tuple[UaeEvidenceTag, ...]:
    tags: dict[tuple[str, str], UaeEvidenceTag] = {}

    for source_slug in sorted(source_slugs):
        authority = _AUTHORITY_TAGS.get(source_slug)
        if authority is None:
            continue
        slug, label = authority
        tags[("authority", slug)] = UaeEvidenceTag(
            kind="authority",
            slug=slug,
            label=label,
            confidence=Decimal("0.950"),
            evidence=f"Controlled source identity: {source_slug}.",
        )

    for slug, label, pattern in _EMIRATE_PATTERNS:
        if any(pattern.search(text) for text in texts):
            tags[("emirate", slug)] = UaeEvidenceTag(
                kind="emirate",
                slug=slug,
                label=label,
                confidence=Decimal("0.700"),
                evidence=f"Normalized text mentions {label}.",
            )

    for slug, label, pattern in _SECTOR_PATTERNS:
        if any(pattern.search(text) for text in texts):
            tags[("sector", slug)] = UaeEvidenceTag(
                kind="sector",
                slug=slug,
                label=label,
                confidence=Decimal("0.700"),
                evidence=f"Normalized text matches the controlled {label} sector rule.",
            )

    if any(_ARABIC_RE.search(text) for text in texts):
        tags[("language", "language-arabic")] = UaeEvidenceTag(
            kind="language",
            slug="language-arabic",
            label="Arabic",
            confidence=Decimal("0.900"),
            evidence="Normalized text contains Arabic-script characters.",
        )
    if any(_LATIN_WORD_RE.search(text) for text in texts):
        tags[("language", "language-english")] = UaeEvidenceTag(
            kind="language",
            slug="language-english",
            label="English",
            confidence=Decimal("0.750"),
            evidence="Normalized text contains Latin-script words.",
        )

    ordered = tuple(tags[key] for key in sorted(tags))
    return ordered[:MAX_CLASSIFICATION_TAGS]


def classify_uae_relevance(
    fields: UaeClassificationInput,
) -> UaeClassificationResult:
    """Classify direct UAE relevance using ordered conservative rules."""

    source_slugs = {normalize_source_slug(slug) for slug in fields.source_slugs}
    texts = tuple(
        part
        for part in (
            normalize_text(fields.title),
            normalize_text(fields.summary),
        )
        if part
    )
    tags = _classification_tags(source_slugs=source_slugs, texts=texts)

    if source_slugs & UAE_CLASSIFICATION_SOURCE_SLUGS:
        return _result(
            geographic_scope="uae",
            uae_relevance_status="confirmed",
            uae_relevance_reason="Direct UAE authority-source evidence.",
            matched_rule_id="approved_uae_source",
            tags=tags,
        )

    if any(_COUNTRY_RE.search(text) for text in texts):
        return _result(
            geographic_scope="uae",
            uae_relevance_status="possible",
            uae_relevance_reason=(
                "Potential UAE relevance from a text mention; no attribution asserted."
            ),
            matched_rule_id="text_country_mention",
            tags=tags,
        )

    if any(_UAE_ACRONYM_RE.search(text) for text in texts):
        return _result(
            geographic_scope="uae",
            uae_relevance_status="possible",
            uae_relevance_reason=(
                "Potential UAE relevance from an acronym mention; no attribution asserted."
            ),
            matched_rule_id="text_uae_acronym_mention",
            tags=tags,
        )

    for _slug, emirate_name, pattern in _EMIRATE_PATTERNS:
        if any(pattern.search(text) for text in texts):
            return _result(
                geographic_scope="uae",
                uae_relevance_status="possible",
                uae_relevance_reason=(
                    f"Potential UAE relevance from a {emirate_name} mention; "
                    "no attribution asserted."
                ),
                matched_rule_id="text_emirate_mention",
                tags=tags,
            )

    if fields.geographic_scope == "uae":
        return _result(
            geographic_scope="uae",
            uae_relevance_status="probable",
            uae_relevance_reason=(
                "Potential UAE relevance from existing structured geographic scope."
            ),
            matched_rule_id="structured_uae_scope",
            tags=tags,
        )

    if fields.geographic_scope == "global":
        return _result(
            geographic_scope="global",
            uae_relevance_status="not_relevant",
            uae_relevance_reason=(
                "Global relevance with no demonstrated UAE-specific evidence."
            ),
            matched_rule_id="explicit_global_scope",
            tags=tags,
        )

    return _result(
        geographic_scope=fields.geographic_scope,
        uae_relevance_status="unknown",
        uae_relevance_reason="No demonstrated UAE relevance evidence.",
        matched_rule_id="no_direct_uae_evidence",
        tags=tags,
    )
