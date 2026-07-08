"""Pure normalization for one public FIRST EPSS score record."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from hashlib import sha256
import json
import re
from typing import Any


MAX_PAYLOAD_BYTES = 4096
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
SCORE_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SIX_DECIMAL_PLACES = Decimal("0.000001")
EPSS_ROUNDING_MODE = ROUND_HALF_UP


class EpssNormalizationError(ValueError):
    """An EPSS record could not be safely normalized."""


class EpssPayloadTooLargeError(EpssNormalizationError):
    """An EPSS record exceeded the approved source-payload size limit."""


@dataclass(frozen=True)
class NormalizedEpssRecord:
    """Validated database-ready values derived from one FIRST EPSS record."""

    cve_id: str
    epss_score: Decimal
    epss_percentile: Decimal
    score_date: date
    raw_payload: dict[str, Any]
    content_hash: str


def normalize_epss_record(record: dict[str, Any]) -> NormalizedEpssRecord:
    """Normalize one FIRST EPSS record without network or database side effects."""

    if not isinstance(record, dict):
        raise EpssNormalizationError("The EPSS record must be an object.")

    cve_id = _normalize_cve_id(record.get("cve"))
    epss_score = _probability(record.get("epss"), "score")
    epss_percentile = _probability(record.get("percentile"), "percentile")
    score_date = _score_date(record.get("date"))
    raw_payload = {
        "cve": cve_id,
        "epss": format_probability(epss_score),
        "percentile": format_probability(epss_percentile),
        "date": score_date.isoformat(),
    }
    canonical_bytes = _canonical_bytes(raw_payload)

    return NormalizedEpssRecord(
        cve_id=cve_id,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        score_date=score_date,
        raw_payload=raw_payload,
        content_hash=sha256(canonical_bytes).hexdigest(),
    )


def _normalize_cve_id(value: object) -> str:
    if not isinstance(value, str) or CVE_ID_PATTERN.fullmatch(value) is None:
        raise EpssNormalizationError("The EPSS record contains an invalid CVE ID.")
    return value.upper()


def _probability(value: object, field_name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise EpssNormalizationError(f"The EPSS {field_name} is invalid.")
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as exc:
        raise EpssNormalizationError(f"The EPSS {field_name} is invalid.") from exc
    if not parsed.is_finite() or not Decimal("0") <= parsed <= Decimal("1"):
        raise EpssNormalizationError(f"The EPSS {field_name} is invalid.")
    return parsed.quantize(SIX_DECIMAL_PLACES, rounding=EPSS_ROUNDING_MODE)


def _score_date(value: object) -> date:
    if not isinstance(value, str) or SCORE_DATE_PATTERN.fullmatch(value) is None:
        raise EpssNormalizationError("The EPSS score date is invalid.")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise EpssNormalizationError("The EPSS score date is invalid.") from exc


def format_probability(value: Decimal) -> str:
    """Return the canonical persisted EPSS numeric representation."""

    return format(value, ".6f")


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    try:
        canonical_json = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise EpssNormalizationError(
            "The EPSS record is not valid canonical JSON."
        ) from exc

    canonical_bytes = canonical_json.encode("utf-8")
    if len(canonical_bytes) > MAX_PAYLOAD_BYTES:
        raise EpssPayloadTooLargeError(
            "The EPSS record exceeds the 4 KiB payload limit."
        )
    return canonical_bytes
