"""Pure normalization for one public NVD CVE vulnerability wrapper."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import re
from typing import Any


MAX_PAYLOAD_BYTES = 512 * 1024
MAX_TITLE_LENGTH = 500
MAX_SUMMARY_LENGTH = 10_000
MAX_CVSS_VECTOR_LENGTH = 300
MAX_AFFECTED_PRODUCTS = 100
MAX_AFFECTED_VALUE_LENGTH = 2_048
MAX_CONFIGURATION_DEPTH = 8
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
ALLOWED_SEVERITIES = {"unknown", "none", "low", "medium", "high", "critical"}
CVSS_METRIC_PREFERENCE = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
AFFECTED_PRODUCT_FIELDS = (
    "criteria",
    "matchCriteriaId",
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


class NvdNormalizationError(ValueError):
    """An NVD record could not be safely normalized."""


class NvdPayloadTooLargeError(NvdNormalizationError):
    """An NVD record exceeded the approved raw-payload size limit."""


@dataclass(frozen=True)
class NormalizedNvdCve:
    """Validated database-ready values derived from one NVD CVE wrapper."""

    cve_id: str
    title: str
    summary: str | None
    canonical_url: str
    source_published_at: datetime
    source_modified_at: datetime
    status: str
    severity: str
    cvss_score: Decimal | None
    cvss_vector: str | None
    cvss_version: str | None
    affected_summary: str | None
    affected_products: list[dict[str, Any]]
    raw_payload: dict[str, Any]
    content_hash: str


def normalize_nvd_cve(wrapper: dict[str, Any]) -> NormalizedNvdCve:
    """Normalize one NVD vulnerability wrapper without side effects."""

    if not isinstance(wrapper, dict):
        raise NvdNormalizationError("The NVD vulnerability wrapper must be an object.")
    cve = wrapper.get("cve")
    if not isinstance(cve, dict):
        raise NvdNormalizationError("The NVD record is missing a CVE object.")

    cve_id = _normalize_cve_id(cve.get("id"))
    summary = _english_description(cve.get("descriptions"))
    title = _bounded_text(
        f"{cve_id}: {summary}" if summary else cve_id,
        MAX_TITLE_LENGTH,
    )
    published = _parse_timestamp(cve.get("published"), "published")
    modified = _parse_timestamp(cve.get("lastModified"), "last modified")
    severity, score, vector, version = _select_cvss(cve.get("metrics"))
    affected_products = _extract_affected_products(cve.get("configurations"))
    affected_summary = (
        f"NVD lists {len(affected_products)} affected product configuration(s)."
        if affected_products
        else None
    )
    upstream_status = cve.get("vulnStatus")
    status = (
        "archived"
        if isinstance(upstream_status, str)
        and upstream_status.strip().lower() == "rejected"
        else "active"
    )
    canonical_bytes, raw_payload = _canonical_payload(wrapper)

    return NormalizedNvdCve(
        cve_id=cve_id,
        title=title,
        summary=summary,
        canonical_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        source_published_at=published,
        source_modified_at=modified,
        status=status,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cvss_version=version,
        affected_summary=affected_summary,
        affected_products=affected_products,
        raw_payload=raw_payload,
        content_hash=sha256(canonical_bytes).hexdigest(),
    )


def _canonical_payload(
    wrapper: dict[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    try:
        canonical_json = json.dumps(
            wrapper,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise NvdNormalizationError(
            "The NVD record is not valid canonical JSON."
        ) from exc

    canonical_bytes = canonical_json.encode("utf-8")
    if len(canonical_bytes) > MAX_PAYLOAD_BYTES:
        raise NvdPayloadTooLargeError(
            "The NVD record exceeds the 512 KiB payload limit."
        )

    return canonical_bytes, json.loads(canonical_json)


def _normalize_cve_id(value: object) -> str:
    if not isinstance(value, str) or CVE_ID_PATTERN.fullmatch(value) is None:
        raise NvdNormalizationError("The NVD record contains an invalid CVE ID.")
    return value.upper()


def _english_description(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise NvdNormalizationError("The NVD descriptions field is invalid.")

    for description in value:
        if not isinstance(description, dict):
            continue
        language = description.get("lang")
        text = description.get("value")
        if (
            isinstance(language, str)
            and language.lower() == "en"
            and isinstance(text, str)
            and text.strip()
        ):
            return _bounded_text(text.strip(), MAX_SUMMARY_LENGTH)
    return None


def _parse_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise NvdNormalizationError(f"The NVD {field_name} timestamp is invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NvdNormalizationError(
            f"The NVD {field_name} timestamp is invalid."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise NvdNormalizationError(
            f"The NVD {field_name} timestamp must include a timezone."
        )
    return parsed.astimezone(UTC)


def _select_cvss(
    metrics: object,
) -> tuple[str, Decimal | None, str | None, str | None]:
    if metrics is None:
        return "unknown", None, None, None
    if not isinstance(metrics, dict):
        raise NvdNormalizationError("The NVD CVSS metrics field is invalid.")

    for metric_name, version in CVSS_METRIC_PREFERENCE:
        candidates = metrics.get(metric_name)
        if candidates is None or candidates == []:
            continue
        if not isinstance(candidates, list) or not isinstance(candidates[0], dict):
            raise NvdNormalizationError("The preferred NVD CVSS metric is invalid.")

        candidate = candidates[0]
        cvss_data = candidate.get("cvssData")
        if not isinstance(cvss_data, dict):
            raise NvdNormalizationError("The preferred NVD CVSS metric is invalid.")

        score = _cvss_score(cvss_data.get("baseScore"))
        severity_value = cvss_data.get("baseSeverity", candidate.get("baseSeverity"))
        severity = _severity(severity_value)
        vector_value = cvss_data.get("vectorString")
        if vector_value is not None and not isinstance(vector_value, str):
            raise NvdNormalizationError("The NVD CVSS vector is invalid.")
        vector = (
            _bounded_text(vector_value, MAX_CVSS_VECTOR_LENGTH)
            if isinstance(vector_value, str)
            else None
        )
        return severity, score, vector, version

    return "unknown", None, None, None


def _cvss_score(value: object) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise NvdNormalizationError("The NVD CVSS score is invalid.")
    try:
        score = Decimal(str(value))
    except InvalidOperation as exc:
        raise NvdNormalizationError("The NVD CVSS score is invalid.") from exc
    if not score.is_finite() or not Decimal("0") <= score <= Decimal("10"):
        raise NvdNormalizationError("The NVD CVSS score is invalid.")
    return score


def _severity(value: object) -> str:
    if value is None:
        return "unknown"
    if not isinstance(value, str):
        raise NvdNormalizationError("The NVD CVSS severity is invalid.")
    normalized = value.strip().lower()
    if normalized not in ALLOWED_SEVERITIES:
        raise NvdNormalizationError("The NVD CVSS severity is invalid.")
    return normalized


def _extract_affected_products(configurations: object) -> list[dict[str, Any]]:
    if configurations is None:
        return []
    if not isinstance(configurations, list):
        raise NvdNormalizationError("The NVD configurations field is invalid.")

    products: list[dict[str, Any]] = []
    stack: list[tuple[object, int]] = [(entry, 0) for entry in reversed(configurations)]
    while stack and len(products) < MAX_AFFECTED_PRODUCTS:
        node, depth = stack.pop()
        if not isinstance(node, dict) or depth > MAX_CONFIGURATION_DEPTH:
            continue

        matches = node.get("cpeMatch", [])
        if isinstance(matches, list):
            for match in matches:
                if len(products) >= MAX_AFFECTED_PRODUCTS:
                    break
                product = _bounded_product(match)
                if product is not None:
                    products.append(product)

        children = node.get("nodes", [])
        if isinstance(children, list):
            stack.extend((child, depth + 1) for child in reversed(children))

    return products


def _bounded_product(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    if value.get("vulnerable") is not True:
        return None

    product: dict[str, Any] = {}
    product["vulnerable"] = True
    for field_name in AFFECTED_PRODUCT_FIELDS:
        field_value = value.get(field_name)
        if isinstance(field_value, str) and field_value:
            product[field_name] = _bounded_text(
                field_value,
                MAX_AFFECTED_VALUE_LENGTH,
            )
    return product or None


def _bounded_text(value: str, maximum_length: int) -> str:
    return value[:maximum_length]
