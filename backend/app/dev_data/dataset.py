"""Deterministic synthetic cybersecurity dataset for development and tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal
from hashlib import sha256
from urllib.parse import urlparse
from uuid import UUID, uuid5

from app.models.intelligence_item import (
    GEOGRAPHIC_SCOPE_VALUES,
    ITEM_TYPE_VALUES,
    STATUS_VALUES,
    UAE_RELEVANCE_METHOD_VALUES,
    UAE_RELEVANCE_STATUS_VALUES,
)
from app.models.intelligence_item_tag import ASSIGNED_BY_VALUES
from app.models.intelligence_source import SOURCE_TYPE_VALUES
from app.models.source_record import PROCESSING_STATUS_VALUES, UPSTREAM_STATUS_VALUES
from app.models.tag import TAG_TYPE_VALUES
from app.models.vulnerability import KEV_STATUS_VALUES, SEVERITY_VALUES


SEED_NAMESPACE = UUID("8b39bd40-cc46-4d39-9954-67e3a72f23f8")
BASE_TIME = datetime(2026, 7, 4, 9, 0, tzinfo=UTC)
SEED_IDENTIFIER_NAMESPACE = "alpha-seed"
SAFE_DOMAIN_SUFFIXES = ("example.com", "example.org", "example.net")
SECRET_FRAGMENTS = (
    "api_key",
    "authorization:",
    "bearer ",
    "cookie:",
    "password=",
    "postgresql://",
    "postgresql+psycopg://",
    "secret",
    "token=",
)
UNSAFE_CYBER_FRAGMENTS = (
    "curl ",
    "meterpreter",
    "msfconsole",
    "powershell -enc",
    "reverse shell",
    "rm -rf",
    "<script",
)


@dataclass(frozen=True)
class SeedSource:
    slug: str
    name: str
    public_id: UUID
    source_type: str
    base_url: str
    rate_limit_notes: str


@dataclass(frozen=True)
class SeedTag:
    slug: str
    display_name: str
    tag_type: str


@dataclass(frozen=True)
class SeedIdentifier:
    namespace: str
    value: str
    normalized_value: str
    is_primary: bool = False


@dataclass(frozen=True)
class SeedSourceRecord:
    source_slug: str
    source_external_id: str
    source_url: str
    source_published_at: datetime
    source_modified_at: datetime | None = None

    @property
    def content_hash(self) -> str:
        return sha256(
            f"{self.source_external_id}|{self.source_url}".encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True)
class SeedVulnerability:
    severity: str
    cvss_score: Decimal | None
    cvss_vector: str | None
    cvss_version: str | None
    epss_score: Decimal | None
    epss_percentile: Decimal | None
    kev_status: str
    kev_last_checked_at: datetime | None
    kev_date_added: date | None
    kev_due_date: date | None
    kev_required_action: str | None
    known_ransomware_campaign_use: bool | None
    affected_summary: str
    affected_products_json: list[dict[str, str]]


@dataclass(frozen=True)
class SeedItem:
    seed_key: str
    public_id: UUID
    item_type: str
    canonical_title: str
    summary: str
    canonical_url: str
    source_published_at: datetime
    source_modified_at: datetime | None
    collected_at: datetime
    last_seen_at: datetime
    status: str
    data_confidence: Decimal
    geographic_scope: str
    uae_relevance_status: str
    uae_relevance_confidence: Decimal | None
    uae_relevance_reason: str | None
    uae_relevance_method: str
    analyst_review_status: str
    source_record: SeedSourceRecord
    identifiers: tuple[SeedIdentifier, ...]
    tag_slugs: tuple[str, ...]
    vulnerability: SeedVulnerability | None = None
    tag_assignment_source: str = "system"
    tag_confidence: Decimal = Decimal("0.900")


@dataclass(frozen=True)
class SeedDataset:
    sources: tuple[SeedSource, ...]
    tags: tuple[SeedTag, ...]
    items: tuple[SeedItem, ...]

    @property
    def identifier_count(self) -> int:
        return sum(len(item.identifiers) for item in self.items)

    @property
    def vulnerability_count(self) -> int:
        return sum(1 for item in self.items if item.vulnerability is not None)

    @property
    def source_record_count(self) -> int:
        return len(self.items)

    @property
    def item_tag_association_count(self) -> int:
        return sum(len(item.tag_slugs) for item in self.items)


@dataclass(frozen=True)
class DatasetValidationResult:
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_valid(self) -> bool:
        return not self.errors


class DatasetValidationError(ValueError):
    """Raised when the static seed dataset is internally inconsistent."""


def deterministic_uuid(name: str) -> UUID:
    return uuid5(SEED_NAMESPACE, name)


def _dt(day: int, hour: int) -> datetime:
    return datetime(2026, 6, day, hour, 0, tzinfo=UTC)


def _seed_identifier(seed_key: str) -> SeedIdentifier:
    return SeedIdentifier(
        namespace=SEED_IDENTIFIER_NAMESPACE,
        value=seed_key,
        normalized_value=seed_key.upper(),
        is_primary=True,
    )


def build_seed_dataset() -> SeedDataset:
    sources = (
        SeedSource(
            slug="alpha-synthetic-cve",
            name="Alpha Synthetic CVE Feed",
            public_id=deterministic_uuid("source:alpha-synthetic-cve"),
            source_type="json",
            base_url="https://example.com/cyber/cves/",
            rate_limit_notes="Synthetic development source; no network requests.",
        ),
        SeedSource(
            slug="alpha-synthetic-advisories",
            name="Alpha Synthetic Advisory Bulletin",
            public_id=deterministic_uuid("source:alpha-synthetic-advisories"),
            source_type="rss",
            base_url="https://example.org/advisories/",
            rate_limit_notes="Synthetic development source; no network requests.",
        ),
        SeedSource(
            slug="alpha-synthetic-news",
            name="Alpha Synthetic Cyber News",
            public_id=deterministic_uuid("source:alpha-synthetic-news"),
            source_type="rss",
            base_url="https://example.net/news/",
            rate_limit_notes="Synthetic development source; no network requests.",
        ),
        SeedSource(
            slug="alpha-synthetic-uae",
            name="Alpha Synthetic UAE Defensive Alerts",
            public_id=deterministic_uuid("source:alpha-synthetic-uae"),
            source_type="api",
            base_url="https://example.com/uae-alerts/",
            rate_limit_notes="Synthetic development source; no network requests.",
        ),
    )
    tags = (
        SeedTag("uae", "UAE", "region"),
        SeedTag("global", "Global", "region"),
        SeedTag("critical-infrastructure", "Critical Infrastructure", "sector"),
        SeedTag("government", "Government", "sector"),
        SeedTag("finance", "Finance", "sector"),
        SeedTag("healthcare", "Healthcare", "sector"),
        SeedTag("cloud", "Cloud", "theme"),
        SeedTag("ransomware", "Ransomware", "theme"),
        SeedTag("phishing", "Phishing", "technique"),
        SeedTag("vulnerability", "Vulnerability", "general"),
        SeedTag("example-vendor", "Example Vendor", "vendor"),
        SeedTag("example-product", "Example Product", "product"),
    )

    items = (
        _vulnerability_item(
            seed_key="ALPHA-SEED-VULN-0001",
            title="Synthetic critical vulnerability in Example Gateway",
            summary=(
                "Fictional reserved CVE-shaped record for frontend testing. "
                "Defensive teams should inventory exposed Example Gateway assets, "
                "apply vendor updates, and monitor official advisories."
            ),
            cve="CVE-2099-900001",
            severity="critical",
            cvss="9.8",
            epss="0.812345",
            percentile="0.982100",
            kev_status="listed",
            kev_added=date(2026, 6, 18),
            kev_due=date(2026, 7, 9),
            source_day=18,
            tags=("global", "vulnerability", "critical-infrastructure", "example-vendor", "example-product"),
            uae_status="possible",
            uae_confidence="0.460",
            uae_reason="Could affect globally deployed perimeter gateways, including UAE operators.",
        ),
        _vulnerability_item(
            seed_key="ALPHA-SEED-VULN-0002",
            title="Synthetic high severity cloud control-plane exposure",
            summary=(
                "Fictional vulnerability record describing a cloud administration "
                "misconfiguration pattern for safe dashboard testing."
            ),
            cve="CVE-2099-900002",
            severity="high",
            cvss="8.1",
            epss="0.421000",
            percentile="0.801000",
            kev_status="not_listed",
            kev_added=None,
            kev_due=None,
            source_day=19,
            tags=("cloud", "vulnerability", "example-vendor", "global"),
            uae_status="not_relevant",
            uae_confidence="0.200",
            uae_reason="No UAE-specific signals in the synthetic source record.",
        ),
        _vulnerability_item(
            seed_key="ALPHA-SEED-VULN-0003",
            title="Synthetic medium vulnerability in healthcare scheduling portal",
            summary=(
                "Fictional medium-risk record for validating healthcare and regional "
                "filter behavior without using live threat intelligence."
            ),
            cve="CVE-2099-900003",
            severity="medium",
            cvss="5.6",
            epss="0.073000",
            percentile="0.411000",
            kev_status="unknown",
            kev_added=None,
            kev_due=None,
            source_day=20,
            tags=("healthcare", "vulnerability", "uae", "example-product"),
            uae_status="probable",
            uae_confidence="0.720",
            uae_reason="Synthetic source indicates possible regional healthcare exposure.",
        ),
        _vulnerability_item(
            seed_key="ALPHA-SEED-VULN-0004",
            title="Synthetic low severity reporting interface issue",
            summary=(
                "Fictional low-risk vulnerability record intended to exercise low "
                "severity and non-KEV dashboard states."
            ),
            cve="CVE-2099-900004",
            severity="low",
            cvss="2.7",
            epss="0.010000",
            percentile="0.120000",
            kev_status="not_listed",
            kev_added=None,
            kev_due=None,
            source_day=21,
            tags=("vulnerability", "example-product", "global"),
            uae_status="unknown",
            uae_confidence=None,
            uae_reason=None,
        ),
        _non_vulnerability_item(
            seed_key="ALPHA-SEED-ADV-0001",
            item_type="security_advisory",
            title="Synthetic advisory on patch prioritization for gateway appliances",
            summary=(
                "Safe advisory content for testing detail pages. Recommended actions "
                "include asset inventory, vendor patch review, and change-window planning."
            ),
            source_slug="alpha-synthetic-advisories",
            path="patch-prioritization-gateway-appliances",
            source_day=22,
            tags=("critical-infrastructure", "government", "vulnerability", "uae"),
            geographic_scope="uae",
            uae_status="confirmed",
            uae_confidence="0.930",
            uae_reason="Synthetic advisory is explicitly marked for UAE defensive teams.",
            uae_method="source_declared",
        ),
        _non_vulnerability_item(
            seed_key="ALPHA-SEED-NEWS-0001",
            item_type="cyber_news",
            title="Synthetic news article on regional phishing awareness campaign",
            summary=(
                "Fictional news item for validating dashboard news cards. The article "
                "summarizes defensive user-awareness themes and reporting workflows."
            ),
            source_slug="alpha-synthetic-news",
            path="regional-phishing-awareness",
            source_day=23,
            tags=("phishing", "finance", "uae"),
            geographic_scope="regional",
            uae_status="probable",
            uae_confidence="0.680",
            uae_reason="Synthetic article covers Gulf-region finance awareness.",
            uae_method="automatic",
        ),
        _non_vulnerability_item(
            seed_key="ALPHA-SEED-REPORT-0001",
            item_type="threat_report",
            title="Synthetic threat report on ransomware resilience trends",
            summary=(
                "Fictional threat report for testing safe detail-page summaries. "
                "It focuses on backup validation, segmentation, and incident readiness."
            ),
            source_slug="alpha-synthetic-news",
            path="ransomware-resilience-trends",
            source_day=24,
            tags=("ransomware", "critical-infrastructure", "global"),
            geographic_scope="global",
            uae_status="not_relevant",
            uae_confidence="0.180",
            uae_reason="Global trend report with no UAE-specific indicator.",
            uae_method="automatic",
        ),
        _non_vulnerability_item(
            seed_key="ALPHA-SEED-UAE-0001",
            item_type="uae_official_alert",
            title="Synthetic UAE alert on cloud account hardening",
            summary=(
                "Fictional UAE-focused defensive alert. Recommended actions include "
                "multi-factor authentication review, role cleanup, and audit logging."
            ),
            source_slug="alpha-synthetic-uae",
            path="cloud-account-hardening",
            source_day=25,
            tags=("uae", "cloud", "government"),
            geographic_scope="uae",
            uae_status="confirmed",
            uae_confidence="0.990",
            uae_reason="Synthetic alert is explicitly scoped to UAE organizations.",
            uae_method="source_declared",
        ),
        _non_vulnerability_item(
            seed_key="ALPHA-SEED-GUIDE-0001",
            item_type="other_defensive_intel",
            title="Synthetic defensive guidance for supplier security reviews",
            summary=(
                "Fictional guidance item for frontend empty and detail states. "
                "It recommends supplier inventory, contract security checks, and evidence review."
            ),
            source_slug="alpha-synthetic-advisories",
            path="supplier-security-reviews",
            source_day=26,
            tags=("finance", "healthcare", "government", "global"),
            geographic_scope="global",
            uae_status="possible",
            uae_confidence="0.410",
            uae_reason="Controls may apply to UAE entities using global suppliers.",
            uae_method="manual",
        ),
        _non_vulnerability_item(
            seed_key="ALPHA-SEED-ADV-0002",
            item_type="security_advisory",
            title="Synthetic advisory with unknown severity for asset owners",
            summary=(
                "Fictional advisory where severity is intentionally not applicable, "
                "supporting frontend handling of unknown or absent vulnerability state."
            ),
            source_slug="alpha-synthetic-advisories",
            path="unknown-severity-asset-owner-advisory",
            source_day=27,
            tags=("example-vendor", "example-product", "global"),
            geographic_scope="unknown",
            uae_status="unknown",
            uae_confidence=None,
            uae_reason=None,
            uae_method="unassigned",
        ),
    )
    dataset = SeedDataset(sources=sources, tags=tags, items=items)
    validate_seed_dataset(dataset, raise_on_error=True)
    return dataset


def _vulnerability_item(
    *,
    seed_key: str,
    title: str,
    summary: str,
    cve: str,
    severity: str,
    cvss: str,
    epss: str,
    percentile: str,
    kev_status: str,
    kev_added: date | None,
    kev_due: date | None,
    source_day: int,
    tags: tuple[str, ...],
    uae_status: str,
    uae_confidence: str | None,
    uae_reason: str | None,
) -> SeedItem:
    source_slug = "alpha-synthetic-cve"
    url = f"https://example.com/cyber/cves/{cve.lower()}"
    source_published_at = _dt(source_day, 8)
    collected_at = _dt(source_day + 1, 9)
    return SeedItem(
        seed_key=seed_key,
        public_id=deterministic_uuid(seed_key),
        item_type="vulnerability",
        canonical_title=title,
        summary=summary,
        canonical_url=url,
        source_published_at=source_published_at,
        source_modified_at=_dt(source_day + 1, 11),
        collected_at=collected_at,
        last_seen_at=BASE_TIME,
        status="active",
        data_confidence=Decimal("0.950"),
        geographic_scope="global" if uae_status in {"not_relevant", "unknown"} else "regional",
        uae_relevance_status=uae_status,
        uae_relevance_confidence=(
            Decimal(uae_confidence) if uae_confidence is not None else None
        ),
        uae_relevance_reason=uae_reason,
        uae_relevance_method="automatic" if uae_confidence is not None else "unassigned",
        analyst_review_status="pending",
        source_record=SeedSourceRecord(
            source_slug=source_slug,
            source_external_id=seed_key,
            source_url=url,
            source_published_at=source_published_at,
            source_modified_at=_dt(source_day + 1, 11),
        ),
        identifiers=(
            _seed_identifier(seed_key),
            SeedIdentifier("cve", cve, cve, is_primary=False),
        ),
        tag_slugs=tags,
        vulnerability=SeedVulnerability(
            severity=severity,
            cvss_score=Decimal(cvss),
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_version="3.1",
            epss_score=Decimal(epss),
            epss_percentile=Decimal(percentile),
            kev_status=kev_status,
            kev_last_checked_at=BASE_TIME,
            kev_date_added=kev_added,
            kev_due_date=kev_due,
            kev_required_action=(
                "Apply vendor mitigation or update according to official guidance."
                if kev_status == "listed"
                else None
            ),
            known_ransomware_campaign_use=(False if kev_status != "unknown" else None),
            affected_summary="Fictional Example Vendor product versions before 9.9.9.",
            affected_products_json=[
                {
                    "vendor": "Example Vendor",
                    "product": "Example Product",
                    "versions": "Synthetic versions before 9.9.9",
                }
            ],
        ),
    )


def _non_vulnerability_item(
    *,
    seed_key: str,
    item_type: str,
    title: str,
    summary: str,
    source_slug: str,
    path: str,
    source_day: int,
    tags: tuple[str, ...],
    geographic_scope: str,
    uae_status: str,
    uae_confidence: str | None,
    uae_reason: str | None,
    uae_method: str,
) -> SeedItem:
    domain = "example.org" if "advisories" in source_slug else "example.net"
    if source_slug == "alpha-synthetic-uae":
        domain = "example.com"
    url = f"https://{domain}/{path}"
    source_published_at = _dt(source_day, 10)
    return SeedItem(
        seed_key=seed_key,
        public_id=deterministic_uuid(seed_key),
        item_type=item_type,
        canonical_title=title,
        summary=summary,
        canonical_url=url,
        source_published_at=source_published_at,
        source_modified_at=None,
        collected_at=_dt(source_day + 1, 9),
        last_seen_at=BASE_TIME,
        status="active",
        data_confidence=Decimal("0.880"),
        geographic_scope=geographic_scope,
        uae_relevance_status=uae_status,
        uae_relevance_confidence=(
            Decimal(uae_confidence) if uae_confidence is not None else None
        ),
        uae_relevance_reason=uae_reason,
        uae_relevance_method=uae_method,
        analyst_review_status="pending",
        source_record=SeedSourceRecord(
            source_slug=source_slug,
            source_external_id=seed_key,
            source_url=url,
            source_published_at=source_published_at,
        ),
        identifiers=(_seed_identifier(seed_key),),
        tag_slugs=tags,
    )


def validate_seed_dataset(
    dataset: SeedDataset,
    *,
    raise_on_error: bool = False,
) -> DatasetValidationResult:
    errors: list[str] = []
    source_slugs = {source.slug for source in dataset.sources}
    tag_slugs = {tag.slug for tag in dataset.tags}
    seed_keys = [item.seed_key for item in dataset.items]

    _require_unique("source slug", [source.slug for source in dataset.sources], errors)
    _require_unique("source name", [source.name for source in dataset.sources], errors)
    _require_unique(
        "source public id",
        [str(source.public_id) for source in dataset.sources],
        errors,
    )
    _require_unique("tag slug", [tag.slug for tag in dataset.tags], errors)
    _require_unique("item seed key", seed_keys, errors)
    _require_unique("item public id", [str(item.public_id) for item in dataset.items], errors)

    identifiers = [
        (identifier.namespace, identifier.normalized_value)
        for item in dataset.items
        for identifier in item.identifiers
        if identifier.namespace != SEED_IDENTIFIER_NAMESPACE
    ]
    _require_unique("non-seed identifier", identifiers, errors)

    for source in dataset.sources:
        _require_in("source_type", source.source_type, SOURCE_TYPE_VALUES, errors)
        _validate_url(source.base_url, errors)
        _validate_text(source.rate_limit_notes, 500, errors)

    for tag in dataset.tags:
        _require_in("tag_type", tag.tag_type, TAG_TYPE_VALUES, errors)
        _validate_text(tag.slug, 100, errors)
        _validate_text(tag.display_name, 120, errors)

    for item in dataset.items:
        _require_in("item_type", item.item_type, ITEM_TYPE_VALUES, errors)
        _require_in("status", item.status, STATUS_VALUES, errors)
        _require_in("geographic_scope", item.geographic_scope, GEOGRAPHIC_SCOPE_VALUES, errors)
        _require_in(
            "uae_relevance_status",
            item.uae_relevance_status,
            UAE_RELEVANCE_STATUS_VALUES,
            errors,
        )
        _require_in(
            "uae_relevance_method",
            item.uae_relevance_method,
            UAE_RELEVANCE_METHOD_VALUES,
            errors,
        )
        _require_in(
            "tag_assignment_source",
            item.tag_assignment_source,
            ASSIGNED_BY_VALUES,
            errors,
        )
        _validate_url(item.canonical_url, errors)
        _validate_text(item.canonical_title, 500, errors)
        _validate_text(item.summary, 4000, errors)
        _validate_optional_text(item.uae_relevance_reason, 1000, errors)
        _validate_decimal_range("data_confidence", item.data_confidence, errors)
        _validate_decimal_range(
            "uae_relevance_confidence",
            item.uae_relevance_confidence,
            errors,
        )
        _validate_decimal_range("tag_confidence", item.tag_confidence, errors)
        _validate_timezone(item.source_published_at, errors)
        _validate_timezone(item.collected_at, errors)
        _validate_timezone(item.last_seen_at, errors)
        if item.source_modified_at is not None:
            _validate_timezone(item.source_modified_at, errors)
        if item.source_record.source_slug not in source_slugs:
            errors.append(f"undefined source slug: {item.source_record.source_slug}")
        if item.source_record.source_external_id != item.seed_key:
            errors.append(f"source external id must match seed key: {item.seed_key}")
        _validate_url(item.source_record.source_url, errors)
        _validate_timezone(item.source_record.source_published_at, errors)
        if item.source_record.source_modified_at is not None:
            _validate_timezone(item.source_record.source_modified_at, errors)

        if len([identifier for identifier in item.identifiers if identifier.is_primary]) != 1:
            errors.append(f"item must have exactly one primary identifier: {item.seed_key}")
        if _seed_identifier(item.seed_key) not in item.identifiers:
            errors.append(f"item missing deterministic seed identifier: {item.seed_key}")

        for tag_slug in item.tag_slugs:
            if tag_slug not in tag_slugs:
                errors.append(f"undefined tag slug: {tag_slug}")

        for identifier in item.identifiers:
            _validate_text(identifier.namespace, 40, errors)
            _validate_text(identifier.value, 300, errors)
            _validate_text(identifier.normalized_value, 300, errors)

        if item.vulnerability is not None:
            _validate_vulnerability(item.vulnerability, errors)

    result = DatasetValidationResult(errors=tuple(errors))
    if raise_on_error and not result.is_valid:
        raise DatasetValidationError("; ".join(result.errors))
    return result


def _validate_vulnerability(vulnerability: SeedVulnerability, errors: list[str]) -> None:
    _require_in("severity", vulnerability.severity, SEVERITY_VALUES, errors)
    _require_in("kev_status", vulnerability.kev_status, KEV_STATUS_VALUES, errors)
    _validate_decimal_range("cvss_score", vulnerability.cvss_score, errors, upper=Decimal("10"))
    _validate_decimal_range("epss_score", vulnerability.epss_score, errors)
    _validate_decimal_range("epss_percentile", vulnerability.epss_percentile, errors)
    _validate_optional_text(vulnerability.cvss_vector, 300, errors)
    _validate_optional_text(vulnerability.cvss_version, 10, errors)
    _validate_optional_text(vulnerability.kev_required_action, 4000, errors)
    _validate_text(vulnerability.affected_summary, 4000, errors)
    if vulnerability.kev_last_checked_at is not None:
        _validate_timezone(vulnerability.kev_last_checked_at, errors)


def _validate_url(url: str, errors: list[str]) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        errors.append(f"unsafe URL scheme: {url}")
    if not any(parsed.hostname == domain for domain in SAFE_DOMAIN_SUFFIXES):
        errors.append(f"URL must use an example domain: {url}")


def _validate_text(value: str, max_length: int, errors: list[str]) -> None:
    if not value or len(value) > max_length:
        errors.append(f"text length outside 1..{max_length}: {value[:30]}")
    lowered = value.lower()
    for fragment in SECRET_FRAGMENTS + UNSAFE_CYBER_FRAGMENTS:
        if fragment in lowered:
            errors.append(f"unsafe text fragment detected: {fragment}")


def _validate_optional_text(
    value: str | None,
    max_length: int,
    errors: list[str],
) -> None:
    if value is not None:
        _validate_text(value, max_length, errors)


def _validate_timezone(value: datetime, errors: list[str]) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        errors.append(f"timestamp must be timezone-aware: {value!r}")


def _validate_decimal_range(
    name: str,
    value: Decimal | None,
    errors: list[str],
    *,
    upper: Decimal = Decimal("1"),
) -> None:
    if value is not None and not (Decimal("0") <= value <= upper):
        errors.append(f"{name} outside allowed range: {value}")


def _require_in(
    name: str,
    value: str,
    allowed_values: tuple[str, ...],
    errors: list[str],
) -> None:
    if value not in allowed_values:
        errors.append(f"{name} has unsupported value: {value}")


def _require_unique(name: str, values: list[object], errors: list[str]) -> None:
    seen: set[object] = set()
    duplicates: set[object] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    if duplicates:
        errors.append(f"duplicate {name}: {sorted(str(value) for value in duplicates)}")


SEED_DATASET = build_seed_dataset()
