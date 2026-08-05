"""Immutable developer-controlled registry for current and planned sources."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import ipaddress
import re
from types import MappingProxyType
from urllib.parse import urlparse


class SourceRegistryError(ValueError):
    """A source registry definition or lookup is invalid."""


class UnknownSourceError(SourceRegistryError):
    """A requested source slug is not registered."""


class AccessMethod(str, Enum):
    """Supported high-level integration classes for source definitions."""

    PUBLIC_PUBLICATION = "public_publication"
    PUBLIC_FEED = "public_feed"
    AUTHORIZED_API = "authorized_api"
    STIX_TAXII = "stix_taxii"
    MANUAL_CATALOGUE = "manual_catalogue"
    DEVELOPER_REFERENCE = "developer_reference"


class ImplementationStatus(str, Enum):
    """Implementation lifecycle status for a registered source."""

    IMPLEMENTED = "implemented"
    PLANNED = "planned"
    EXCLUDED = "excluded"


class ContentFamily(str, Enum):
    """Normalized content families used by current and planned source work."""

    VULNERABILITY = "vulnerability"
    EXPLOIT_ENRICHMENT = "exploit_enrichment"
    SECURITY_ADVISORY = "security_advisory"
    THREAT_RESEARCH = "threat_research"
    EXPOSURE_RESEARCH = "exposure_research"
    PUBLIC_OSINT_ADVISORY = "public_osint_advisory"


class ProgressContract(str, Enum):
    """Developer-controlled progress state required after durable persistence."""

    NONE = "none"
    CHECKPOINT = "checkpoint"
    WATERMARK = "watermark"


@dataclass(frozen=True, slots=True)
class SourceDefinition:
    """Safe non-secret source metadata controlled by application code."""

    slug: str
    display_name: str
    vendor: str
    source_family: str
    content_family: ContentFamily
    access_method: AccessMethod
    allowed_hosts: tuple[str, ...]
    authentication_required: bool
    structured: bool
    implementation_status: ImplementationStatus
    enabled: bool
    progress_contract: ProgressContract
    source_type: str | None = None
    base_url: str | None = None
    canonical_publication_hosts: tuple[str, ...] | None = None
    rate_limit_notes: str | None = None


_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SOURCE_TYPE_VALUES = {"api", "rss", "csv", "json", "html"}


def get_source_definition(slug: str) -> SourceDefinition:
    """Return one immutable source definition by canonical slug."""

    canonical_slug = _normalize_slug(slug)
    try:
        return _REGISTRY[canonical_slug]
    except KeyError as exc:
        raise UnknownSourceError("Unknown source slug.") from exc


def list_source_definitions() -> tuple[SourceDefinition, ...]:
    """Return all registered source definitions in deterministic slug order."""

    return tuple(_REGISTRY[slug] for slug in sorted(_REGISTRY))


def list_enabled_implemented_sources() -> tuple[SourceDefinition, ...]:
    """Return enabled sources that are fully implemented today."""

    return tuple(
        source
        for source in list_source_definitions()
        if source.enabled
        and source.implementation_status is ImplementationStatus.IMPLEMENTED
    )


def list_source_definitions_by_vendor(vendor: str) -> tuple[SourceDefinition, ...]:
    """Return registered source definitions for one vendor name."""

    normalized_vendor = _require_text(vendor, "vendor").casefold()
    return tuple(
        source
        for source in list_source_definitions()
        if source.vendor.casefold() == normalized_vendor
    )


def source_allows_hostname(slug: str, hostname: str) -> bool:
    """Match exact registry host metadata without granting network approval."""

    source = get_source_definition(slug)
    try:
        candidate = _normalize_allowed_host(hostname)
    except SourceRegistryError:
        return False
    return candidate in source.allowed_hosts


def source_allows_publication_hostname(slug: str, hostname: str) -> bool:
    """Match publication-host metadata without granting network approval."""

    source = get_source_definition(slug)
    try:
        candidate = _normalize_allowed_host(hostname)
    except SourceRegistryError:
        return False
    return candidate in _publication_hosts_for_source(source)


def get_required_source_base_url(slug: str) -> str:
    """Return an implemented source base URL or fail with a sanitized error."""

    source = get_source_definition(slug)
    if (
        source.implementation_status is not ImplementationStatus.IMPLEMENTED
        or source.enabled is not True
        or source.base_url is None
    ):
        raise SourceRegistryError("Source base URL is unavailable.")
    return source.base_url


def build_source_registry(
    definitions: tuple[SourceDefinition, ...],
) -> MappingProxyType[str, SourceDefinition]:
    """Validate and freeze source definitions for internal construction/tests."""

    registry: dict[str, SourceDefinition] = {}
    for definition in definitions:
        normalized = validate_source_definition(definition)
        if normalized.slug in registry:
            raise SourceRegistryError("Duplicate source slug.")
        registry[normalized.slug] = normalized
    return MappingProxyType(registry)


def validate_source_definition(definition: SourceDefinition) -> SourceDefinition:
    """Validate one source definition and return a normalized frozen copy."""

    slug = _normalize_slug(definition.slug)
    display_name = _require_text(definition.display_name, "display_name")
    vendor = _require_text(definition.vendor, "vendor")
    source_family = _require_text(definition.source_family, "source_family")
    authentication_required = _require_bool(
        definition.authentication_required,
        "authentication_required",
    )
    structured = _require_bool(definition.structured, "structured")
    enabled = _require_bool(definition.enabled, "enabled")
    access_method = _enum_value(definition.access_method, AccessMethod, "access_method")
    content_family = _enum_value(
        definition.content_family,
        ContentFamily,
        "content_family",
    )
    implementation_status = _enum_value(
        definition.implementation_status,
        ImplementationStatus,
        "implementation_status",
    )
    progress_contract = _enum_value(
        definition.progress_contract,
        ProgressContract,
        "progress_contract",
    )
    allowed_hosts = tuple(
        _normalize_allowed_host(host) for host in definition.allowed_hosts
    )
    if not allowed_hosts:
        raise SourceRegistryError("Source definitions require at least one allowed host.")
    if len(set(allowed_hosts)) != len(allowed_hosts):
        raise SourceRegistryError("Duplicate allowed host entry.")
    source_type = _optional_text(definition.source_type, "source_type")
    base_url = _optional_text(definition.base_url, "base_url")
    canonical_publication_hosts = (
        None
        if definition.canonical_publication_hosts is None
        else tuple(
            _normalize_allowed_host(host)
            for host in definition.canonical_publication_hosts
        )
    )
    rate_limit_notes = _optional_text(definition.rate_limit_notes, "rate_limit_notes")
    if enabled and implementation_status is not ImplementationStatus.IMPLEMENTED:
        raise SourceRegistryError("Only implemented sources may be enabled.")
    if implementation_status is ImplementationStatus.IMPLEMENTED and (
        source_type is None or base_url is None
    ):
        raise SourceRegistryError("Implemented sources require safe source identity.")
    if source_type is not None and source_type not in _SOURCE_TYPE_VALUES:
        raise SourceRegistryError("Unsupported source type.")
    if base_url is not None:
        _validate_base_url(base_url, allowed_hosts)
    if canonical_publication_hosts is not None:
        if not canonical_publication_hosts:
            raise SourceRegistryError(
                "Canonical publication hosts must not be empty."
            )
        if len(set(canonical_publication_hosts)) != len(canonical_publication_hosts):
            raise SourceRegistryError("Duplicate canonical publication host entry.")

    return replace(
        definition,
        slug=slug,
        display_name=display_name,
        vendor=vendor,
        source_family=source_family,
        content_family=content_family,
        access_method=access_method,
        allowed_hosts=allowed_hosts,
        authentication_required=authentication_required,
        structured=structured,
        implementation_status=implementation_status,
        enabled=enabled,
        progress_contract=progress_contract,
        source_type=source_type,
        base_url=base_url,
        canonical_publication_hosts=canonical_publication_hosts,
        rate_limit_notes=rate_limit_notes,
    )


def _publication_hosts_for_source(source: SourceDefinition) -> tuple[str, ...]:
    return source.canonical_publication_hosts or source.allowed_hosts


def _normalize_slug(slug: str) -> str:
    if not isinstance(slug, str):
        raise SourceRegistryError("Source slug must be a string.")
    canonical = slug
    if not canonical or _SLUG_PATTERN.fullmatch(canonical) is None:
        raise SourceRegistryError("Source slug is not canonical.")
    return canonical


def _require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SourceRegistryError(f"Source {field_name} is required.")
    return value.strip()


def _optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SourceRegistryError(f"Source {field_name} must be a string.")
    normalized = value.strip()
    if not normalized:
        raise SourceRegistryError(f"Source {field_name} must not be empty.")
    return normalized


def _require_bool(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise SourceRegistryError(f"Source {field_name} must be a boolean.")
    return value


def _enum_value(value, enum_type, field_name: str):
    try:
        return value if isinstance(value, enum_type) else enum_type(value)
    except ValueError as exc:
        raise SourceRegistryError(f"Unsupported {field_name}.") from exc


def _normalize_allowed_host(host: str) -> str:
    if not isinstance(host, str) or not host.strip():
        raise SourceRegistryError("Allowed host must be a non-empty hostname.")
    candidate = host.strip().lower()
    if candidate.endswith(".."):
        raise SourceRegistryError("Allowed host is malformed.")
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if any(token in candidate for token in ("://", "/", "\\", "?", "#", "@", "*")):
        raise SourceRegistryError("Allowed host must be a hostname only.")
    if ":" in candidate:
        raise SourceRegistryError("Allowed host must not include a port.")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise SourceRegistryError("Allowed host must be a DNS hostname.")

    labels = candidate.split(".")
    if (
        len(labels) < 2
        or any(not label for label in labels)
        or any(_HOST_LABEL_PATTERN.fullmatch(label) is None for label in labels)
    ):
        raise SourceRegistryError("Allowed host is malformed.")
    return candidate


def _validate_base_url(base_url: str, allowed_hosts: tuple[str, ...]) -> None:
    if not isinstance(base_url, str) or not base_url.strip():
        raise SourceRegistryError("Source base URL must be a non-empty string.")
    try:
        parsed = urlparse(base_url.strip())
        scheme = parsed.scheme.lower()
        username = parsed.username
        password = parsed.password
        port = parsed.port
        host = _normalize_allowed_host(parsed.hostname or "")
    except ValueError as exc:
        raise SourceRegistryError("Source base URL is invalid.") from exc
    if scheme != "https":
        raise SourceRegistryError("Source base URL must use HTTPS.")
    if "@" in parsed.netloc or username or password:
        raise SourceRegistryError("Source base URL must not contain credentials.")
    if port not in (None, 443):
        raise SourceRegistryError("Source base URL uses an unexpected port.")
    if parsed.fragment:
        raise SourceRegistryError("Source base URL must not contain a fragment.")
    if parsed.query:
        raise SourceRegistryError("Source base URL must not contain a query string.")
    if host not in allowed_hosts:
        raise SourceRegistryError("Source base URL host is not allowed.")


_IMPLEMENTED_DEFINITIONS = (
    SourceDefinition(
        slug="nvd",
        display_name="National Vulnerability Database",
        vendor="NIST",
        source_family="NVD CVE API",
        content_family=ContentFamily.VULNERABILITY,
        access_method=AccessMethod.AUTHORIZED_API,
        allowed_hosts=("services.nvd.nist.gov",),
        authentication_required=False,
        structured=True,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.WATERMARK,
        source_type="api",
        base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        rate_limit_notes=(
            "Use conservative NVD API pacing; authenticated requests may use the "
            "documented higher limit."
        ),
    ),
    SourceDefinition(
        slug="first-epss",
        display_name="FIRST EPSS",
        vendor="FIRST",
        source_family="Exploit Prediction Scoring System",
        content_family=ContentFamily.EXPLOIT_ENRICHMENT,
        access_method=AccessMethod.AUTHORIZED_API,
        allowed_hosts=("api.first.org",),
        authentication_required=False,
        structured=True,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.WATERMARK,
        source_type="api",
        base_url="https://api.first.org/data/v1/epss",
        rate_limit_notes="Use bounded manual requests to the public FIRST EPSS API.",
    ),
    SourceDefinition(
        slug="cisa-kev",
        display_name="CISA Known Exploited Vulnerabilities Catalog",
        vendor="CISA",
        source_family="Known Exploited Vulnerabilities Catalog",
        content_family=ContentFamily.EXPLOIT_ENRICHMENT,
        access_method=AccessMethod.PUBLIC_PUBLICATION,
        allowed_hosts=("www.cisa.gov",),
        authentication_required=False,
        structured=True,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.CHECKPOINT,
        source_type="json",
        base_url=(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        ),
        rate_limit_notes=(
            "Use bounded manual requests to the official CISA KEV JSON catalog."
        ),
    ),
    SourceDefinition(
        slug="cert-eu-security-advisories",
        display_name="CERT-EU Security Advisories",
        vendor="CERT-EU",
        source_family="Security Advisories RSS",
        content_family=ContentFamily.SECURITY_ADVISORY,
        access_method=AccessMethod.PUBLIC_FEED,
        allowed_hosts=("cert.europa.eu",),
        authentication_required=False,
        structured=True,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.WATERMARK,
        source_type="rss",
        base_url="https://cert.europa.eu/publications/security-advisories-rss",
        rate_limit_notes="Manual bounded requests to the approved CERT-EU RSS feed only.",
    ),
    SourceDefinition(
        slug="censys-arc-research",
        display_name="Censys ARC Research",
        vendor="Censys",
        source_family="ARC research",
        content_family=ContentFamily.EXPOSURE_RESEARCH,
        access_method=AccessMethod.MANUAL_CATALOGUE,
        allowed_hosts=("censys.com",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.NONE,
        source_type="json",
        base_url="https://censys.com/blog/",
        rate_limit_notes=(
            "Bounded manual live publication-metadata collection from the fixed "
            "public discovery location with at least ten seconds between request "
            "starts; reviewed local-file JSON import remains supported."
        ),
    ),
    SourceDefinition(
        slug="censys-rapid-response-advisories",
        display_name="Censys Rapid Response Advisories",
        vendor="Censys",
        source_family="Rapid response advisories",
        content_family=ContentFamily.PUBLIC_OSINT_ADVISORY,
        access_method=AccessMethod.MANUAL_CATALOGUE,
        allowed_hosts=("censys.com",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.NONE,
        source_type="json",
        base_url="https://censys.com/advisory/",
        rate_limit_notes=(
            "Bounded manual live publication-metadata collection from the fixed "
            "public discovery location with at least ten seconds between request "
            "starts; reviewed local-file JSON import remains supported."
        ),
    ),
    SourceDefinition(
        slug="anomali-cyber-watch",
        display_name="Anomali Cyber Watch",
        vendor="Anomali",
        source_family="Cyber Watch",
        content_family=ContentFamily.THREAT_RESEARCH,
        access_method=AccessMethod.MANUAL_CATALOGUE,
        allowed_hosts=("www.anomali.com",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.NONE,
        source_type="json",
        base_url="https://www.anomali.com/blog",
        rate_limit_notes=(
            "Manual-only live publication-metadata collection from one fixed public "
            "discovery page, with at least ten seconds between request starts and "
            "a maximum of 20 records; reviewed local-file JSON fallback remains "
            "supported. The controlled 19 July 2026 HTTP 200 response contained no "
            "deterministic main-content region or approved Cyber Watch article "
            "links, so discovery failed safely before database-session creation."
        ),
    ),
    SourceDefinition(
        slug="ibm-x-force-public-research",
        display_name="IBM X-Force Public Research",
        vendor="IBM X-Force",
        source_family="X-Force research",
        content_family=ContentFamily.THREAT_RESEARCH,
        access_method=AccessMethod.MANUAL_CATALOGUE,
        allowed_hosts=("www.ibm.com",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.NONE,
        source_type="json",
        base_url="https://www.ibm.com/think/x-force/",
        rate_limit_notes=(
            "Manual local-file metadata import only; no IBM network requests."
        ),
    ),
    SourceDefinition(
        slug="ibm-x-force-public-osint-advisories",
        display_name="IBM X-Force Public OSINT Advisories",
        vendor="IBM X-Force",
        source_family="Public OSINT advisories",
        content_family=ContentFamily.PUBLIC_OSINT_ADVISORY,
        access_method=AccessMethod.MANUAL_CATALOGUE,
        allowed_hosts=("exchange.xforce.ibmcloud.com",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.NONE,
        source_type="json",
        base_url="https://exchange.xforce.ibmcloud.com/osint/",
        rate_limit_notes=(
            "Manual local-file metadata import only; no X-Force Exchange network "
            "requests, login, guest automation, or API access."
        ),
    ),
    SourceDefinition(
        slug="google-threat-intelligence-public-research",
        display_name="Google Threat Intelligence Public Research",
        vendor="Google Threat Intelligence",
        source_family="Public threat research",
        content_family=ContentFamily.THREAT_RESEARCH,
        access_method=AccessMethod.PUBLIC_FEED,
        allowed_hosts=("feeds.feedburner.com",),
        authentication_required=False,
        structured=True,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.WATERMARK,
        source_type="rss",
        base_url="https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
        canonical_publication_hosts=("cloud.google.com",),
        rate_limit_notes=(
            "Manual bounded requests to the official shared Google Cloud Threat "
            "Intelligence RSS feed only; article bodies are not fetched."
        ),
    ),
    SourceDefinition(
        slug="mandiant-public-threat-research",
        display_name="Mandiant Public Threat Research",
        vendor="Mandiant / Google Security",
        source_family="Mandiant threat research",
        content_family=ContentFamily.THREAT_RESEARCH,
        access_method=AccessMethod.PUBLIC_FEED,
        allowed_hosts=("feeds.feedburner.com",),
        authentication_required=False,
        structured=True,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        progress_contract=ProgressContract.WATERMARK,
        source_type="rss",
        base_url="https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
        canonical_publication_hosts=("cloud.google.com",),
        rate_limit_notes=(
            "Manual bounded requests to the official shared Google Cloud Threat "
            "Intelligence RSS feed only; article bodies are not fetched."
        ),
    ),
)

_DISABLED_DEFINITIONS: tuple[SourceDefinition, ...] = (
    SourceDefinition(
        slug="mitre-attack-enterprise",
        display_name="MITRE ATT&CK Enterprise",
        vendor="MITRE",
        source_family="Enterprise ATT&CK TAXII/STIX 2.1",
        content_family=ContentFamily.THREAT_RESEARCH,
        access_method=AccessMethod.STIX_TAXII,
        allowed_hosts=("attack-taxii.mitre.org",),
        authentication_required=False,
        structured=True,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=False,
        progress_contract=ProgressContract.CHECKPOINT,
        source_type="json",
        base_url=(
            "https://attack-taxii.mitre.org/api/v21/collections/"
            "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019/"
            "objects/"
        ),
        rate_limit_notes=(
            "Fixture-tested fixed Enterprise ATT&CK TAXII 2.1 collection; disabled "
            "pending separate activation approval. Maximum 40 requests per run "
            "preserves headroom below the documented service limit."
        ),
    ),
    SourceDefinition(
        slug="cert-fr-security-alerts",
        display_name="CERT-FR Security Alerts",
        vendor="CERT-FR / ANSSI",
        source_family="Official security alerts RSS metadata",
        content_family=ContentFamily.SECURITY_ADVISORY,
        access_method=AccessMethod.PUBLIC_FEED,
        allowed_hosts=("www.cert.ssi.gouv.fr",),
        authentication_required=False,
        structured=True,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=False,
        progress_contract=ProgressContract.CHECKPOINT,
        source_type="rss",
        base_url="https://www.cert.ssi.gouv.fr/alerte/feed/",
        canonical_publication_hosts=(
            "www.cert.ssi.gouv.fr",
            "cert.ssi.gouv.fr",
        ),
        rate_limit_notes=(
            "Fixture-tested strict official RSS metadata collector; disabled pending "
            "separate activation approval."
        ),
    ),
    SourceDefinition(
        slug="cert-fr-security-advisories",
        display_name="CERT-FR Security Advisories",
        vendor="CERT-FR / ANSSI",
        source_family="Official security advisories RSS metadata",
        content_family=ContentFamily.SECURITY_ADVISORY,
        access_method=AccessMethod.PUBLIC_FEED,
        allowed_hosts=("cert.ssi.gouv.fr",),
        authentication_required=False,
        structured=True,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=False,
        progress_contract=ProgressContract.CHECKPOINT,
        source_type="rss",
        base_url="https://cert.ssi.gouv.fr/avis/feed/",
        canonical_publication_hosts=(
            "www.cert.ssi.gouv.fr",
            "cert.ssi.gouv.fr",
        ),
        rate_limit_notes=(
            "Fixture-tested strict official RSS metadata collector; disabled pending "
            "separate activation approval."
        ),
    ),
    SourceDefinition(
        slug="uk-ncsc-threat-reports",
        display_name="UK NCSC Threat Reports",
        vendor="UK National Cyber Security Centre",
        source_family="Official Threat Reports RSS metadata",
        content_family=ContentFamily.THREAT_RESEARCH,
        access_method=AccessMethod.PUBLIC_FEED,
        allowed_hosts=("www.ncsc.gov.uk",),
        authentication_required=False,
        structured=True,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=False,
        progress_contract=ProgressContract.CHECKPOINT,
        source_type="rss",
        base_url=(
            "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"
        ),
        canonical_publication_hosts=("www.ncsc.gov.uk",),
        rate_limit_notes=(
            "Fixture-tested strict official RSS metadata collector; disabled pending "
            "separate activation approval."
        ),
    ),
    SourceDefinition(
        slug="ae-cert",
        display_name="UAE Computer Emergency Response Team (aeCERT)",
        vendor="TDRA / aeCERT",
        source_family="Public security advisories",
        content_family=ContentFamily.SECURITY_ADVISORY,
        access_method=AccessMethod.MANUAL_CATALOGUE,
        allowed_hosts=("tdra.gov.ae",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.PLANNED,
        enabled=False,
        progress_contract=ProgressContract.NONE,
        rate_limit_notes=(
            "No stable advisory or security-publication listing or assessed "
            "request path; automation and cadence remain unapproved."
        ),
    ),
    SourceDefinition(
        slug="uae-cyber-security-council",
        display_name="UAE Cyber Security Council Public Updates",
        vendor="UAE Cyber Security Council",
        source_family="Stay Alert and public update metadata",
        content_family=ContentFamily.PUBLIC_OSINT_ADVISORY,
        access_method=AccessMethod.PUBLIC_PUBLICATION,
        allowed_hosts=("csc.gov.ae",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.PLANNED,
        enabled=False,
        progress_contract=ProgressContract.NONE,
        base_url="https://csc.gov.ae/en/stay-alert",
        rate_limit_notes=(
            "Automation requires explicit permission; proposed minimum cadence "
            "after approval is six hours."
        ),
    ),
    SourceDefinition(
        slug="uae-cyber-security-council-nibras",
        display_name="UAE Cyber Security Council NibraS",
        vendor="UAE Cyber Security Council",
        source_family="NibraS navigation reference",
        content_family=ContentFamily.THREAT_RESEARCH,
        access_method=AccessMethod.MANUAL_CATALOGUE,
        allowed_hosts=("csc.gov.ae",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.PLANNED,
        enabled=False,
        progress_contract=ProgressContract.NONE,
        rate_limit_notes=(
            "Navigation text only; no stable listing, record structure, feed, "
            "deterministic extraction, or assessed request path."
        ),
    ),
    SourceDefinition(
        slug="desc-news",
        display_name="DESC News",
        vendor="Dubai Electronic Security Center (DESC)",
        source_family="Public news metadata",
        content_family=ContentFamily.PUBLIC_OSINT_ADVISORY,
        access_method=AccessMethod.PUBLIC_PUBLICATION,
        allowed_hosts=("www.desc.gov.ae",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=False,
        progress_contract=ProgressContract.WATERMARK,
        source_type="html",
        base_url="https://www.desc.gov.ae/media-hub/news/",
        canonical_publication_hosts=("www.desc.gov.ae",),
        rate_limit_notes=(
            "Fixture-tested metadata collector implemented; automated access remains "
            "disabled pending project-owner approval."
        ),
    ),
    SourceDefinition(
        slug="desc-published-research",
        display_name="DESC Published Research",
        vendor="Dubai Electronic Security Center (DESC)",
        source_family="Published research metadata",
        content_family=ContentFamily.THREAT_RESEARCH,
        access_method=AccessMethod.PUBLIC_PUBLICATION,
        allowed_hosts=("www.desc.gov.ae",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=False,
        progress_contract=ProgressContract.WATERMARK,
        source_type="html",
        base_url=(
            "https://www.desc.gov.ae/research-innovation/published-research/"
        ),
        canonical_publication_hosts=(
            "ieeexplore.ieee.org",
            "www.sciencedirect.com",
            "dl.acm.org",
            "www.researchgate.net",
        ),
        rate_limit_notes=(
            "Fixture-tested metadata collector implemented; external landing links are "
            "metadata identities only and automated access remains disabled."
        ),
    ),
)

_REGISTRY = build_source_registry(_IMPLEMENTED_DEFINITIONS + _DISABLED_DEFINITIONS)
