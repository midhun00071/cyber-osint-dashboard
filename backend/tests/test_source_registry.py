from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from types import MappingProxyType

import pytest

from app.ingestion import source_registry
from app.ingestion.collectors.cisa_kev_client import (
    CISA_KEV_ALLOWED_HOST,
    CISA_KEV_CATALOG_URL,
)
from app.ingestion.collectors.epss_client import FIRST_EPSS_API_URL
from app.ingestion.collectors.nvd_client import NVD_CVE_API_URL
from app.ingestion.collectors.rss_client import CERT_EU_ALLOWED_HOST, CERT_EU_FEED_URL
from app.ingestion.collectors.google_threat_intelligence_rss_client import (
    GOOGLE_THREAT_INTELLIGENCE_ALLOWED_HOST,
    GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
)
from app.ingestion.services.cisa_kev_ingestion_service import CISA_KEV_SOURCE_SLUG
from app.ingestion.services.epss_enrichment_service import EPSS_SOURCE_SLUG
from app.ingestion.services.nvd_ingestion_service import NVD_SOURCE_BASE_URL, NVD_SOURCE_SLUG
from app.ingestion.services.rss_ingestion_service import RSS_SOURCE_SLUG
from app.ingestion.publication_pipeline import publication_item_type_for_content_family
from app.ingestion.source_registry import (
    AccessMethod,
    ContentFamily,
    ImplementationStatus,
    SourceDefinition,
    SourceRegistryError,
    UnknownSourceError,
    build_source_registry,
    get_required_source_base_url,
    get_source_definition,
    list_enabled_implemented_sources,
    list_source_definitions,
    list_source_definitions_by_vendor,
    source_allows_hostname,
    source_allows_publication_hostname,
    validate_source_definition,
)


IMPLEMENTED_SLUGS = {
    "nvd",
    "first-epss",
    "cisa-kev",
    "cert-eu-security-advisories",
    "censys-arc-research",
    "censys-rapid-response-advisories",
    "anomali-cyber-watch",
    "ibm-x-force-public-research",
    "ibm-x-force-public-osint-advisories",
    "google-threat-intelligence-public-research",
    "mandiant-public-threat-research",
}
PLANNED_PUBLIC_SLUGS: set[str] = set()


def valid_definition(slug: str = "example-source") -> SourceDefinition:
    return SourceDefinition(
        slug=slug,
        display_name="Example Source",
        vendor="Example Vendor",
        source_family="Example family",
        content_family=ContentFamily.THREAT_RESEARCH,
        access_method=AccessMethod.MANUAL_CATALOGUE,
        allowed_hosts=("example.com",),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.PLANNED,
        enabled=False,
    )


def definition_with_base_url(
    slug: str,
    *,
    implementation_status: ImplementationStatus,
    enabled: bool,
) -> SourceDefinition:
    return replace(
        valid_definition(slug),
        implementation_status=implementation_status,
        enabled=enabled,
        source_type="api",
        base_url="https://example.com/path",
    )


def test_all_registered_source_slugs_are_unique() -> None:
    slugs = [source.slug for source in list_source_definitions()]

    assert len(slugs) == len(set(slugs))


@pytest.mark.parametrize(
    "slug",
    ["", "NVD", "first_epss", " cisa-kev ", "cert--eu", "-leading", "trailing-"],
)
def test_canonical_slug_validation_rejects_malformed_slugs(slug: str) -> None:
    with pytest.raises(SourceRegistryError):
        validate_source_definition(replace(valid_definition(), slug=slug))


def test_registry_definitions_are_immutable() -> None:
    nvd = get_source_definition("nvd")

    with pytest.raises(FrozenInstanceError):
        nvd.slug = "changed"  # type: ignore[misc]
    assert isinstance(nvd.allowed_hosts, tuple)
    with pytest.raises(TypeError):
        nvd.allowed_hosts[0] = "changed.example"  # type: ignore[index]


def test_registry_construction_returns_read_only_mapping() -> None:
    registry = build_source_registry((valid_definition(),))

    assert isinstance(registry, MappingProxyType)
    with pytest.raises(TypeError):
        registry["another-source"] = valid_definition("another-source")  # type: ignore[index]


def test_unknown_source_lookup_fails_safely() -> None:
    with pytest.raises(UnknownSourceError) as exc_info:
        get_source_definition("missing-source")

    assert "missing-source" not in str(exc_info.value)


def test_exact_source_lookup_returns_expected_definition() -> None:
    nvd = get_source_definition("nvd")

    assert nvd.slug == "nvd"
    assert nvd.display_name == "National Vulnerability Database"
    assert nvd.base_url == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert nvd.base_url == NVD_SOURCE_BASE_URL


def test_enabled_implemented_listing_contains_only_live_sources() -> None:
    enabled = list_enabled_implemented_sources()

    assert {source.slug for source in enabled} == IMPLEMENTED_SLUGS
    assert all(source.enabled for source in enabled)
    assert all(
        source.implementation_status is ImplementationStatus.IMPLEMENTED
        for source in enabled
    )


def test_planned_sources_remain_disabled() -> None:
    sources = {source.slug: source for source in list_source_definitions()}

    assert PLANNED_PUBLIC_SLUGS.issubset(sources)
    for slug in PLANNED_PUBLIC_SLUGS:
        assert sources[slug].implementation_status is ImplementationStatus.PLANNED
        assert sources[slug].enabled is False


@pytest.mark.parametrize(
    "slug",
    ["censys-arc-research", "censys-rapid-response-advisories"],
)
def test_censys_publication_sources_allow_only_exact_canonical_host(slug: str) -> None:
    assert source_allows_hostname(slug, "censys.com") is True
    assert source_allows_hostname(slug, "www.censys.com") is False
    assert source_allows_hostname(slug, "evil-censys.com") is False
    assert source_allows_hostname(slug, "censys.com.evil.example") is False
    assert source_allows_hostname(slug, "docs.censys.com") is False


@pytest.mark.parametrize(
    ("slug", "content_family", "base_url"),
    [
        (
            "censys-arc-research",
            ContentFamily.EXPOSURE_RESEARCH,
            "https://censys.com/blog/",
        ),
        (
            "censys-rapid-response-advisories",
            ContentFamily.PUBLIC_OSINT_ADVISORY,
            "https://censys.com/advisory/",
        ),
    ],
)
def test_censys_sources_support_bounded_live_and_manual_json_imports(
    slug: str,
    content_family: ContentFamily,
    base_url: str,
) -> None:
    source = get_source_definition(slug)

    assert source.content_family is content_family
    assert source.access_method is AccessMethod.MANUAL_CATALOGUE
    assert source.allowed_hosts == ("censys.com",)
    assert source.implementation_status is ImplementationStatus.IMPLEMENTED
    assert source.enabled is True
    assert source.structured is False
    assert source.source_type == "json"
    assert source.base_url == base_url
    assert source.authentication_required is False
    notes = source.rate_limit_notes or ""
    assert "Bounded manual live" in notes
    assert "fixed public discovery location" in notes
    assert "at least ten seconds between request starts" in notes
    assert "local-file JSON import remains supported" in notes


def test_censys_registry_metadata_remains_distinct_and_safe() -> None:
    arc = get_source_definition("censys-arc-research")
    rapid_response = get_source_definition("censys-rapid-response-advisories")

    assert arc != rapid_response
    assert arc.slug != rapid_response.slug
    assert arc.source_family != rapid_response.source_family
    assert arc.content_family is not rapid_response.content_family
    assert arc.base_url != rapid_response.base_url

    serialized = " ".join(
        str(value)
        for source in (arc, rapid_response)
        for value in (
            source.display_name,
            source.vendor,
            source.source_family,
            source.allowed_hosts,
            source.base_url,
            source.rate_limit_notes,
        )
    ).casefold()
    assert "api_key=" not in serialized
    assert "password=" not in serialized
    assert "secret=" not in serialized
    assert "token=" not in serialized
    assert "arbitrary url" not in serialized
    assert "scheduler" not in serialized
    assert "worker" not in serialized
    assert "startup ingestion" not in serialized

    registry_fields = {field.name for field in fields(SourceDefinition)}
    assert registry_fields.isdisjoint(
        {
            "api_key",
            "credential",
            "password",
            "secret",
            "token",
            "url",
            "arbitrary_url",
            "discovery_url",
            "scheduler",
            "worker",
            "startup_ingestion",
        }
    )


def test_anomali_cyber_watch_is_exact_enabled_manual_catalogue_source() -> None:
    source = get_source_definition("anomali-cyber-watch")

    assert source.display_name == "Anomali Cyber Watch"
    assert source.vendor == "Anomali"
    assert source.source_family == "Cyber Watch"
    assert source.content_family is ContentFamily.THREAT_RESEARCH
    assert source.access_method is AccessMethod.MANUAL_CATALOGUE
    assert source.allowed_hosts == ("www.anomali.com",)
    assert source.authentication_required is False
    assert source.structured is False
    assert source.implementation_status is ImplementationStatus.IMPLEMENTED
    assert source.enabled is True
    assert source.source_type == "json"
    assert source.base_url == "https://www.anomali.com/blog/"
    assert "local-file" in (source.rate_limit_notes or "")
    assert "no Anomali network requests" in (source.rate_limit_notes or "")
    assert publication_item_type_for_content_family(source.content_family) == (
        "threat_report"
    )


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("www.anomali.com", True),
        ("anomali.com", False),
        ("blog.anomali.com", False),
        ("www.anomali.com.evil.example", False),
        ("evil-anomali.com", False),
        ("www.anomali.com:443", False),
        ("user@www.anomali.com", False),
    ],
)
def test_anomali_registry_host_enforcement(hostname: str, expected: bool) -> None:
    assert source_allows_hostname("anomali-cyber-watch", hostname) is expected
    assert (
        source_allows_publication_hostname("anomali-cyber-watch", hostname)
        is expected
    )


@pytest.mark.parametrize(
    ("slug", "content_family", "host", "base_url", "item_type"),
    [
        (
            "ibm-x-force-public-research",
            ContentFamily.THREAT_RESEARCH,
            "www.ibm.com",
            "https://www.ibm.com/think/x-force/",
            "threat_report",
        ),
        (
            "ibm-x-force-public-osint-advisories",
            ContentFamily.PUBLIC_OSINT_ADVISORY,
            "exchange.xforce.ibmcloud.com",
            "https://exchange.xforce.ibmcloud.com/osint/",
            "security_advisory",
        ),
    ],
)
def test_ibm_x_force_sources_are_exact_enabled_manual_catalogues(
    slug: str,
    content_family: ContentFamily,
    host: str,
    base_url: str,
    item_type: str,
) -> None:
    source = get_source_definition(slug)

    assert source.vendor == "IBM X-Force"
    assert source.content_family is content_family
    assert source.access_method is AccessMethod.MANUAL_CATALOGUE
    assert source.allowed_hosts == (host,)
    assert source.authentication_required is False
    assert source.structured is False
    assert source.implementation_status is ImplementationStatus.IMPLEMENTED
    assert source.enabled is True
    assert source.source_type == "json"
    assert source.base_url == base_url
    assert "local-file" in (source.rate_limit_notes or "")
    assert publication_item_type_for_content_family(content_family) == item_type


@pytest.mark.parametrize(
    ("slug", "hostname", "expected"),
    [
        ("ibm-x-force-public-research", "www.ibm.com", True),
        ("ibm-x-force-public-research", "ibm.com", False),
        ("ibm-x-force-public-research", "research.ibm.com", False),
        ("ibm-x-force-public-research", "www.ibm.com.evil.example", False),
        (
            "ibm-x-force-public-osint-advisories",
            "exchange.xforce.ibmcloud.com",
            True,
        ),
        ("ibm-x-force-public-osint-advisories", "www.ibm.com", False),
        ("ibm-x-force-public-osint-advisories", "ibmcloud.com", False),
        (
            "ibm-x-force-public-osint-advisories",
            "api.xforce.ibmcloud.com",
            False,
        ),
        (
            "ibm-x-force-public-osint-advisories",
            "exchange.xforce.ibmcloud.com.evil.example",
            False,
        ),
    ],
)
def test_ibm_x_force_registry_uses_exact_hosts(
    slug: str,
    hostname: str,
    expected: bool,
) -> None:
    assert source_allows_hostname(slug, hostname) is expected
    assert source_allows_publication_hostname(slug, hostname) is expected


@pytest.mark.parametrize(
    "slug",
    [
        "google-threat-intelligence-public-research",
        "mandiant-public-threat-research",
    ],
)
def test_google_threat_sources_separate_collection_and_publication_hosts(
    slug: str,
) -> None:
    source = get_source_definition(slug)

    assert source.content_family is ContentFamily.THREAT_RESEARCH
    assert source.access_method is AccessMethod.PUBLIC_FEED
    assert source.source_type == "rss"
    assert source.base_url == GOOGLE_THREAT_INTELLIGENCE_FEED_URL
    assert source.allowed_hosts == ("feeds.feedburner.com",)
    assert source.canonical_publication_hosts == ("cloud.google.com",)
    assert source.implementation_status is ImplementationStatus.IMPLEMENTED
    assert source.enabled is True
    assert source.authentication_required is False
    assert "article bodies are not fetched" in (source.rate_limit_notes or "")
    assert source_allows_hostname(slug, "feeds.feedburner.com") is True
    assert source_allows_hostname(slug, "cloud.google.com") is False
    assert source_allows_publication_hostname(slug, "cloud.google.com") is True
    assert source_allows_publication_hostname(slug, "feeds.feedburner.com") is False
    assert source_allows_publication_hostname(slug, "gtidocs.virustotal.com") is False
    assert source_allows_publication_hostname(slug, "cloud.google.com.evil.example") is False
    assert source_allows_publication_hostname(slug, "evil-cloud.google.com") is False


def test_gti_public_research_collection_host_does_not_allow_publication_host() -> None:
    slug = "google-threat-intelligence-public-research"

    assert source_allows_hostname(slug, "feeds.feedburner.com") is True
    assert source_allows_hostname(slug, "cloud.google.com") is False
    assert source_allows_hostname(slug, "gtidocs.virustotal.com") is False
    assert source_allows_hostname(slug, "google.com") is False
    assert source_allows_hostname(slug, "feeds.feedburner.com.evil.example") is False
    assert source_allows_hostname(slug, "evil-feeds.feedburner.com") is False


def test_implemented_source_definitions_exist_with_existing_slugs() -> None:
    assert get_source_definition("nvd").slug == NVD_SOURCE_SLUG
    assert get_source_definition("first-epss").slug == EPSS_SOURCE_SLUG
    assert get_source_definition("cisa-kev").slug == CISA_KEV_SOURCE_SLUG
    assert get_source_definition("cert-eu-security-advisories").slug == RSS_SOURCE_SLUG


def test_vendor_listing_is_case_insensitive_and_immutable() -> None:
    sources = list_source_definitions_by_vendor("ibm x-force")

    assert {source.slug for source in sources} == {
        "ibm-x-force-public-research",
        "ibm-x-force-public-osint-advisories",
    }
    assert isinstance(sources, tuple)


def test_allowed_hosts_are_normalized_and_exactly_matched() -> None:
    plain = validate_source_definition(
        replace(valid_definition(), allowed_hosts=("example.com",))
    )
    definition = validate_source_definition(
        replace(valid_definition(), allowed_hosts=("EXAMPLE.COM.",))
    )

    assert plain.allowed_hosts == ("example.com",)
    assert definition.allowed_hosts == ("example.com",)
    assert source_allows_hostname("nvd", "SERVICES.NVD.NIST.GOV.") is True
    assert source_allows_hostname("nvd", "services.nvd.nist.gov") is True
    assert source_allows_hostname("nvd", "services.nvd.nist.gov..") is False
    assert source_allows_hostname("nvd", "services.nvd.nist.gov...") is False


@pytest.mark.parametrize(
    "hostname",
    [
        "evil-services.nvd.nist.gov",
        "services.nvd.nist.gov.evil.example",
        "nist.gov",
        "example.com",
    ],
)
def test_suffix_confusion_hosts_are_not_allowed(hostname: str) -> None:
    assert source_allows_hostname("nvd", hostname) is False


@pytest.mark.parametrize(
    "host",
    [
        "https://example.com",
        "example.com/path",
        "user:pass@example.com",
        "example.com:443",
        "example.com?query=1",
        "example.com#fragment",
        "*.example.com",
        ".example.com",
        "example.com..",
        "example.com...",
    ],
)
def test_malformed_host_entries_are_rejected(host: str) -> None:
    with pytest.raises(SourceRegistryError):
        validate_source_definition(replace(valid_definition(), allowed_hosts=(host,)))


def test_duplicate_host_entries_are_rejected_after_normalization() -> None:
    with pytest.raises(SourceRegistryError, match="Duplicate"):
        validate_source_definition(
            replace(valid_definition(), allowed_hosts=("example.com", "EXAMPLE.COM."))
        )


def test_duplicate_registry_entries_are_rejected() -> None:
    with pytest.raises(SourceRegistryError, match="Duplicate"):
        build_source_registry((valid_definition("same"), valid_definition("same")))


def test_enabled_planned_status_combination_is_rejected() -> None:
    with pytest.raises(SourceRegistryError):
        validate_source_definition(
            replace(
                valid_definition(),
                implementation_status=ImplementationStatus.PLANNED,
                enabled=True,
            )
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authentication_required", 1),
        ("authentication_required", "false"),
        ("structured", 0),
        ("structured", "true"),
        ("enabled", 1),
        ("enabled", "false"),
        ("enabled", None),
    ],
)
def test_boolean_fields_require_exact_bool_values(field: str, value: object) -> None:
    definition = replace(valid_definition(), **{field: value})

    with pytest.raises(SourceRegistryError, match=field):
        validate_source_definition(definition)


@pytest.mark.parametrize("field", ["source_type", "base_url", "rate_limit_notes"])
def test_optional_metadata_rejects_non_string_values(field: str) -> None:
    definition = replace(valid_definition(), **{field: 123})

    with pytest.raises(SourceRegistryError, match=field):
        validate_source_definition(definition)


@pytest.mark.parametrize("field", ["source_type", "base_url", "rate_limit_notes"])
def test_optional_metadata_rejects_empty_values(field: str) -> None:
    definition = replace(valid_definition(), **{field: "   "})

    with pytest.raises(SourceRegistryError, match=field):
        validate_source_definition(definition)


def test_unsupported_enum_values_are_rejected() -> None:
    with pytest.raises(SourceRegistryError):
        validate_source_definition(
            replace(valid_definition(), access_method="unsupported")  # type: ignore[arg-type]
        )


def test_implemented_sources_require_safe_source_identity() -> None:
    with pytest.raises(SourceRegistryError):
        validate_source_definition(
            replace(
                valid_definition(),
                implementation_status=ImplementationStatus.IMPLEMENTED,
                source_type=None,
                base_url=None,
            )
        )


def test_base_url_must_use_allowed_exact_host() -> None:
    with pytest.raises(SourceRegistryError):
        validate_source_definition(
            replace(
                valid_definition(),
                base_url="https://evil-example.com/feed.json",
            )
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://example.com/api?api_key=value",
        "https://example.com/api?token=value",
    ],
)
def test_base_url_rejects_query_strings(base_url: str) -> None:
    with pytest.raises(SourceRegistryError, match="query"):
        validate_source_definition(replace(valid_definition(), base_url=base_url))


@pytest.mark.parametrize("base_url", [123, "   "])
def test_base_url_rejects_non_string_or_empty_values(base_url: object) -> None:
    with pytest.raises(SourceRegistryError):
        validate_source_definition(replace(valid_definition(), base_url=base_url))


@pytest.mark.parametrize(
    "base_url",
    [
        "https://example.com../path",
        "https://example.com.../path",
    ],
)
def test_base_url_rejects_multiple_trailing_host_dots(base_url: str) -> None:
    with pytest.raises(SourceRegistryError):
        validate_source_definition(replace(valid_definition(), base_url=base_url))


def test_required_base_url_lookup_returns_safe_string() -> None:
    assert (
        get_required_source_base_url("nvd")
        == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )


def test_required_base_url_lookup_requires_enabled_implemented_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = build_source_registry(
        (
            definition_with_base_url(
                "enabled-implemented-source",
                implementation_status=ImplementationStatus.IMPLEMENTED,
                enabled=True,
            ),
            definition_with_base_url(
                "planned-disabled-source",
                implementation_status=ImplementationStatus.PLANNED,
                enabled=False,
            ),
            definition_with_base_url(
                "implemented-disabled-source",
                implementation_status=ImplementationStatus.IMPLEMENTED,
                enabled=False,
            ),
        )
    )
    monkeypatch.setattr(source_registry, "_REGISTRY", registry)

    assert (
        get_required_source_base_url("enabled-implemented-source")
        == "https://example.com/path"
    )
    for slug in ("planned-disabled-source", "implemented-disabled-source"):
        with pytest.raises(SourceRegistryError) as exc_info:
            get_required_source_base_url(slug)
        assert slug not in str(exc_info.value)
        assert "https://example.com/path" not in str(exc_info.value)


def test_configured_url_alone_does_not_activate_planned_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = build_source_registry(
        (
            definition_with_base_url(
                "configured-planned-source",
                implementation_status=ImplementationStatus.PLANNED,
                enabled=False,
            ),
        )
    )
    monkeypatch.setattr(source_registry, "_REGISTRY", registry)

    with pytest.raises(SourceRegistryError) as exc_info:
        get_required_source_base_url("configured-planned-source")
    assert "configured-planned-source" not in str(exc_info.value)
    assert "https://example.com/path" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("slug", "base_url"),
    [
        ("censys-arc-research", "https://censys.com/blog/"),
        (
            "censys-rapid-response-advisories",
            "https://censys.com/advisory/",
        ),
    ],
)
def test_required_base_url_lookup_supports_censys_manual_sources(
    slug: str,
    base_url: str,
) -> None:
    assert get_required_source_base_url(slug) == base_url


def test_collector_url_constants_match_registry_base_urls() -> None:
    assert NVD_CVE_API_URL == get_required_source_base_url("nvd")
    assert FIRST_EPSS_API_URL == get_required_source_base_url("first-epss")
    assert CISA_KEV_CATALOG_URL == get_required_source_base_url("cisa-kev")
    assert CERT_EU_FEED_URL == get_required_source_base_url(
        "cert-eu-security-advisories"
    )
    assert GOOGLE_THREAT_INTELLIGENCE_FEED_URL == get_required_source_base_url(
        "google-threat-intelligence-public-research"
    )
    assert GOOGLE_THREAT_INTELLIGENCE_FEED_URL == get_required_source_base_url(
        "mandiant-public-threat-research"
    )
    assert NVD_CVE_API_URL == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert FIRST_EPSS_API_URL == "https://api.first.org/data/v1/epss"
    assert CISA_KEV_CATALOG_URL == (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    assert CERT_EU_FEED_URL == (
        "https://cert.europa.eu/publications/security-advisories-rss"
    )
    assert GOOGLE_THREAT_INTELLIGENCE_FEED_URL == (
        "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v"
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://user@example.com/path",
        "https://user:password@example.com/path",
        "https://@example.com/path",
        "https://:password@example.com/path",
    ],
)
def test_base_url_rejects_all_userinfo(base_url: str) -> None:
    with pytest.raises(SourceRegistryError, match="credentials"):
        validate_source_definition(replace(valid_definition(), base_url=base_url))


def test_base_url_accepts_normal_safe_url() -> None:
    definition = validate_source_definition(
        replace(valid_definition(), base_url="https://example.com/path")
    )

    assert definition.base_url == "https://example.com/path"


def test_existing_collector_host_constants_come_from_registry() -> None:
    assert CISA_KEV_ALLOWED_HOST == get_source_definition("cisa-kev").allowed_hosts[0]
    assert CERT_EU_ALLOWED_HOST == get_source_definition(
        "cert-eu-security-advisories"
    ).allowed_hosts[0]
    assert GOOGLE_THREAT_INTELLIGENCE_ALLOWED_HOST == get_source_definition(
        "google-threat-intelligence-public-research"
    ).allowed_hosts[0]


def test_publication_host_falls_back_to_allowed_hosts_for_existing_sources() -> None:
    assert source_allows_publication_hostname("nvd", "services.nvd.nist.gov") is True
    assert source_allows_publication_hostname("censys-arc-research", "censys.com") is True
    assert source_allows_publication_hostname("censys-arc-research", "docs.censys.com") is False


def test_canonical_publication_hosts_are_immutable_and_normalized() -> None:
    definition = validate_source_definition(
        replace(
            valid_definition(),
            allowed_hosts=("feeds.example.com",),
            canonical_publication_hosts=("PUBLIC.EXAMPLE.COM.",),
        )
    )

    assert definition.canonical_publication_hosts == ("public.example.com",)
    with pytest.raises(FrozenInstanceError):
        definition.canonical_publication_hosts = ("changed.example",)  # type: ignore[misc]


def test_invalid_canonical_publication_hosts_are_rejected() -> None:
    with pytest.raises(SourceRegistryError):
        validate_source_definition(
            replace(
                valid_definition(),
                canonical_publication_hosts=("192.0.2.10",),
            )
        )
