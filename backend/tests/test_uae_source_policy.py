from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType

import pytest

from app.ingestion.uae_source_policy import (
    AssessedUrlKind,
    AutomationApprovalState,
    MAX_UAE_URL_CHARS,
    UAE_SOURCE_POLICIES,
    UnknownUaeSourcePolicyError,
    assess_uae_source_url,
    automated_uae_access_is_approved,
    classify_assessed_uae_url,
    get_uae_source_policy,
    list_uae_source_policies,
    url_matches_assessed_uae_boundary,
)


EXPECTED_POLICY_SLUGS = (
    "ae-cert",
    "desc-news",
    "desc-published-research",
    "uae-cyber-security-council",
    "uae-cyber-security-council-nibras",
)


def test_policy_set_and_listing_order_are_exact_and_deterministic() -> None:
    first = list_uae_source_policies()
    second = list_uae_source_policies()

    assert tuple(policy.source_slug for policy in first) == EXPECTED_POLICY_SLUGS
    assert first == second
    assert isinstance(first, tuple)
    assert tuple(UAE_SOURCE_POLICIES) == EXPECTED_POLICY_SLUGS


def test_policy_objects_and_registry_are_immutable() -> None:
    policy = get_uae_source_policy("uae-cyber-security-council")

    assert isinstance(UAE_SOURCE_POLICIES, MappingProxyType)
    with pytest.raises(FrozenInstanceError):
        policy.assessed_host = "changed.example"  # type: ignore[misc]
    with pytest.raises(TypeError):
        policy.assessed_listing_paths[0] = "/changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        UAE_SOURCE_POLICIES["changed"] = policy  # type: ignore[index]


def test_all_automation_decisions_are_separately_pending_and_false() -> None:
    for policy in list_uae_source_policies():
        assert policy.automated_access_approved is False
        assert policy.automation_approval_state is AutomationApprovalState.PENDING
        assert automated_uae_access_is_approved(policy.source_slug) is False


@pytest.mark.parametrize(
    ("source_slug", "url"),
    [
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae/en/stay-alert",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae/en/all-threats",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae/en/all-updates",
        ),
        ("desc-news", "https://www.desc.gov.ae/media-hub/news/"),
        (
            "desc-published-research",
            "https://www.desc.gov.ae/research-innovation/published-research/",
        ),
    ],
)
def test_exact_assessed_listing_urls_are_request_targets_but_not_approved(
    source_slug: str,
    url: str,
) -> None:
    assessment = assess_uae_source_url(source_slug, url)

    assert assessment.matches_assessed_boundary is True
    assert assessment.assessed_url_kind is AssessedUrlKind.LISTING
    assert assessment.assessed_request_target is True
    assert assessment.automated_access_approved is False
    assert url_matches_assessed_uae_boundary(source_slug, url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://csc.gov.ae/en/w/critical-security-update",
        "https://csc.gov.ae/en/w/update-2026",
    ],
)
def test_csc_publication_family_is_metadata_only_not_a_request_target(url: str) -> None:
    assessment = assess_uae_source_url("uae-cyber-security-council", url)

    assert assessment.matches_assessed_boundary is True
    assert assessment.assessed_url_kind is AssessedUrlKind.CANONICAL_METADATA_LINK
    assert assessment.assessed_request_target is False
    assert assessment.automated_access_approved is False


@pytest.mark.parametrize(
    ("source_slug", "url"),
    [
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:443/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:0443/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:444/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:80/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:0/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:65535/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:65536/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:999999/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:not-a-port/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:+443/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae: 443/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:%34%34%33/en/all-updates",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:443/en/w/critical-security-update",
        ),
        (
            "uae-cyber-security-council",
            "https://csc.gov.ae:0443/en/w/update-2026",
        ),
        (
            "desc-news",
            "https://www.desc.gov.ae:443/media-hub/news/",
        ),
        (
            "desc-news",
            "https://www.desc.gov.ae:0443/media-hub/news/",
        ),
        (
            "desc-published-research",
            "https://www.desc.gov.ae:443/research-innovation/published-research/",
        ),
        (
            "ae-cert",
            "https://tdra.gov.ae:443/en/about/tdra-sectors/ae-cert",
        ),
        (
            "uae-cyber-security-council-nibras",
            "https://csc.gov.ae:443/en/nibras",
        ),
    ],
)
def test_explicit_ports_fail_closed_for_every_uae_policy_boundary(
    source_slug: str,
    url: str,
) -> None:
    assert classify_assessed_uae_url(source_slug, url) is None
    assert url_matches_assessed_uae_boundary(source_slug, url) is False

    assessment = assess_uae_source_url(source_slug, url)
    assert assessment.matches_assessed_boundary is False
    assert assessment.assessed_url_kind is None
    assert assessment.assessed_request_target is False
    assert assessment.automated_access_approved is False
    assert assessment.automation_approval_state is AutomationApprovalState.PENDING


@pytest.mark.parametrize(
    ("source_slug", "url"),
    [
        ("desc-news", "https://csc.gov.ae/en/stay-alert"),
        (
            "desc-published-research",
            "https://www.desc.gov.ae/media-hub/news/",
        ),
        (
            "desc-news",
            "https://www.desc.gov.ae/research-innovation/published-research/",
        ),
        (
            "uae-cyber-security-council",
            "https://www.desc.gov.ae/media-hub/news/",
        ),
    ],
)
def test_assessed_url_boundaries_are_source_specific(
    source_slug: str,
    url: str,
) -> None:
    assert url_matches_assessed_uae_boundary(source_slug, url) is False


@pytest.mark.parametrize(
    "url",
    [
        "http://csc.gov.ae/en/stay-alert",
        "ftp://csc.gov.ae/en/stay-alert",
        "https://www.csc.gov.ae/en/stay-alert",
        "https://evil-csc.gov.ae/en/stay-alert",
        "https://csc.gov.ae.evil.example/en/stay-alert",
        "https://192.0.2.10/en/stay-alert",
        "https://user@csc.gov.ae/en/stay-alert",
        "https://user:password@csc.gov.ae/en/stay-alert",
        "https://csc.gov.ae/en/@stay-alert",
        "https://csc.gov.ae:444/en/stay-alert",
        "https://csc.gov.ae:/en/stay-alert",
        "https://csc.gov.ae/en/stay-alert?page=2",
        "https://csc.gov.ae/en/stay-alert?",
        "https://csc.gov.ae/en/stay-alert#section",
        "https://csc.gov.ae/en/stay-alert#",
        "https://csc.gov.ae/en/%73tay-alert",
        "https://csc.gov.ae/en/%2e%2e/documents/report",
        "https://csc.gov.ae/en/../stay-alert",
        "https://csc.gov.ae/en/./stay-alert",
        "https://csc.gov.ae/en//stay-alert",
        "https://csc.gov.ae\\en\\stay-alert",
        "https://csc.gov.ae/en/stay-alert\n",
        "https://csc.gov.ae/en/\ufffdstay-alert",
        "https://csc.gov.ae/en/w/Uppercase-Slug",
        "https://csc.gov.ae/en/w/trailing-",
        "https://csc.gov.ae/en/w/publication/extra",
        "https://csc.gov.ae/documents/report.pdf",
        "https://csc.gov.ae/o/platform",
        "https://csc.gov.ae/c/group",
        "https://csc.gov.ae/combo/resources",
        "https://csc.gov.ae/cdn-cgi/trace",
        "https://csc.gov.ae/media/report.pdf",
        "https://csc.gov.ae/api/updates",
        "https://csc.gov.ae/forms/contact",
        "https://csc.gov.ae/search",
        "https://csc.gov.ae/callback",
        "https://external.example/en/stay-alert",
    ],
)
def test_malformed_confusing_and_unassessed_urls_fail_closed(url: str) -> None:
    assert classify_assessed_uae_url("uae-cyber-security-council", url) is None
    assessment = assess_uae_source_url("uae-cyber-security-council", url)
    assert assessment.matches_assessed_boundary is False
    assert assessment.assessed_url_kind is None
    assert assessment.assessed_request_target is False
    assert assessment.automated_access_approved is False


def test_oversized_url_and_path_identity_fail_closed() -> None:
    oversized_url = "https://csc.gov.ae/en/w/" + (
        "a" * (MAX_UAE_URL_CHARS + 1)
    )
    oversized_segment = "https://csc.gov.ae/en/w/" + ("a" * 161)

    assert url_matches_assessed_uae_boundary(
        "uae-cyber-security-council", oversized_url
    ) is False
    assert url_matches_assessed_uae_boundary(
        "uae-cyber-security-council", oversized_segment
    ) is False


@pytest.mark.parametrize(
    ("source_slug", "url"),
    [
        ("ae-cert", "https://tdra.gov.ae/"),
        ("ae-cert", "https://tdra.gov.ae/en/about/tdra-sectors/ae-cert"),
        ("uae-cyber-security-council-nibras", "https://csc.gov.ae/en/nibras"),
        ("uae-cyber-security-council-nibras", "https://csc.gov.ae/en/stay-alert"),
    ],
)
def test_ae_cert_and_nibras_have_no_assessed_collection_path(
    source_slug: str,
    url: str,
) -> None:
    policy = get_uae_source_policy(source_slug)

    assert policy.assessed_listing_paths == ()
    assert policy.canonical_metadata_path_pattern is None
    assert policy.proposed_minimum_cadence_hours is None
    assert url_matches_assessed_uae_boundary(source_slug, url) is False
    assert automated_uae_access_is_approved(source_slug) is False


@pytest.mark.parametrize(
    "url",
    [
        "https://www.desc.gov.ae/media-hub/news/page/2/",
        "https://www.desc.gov.ae/media-hub/news/article-title/",
        "https://www.desc.gov.ae/research-innovation/published-research/report.pdf",
        "https://www.desc.gov.ae/wp-content/uploads/report.pdf",
        "https://external.example/report",
    ],
)
def test_desc_pagination_articles_pdfs_attachments_and_external_paths_fail_closed(
    url: str,
) -> None:
    assert url_matches_assessed_uae_boundary("desc-news", url) is False
    assert url_matches_assessed_uae_boundary("desc-published-research", url) is False


def test_unknown_policy_lookup_is_sanitized() -> None:
    with pytest.raises(UnknownUaeSourcePolicyError) as exc_info:
        get_uae_source_policy("missing-source")

    assert "missing-source" not in str(exc_info.value)


def test_governance_module_contains_no_network_client_or_transport_import() -> None:
    module_path = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "ingestion"
        / "uae_source_policy.py"
    )
    source = module_path.read_text(encoding="utf-8").casefold()

    for prohibited in (
        "import httpx",
        "from httpx",
        "import socket",
        "from socket",
        "import requests",
        "from requests",
        "urlopen(",
        "client(",
        "getaddrinfo(",
    ):
        assert prohibited not in source
