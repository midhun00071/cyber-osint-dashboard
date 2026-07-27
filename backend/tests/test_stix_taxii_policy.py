from dataclasses import FrozenInstanceError, replace
import inspect
import socket
from types import MappingProxyType

import pytest

from app.ingestion.stix_taxii.import_service import StixBundleImportService
from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    PRODUCTION_STIX_SOURCE_POLICIES,
    SUPPORTED_RELATIONSHIP_TYPES,
    SUPPORTED_STIX_TYPES,
    StixInputTransport,
    StixPolicyError,
    UnknownStixSourceError,
    build_stix_policy_registry,
    get_production_stix_policy,
    validate_stix_source_policy,
)


def policy(**changes):
    value = ApprovedStixSourcePolicy(
        source_slug="synthetic-stix",
        allowed_transport=StixInputTransport.LOCAL_BUNDLE,
        policy_base_url="https://stix.example/objects",
        allowed_tlp_levels=frozenset({"white", "green"}),
    )
    return replace(value, **changes)


def test_policy_is_normalized_immutable_and_has_conservative_limits():
    approved = validate_stix_source_policy(policy())

    assert approved.allowed_stix_types == SUPPORTED_STIX_TYPES
    assert approved.allowed_relationship_types == SUPPORTED_RELATIONSHIP_TYPES
    assert approved.maximum_file_bytes == 2 * 1024 * 1024
    assert approved.maximum_json_depth == 16
    assert approved.maximum_objects == 500
    assert approved.allow_statement_markings is False
    with pytest.raises(FrozenInstanceError):
        approved.source_slug = "changed"  # type: ignore[misc]


def test_policy_registry_is_read_only_and_rejects_duplicates():
    registry = build_stix_policy_registry((policy(),))

    assert isinstance(registry, MappingProxyType)
    with pytest.raises(TypeError):
        registry["other"] = policy()  # type: ignore[index]
    with pytest.raises(StixPolicyError, match="Duplicate STIX source policy"):
        build_stix_policy_registry((policy(), policy()))


def test_production_policy_registry_is_intentionally_empty_and_lookup_is_safe():
    assert dict(PRODUCTION_STIX_SOURCE_POLICIES) == {}

    with pytest.raises(UnknownStixSourceError) as caught:
        get_production_stix_policy("unapproved-source")
    assert "unapproved-source" not in str(caught.value)


@pytest.mark.parametrize(
    "slug",
    ["", "Synthetic-Stix", "synthetic_stix", " synthetic-stix", "a--b"],
)
def test_source_slug_must_be_exactly_canonical(slug):
    with pytest.raises(StixPolicyError):
        validate_stix_source_policy(policy(source_slug=slug))


@pytest.mark.parametrize(
    "transport",
    ["https", "taxii", "remote", "arbitrary_url", "local_file"],
)
def test_only_explicit_offline_transports_are_accepted(transport):
    with pytest.raises(StixPolicyError, match="transport"):
        validate_stix_source_policy(policy(allowed_transport=transport))


def test_taxii_fixture_transport_is_explicitly_supported_offline():
    approved = validate_stix_source_policy(
        policy(allowed_transport=StixInputTransport.TAXII_ENVELOPE_FIXTURE)
    )

    assert approved.allowed_transport is StixInputTransport.TAXII_ENVELOPE_FIXTURE


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("allowed_stix_types", frozenset({"observed-data"})),
        ("allowed_stix_types", frozenset({"x-custom"})),
        ("allowed_relationship_types", frozenset({"downloads"})),
        ("allowed_tlp_levels", frozenset({"clear"})),
    ],
)
def test_semantic_allow_lists_reject_unsupported_values(field, value):
    with pytest.raises(StixPolicyError):
        validate_stix_source_policy(policy(**{field: value}))


@pytest.mark.parametrize(
    "field",
    [
        "maximum_file_bytes",
        "maximum_json_depth",
        "maximum_json_nodes",
        "maximum_json_string_length",
        "maximum_objects",
        "maximum_relationships",
        "maximum_marking_refs",
        "maximum_external_references",
        "maximum_aliases",
    ],
)
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_policy_bounds_are_positive_real_integers(field, value):
    with pytest.raises(StixPolicyError, match="positive integers"):
        validate_stix_source_policy(policy(**{field: value}))


@pytest.mark.parametrize(
    "base_url",
    [
        "http://stix.example/objects",
        "https://user:secret@stix.example/objects",
        "https://stix.example/objects?collection=x",
        "https://stix.example/objects#fragment",
        "https://stix.example/../objects",
        "https://STIX.example/objects",
        "https://stix.example./objects",
        "https://127.0.0.1/objects",
        "https://stix.example:8443/objects",
    ],
)
def test_policy_base_url_rejects_unsafe_identity(base_url):
    with pytest.raises(StixPolicyError, match="base URL"):
        validate_stix_source_policy(policy(policy_base_url=base_url))


def test_object_url_uses_fixed_base_and_percent_encoded_object_identity():
    approved = validate_stix_source_policy(policy())

    stix_id = "indicator--11111111-1111-4111-8111-111111111111"
    assert approved.object_url(stix_id) == (
        f"https://stix.example/objects/{stix_id}"
    )
    with pytest.raises(StixPolicyError):
        approved.object_url("../secret?token=x")


@pytest.mark.parametrize(
    "base_url",
    [
        "https://stix.example/%2e%2e/objects",
        "https://stix.example/%2E%2E/objects",
        "https://stix.example/root%2fobjects",
        "https://stix.example/root%5cobjects",
        "https://stix.example/root%3fsecret",
        "https://stix.example/root//objects",
        "https://stix.example/root/../objects",
        "https://stix.example/root\u0085/objects",
        "https://stix.example/" + "a" * 1700,
    ],
)
def test_policy_path_rejects_encoded_ambiguous_or_oversized_identity(base_url):
    with pytest.raises(StixPolicyError, match="base URL"):
        validate_stix_source_policy(policy(policy_base_url=base_url))


def test_policy_base_default_port_is_canonical_and_nested_paths_are_allowed():
    omitted = validate_stix_source_policy(
        policy(policy_base_url="https://stix.example/taxii2/root-1/collections/c1/objects")
    )
    explicit = validate_stix_source_policy(
        policy(
            policy_base_url=(
                "https://stix.example:443/taxii2/root-1/collections/c1/objects/"
            )
        )
    )

    assert omitted.policy_base_url == explicit.policy_base_url
    assert omitted.policy_base_url == (
        "https://stix.example/taxii2/root-1/collections/c1/objects"
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://xn--a.example/objects",
        "https://xn--.example/objects",
        "https://xn--abc-.example/objects",
        "https://faß.de/objects",
    ],
)
def test_policy_host_rejects_malformed_alabels_and_noncanonical_unicode(base_url):
    with pytest.raises(StixPolicyError, match="base URL"):
        validate_stix_source_policy(policy(policy_base_url=base_url))


def test_canonical_modern_idna_alabel_is_accepted_without_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)

    approved = validate_stix_source_policy(
        policy(policy_base_url="https://xn--fa-hia.de/objects")
    )

    assert approved.policy_base_url == "https://xn--fa-hia.de/objects"
    assert validate_stix_source_policy(policy()).policy_base_url == (
        "https://stix.example/objects"
    )


def test_production_interfaces_have_no_server_collection_or_url_parameter():
    names = set(inspect.signature(StixBundleImportService.import_document).parameters)
    names |= set(inspect.signature(get_production_stix_policy).parameters)

    assert names.isdisjoint({"server", "server_url", "collection", "collection_url", "url"})
