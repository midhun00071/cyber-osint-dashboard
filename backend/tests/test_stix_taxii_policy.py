from dataclasses import FrozenInstanceError, replace
import inspect
import socket
from types import MappingProxyType

import pytest

from app.ingestion.stix_taxii.import_service import StixBundleImportService
from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    ApprovedTaxiiCollectionPolicy,
    PRODUCTION_STIX_SOURCE_POLICIES,
    PRODUCTION_TAXII_COLLECTION_POLICIES,
    SUPPORTED_RELATIONSHIP_TYPES,
    SUPPORTED_STIX_TYPES,
    StixInputTransport,
    StixPolicyError,
    UnknownStixSourceError,
    build_stix_policy_registry,
    build_taxii_policy_registry,
    get_production_stix_policy,
    get_production_taxii_policy,
    validate_stix_source_policy,
    validate_taxii_collection_policy,
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
def test_only_explicit_stix_transports_are_accepted(transport):
    with pytest.raises(StixPolicyError, match="transport"):
        validate_stix_source_policy(policy(allowed_transport=transport))


def test_taxii_fixture_transport_is_explicitly_supported_offline():
    approved = validate_stix_source_policy(
        policy(allowed_transport=StixInputTransport.TAXII_ENVELOPE_FIXTURE)
    )

    assert approved.allowed_transport is StixInputTransport.TAXII_ENVELOPE_FIXTURE


def taxii_policy(**changes):
    stix = policy(allowed_transport=StixInputTransport.TAXII_21_COLLECTION)
    value = ApprovedTaxiiCollectionPolicy(
        stix_policy=stix,
        api_root_url="https://taxii.example/api/root-1",
        collection_id="11111111-1111-4111-8111-111111111111",
    )
    return replace(value, **changes)


def test_taxii_policy_is_frozen_derived_bounded_and_registry_is_immutable():
    approved = validate_taxii_collection_policy(taxii_policy())
    registry = build_taxii_policy_registry((approved,))

    assert approved.objects_endpoint == (
        "https://taxii.example/api/root-1/collections/"
        "11111111-1111-4111-8111-111111111111/objects/"
    )
    assert approved.maximum_response_bytes == 2 * 1024 * 1024
    assert approved.maximum_total_response_bytes == 8 * 1024 * 1024
    assert approved.maximum_pages == 10
    assert approved.maximum_total_objects == 500
    assert approved.maximum_pagination_token_length == 1024
    assert approved.total_collection_deadline_seconds == 60.0
    assert isinstance(registry, MappingProxyType)
    with pytest.raises(FrozenInstanceError):
        approved.collection_id = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        registry["other"] = approved  # type: ignore[index]


def test_production_taxii_registry_is_empty_and_lookup_is_sanitized():
    assert dict(PRODUCTION_TAXII_COLLECTION_POLICIES) == {}
    with pytest.raises(UnknownStixSourceError) as caught:
        get_production_taxii_policy("unapproved-source")
    assert "unapproved-source" not in str(caught.value)


@pytest.mark.parametrize(
    "api_root_url",
    [
        "http://taxii.example/api/root",
        "https://user:secret@taxii.example/api/root",
        "https://127.0.0.1/api/root",
        "https://TAXII.example/api/root",
        "https://taxii.example.:443/api/root",
        "https://taxii.example:8443/api/root",
        "https://taxii.example/api/root?secret=x",
        "https://taxii.example/api/root#fragment",
        "https://taxii.example/api/../root",
        "https://taxii.example/api/%2e%2e/root",
        "https://taxii.example/api//root",
        "https://taxii.example",
        "https://faß.de/api/root",
    ],
)
def test_taxii_api_root_rejects_noncanonical_or_unsafe_values(api_root_url):
    with pytest.raises(StixPolicyError, match="API root"):
        validate_taxii_collection_policy(taxii_policy(api_root_url=api_root_url))


@pytest.mark.parametrize(
    "collection_id",
    [
        "",
        ".",
        "..",
        "/collection",
        "../collection",
        "collection%2fother",
        "a/b",
        "a?b",
        "a#b",
        " a",
        "a ",
        "a\n",
        "é",
    ],
)
def test_taxii_collection_id_rejects_ambiguous_values(collection_id):
    with pytest.raises(StixPolicyError, match="identifier"):
        validate_taxii_collection_policy(taxii_policy(collection_id=collection_id))


def test_taxii_policy_requires_live_transport_and_coherent_limits():
    with pytest.raises(StixPolicyError, match="live transport"):
        validate_taxii_collection_policy(
            taxii_policy(stix_policy=policy())
        )
    with pytest.raises(StixPolicyError, match="exceed"):
        validate_taxii_collection_policy(
            taxii_policy(maximum_total_objects=501)
        )


@pytest.mark.parametrize(
    "field",
    [
        "maximum_response_bytes",
        "maximum_total_response_bytes",
        "maximum_pages",
        "maximum_total_objects",
        "maximum_pagination_token_length",
    ],
)
@pytest.mark.parametrize(
    "value",
    [0, -1, True, 1.5, float("nan"), float("inf"), float("-inf")],
)
def test_taxii_integer_limits_reject_non_positive_or_non_integer_values(
    field,
    value,
):
    with pytest.raises(StixPolicyError, match="positive integers"):
        validate_taxii_collection_policy(taxii_policy(**{field: value}))


@pytest.mark.parametrize(
    "field",
    [
        "connect_timeout_seconds",
        "read_timeout_seconds",
        "write_timeout_seconds",
        "pool_timeout_seconds",
        "total_collection_deadline_seconds",
    ],
)
@pytest.mark.parametrize(
    "value",
    [0, -1, True, float("nan"), float("inf"), float("-inf")],
)
def test_taxii_timeouts_reject_non_positive_boolean_or_non_finite_values(
    field,
    value,
):
    with pytest.raises(StixPolicyError, match="finite and positive"):
        validate_taxii_collection_policy(taxii_policy(**{field: value}))


def test_taxii_policy_rejects_limits_that_exceed_related_stix_boundaries():
    with pytest.raises(StixPolicyError, match="exceed"):
        validate_taxii_collection_policy(
            taxii_policy(
                maximum_response_bytes=101,
                maximum_total_response_bytes=100,
            )
        )

    byte_limited_stix = replace(
        taxii_policy().stix_policy,
        maximum_file_bytes=100,
    )
    with pytest.raises(StixPolicyError, match="exceed"):
        validate_taxii_collection_policy(
            taxii_policy(
                stix_policy=byte_limited_stix,
                maximum_response_bytes=101,
                maximum_total_response_bytes=101,
            )
        )

    object_limited_stix = replace(
        taxii_policy().stix_policy,
        maximum_objects=1,
    )
    with pytest.raises(StixPolicyError, match="exceed"):
        validate_taxii_collection_policy(
            taxii_policy(
                stix_policy=object_limited_stix,
                maximum_total_objects=2,
            )
        )

    string_limited_stix = replace(
        taxii_policy().stix_policy,
        maximum_json_string_length=10,
    )
    with pytest.raises(StixPolicyError, match="exceed"):
        validate_taxii_collection_policy(
            taxii_policy(
                stix_policy=string_limited_stix,
                maximum_pagination_token_length=11,
            )
        )


def test_taxii_pagination_token_limit_may_equal_stix_string_limit():
    stix = replace(
        taxii_policy().stix_policy,
        maximum_json_string_length=1024,
    )

    approved = validate_taxii_collection_policy(
        taxii_policy(
            stix_policy=stix,
            maximum_pagination_token_length=1024,
        )
    )

    assert approved.maximum_pagination_token_length == 1024


def test_production_taxii_entrypoint_has_no_network_target_arguments():
    from app.ingestion.stix_taxii.taxii_client import (
        TaxiiCollectionClient,
        collect_production_taxii_collection,
    )

    names = set(inspect.signature(TaxiiCollectionClient.collect).parameters)
    names |= set(inspect.signature(collect_production_taxii_collection).parameters)
    assert names.isdisjoint(
        {"server", "api_root", "collection", "endpoint", "url", "path", "headers", "cookies"}
    )


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
