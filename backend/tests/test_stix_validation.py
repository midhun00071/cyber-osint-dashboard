from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
import json
from types import MappingProxyType
from copy import deepcopy

import pytest

from app.indicators.value_normalization import normalize_observable
from app.ingestion.stix_taxii.bounded_json import (
    StixDocumentFormat,
    parse_stix_json_bytes,
    thaw_json,
)
from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
    StixInputTransport,
    validate_stix_source_policy,
)
from app.ingestion.stix_taxii.stix_validation import (
    ExistingStixReferenceUse,
    StixValidationError,
    validate_canonical_safe_payload,
    validate_existing_safe_payload,
    validate_stix_document,
)


CREATED = "2026-07-01T10:00:00Z"
MODIFIED = "2026-07-01T11:00:00Z"
TLP_WHITE_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
STANDARD_TLP_IDS = {
    "white": TLP_WHITE_ID,
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
INCORRECT_RED_ID = "marking-definition--5e57c739-391a-4eb3-b6f1-b6c5e125f2f8"
OTHER_IDENTITY_ID = "identity--12121212-1212-4121-8121-121212121212"
IDS = {
    "identity": "identity--11111111-1111-4111-8111-111111111111",
    "indicator": "indicator--22222222-2222-4222-8222-222222222222",
    "relationship": "relationship--33333333-3333-4333-8333-333333333333",
    "attack-pattern": "attack-pattern--44444444-4444-4444-8444-444444444444",
    "campaign": "campaign--55555555-5555-4555-8555-555555555555",
    "malware": "malware--66666666-6666-4666-8666-666666666666",
    "threat-actor": "threat-actor--77777777-7777-4777-8777-777777777777",
    "ipv4-addr": "ipv4-addr--88888888-8888-4888-8888-888888888888",
    "ipv6-addr": "ipv6-addr--99999999-9999-4999-8999-999999999999",
    "domain-name": "domain-name--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "url": "url--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "file": "file--cccccccc-cccc-4ccc-8ccc-cccccccccccc",
}


def policy(**changes):
    base = ApprovedStixSourcePolicy(
        source_slug="synthetic-stix",
        allowed_transport=StixInputTransport.LOCAL_BUNDLE,
        policy_base_url="https://stix.example/objects",
        allowed_tlp_levels=frozenset({"white"}),
    )
    return validate_stix_source_policy(replace(base, **changes))


def versioned(stix_type, **changes):
    value = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": IDS[stix_type],
        "created": CREATED,
        "modified": MODIFIED,
        "name": f"Synthetic {stix_type}",
    }
    value.update(changes)
    return value


def observable(stix_type, value, **changes):
    item = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": IDS[stix_type],
        "value": value,
    }
    item.update(changes)
    return item


def validate(objects, *, approved=None, existing=None):
    raw = json.dumps({"type": "bundle", "objects": objects}).encode()
    selected = approved or policy()
    bounded = parse_stix_json_bytes(raw, selected, StixDocumentFormat.STIX_BUNDLE)
    return validate_stix_document(bounded, selected, existing_objects=existing)


def existing_payload(stix_id, stix_type, **changes):
    value = {"type": stix_type, "id": stix_id, "spec_version": "2.1"}
    if stix_type == "marking-definition":
        value.update(
            created=(
                "2017-01-20T00:00:00.000000Z"
                if stix_id == TLP_WHITE_ID
                else "2026-07-01T10:00:00.000000Z"
            ),
            marking_type="statement",
            statement="Approved handling",
        )
    elif stix_type in {
        "identity",
        "indicator",
        "relationship",
        "attack-pattern",
        "campaign",
        "malware",
        "threat-actor",
    }:
        value.update(
            created="2026-07-01T10:00:00.000000Z",
            modified="2026-07-01T11:00:00.000000Z",
        )
        if stix_type == "identity":
            value.update(name="Existing identity", identity_class="organization")
        elif stix_type == "indicator":
            normalized = normalize_observable("ipv4", "8.8.8.8")
            value.update(
                pattern="[ipv4-addr:value = '8.8.8.8']",
                pattern_type="stix",
                pattern_version="2.1",
                valid_from="2026-07-01T10:00:00.000000Z",
                mapped_observables=[
                    {
                        "observable_type": "ipv4",
                        "hash_algorithm": None,
                        "identity_sha256": normalized.identity_sha256,
                    }
                ],
            )
        elif stix_type == "relationship":
            value.update(
                relationship_type="related-to",
                source_ref=IDS["identity"],
                target_ref=IDS["malware"],
            )
        else:
            value["name"] = f"Existing {stix_type}"
    elif stix_type in {"ipv4-addr", "ipv6-addr", "domain-name", "url"}:
        observable_type, raw_value = {
            "ipv4-addr": ("ipv4", "8.8.8.8"),
            "ipv6-addr": ("ipv6", "2606:4700:4700::1111"),
            "domain-name": ("domain", "example.test"),
            "url": ("url", "https://example.test/path"),
        }[stix_type]
        normalized = normalize_observable(observable_type, raw_value)
        value.update(
            observable={
                "observable_type": observable_type,
                "normalized_value": normalized.normalized_value,
                "hash_algorithm": None,
            },
            mapped_observables=[
                {
                    "observable_type": observable_type,
                    "hash_algorithm": None,
                    "identity_sha256": normalized.identity_sha256,
                }
            ],
        )
    elif stix_type == "file":
        normalized = normalize_observable(
            "file_hash",
            "a" * 64,
            hash_algorithm="sha256",
        )
        value.update(
            hashes={"sha256": normalized.normalized_value},
            mapped_observables=[
                {
                    "observable_type": "file_hash",
                    "hash_algorithm": "sha256",
                    "identity_sha256": normalized.identity_sha256,
                }
            ],
        )
    value.update(changes)
    if stix_type == "marking-definition":
        if value.get("marking_type") == "tlp":
            value.pop("statement", None)
        elif value.get("marking_type") == "statement":
            value.pop("marking_level", None)
    return value


def test_standard_tlp_identity_external_id_and_marking_reference_are_staged_safely():
    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": TLP_WHITE_ID,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "white"},
    }
    identity = versioned(
        "identity",
        identity_class="organization",
        sectors=["technology"],
        description="  Safe   synthetic description  ",
        object_marking_refs=[TLP_WHITE_ID],
        external_references=[{"source_name": "mitre-attack", "external_id": "G0001"}],
    )

    result = validate([marking, identity])

    assert result.markings_validated == 1
    staged = result.objects[1]
    assert staged.created == datetime(2026, 7, 1, 10, tzinfo=UTC)
    assert staged.modified == datetime(2026, 7, 1, 11, tzinfo=UTC)
    assert "description_summary" not in staged.safe_payload
    assert staged.safe_payload["object_marking_refs"] == (TLP_WHITE_ID,)
    assert staged.safe_payload["external_references"] == (
        MappingProxyType({"source_name": "mitre-attack", "external_id": "G0001"}),
    )
    assert len(staged.content_hash) == 64
    assert "definition" not in result.objects[0].safe_payload


@pytest.mark.parametrize(
    ("stix_type", "value", "expected_type", "expected_value"),
    [
        ("ipv4-addr", "8.8.8.8", "ipv4", "8.8.8.8"),
        ("ipv6-addr", "2606:4700:4700::1111", "ipv6", "2606:4700:4700::1111"),
        ("domain-name", "BÜCHER.example", "domain", "xn--bcher-kva.example"),
        ("url", "HTTPS://Example.COM/a%2fb?q=%00", "url", "https://example.com/a%2Fb?q=%00"),
    ],
)
def test_direct_observable_mapping_uses_p9_08_normalization(
    stix_type, value, expected_type, expected_value
):
    result = validate([observable(stix_type, value)])

    mapped = result.objects[0].observables[0].normalized
    assert (mapped.observable_type, mapped.normalized_value) == (
        expected_type,
        expected_value,
    )
    assert result.objects[0].safe_payload["observable"]["normalized_value"] == expected_value


def test_file_hashes_map_only_supported_algorithms_without_raw_file_metadata():
    hashes = {
        "MD5": "a" * 32,
        "SHA-1": "b" * 40,
        "SHA-256": "c" * 64,
        "SHA-512": "d" * 128,
    }
    item = {
        "type": "file",
        "spec_version": "2.1",
        "id": IDS["file"],
        "hashes": hashes,
    }

    result = validate([item])

    assert {entry.normalized.hash_algorithm for entry in result.objects[0].observables} == {
        "md5",
        "sha1",
        "sha256",
        "sha512",
    }
    assert set(result.objects[0].safe_payload) == {
        "type",
        "id",
        "spec_version",
        "hashes",
        "mapped_observables",
    }


def test_mapped_observable_identities_are_immutable_deterministic_and_hashed():
    item = {
        "type": "file",
        "spec_version": "2.1",
        "id": IDS["file"],
        "hashes": {"SHA-256": "c" * 64, "MD5": "a" * 32},
    }

    staged = validate([item]).objects[0]
    identities = staged.safe_payload["mapped_observables"]

    assert [entry["hash_algorithm"] for entry in identities] == ["md5", "sha256"]
    assert all(set(entry) == {"observable_type", "hash_algorithm", "identity_sha256"} for entry in identities)
    with pytest.raises(TypeError):
        identities[0]["identity_sha256"] = "0" * 64  # type: ignore[index]
    changed = validate([{**item, "hashes": {"SHA-256": "d" * 64, "MD5": "a" * 32}}]).objects[0]
    assert staged.content_hash != changed.content_hash


@pytest.mark.parametrize(
    ("path", "value", "expected_type"),
    [
        ("ipv4-addr:value", "1.1.1.1", "ipv4"),
        ("ipv6-addr:value", "2001:4860:4860::8888", "ipv6"),
        ("domain-name:value", "example.co", "domain"),
        ("url:value", "https://example.co/path", "url"),
        ("file:hashes.'MD5'", "a" * 32, "file_hash"),
        ("file:hashes.'SHA-1'", "b" * 40, "file_hash"),
        ("file:hashes.'SHA-256'", "c" * 64, "file_hash"),
        ("file:hashes.'SHA-512'", "d" * 128, "file_hash"),
    ],
)
def test_simple_indicator_patterns_are_officially_validated_and_mapped(
    path, value, expected_type
):
    item = versioned(
        "indicator",
        pattern=f"[{path} = '{value}']",
        pattern_type="stix",
        pattern_version="2.1",
        valid_from=CREATED,
        confidence=80,
        indicator_types=["malicious-activity"],
    )

    result = validate([item])

    mapped = result.objects[0].observables[0]
    assert mapped.normalized.observable_type == expected_type
    assert mapped.confidence == Decimal("0.800")


@pytest.mark.parametrize("stix_type", ["attack-pattern", "campaign", "threat-actor"])
def test_planned_p9_11_objects_stage_only_common_safe_fields(stix_type):
    item = versioned(stix_type, aliases=["Synthetic alias"], description="Safe summary")

    result = validate([item])

    assert result.objects[0].safe_payload["name"] == f"Synthetic {stix_type}"
    assert "description" not in result.objects[0].safe_payload


def test_malware_requires_standard_field_but_does_not_stage_it():
    item = versioned("malware", is_family=False, malware_types=["unknown"])

    staged = validate([item]).objects[0]

    assert staged.stix_type == "malware"
    assert "is_family" not in staged.safe_payload
    assert "malware_types" not in staged.safe_payload


def test_relationship_resolves_same_document_and_is_ordered_after_targets():
    source = versioned("identity", identity_class="organization")
    target = versioned("malware", is_family=False)
    relationship = versioned(
        "relationship",
        name=None,
        relationship_type="uses",
        source_ref=source["id"],
        target_ref=target["id"],
        start_time=CREATED,
        stop_time=MODIFIED,
    )
    relationship.pop("name")

    result = validate([relationship, target, source])

    assert result.relationships_validated == 1
    assert result.objects[-1].stix_type == "relationship"


def test_relationship_and_marking_may_resolve_only_explicit_same_source_existing_data():
    item = versioned(
        "relationship",
        name=None,
        relationship_type="related-to",
        source_ref=IDS["identity"],
        target_ref=IDS["malware"],
        object_marking_refs=[TLP_WHITE_ID],
    )
    item.pop("name")
    existing = {
        IDS["identity"]: existing_payload(IDS["identity"], "identity"),
        IDS["malware"]: existing_payload(IDS["malware"], "malware"),
        TLP_WHITE_ID: existing_payload(
            TLP_WHITE_ID,
            "marking-definition",
            marking_type="tlp",
            marking_level="white",
        ),
    }

    assert validate([item], existing=existing).relationships_validated == 1


@pytest.mark.parametrize(
    "stix_type",
    [
        "extension-definition",
        "observed-data",
        "sighting",
        "report",
        "note",
        "opinion",
        "grouping",
        "infrastructure",
        "location",
        "vulnerability",
        "course-of-action",
        "intrusion-set",
        "malware-analysis",
        "process",
        "network-traffic",
        "artifact",
        "email-message",
        "user-account",
        "windows-registry-key",
        "autonomous-system",
        "x509-certificate",
        "x-custom",
    ],
)
def test_unsupported_object_types_reject_the_whole_document(stix_type):
    item = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": f"{stix_type}--dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    }
    with pytest.raises(StixValidationError, match="type is not approved"):
        validate([observable("ipv4-addr", "8.8.8.8"), item])


@pytest.mark.parametrize(
    "mutation",
    [
        lambda item: item.update(spec_version="2.0"),
        lambda item: item.pop("id"),
        lambda item: item.update(id=IDS["campaign"]),
        lambda item: item.update(id="identity--not-a-uuid"),
        lambda item: item.update(created="2026-07-01T10:00:00"),
        lambda item: item.update(modified="2026-06-01T10:00:00Z"),
        lambda item: item.update(confidence=True),
        lambda item: item.update(confidence=101),
        lambda item: item.update(revoked="false"),
        lambda item: item.update(extensions={"x-test": {}}),
        lambda item: item.update(granular_markings=[]),
        lambda item: item.update(x_custom="unsafe"),
        lambda item: item.update(description="safe\u0085unsafe"),
    ],
)
def test_invalid_common_stix_fields_are_sanitized(mutation):
    item = versioned("identity", identity_class="organization")
    mutation(item)

    with pytest.raises(StixValidationError) as caught:
        validate([item])
    assert "Synthetic identity" not in str(caught.value)


@pytest.mark.parametrize(
    "pattern",
    [
        "[ipv4-addr:value = '1.1.1.1' AND domain-name:value = 'evil.co']",
        "[ipv4-addr:value = '1.1.1.1'] OR [ipv4-addr:value = '8.8.8.8']",
        "[domain-name:value MATCHES 'evil.*']",
        "[domain-name:value IN ('evil.co', 'bad.co')]",
        "[network-traffic:dst_port = 443]",
        "[file:name = 'sample.exe']",
    ],
)
def test_complex_or_unsupported_indicator_patterns_are_rejected(pattern):
    item = versioned(
        "indicator",
        pattern=pattern,
        pattern_type="stix",
        pattern_version="2.1",
        valid_from=CREATED,
    )
    with pytest.raises(StixValidationError):
        validate([item])


def test_excessive_safe_arrays_and_description_are_rejected():
    approved = policy(maximum_aliases=1)
    identity = versioned(
        "identity",
        identity_class="organization",
        aliases=["one", "two"],
    )
    with pytest.raises(StixValidationError):
        validate([identity], approved=approved)

    indicator = versioned(
        "indicator",
        pattern="[ipv4-addr:value = '1.1.1.1']",
        pattern_type="stix",
        pattern_version="2.1",
        valid_from=CREATED,
        kill_chain_phases=[
            {"kill_chain_name": "test", "phase_name": "one"},
            {"kill_chain_name": "test", "phase_name": "two"},
        ],
    )
    with pytest.raises(StixValidationError):
        validate([indicator], approved=approved)

    too_long = versioned(
        "identity",
        identity_class="organization",
        description="x" * 10_001,
    )
    staged = validate(
        [too_long],
        approved=policy(maximum_json_string_length=20_000),
    ).objects[0]
    assert "description_summary" not in staged.safe_payload


@pytest.mark.parametrize(
    "item",
    [
        {"type": "file", "spec_version": "2.1", "id": IDS["file"]},
        {
            "type": "file",
            "spec_version": "2.1",
            "id": IDS["file"],
            "hashes": {"SHA-224": "a" * 56},
        },
    ],
)
def test_file_without_approved_hash_is_rejected(item):
    with pytest.raises(StixValidationError):
        validate([item])


@pytest.mark.parametrize(
    "external_reference",
    [
        {"source_name": "vendor", "url": "https://evil.example/?token=secret"},
        {"source_name": "vendor", "description": "raw payload"},
        {"source_name": "vendor", "hashes": {"SHA-256": "a" * 64}},
    ],
)
def test_unsafe_external_reference_fields_are_rejected(external_reference):
    item = versioned(
        "identity",
        identity_class="organization",
        external_references=[external_reference],
    )
    with pytest.raises(StixValidationError):
        validate([item])


@pytest.mark.parametrize(
    "external_id",
    ["G0001", "T1059.001", "CAPEC-100", "CVE-2026-12345"],
)
def test_external_reference_plain_identifier_tokens_are_retained(external_id):
    item = versioned(
        "identity",
        identity_class="organization",
        external_references=[
            {"source_name": "defensive.vendor_feed", "external_id": external_id}
        ],
    )

    staged = validate([item]).objects[0]

    assert staged.safe_payload["external_references"][0]["external_id"] == external_id


@pytest.mark.parametrize(
    "source_name",
    [
        "Vendor",
        ".vendor",
        "vendor-",
        " vendor",
        "vendor ",
        "https://vendor.example",
        "user@vendor",
        "vendor/path",
        "vendor\\path",
        "vendor?key=value",
        "vendor#fragment",
        "vendor%20feed",
        "a" * 201,
    ],
)
def test_external_reference_source_name_requires_canonical_ascii_token(source_name):
    item = versioned(
        "identity",
        identity_class="organization",
        external_references=[{"source_name": source_name, "external_id": "G0001"}],
    )

    with pytest.raises(StixValidationError):
        validate([item])


@pytest.mark.parametrize(
    "external_id",
    [
        "https://user:secret@vendor.example/object?utm_source=x#fragment",
        "user@vendor.example",
        "T1059.001?token=secret",
        "T1059.001#fragment",
        "T1059.001%2Fchild",
        "path/to/object",
        "path\\to\\object",
        "../G0001",
        "token=secret",
        " G0001",
        "G0001 ",
        "unsafe\u0085token",
        "a" * 201,
    ],
)
def test_external_reference_external_id_rejects_urls_credentials_and_paths(
    external_id,
):
    item = versioned(
        "identity",
        identity_class="organization",
        external_references=[{"source_name": "vendor", "external_id": external_id}],
    )

    with pytest.raises(StixValidationError):
        validate([item])


@pytest.mark.parametrize(
    "description",
    [
        "Retrieve http://payload.example/sample.exe",
        "Retrieve https://payload.example/sample.exe",
        "Use https://user:password@payload.example/archive",
        "Run sh -c 'download payload.bin'",
        "Run PowerShell -EncodedCommand AAAA",
        "Invoke tool.exe --download --execute",
        "Exploit the service and execute the staged command",
        "Payload name: synthetic-payload.exe",
    ],
)
def test_external_descriptions_are_omitted_from_all_staged_content(description):
    item = versioned(
        "threat-actor",
        description=description,
    )

    staged = validate([item]).objects[0]
    serialized = json.dumps(thaw_json(staged.safe_payload), sort_keys=True)

    assert "description" not in staged.safe_payload
    assert "description_summary" not in staged.safe_payload
    assert description not in serialized


def test_marking_rejections_cover_missing_unapproved_custom_and_statement():
    marked = versioned(
        "identity",
        identity_class="organization",
        object_marking_refs=[TLP_WHITE_ID],
    )
    with pytest.raises(StixValidationError, match="unresolved"):
        validate([marked])

    tlp = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": TLP_WHITE_ID,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "white"},
    }
    with pytest.raises(StixValidationError):
        validate([tlp], approved=policy(allowed_tlp_levels=frozenset()))

    custom = {**tlp, "id": "marking-definition--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}
    with pytest.raises(StixValidationError):
        validate([custom])

    statement = {
        **tlp,
        "id": "marking-definition--ffffffff-ffff-4fff-8fff-ffffffffffff",
        "definition_type": "statement",
        "definition": {"statement": "Synthetic handling statement"},
    }
    with pytest.raises(StixValidationError, match="disabled"):
        validate([statement])


def test_statement_marking_can_be_explicitly_enabled_and_remains_bounded():
    statement_id = "marking-definition--ffffffff-ffff-4fff-8fff-ffffffffffff"
    statement = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": statement_id,
        "created": CREATED,
        "definition_type": "statement",
        "definition": {"statement": "  Approved   handling  "},
    }
    marked = versioned(
        "identity",
        identity_class="organization",
        object_marking_refs=[statement_id],
    )
    approved = policy(allow_statement_markings=True)

    result = validate([statement, marked], approved=approved)

    assert result.objects[0].safe_payload["statement"] == "Approved handling"


@pytest.mark.parametrize(("level", "marking_id"), STANDARD_TLP_IDS.items())
def test_all_official_tlp_identifiers_require_exact_policy_approval(level, marking_id):
    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": level},
    }
    approved = policy(allowed_tlp_levels=frozenset({level}))
    assert validate([marking], approved=approved).objects[0].safe_payload[
        "marking_level"
    ] == level
    with pytest.raises(StixValidationError, match="not approved"):
        validate([marking], approved=policy(allowed_tlp_levels=frozenset()))


@pytest.mark.parametrize(
    "marking",
    [
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": INCORRECT_RED_ID,
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "definition": {"tlp": "red"},
        },
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": TLP_WHITE_ID,
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "definition": {"tlp": "green"},
        },
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "definition": {"tlp": "red"},
        },
    ],
)
def test_incorrect_mismatched_and_custom_tlp_identifiers_are_rejected(marking):
    with pytest.raises(StixValidationError):
        validate(
            [marking],
            approved=policy(allowed_tlp_levels=frozenset({"white", "green", "red"})),
        )


@pytest.mark.parametrize("relationship_type", ["downloads", "compromises"])
def test_unknown_relationship_types_are_rejected(relationship_type):
    item = versioned(
        "relationship",
        name=None,
        relationship_type=relationship_type,
        source_ref=IDS["identity"],
        target_ref=IDS["malware"],
    )
    item.pop("name")
    with pytest.raises(StixValidationError):
        validate(
            [item],
            existing={
                IDS["identity"]: existing_payload(IDS["identity"], "identity"),
                IDS["malware"]: existing_payload(IDS["malware"], "malware"),
            },
        )


def test_relationship_rejects_unresolved_unsupported_self_and_bad_time_order():
    base = versioned(
        "relationship",
        name=None,
        relationship_type="uses",
        source_ref=IDS["identity"],
        target_ref=IDS["malware"],
    )
    base.pop("name")
    with pytest.raises(StixValidationError, match="unresolved"):
        validate([base])
    with pytest.raises(StixValidationError):
        validate(
            [base],
            existing={
                IDS["identity"]: {"type": "identity"},
                IDS["malware"]: {"type": "report"},
            },
        )
    self_ref = {**base, "target_ref": IDS["identity"]}
    with pytest.raises(StixValidationError, match="self-reference"):
        validate(
            [self_ref],
            existing={
                IDS["identity"]: existing_payload(IDS["identity"], "identity")
            },
        )
    bad_time = {**base, "start_time": MODIFIED, "stop_time": CREATED}
    with pytest.raises(StixValidationError):
        validate(
            [bad_time],
            existing={
                IDS["identity"]: existing_payload(IDS["identity"], "identity"),
                IDS["malware"]: existing_payload(IDS["malware"], "malware"),
            },
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "marking-definition"},
        {"type": "marking-definition", "spec_version": "2.1"},
        {
            "type": "marking-definition",
            "id": "marking-definition--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "spec_version": "2.1",
            "marking_type": "tlp",
            "marking_level": "white",
        },
        {
            "type": "marking-definition",
            "id": TLP_WHITE_ID,
            "spec_version": "2.0",
            "marking_type": "tlp",
            "marking_level": "white",
        },
        existing_payload(TLP_WHITE_ID, "marking-definition"),
        existing_payload(TLP_WHITE_ID, "marking-definition", marking_type="tlp"),
        existing_payload(
            TLP_WHITE_ID,
            "marking-definition",
            marking_type="tlp",
            marking_level="green",
        ),
    ],
)
def test_existing_tlp_marking_payload_requires_complete_exact_safe_identity(payload):
    with pytest.raises(StixValidationError):
        validate_existing_safe_payload(
            TLP_WHITE_ID,
            payload,
            policy(),
            ExistingStixReferenceUse.OBJECT_MARKING,
        )


@pytest.mark.parametrize(
    ("marking_id", "level"),
    [
        (INCORRECT_RED_ID, "red"),
        ("marking-definition--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "red"),
    ],
)
def test_existing_tlp_rejects_incorrect_red_and_custom_ids(marking_id, level):
    payload = existing_payload(
        marking_id,
        "marking-definition",
        marking_type="tlp",
        marking_level=level,
    )
    with pytest.raises(StixValidationError):
        validate_existing_safe_payload(
            marking_id,
            payload,
            policy(allowed_tlp_levels=frozenset({"red"})),
            ExistingStixReferenceUse.OBJECT_MARKING,
        )


def test_existing_markings_accept_exact_tlp_and_explicit_safe_statement():
    tlp = existing_payload(
        TLP_WHITE_ID,
        "marking-definition",
        marking_type="tlp",
        marking_level="white",
    )
    assert validate_existing_safe_payload(
        TLP_WHITE_ID,
        tlp,
        policy(),
        ExistingStixReferenceUse.OBJECT_MARKING,
    )["marking_level"] == "white"

    statement_id = "marking-definition--ffffffff-ffff-4fff-8fff-ffffffffffff"
    statement = existing_payload(
        statement_id,
        "marking-definition",
        marking_type="statement",
        statement="Approved handling",
    )
    approved = policy(allow_statement_markings=True)
    result = validate_existing_safe_payload(
        statement_id,
        statement,
        approved,
        ExistingStixReferenceUse.OBJECT_MARKING,
    )
    assert result["statement"] == "Approved handling"
    with pytest.raises(TypeError):
        result["statement"] = "changed"  # type: ignore[index]

    with pytest.raises(StixValidationError):
        validate_existing_safe_payload(
            TLP_WHITE_ID,
            tlp,
            policy(allowed_tlp_levels=frozenset()),
            ExistingStixReferenceUse.OBJECT_MARKING,
        )
    with pytest.raises(StixValidationError):
        validate_existing_safe_payload(
            TLP_WHITE_ID,
            existing_payload(TLP_WHITE_ID, "marking-definition"),
            policy(allow_statement_markings=True),
            ExistingStixReferenceUse.OBJECT_MARKING,
        )
    with pytest.raises(StixValidationError):
        validate_existing_safe_payload(
            TLP_WHITE_ID,
            {**tlp, "created": "2026-07-01T10:00:00.000000Z"},
            policy(),
            ExistingStixReferenceUse.OBJECT_MARKING,
        )


@pytest.mark.parametrize(
    "statement",
    ["", "   ", "unsafe\u0085statement", "not  canonical"],
)
def test_existing_statement_marking_requires_enabled_bounded_control_free_text(statement):
    statement_id = "marking-definition--ffffffff-ffff-4fff-8fff-ffffffffffff"
    payload = existing_payload(
        statement_id,
        "marking-definition",
        marking_type="statement",
        statement=statement,
    )
    with pytest.raises(StixValidationError):
        validate_existing_safe_payload(
            statement_id,
            payload,
            policy(allow_statement_markings=True),
            ExistingStixReferenceUse.OBJECT_MARKING,
        )
    with pytest.raises(StixValidationError):
        validate_existing_safe_payload(
            statement_id,
            {**payload, "statement": "Approved"},
            policy(),
            ExistingStixReferenceUse.OBJECT_MARKING,
        )


@pytest.mark.parametrize(
    ("expected_id", "payload"),
    [
        (IDS["identity"], {"type": "identity", "spec_version": "2.1"}),
        (
            IDS["identity"],
            existing_payload(IDS["malware"], "malware"),
        ),
        (
            IDS["identity"],
            {"type": "identity", "id": IDS["identity"]},
        ),
        (
            IDS["identity"],
            existing_payload(IDS["identity"], "identity", spec_version="2.0"),
        ),
        (
            IDS["identity"],
            existing_payload(IDS["identity"], "url"),
        ),
        (
            "report--dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            existing_payload(
                "report--dddddddd-dddd-4ddd-8ddd-dddddddddddd", "report"
            ),
        ),
        (
            TLP_WHITE_ID,
            existing_payload(
                TLP_WHITE_ID,
                "marking-definition",
                marking_type="tlp",
                marking_level="white",
            ),
        ),
        (
            IDS["relationship"],
            existing_payload(IDS["relationship"], "relationship"),
        ),
    ],
)
def test_existing_relationship_targets_require_canonical_compatible_safe_identity(
    expected_id, payload
):
    with pytest.raises(StixValidationError):
        validate_existing_safe_payload(
            expected_id,
            payload,
            policy(),
            ExistingStixReferenceUse.RELATIONSHIP_TARGET,
        )


@pytest.mark.parametrize(
    ("stix_id", "stix_type"),
    [
        (IDS["identity"], "identity"),
        (IDS["ipv4-addr"], "ipv4-addr"),
    ],
)
def test_existing_relationship_targets_accept_canonical_sdo_and_sco(stix_id, stix_type):
    result = validate_existing_safe_payload(
        stix_id,
        existing_payload(stix_id, stix_type),
        policy(),
        ExistingStixReferenceUse.RELATIONSHIP_TARGET,
    )
    assert dict(result) == {"type": stix_type, "id": stix_id, "spec_version": "2.1"}


@pytest.mark.parametrize(
    ("stix_id", "stix_type", "changes"),
    [
        (TLP_WHITE_ID, "marking-definition", {"marking_type": "tlp", "marking_level": "white"}),
        *[(IDS[stix_type], stix_type, {}) for stix_type in IDS],
    ],
)
def test_complete_canonical_safe_schema_exists_for_every_supported_type(
    stix_id, stix_type, changes
):
    payload = existing_payload(stix_id, stix_type, **changes)

    validated = validate_canonical_safe_payload(
        stix_id,
        payload,
        policy(),
        expected_stix_type=stix_type,
    )

    assert validated["id"] == stix_id
    with pytest.raises(StixValidationError):
        validate_canonical_safe_payload(
            stix_id,
            {**payload, "payload_url": "https://payload.example/sample"},
            policy(),
            expected_stix_type=stix_type,
        )


@pytest.mark.parametrize(
    "unexpected_key",
    [
        "password",
        "secret",
        "token",
        "headers",
        "cookies",
        "database_url",
        "raw_payload",
        "command",
        "command_line",
        "payload",
        "payload_url",
        "binary",
        "sample",
        "executable",
        "script",
        "exploit",
    ],
)
def test_canonical_safe_schema_rejects_every_unexpected_sensitive_key(
    unexpected_key,
):
    payload = existing_payload(IDS["identity"], "identity")
    payload[unexpected_key] = "must-not-stage"

    with pytest.raises(StixValidationError):
        validate_canonical_safe_payload(IDS["identity"], payload, policy())


def test_canonical_safe_schema_validates_nested_structures_exactly():
    ipv4 = existing_payload(IDS["ipv4-addr"], "ipv4-addr")
    malformed_observable = deepcopy(ipv4)
    malformed_observable["observable"]["payload"] = "unexpected"
    malformed_mapping = deepcopy(ipv4)
    malformed_mapping["mapped_observables"][0]["token"] = "unexpected"

    identity = existing_payload(IDS["identity"], "identity")
    malformed_reference = deepcopy(identity)
    malformed_reference["external_references"] = [
        {"source_name": "vendor", "external_id": "G0001", "url": "https://example.test"}
    ]
    malformed_array = deepcopy(identity)
    malformed_array["sectors"] = [{"name": "technology"}]

    file_payload = existing_payload(IDS["file"], "file")
    malformed_hashes = deepcopy(file_payload)
    malformed_hashes["hashes"]["sha224"] = "a" * 56

    for stix_id, payload in (
        (IDS["ipv4-addr"], malformed_observable),
        (IDS["ipv4-addr"], malformed_mapping),
        (IDS["identity"], malformed_reference),
        (IDS["identity"], malformed_array),
        (IDS["file"], malformed_hashes),
    ):
        with pytest.raises(StixValidationError):
            validate_canonical_safe_payload(stix_id, payload, policy())


def test_existing_safe_payload_rejects_controls_and_unbounded_integer_values():
    for unsafe in ("unsafe\u0085text", 2**64):
        payload = existing_payload(
            IDS["identity"],
            "identity",
            extra=unsafe,
        )
        with pytest.raises(StixValidationError):
            validate_existing_safe_payload(
                IDS["identity"],
                payload,
                policy(),
                ExistingStixReferenceUse.RELATIONSHIP_TARGET,
            )


def test_duplicate_versions_are_sorted_and_latest_wins_without_list_order():
    latest = versioned(
        "identity",
        identity_class="organization",
        modified="2026-07-03T00:00:00Z",
        name="Latest",
    )
    oldest = versioned(
        "identity",
        identity_class="organization",
        modified="2026-07-02T00:00:00Z",
        name="Oldest",
    )

    result = validate([latest, oldest])

    assert result.objects_received == result.objects_validated == 2
    assert len(result.objects) == 1
    assert result.objects[0].safe_payload["name"] == "Latest"
    assert tuple(
        item.safe_payload["name"] for item in result.validated_versions
    ) == ("Oldest", "Latest")


def test_version_sequence_requires_stable_created_and_creator_and_terminal_revocation():
    creator = IDS["identity"]
    base = versioned(
        "indicator",
        pattern="[ipv4-addr:value = '8.8.8.8']",
        pattern_type="stix",
        pattern_version="2.1",
        valid_from=CREATED,
        created_by_ref=creator,
    )
    later = {**base, "modified": "2026-07-02T11:00:00Z"}
    assert validate([later, base]).objects[0].modified == datetime(
        2026, 7, 2, 11, tzinfo=UTC
    )

    with pytest.raises(StixValidationError, match="created timestamp"):
        validate([{**later, "created": "2026-06-30T10:00:00Z"}, base])
    with pytest.raises(StixValidationError, match="creator identity"):
        validate([{**later, "created_by_ref": OTHER_IDENTITY_ID}, base])
    without_creator = {key: value for key, value in base.items() if key != "created_by_ref"}
    with pytest.raises(StixValidationError, match="creator identity"):
        validate([later, without_creator])
    with pytest.raises(StixValidationError, match="terminal"):
        validate([{**base, "revoked": True}, later])

    latest_revoked = {**later, "revoked": True}
    assert validate([latest_revoked, base]).objects[0].safe_payload["revoked"] is True


def test_duplicate_same_version_and_nonversioned_objects_are_rejected():
    first = versioned("identity", identity_class="organization", name="First")
    second = versioned("identity", identity_class="organization", name="Second")
    with pytest.raises(StixValidationError, match="duplicate STIX object version"):
        validate([first, second])
    item = observable("ipv4-addr", "8.8.8.8")
    with pytest.raises(StixValidationError, match="non-versioned"):
        validate([item, item])


def test_safe_content_hash_is_deterministic_and_raw_fields_are_not_retained():
    item = versioned(
        "identity",
        identity_class="organization",
        description="Synthetic summary",
        contact_information="do-not-stage@example.test",
    )
    first = validate([item]).objects[0]
    second = validate([item]).objects[0]

    assert first.content_hash == second.content_hash
    assert "contact_information" not in first.safe_payload
    assert "description" not in first.safe_payload
    assert "description_summary" not in first.safe_payload


def _mitre_object(stix_type, stix_id, **changes):
    value = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": stix_id,
        "created": CREATED,
        "modified": MODIFIED,
        "name": f"Synthetic {stix_type}",
        "x_mitre_domains": ["enterprise-attack"],
    }
    value.update(changes)
    return value


def _validate_mitre(objects):
    raw = json.dumps({"objects": objects, "more": False}).encode()
    bounded = parse_stix_json_bytes(
        raw,
        MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
        StixDocumentFormat.TAXII_ENVELOPE,
    )
    return validate_stix_document(
        bounded,
        MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
        allow_unresolved_relationships=True,
    )


def test_mitre_custom_allow_list_domain_and_deprecated_lifecycle():
    intrusion_id = "intrusion-set--dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    document = _validate_mitre(
        [
            _mitre_object(
                "intrusion-set",
                intrusion_id,
                aliases=["One"],
                x_mitre_aliases=["Two"],
                revoked=False,
                x_mitre_deprecated=True,
                x_mitre_version="1.0",
            )
        ],
    )
    payload = document.objects[0].safe_payload
    assert payload["type"] == "intrusion-set"
    assert payload["aliases"] == ("One", "Two")
    assert payload["revoked"] is True
    assert payload["source_revoked"] is False
    assert payload["x_mitre_deprecated"] is True
    assert "x_mitre_version" not in payload
    validate_canonical_safe_payload(
        intrusion_id,
        payload,
        MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
    )


def test_mitre_unknown_custom_property_and_non_enterprise_domain_are_rejected():
    attack_id = "attack-pattern--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    with pytest.raises(StixValidationError, match="custom property"):
        _validate_mitre(
            [
                _mitre_object(
                    "attack-pattern",
                    attack_id,
                    x_mitre_unreviewed="unsafe",
                )
            ],
        )
    with pytest.raises(StixValidationError, match="Enterprise domain"):
        _validate_mitre(
            [
                _mitre_object(
                    "attack-pattern",
                    attack_id,
                    x_mitre_domains=["mobile-attack"],
                )
            ],
        )


def test_mitre_custom_object_type_is_rejected_even_with_x_mitre_prefix():
    with pytest.raises(StixValidationError, match="type is not approved"):
        _validate_mitre(
            [
                {
                    "type": "x-mitre-data-source",
                    "spec_version": "2.1",
                    "id": "x-mitre-data-source--ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "created": CREATED,
                    "modified": MODIFIED,
                    "name": "Synthetic",
                }
            ],
        )


def test_mitre_unsupported_relationship_combination_is_counted_and_excluded():
    intrusion_id = "intrusion-set--dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    campaign_id = "campaign--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--ffffffff-ffff-4fff-8fff-ffffffffffff",
        "created": CREATED,
        "modified": MODIFIED,
        "relationship_type": "uses",
        "source_ref": intrusion_id,
        "target_ref": campaign_id,
        "x_mitre_domains": ["enterprise-attack"],
    }
    document = _validate_mitre(
        [
            _mitre_object("intrusion-set", intrusion_id),
            _mitre_object("campaign", campaign_id),
            relationship,
        ],
    )
    assert document.objects_received == 3
    assert document.objects_validated == 2
    assert document.relationships_validated == 0
    assert document.relationships_excluded == 1
