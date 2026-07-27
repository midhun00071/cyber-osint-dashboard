from dataclasses import replace
import json
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from app.ingestion.stix_taxii import bounded_json
from app.ingestion.stix_taxii.bounded_json import (
    StixBoundedJsonError,
    StixDocumentFormat,
    load_stix_json_file,
    parse_stix_json_bytes,
)
from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    StixInputTransport,
    validate_stix_source_policy,
)


OBJECT = {
    "type": "ipv4-addr",
    "spec_version": "2.1",
    "id": "ipv4-addr--89a9b3aa-12ac-4e13-a93b-6dd09d95fa00",
    "value": "8.8.8.8",
}
VALID_BUNDLE_ID = "bundle--11111111-1111-4111-8111-111111111111"


def policy(**changes):
    base = ApprovedStixSourcePolicy(
        source_slug="synthetic-stix",
        allowed_transport=StixInputTransport.LOCAL_BUNDLE,
        policy_base_url="https://stix.example/objects",
    )
    return validate_stix_source_policy(replace(base, **changes))


def bundle_bytes(objects=(OBJECT,), **extra):
    return json.dumps({"type": "bundle", "objects": list(objects), **extra}).encode()


def test_valid_utf8_and_optional_bom_load_to_deeply_immutable_document(tmp_path):
    for prefix in (b"", b"\xef\xbb\xbf"):
        path = tmp_path / f"bundle-{len(prefix)}.json"
        path.write_bytes(prefix + bundle_bytes())

        document = load_stix_json_file(path, policy(), StixDocumentFormat.STIX_BUNDLE)

        assert document.objects[0]["value"] == "8.8.8.8"
        assert isinstance(document.objects[0], MappingProxyType)
        with pytest.raises(TypeError):
            document.objects[0]["value"] = "changed"  # type: ignore[index]


def test_taxii_envelope_fixture_is_explicit_and_bounded():
    fixture_policy = policy(
        allowed_transport=StixInputTransport.TAXII_ENVELOPE_FIXTURE
    )
    data = json.dumps({"objects": [OBJECT], "more": True, "next": "page-2"}).encode()

    document = parse_stix_json_bytes(
        data,
        fixture_policy,
        StixDocumentFormat.TAXII_ENVELOPE,
    )

    assert document.more is True
    assert document.next_token == "page-2"


@pytest.mark.parametrize(
    "payload",
    [
        {"objects": [], "more": "true"},
        {"objects": [], "more": False, "next": "page-2"},
        {"objects": [], "server": "https://evil.example"},
        {"objects": [], "headers": {"Authorization": "secret"}},
    ],
)
def test_taxii_fixture_rejects_invalid_or_unsafe_envelope_fields(payload):
    fixture_policy = policy(
        allowed_transport=StixInputTransport.TAXII_ENVELOPE_FIXTURE
    )
    with pytest.raises(StixBoundedJsonError):
        parse_stix_json_bytes(
            json.dumps(payload).encode(),
            fixture_policy,
            StixDocumentFormat.TAXII_ENVELOPE,
        )


@pytest.mark.parametrize(
    "data",
    [
        b'\xff{"type":"bundle","objects":[]}',
        b'{"type":"bundle","objects":[],"objects":[]}',
        b'{"type":"bundle","objects":[],"value":NaN}',
        b'{"type":"bundle","objects":[],"value":Infinity}',
    ],
)
def test_invalid_utf8_duplicate_keys_and_nonstandard_constants_are_rejected(data):
    with pytest.raises(StixBoundedJsonError):
        parse_stix_json_bytes(data, policy(), StixDocumentFormat.STIX_BUNDLE)


def test_exact_byte_boundary_is_accepted_and_one_byte_over_is_rejected():
    data = bundle_bytes()
    exact = policy(maximum_file_bytes=len(data))

    assert parse_stix_json_bytes(data, exact, StixDocumentFormat.STIX_BUNDLE)
    with pytest.raises(StixBoundedJsonError, match="byte limit"):
        parse_stix_json_bytes(
            data,
            policy(maximum_file_bytes=len(data) - 1),
            StixDocumentFormat.STIX_BUNDLE,
        )


def test_depth_node_object_and_string_limits_are_enforced():
    deep = {"type": "bundle", "objects": [], "extra": {"a": {"b": {}}}}
    with pytest.raises(StixBoundedJsonError):
        parse_stix_json_bytes(
            json.dumps(deep).encode(),
            policy(maximum_json_depth=2),
            StixDocumentFormat.STIX_BUNDLE,
        )
    with pytest.raises(StixBoundedJsonError):
        parse_stix_json_bytes(
            bundle_bytes((OBJECT, OBJECT)),
            policy(maximum_objects=1),
            StixDocumentFormat.STIX_BUNDLE,
        )
    with pytest.raises(StixBoundedJsonError):
        parse_stix_json_bytes(
            bundle_bytes(({**OBJECT, "value": "x" * 20},)),
            policy(maximum_json_string_length=10),
            StixDocumentFormat.STIX_BUNDLE,
        )
    with pytest.raises(StixBoundedJsonError):
        parse_stix_json_bytes(
            bundle_bytes(),
            policy(maximum_json_nodes=4, maximum_objects=1),
            StixDocumentFormat.STIX_BUNDLE,
        )


def test_bundle_requires_exact_shape_and_explicit_matching_transport():
    with pytest.raises(StixBoundedJsonError):
        parse_stix_json_bytes(
            json.dumps({"type": "bundle", "objects": [], "server": "x"}).encode(),
            policy(),
            StixDocumentFormat.STIX_BUNDLE,
        )


def test_optional_bundle_identifier_requires_canonical_rfc_4122_uuid():
    accepted = parse_stix_json_bytes(
        bundle_bytes(id=VALID_BUNDLE_ID),
        policy(),
        StixDocumentFormat.STIX_BUNDLE,
    )
    assert accepted.bundle_id == VALID_BUNDLE_ID
    assert parse_stix_json_bytes(
        bundle_bytes(), policy(), StixDocumentFormat.STIX_BUNDLE
    ).bundle_id is None


@pytest.mark.parametrize(
    "bundle_id",
    [
        "bundle--x",
        "bundle--not-a-uuid",
        "indicator--11111111-1111-4111-8111-111111111111",
        "bundle--AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        "bundle--00000000-0000-4000-0000-000000000000",
        "bundle--11111111-1111-4111-8111-111111111111?x=1",
        "bundle--11111111-1111-4111-8111-111111111111#x",
        "bundle--11111111-1111-4111-8111-111111111111/path",
        " bundle--11111111-1111-4111-8111-111111111111",
        "bundle--11111111-1111-4111-8111-11111111111\u0085",
        "bundle--" + "a" * 301,
    ],
)
def test_invalid_bundle_identifiers_are_rejected(bundle_id):
    with pytest.raises(StixBoundedJsonError, match="identifier"):
        parse_stix_json_bytes(
            bundle_bytes(id=bundle_id),
            policy(),
            StixDocumentFormat.STIX_BUNDLE,
        )
    fixture_policy = policy(
        allowed_transport=StixInputTransport.TAXII_ENVELOPE_FIXTURE
    )
    with pytest.raises(StixBoundedJsonError, match="does not allow"):
        parse_stix_json_bytes(
            bundle_bytes(), fixture_policy, StixDocumentFormat.STIX_BUNDLE
        )


def test_directory_remote_device_and_pipe_paths_are_rejected_without_disclosure(tmp_path):
    for path in (
        tmp_path,
        r"\\server\share\bundle.json",
        r"\\?\C:\bundle.json",
        r"\\.\pipe\stix",
        r"\Device\NamedPipe\stix",
    ):
        with pytest.raises(StixBoundedJsonError) as caught:
            load_stix_json_file(path, policy(), StixDocumentFormat.STIX_BUNDLE)
        assert str(path) not in str(caught.value)


def test_direct_and_parent_symlinks_are_rejected_when_supported(tmp_path):
    target = tmp_path / "target.json"
    target.write_bytes(bundle_bytes())
    direct = tmp_path / "direct.json"
    parent = tmp_path / "linked-parent"
    try:
        direct.symlink_to(target)
        parent.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    for path in (direct, parent / "target.json"):
        with pytest.raises(StixBoundedJsonError):
            load_stix_json_file(path, policy(), StixDocumentFormat.STIX_BUNDLE)


def test_descriptor_snapshot_change_is_rejected_and_error_is_sanitized(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "bundle.json"
    path.write_bytes(bundle_bytes())
    monkeypatch.setattr(bounded_json, "_same_file_snapshot", lambda before, after: False)

    with pytest.raises(StixBoundedJsonError) as caught:
        load_stix_json_file(path, policy(), StixDocumentFormat.STIX_BUNDLE)

    assert "8.8.8.8" not in str(caught.value)
    assert str(path) not in str(caught.value)


def test_file_descriptor_is_closed_when_validation_after_open_fails(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "bundle.json"
    path.write_bytes(bundle_bytes())
    real_open = os.open
    descriptor = None

    def tracked_open(*args, **kwargs):
        nonlocal descriptor
        descriptor = real_open(*args, **kwargs)
        return descriptor

    monkeypatch.setattr(bounded_json.os, "open", tracked_open)
    monkeypatch.setattr(bounded_json, "_same_path_chain", lambda before, after: False)
    with pytest.raises(StixBoundedJsonError):
        load_stix_json_file(path, policy(), StixDocumentFormat.STIX_BUNDLE)

    assert descriptor is not None
    with pytest.raises(OSError):
        os.fstat(descriptor)
