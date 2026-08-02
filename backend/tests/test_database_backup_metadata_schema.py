from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
import re

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "database" / "backup-metadata.schema.json"


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def valid_document() -> dict:
    return {
        "metadata_format_version": "1.0",
        "backup_identifier": "backup_review_20260731",
        "database_system": "postgresql",
        "logical_backup_type": "pg_dump_custom",
        "started_utc": "2026-07-31T08:00:00Z",
        "completed_utc": "2026-07-31T08:01:00Z",
        "alembic_revision": "d7a9e51c2f40",
        "outcome_state": "failed",
        "encryption_state": "unknown",
        "checksum_algorithm": "sha256",
        "checksum_value": "a" * 64,
        "artifact_size_bytes": 0,
        "artifact_reference": "artifact_ref_review_20260731",
        "safe_summary": "Synthetic contract-validation metadata only.",
    }


def assert_contract_accepts(document: dict) -> None:
    schema = load_schema()
    assert set(document) == set(schema["required"])
    assert not (set(document) - set(schema["properties"]))
    for name, value in document.items():
        definition = schema["properties"][name]
        if "const" in definition:
            assert value == definition["const"]
        if "enum" in definition:
            assert value in definition["enum"]
        if definition.get("type") == "string":
            assert isinstance(value, str)
            assert len(value) >= definition.get("minLength", 0)
            assert len(value) <= definition.get("maxLength", len(value))
            if "pattern" in definition:
                assert re.fullmatch(definition["pattern"], value)
        if definition.get("type") == "integer":
            assert type(value) is int
            assert definition["minimum"] <= value <= definition["maximum"]
    timestamp_pattern = re.compile(schema["properties"]["started_utc"]["pattern"])
    for name in ("started_utc", "completed_utc"):
        assert timestamp_pattern.fullmatch(document[name])
        assert datetime.fromisoformat(document[name].replace("Z", "+00:00")).tzinfo is UTC
    expected_checksum_lengths = {"sha256": 64, "sha384": 96, "sha512": 128}
    assert len(document["checksum_value"]) == expected_checksum_lengths[
        document["checksum_algorithm"]
    ]
    prohibited_summary = re.compile(
        schema["properties"]["safe_summary"]["allOf"][0]["not"]["pattern"]
    )
    assert prohibited_summary.search(document["safe_summary"]) is None


def test_schema_is_strict_versioned_and_accepts_safe_metadata() -> None:
    schema = load_schema()

    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["additionalProperties"] is False
    assert_contract_accepts(valid_document())


def test_unknown_or_credential_properties_are_rejected() -> None:
    schema = load_schema()
    for name in ("password", "token", "database_url", "connection_string", "diagnostics"):
        document = valid_document()
        document[name] = "synthetic-prohibited-value"
        assert set(document) - set(schema["properties"])


@pytest.mark.parametrize(
    "reference",
    [
        "C:\\backups\\artifact.dump",
        "/var/backups/artifact.dump",
        "https://backup.example.invalid/artifact",
        "backup.example.invalid",
        "api.example.invalid:443",
        "powershell -Command Get-Item",
        "secret://backup-reference",
    ],
)
def test_artifact_reference_rejects_paths_urls_hosts_endpoints_and_commands(
    reference: str,
) -> None:
    definition = load_schema()["properties"]["artifact_reference"]

    assert re.fullmatch(definition["pattern"], reference) is None


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-07-31T08:00:00",
        "2026-07-31T08:00:00+04:00",
        "2026-07-31 08:00:00Z",
        "2026-13-31T08:00:00Z",
        "2026-07-31T25:00:00Z",
        "not-a-timestamp",
    ],
)
def test_timestamps_require_explicit_utc_z_format(timestamp: str) -> None:
    definition = load_schema()["properties"]["started_utc"]

    assert re.fullmatch(definition["pattern"], timestamp) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("checksum_algorithm", "md5"),
        ("outcome_state", "complete-ish"),
        ("encryption_state", "probably-encrypted"),
        ("artifact_size_bytes", -1),
        ("artifact_size_bytes", 9223372036854775808),
    ],
)
def test_unapproved_states_algorithms_and_sizes_are_rejected(field, value) -> None:
    document = valid_document()
    document[field] = value

    with pytest.raises(AssertionError):
        assert_contract_accepts(document)


def test_checksum_length_must_match_allow_list_algorithm() -> None:
    document = valid_document()
    document["checksum_value"] = "a" * 96

    with pytest.raises(AssertionError):
        assert_contract_accepts(document)


@pytest.mark.parametrize(
    "summary",
    [
        "Traceback: raw failure",
        "SELECT secret FROM table",
        "postgresql://credential-bearing-value",
        "powershell -Command Get-ChildItem",
        "token=synthetic-value",
        "Stored at C:\\backups\\artifact.dump",
        "Stored at /var/backups/artifact.dump",
        "Endpoint backup.example.invalid",
        "Endpoint 192.0.2.10:5432",
        "POSTGRES_PASSWORD=synthetic-value",
        "psql: raw diagnostic",
    ],
)
def test_summary_rejects_raw_errors_sql_commands_and_secret_shapes(summary: str) -> None:
    document = valid_document()
    document["safe_summary"] = summary

    with pytest.raises(AssertionError):
        assert_contract_accepts(document)


def test_summary_and_identifiers_are_bounded() -> None:
    document = valid_document()
    document["safe_summary"] = "x" * 501

    with pytest.raises(AssertionError):
        assert_contract_accepts(document)

    document = valid_document()
    document["backup_identifier"] = "backup_" + "x" * 100
    with pytest.raises(AssertionError):
        assert_contract_accepts(document)
