from __future__ import annotations

from copy import deepcopy
from datetime import date

import pytest

from app.ingestion.normalizers.cisa_kev import (
    CisaKevNormalizationError,
    MAX_PAYLOAD_BYTES,
    MAX_REQUIRED_ACTION_LENGTH,
    deduplicate_cisa_kev_entries,
    extract_cisa_kev_entries,
    normalize_cisa_kev_entry,
)


def make_entry(**overrides: object) -> dict:
    entry = {
        "cveID": "CVE-2026-12345",
        "vendorProject": "Vendor",
        "product": "Product",
        "vulnerabilityName": "Example Vulnerability",
        "dateAdded": "2026-07-08",
        "shortDescription": "A public defensive description.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2026-07-29",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Safe notes.",
        "ignored": "not retained",
    }
    entry.update(overrides)
    return entry


def test_catalog_entries_are_extracted_from_vulnerabilities_list() -> None:
    entries = [make_entry()]

    assert extract_cisa_kev_entries({"vulnerabilities": entries}) == entries


def test_valid_kev_entry_maps_to_normalized_contract() -> None:
    normalized = normalize_cisa_kev_entry(make_entry())

    assert normalized.cve_id == "CVE-2026-12345"
    assert normalized.date_added == date(2026, 7, 8)
    assert normalized.due_date == date(2026, 7, 29)
    assert normalized.known_ransomware_campaign_use is True
    assert normalized.raw_payload == {
        "cveID": "CVE-2026-12345",
        "dateAdded": "2026-07-08",
        "dueDate": "2026-07-29",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Safe notes.",
        "product": "Product",
        "requiredAction": "Apply updates per vendor instructions.",
        "shortDescription": "A public defensive description.",
        "vendorProject": "Vendor",
        "vulnerabilityName": "Example Vulnerability",
    }
    assert len(normalized.content_hash) == 64


def test_unknown_ransomware_value_maps_to_false() -> None:
    normalized = normalize_cisa_kev_entry(
        make_entry(knownRansomwareCampaignUse="Unknown")
    )

    assert normalized.known_ransomware_campaign_use is False
    assert normalized.raw_payload["knownRansomwareCampaignUse"] == "Unknown"


def test_cve_id_is_normalized_to_uppercase() -> None:
    assert normalize_cisa_kev_entry(make_entry(cveID="cve-2026-12345")).cve_id == (
        "CVE-2026-12345"
    )


@pytest.mark.parametrize(
    "cve_id",
    [
        None,
        "CVE-26-1234",
        "CVE-2026-123",
        "unsafe",
        "CVE-２０２６-１２３４",
    ],
)
def test_invalid_cve_id_is_rejected(cve_id: object) -> None:
    with pytest.raises(CisaKevNormalizationError, match="invalid CVE ID"):
        normalize_cisa_kev_entry(make_entry(cveID=cve_id))


@pytest.mark.parametrize(
    "field",
    ["dateAdded", "dueDate"],
)
@pytest.mark.parametrize(
    "value",
    [
        None,
        "20260708",
        "2026-W28-3",
        "08-07-2026",
        "2026-7-8",
        "2026-02-30",
        "2026-07-08T00:00:00Z",
        "not-a-date",
    ],
)
def test_invalid_dates_are_rejected(field: str, value: object) -> None:
    with pytest.raises(CisaKevNormalizationError):
        normalize_cisa_kev_entry(make_entry(**{field: value}))


@pytest.mark.parametrize("value", [None, "Likely", "", True])
def test_malformed_ransomware_value_fails_safely(value: object) -> None:
    with pytest.raises(CisaKevNormalizationError, match="ransomware"):
        normalize_cisa_kev_entry(make_entry(knownRansomwareCampaignUse=value))


def test_text_and_payload_are_bounded_and_extras_are_not_retained() -> None:
    marker = "private-untrusted-marker"
    normalized = normalize_cisa_kev_entry(
        make_entry(requiredAction="x" * (MAX_REQUIRED_ACTION_LENGTH + 10), extra=marker)
    )

    assert len(normalized.required_action) == MAX_REQUIRED_ACTION_LENGTH
    assert marker not in str(normalized.raw_payload)
    assert len(str(normalized.raw_payload).encode("utf-8")) < MAX_PAYLOAD_BYTES


def test_content_hash_is_deterministic() -> None:
    first = normalize_cisa_kev_entry(make_entry())
    second = normalize_cisa_kev_entry(
        {
            "knownRansomwareCampaignUse": "Known",
            "dueDate": "2026-07-29",
            "requiredAction": "Apply updates per vendor instructions.",
            "shortDescription": "A public defensive description.",
            "dateAdded": "2026-07-08",
            "vulnerabilityName": "Example Vulnerability",
            "product": "Product",
            "vendorProject": "Vendor",
            "cveID": "CVE-2026-12345",
            "notes": "Safe notes.",
        }
    )

    assert first.content_hash == second.content_hash


def test_normalizer_does_not_mutate_input() -> None:
    entry = make_entry()
    before = deepcopy(entry)

    normalize_cisa_kev_entry(entry)

    assert entry == before


def test_exact_duplicate_cves_are_collapsed_deterministically() -> None:
    record = normalize_cisa_kev_entry(make_entry())

    assert deduplicate_cisa_kev_entries([record, record]) == [record]


def test_conflicting_duplicate_cves_are_rejected() -> None:
    first = normalize_cisa_kev_entry(make_entry(requiredAction="A"))
    second = normalize_cisa_kev_entry(make_entry(requiredAction="B"))

    with pytest.raises(CisaKevNormalizationError, match="Conflicting duplicate"):
        deduplicate_cisa_kev_entries([first, second])


def test_error_messages_do_not_include_raw_values() -> None:
    marker = "sensitive-untrusted-fragment"

    with pytest.raises(CisaKevNormalizationError) as exc_info:
        normalize_cisa_kev_entry(make_entry(cveID=marker))

    assert marker not in str(exc_info.value)
