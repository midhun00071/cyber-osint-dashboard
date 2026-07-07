from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from app.ingestion.normalizers.nvd import (
    MAX_AFFECTED_PRODUCTS,
    MAX_PAYLOAD_BYTES,
    MAX_SUMMARY_LENGTH,
    NvdNormalizationError,
    NvdPayloadTooLargeError,
    normalize_nvd_cve,
)


def make_wrapper(**cve_overrides: object) -> dict:
    cve = {
        "id": "CVE-2026-12345",
        "published": "2026-01-02T03:04:05.000Z",
        "lastModified": "2026-01-03T04:05:06+00:00",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "es", "value": "Descripción no seleccionada"},
            {"lang": "en", "value": "English defensive vulnerability summary."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
                                "matchCriteriaId": "11111111-1111-1111-1111-111111111111",
                                "untrustedExtra": {"ignored": True},
                            }
                        ]
                    }
                ]
            }
        ],
    }
    cve.update(cve_overrides)
    return {"cve": cve}


def metric(version: str, score: object, severity: object = "HIGH") -> list[dict]:
    return [
        {
            "cvssData": {
                "version": version,
                "baseScore": score,
                "baseSeverity": severity,
                "vectorString": f"CVSS:{version}/AV:N",
            }
        }
    ]


def test_valid_record_maps_to_normalized_contract() -> None:
    normalized = normalize_nvd_cve(make_wrapper())

    assert normalized.cve_id == "CVE-2026-12345"
    assert normalized.title.startswith("CVE-2026-12345:")
    assert normalized.summary == "English defensive vulnerability summary."
    assert normalized.canonical_url == (
        "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"
    )
    assert normalized.source_published_at == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert normalized.source_modified_at == datetime(2026, 1, 3, 4, 5, 6, tzinfo=UTC)
    assert normalized.status == "active"
    assert normalized.severity == "critical"
    assert normalized.cvss_score == Decimal("9.8")
    assert normalized.cvss_version == "3.1"
    assert normalized.affected_summary == "NVD lists 1 affected product configuration(s)."
    assert normalized.affected_products == [
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
            "matchCriteriaId": "11111111-1111-1111-1111-111111111111",
        }
    ]
    assert len(normalized.content_hash) == 64


def test_cve_id_is_normalized_to_uppercase() -> None:
    normalized = normalize_nvd_cve(make_wrapper(id="cve-2026-12345"))

    assert normalized.cve_id == "CVE-2026-12345"


@pytest.mark.parametrize("cve_id", [None, "CVE-26-1234", "CVE-2026-123", "unsafe"])
def test_invalid_cve_id_is_rejected(cve_id: object) -> None:
    with pytest.raises(NvdNormalizationError, match="invalid CVE ID"):
        normalize_nvd_cve(make_wrapper(id=cve_id))


def test_first_english_description_is_selected_and_bounded() -> None:
    long_summary = "a" * (MAX_SUMMARY_LENGTH + 10)
    normalized = normalize_nvd_cve(
        make_wrapper(
            descriptions=[
                {"lang": "fr", "value": "French"},
                {"lang": "EN", "value": long_summary},
                {"lang": "en", "value": "Second English value"},
            ]
        )
    )

    assert normalized.summary == "a" * MAX_SUMMARY_LENGTH
    assert len(normalized.title) == 500


def test_missing_english_description_uses_cve_id_title() -> None:
    normalized = normalize_nvd_cve(
        make_wrapper(descriptions=[{"lang": "fr", "value": "French"}])
    )

    assert normalized.summary is None
    assert normalized.title == normalized.cve_id


@pytest.mark.parametrize(
    "field",
    ["published", "lastModified"],
)
def test_invalid_or_naive_timestamp_is_rejected(field: str) -> None:
    with pytest.raises(NvdNormalizationError, match="timestamp"):
        normalize_nvd_cve(make_wrapper(**{field: "2026-01-01T00:00:00"}))


def test_cvss_precedence_prefers_newest_supported_version() -> None:
    normalized = normalize_nvd_cve(
        make_wrapper(
            metrics={
                "cvssMetricV2": metric("2.0", 5.0, "MEDIUM"),
                "cvssMetricV30": metric("3.0", 7.0),
                "cvssMetricV31": metric("3.1", 8.0),
                "cvssMetricV40": metric("4.0", 9.0, "CRITICAL"),
            }
        )
    )

    assert normalized.cvss_version == "4.0"
    assert normalized.cvss_score == Decimal("9.0")
    assert normalized.severity == "critical"


def test_missing_optional_cvss_metrics_maps_to_unknown() -> None:
    normalized = normalize_nvd_cve(make_wrapper(metrics={}))

    assert normalized.severity == "unknown"
    assert normalized.cvss_score is None
    assert normalized.cvss_vector is None
    assert normalized.cvss_version is None


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -1, 10.1])
def test_non_finite_or_out_of_range_cvss_score_is_rejected(score: object) -> None:
    with pytest.raises(NvdNormalizationError, match="CVSS score is invalid"):
        normalize_nvd_cve(
            make_wrapper(metrics={"cvssMetricV40": metric("4.0", score)})
        )


def test_uncontrolled_severity_is_rejected() -> None:
    with pytest.raises(NvdNormalizationError, match="severity is invalid"):
        normalize_nvd_cve(
            make_wrapper(
                metrics={"cvssMetricV31": metric("3.1", 5.0, "EXTREME")}
            )
        )


def test_rejected_cve_maps_to_archived_status() -> None:
    normalized = normalize_nvd_cve(make_wrapper(vulnStatus="Rejected"))

    assert normalized.status == "archived"


def test_equivalent_payload_ordering_has_stable_hash() -> None:
    first = make_wrapper()
    second = {"cve": dict(reversed(list(first["cve"].items())))}

    assert normalize_nvd_cve(first).content_hash == normalize_nvd_cve(second).content_hash


def test_oversized_payload_is_rejected_without_echoing_payload() -> None:
    marker = "private-raw-payload-marker"
    wrapper = make_wrapper(extra=marker + ("x" * MAX_PAYLOAD_BYTES))

    with pytest.raises(NvdPayloadTooLargeError) as exc_info:
        normalize_nvd_cve(wrapper)

    assert marker not in str(exc_info.value)
    assert "512 KiB" in str(exc_info.value)


def test_affected_product_data_is_bounded_and_allow_listed() -> None:
    matches = [
        {
            "vulnerable": True,
            "criteria": f"cpe:2.3:a:example:product_{index}:*:*:*:*:*:*:*:*",
            "unsafe": "must-not-be-copied",
        }
        for index in range(MAX_AFFECTED_PRODUCTS + 20)
    ]
    normalized = normalize_nvd_cve(
        make_wrapper(configurations=[{"nodes": [{"cpeMatch": matches}]}])
    )

    assert len(normalized.affected_products) == MAX_AFFECTED_PRODUCTS
    assert all("unsafe" not in product for product in normalized.affected_products)


def test_only_explicitly_vulnerable_cpe_matches_are_retained() -> None:
    matches = [
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:example:retained:*:*:*:*:*:*:*:*",
            "unsafe": "must-not-be-copied",
        },
        {
            "vulnerable": False,
            "criteria": "cpe:2.3:a:example:not_vulnerable:*:*:*:*:*:*:*:*",
        },
        {"criteria": "cpe:2.3:a:example:missing_flag:*:*:*:*:*:*:*:*"},
        {
            "vulnerable": "true",
            "criteria": "cpe:2.3:a:example:string_flag:*:*:*:*:*:*:*:*",
        },
    ]

    normalized = normalize_nvd_cve(
        make_wrapper(configurations=[{"nodes": [{"cpeMatch": matches}]}])
    )

    assert normalized.affected_products == [
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:example:retained:*:*:*:*:*:*:*:*",
        }
    ]
    assert normalized.affected_summary == (
        "NVD lists 1 affected product configuration(s)."
    )


def test_affected_summary_is_none_without_vulnerable_products() -> None:
    matches = [
        {
            "vulnerable": False,
            "criteria": "cpe:2.3:a:example:not_vulnerable:*:*:*:*:*:*:*:*",
        },
        {"criteria": "cpe:2.3:a:example:missing_flag:*:*:*:*:*:*:*:*"},
        {
            "vulnerable": 1,
            "criteria": "cpe:2.3:a:example:integer_flag:*:*:*:*:*:*:*:*",
        },
    ]

    normalized = normalize_nvd_cve(
        make_wrapper(configurations=[{"nodes": [{"cpeMatch": matches}]}])
    )

    assert normalized.affected_products == []
    assert normalized.affected_summary is None


def test_input_dictionary_is_not_mutated_or_reused() -> None:
    wrapper = make_wrapper()
    original = deepcopy(wrapper)

    normalized = normalize_nvd_cve(wrapper)
    normalized.raw_payload["cve"]["id"] = "CVE-2099-9999"

    assert wrapper == original


def test_error_messages_do_not_include_raw_payload_fragments() -> None:
    marker = "sensitive-untrusted-fragment"

    with pytest.raises(NvdNormalizationError) as exc_info:
        normalize_nvd_cve(make_wrapper(id=marker))

    assert marker not in str(exc_info.value)
