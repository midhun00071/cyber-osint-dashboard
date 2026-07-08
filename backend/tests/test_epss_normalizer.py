from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest

from app.ingestion.normalizers.epss import (
    EpssNormalizationError,
    MAX_PAYLOAD_BYTES,
    normalize_epss_record,
)


def make_record(**overrides: object) -> dict:
    record = {
        "cve": "CVE-2026-12345",
        "epss": "0.123456",
        "percentile": "0.987654",
        "date": "2026-07-08",
        "ignored": "not retained",
    }
    record.update(overrides)
    return record


def test_valid_record_maps_to_normalized_contract() -> None:
    normalized = normalize_epss_record(make_record())

    assert normalized.cve_id == "CVE-2026-12345"
    assert normalized.epss_score == Decimal("0.123456")
    assert normalized.epss_percentile == Decimal("0.987654")
    assert normalized.score_date == date(2026, 7, 8)
    assert normalized.raw_payload == {
        "cve": "CVE-2026-12345",
        "epss": "0.123456",
        "percentile": "0.987654",
        "date": "2026-07-08",
    }
    assert len(normalized.content_hash) == 64


def test_decimal_precision_is_normalized_to_six_fractional_places() -> None:
    normalized = normalize_epss_record(
        make_record(epss="0.123456789", percentile="0.0000004")
    )

    assert normalized.epss_score == Decimal("0.123457")
    assert normalized.epss_percentile == Decimal("0.000000")
    assert normalized.raw_payload["epss"] == "0.123457"
    assert normalized.raw_payload["percentile"] == "0.000000"


def test_cve_id_is_normalized_to_uppercase() -> None:
    assert normalize_epss_record(make_record(cve="cve-2026-12345")).cve_id == (
        "CVE-2026-12345"
    )


@pytest.mark.parametrize("value", ["0", "1", 0, 1, Decimal("0.5")])
def test_score_boundaries_are_valid(value: object) -> None:
    normalized = normalize_epss_record(make_record(epss=value, percentile=value))

    assert Decimal("0") <= normalized.epss_score <= Decimal("1")
    assert Decimal("0") <= normalized.epss_percentile <= Decimal("1")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0.0000004", Decimal("0.000000")),
        ("0.9999999", Decimal("1.000000")),
        ("1", Decimal("1.000000")),
        ("0", Decimal("0.000000")),
    ],
)
def test_probability_values_quantize_to_persisted_precision(
    value: str,
    expected: Decimal,
) -> None:
    normalized = normalize_epss_record(make_record(epss=value, percentile=value))

    assert normalized.epss_score == expected
    assert normalized.epss_percentile == expected
    assert normalized.raw_payload["epss"] == format(expected, ".6f")
    assert normalized.raw_payload["percentile"] == format(expected, ".6f")


@pytest.mark.parametrize("field", ["epss", "percentile"])
@pytest.mark.parametrize("value", [-1, "1.000001", "NaN", "Infinity", True])
def test_invalid_probability_values_are_rejected(field: str, value: object) -> None:
    with pytest.raises(EpssNormalizationError, match="invalid"):
        normalize_epss_record(make_record(**{field: value}))


@pytest.mark.parametrize("cve_id", [None, "CVE-26-1234", "CVE-2026-123", "unsafe"])
def test_invalid_cve_id_is_rejected(cve_id: object) -> None:
    with pytest.raises(EpssNormalizationError, match="invalid CVE ID"):
        normalize_epss_record(make_record(cve=cve_id))


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
def test_invalid_date_is_rejected(value: object) -> None:
    with pytest.raises(EpssNormalizationError, match="score date"):
        normalize_epss_record(make_record(date=value))


@pytest.mark.parametrize("field", ["cve", "epss", "percentile", "date"])
def test_missing_required_fields_are_rejected(field: str) -> None:
    record = make_record()
    del record[field]

    with pytest.raises(EpssNormalizationError):
        normalize_epss_record(record)


@pytest.mark.parametrize("record", [[], "bad", False])
def test_unexpected_record_types_are_rejected(record: object) -> None:
    with pytest.raises(EpssNormalizationError, match="object"):
        normalize_epss_record(record)  # type: ignore[arg-type]


def test_content_hash_is_deterministic() -> None:
    first = normalize_epss_record(make_record())
    second = normalize_epss_record(
        {"percentile": "0.987654", "date": "2026-07-08", "epss": "0.123456", "cve": "CVE-2026-12345"}
    )

    assert first.content_hash == second.content_hash


def test_safe_source_payload_is_bounded_and_does_not_echo_extras() -> None:
    marker = "private-untrusted-marker"
    normalized = normalize_epss_record(make_record(extra=marker + ("x" * MAX_PAYLOAD_BYTES)))

    assert marker not in str(normalized.raw_payload)


def test_error_messages_do_not_include_raw_values() -> None:
    marker = "sensitive-untrusted-fragment"

    with pytest.raises(EpssNormalizationError) as exc_info:
        normalize_epss_record(make_record(cve=marker))

    assert marker not in str(exc_info.value)
