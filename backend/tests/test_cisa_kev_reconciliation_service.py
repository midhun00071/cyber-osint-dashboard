from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion.services.cisa_kev_reconciliation_service import (
    MAX_CATALOG_METADATA_LENGTH,
    CisaKevCatalogValidationError,
    CisaKevReconciliationPersistenceError,
    CisaKevReconciliationRecord,
    CisaKevReconciliationResult,
    CisaKevReconciliationService,
    validate_complete_cisa_kev_catalog,
)
from app.models import Vulnerability


CHECKED_AT = datetime(2026, 7, 23, 9, 30, tzinfo=UTC)
LATER = datetime(2026, 7, 23, 10, 30, tzinfo=UTC)


def entry(cve_id: str, *, action: str = "Apply updates.") -> dict[str, str]:
    return {
        "cveID": cve_id,
        "vendorProject": "Vendor",
        "product": "Product",
        "vulnerabilityName": "Example Vulnerability",
        "dateAdded": "2026-07-01",
        "shortDescription": "Safe public description.",
        "requiredAction": action,
        "dueDate": "2026-07-22",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "Safe notes.",
    }


def catalog(*entries: dict[str, str], count: int | None = None) -> dict[str, Any]:
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.07.23",
        "dateReleased": "2026-07-23T08:00:00Z",
        "count": len(entries) if count is None else count,
        "vulnerabilities": list(entries),
    }


class RowsResult:
    def __init__(self, rows: list[Any]):
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows

    def scalars(self) -> RowsResult:
        return self


class FakeSession:
    def __init__(
        self,
        rows: list[tuple[object, str | None]],
        *,
        fail_flush: int | None = None,
    ):
        self.rows = rows
        self.fail_flush = fail_flush
        self.flushes = 0
        self.commits = 0
        self.rollbacks = 0
        self.limits: list[int] = []
        self.identifier_query_count = 0
        self.identifier_query_sql: list[str] = []
        self._selected_item_ids: set[int] = set()

    def execute(self, statement: Any) -> RowsResult:
        if statement.column_descriptions[0]["expr"] is not Vulnerability:
            self.identifier_query_count += 1
            self.identifier_query_sql.append(str(statement))
            return RowsResult(
                [
                    (getattr(row[0], "intelligence_item_id"), row[1])
                    for row in self.rows
                    if row[1] is not None
                    and getattr(row[0], "intelligence_item_id")
                    in self._selected_item_ids
                ]
            )

        after_id = 0
        for criterion in statement._where_criteria:
            if getattr(getattr(criterion, "left", None), "name", None) == "id":
                after_id = criterion.right.value
        limit = statement._limit_clause.value
        self.limits.append(limit)
        vulnerabilities_by_id = {
            getattr(row[0], "id"): row[0]
            for row in self.rows
            if getattr(row[0], "id") > after_id
        }
        selected = [
            vulnerabilities_by_id[row_id]
            for row_id in sorted(vulnerabilities_by_id)[:limit]
        ]
        self._selected_item_ids = {
            getattr(vulnerability, "intelligence_item_id")
            for vulnerability in selected
        }
        return RowsResult(selected)

    def flush(self) -> None:
        self.flushes += 1
        if self.fail_flush == self.flushes:
            raise SQLAlchemyError(
                "postgresql://private-user:private-password@private-host/db"
            )

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def vulnerability(row_id: int, status: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=row_id,
        intelligence_item_id=1000 + row_id,
        kev_status=status,
        kev_last_checked_at=None,
        severity="critical",
        cvss_score=Decimal("9.8"),
        cvss_vector="CVSS:3.1/AV:N",
        cvss_version="3.1",
        epss_score=Decimal("0.900000"),
        epss_percentile=Decimal("0.990000"),
        affected_summary="preserve this",
        analyst_review_status="reviewed",
        uae_relevance_status="confirmed",
    )


def test_complete_catalog_normalizes_case_and_exact_duplicates() -> None:
    duplicated = entry("cve-2026-1001")

    validated = validate_complete_cisa_kev_catalog(
        catalog(duplicated, dict(duplicated))
    )

    assert validated.raw_record_count == 2
    assert validated.cve_count == 1
    assert validated.cve_ids == frozenset({"CVE-2026-1001"})
    assert validated.date_released == datetime(2026, 7, 23, 8, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "catalog_version",
    ["2026.07.23", "v1", "V1_2-rc.3", "A" * MAX_CATALOG_METADATA_LENGTH],
)
def test_catalog_version_accepts_only_bounded_safe_ascii_tokens(
    catalog_version: str,
) -> None:
    payload = dict(catalog(entry("CVE-2026-1001")), catalogVersion=catalog_version)

    validated = validate_complete_cisa_kev_catalog(payload)

    assert validated.catalog_version == catalog_version


@pytest.mark.parametrize(
    "catalog_version",
    [
        "",
        "2026.07.23\n",
        "2026.07.23\r",
        "2026.07.23\t",
        "2026. 07.23",
        "2026.07.23;raw-records:1",
        "2026:07:23",
        "2026.07.23\u202e",
        "2026.07.23\u200e",
        "é",
        "A" * (MAX_CATALOG_METADATA_LENGTH + 1),
    ],
)
def test_catalog_version_rejects_unsafe_or_oversized_values(
    catalog_version: str,
) -> None:
    payload = dict(catalog(entry("CVE-2026-1001")), catalogVersion=catalog_version)

    with pytest.raises(CisaKevCatalogValidationError):
        validate_complete_cisa_kev_catalog(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"catalogVersion": "1", "dateReleased": "2026-07-23T08:00:00Z", "count": 1},
        catalog(),
        catalog(entry("CVE-2026-1001"), count=2),
        catalog(entry("not-a-cve")),
        dict(catalog(entry("CVE-2026-1001")), catalogVersion=""),
        dict(catalog(entry("CVE-2026-1001")), dateReleased="not-a-date"),
    ],
)
def test_incomplete_malformed_or_empty_catalog_is_rejected(
    payload: dict[str, Any],
) -> None:
    with pytest.raises(
        CisaKevCatalogValidationError,
        match="failed complete validation",
    ):
        validate_complete_cisa_kev_catalog(payload)


def test_conflicting_duplicate_catalog_cve_is_rejected() -> None:
    with pytest.raises(CisaKevCatalogValidationError):
        validate_complete_cisa_kev_catalog(
            catalog(
                entry("CVE-2026-1001"),
                entry("CVE-2026-1001", action="Use a different mitigation."),
            )
        )


def test_all_status_transitions_are_reconciled_in_multiple_batches() -> None:
    vulnerabilities = [
        vulnerability(1, "unknown"),
        vulnerability(2, "unknown"),
        vulnerability(3, "listed"),
        vulnerability(4, "not_listed"),
        vulnerability(5, "listed"),
        vulnerability(6, "not_listed"),
    ]
    original_fields = [
        (
            item.severity,
            item.cvss_score,
            item.cvss_vector,
            item.cvss_version,
            item.epss_score,
            item.epss_percentile,
            item.affected_summary,
            item.analyst_review_status,
            item.uae_relevance_status,
        )
        for item in vulnerabilities
    ]
    rows = [
        (vulnerabilities[0], "CVE-2026-1001"),
        (vulnerabilities[1], "CVE-2026-1002"),
        (vulnerabilities[2], "CVE-2026-1003"),
        (vulnerabilities[3], "CVE-2026-1004"),
        (vulnerabilities[4], "CVE-2026-1005"),
        (vulnerabilities[5], "CVE-2026-1006"),
    ]
    session = FakeSession(rows)

    result = CisaKevReconciliationService(session).reconcile(  # type: ignore[arg-type]
        {"CVE-2026-1001", "CVE-2026-1004", "CVE-2026-1005"},
        max_cves=6,
        batch_size=2,
        checked_at=CHECKED_AT,
    )

    assert [item.kev_status for item in vulnerabilities] == [
        "listed",
        "not_listed",
        "not_listed",
        "listed",
        "listed",
        "not_listed",
    ]
    assert all(item.kev_last_checked_at == CHECKED_AT for item in vulnerabilities)
    assert result.inspected == 6
    assert result.listed == 3
    assert result.not_listed == 3
    assert result.updated == 4
    assert result.unchanged == 2
    assert result.skipped == 0
    assert result.failed == 0
    assert result.unknown_remaining == 0
    assert session.limits == [2, 2, 2]
    assert session.flushes == 3
    assert session.commits == 0
    assert session.rollbacks == 0
    assert original_fields == [
        (
            item.severity,
            item.cvss_score,
            item.cvss_vector,
            item.cvss_version,
            item.epss_score,
            item.epss_percentile,
            item.affected_summary,
            item.analyst_review_status,
            item.uae_relevance_status,
        )
        for item in vulnerabilities
    ]


def test_second_run_is_idempotent_except_for_checked_timestamp_refresh() -> None:
    first = vulnerability(1, "unknown")
    second = vulnerability(2, "unknown")
    session = FakeSession(
        [(first, "CVE-2026-1001"), (second, "CVE-2026-1002")]
    )
    service = CisaKevReconciliationService(session)  # type: ignore[arg-type]

    initial = service.reconcile(
        {"CVE-2026-1001"},
        max_cves=2,
        batch_size=2,
        checked_at=CHECKED_AT,
    )
    repeated = service.reconcile(
        {"CVE-2026-1001"},
        max_cves=2,
        batch_size=2,
        checked_at=LATER,
    )

    assert initial.updated == 2
    assert repeated.updated == 0
    assert repeated.unchanged == 2
    assert first.kev_last_checked_at == LATER
    assert second.kev_last_checked_at == LATER


def test_local_limit_applies_to_local_rows_not_catalog_size() -> None:
    rows = [
        (vulnerability(index, "unknown"), f"CVE-2026-{1000 + index}")
        for index in range(1, 6)
    ]
    session = FakeSession(rows)

    result = CisaKevReconciliationService(session).reconcile(  # type: ignore[arg-type]
        {f"CVE-2026-{index}" for index in range(1001, 1101)},
        max_cves=2,
        batch_size=100,
        checked_at=CHECKED_AT,
    )

    assert result.inspected == 2
    assert result.updated == 2
    assert rows[2][0].kev_status == "unknown"
    assert session.limits == [2]


@pytest.mark.parametrize(
    ("status", "expected_unknown_remaining"),
    [("unknown", 1), ("listed", 0), ("not_listed", 0)],
)
@pytest.mark.parametrize("reverse_identifiers", [False, True])
def test_ambiguous_global_cve_identity_is_skipped_once_regardless_of_order(
    status: str,
    expected_unknown_remaining: int,
    reverse_identifiers: bool,
) -> None:
    ambiguous = vulnerability(1, status)
    original_checked_at = ambiguous.kev_last_checked_at
    identifiers = ["CVE-2026-1001", "CVE-2026-1002"]
    if reverse_identifiers:
        identifiers.reverse()
    session = FakeSession([(ambiguous, value) for value in identifiers])

    result = CisaKevReconciliationService(session).reconcile(  # type: ignore[arg-type]
        {"CVE-2026-1001"},
        max_cves=1,
        batch_size=1,
        checked_at=CHECKED_AT,
    )

    assert result.inspected == 1
    assert result.skipped == 1
    assert result.updated == 0
    assert result.unchanged == 0
    assert result.unknown_remaining == expected_unknown_remaining
    assert len(result.records) == 1
    assert result.records[0].outcome == "skipped"
    assert result.records[0].cve_id is None
    assert result.records[0].safe_detail == (
        "Local vulnerability skipped because it has ambiguous global CVE identity."
    )
    assert all(value not in result.records[0].safe_detail for value in identifiers)
    assert ambiguous.kev_status == status
    assert ambiguous.kev_last_checked_at == original_checked_at
    assert session.limits == [1]
    assert session.identifier_query_count == 1


def test_max_cves_and_batches_count_unique_vulnerabilities_not_identifier_rows() -> None:
    ambiguous = vulnerability(1, "unknown")
    second = vulnerability(2, "unknown")
    third = vulnerability(3, "unknown")
    session = FakeSession(
        [
            (ambiguous, "CVE-2026-1001"),
            (ambiguous, "CVE-2026-1002"),
            (second, "CVE-2026-1003"),
            (third, "CVE-2026-1004"),
        ]
    )

    result = CisaKevReconciliationService(session).reconcile(  # type: ignore[arg-type]
        {"CVE-2026-1003", "CVE-2026-1004"},
        max_cves=3,
        batch_size=1,
        checked_at=CHECKED_AT,
    )

    assert result.inspected == 3
    assert result.skipped == 1
    assert result.updated == 2
    assert [record.vulnerability_id for record in result.records] == [1, 2, 3]
    assert ambiguous.kev_status == "unknown"
    assert second.kev_status == "listed"
    assert third.kev_status == "listed"
    assert session.limits == [1, 1, 1]
    assert session.identifier_query_count == 3
    assert all(
        "intelligence_item_identifiers.source_id IS NULL" in statement
        and "intelligence_item_identifiers.namespace" in statement
        for statement in session.identifier_query_sql
    )


@pytest.mark.parametrize(
    ("status", "expected_unknown_remaining"),
    [
        ("unknown", 1),
        ("listed", 0),
        ("not_listed", 0),
    ],
)
def test_skipped_row_counts_unknown_only_when_status_remains_unknown(
    status: str,
    expected_unknown_remaining: int,
) -> None:
    skipped = vulnerability(1, status)
    session = FakeSession([(skipped, None)])

    result = CisaKevReconciliationService(session).reconcile(  # type: ignore[arg-type]
        {"CVE-2026-1001"},
        max_cves=1,
        batch_size=1,
        checked_at=CHECKED_AT,
    )

    assert result.inspected == 1
    assert result.skipped == 1
    assert result.updated == 0
    assert result.unknown_remaining == expected_unknown_remaining
    assert skipped.kev_status == status
    assert skipped.kev_last_checked_at is None
    assert all(record.cve_id is None for record in result.records)


def test_mixed_valid_and_skipped_rows_reconcile_all_counters() -> None:
    valid_listed = vulnerability(1, "unknown")
    skipped_unknown = vulnerability(2, "unknown")
    skipped_listed = vulnerability(3, "listed")
    valid_not_listed = vulnerability(4, "not_listed")
    session = FakeSession(
        [
            (valid_listed, "CVE-2026-1001"),
            (skipped_unknown, None),
            (skipped_listed, "private-value"),
            (valid_not_listed, "CVE-2026-1004"),
        ]
    )

    result = CisaKevReconciliationService(session).reconcile(  # type: ignore[arg-type]
        {"CVE-2026-1001"},
        max_cves=4,
        batch_size=2,
        checked_at=CHECKED_AT,
    )

    assert result.inspected == 4
    assert result.listed == 1
    assert result.not_listed == 1
    assert result.updated == 1
    assert result.unchanged == 1
    assert result.skipped == 2
    assert result.failed == 0
    assert result.unknown_remaining == 1
    assert result.inspected == (
        result.updated + result.unchanged + result.skipped + result.failed
    )
    assert result.listed + result.not_listed == result.updated + result.unchanged
    assert len(result.records) == result.inspected
    assert valid_listed.kev_last_checked_at == CHECKED_AT
    assert valid_not_listed.kev_last_checked_at == CHECKED_AT
    assert skipped_unknown.kev_last_checked_at is None
    assert skipped_listed.kev_last_checked_at is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"inspected": -1},
        {"listed": 1},
        {"unknown_remaining": 2},
        {"records": ()},
    ],
)
def test_reconciliation_result_rejects_broken_counter_invariants(
    overrides: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "inspected": 1,
        "listed": 0,
        "not_listed": 0,
        "updated": 0,
        "unchanged": 0,
        "skipped": 1,
        "failed": 0,
        "unknown_remaining": 1,
        "records": (
            CisaKevReconciliationRecord(
                vulnerability_id=1,
                intelligence_item_id=1001,
                cve_id=None,
                target_status=None,
                outcome="skipped",
                safe_detail="Safe skipped row.",
            ),
        ),
    }
    values.update(overrides)

    with pytest.raises(ValueError):
        CisaKevReconciliationResult(**values)  # type: ignore[arg-type]


def test_database_failure_is_sanitized_and_service_never_owns_rollback() -> None:
    session = FakeSession(
        [(vulnerability(1, "unknown"), "CVE-2026-1001")],
        fail_flush=1,
    )

    with pytest.raises(
        CisaKevReconciliationPersistenceError,
        match="database error",
    ) as captured:
        CisaKevReconciliationService(session).reconcile(  # type: ignore[arg-type]
            {"CVE-2026-1001"},
            max_cves=1,
            batch_size=1,
            checked_at=CHECKED_AT,
        )

    assert "private" not in str(captured.value)
    assert session.commits == 0
    assert session.rollbacks == 0
