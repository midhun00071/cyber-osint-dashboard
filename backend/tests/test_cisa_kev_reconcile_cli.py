from __future__ import annotations

from datetime import UTC, datetime
from io import StringIO
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion import cisa_kev_reconcile_cli
from app.ingestion.collectors.cisa_kev_client import (
    CISA_KEV_CATALOG_URL,
    CisaKevFetchResult,
    CisaKevHttpError,
    CisaKevRequestError,
    CisaKevResponseTooLargeError,
)
from app.ingestion.services.cisa_kev_reconciliation_service import (
    CisaKevReconciliationRecord,
    CisaKevReconciliationResult,
    ValidatedCisaKevCatalog,
)
from app.models import (
    IngestionError,
    IngestionRun,
    IngestionRunRecord,
    IntelligenceSource,
)


STARTED_AT = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
CHECKED_AT = datetime(2026, 7, 23, 12, 1, tzinfo=UTC)
COMPLETED_AT = datetime(2026, 7, 23, 12, 2, tzinfo=UTC)
FAILURE_COMPLETED_AT = datetime(2026, 7, 23, 12, 3, tzinfo=UTC)
VALID_CATALOG = {
    "catalogVersion": "2026.07.23",
    "dateReleased": "2026-07-23T11:00:00Z",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-1001",
            "vendorProject": "Vendor",
            "product": "Product",
            "vulnerabilityName": "Example Vulnerability",
            "dateAdded": "2026-07-01",
            "shortDescription": "Safe public description.",
            "requiredAction": "Apply updates.",
            "dueDate": "2026-07-22",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "Safe notes.",
        }
    ],
}


class FakeClient:
    def __init__(
        self,
        *,
        catalog: dict[str, Any] | None = None,
        error: Exception | None = None,
    ):
        self.catalog = catalog or VALID_CATALOG
        self.error = error
        self.fetches = 0
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.closed = True

    def fetch_catalog(self) -> CisaKevFetchResult:
        self.fetches += 1
        if self.error is not None:
            raise self.error
        return CisaKevFetchResult(
            catalog=self.catalog,
            source_url=CISA_KEV_CATALOG_URL,
            final_url=CISA_KEV_CATALOG_URL,
            content_type="application/json",
            byte_count=1024,
        )


class FakeSession:
    def __init__(self, *, fail_commit: bool = False):
        self.fail_commit = fail_commit
        self.added: list[object] = []
        self.flushes = 0
        self.commits = 0
        self.rollbacks = 0
        self.closed = False
        self.restore_target: SimpleNamespace | None = None
        self.restore_status: str | None = None

    def add(self, value: object) -> None:
        self.added.append(value)

    def flush(self) -> None:
        self.flushes += 1
        for value in self.added:
            if isinstance(value, IngestionRun) and getattr(value, "id", None) is None:
                value.id = 1
                value.public_id = uuid4()

    def commit(self) -> None:
        if self.fail_commit:
            raise SQLAlchemyError(
                "postgresql://private-user:private-password@private-host/db"
            )
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1
        if self.restore_target is not None:
            self.restore_target.kev_status = self.restore_status

    def close(self) -> None:
        self.closed = True


class FakeSourceService:
    def __init__(self, session: FakeSession):
        del session
        self.source = IntelligenceSource(
            slug="cisa-kev",
            name="CISA Known Exploited Vulnerabilities Catalog",
            source_type="json",
            base_url=CISA_KEV_CATALOG_URL,
            is_enabled=True,
            checkpoint_value="existing-checkpoint",
        )

    def ensure_source(self) -> IntelligenceSource:
        return self.source


def reconciliation_result() -> CisaKevReconciliationResult:
    return CisaKevReconciliationResult(
        inspected=2,
        listed=1,
        not_listed=1,
        updated=1,
        unchanged=1,
        skipped=0,
        failed=0,
        unknown_remaining=0,
        records=(
            CisaKevReconciliationRecord(
                1,
                101,
                "CVE-2026-1001",
                "listed",
                "updated",
                "Local CVE reconciliation updated; KEV status is listed.",
            ),
            CisaKevReconciliationRecord(
                2,
                102,
                "CVE-2026-1002",
                "not_listed",
                "unchanged",
                "Local CVE reconciliation unchanged; KEV status is not_listed.",
            ),
        ),
    )


def skipped_reconciliation_result(
    *,
    unknown_remaining: int,
) -> CisaKevReconciliationResult:
    clean = reconciliation_result()
    return CisaKevReconciliationResult(
        inspected=3,
        listed=clean.listed,
        not_listed=clean.not_listed,
        updated=clean.updated,
        unchanged=clean.unchanged,
        skipped=1,
        failed=0,
        unknown_remaining=unknown_remaining,
        records=(
            *clean.records,
            CisaKevReconciliationRecord(
                3,
                103,
                None,
                None,
                "skipped",
                "Local vulnerability has no usable global CVE identifier.",
            ),
        ),
    )


class FakeReconciliationService:
    def __init__(
        self,
        session: FakeSession,
        *,
        result: CisaKevReconciliationResult | None = None,
    ):
        self.session = session
        self.result = result or reconciliation_result()
        self.calls: list[dict[str, object]] = []

    def reconcile(
        self,
        catalog_cve_ids: frozenset[str],
        *,
        max_cves: int,
        batch_size: int,
        checked_at: datetime,
    ) -> CisaKevReconciliationResult:
        self.calls.append(
            {
                "catalog_cve_ids": catalog_cve_ids,
                "max_cves": max_cves,
                "batch_size": batch_size,
                "checked_at": checked_at,
            }
        )
        return self.result


class ReconciliationFactory:
    def __init__(self, result: CisaKevReconciliationResult | None = None):
        self.service: FakeReconciliationService | None = None
        self.result = result

    def __call__(self, session: FakeSession) -> FakeReconciliationService:
        self.service = FakeReconciliationService(session, result=self.result)
        return self.service


def sequence_clock(*values: object):
    remaining = iter(values)

    def read() -> datetime:
        value = next(remaining)
        if isinstance(value, Exception):
            raise value
        return value  # type: ignore[return-value]

    return read


def run_fake(
    *,
    session: FakeSession | None = None,
    client: FakeClient | None = None,
    max_cves: int = 500,
    batch_size: int = 100,
    result: CisaKevReconciliationResult | None = None,
    clock_values: tuple[object, ...] = (STARTED_AT, CHECKED_AT, COMPLETED_AT),
):
    fake_session = session or FakeSession()
    fake_client = client or FakeClient()
    factory = ReconciliationFactory(result)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = cisa_kev_reconcile_cli.run_reconciliation(
        max_cves=max_cves,
        batch_size=batch_size,
        clock=sequence_clock(*clock_values),
        client_factory=lambda: fake_client,  # type: ignore[arg-type]
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        source_service_factory=FakeSourceService,  # type: ignore[arg-type]
        reconciliation_service_factory=factory,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    return (
        exit_code,
        stdout.getvalue(),
        stderr.getvalue(),
        fake_session,
        fake_client,
        factory,
    )


@pytest.mark.parametrize(
    ("argument", "valid_values", "invalid_values"),
    [
        ("--max-cves", ["1", "500"], ["0", "-1", "501", "bad", "true"]),
        ("--batch-size", ["1", "100"], ["0", "-1", "101", "bad", "false"]),
    ],
)
def test_cli_argument_bounds(
    monkeypatch,
    argument: str,
    valid_values: list[str],
    invalid_values: list[str],
    capsys,
) -> None:
    monkeypatch.setattr(
        cisa_kev_reconcile_cli,
        "run_reconciliation",
        lambda **kwargs: 0,
    )

    for value in valid_values:
        assert cisa_kev_reconcile_cli.main([argument, value, "--plan"]) == 0
    for value in invalid_values:
        assert cisa_kev_reconcile_cli.main([argument, value, "--plan"]) == 2
        assert (
            "Invalid manual CISA KEV reconciliation arguments."
            in capsys.readouterr().err
        )


@pytest.mark.parametrize(
    ("max_cves", "batch_size"),
    [(True, 100), (500, False), (0, 100), (500, 101)],
)
def test_direct_argument_validation_runs_before_factories(
    max_cves: object,
    batch_size: object,
) -> None:
    stderr = StringIO()

    exit_code = cisa_kev_reconcile_cli.run_reconciliation(
        max_cves=max_cves,  # type: ignore[arg-type]
        batch_size=batch_size,  # type: ignore[arg-type]
        clock=lambda: pytest.fail("clock must not run"),
        client_factory=lambda: pytest.fail("client must not run"),
        session_factory=lambda: pytest.fail("session must not run"),
        stderr=stderr,
    )

    assert exit_code == 2
    assert stderr.getvalue() == (
        "Invalid manual CISA KEV reconciliation parameters.\n"
    )


def test_plan_mode_has_no_clock_network_or_database_access() -> None:
    stdout = StringIO()

    exit_code = cisa_kev_reconcile_cli.run_reconciliation(
        max_cves=500,
        batch_size=100,
        plan=True,
        clock=lambda: pytest.fail("clock must not run"),
        client_factory=lambda: pytest.fail("client must not run"),
        session_factory=lambda: pytest.fail("session must not run"),
        stdout=stdout,
    )

    assert exit_code == 0
    assert "Approved source: cisa-kev" in stdout.getvalue()
    assert CISA_KEV_CATALOG_URL in stdout.getvalue()
    assert "Local CVE limit: 500" in stdout.getvalue()
    assert "Database batch size: 100" in stdout.getvalue()
    assert "Network access: none" in stdout.getvalue()
    assert "Database access: none" in stdout.getvalue()


def test_success_commits_one_transaction_and_records_safe_counts() -> None:
    exit_code, stdout, stderr, session, client, factory = run_fake()

    run = next(value for value in session.added if isinstance(value, IngestionRun))
    records = [
        value for value in session.added if isinstance(value, IngestionRunRecord)
    ]
    assert exit_code == 0
    assert isinstance(run.public_id, UUID)
    assert run.status == "succeeded"
    assert run.started_at == STARTED_AT
    assert run.completed_at == COMPLETED_AT
    assert run.started_at.tzinfo is not None
    assert run.started_at.utcoffset() is not None
    assert run.completed_at.tzinfo is not None
    assert run.completed_at.utcoffset() is not None
    assert run.completed_at >= run.started_at
    assert run.records_fetched == 2
    assert run.records_created == 0
    assert run.records_updated == 1
    assert run.records_unchanged == 1
    assert run.records_skipped == 0
    assert run.records_failed == 0
    assert run.records_fetched == (
        run.records_created
        + run.records_updated
        + run.records_unchanged
        + run.records_skipped
        + run.records_failed
    )
    assert len(records) == 2
    assert {record.action for record in records} == {
        "updated",
        "unchanged",
    }
    assert all(record.processed_at == CHECKED_AT for record in records)
    assert run.checkpoint_before == "existing-checkpoint"
    assert run.checkpoint_after == (
        "catalog-version:2026.07.23;raw-records:1;unique-cves:1"
    )
    assert "catalog_version=2026.07.23" in run.safe_summary
    assert "catalog_raw_records=1" in run.safe_summary
    assert "catalog_unique_cves=1" in run.safe_summary
    assert "listed=1" in run.safe_summary
    assert "not_listed=1" in run.safe_summary
    assert "full_catalog_validated=true" in run.safe_summary
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed
    assert client.closed
    assert factory.service.calls == [
        {
            "catalog_cve_ids": frozenset({"CVE-2026-1001"}),
            "max_cves": 500,
            "batch_size": 100,
            "checked_at": CHECKED_AT,
        }
    ]
    checked_at = factory.service.calls[0]["checked_at"]
    assert isinstance(checked_at, datetime)
    assert checked_at.tzinfo is not None
    assert checked_at.utcoffset() is not None
    assert checked_at >= run.started_at
    assert "Status: succeeded" in stdout
    assert "Catalog version: 2026.07.23" in stdout
    assert "Catalog raw record count: 1" in stdout
    assert "Catalog unique CVE count: 1" in stdout
    assert "Local CVEs inspected: 2" in stdout
    assert "Unknown remaining in processed set: 0" in stdout
    assert "Full catalog validated: true" in stdout
    assert stderr == ""


def test_catalog_raw_and_unique_counts_are_separate_from_local_counters() -> None:
    duplicated_catalog = dict(
        VALID_CATALOG,
        count=2,
        vulnerabilities=[
            VALID_CATALOG["vulnerabilities"][0],
            dict(VALID_CATALOG["vulnerabilities"][0]),
        ],
    )

    exit_code, stdout, _, session, _, _ = run_fake(
        client=FakeClient(catalog=duplicated_catalog)
    )

    run = next(value for value in session.added if isinstance(value, IngestionRun))
    assert exit_code == 0
    assert run.records_fetched == 2
    assert "catalog_raw_records=2" in run.safe_summary
    assert "catalog_unique_cves=1" in run.safe_summary
    assert run.checkpoint_after == (
        "catalog-version:2026.07.23;raw-records:2;unique-cves:1"
    )
    assert "Catalog raw record count: 2" in stdout
    assert "Catalog unique CVE count: 1" in stdout
    assert "Local CVEs inspected: 2" in stdout


def test_skipped_unknown_is_controlled_partial_and_commits_safe_results() -> None:
    result = skipped_reconciliation_result(unknown_remaining=1)

    exit_code, stdout, stderr, session, _, _ = run_fake(result=result)

    run = next(value for value in session.added if isinstance(value, IngestionRun))
    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 3
    assert run.records_created == 0
    assert run.records_updated == 1
    assert run.records_unchanged == 1
    assert run.records_skipped == 1
    assert run.records_failed == 0
    assert run.records_fetched == (
        run.records_created
        + run.records_updated
        + run.records_unchanged
        + run.records_skipped
        + run.records_failed
    )
    assert "unknown_remaining=1" in run.safe_summary
    assert session.commits == 1
    assert session.rollbacks == 0
    assert "Status: partial" in stdout
    assert "Unknown remaining in processed set: 1" in stdout
    assert "Controlled partial result:" in stdout
    assert stderr == ""


@pytest.mark.parametrize(
    "error",
    [
        CisaKevRequestError("timeout with API_KEY=private-value"),
        CisaKevHttpError("HTTP failure with bearer private-value"),
        CisaKevResponseTooLargeError("oversized private-value"),
    ],
)
def test_fetch_failures_are_sanitized_audited_and_never_reconcile_local_rows(
    error: Exception,
) -> None:
    stdout = StringIO()
    stderr = StringIO()
    client = FakeClient(error=error)
    session = FakeSession()

    exit_code = cisa_kev_reconcile_cli.run_reconciliation(
        max_cves=500,
        batch_size=100,
        clock=sequence_clock(STARTED_AT, FAILURE_COMPLETED_AT),
        client_factory=lambda: client,  # type: ignore[arg-type]
        session_factory=lambda: session,  # type: ignore[arg-type]
        source_service_factory=FakeSourceService,  # type: ignore[arg-type]
        reconciliation_service_factory=lambda session: pytest.fail(
            "reconciliation service must not run"
        ),
        stdout=stdout,
        stderr=stderr,
    )

    run = next(value for value in session.added if isinstance(value, IngestionRun))
    audit_error = next(
        value for value in session.added if isinstance(value, IngestionError)
    )
    assert exit_code == 1
    assert client.closed
    assert isinstance(run.public_id, UUID)
    assert run.status == "failed"
    assert run.started_at == STARTED_AT
    assert run.completed_at == FAILURE_COMPLETED_AT
    assert run.records_fetched == 0
    assert run.records_failed == 0
    assert run.records_updated == 0
    assert run.records_fetched == (
        run.records_created
        + run.records_updated
        + run.records_unchanged
        + run.records_skipped
        + run.records_failed
    )
    assert audit_error.error_type == "cisa_kev_catalog_fetch_error"
    assert audit_error.occurred_at == FAILURE_COMPLETED_AT
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed
    assert "Status: failed" in stdout.getvalue()
    assert "Run ID: not-created" not in stdout.getvalue()
    assert "Full catalog validated: false" in stdout.getvalue()
    assert "Not listed: 0" in stdout.getvalue()
    assert "private-value" not in stdout.getvalue()
    assert "private-value" not in stderr.getvalue()
    assert "catalog fetch did not complete safely" in stderr.getvalue()


def test_incomplete_catalog_makes_no_local_writes() -> None:
    incomplete = dict(VALID_CATALOG, count=2)
    client = FakeClient(catalog=incomplete)
    stdout = StringIO()
    stderr = StringIO()
    session = FakeSession()

    exit_code = cisa_kev_reconcile_cli.run_reconciliation(
        max_cves=500,
        batch_size=100,
        clock=sequence_clock(STARTED_AT, FAILURE_COMPLETED_AT),
        client_factory=lambda: client,  # type: ignore[arg-type]
        session_factory=lambda: session,  # type: ignore[arg-type]
        source_service_factory=FakeSourceService,  # type: ignore[arg-type]
        reconciliation_service_factory=lambda session: pytest.fail(
            "reconciliation service must not run"
        ),
        stdout=stdout,
        stderr=stderr,
    )

    run = next(value for value in session.added if isinstance(value, IngestionRun))
    audit_error = next(
        value for value in session.added if isinstance(value, IngestionError)
    )
    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_fetched == 0
    assert run.records_updated == 0
    assert run.records_unchanged == 0
    assert audit_error.error_type == "cisa_kev_catalog_validation_error"
    assert session.commits == 1
    assert "Full catalog validated: false" in stdout.getvalue()
    assert "Not listed: 0" in stdout.getvalue()
    assert "failed complete validation" in stderr.getvalue()


@pytest.mark.parametrize(
    "clock_value",
    [
        datetime(2026, 7, 23, 12, 0),
        "private-value",
        RuntimeError("private-value"),
    ],
)
def test_invalid_initial_clock_is_sanitized_before_external_access(
    clock_value: object,
) -> None:
    client = FakeClient()
    session = FakeSession()
    stderr = StringIO()

    exit_code = cisa_kev_reconcile_cli.run_reconciliation(
        max_cves=500,
        batch_size=100,
        clock=sequence_clock(clock_value),
        client_factory=lambda: client,  # type: ignore[arg-type]
        session_factory=lambda: session,  # type: ignore[arg-type]
        stdout=StringIO(),
        stderr=stderr,
    )

    assert exit_code == 1
    assert client.fetches == 0
    assert session.added == []
    assert "valid timezone-aware workflow timestamps" in stderr.getvalue()
    assert "private-value" not in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()


@pytest.mark.parametrize(
    "clock_values",
    [
        (STARTED_AT, datetime(2026, 7, 23, 12, 1)),
        (STARTED_AT, STARTED_AT.replace(minute=59, hour=11)),
        (STARTED_AT, CHECKED_AT, STARTED_AT),
        (STARTED_AT, CHECKED_AT, "private-value"),
    ],
)
def test_invalid_staged_clock_rolls_back_with_sanitized_output(
    clock_values: tuple[object, ...],
) -> None:
    exit_code, stdout, stderr, session, client, _ = run_fake(
        clock_values=clock_values
    )

    assert exit_code == 1
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed
    assert client.closed
    assert stdout == ""
    assert "valid timezone-aware workflow timestamps" in stderr
    assert "private-value" not in stderr
    assert "Traceback" not in stderr
    assert "database operation" not in stderr
    assert "unexpectedly" not in stderr


def test_commit_failure_rolls_back_all_reconciliation_changes() -> None:
    session = FakeSession(fail_commit=True)
    local = SimpleNamespace(kev_status="unknown")
    session.restore_target = local
    session.restore_status = "unknown"

    class MutatingService(FakeReconciliationService):
        def reconcile(self, *args: object, **kwargs: object):
            local.kev_status = "not_listed"
            return reconciliation_result()

    exit_code = cisa_kev_reconcile_cli.run_reconciliation(
        max_cves=500,
        batch_size=100,
        clock=sequence_clock(STARTED_AT, CHECKED_AT, COMPLETED_AT),
        client_factory=lambda: FakeClient(),  # type: ignore[arg-type]
        session_factory=lambda: session,  # type: ignore[arg-type]
        source_service_factory=FakeSourceService,  # type: ignore[arg-type]
        reconciliation_service_factory=MutatingService,  # type: ignore[arg-type]
        stdout=StringIO(),
        stderr=(stderr := StringIO()),
    )

    assert exit_code == 1
    assert local.kev_status == "unknown"
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed
    assert "database operation" in stderr.getvalue()
    assert "private" not in stderr.getvalue()
