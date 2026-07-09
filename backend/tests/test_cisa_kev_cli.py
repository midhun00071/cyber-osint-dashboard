from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from io import StringIO
from uuid import UUID, uuid4

import pytest

from app.ingestion import cisa_kev_cli
from app.ingestion.collectors.cisa_kev_client import (
    CISA_KEV_CATALOG_URL,
    CisaKevFetchResult,
    CisaKevRateLimitError,
    CisaKevRedirectError,
    CisaKevRequestError,
)
from app.ingestion.normalizers.cisa_kev import (
    CisaKevNormalizationError,
    normalize_cisa_kev_entry,
)
from app.ingestion.services.cisa_kev_ingestion_service import (
    CisaKevPersistenceError,
    CisaKevPersistenceResult,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord, IntelligenceSource


NOW = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)
CATALOG = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-0001",
            "vendorProject": "Vendor",
            "product": "Product",
            "vulnerabilityName": "Example Vulnerability",
            "dateAdded": "2026-07-08",
            "shortDescription": "Safe description.",
            "requiredAction": "Apply updates.",
            "dueDate": "2026-07-29",
            "knownRansomwareCampaignUse": "Known",
            "notes": "Safe notes.",
        }
    ]
}


class FakeSession:
    def __init__(self, *, fail_commit: bool = False):
        self.fail_commit = fail_commit
        self.added: list[object] = []
        self.commits = 0
        self.rollbacks = 0
        self.flushes = 0
        self.closed = False
        self.nested_transactions = 0

    def add(self, record: object) -> None:
        self.added.append(record)

    def flush(self) -> None:
        self.flushes += 1
        for record in self.added:
            if isinstance(record, IngestionRun) and getattr(record, "id", None) is None:
                record.id = 1
                record.public_id = uuid4()

    def begin_nested(self):
        self.nested_transactions += 1
        return nullcontext()

    def commit(self) -> None:
        if self.fail_commit:
            raise CisaKevPersistenceError("postgresql://private:password@host/db")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class FakeClient:
    def __init__(self, catalog: dict | None = None, error: Exception | None = None):
        self.catalog = catalog if catalog is not None else CATALOG
        self.error = error
        self.closed = False
        self.fetches = 0

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
            byte_count=128,
        )


class FakeService:
    def __init__(
        self,
        session: FakeSession,
        outcomes: list[str] | None = None,
        error: Exception | None = None,
    ):
        self.session = session
        self.outcomes = list(outcomes or ["created"])
        self.error = error
        self.enrich_calls: list[object] = []
        self.source = IntelligenceSource(
            slug="cisa-kev",
            name="CISA Known Exploited Vulnerabilities Catalog",
            source_type="json",
            base_url=CISA_KEV_CATALOG_URL,
            is_enabled=True,
            checkpoint_value="existing-checkpoint",
            last_successful_fetch_at=datetime(2026, 7, 9, 12, 0, tzinfo=UTC),
        )

    def ensure_source(self) -> IntelligenceSource:
        return self.source

    def enrich(self, normalized: object, *, observed_at: datetime):
        del observed_at
        self.enrich_calls.append(normalized)
        if self.error is not None:
            raise self.error
        outcome = self.outcomes.pop(0)
        cve_id = getattr(normalized, "cve_id")
        return CisaKevPersistenceResult(cve_id, outcome, None, None, 123)


class ServiceFactory:
    def __init__(self, outcomes: list[str] | None = None, error: Exception | None = None):
        self.outcomes = outcomes
        self.error = error
        self.service: FakeService | None = None

    def __call__(self, session: FakeSession) -> FakeService:
        self.service = FakeService(session, self.outcomes, self.error)
        return self.service


def run_fake(
    *,
    session: FakeSession | None = None,
    client: FakeClient | None = None,
    service_factory: ServiceFactory | None = None,
    catalog_entry_extractor=None,
    entry_normalizer=normalize_cisa_kev_entry,
    max_records: int = 25,
):
    fake_session = session or FakeSession()
    fake_client = client or FakeClient()
    services = service_factory or ServiceFactory()
    stdout = StringIO()
    stderr = StringIO()
    exit_code = cisa_kev_cli.run_ingestion(
        max_records=max_records,
        clock=lambda: NOW,
        client_factory=lambda: fake_client,  # type: ignore[arg-type]
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        catalog_entry_extractor=catalog_entry_extractor or cisa_kev_cli.extract_cisa_kev_entries,
        entry_normalizer=entry_normalizer,
        service_factory=services,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), fake_session, fake_client, services


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1", 0), ("500", 0), ("0", 2), ("501", 2), ("bad", 2)],
)
def test_cli_argument_bounds(monkeypatch, value: str, expected: int, capsys) -> None:
    monkeypatch.setattr(cisa_kev_cli, "run_ingestion", lambda **kwargs: 0)

    assert cisa_kev_cli.main(["--max-records", value]) == expected
    if expected == 2:
        assert "Invalid manual CISA KEV ingestion arguments." in capsys.readouterr().err


def test_direct_validation_rejects_values_before_factories() -> None:
    stderr = StringIO()

    exit_code = cisa_kev_cli.run_ingestion(
        max_records=True,  # type: ignore[arg-type]
        clock=lambda: pytest.fail("clock must not run"),
        client_factory=lambda: pytest.fail("client must not be created"),
        session_factory=lambda: pytest.fail("session must not be created"),
        stderr=stderr,
    )

    assert exit_code == 2
    assert stderr.getvalue() == "Invalid manual CISA KEV ingestion parameters.\n"


def test_successful_ingestion_creates_audit_and_commits() -> None:
    exit_code, stdout, stderr, session, client, _ = run_fake()

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert isinstance(run.public_id, UUID)
    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 1
    assert run.records_created == 1
    assert run.records_failed == 0
    assert run.checkpoint_after == "2026-07-10T12:00:00Z"
    assert run.source.checkpoint_value == "2026-07-10T12:00:00Z"
    assert run.source.last_successful_fetch_at == NOW
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed
    assert client.closed
    assert "Created: 1" in stdout
    assert "Capped: false" in stdout
    assert stderr == ""


def test_empty_catalog_succeeds_without_record_work() -> None:
    exit_code, _, stderr, session, _, services = run_fake(
        client=FakeClient({"vulnerabilities": []})
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 0
    assert services.service.enrich_calls == []
    assert stderr == ""


def test_exact_duplicate_kev_entry_is_processed_once() -> None:
    duplicate = {"vulnerabilities": [CATALOG["vulnerabilities"][0], CATALOG["vulnerabilities"][0]]}

    exit_code, _, _, session, _, services = run_fake(client=FakeClient(duplicate))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 0
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert len(services.service.enrich_calls) == 1


def test_conflicting_duplicate_kev_entry_fails_safely() -> None:
    second = dict(CATALOG["vulnerabilities"][0], requiredAction="Different action")
    catalog = {"vulnerabilities": [CATALOG["vulnerabilities"][0], second]}

    exit_code, stdout, stderr, session, _, services = run_fake(client=FakeClient(catalog))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    error = next(record for record in session.added if isinstance(record, IngestionError))
    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_failed == 1
    assert run.error_count == 1
    assert error.error_type == "cisa_kev_duplicate_conflict"
    assert services.service.enrich_calls == []
    assert "Different action" not in stdout
    assert "Different action" not in stderr


def test_entry_normalization_failure_is_isolated_and_commits_partial() -> None:
    invalid = dict(CATALOG["vulnerabilities"][0], cveID="private-invalid-cve")
    valid = dict(CATALOG["vulnerabilities"][0], cveID="CVE-2026-0002")
    catalog = {"vulnerabilities": [invalid, valid]}

    exit_code, stdout, stderr, session, _, services = run_fake(client=FakeClient(catalog))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    failed_records = [
        record
        for record in session.added
        if isinstance(record, IngestionRunRecord) and record.action == "failed"
    ]
    errors = [record for record in session.added if isinstance(record, IngestionError)]
    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_failed == 1
    assert run.checkpoint_after is None
    assert len(services.service.enrich_calls) == 1
    assert len(failed_records) == 1
    assert len(errors) == 1
    assert errors[0].error_type == "cisa_kev_normalization_error"
    assert "private-invalid-cve" not in stdout
    assert "private-invalid-cve" not in stderr
    assert "private-invalid-cve" not in errors[0].safe_message
    assert session.commits == 1
    assert session.rollbacks == 0


def test_catalog_normalization_failure_is_sanitized() -> None:
    marker = "private-catalog-fragment"

    def fail_extraction(value: dict):
        assert value["secret"] == marker
        raise CisaKevNormalizationError(marker)

    exit_code, stdout, stderr, session, _, _ = run_fake(
        client=FakeClient({"secret": marker}),
        catalog_entry_extractor=fail_extraction,
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    error = next(record for record in session.added if isinstance(record, IngestionError))
    assert exit_code == 1
    assert run.records_failed == 1
    assert error.error_type == "cisa_kev_normalization_error"
    assert marker not in stdout
    assert marker not in stderr
    assert marker not in error.safe_message


def test_persistence_failure_is_sanitized_and_committed_as_partial() -> None:
    marker = "postgresql://private:password@host/database"

    exit_code, stdout, stderr, session, _, _ = run_fake(
        service_factory=ServiceFactory(error=CisaKevPersistenceError(marker)),
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    error = next(record for record in session.added if isinstance(record, IngestionError))
    assert exit_code == 1
    assert run.status == "failed"
    assert session.commits == 1
    assert marker not in stdout
    assert marker not in stderr
    assert error.error_type == "cisa_kev_persistence_error"


@pytest.mark.parametrize(
    ("error", "expected_type", "retryable"),
    [
        (CisaKevRequestError("secret transport detail"), "cisa_kev_fetch_error", True),
        (CisaKevRateLimitError("secret rate detail"), "cisa_kev_rate_limit", True),
        (CisaKevRedirectError("secret redirect detail"), "cisa_kev_fetch_rejected", False),
    ],
)
def test_fetch_failures_are_retryable_or_rejected_safely(
    error: Exception,
    expected_type: str,
    retryable: bool,
) -> None:
    exit_code, stdout, stderr, session, client, _ = run_fake(client=FakeClient(error=error))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    error_record = next(record for record in session.added if isinstance(record, IngestionError))
    assert exit_code == 1
    assert run.status == "failed"
    assert client.closed
    assert error_record.error_type == expected_type
    assert error_record.retryable is retryable
    assert "secret" not in stdout
    assert "secret" not in stderr


def test_partial_run_does_not_advance_checkpoint() -> None:
    exit_code, _, _, session, _, _ = run_fake(
        service_factory=ServiceFactory(["skipped"]),
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 1
    assert run.checkpoint_after is None
    assert run.source.checkpoint_value == "existing-checkpoint"
    assert run.source.last_successful_fetch_at == datetime(2026, 7, 9, 12, 0, tzinfo=UTC)


def test_whole_run_database_failure_rolls_back_and_closes() -> None:
    session = FakeSession(fail_commit=True)

    exit_code, stdout, stderr, session, _, _ = run_fake(session=session)

    assert exit_code == 1
    assert stdout == ""
    assert "database operation" in stderr
    assert "private" not in stderr
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed


def test_max_records_cap_marks_run_partial_without_advancing_checkpoint() -> None:
    second = dict(CATALOG["vulnerabilities"][0], cveID="CVE-2026-0002")
    catalog = {"vulnerabilities": [CATALOG["vulnerabilities"][0], second]}

    exit_code, stdout, stderr, session, _, services = run_fake(
        client=FakeClient(catalog),
        service_factory=ServiceFactory(["created"]),
        max_records=1,
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 1
    assert run.status == "partial"
    assert run.checkpoint_after is None
    assert run.source.checkpoint_value == "existing-checkpoint"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_failed == 0
    assert "capped=true" in run.safe_summary
    assert "Capped: true" in stdout
    assert "Record cap reached" in stdout
    assert "controlled failure" in stderr
    assert session.commits == 1
    assert session.rollbacks == 0
    assert len(services.service.enrich_calls) == 1
