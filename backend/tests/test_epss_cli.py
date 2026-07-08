from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from io import StringIO
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.ingestion import epss_cli
from app.ingestion.collectors.epss_client import EpssBatch, EpssRateLimitError, EpssRequestError
from app.ingestion.normalizers.epss import EpssNormalizationError, normalize_epss_record
from app.ingestion.services.epss_enrichment_service import EpssPersistenceError, EpssPersistenceResult
from app.models import IngestionError, IngestionRun, IngestionRunRecord, IntelligenceSource


NOW = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)


class ExecuteRows:
    def __init__(self, values: list[str]):
        self.values = values

    def all(self):
        return [(value,) for value in self.values]


class FakeSession:
    def __init__(self, cves: list[str] | None = None, *, fail_commit: bool = False):
        self.cves = cves if cves is not None else ["CVE-2026-0001"]
        self.fail_commit = fail_commit
        self.added: list[object] = []
        self.commits = 0
        self.rollbacks = 0
        self.flushes = 0
        self.closed = False
        self.nested_transactions = 0

    def execute(self, _statement):
        return ExecuteRows(self.cves)

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
            raise EpssPersistenceError("postgresql://private:password@host/db")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class FakeClient:
    def __init__(
        self,
        batches: list[EpssBatch] | None = None,
        error: Exception | None = None,
    ):
        self.batches = list(batches or [])
        self.error = error
        self.closed = False
        self.fetch_calls: list[tuple[str, ...]] = []
        self.build_calls: list[dict[str, Any]] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.closed = True

    def build_batches(self, cve_ids: list[str], *, max_batch_size: int):
        self.build_calls.append({"cve_ids": cve_ids, "max_batch_size": max_batch_size})
        return [
            tuple(cve_ids[index : index + max_batch_size])
            for index in range(0, len(cve_ids), max_batch_size)
        ]

    def fetch_batch(self, batch: tuple[str, ...]) -> EpssBatch:
        self.fetch_calls.append(batch)
        if self.error is not None:
            raise self.error
        return self.batches.pop(0)


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
            slug="first-epss",
            name="FIRST EPSS",
            source_type="api",
            base_url="https://api.first.org/data/v1/epss",
            is_enabled=True,
            checkpoint_value=None,
        )

    def ensure_source(self) -> IntelligenceSource:
        return self.source

    def enrich(self, normalized: object, *, observed_at: datetime):
        del observed_at
        self.enrich_calls.append(normalized)
        if self.error is not None:
            raise self.error
        outcome = self.outcomes.pop(0)
        return EpssPersistenceResult("CVE-2026-0001", outcome, None, None, 123)


class ServiceFactory:
    def __init__(self, outcomes: list[str] | None = None, error: Exception | None = None):
        self.outcomes = outcomes
        self.error = error
        self.service: FakeService | None = None

    def __call__(self, session: FakeSession) -> FakeService:
        self.service = FakeService(session, self.outcomes, self.error)
        return self.service


def record(cve_id: str = "CVE-2026-0001", **overrides: object) -> dict:
    value = {"cve": cve_id, "epss": "0.100000", "percentile": "0.200000", "date": "2026-07-10"}
    value.update(overrides)
    return value


def batch(requested: tuple[str, ...], records: list[dict]) -> EpssBatch:
    return EpssBatch(requested_cves=requested, records=records)


def run_fake(
    *,
    session: FakeSession | None = None,
    client: FakeClient | None = None,
    service_factory: ServiceFactory | None = None,
    normalizer=normalize_epss_record,
    max_cves: int = 25,
    batch_size: int = 25,
):
    fake_session = session or FakeSession()
    fake_client = client or FakeClient([batch(("CVE-2026-0001",), [record()])])
    services = service_factory or ServiceFactory()
    stdout = StringIO()
    stderr = StringIO()
    exit_code = epss_cli.run_enrichment(
        max_cves=max_cves,
        batch_size=batch_size,
        clock=lambda: NOW,
        client_factory=lambda: fake_client,  # type: ignore[arg-type]
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        normalizer=normalizer,
        service_factory=services,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), fake_session, fake_client


@pytest.mark.parametrize(
    ("option", "valid_values", "invalid_values"),
    [
        ("--max-cves", ["1", "500"], ["0", "501", "bad"]),
        ("--batch-size", ["1", "100"], ["0", "101", "bad"]),
    ],
)
def test_cli_argument_bounds(monkeypatch, option, valid_values, invalid_values, capsys):
    monkeypatch.setattr(epss_cli, "run_enrichment", lambda **kwargs: 0)
    for value in valid_values:
        assert epss_cli.main([option, value]) == 0
    for value in invalid_values:
        assert epss_cli.main([option, value]) == 2
        assert "Invalid manual EPSS enrichment arguments." in capsys.readouterr().err


@pytest.mark.parametrize(("field", "value"), [("max_cves", True), ("batch_size", 0)])
def test_direct_validation_rejects_values_before_factories(field: str, value: object):
    values: dict[str, object] = {"max_cves": 25, "batch_size": 25}
    values[field] = value
    stderr = StringIO()

    exit_code = epss_cli.run_enrichment(
        **values,  # type: ignore[arg-type]
        clock=lambda: pytest.fail("clock must not run"),
        client_factory=lambda: pytest.fail("client must not be created"),
        session_factory=lambda: pytest.fail("session must not be created"),
        stderr=stderr,
    )

    assert exit_code == 2
    assert stderr.getvalue() == "Invalid manual EPSS enrichment parameters.\n"


def test_empty_local_cve_set_succeeds_without_client() -> None:
    session = FakeSession(cves=[])
    client = FakeClient()

    exit_code, stdout, stderr, session, client = run_fake(session=session, client=client)

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 0
    assert client.fetch_calls == []
    assert "Status: succeeded" in stdout
    assert stderr == ""


def test_successful_bounded_enrichment_creates_audit_and_commits() -> None:
    exit_code, stdout, stderr, session, client = run_fake(
        service_factory=ServiceFactory(["created"])
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert isinstance(run.public_id, UUID)
    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 1
    assert run.records_created == 1
    assert run.records_failed == 0
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed
    assert client.closed
    assert "Created: 1" in stdout
    assert stderr == ""


def test_multiple_batches_are_processed() -> None:
    session = FakeSession(cves=["CVE-2026-0001", "CVE-2026-0002"])
    client = FakeClient(
        [
            batch(("CVE-2026-0001",), [record("CVE-2026-0001")]),
            batch(("CVE-2026-0002",), [record("CVE-2026-0002")]),
        ]
    )

    exit_code, _, _, _, client = run_fake(
        session=session,
        client=client,
        service_factory=ServiceFactory(["created", "updated"]),
        batch_size=1,
    )

    assert exit_code == 0
    assert client.fetch_calls == [("CVE-2026-0001",), ("CVE-2026-0002",)]


def test_omitted_api_record_is_controlled_skipped_partial() -> None:
    client = FakeClient([batch(("CVE-2026-0001",), [])])

    exit_code, _, stderr, session, _ = run_fake(client=client)

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 0
    assert run.records_failed == 0
    assert run.records_skipped == 1
    assert "controlled failure" in stderr


def test_exact_duplicate_api_record_is_processed_once() -> None:
    client = FakeClient([batch(("CVE-2026-0001",), [record(), record()])])

    exit_code, _, _, session, _ = run_fake(
        client=client,
        service_factory=ServiceFactory(["unchanged"]),
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 0
    assert run.records_unchanged == 1
    assert run.records_failed == 0


def test_conflicting_duplicate_api_record_fails_safely() -> None:
    services = ServiceFactory()
    client = FakeClient(
        [
            batch(
                ("CVE-2026-0001",),
                [record(epss="0.100000"), record(epss="0.300000")],
            )
        ]
    )

    exit_code, stdout, stderr, session, _ = run_fake(
        client=client,
        service_factory=services,
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    failed_records = [
        item
        for item in session.added
        if isinstance(item, IngestionRunRecord) and item.action == "failed"
    ]
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert exit_code == 1
    assert run.records_failed == 1
    assert run.records_skipped == 0
    assert run.error_count == 1
    assert len(failed_records) == 1
    assert len(errors) == 1
    assert services.service.enrich_calls == []
    assert "0.300000" not in stdout
    assert "0.300000" not in stderr
    assert errors[0].error_type == "epss_duplicate_conflict"


def test_unexpected_api_record_does_not_enrich_unrequested_cve() -> None:
    client = FakeClient(
        [batch(("CVE-2026-0001",), [record("CVE-2026-9999"), record()])]
    )

    exit_code, _, _, session, _ = run_fake(
        client=client,
        service_factory=ServiceFactory(["created"]),
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 1
    assert run.records_created == 1
    assert run.records_failed == 1


def test_normalization_failure_is_sanitized() -> None:
    marker = "private-raw-payload-fragment"

    def fail_normalization(value: object):
        del value
        raise EpssNormalizationError(marker)

    client = FakeClient([batch(("CVE-2026-0001",), [record(secret=marker)])])

    exit_code, stdout, stderr, session, _ = run_fake(
        client=client,
        normalizer=fail_normalization,
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    failed_records = [
        item
        for item in session.added
        if isinstance(item, IngestionRunRecord) and item.action == "failed"
    ]
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert exit_code == 1
    assert run.records_fetched == 1
    assert run.records_failed == 1
    assert run.records_skipped == 0
    assert run.error_count == 1
    assert len(failed_records) == 1
    assert len(errors) == 1
    assert marker not in stdout
    assert marker not in stderr
    assert errors[0].error_type == "epss_normalization_error"
    assert marker not in errors[0].safe_message


def test_persistence_failure_is_sanitized_and_committed_as_partial() -> None:
    marker = "postgresql://private:password@host/database"
    client = FakeClient([batch(("CVE-2026-0001",), [record()])])

    exit_code, stdout, stderr, session, _ = run_fake(
        client=client,
        service_factory=ServiceFactory(error=EpssPersistenceError(marker)),
    )

    assert exit_code == 1
    assert marker not in stdout
    assert marker not in stderr
    assert session.commits == 1
    error = next(item for item in session.added if isinstance(item, IngestionError))
    assert error.error_type == "epss_persistence_error"


@pytest.mark.parametrize(
    ("error", "expected_type"),
    [
        (EpssRequestError("secret transport detail"), "epss_fetch_error"),
        (EpssRateLimitError("secret rate detail"), "epss_rate_limit"),
    ],
)
def test_fetch_failures_are_retryable_and_safe(error: Exception, expected_type: str) -> None:
    client = FakeClient(error=error)

    exit_code, stdout, stderr, session, client = run_fake(client=client)

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 1
    assert run.status == "failed"
    assert "secret" not in stdout
    assert "secret" not in stderr
    assert client.closed
    error_record = next(item for item in session.added if isinstance(item, IngestionError))
    assert error_record.error_type == expected_type
    assert error_record.retryable is True


def test_successful_run_updates_checkpoint_only_on_success() -> None:
    exit_code, _, _, session, _ = run_fake()

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 0
    assert run.checkpoint_after == "2026-07-10T12:00:00Z"


def test_partial_run_does_not_advance_checkpoint() -> None:
    client = FakeClient([batch(("CVE-2026-0001",), [])])

    exit_code, _, _, session, _ = run_fake(client=client)

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 1
    assert run.checkpoint_after is None


def test_whole_run_database_failure_rolls_back_and_closes() -> None:
    session = FakeSession(fail_commit=True)

    exit_code, stdout, stderr, session, _ = run_fake(session=session)

    assert exit_code == 1
    assert stdout == ""
    assert "database operation" in stderr
    assert "private" not in stderr
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed
