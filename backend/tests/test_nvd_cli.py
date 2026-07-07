from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from io import StringIO
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr

from app.ingestion import nvd_cli
from app.ingestion.collectors.nvd_client import NvdPage, NvdRequestError
from app.ingestion.normalizers.nvd import NvdNormalizationError
from app.ingestion.services.nvd_ingestion_service import (
    NvdPersistenceError,
    NvdPersistenceResult,
)
from app.models import (
    IngestionError,
    IngestionRun,
    IngestionRunRecord,
    IntelligenceSource,
)


NOW = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)


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
            raise NvdPersistenceError("private database details")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class FakeClient:
    def __init__(self, pages: list[NvdPage] | None = None, error: Exception | None = None):
        self.pages = list(pages or [])
        self.error = error
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def __enter__(self) -> FakeClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.closed = True

    def fetch_page(self, **kwargs: Any) -> NvdPage:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.pages.pop(0)


class ClientFactory:
    def __init__(self, client: FakeClient):
        self.client = client
        self.api_keys: list[SecretStr | None] = []

    def __call__(self, *, api_key: SecretStr | None) -> FakeClient:
        self.api_keys.append(api_key)
        return self.client


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
        self.source = IntelligenceSource(
            slug="nvd",
            name="National Vulnerability Database",
            source_type="api",
            base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            is_enabled=True,
            checkpoint_value=None,
        )
        self.persist_calls = 0

    def ensure_source(self) -> IntelligenceSource:
        return self.source

    def persist(self, normalized: object, *, observed_at: datetime):
        del normalized, observed_at
        self.persist_calls += 1
        if self.error is not None:
            raise self.error
        outcome = self.outcomes.pop(0)
        return NvdPersistenceResult("CVE-2026-12345", outcome)


class ServiceFactory:
    def __init__(self, outcomes: list[str] | None = None, error: Exception | None = None):
        self.outcomes = outcomes
        self.error = error
        self.service: FakeService | None = None

    def __call__(self, session: FakeSession) -> FakeService:
        self.service = FakeService(session, self.outcomes, self.error)
        return self.service


def wrapper(cve_id: str = "CVE-2026-12345", **extra: object) -> dict:
    return {"cve": {"id": cve_id, **extra}}


def page(records: list[dict], *, start: int = 0, total: int | None = None) -> NvdPage:
    return NvdPage(
        vulnerabilities=records,
        start_index=start,
        results_per_page=len(records),
        total_results=len(records) if total is None else total,
    )


def run_fake(
    *,
    client: FakeClient,
    service_factory: ServiceFactory | None = None,
    session: FakeSession | None = None,
    normalizer=lambda value: value,
    api_key: SecretStr | None = None,
    window_minutes: int = 60,
    results_per_page: int = 25,
    max_records: int = 25,
    sleeps: list[float] | None = None,
):
    fake_session = session or FakeSession()
    factory = ClientFactory(client)
    services = service_factory or ServiceFactory()
    stdout = StringIO()
    stderr = StringIO()
    exit_code = nvd_cli.run_ingestion(
        window_minutes=window_minutes,
        results_per_page=results_per_page,
        max_records=max_records,
        api_key=api_key,
        clock=lambda: NOW,
        client_factory=factory,  # type: ignore[arg-type]
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        normalizer=normalizer,
        service_factory=services,  # type: ignore[arg-type]
        sleeper=(sleeps if sleeps is not None else []).append,
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), fake_session, factory, services


@pytest.mark.parametrize(
    ("option", "valid_values", "invalid_values"),
    [
        ("--window-minutes", ["1", "1440"], ["0", "1441", "bad"]),
        ("--results-per-page", ["1", "100"], ["0", "101", "bad"]),
        ("--max-records", ["1", "100"], ["0", "101", "bad"]),
    ],
)
def test_cli_argument_bounds(monkeypatch, option, valid_values, invalid_values, capsys):
    monkeypatch.setattr(nvd_cli, "get_settings", lambda: type("S", (), {"nvd_api_key": None})())
    monkeypatch.setattr(nvd_cli, "run_ingestion", lambda **kwargs: 0)
    for value in valid_values:
        assert nvd_cli.main([option, value]) == 0
    for value in invalid_values:
        assert nvd_cli.main([option, value]) == 2
        assert "Invalid manual NVD ingestion arguments." in capsys.readouterr().err


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("window_minutes", True),
        ("window_minutes", "60"),
        ("results_per_page", False),
        ("results_per_page", 1.5),
        ("max_records", True),
        ("max_records", 101),
    ],
)
def test_direct_validation_rejects_values_before_factories(field: str, value: object):
    values: dict[str, object] = {
        "window_minutes": 60,
        "results_per_page": 25,
        "max_records": 25,
    }
    values[field] = value
    stderr = StringIO()
    exit_code = nvd_cli.run_ingestion(
        **values,  # type: ignore[arg-type]
        api_key=None,
        clock=lambda: pytest.fail("clock must not run"),
        client_factory=lambda **kwargs: pytest.fail("client must not be created"),
        session_factory=lambda: pytest.fail("session must not be created"),
        stderr=stderr,
    )
    assert exit_code == 2
    assert stderr.getvalue() == "Invalid manual NVD ingestion parameters.\n"


def test_successful_run_creates_audit_records_and_commits() -> None:
    client = FakeClient([page([wrapper(), wrapper("CVE-2026-12346")])])
    services = ServiceFactory(["created", "unchanged"])

    exit_code, stdout, stderr, session, _, _ = run_fake(
        client=client,
        service_factory=services,
    )

    assert exit_code == 0
    assert stderr == ""
    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert isinstance(run.public_id, UUID)
    assert run.status == "succeeded"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_unchanged == 1
    assert run.records_failed == 0
    assert len([r for r in session.added if isinstance(r, IngestionRunRecord)]) == 2
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed
    assert "Status: succeeded" in stdout
    assert "Created: 1" in stdout
    assert "Unchanged: 1" in stdout


def test_max_records_cap_is_partial_and_never_exceeded() -> None:
    client = FakeClient([page([wrapper(), wrapper("CVE-2026-12346")], total=10)])

    exit_code, stdout, stderr, session, _, services = run_fake(
        client=client,
        max_records=2,
        results_per_page=10,
        service_factory=ServiceFactory(["created", "created"]),
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 2
    assert services.service.persist_calls == 2
    assert client.calls[0]["results_per_page"] == 2
    assert "Capped: true" in stdout
    assert "controlled failure" in stderr
    assert session.commits == 1


def test_multiple_pages_are_paced_and_bounded() -> None:
    client = FakeClient(
        [
            page([wrapper()], start=0, total=2),
            page([wrapper("CVE-2026-12346")], start=1, total=2),
        ]
    )
    sleeps: list[float] = []

    exit_code, _, _, _, _, _ = run_fake(
        client=client,
        results_per_page=1,
        max_records=2,
        service_factory=ServiceFactory(["created", "created"]),
        sleeps=sleeps,
    )

    assert exit_code == 0
    assert [call["start_index"] for call in client.calls] == [0, 1]
    assert sleeps == [nvd_cli.UNAUTHENTICATED_DELAY_SECONDS]


def test_normalization_failure_is_sanitized_and_committed_as_partial() -> None:
    marker = "private-raw-payload-fragment"

    def fail_normalization(value: object):
        del value
        raise NvdNormalizationError(marker)

    client = FakeClient([page([wrapper(secret=marker)])])
    exit_code, stdout, stderr, session, _, _ = run_fake(
        client=client,
        normalizer=fail_normalization,
    )

    assert exit_code == 1
    assert marker not in stdout
    assert marker not in stderr
    error = next(record for record in session.added if isinstance(record, IngestionError))
    assert error.error_type == "nvd_normalization_error"
    assert marker not in error.safe_message
    assert session.commits == 1


def test_persistence_failure_hides_database_details() -> None:
    marker = "postgresql://private:password@host/database"
    services = ServiceFactory(error=NvdPersistenceError(marker))
    client = FakeClient([page([wrapper(database_detail=marker)])])

    exit_code, stdout, stderr, session, _, _ = run_fake(
        client=client,
        service_factory=services,
    )

    assert exit_code == 1
    assert marker not in stdout
    assert marker not in stderr
    error = next(record for record in session.added if isinstance(record, IngestionError))
    assert error.error_type == "nvd_persistence_error"
    assert marker not in error.safe_message
    assert session.commits == 1


def test_fetch_failure_is_failed_safe_and_closes_resources() -> None:
    secret = "synthetic-nvd-key-do-not-use"
    client = FakeClient(error=NvdRequestError(f"request failed {secret}"))

    exit_code, stdout, stderr, session, factory, _ = run_fake(
        client=client,
        api_key=SecretStr(secret),
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 1
    assert run.status == "failed"
    assert factory.api_keys[0].get_secret_value() == secret
    assert secret not in stdout
    assert secret not in stderr
    assert client.closed
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed


def test_whole_run_database_failure_rolls_back_and_closes() -> None:
    session = FakeSession(fail_commit=True)
    client = FakeClient([page([wrapper()])])

    exit_code, stdout, stderr, session, _, _ = run_fake(
        client=client,
        session=session,
    )

    assert exit_code == 1
    assert stdout == ""
    assert "database operation" in stderr
    assert "private" not in stderr
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed
