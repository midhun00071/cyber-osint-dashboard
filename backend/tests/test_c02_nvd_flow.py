from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from app.orchestration.contracts import (
    ClassifiedFailure,
    ProgressKind,
    ProgressSnapshot,
    ProgressStorage,
    QuotaObservation,
    ResultStatus,
    SOURCE_POLICIES,
    SourceAttemptIdentity,
    SourceExecutionContext,
)
from app.orchestration.source_handlers.nvd import (
    MAX_RECORDS,
    RESULTS_PER_PAGE,
    WINDOW_OVERLAP,
    NvdSourceHandler,
)


SLOT = datetime(2026, 8, 3, 8, 17, tzinfo=UTC)


def wrapper(cve_id: str) -> dict[str, object]:
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-08-03T06:30:00Z",
            "lastModified": "2026-08-03T07:30:00Z",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Safe summary."}],
            "metrics": {},
            "configurations": [],
        }
    }


class Rows:
    def scalars(self):
        return self

    def all(self):
        return []


class FakeSession:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def begin(self):
        return nullcontext()

    def execute(self, statement):
        del statement
        return Rows()

    def add(self, record):
        del record

    def flush(self):
        return None


class FakeClient:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []
        self.closed = False

    def fetch_page(self, start, end, **kwargs):
        self.calls.append((start, end, kwargs))
        return self.pages.pop(0)

    def close(self):
        self.closed = True


def page(records, *, start=0, total=None):
    return SimpleNamespace(
        vulnerabilities=records,
        start_index=start,
        results_per_page=RESULTS_PER_PAGE,
        total_results=len(records) if total is None else total,
    )


def context(progress=None):
    policy = SOURCE_POLICIES["nvd"]
    return SourceExecutionContext(
        policy=policy,
        attempt=SourceAttemptIdentity("nvd", 1, 3, 0, 1),
        scheduled_for=SLOT,
        deployment_ref="alpha-data-ingestion-cycle",
        progress=progress,
        quota=QuotaObservation(policy.quota_policy_key),
    )


def install_service(monkeypatch, outcomes=("created",)):
    queued = list(outcomes)

    class Service:
        def __init__(self, session):
            del session

        def persist(self, record, *, observed_at):
            del record, observed_at
            return SimpleNamespace(outcome=queued.pop(0))

    monkeypatch.setattr(
        "app.orchestration.source_handlers.nvd.NvdIngestionService",
        Service,
    )


def handler_for(client, *, api_key=None, sleeper=lambda value: None):
    captured = {}

    def factory(key, supplied_sleeper):
        captured["key"] = key
        captured["sleeper"] = supplied_sleeper
        return client

    handler = NvdSourceHandler(
        session_factory=FakeSession,
        client_factory=factory,
        settings_provider=lambda: SimpleNamespace(nvd_api_key=api_key),
        sleeper=sleeper,
    )
    return handler, captured


def test_initial_window_is_two_hours_and_advances_to_scheduled_slot(monkeypatch) -> None:
    install_service(monkeypatch)
    client = FakeClient([page([wrapper("CVE-2026-1001")])])
    handler, _ = handler_for(client)

    result = handler.execute(context())

    assert client.calls[0][0] == SLOT - timedelta(hours=2)
    assert client.calls[0][1] == SLOT
    assert result.status is ResultStatus.SUCCESS
    assert result.progress_proposal.value == SLOT
    assert client.closed is True


def test_existing_watermark_uses_fixed_overlap(monkeypatch) -> None:
    install_service(monkeypatch, outcomes=())
    previous = SLOT - timedelta(hours=2)
    progress = ProgressSnapshot(
        storage=ProgressStorage.WATERMARK,
        kind=ProgressKind.MODIFIED_SINCE,
        name="modified_since",
        value=previous,
        version=4,
    )
    client = FakeClient([page([])])
    handler, _ = handler_for(client)

    result = handler.execute(context(progress))

    assert client.calls[0][0] == previous - WINDOW_OVERLAP
    assert result.status is ResultStatus.NO_CHANGE
    assert result.progress_proposal.expected_previous_version == 4


def test_paging_is_complete_and_public_requests_are_paced(monkeypatch) -> None:
    install_service(monkeypatch, outcomes=("created", "unchanged"))
    sleeps = []
    client = FakeClient(
        [
            page([wrapper("CVE-2026-1001")], start=0, total=2),
            page([wrapper("CVE-2026-1002")], start=1, total=2),
        ]
    )
    handler, _ = handler_for(client, sleeper=sleeps.append)

    result = handler.execute(context())

    assert result.counters.fetched == 2
    assert result.metrics.page_count == 2
    assert sleeps == [6.0]


def test_api_key_is_passed_as_secret_and_authenticated_pacing_is_preserved(monkeypatch) -> None:
    install_service(monkeypatch, outcomes=("created", "unchanged"))
    sleeps = []
    secret = SecretStr("not-serialized")
    client = FakeClient(
        [
            page([wrapper("CVE-2026-1001")], start=0, total=2),
            page([wrapper("CVE-2026-1002")], start=1, total=2),
        ]
    )
    handler, captured = handler_for(client, api_key=secret, sleeper=sleeps.append)

    handler.execute(context())

    assert captured["key"] is secret
    assert sleeps == [0.6]


def test_exact_duplicate_cve_is_persisted_once(monkeypatch) -> None:
    install_service(monkeypatch)
    duplicate = wrapper("CVE-2026-1001")
    client = FakeClient([page([duplicate, duplicate])])
    handler, _ = handler_for(client)

    result = handler.execute(context())

    assert result.counters.fetched == 1
    assert result.counters.created == 1


def test_declared_window_over_record_limit_fails_without_progress(monkeypatch) -> None:
    client = FakeClient([page([], total=MAX_RECORDS + 1)])
    handler, _ = handler_for(client)

    with pytest.raises(ClassifiedFailure, match="record bound"):
        handler.execute(context())


def test_page_payload_cannot_exceed_declared_page_size() -> None:
    malformed_page = page(
        [wrapper("CVE-2026-1001"), wrapper("CVE-2026-1002")],
        total=2,
    )
    malformed_page.results_per_page = 1
    client = FakeClient([malformed_page])
    handler, _ = handler_for(client)

    with pytest.raises(ClassifiedFailure, match="declared record bound"):
        handler.execute(context())
