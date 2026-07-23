from __future__ import annotations

from contextlib import nullcontext
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from io import StringIO
from typing import Any
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion import nvd_curated_cli as curated
from app.ingestion.collectors.nvd_client import (
    NvdPage,
    NvdRateLimitError,
    NvdRequestError,
)
from app.ingestion.normalizers.nvd import normalize_nvd_cve
from app.ingestion.services.nvd_ingestion_service import (
    NvdPersistenceError,
    NvdPersistenceResult,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord, IntelligenceSource


NOW = datetime(2026, 7, 23, 12, 34, 56, 789123, tzinfo=UTC)
EARLY_NOW = datetime(2026, 1, 2, 12, 0, tzinfo=UTC)


def make_wrapper(
    cve_id: str,
    *,
    severity: str = "CRITICAL",
    score: float = 9.8,
    version: str = "3.1",
    published: str = "2026-01-01T01:00:00Z",
    modified: str = "2026-01-02T01:00:00Z",
    kev: bool = False,
    status: str = "Analyzed",
) -> dict[str, Any]:
    metric_name = "cvssMetricV40" if version == "4.0" else (
        "cvssMetricV31" if version == "3.1" else "cvssMetricV30"
    )
    cve: dict[str, Any] = {
        "id": cve_id,
        "published": published,
        "lastModified": modified,
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": "Safe candidate."}],
        "metrics": {
            metric_name: [
                {
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": severity,
                        "vectorString": f"CVSS:{version}/AV:N",
                    }
                }
            ]
        },
        "configurations": [],
    }
    if kev:
        cve["cisaExploitAdd"] = "2026-01-02"
    return {"cve": cve}


def page(
    wrappers: list[dict[str, Any]],
    *,
    start: int = 0,
    total: int | None = None,
) -> NvdPage:
    return NvdPage(
        vulnerabilities=wrappers,
        start_index=start,
        results_per_page=len(wrappers),
        total_results=len(wrappers) if total is None else total,
    )


class FakeClient:
    def __init__(
        self,
        handler=None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.handler = handler or (lambda kwargs: page([]))
        self.error = error
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.closed = True

    def fetch_publication_page(
        self,
        publication_start: datetime,
        publication_end: datetime,
        **kwargs: Any,
    ) -> NvdPage:
        call = {
            "publication_start": publication_start,
            "publication_end": publication_end,
            **kwargs,
        }
        self.calls.append(call)
        if self.error is not None:
            raise self.error
        return self.handler(call)


class ClientFactory:
    def __init__(self, client: FakeClient) -> None:
        self.client = client
        self.api_keys: list[SecretStr | None] = []

    def __call__(self, *, api_key: SecretStr | None) -> FakeClient:
        self.api_keys.append(api_key)
        return self.client


class FakeSession:
    def __init__(self, *, fail_commit: bool = False) -> None:
        self.fail_commit = fail_commit
        self.added: list[object] = []
        self.commits = 0
        self.rollbacks = 0
        self.flushes = 0
        self.nested_transactions = 0
        self.closed = False

    def add(self, value: object) -> None:
        self.added.append(value)

    def flush(self) -> None:
        self.flushes += 1
        for value in self.added:
            if isinstance(value, IngestionRun) and value.id is None:
                value.id = 1
                value.public_id = uuid4()

    def begin_nested(self):
        self.nested_transactions += 1
        return nullcontext()

    def commit(self) -> None:
        if self.fail_commit:
            raise SQLAlchemyError("postgresql://private:password@host/database")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class FakeService:
    def __init__(
        self,
        session: FakeSession,
        *,
        outcomes: list[str] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.session = session
        self.outcomes = list(outcomes or [])
        self.error = error
        self.persisted: list[str] = []
        self.source = IntelligenceSource(
            slug="nvd",
            name="National Vulnerability Database",
            source_type="api",
            base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            is_enabled=True,
            checkpoint_value="incremental-checkpoint",
        )

    def ensure_source(self) -> IntelligenceSource:
        return self.source

    def persist(self, normalized, *, observed_at: datetime) -> NvdPersistenceResult:
        del observed_at
        self.persisted.append(normalized.cve_id)
        if self.error is not None:
            raise self.error
        outcome = self.outcomes.pop(0) if self.outcomes else "created"
        return NvdPersistenceResult(normalized.cve_id, outcome)


class ServiceFactory:
    def __init__(
        self,
        outcomes: list[str] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.outcomes = outcomes
        self.error = error
        self.service: FakeService | None = None

    def __call__(self, session: FakeSession) -> FakeService:
        self.service = FakeService(
            session,
            outcomes=self.outcomes,
            error=self.error,
        )
        return self.service


def make_plan(
    *,
    now: datetime = EARLY_NOW,
    max_pages: int = 2,
    max_requests: int = 50,
) -> curated.CuratedPlan:
    return curated.build_plan(
        start_year=2026,
        end_year=2026,
        chunk_days=90,
        results_per_page=50,
        max_pages_per_query=max_pages,
        max_requests=max_requests,
        now=now,
    )


def quota_wrappers() -> list[dict[str, Any]]:
    wrappers: list[dict[str, Any]] = []
    number = 1000
    for severity, quota in curated.DEFAULT_QUOTAS.items():
        for offset in range(quota):
            wrappers.append(
                make_wrapper(
                    f"CVE-2026-{number + offset:04d}",
                    severity=severity.upper(),
                    score={
                        "critical": 9.8,
                        "high": 8.2,
                        "medium": 5.5,
                        "low": 2.1,
                    }[severity],
                )
            )
        number += 100
    return wrappers


def run_fake(
    *,
    client: FakeClient,
    session: FakeSession | None = None,
    services: ServiceFactory | None = None,
    api_key: SecretStr | None = None,
    max_requests: int = 50,
    retention_multiplier: int = curated.DEFAULT_RETENTION_MULTIPLIER,
    clock: Callable[[], datetime] = lambda: EARLY_NOW,
) -> tuple[int, str, str, FakeSession, ClientFactory, ServiceFactory]:
    fake_session = session or FakeSession()
    factory = ClientFactory(client)
    service_factory = services or ServiceFactory()
    stdout = StringIO()
    stderr = StringIO()
    exit_code = curated.run_curated_ingestion(
        start_year=2026,
        end_year=2026,
        chunk_days=90,
        results_per_page=50,
        max_pages_per_query=2,
        max_requests=max_requests,
        api_key=api_key,
        retention_multiplier=retention_multiplier,
        clock=clock,
        client_factory=factory,  # type: ignore[arg-type]
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        service_factory=service_factory,  # type: ignore[arg-type]
        sleeper=lambda delay: None,
        stdout=stdout,
        stderr=stderr,
    )
    return (
        exit_code,
        stdout.getvalue(),
        stderr.getvalue(),
        fake_session,
        factory,
        service_factory,
    )


def test_default_plan_covers_2020_through_current_utc_year() -> None:
    plan = curated.build_plan(
        start_year=curated.MIN_YEAR,
        end_year=NOW.year,
        chunk_days=curated.DEFAULT_CHUNK_DAYS,
        results_per_page=curated.DEFAULT_RESULTS_PER_PAGE,
        max_pages_per_query=curated.DEFAULT_MAX_PAGES_PER_QUERY,
        max_requests=curated.DEFAULT_MAX_REQUESTS,
        now=NOW,
    )

    assert list(plan.chunks_by_year) == list(range(2020, NOW.year + 1))
    assert plan.start_year == 2020
    assert plan.end_year == 2026
    assert plan.retained_limits == curated.DEFAULT_QUOTAS


def test_explicit_valid_year_range_is_preserved() -> None:
    plan = curated.build_plan(
        start_year=2022,
        end_year=2024,
        chunk_days=90,
        results_per_page=50,
        max_pages_per_query=2,
        max_requests=400,
        now=NOW,
    )

    assert list(plan.chunks_by_year) == [2022, 2023, 2024]


@pytest.mark.parametrize(
    ("start_year", "end_year", "message"),
    [
        (2019, 2020, "Invalid curated"),
        (2025, 2024, "must not be after"),
        (2020, 2027, "Invalid curated"),
    ],
)
def test_invalid_year_ranges_are_rejected(
    start_year: int,
    end_year: int,
    message: str,
) -> None:
    with pytest.raises(curated.CuratedCliArgumentError, match=message):
        curated.build_plan(
            start_year=start_year,
            end_year=end_year,
            chunk_days=90,
            results_per_page=50,
            max_pages_per_query=2,
            max_requests=400,
            now=NOW,
        )


def test_normal_year_chunks_are_gap_free_and_bounded() -> None:
    chunks = curated.build_date_chunks(2023, now=NOW, chunk_days=90)

    assert chunks[0].start == datetime(2023, 1, 1, tzinfo=UTC)
    assert chunks[-1].end == datetime(2024, 1, 1, tzinfo=UTC) - curated.MILLISECOND
    assert all(
        current.end + curated.MILLISECOND == following.start
        for current, following in zip(chunks, chunks[1:])
    )
    assert all(
        chunk.end - chunk.start < timedelta(days=curated.MAX_CHUNK_DAYS)
        for chunk in chunks
    )


def test_leap_year_chunks_end_exactly_at_year_end() -> None:
    chunks = curated.build_date_chunks(2024, now=NOW, chunk_days=90)

    assert any(chunk.start <= datetime(2024, 2, 29, tzinfo=UTC) <= chunk.end for chunk in chunks)
    assert chunks[-1].end == datetime(2025, 1, 1, tzinfo=UTC) - curated.MILLISECOND
    assert sum(
        int((chunk.end - chunk.start + curated.MILLISECOND).total_seconds())
        for chunk in chunks
    ) == 366 * 24 * 60 * 60


def test_current_year_final_chunk_ends_at_current_utc_millisecond() -> None:
    chunks = curated.build_date_chunks(2026, now=NOW, chunk_days=90)

    assert chunks[-1].end == datetime(2026, 7, 23, 12, 34, 56, 789000, tzinfo=UTC)


def test_collection_issues_v3_v4_and_kev_queries() -> None:
    client = FakeClient()

    result = curated.collect_candidates(
        make_plan(),
        client=client,  # type: ignore[arg-type]
        sleeper=lambda delay: None,
    )

    assert result.request_count == 9
    assert any(call.get("has_kev") is True for call in client.calls)
    assert {
        call.get("cvss_v3_severity")
        for call in client.calls
        if "cvss_v3_severity" in call
    } == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert {
        call.get("cvss_v4_severity")
        for call in client.calls
        if "cvss_v4_severity" in call
    } == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_multiple_pages_and_final_partial_page_are_collected() -> None:
    def handler(call: dict[str, Any]) -> NvdPage:
        if call.get("cvss_v3_severity") != "CRITICAL":
            return page([])
        if call["start_index"] == 0:
            return page(
                [make_wrapper("CVE-2026-1001")],
                start=0,
                total=2,
            )
        return page(
            [make_wrapper("CVE-2026-1002")],
            start=1,
            total=2,
        )

    client = FakeClient(handler)
    result = curated.collect_candidates(
        make_plan(),
        client=client,  # type: ignore[arg-type]
        sleeper=lambda delay: None,
    )

    state = result.years[0]
    assert state.candidates_inspected == 2
    assert set(state.candidates) == {"CVE-2026-1001", "CVE-2026-1002"}
    critical_starts = [
        call["start_index"]
        for call in client.calls
        if call.get("cvss_v3_severity") == "CRITICAL"
    ]
    assert critical_starts == [0, 1]
    assert not state.incomplete_reasons


def test_zero_result_queries_are_complete() -> None:
    result = curated.collect_candidates(
        make_plan(),
        client=FakeClient(),  # type: ignore[arg-type]
        sleeper=lambda delay: None,
    )

    assert result.years[0].candidates == {}
    assert result.years[0].incomplete_reasons == set()
    assert result.stopped_reason is None


def test_duplicate_cve_across_cvss_versions_is_deduplicated() -> None:
    state = curated.YearCollection(year=2026)
    chunk = curated.build_date_chunks(2026, now=EARLY_NOW)[0]

    curated._inspect_candidate(
        state,
        make_wrapper("cve-2026-1234", version="3.1", score=9.7),
        chunk=chunk,
        normalizer=normalize_nvd_cve,
    )
    curated._inspect_candidate(
        state,
        make_wrapper("CVE-2026-1234", version="4.0", score=9.8),
        chunk=chunk,
        normalizer=normalize_nvd_cve,
    )

    assert list(state.candidates) == ["CVE-2026-1234"]
    assert state.duplicates == 1
    assert state.candidates["CVE-2026-1234"].normalized.cvss_version == "4.0"


def test_duplicate_cve_across_chunks_keeps_latest_deterministically() -> None:
    state = curated.YearCollection(year=2026)
    chunks = curated.build_date_chunks(
        2026,
        now=datetime(2026, 7, 1, tzinfo=UTC),
    )
    curated._inspect_candidate(
        state,
        make_wrapper(
            "CVE-2026-2222",
            published="2026-01-10T00:00:00Z",
            modified="2026-01-11T00:00:00Z",
        ),
        chunk=chunks[0],
        normalizer=normalize_nvd_cve,
    )
    curated._inspect_candidate(
        state,
        make_wrapper(
            "CVE-2026-2222",
            published="2026-04-10T00:00:00Z",
            modified="2026-04-11T00:00:00Z",
        ),
        chunk=chunks[1],
        normalizer=normalize_nvd_cve,
    )

    assert state.duplicates == 1
    assert (
        state.candidates["CVE-2026-2222"].normalized.source_modified_at
        == datetime(2026, 4, 11, tzinfo=UTC)
    )


def test_duplicate_replacement_is_independent_of_observation_order() -> None:
    chunk = curated.build_date_chunks(2026, now=EARLY_NOW)[0]
    lower = make_wrapper("CVE-2026-3333", version="3.1", score=9.7)
    higher = make_wrapper("CVE-2026-3333", version="4.0", score=9.9)
    selected_hashes: list[str] = []

    for wrappers in ((lower, higher), (higher, lower)):
        state = curated.YearCollection(year=2026)
        for wrapper in wrappers:
            curated._inspect_candidate(
                state,
                wrapper,
                chunk=chunk,
                normalizer=normalize_nvd_cve,
            )
        selected_hashes.append(
            state.candidates["CVE-2026-3333"].normalized.content_hash
        )
        assert state.duplicates == 1

    assert selected_hashes[0] == selected_hashes[1]


def candidate(
    cve_id: str,
    *,
    score: float,
    modified: str,
    kev: bool = False,
) -> curated.CuratedCandidate:
    wrapper = make_wrapper(
        cve_id,
        score=score,
        modified=modified,
        kev=kev,
    )
    return curated.CuratedCandidate(
        normalized=normalize_nvd_cve(wrapper),
        is_kev=kev,
    )


def test_ranking_uses_kev_score_modified_and_cve_tie_breaks() -> None:
    candidates = [
        candidate(
            "CVE-2026-1004",
            score=10.0,
            modified="2026-01-04T00:00:00Z",
        ),
        candidate(
            "CVE-2026-1003",
            score=9.9,
            modified="2026-01-03T00:00:00Z",
            kev=True,
        ),
        candidate(
            "CVE-2026-1002",
            score=9.9,
            modified="2026-01-03T00:00:00Z",
        ),
        candidate(
            "CVE-2026-1001",
            score=9.9,
            modified="2026-01-03T00:00:00Z",
        ),
        candidate(
            "CVE-2026-1005",
            score=9.9,
            modified="2026-01-02T00:00:00Z",
        ),
    ]

    ranked = sorted(candidates, key=curated._ranking_key)

    assert [entry.normalized.cve_id for entry in ranked] == [
        "CVE-2026-1003",
        "CVE-2026-1004",
        "CVE-2026-1001",
        "CVE-2026-1002",
        "CVE-2026-1005",
    ]


def test_exact_yearly_quotas_and_kev_count_are_reported() -> None:
    state = curated.YearCollection(year=2026)
    chunk = curated.build_date_chunks(2026, now=EARLY_NOW)[0]
    wrappers = quota_wrappers()
    wrappers[0]["cve"]["cisaExploitAdd"] = "2026-01-02"
    for wrapper in wrappers:
        curated._inspect_candidate(
            state,
            wrapper,
            chunk=chunk,
            normalizer=normalize_nvd_cve,
        )

    selection = curated.select_year(state)

    assert selection.selected_counts == curated.DEFAULT_QUOTAS
    assert selection.shortfalls == {severity: 0 for severity in curated.SEVERITY_ORDER}
    assert len(selection.selected) == 20
    assert selection.kev_prioritized_count == 1
    assert not selection.incomplete


def test_thousands_of_candidates_never_exceed_retained_pool() -> None:
    state = curated.YearCollection(year=2026)
    chunk = curated.build_date_chunks(2026, now=EARLY_NOW)[0]

    for index in range(2_000):
        curated._inspect_candidate(
            state,
            make_wrapper(
                f"CVE-2026-{10000 + index}",
                score=9.0 + ((index % 10) / 10),
                kev=index == 1_999,
            ),
            chunk=chunk,
            normalizer=normalize_nvd_cve,
        )

    critical = [
        candidate
        for candidate in state.candidates.values()
        if candidate.normalized.severity == "critical"
    ]
    assert len(critical) == curated.DEFAULT_QUOTAS["critical"]
    assert len(state.candidates) == curated.DEFAULT_QUOTAS["critical"]
    assert state.retention_discarded == 1_990
    assert "maximum retained candidate limit reached" in state.incomplete_reasons
    assert any(candidate.is_kev for candidate in critical)


def test_retention_ceiling_keeps_best_candidates_and_reports_incomplete() -> None:
    state = curated.YearCollection(year=2026)
    chunk = curated.build_date_chunks(2026, now=EARLY_NOW)[0]
    for index in range(12):
        curated._inspect_candidate(
            state,
            make_wrapper(
                f"CVE-2026-{7000 + index}",
                score=9.0 + (index / 100),
            ),
            chunk=chunk,
            normalizer=normalize_nvd_cve,
        )

    selection = curated.select_year(state)

    assert len(selection.selected) == 10
    assert selection.retention_discarded == 2
    assert selection.valid_unselected == 0
    assert selection.retained_counts["critical"] == 10
    assert selection.incomplete
    assert {candidate.normalized.cve_id for candidate in selection.selected} == {
        f"CVE-2026-{7000 + index}" for index in range(2, 12)
    }


def test_quota_shortfalls_are_exact_and_never_relabel_severity() -> None:
    state = curated.YearCollection(year=2026)
    chunk = curated.build_date_chunks(2026, now=EARLY_NOW)[0]
    curated._inspect_candidate(
        state,
        make_wrapper("CVE-2026-4444", severity="HIGH", score=8.0),
        chunk=chunk,
        normalizer=normalize_nvd_cve,
    )

    selection = curated.select_year(state)

    assert selection.selected_counts == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
    }
    assert selection.shortfalls == {
        "critical": 10,
        "high": 4,
        "medium": 3,
        "low": 2,
    }
    assert selection.incomplete


@pytest.mark.parametrize(
    "wrapper",
    [
        {"malformed": True},
        {
            "cve": {
                "id": "CVE-2026-5555",
                "published": "2026-01-01T01:00:00Z",
                "lastModified": "2026-01-02T01:00:00Z",
                "vulnStatus": "Analyzed",
                "metrics": {},
            }
        },
        make_wrapper("CVE-2026-5556", status="Rejected"),
    ],
)
def test_malformed_missing_cvss_and_rejected_candidates_do_not_use_slots(
    wrapper: dict[str, Any],
) -> None:
    state = curated.YearCollection(year=2026)
    curated._inspect_candidate(
        state,
        wrapper,
        chunk=curated.build_date_chunks(2026, now=EARLY_NOW)[0],
        normalizer=normalize_nvd_cve,
    )

    assert state.candidates == {}
    assert state.rejected == 1


def test_maximum_page_limit_marks_year_incomplete() -> None:
    client = FakeClient(
        lambda call: page(
            [make_wrapper("CVE-2026-6001")],
            start=call["start_index"],
            total=100,
        )
    )
    result = curated.collect_candidates(
        make_plan(max_pages=1),
        client=client,  # type: ignore[arg-type]
        sleeper=lambda delay: None,
    )

    assert "maximum candidate page limit reached" in result.years[0].incomplete_reasons
    assert result.stopped_reason is None


def test_maximum_request_limit_stops_collection_and_marks_year_incomplete() -> None:
    result = curated.collect_candidates(
        make_plan(max_requests=1),
        client=FakeClient(),  # type: ignore[arg-type]
        sleeper=lambda delay: None,
    )

    assert result.request_count == 1
    assert result.stopped_reason == "maximum total request limit reached"
    assert "maximum total request limit reached" in result.years[0].incomplete_reasons


@pytest.mark.parametrize(
    "error",
    [
        NvdRequestError("private timeout details"),
        NvdRateLimitError("private rate-limit details"),
    ],
)
def test_timeout_and_rate_limit_stop_collection_with_sanitized_reason(
    error: Exception,
) -> None:
    result = curated.collect_candidates(
        make_plan(),
        client=FakeClient(error=error),  # type: ignore[arg-type]
        sleeper=lambda delay: None,
    )

    assert result.stopped_reason == "NVD candidate request failed"
    assert "private" not in " ".join(result.years[0].incomplete_reasons)


def test_success_persists_selected_records_with_savepoints_and_one_commit() -> None:
    wrappers = quota_wrappers()
    client = FakeClient(
        lambda call: page(wrappers) if call.get("has_kev") else page([])
    )

    exit_code, stdout, stderr, session, _, services = run_fake(client=client)

    run = next(value for value in session.added if isinstance(value, IngestionRun))
    assert exit_code == 0
    assert stderr == ""
    assert run.status == "succeeded"
    assert run.records_created == 20
    assert run.records_skipped == 0
    assert run.records_failed == 0
    assert session.nested_transactions == 20
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed
    assert services.service is not None
    assert len(services.service.persisted) == 20
    assert services.service.source.checkpoint_value == "incremental-checkpoint"
    assert run.checkpoint_after is None
    assert "Capped or incomplete years: none" in stdout
    assert (
        "Maximum retained candidates per severity/year: "
        "critical=10, high=5, medium=3, low=2"
    ) in stdout


def test_audit_counters_reconcile_all_skipped_candidate_categories() -> None:
    wrappers = quota_wrappers()
    wrappers.extend(
        [
            make_wrapper("CVE-2026-9000"),
            make_wrapper("CVE-2026-9001"),
            {"malformed": True},
            make_wrapper("CVE-2026-1000"),
        ]
    )
    client = FakeClient(
        lambda call: page(wrappers) if call.get("has_kev") else page([])
    )

    exit_code, _, _, session, _, _ = run_fake(client=client)

    run = next(value for value in session.added if isinstance(value, IngestionRun))
    assert exit_code == 1
    assert run.records_fetched == 24
    assert run.records_created == 20
    assert run.records_skipped == 4
    assert run.records_failed == 0
    assert run.records_fetched == (
        run.records_created
        + run.records_updated
        + run.records_unchanged
        + run.records_skipped
        + run.records_failed
    )


def test_valid_retained_candidates_outside_quota_are_counted_as_skipped() -> None:
    wrappers = quota_wrappers()
    wrappers.extend(
        [
            make_wrapper("CVE-2026-9000", score=9.1),
            make_wrapper("CVE-2026-9001", score=9.0),
        ]
    )

    exit_code, _, _, session, _, _ = run_fake(
        client=FakeClient(
            lambda call: page(wrappers) if call.get("has_kev") else page([])
        ),
        retention_multiplier=2,
    )

    run = next(value for value in session.added if isinstance(value, IngestionRun))
    assert exit_code == 0
    assert run.records_fetched == 22
    assert run.records_created == 20
    assert run.records_skipped == 2
    assert run.records_fetched == (
        run.records_created
        + run.records_updated
        + run.records_unchanged
        + run.records_skipped
        + run.records_failed
    )


def test_completion_time_is_fresh_and_after_start_time() -> None:
    completion = EARLY_NOW + timedelta(minutes=17)
    clock_values = iter((EARLY_NOW, completion))
    wrappers = quota_wrappers()

    exit_code, _, _, session, _, _ = run_fake(
        client=FakeClient(
            lambda call: page(wrappers) if call.get("has_kev") else page([])
        ),
        clock=lambda: next(clock_values),
    )

    run = next(value for value in session.added if isinstance(value, IngestionRun))
    assert exit_code == 0
    assert run.started_at == EARLY_NOW
    assert run.completed_at == completion
    assert run.completed_at > run.started_at


def test_invalid_completion_clock_fails_safely_and_rolls_back() -> None:
    clock_values = iter((EARLY_NOW, EARLY_NOW.replace(tzinfo=None)))
    wrappers = quota_wrappers()

    exit_code, stdout, stderr, session, _, _ = run_fake(
        client=FakeClient(
            lambda call: page(wrappers) if call.get("has_kev") else page([])
        ),
        clock=lambda: next(clock_values),
    )

    assert exit_code == 1
    assert stdout == ""
    assert stderr == "Curated NVD ingestion failed unexpectedly.\n"
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed


def test_existing_update_unchanged_and_idempotent_outcomes_are_reused() -> None:
    wrappers = quota_wrappers()
    outcomes = ["updated", "unchanged"] + ["unchanged"] * 18
    services = ServiceFactory(outcomes=outcomes)

    exit_code, stdout, _, session, _, _ = run_fake(
        client=FakeClient(
            lambda call: page(wrappers) if call.get("has_kev") else page([])
        ),
        services=services,
    )

    run = next(value for value in session.added if isinstance(value, IngestionRun))
    assert exit_code == 0
    assert run.records_updated == 1
    assert run.records_unchanged == 19
    assert run.records_created == 0
    assert len(
        [value for value in session.added if isinstance(value, IngestionRunRecord)]
    ) == 20
    assert "Updated: 1" in stdout
    assert "Unchanged: 19" in stdout


def test_persistence_failure_is_sanitized_and_committed_as_partial() -> None:
    marker = "postgresql://private:password@host/database"
    wrappers = quota_wrappers()
    services = ServiceFactory(error=NvdPersistenceError(marker))

    exit_code, stdout, stderr, session, _, _ = run_fake(
        client=FakeClient(
            lambda call: page(wrappers) if call.get("has_kev") else page([])
        ),
        services=services,
    )

    assert exit_code == 1
    assert marker not in stdout
    assert marker not in stderr
    assert session.commits == 1
    assert session.rollbacks == 0
    assert any(isinstance(value, IngestionError) for value in session.added)
    run = next(value for value in session.added if isinstance(value, IngestionRun))
    assert run.status == "partial"
    assert run.records_failed == 20


def test_uncaught_database_commit_failure_rolls_back_and_closes() -> None:
    wrappers = quota_wrappers()
    session = FakeSession(fail_commit=True)

    exit_code, stdout, stderr, returned, _, _ = run_fake(
        client=FakeClient(
            lambda call: page(wrappers) if call.get("has_kev") else page([])
        ),
        session=session,
    )

    assert exit_code == 1
    assert stdout == ""
    assert "database operation" in stderr
    assert "private" not in stderr
    assert returned.rollbacks == 1
    assert returned.closed


def test_api_key_absent_from_output_errors_and_client_arguments() -> None:
    secret = "synthetic-nvd-key-do-not-use"
    client = FakeClient(error=NvdRequestError(f"timeout {secret}"))

    exit_code, stdout, stderr, session, factory, _ = run_fake(
        client=client,
        api_key=SecretStr(secret),
    )

    assert exit_code == 1
    assert secret not in stdout
    assert secret not in stderr
    assert secret not in repr(client)
    assert factory.api_keys[0] is not None
    assert factory.api_keys[0].get_secret_value() == secret
    assert session.commits == 1
    assert client.closed


def test_planning_mode_makes_no_network_or_database_access(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        curated,
        "get_settings",
        lambda: pytest.fail("planning must not load runtime settings"),
    )
    monkeypatch.setattr(
        curated,
        "run_curated_ingestion",
        lambda **kwargs: pytest.fail("planning must not execute ingestion"),
    )

    exit_code = curated.main(
        ["--plan", "--start-year", "2024", "--end-year", "2026"],
        clock=lambda: NOW,
    )

    output = capsys.readouterr()
    assert exit_code == 0
    assert output.err == ""
    assert "no network or database access" in output.out
    assert "Years: 2024-2026" in output.out
    assert "critical=10, high=5, medium=3, low=2" in output.out
    assert "Maximum total requests: 400" in output.out
    assert (
        "Maximum retained candidates per severity/year: "
        "critical=10, high=5, medium=3, low=2"
    ) in output.out
    assert "Maximum retries: 0" in output.out


@pytest.mark.parametrize(
    "arguments",
    [
        ["--start-year", "2019"],
        ["--start-year", "2026", "--end-year", "2025"],
        ["--end-year", "2027"],
        ["--chunk-days", "121"],
        ["--results-per-page", "201"],
        ["--max-pages-per-query", "11"],
        ["--max-requests", "1001"],
        ["--retention-multiplier", "6"],
    ],
)
def test_cli_rejects_invalid_bounded_arguments(arguments: list[str], capsys) -> None:
    assert curated.main(arguments, clock=lambda: NOW) == 2
    assert "curated NVD" in capsys.readouterr().err
