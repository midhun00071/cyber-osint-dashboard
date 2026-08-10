from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from statistics import median
from threading import Barrier, Lock
import time

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.pool import QueuePool

from app.api.v1.routes import analyst as analyst_routes
from app.db.session import get_db_session
from app.main import (
    MAX_REQUEST_BODY_BYTES,
    MAX_REQUEST_BODY_MESSAGES,
    app,
)
from app.orchestration.contracts import (
    ProgressProposal,
    ProgressSnapshot,
    ProgressStorage,
    QuotaObservation,
    ReconciledCounters,
    ResultStatus,
    RunHandle,
    SourceAttemptIdentity,
    SourceExecutionResult,
    list_source_policies,
)
from app.orchestration.flows import run_source_once
from app.security.dependencies import (
    require_analysis_use,
    require_audit_read,
    require_content_read,
    require_ingestion_read,
    require_report_read,
    require_source_read,
)
from app.services.analyst_query_service import AnalystQueryService
from app.services.article_query_service import ArticleQueryService
from app.services.audit_query_service import AuditQueryService
from app.services.dashboard_summary_service import DashboardSummaryService
from app.services.intelligence_query_service import IntelligenceQueryService
from app.services.operations_query_service import OperationsQueryService
from app.services.system_health_service import SystemHealthService
from tests.c06_auth_test_support import principal


NOW = datetime(2026, 8, 10, 8, 17, tzinfo=UTC)
API_LOAD_CONCURRENCY = 12
API_LOAD_ROUNDS = 12
API_LOAD_PATHS = (
    "/api/v1/dashboard/summary",
    "/api/v1/articles",
    "/api/v1/intelligence/items?item_type=vulnerability",
    "/api/v1/analysis/uae-intelligence",
    "/api/v1/analysis/indicators?q=example.com",
    "/api/v1/ingestion/operations/summary",
    "/api/v1/sources",
    "/api/v1/ingestion/runs",
    "/api/v1/reports/catalog",
    "/api/v1/system/health",
    "/api/v1/audit/events",
)


def _dashboard_summary(filters):
    return {
        "window_days": filters.window_days,
        "window_start": NOW,
        "window_end": NOW,
        "generated_at": NOW,
        "metrics": {
            "critical_vulnerability_count": 0,
            "kev_vulnerability_count": 0,
            "active_article_count": 0,
            "uae_related_item_count": 0,
        },
        "counts": {
            "active_intelligence_items": 0,
            "critical_vulnerabilities": 0,
            "high_severity_vulnerabilities": 0,
            "cisa_kev_listed_vulnerabilities": 0,
            "high_epss_vulnerabilities": 0,
            "uae_relevant_intelligence": 0,
            "intelligence_items_collected_in_window": 0,
        },
        "thresholds": {"high_epss_minimum": 0.7},
        "ingestion": {"last_successful_ingestion_at": None},
        "latest_articles": [],
        "latest_fetch": None,
    }


def _health_snapshot():
    names = (
        "backend",
        "database",
        "prefect_server",
        "prefect_worker",
        "ingestion_operations",
        "source_freshness",
        "storage",
        "deployment_identity",
    )
    return {
        "status": "healthy",
        "generated_at": NOW,
        "version": "0.1.0",
        "commit_sha": "b" * 40,
        "components": [
            {
                "name": name,
                "status": "healthy",
                "summary": "Synthetic bounded release observation.",
                "observations": {},
            }
            for name in names
        ],
    }


@pytest.fixture
def release_api(monkeypatch: pytest.MonkeyPatch):
    administrator = principal()
    for dependency in (
        require_analysis_use,
        require_audit_read,
        require_content_read,
        require_ingestion_read,
        require_report_read,
        require_source_read,
        analyst_routes.indicator_rate_limit,
        analyst_routes.uae_rate_limit,
    ):
        app.dependency_overrides[dependency] = lambda: administrator
    app.dependency_overrides[get_db_session] = lambda: object()

    monkeypatch.setattr(
        DashboardSummaryService,
        "get_summary",
        lambda _self, filters: _dashboard_summary(filters),
    )
    monkeypatch.setattr(
        ArticleQueryService,
        "list_articles",
        lambda _self, filters: {
            "items": [],
            "total": 0,
            "limit": filters.limit,
            "offset": filters.offset,
        },
    )
    monkeypatch.setattr(
        IntelligenceQueryService,
        "list_items",
        lambda _self, filters: {
            "items": [],
            "total": 0,
            "limit": filters.limit,
            "offset": filters.offset,
        },
    )
    monkeypatch.setattr(
        AnalystQueryService,
        "list_uae_intelligence",
        lambda _self, filters: {
            "items": [],
            "total": 0,
            "limit": filters.limit,
            "offset": filters.offset,
        },
    )
    monkeypatch.setattr(
        AnalystQueryService,
        "list_indicators",
        lambda _self, filters: {
            "items": [],
            "total": 0,
            "limit": filters.limit,
            "offset": filters.offset,
        },
    )
    monkeypatch.setattr(
        OperationsQueryService,
        "operations_summary",
        lambda _self: {
            "generated_at": NOW,
            "deployment_state": "inactive",
            "configured_handler_count": 0,
            "active_cycle_count": 0,
            "active_run_count": 0,
            "source_attention_count": 0,
            "run_counts_by_status": {},
            "latest_cycle": None,
        },
    )
    monkeypatch.setattr(
        OperationsQueryService,
        "list_sources",
        lambda _self, **_kwargs: ([], 0),
    )
    monkeypatch.setattr(
        OperationsQueryService,
        "list_runs",
        lambda _self, **_kwargs: ([], 0),
    )
    monkeypatch.setattr(
        SystemHealthService,
        "snapshot",
        lambda _self, **_kwargs: _health_snapshot(),
    )
    monkeypatch.setattr(
        AuditQueryService,
        "list_events",
        lambda _self, _filters: ([], 0),
    )

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * percentile))
    return ordered[index]


def test_bounded_concurrent_release_api_reads_are_schema_valid(release_api) -> None:
    requests = list(API_LOAD_PATHS) * API_LOAD_ROUNDS

    def request(path: str) -> float:
        started = time.perf_counter()
        response = release_api.get(path)
        elapsed_ms = (time.perf_counter() - started) * 1_000
        assert response.status_code == 200, (path, response.status_code, response.text)
        assert "traceback" not in response.text.casefold()
        response.json()
        return elapsed_ms

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=API_LOAD_CONCURRENCY) as executor:
        timings = list(executor.map(request, requests))
    elapsed = time.perf_counter() - started

    assert len(timings) == len(requests) == 132
    print(
        "C11_API_LOAD "
        f"requests={len(requests)} concurrency={API_LOAD_CONCURRENCY} "
        f"success={len(timings)} failure=0 elapsed_seconds={elapsed:.3f} "
        f"median_ms={median(timings):.3f} "
        f"p95_ms={_percentile(timings, 0.95):.3f} max_ms={max(timings):.3f}"
    )


def test_release_read_paths_remain_anonymous_deny_by_default() -> None:
    with TestClient(app) as client:
        for path in API_LOAD_PATHS:
            response = client.get(path)
            assert response.status_code == 401, (path, response.status_code)
            assert response.json() == {"detail": "Authentication required."}
            assert response.headers["Cache-Control"] == "no-store"


def test_private_backend_resource_limits_remain_frozen() -> None:
    assert MAX_REQUEST_BODY_BYTES == 1_000_000
    assert MAX_REQUEST_BODY_MESSAGES == 1_024


def test_bounded_pool_times_out_then_reuses_released_connection() -> None:
    engine = create_engine(
        "sqlite://",
        poolclass=QueuePool,
        pool_size=1,
        max_overflow=0,
        pool_timeout=0.05,
        connect_args={"check_same_thread": False},
        hide_parameters=True,
    )
    first = engine.connect()
    started = time.perf_counter()
    try:
        with pytest.raises(SQLAlchemyTimeoutError) as captured:
            with engine.connect():
                pass
        elapsed = time.perf_counter() - started
        assert elapsed >= 0.03
        assert engine.pool.size() == 1
        assert engine.pool.overflow() == 0
        assert engine.pool.checkedout() == 1
        message = str(captured.value).casefold()
        assert "password" not in message
        assert "database_url" not in message
    finally:
        first.close()

    with engine.connect() as reused:
        assert reused.exec_driver_sql("select 1").scalar_one() == 1
    assert engine.pool.checkedout() == 0
    assert engine.pool.checkedin() == 1
    engine.dispose()


class _ConcurrentPersistence:
    def __init__(self, policies) -> None:
        self._lock = Lock()
        self._next_run_id = 100
        self._policies = {policy.source_slug: policy for policy in policies}
        self.runs: dict[str, RunHandle] = {}
        self.runs_by_id: dict[int, RunHandle] = {}
        self.progress: dict[str, ProgressSnapshot] = {}

    def acquire_scheduled_cycle(self, _scheduled_for, _sources_expected):
        raise AssertionError("The source-level test must not acquire a parent cycle.")

    def _new_run(self, source_slug: str, attempt_number: int) -> RunHandle:
        self._next_run_id += 1
        run = RunHandle(
            SourceAttemptIdentity(
                source_slug=source_slug,
                cycle_id=1,
                run_id=self._next_run_id,
                attempt_number=attempt_number,
                state_version=1,
            ),
            "running",
        )
        self.runs[source_slug] = run
        self.runs_by_id[run.identity.run_id] = run
        return run

    def acquire_source_run(self, _cycle_id, source_slug):
        with self._lock:
            return self.runs.get(source_slug) or self._new_run(source_slug, 0)

    def acquire_retry(self, prior_run_id):
        with self._lock:
            prior = self.runs_by_id[prior_run_id]
            return self._new_run(
                prior.identity.source_slug,
                prior.identity.attempt_number + 1,
            )

    def read_progress(self, policy):
        with self._lock:
            return self.progress.get(policy.source_slug)

    def read_quota(self, policy):
        return QuotaObservation(policy.quota_policy_key)

    def record_result(self, run, result):
        policy = self._policies[result.source_slug]
        status = result.status.value
        if (
            result.status in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}
            and policy.progress_storage is not ProgressStorage.NONE
        ):
            status = "checkpoint_pending"
        committed = replace(run, status=status, counters=result.counters)
        with self._lock:
            self.runs[result.source_slug] = committed
            self.runs_by_id[committed.identity.run_id] = committed
        return committed

    def advance_progress(self, run, proposal):
        with self._lock:
            current = self.progress.get(run.identity.source_slug)
            current_version = 0 if current is None else current.version
            if proposal.expected_previous_version != current_version:
                raise RuntimeError("synthetic progress conflict")
            self.progress[run.identity.source_slug] = ProgressSnapshot(
                storage=proposal.storage,
                kind=proposal.kind,
                name=proposal.name,
                value=proposal.value,
                version=current_version + 1,
            )
            status = (
                "success"
                if run.counters.created + run.counters.updated
                else "no_change"
            )
            committed = replace(
                run,
                status=status,
                identity=replace(
                    run.identity,
                    state_version=run.identity.state_version + 1,
                ),
            )
            self.runs[run.identity.source_slug] = committed
            self.runs_by_id[committed.identity.run_id] = committed
            return committed

    def abandon_pending_progress(self, _run, _status, _safe_message):
        raise AssertionError("No pending progress abandonment was expected.")

    def read_cycle_evidence(self, _cycle_id):
        raise AssertionError("The source-level test must not read parent evidence.")

    def finalize_cycle(self, _result, _safe_summary):
        raise AssertionError("The source-level test must not finalize a parent cycle.")


class _ConcurrentHandler:
    def __init__(self, barrier: Barrier, *, fail: bool = False) -> None:
        self.barrier = barrier
        self.fail = fail
        self.attempts = 0

    def execute(self, context):
        self.attempts += 1
        if self.attempts == 1:
            self.barrier.wait(timeout=3)
        if self.fail:
            raise TimeoutError("private provider diagnostic must be classified")
        policy = context.policy
        assert policy.progress_kind is not None
        value = (
            NOW
            if policy.progress_kind.value == "modified_since"
            else f"c11-{policy.source_slug}-checkpoint"
        )
        return SourceExecutionResult(
            source_slug=policy.source_slug,
            status=ResultStatus.SUCCESS,
            counters=ReconciledCounters(fetched=1, created=1),
            safe_message="The mocked source committed one bounded record.",
            progress_proposal=ProgressProposal(
                storage=policy.progress_storage,
                kind=policy.progress_kind,
                name=policy.progress_kind.value,
                value=value,
                expected_previous_version=0,
            ),
        )

    def reconstruct_progress(self, _context, _committed_counters):
        raise AssertionError("No recovery was expected.")


def test_mocked_concurrent_sources_isolate_failure_and_progress(monkeypatch) -> None:
    policies_by_slug = {policy.source_slug: policy for policy in list_source_policies()}
    policies = tuple(
        policies_by_slug[slug] for slug in ("cisa-kev", "nvd", "first-epss")
    )
    persistence = _ConcurrentPersistence(policies)
    barrier = Barrier(3)
    handlers = {
        "cisa-kev": _ConcurrentHandler(barrier),
        "nvd": _ConcurrentHandler(barrier, fail=True),
        "first-epss": _ConcurrentHandler(barrier),
    }

    @contextmanager
    def no_timeout(_seconds):
        yield

    monkeypatch.setattr("app.orchestration.flows.prefect_timeout", no_timeout)

    def execute(policy):
        return run_source_once(
            policy=policy,
            cycle_id=1,
            scheduled_for=NOW,
            handler=handlers[policy.source_slug],
            persistence=persistence,
            retry_sleep=lambda _seconds: None,
        )

    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(execute, policies))

    by_slug = {result.source_slug: result for result in results}
    assert by_slug["cisa-kev"].status is ResultStatus.SUCCESS
    assert by_slug["first-epss"].status is ResultStatus.SUCCESS
    assert by_slug["nvd"].status is ResultStatus.FAILED
    assert set(persistence.progress) == {"cisa-kev", "first-epss"}
    assert persistence.progress["cisa-kev"].version == 1
    assert persistence.progress["first-epss"].version == 1
    assert "nvd" not in persistence.progress
    assert persistence.runs["nvd"].status == "failed"
    assert handlers["nvd"].attempts == policies_by_slug["nvd"].retry_plan.maximum_attempts
    assert "private provider" not in by_slug["nvd"].safe_message.casefold()
