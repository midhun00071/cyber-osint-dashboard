"""Manual, deterministic, bounded multi-year NVD sample ingestion."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import sys
import time
from typing import Any, TextIO

from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_session_factory
from app.ingestion.collectors.nvd_client import (
    AUTHENTICATED_DELAY_SECONDS,
    NvdClient,
    NvdClientError,
    UNAUTHENTICATED_DELAY_SECONDS,
)
from app.ingestion.normalizers.nvd import (
    NormalizedNvdCve,
    NvdNormalizationError,
    normalize_nvd_cve,
)
from app.ingestion.services.nvd_ingestion_service import (
    NvdIngestionService,
    NvdPersistenceError,
    NvdPersistenceResult,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord


MIN_YEAR = 2020
MAX_YEAR_SPAN = 25
DEFAULT_CHUNK_DAYS = 90
MAX_CHUNK_DAYS = 120
DEFAULT_RESULTS_PER_PAGE = 50
MAX_RESULTS_PER_PAGE = 200
DEFAULT_MAX_PAGES_PER_QUERY = 2
MAX_PAGES_PER_QUERY = 10
DEFAULT_MAX_REQUESTS = 400
MAX_REQUESTS = 1000
DEFAULT_RETENTION_MULTIPLIER = 1
MAX_RETENTION_MULTIPLIER = 5
MAX_RETRIES = 0
MILLISECOND = timedelta(milliseconds=1)
SELECTABLE_CVSS_VERSIONS = frozenset({"3.0", "3.1", "4.0"})
SEVERITY_ORDER = ("critical", "high", "medium", "low")
DEFAULT_QUOTAS = {
    "critical": 10,
    "high": 5,
    "medium": 3,
    "low": 2,
}


class CuratedCliArgumentError(ValueError):
    """The curated NVD command arguments were invalid."""


class CuratedCliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CuratedCliArgumentError("Invalid curated NVD ingestion arguments.")


@dataclass(frozen=True, slots=True)
class DateChunk:
    year: int
    sequence: int
    start: datetime
    end: datetime


@dataclass(frozen=True, slots=True)
class CuratedPlan:
    start_year: int
    end_year: int
    now: datetime
    chunks_by_year: dict[int, tuple[DateChunk, ...]]
    results_per_page: int
    max_pages_per_query: int
    max_requests: int
    retained_limits: dict[str, int]


@dataclass(frozen=True, slots=True)
class CuratedCandidate:
    normalized: NormalizedNvdCve
    is_kev: bool


@dataclass(slots=True)
class YearCollection:
    year: int
    retained_limits: dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_QUOTAS)
    )
    candidates: dict[str, CuratedCandidate] = field(default_factory=dict)
    candidates_inspected: int = 0
    rejected: int = 0
    duplicates: int = 0
    retention_discarded: int = 0
    incomplete_reasons: set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class YearSelection:
    year: int
    selected: tuple[CuratedCandidate, ...]
    selected_counts: dict[str, int]
    shortfalls: dict[str, int]
    candidates_inspected: int
    rejected: int
    duplicates: int
    retention_discarded: int
    valid_unselected: int
    retained_counts: dict[str, int]
    incomplete_reasons: tuple[str, ...]

    @property
    def kev_prioritized_count(self) -> int:
        return sum(candidate.is_kev for candidate in self.selected)

    @property
    def incomplete(self) -> bool:
        return bool(self.incomplete_reasons or any(self.shortfalls.values()))

    @property
    def skipped_count(self) -> int:
        return (
            self.rejected
            + self.duplicates
            + self.retention_discarded
            + self.valid_unselected
        )


@dataclass(slots=True)
class CollectionResult:
    years: list[YearCollection]
    request_count: int = 0
    stopped_reason: str | None = None


def _bounded_integer(name: str, minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer.") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}."
            )
        return parsed

    return parse


def _build_parser(current_year: int) -> CuratedCliArgumentParser:
    parser = CuratedCliArgumentParser(
        description=(
            "Manually build and persist a bounded representative multi-year NVD sample."
        ),
    )
    parser.add_argument(
        "--start-year",
        type=_bounded_integer("start year", MIN_YEAR, current_year),
        default=MIN_YEAR,
    )
    parser.add_argument(
        "--end-year",
        type=_bounded_integer("end year", MIN_YEAR, current_year),
        default=current_year,
    )
    parser.add_argument(
        "--chunk-days",
        type=_bounded_integer("chunk days", 1, MAX_CHUNK_DAYS),
        default=DEFAULT_CHUNK_DAYS,
    )
    parser.add_argument(
        "--results-per-page",
        type=_bounded_integer(
            "results per page",
            1,
            MAX_RESULTS_PER_PAGE,
        ),
        default=DEFAULT_RESULTS_PER_PAGE,
    )
    parser.add_argument(
        "--max-pages-per-query",
        type=_bounded_integer(
            "maximum pages per query",
            1,
            MAX_PAGES_PER_QUERY,
        ),
        default=DEFAULT_MAX_PAGES_PER_QUERY,
    )
    parser.add_argument(
        "--max-requests",
        type=_bounded_integer("maximum requests", 1, MAX_REQUESTS),
        default=DEFAULT_MAX_REQUESTS,
    )
    parser.add_argument(
        "--retention-multiplier",
        type=_bounded_integer(
            "retention multiplier",
            1,
            MAX_RETENTION_MULTIPLIER,
        ),
        default=DEFAULT_RETENTION_MULTIPLIER,
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Validate and print the no-network, no-database execution plan.",
    )
    return parser


def _valid_integer(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _normalize_clock(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CuratedCliArgumentError(
            "Curated NVD ingestion requires a timezone-aware clock."
        )
    utc_value = value.astimezone(UTC)
    return utc_value.replace(microsecond=(utc_value.microsecond // 1000) * 1000)


def validate_parameters(
    *,
    start_year: int,
    end_year: int,
    chunk_days: int,
    results_per_page: int,
    max_pages_per_query: int,
    max_requests: int,
    retention_multiplier: int,
    current_year: int,
) -> None:
    if not (
        _valid_integer(current_year, MIN_YEAR, 9999)
        and _valid_integer(start_year, MIN_YEAR, current_year)
        and _valid_integer(end_year, MIN_YEAR, current_year)
        and _valid_integer(chunk_days, 1, MAX_CHUNK_DAYS)
        and _valid_integer(results_per_page, 1, MAX_RESULTS_PER_PAGE)
        and _valid_integer(
            max_pages_per_query,
            1,
            MAX_PAGES_PER_QUERY,
        )
        and _valid_integer(max_requests, 1, MAX_REQUESTS)
        and _valid_integer(
            retention_multiplier,
            1,
            MAX_RETENTION_MULTIPLIER,
        )
    ):
        raise CuratedCliArgumentError("Invalid curated NVD ingestion parameters.")
    if start_year > end_year:
        raise CuratedCliArgumentError(
            "The curated NVD start year must not be after the end year."
        )
    if end_year - start_year + 1 > MAX_YEAR_SPAN:
        raise CuratedCliArgumentError(
            "The curated NVD year range exceeds the approved span."
        )


def build_date_chunks(
    year: int,
    *,
    now: datetime,
    chunk_days: int = DEFAULT_CHUNK_DAYS,
) -> tuple[DateChunk, ...]:
    """Return gap-free, non-overlapping millisecond publication chunks."""

    normalized_now = _normalize_clock(now)
    if not _valid_integer(year, MIN_YEAR, normalized_now.year):
        raise CuratedCliArgumentError("The curated NVD year is invalid.")
    if not _valid_integer(chunk_days, 1, MAX_CHUNK_DAYS):
        raise CuratedCliArgumentError("The curated NVD chunk size is invalid.")

    year_start = datetime(year, 1, 1, tzinfo=UTC)
    year_end = (
        normalized_now
        if year == normalized_now.year
        else datetime(year + 1, 1, 1, tzinfo=UTC) - MILLISECOND
    )
    chunks: list[DateChunk] = []
    start = year_start
    sequence = 1
    while start <= year_end:
        end = min(
            start + timedelta(days=chunk_days) - MILLISECOND,
            year_end,
        )
        chunks.append(DateChunk(year=year, sequence=sequence, start=start, end=end))
        start = end + MILLISECOND
        sequence += 1
    return tuple(chunks)


def build_plan(
    *,
    start_year: int,
    end_year: int,
    chunk_days: int,
    results_per_page: int,
    max_pages_per_query: int,
    max_requests: int,
    now: datetime,
    retention_multiplier: int = DEFAULT_RETENTION_MULTIPLIER,
) -> CuratedPlan:
    normalized_now = _normalize_clock(now)
    validate_parameters(
        start_year=start_year,
        end_year=end_year,
        chunk_days=chunk_days,
        results_per_page=results_per_page,
        max_pages_per_query=max_pages_per_query,
        max_requests=max_requests,
        retention_multiplier=retention_multiplier,
        current_year=normalized_now.year,
    )
    return CuratedPlan(
        start_year=start_year,
        end_year=end_year,
        now=normalized_now,
        chunks_by_year={
            year: build_date_chunks(
                year,
                now=normalized_now,
                chunk_days=chunk_days,
            )
            for year in range(start_year, end_year + 1)
        },
        results_per_page=results_per_page,
        max_pages_per_query=max_pages_per_query,
        max_requests=max_requests,
        retained_limits={
            severity: quota * retention_multiplier
            for severity, quota in DEFAULT_QUOTAS.items()
        },
    )


def print_plan(plan: CuratedPlan, stdout: TextIO = sys.stdout) -> None:
    print("Curated NVD planning mode (no network or database access).", file=stdout)
    print(f"Years: {plan.start_year}-{plan.end_year}", file=stdout)
    print(f"Yearly quotas: {_quota_text(DEFAULT_QUOTAS)}", file=stdout)
    for year, chunks in plan.chunks_by_year.items():
        print(f"{year} chunks ({len(chunks)}):", file=stdout)
        for chunk in chunks:
            print(
                f"  {chunk.sequence}: {_format_datetime(chunk.start)} "
                f"through {_format_datetime(chunk.end)}",
                file=stdout,
            )
    print(f"Results per page: {plan.results_per_page}", file=stdout)
    print(f"Maximum candidate pages per query: {plan.max_pages_per_query}", file=stdout)
    print(f"Maximum total requests: {plan.max_requests}", file=stdout)
    print(
        "Maximum retained candidates per severity/year: "
        f"{_quota_text(plan.retained_limits)}",
        file=stdout,
    )
    print(f"Maximum retries: {MAX_RETRIES}", file=stdout)


def _candidate_queries() -> tuple[dict[str, object], ...]:
    queries: list[dict[str, object]] = [{"has_kev": True}]
    for severity in SEVERITY_ORDER:
        queries.append({"cvss_v4_severity": severity.upper()})
        queries.append({"cvss_v3_severity": severity.upper()})
    return tuple(queries)


def collect_candidates(
    plan: CuratedPlan,
    *,
    client: NvdClient,
    normalizer: Callable[[dict[str, Any]], NormalizedNvdCve] = normalize_nvd_cve,
    sleeper: Callable[[float], None] = time.sleep,
    request_delay: float = UNAUTHENTICATED_DELAY_SECONDS,
) -> CollectionResult:
    """Collect a bounded deterministic candidate pool for every planned year."""

    result = CollectionResult(
        years=[
            YearCollection(
                year=year,
                retained_limits=dict(plan.retained_limits),
            )
            for year in range(plan.start_year, plan.end_year + 1)
        ]
    )
    stop_all = False
    for year_index, year_state in enumerate(result.years):
        for chunk in plan.chunks_by_year[year_state.year]:
            for query in _candidate_queries():
                if result.request_count >= plan.max_requests:
                    reason = "maximum total request limit reached"
                    year_state.incomplete_reasons.add(reason)
                    result.stopped_reason = reason
                    stop_all = True
                    break
                start_index = 0
                page_number = 0
                while page_number < plan.max_pages_per_query:
                    if result.request_count >= plan.max_requests:
                        reason = "maximum total request limit reached"
                        year_state.incomplete_reasons.add(reason)
                        result.stopped_reason = reason
                        stop_all = True
                        break
                    if result.request_count > 0:
                        sleeper(request_delay)
                    result.request_count += 1
                    try:
                        page = client.fetch_publication_page(
                            chunk.start,
                            chunk.end,
                            start_index=start_index,
                            results_per_page=plan.results_per_page,
                            **query,
                        )
                    except NvdClientError:
                        reason = "NVD candidate request failed"
                        year_state.incomplete_reasons.add(reason)
                        result.stopped_reason = reason
                        stop_all = True
                        break
                    page_number += 1
                    if page.start_index != start_index:
                        reason = "NVD candidate pagination mismatch"
                        year_state.incomplete_reasons.add(reason)
                        result.stopped_reason = reason
                        stop_all = True
                        break

                    for wrapper in page.vulnerabilities:
                        _inspect_candidate(
                            year_state,
                            wrapper,
                            chunk=chunk,
                            normalizer=normalizer,
                        )

                    next_index = page.start_index + len(page.vulnerabilities)
                    if next_index >= page.total_results:
                        break
                    if not page.vulnerabilities or next_index <= start_index:
                        reason = "NVD candidate pagination stopped"
                        year_state.incomplete_reasons.add(reason)
                        result.stopped_reason = reason
                        stop_all = True
                        break
                    if page_number >= plan.max_pages_per_query:
                        year_state.incomplete_reasons.add(
                            "maximum candidate page limit reached"
                        )
                        break
                    start_index = next_index
                if stop_all:
                    break
            if stop_all:
                break
        if stop_all:
            for remaining in result.years[year_index + 1 :]:
                remaining.incomplete_reasons.add(
                    result.stopped_reason or "candidate collection stopped"
                )
            break
    return result


def _inspect_candidate(
    year_state: YearCollection,
    wrapper: dict[str, Any],
    *,
    chunk: DateChunk,
    normalizer: Callable[[dict[str, Any]], NormalizedNvdCve],
) -> None:
    year_state.candidates_inspected += 1
    try:
        normalized = normalizer(wrapper)
    except (NvdNormalizationError, TypeError, ValueError):
        year_state.rejected += 1
        return

    if (
        normalized.status == "archived"
        or normalized.cvss_score is None
        or normalized.cvss_version not in SELECTABLE_CVSS_VERSIONS
        or normalized.severity not in DEFAULT_QUOTAS
        or not chunk.start <= normalized.source_published_at <= chunk.end
    ):
        year_state.rejected += 1
        return

    candidate = CuratedCandidate(
        normalized=normalized,
        is_kev=_wrapper_has_kev(wrapper),
    )
    existing = year_state.candidates.get(normalized.cve_id)
    if existing is not None:
        year_state.duplicates += 1
        preferred = _preferred_duplicate(existing, candidate)
        if preferred is existing:
            return
        del year_state.candidates[normalized.cve_id]
        _retain_candidate(year_state, candidate)
        return
    _retain_candidate(year_state, candidate)


def _retain_candidate(
    year_state: YearCollection,
    candidate: CuratedCandidate,
) -> None:
    severity = candidate.normalized.severity
    limit = year_state.retained_limits[severity]
    retained_for_severity = [
        retained
        for retained in year_state.candidates.values()
        if retained.normalized.severity == severity
    ]
    if len(retained_for_severity) < limit:
        year_state.candidates[candidate.normalized.cve_id] = candidate
        return

    year_state.incomplete_reasons.add("maximum retained candidate limit reached")
    worst_retained = max(retained_for_severity, key=_ranking_key)
    if _ranking_key(candidate) < _ranking_key(worst_retained):
        del year_state.candidates[worst_retained.normalized.cve_id]
        year_state.candidates[candidate.normalized.cve_id] = candidate
    year_state.retention_discarded += 1


def _wrapper_has_kev(wrapper: dict[str, Any]) -> bool:
    cve = wrapper.get("cve")
    if not isinstance(cve, dict):
        return False
    value = cve.get("cisaExploitAdd")
    return isinstance(value, str) and bool(value.strip())


def _preferred_duplicate(
    first: CuratedCandidate,
    second: CuratedCandidate,
) -> CuratedCandidate:
    def key(candidate: CuratedCandidate) -> tuple[object, ...]:
        score = candidate.normalized.cvss_score or Decimal("-1")
        return (
            not candidate.is_kev,
            -score,
            -candidate.normalized.source_modified_at.timestamp(),
            candidate.normalized.content_hash,
        )

    return min((first, second), key=key)


def select_year(year_state: YearCollection) -> YearSelection:
    selected: list[CuratedCandidate] = []
    counts: dict[str, int] = {}
    shortfalls: dict[str, int] = {}
    retained_counts: dict[str, int] = {}
    for severity in SEVERITY_ORDER:
        ranked = sorted(
            (
                candidate
                for candidate in year_state.candidates.values()
                if candidate.normalized.severity == severity
            ),
            key=_ranking_key,
        )
        quota = DEFAULT_QUOTAS[severity]
        chosen = ranked[:quota]
        selected.extend(chosen)
        retained_counts[severity] = len(ranked)
        counts[severity] = len(chosen)
        shortfalls[severity] = quota - len(chosen)
    valid_unselected = len(year_state.candidates) - len(selected)
    return YearSelection(
        year=year_state.year,
        selected=tuple(selected),
        selected_counts=counts,
        shortfalls=shortfalls,
        candidates_inspected=year_state.candidates_inspected,
        rejected=year_state.rejected,
        duplicates=year_state.duplicates,
        retention_discarded=year_state.retention_discarded,
        valid_unselected=valid_unselected,
        retained_counts=retained_counts,
        incomplete_reasons=tuple(sorted(year_state.incomplete_reasons)),
    )


def _ranking_key(candidate: CuratedCandidate) -> tuple[object, ...]:
    normalized = candidate.normalized
    assert normalized.cvss_score is not None
    return (
        not candidate.is_kev,
        -normalized.cvss_score,
        -normalized.source_modified_at.timestamp(),
        normalized.cve_id,
    )


def run_curated_ingestion(
    *,
    start_year: int,
    end_year: int,
    chunk_days: int,
    results_per_page: int,
    max_pages_per_query: int,
    max_requests: int,
    api_key: SecretStr | None,
    retention_multiplier: int = DEFAULT_RETENTION_MULTIPLIER,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    client_factory: Callable[..., NvdClient] = NvdClient,
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    normalizer: Callable[[dict[str, Any]], NormalizedNvdCve] = normalize_nvd_cve,
    service_factory: Callable[..., NvdIngestionService] = NvdIngestionService,
    sleeper: Callable[[float], None] = time.sleep,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Collect, select, and persist one caller-transactional curated sample."""

    try:
        now = _normalize_clock(clock())
        plan = build_plan(
            start_year=start_year,
            end_year=end_year,
            chunk_days=chunk_days,
            results_per_page=results_per_page,
            max_pages_per_query=max_pages_per_query,
            max_requests=max_requests,
            now=now,
            retention_multiplier=retention_multiplier,
        )
    except CuratedCliArgumentError as exc:
        print(str(exc), file=stderr)
        return 2

    secret_value = api_key.get_secret_value() if api_key is not None else ""
    request_delay = (
        AUTHENTICATED_DELAY_SECONDS
        if secret_value
        else UNAUTHENTICATED_DELAY_SECONDS
    )
    try:
        with client_factory(api_key=api_key) as client:
            collection = collect_candidates(
                plan,
                client=client,
                normalizer=normalizer,
                sleeper=sleeper,
                request_delay=request_delay,
            )
    except Exception:
        print("Curated NVD ingestion failed during candidate collection.", file=stderr)
        return 1

    selections = [select_year(year) for year in collection.years]
    session: Session | None = None
    try:
        session = session_factory()
        service = service_factory(session)
        source = service.ensure_source()
        run = IngestionRun(
            source=source,
            trigger_type="manual",
            status="running",
            started_at=now,
            completed_at=None,
            records_fetched=sum(year.candidates_inspected for year in selections),
            records_created=0,
            records_updated=0,
            records_unchanged=0,
            records_skipped=sum(year.skipped_count for year in selections),
            records_failed=0,
            error_count=0,
            checkpoint_before=source.checkpoint_value,
            checkpoint_after=None,
            safe_summary="Manual curated NVD ingestion started.",
            created_at=now,
        )
        session.add(run)
        session.flush()

        audit_errors = 0
        for selection in selections:
            for candidate in selection.selected:
                outcome = _persist_candidate(
                    session,
                    run,
                    candidate,
                    service,
                    observed_at=now,
                )
                _increment_outcome(run, outcome)
                if outcome == "failed":
                    audit_errors += 1
            if selection.incomplete_reasons:
                _add_run_error(
                    session,
                    run,
                    "nvd_curated_candidate_limit",
                    f"Curated NVD candidate collection was incomplete for {selection.year}.",
                    retryable=collection.stopped_reason is not None,
                    occurred_at=now,
                )
                audit_errors += 1
            if any(selection.shortfalls.values()):
                _add_run_error(
                    session,
                    run,
                    "nvd_curated_quota_shortfall",
                    f"Curated NVD severity quotas were not filled for {selection.year}.",
                    retryable=False,
                    occurred_at=now,
                )
                audit_errors += 1

        incomplete = any(selection.incomplete for selection in selections)
        if collection.stopped_reason and run.records_fetched == 0:
            run.status = "failed"
        elif incomplete or run.records_failed:
            run.status = "partial"
        else:
            run.status = "succeeded"
        completion_time = _completion_time(clock, started_at=now)
        run.completed_at = completion_time
        run.error_count = audit_errors
        _validate_audit_counters(run)
        run.safe_summary = (
            f"Manual curated NVD ingestion {run.status}; "
            f"years={plan.start_year}-{plan.end_year}; "
            f"inspected={run.records_fetched}; selected="
            f"{sum(len(year.selected) for year in selections)}; "
            f"created={run.records_created}; updated={run.records_updated}; "
            f"unchanged={run.records_unchanged}; skipped={run.records_skipped}; "
            f"failed={run.records_failed}; "
            f"requests={collection.request_count}."
        )
        session.commit()
        _print_summary(
            run,
            plan=plan,
            selections=selections,
            request_count=collection.request_count,
            stdout=stdout,
        )
        if run.status != "succeeded":
            print(
                "Curated NVD ingestion completed with a controlled partial or failed result.",
                file=stderr,
            )
            return 1
        return 0
    except (NvdPersistenceError, SQLAlchemyError):
        if session is not None:
            session.rollback()
        print("Curated NVD ingestion failed during a database operation.", file=stderr)
        return 1
    except Exception:
        if session is not None:
            session.rollback()
        print("Curated NVD ingestion failed unexpectedly.", file=stderr)
        return 1
    finally:
        if session is not None:
            session.close()


def _persist_candidate(
    session: Session,
    run: IngestionRun,
    candidate: CuratedCandidate,
    service: NvdIngestionService,
    *,
    observed_at: datetime,
) -> str:
    try:
        nested = (
            session.begin_nested()
            if hasattr(session, "begin_nested")
            else nullcontext()
        )
        with nested:
            result: NvdPersistenceResult = service.persist(
                candidate.normalized,
                observed_at=observed_at,
            )
            if result.outcome == "failed":
                raise NvdPersistenceError("The selected NVD record conflicted.")
            session.add(
                IngestionRunRecord(
                    ingestion_run=run,
                    source_record=None,
                    intelligence_item=None,
                    action=result.outcome,
                    safe_detail=f"Curated NVD CVE record {result.outcome}.",
                    processed_at=observed_at,
                )
            )
            return result.outcome
    except (NvdPersistenceError, SQLAlchemyError):
        error_type = "nvd_curated_persistence_error"
        message = "A selected curated NVD record could not be persisted safely."
    except Exception:
        error_type = "nvd_curated_record_error"
        message = "A selected curated NVD record failed unexpectedly."

    failed_record = IngestionRunRecord(
        ingestion_run=run,
        source_record=None,
        intelligence_item=None,
        action="failed",
        safe_detail=message,
        processed_at=observed_at,
    )
    session.add(failed_record)
    session.add(
        IngestionError(
            ingestion_run=run,
            ingestion_run_record=failed_record,
            source_record=None,
            error_type=error_type,
            safe_message=message,
            retryable=False,
            retry_count=0,
            occurred_at=observed_at,
        )
    )
    return "failed"


def _add_run_error(
    session: Session,
    run: IngestionRun,
    error_type: str,
    message: str,
    *,
    retryable: bool,
    occurred_at: datetime,
) -> None:
    session.add(
        IngestionError(
            ingestion_run=run,
            ingestion_run_record=None,
            source_record=None,
            error_type=error_type,
            safe_message=message,
            retryable=retryable,
            retry_count=0,
            occurred_at=occurred_at,
        )
    )


def _increment_outcome(run: IngestionRun, outcome: str) -> None:
    if outcome == "created":
        run.records_created += 1
    elif outcome == "updated":
        run.records_updated += 1
    elif outcome == "unchanged":
        run.records_unchanged += 1
    else:
        run.records_failed += 1


def _completion_time(
    clock: Callable[[], datetime],
    *,
    started_at: datetime,
) -> datetime:
    completed_at = _normalize_clock(clock())
    if completed_at < started_at:
        raise CuratedCliArgumentError(
            "The curated NVD completion time is invalid."
        )
    return completed_at


def _validate_audit_counters(run: IngestionRun) -> None:
    accounted = (
        run.records_created
        + run.records_updated
        + run.records_unchanged
        + run.records_skipped
        + run.records_failed
    )
    if run.records_fetched != accounted:
        raise NvdPersistenceError(
            "Curated NVD audit counters did not reconcile."
        )


def _print_summary(
    run: IngestionRun,
    *,
    plan: CuratedPlan,
    selections: list[YearSelection],
    request_count: int,
    stdout: TextIO,
) -> None:
    print("Manual curated NVD ingestion completed.", file=stdout)
    print(f"Run ID: {run.public_id}", file=stdout)
    print(f"Status: {run.status}", file=stdout)
    print(f"Years requested: {plan.start_year}-{plan.end_year}", file=stdout)
    print(f"Yearly quotas: {_quota_text(DEFAULT_QUOTAS)}", file=stdout)
    print(
        "Maximum retained candidates per severity/year: "
        f"{_quota_text(plan.retained_limits)}",
        file=stdout,
    )
    print(
        f"Candidates inspected: "
        f"{sum(year.candidates_inspected for year in selections)}",
        file=stdout,
    )
    for selection in selections:
        shortfalls = {
            severity: count
            for severity, count in selection.shortfalls.items()
            if count
        }
        print(
            f"{selection.year}: selected {_quota_text(selection.selected_counts)}; "
            f"shortfalls {_quota_text(shortfalls) if shortfalls else 'none'}",
            file=stdout,
        )
    print(
        f"KEV-prioritized selected: "
        f"{sum(year.kev_prioritized_count for year in selections)}",
        file=stdout,
    )
    print(f"Created: {run.records_created}", file=stdout)
    print(f"Updated: {run.records_updated}", file=stdout)
    print(f"Unchanged: {run.records_unchanged}", file=stdout)
    print(f"Skipped: {run.records_skipped}", file=stdout)
    print(f"Failed: {run.records_failed}", file=stdout)
    print(f"Request count: {request_count}/{plan.max_requests}", file=stdout)
    incomplete_years = [str(year.year) for year in selections if year.incomplete]
    print(
        "Capped or incomplete years: "
        + (", ".join(incomplete_years) if incomplete_years else "none"),
        file=stdout,
    )


def _quota_text(values: dict[str, int]) -> str:
    return ", ".join(
        f"{severity}={values[severity]}"
        for severity in SEVERITY_ORDER
        if severity in values
    )


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace(
        "+00:00",
        "Z",
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    try:
        now = _normalize_clock(clock())
        arguments = _build_parser(now.year).parse_args(argv)
        plan = build_plan(
            start_year=arguments.start_year,
            end_year=arguments.end_year,
            chunk_days=arguments.chunk_days,
            results_per_page=arguments.results_per_page,
            max_pages_per_query=arguments.max_pages_per_query,
            max_requests=arguments.max_requests,
            now=now,
            retention_multiplier=arguments.retention_multiplier,
        )
    except CuratedCliArgumentError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if arguments.plan:
        print_plan(plan, stdout=sys.stdout)
        return 0

    settings = get_settings()
    return run_curated_ingestion(
        start_year=arguments.start_year,
        end_year=arguments.end_year,
        chunk_days=arguments.chunk_days,
        results_per_page=arguments.results_per_page,
        max_pages_per_query=arguments.max_pages_per_query,
        max_requests=arguments.max_requests,
        api_key=settings.nvd_api_key,
        retention_multiplier=arguments.retention_multiplier,
        clock=clock,
    )


if __name__ == "__main__":
    raise SystemExit(main())
