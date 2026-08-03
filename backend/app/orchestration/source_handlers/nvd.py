"""Bounded incremental C02 handler for the official NVD CVE API."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from time import perf_counter, sleep

from pydantic import SecretStr

from app.core.config import Settings, get_settings
from app.ingestion.collectors.nvd_client import (
    AUTHENTICATED_DELAY_SECONDS,
    UNAUTHENTICATED_DELAY_SECONDS,
    NvdClient,
)
from app.ingestion.normalizers.nvd import normalize_nvd_cve
from app.ingestion.services.nvd_ingestion_service import NvdIngestionService
from app.orchestration.contracts import (
    ClassifiedFailure,
    FailureCategory,
    ProgressKind,
    ProgressProposal,
    ProgressStorage,
    ReconciledCounters,
    SafeMetrics,
    SourceExecutionContext,
    SourceExecutionResult,
)
from app.orchestration.source_handlers.common import (
    OutcomeEvidence,
    SessionFactory,
    classified_client_failure,
    counters_from_outcomes,
    default_session_factory,
    elapsed_milliseconds,
    load_execution_evidence,
    make_result,
    persist_execution_evidence,
    persist_outcome_evidence,
    reconstruct_progress_from_evidence,
    scheduled_watermark_proposal,
    validate_handler_context,
)


NVD_SOURCE_SLUG = "nvd"
INITIAL_WINDOW = timedelta(hours=2)
WINDOW_OVERLAP = timedelta(minutes=5)
MAX_WINDOW = timedelta(days=120)
RESULTS_PER_PAGE = 500
MAX_PAGES = 10
MAX_RECORDS = RESULTS_PER_PAGE * MAX_PAGES

NvdClientFactory = Callable[[SecretStr | None, Callable[[float], None]], NvdClient]


def _default_client_factory(
    api_key: SecretStr | None,
    sleeper: Callable[[float], None],
) -> NvdClient:
    return NvdClient(api_key=api_key, sleeper=sleeper)


class NvdSourceHandler:
    """Collect one complete bounded modified window and persist it atomically."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory | None = None,
        client_factory: NvdClientFactory = _default_client_factory,
        settings_provider: Callable[[], Settings] = get_settings,
        sleeper: Callable[[float], None] = sleep,
    ) -> None:
        self._session_factory = session_factory or default_session_factory()
        self._client_factory = client_factory
        self._settings_provider = settings_provider
        self._sleeper = sleeper

    def execute(self, context: SourceExecutionContext) -> SourceExecutionResult:
        validate_handler_context(
            context,
            source_slug=NVD_SOURCE_SLUG,
            progress_storage=ProgressStorage.WATERMARK,
            progress_kind=ProgressKind.MODIFIED_SINCE,
        )
        replay = load_execution_evidence(self._session_factory, context)
        if replay is not None:
            return replay

        window_start, window_end = _modified_window(context)
        settings = self._settings_provider()
        api_key = settings.nvd_api_key
        request_delay = (
            AUTHENTICATED_DELAY_SECONDS
            if api_key is not None and api_key.get_secret_value()
            else UNAUTHENTICATED_DELAY_SECONDS
        )
        client = self._client_factory(api_key, self._sleeper)
        started = perf_counter()
        pages = 0
        wrappers: list[dict[str, object]] = []
        expected_total: int | None = None
        start_index = 0
        try:
            while True:
                if pages >= MAX_PAGES:
                    raise ClassifiedFailure(
                        FailureCategory.UNSUPPORTED_CONTENT,
                        "The NVD window exceeds the approved page bound.",
                    )
                page = client.fetch_page(
                    window_start,
                    window_end,
                    start_index=start_index,
                    results_per_page=RESULTS_PER_PAGE,
                )
                pages += 1
                if page.start_index != start_index:
                    raise ClassifiedFailure(
                        FailureCategory.UNSUPPORTED_CONTENT,
                        "The NVD pagination identity is inconsistent.",
                    )
                if not 1 <= page.results_per_page <= RESULTS_PER_PAGE:
                    raise ClassifiedFailure(
                        FailureCategory.UNSUPPORTED_CONTENT,
                        "The NVD page metadata exceeds the approved bound.",
                    )
                if expected_total is None:
                    expected_total = page.total_results
                    if expected_total > MAX_RECORDS:
                        raise ClassifiedFailure(
                            FailureCategory.UNSUPPORTED_CONTENT,
                            "The NVD window exceeds the approved record bound.",
                        )
                elif page.total_results != expected_total:
                    raise ClassifiedFailure(
                        FailureCategory.UNSUPPORTED_CONTENT,
                        "The NVD pagination total changed during the bounded window.",
                    )
                if len(page.vulnerabilities) > page.results_per_page:
                    raise ClassifiedFailure(
                        FailureCategory.UNSUPPORTED_CONTENT,
                        "The NVD page conflicts with its declared record bound.",
                    )
                wrappers.extend(page.vulnerabilities)
                next_index = start_index + len(page.vulnerabilities)
                if next_index >= expected_total:
                    if len(wrappers) != expected_total:
                        raise ClassifiedFailure(
                            FailureCategory.UNSUPPORTED_CONTENT,
                            "The NVD window did not return its complete declared result set.",
                        )
                    break
                if not page.vulnerabilities or next_index <= start_index:
                    raise ClassifiedFailure(
                        FailureCategory.UNSUPPORTED_CONTENT,
                        "The NVD pagination stopped before the window completed.",
                    )
                start_index = next_index
                self._sleeper(request_delay)
        except ClassifiedFailure:
            raise
        except Exception as error:
            raise classified_client_failure(error, source_label="NVD") from None
        finally:
            client.close()

        try:
            records = _normalize_unique(wrappers)
        except Exception as error:
            raise classified_client_failure(error, source_label="NVD") from None

        outcomes: list[str] = []
        evidence: list[OutcomeEvidence] = []
        proposal = scheduled_watermark_proposal(context)
        try:
            with self._session_factory() as session, session.begin():
                service = NvdIngestionService(session)
                for record in records:
                    persisted = service.persist(record, observed_at=context.scheduled_for)
                    outcomes.append(persisted.outcome)
                    evidence.append(
                        OutcomeEvidence(
                            outcome=persisted.outcome,
                            safe_detail="C02 processed one validated NVD CVE record.",
                        )
                    )
                counters = counters_from_outcomes(outcomes)
                result = make_result(
                    source_slug=NVD_SOURCE_SLUG,
                    counters=counters,
                    metrics=SafeMetrics(
                        duration_ms=elapsed_milliseconds(started),
                        request_count=pages,
                        page_count=pages,
                    ),
                    progress_proposal=proposal,
                )
                persist_outcome_evidence(
                    session,
                    run_id=context.attempt.run_id,
                    evidence=evidence,
                )
                persist_execution_evidence(session, context=context, result=result)
                session.flush()
        except Exception as error:
            raise classified_client_failure(error, source_label="NVD") from None
        return result

    def reconstruct_progress(
        self,
        context: SourceExecutionContext,
        committed_counters: ReconciledCounters,
    ) -> ProgressProposal:
        validate_handler_context(
            context,
            source_slug=NVD_SOURCE_SLUG,
            progress_storage=ProgressStorage.WATERMARK,
            progress_kind=ProgressKind.MODIFIED_SINCE,
        )
        return reconstruct_progress_from_evidence(
            self._session_factory,
            context,
            committed_counters,
        )


def _modified_window(context: SourceExecutionContext) -> tuple[datetime, datetime]:
    end = context.scheduled_for.astimezone(UTC)
    if context.progress is None:
        start = end - INITIAL_WINDOW
    else:
        value = context.progress.value
        if not isinstance(value, datetime):
            raise ClassifiedFailure(
                FailureCategory.INVALID_SOURCE_POLICY,
                "The NVD watermark is invalid.",
            )
        start = value.astimezone(UTC) - WINDOW_OVERLAP
    if start > end or end - start > MAX_WINDOW:
        raise ClassifiedFailure(
            FailureCategory.UNSAFE_INPUT,
            "The NVD modified window is outside the approved bound.",
        )
    return start, end


def _normalize_unique(wrappers: list[dict[str, object]]):
    ordered = []
    by_cve = {}
    for wrapper in wrappers:
        normalized = normalize_nvd_cve(wrapper)
        existing = by_cve.get(normalized.cve_id)
        if existing is None:
            by_cve[normalized.cve_id] = normalized
            ordered.append(normalized)
        elif existing.content_hash != normalized.content_hash:
            raise ValueError("The NVD response contains conflicting duplicate CVEs.")
    return ordered


__all__ = [
    "INITIAL_WINDOW",
    "MAX_PAGES",
    "MAX_RECORDS",
    "NVD_SOURCE_SLUG",
    "NvdSourceHandler",
    "RESULTS_PER_PAGE",
    "WINDOW_OVERLAP",
]
