"""Inactive C05 handlers for strict official RSS publication metadata."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from time import perf_counter
from types import MappingProxyType

from app.ingestion.adapters.official_rss_publications import (
    OfficialRssDocument,
    adapt_official_rss_feed,
    build_official_rss_cursor,
    parse_official_rss_cursor,
)
from app.ingestion.collectors.official_rss_client import (
    C05_OFFICIAL_RSS_POLICIES,
    C05_OFFICIAL_RSS_SOURCE_SLUGS,
    OfficialRssClient,
    OfficialRssSourcePolicy,
    validate_c05_official_rss_policy_registry,
)
from app.ingestion.publication_pipeline import (
    PublicationPersistenceError,
    PublicationPipeline,
)
from app.orchestration.contracts import (
    ProgressKind,
    ProgressProposal,
    ProgressStorage,
    ReconciledCounters,
    ResultStatus,
    SafeMetrics,
    SourceExecutionContext,
    SourceExecutionResult,
    SourceHandler,
)
from app.orchestration.source_handlers.common import (
    OutcomeEvidence,
    SessionFactory,
    classified_client_failure,
    default_session_factory,
    elapsed_milliseconds,
    expected_previous_version,
    failure_for_status,
    load_execution_evidence,
    persist_execution_evidence,
    persist_outcome_evidence,
    reconstruct_progress_from_evidence,
    validate_handler_context,
)


OfficialRssClientFactory = Callable[
    [MappingProxyType[str, OfficialRssSourcePolicy]], OfficialRssClient
]


class OfficialRssSourceHandler:
    """Collect outside and persist inside one caller-owned transaction."""

    def __init__(
        self,
        source_slug: str,
        *,
        policy_registry: MappingProxyType[str, OfficialRssSourcePolicy] = (
            C05_OFFICIAL_RSS_POLICIES
        ),
        session_factory: SessionFactory | None = None,
        client_factory: OfficialRssClientFactory = (
            lambda registry: OfficialRssClient(policy_registry=registry)
        ),
    ) -> None:
        try:
            approved_registry = validate_c05_official_rss_policy_registry(
                policy_registry
            )
        except Exception:
            raise ValueError(
                "The official RSS handler policy registry is invalid."
            ) from None
        if source_slug not in approved_registry:
            raise ValueError("The official RSS handler source is not approved.")
        self._source_slug = source_slug
        self._policy_registry = approved_registry
        self._session_factory = session_factory or default_session_factory()
        self._client_factory = client_factory

    @property
    def source_slug(self) -> str:
        return self._source_slug

    def execute(self, context: SourceExecutionContext) -> SourceExecutionResult:
        self._validate_context(context)
        replay = load_execution_evidence(self._session_factory, context)
        if replay is not None:
            return replay
        previous_hash, previous_timestamp = _previous_cursor(context)
        started = perf_counter()
        try:
            client = self._client_factory(self._policy_registry)
            fetched = client.fetch(self._source_slug)
            document = adapt_official_rss_feed(self._source_slug, fetched.body)
        except Exception as error:
            raise classified_client_failure(error, source_label="official RSS") from None
        metrics = SafeMetrics(
            duration_ms=elapsed_milliseconds(started),
            request_count=fetched.request_count,
            page_count=1,
        )
        if (
            document.records_rejected == 0
            and document.canonical_metadata_hash == previous_hash
        ):
            result = SourceExecutionResult(
                source_slug=self._source_slug,
                status=ResultStatus.NO_CHANGE,
                counters=ReconciledCounters(),
                metrics=metrics,
                safe_message="The approved official RSS metadata is unchanged.",
            )
            try:
                with self._session_factory() as session, session.begin():
                    persist_execution_evidence(session, context=context, result=result)
                    session.flush()
            except Exception as error:
                raise classified_client_failure(
                    error, source_label="official RSS"
                ) from None
            return result

        try:
            with self._session_factory() as session, session.begin():
                batch = PublicationPipeline(session).process_candidates(
                    document.candidates,
                    observed_at=context.scheduled_for,
                )
                if batch.failed:
                    raise PublicationPersistenceError(
                        "Official RSS publication persistence failed safely."
                    )
                duplicates = max(
                    document.entries_received
                    - document.records_rejected
                    - document.records_accepted,
                    0,
                )
                counters = ReconciledCounters(
                    fetched=batch.total + document.records_rejected + duplicates,
                    created=batch.created,
                    updated=batch.updated,
                    unchanged=batch.unchanged,
                    skipped=batch.skipped + duplicates,
                    failed=document.records_rejected,
                    error_count=document.records_rejected,
                )
                proposal = _cursor_proposal(
                    context,
                    document,
                    previous_timestamp,
                )
                status = (
                    ResultStatus.PARTIAL
                    if document.records_rejected
                    else ResultStatus.SUCCESS
                    if batch.created + batch.updated
                    else ResultStatus.NO_CHANGE
                )
                result = SourceExecutionResult(
                    source_slug=self._source_slug,
                    status=status,
                    counters=counters,
                    metrics=metrics,
                    safe_message=(
                        "The official RSS feed contained rejected metadata."
                        if status is ResultStatus.PARTIAL
                        else "The official RSS metadata committed successfully."
                    ),
                    progress_proposal=(
                        proposal if status is not ResultStatus.PARTIAL else None
                    ),
                    failure=failure_for_status(status),
                )
                persist_outcome_evidence(
                    session,
                    run_id=context.attempt.run_id,
                    evidence=(
                        OutcomeEvidence(
                            outcome=item.outcome,
                            source_record_id=getattr(item.source_record, "id", None),
                            intelligence_item_id=item.intelligence_item_id,
                            safe_detail=(
                                "C05 processed one official RSS publication record."
                            ),
                        )
                        for item in batch.results
                    ),
                )
                persist_execution_evidence(session, context=context, result=result)
                session.flush()
        except Exception as error:
            raise classified_client_failure(error, source_label="official RSS") from None
        return result

    def reconstruct_progress(
        self,
        context: SourceExecutionContext,
        committed_counters: ReconciledCounters,
    ) -> ProgressProposal:
        self._validate_context(context)
        return reconstruct_progress_from_evidence(
            self._session_factory,
            context,
            committed_counters,
        )

    def _validate_context(self, context: SourceExecutionContext) -> None:
        validate_handler_context(
            context,
            source_slug=self._source_slug,
            progress_storage=ProgressStorage.CHECKPOINT,
            progress_kind=ProgressKind.SOURCE_CURSOR,
        )


def build_c05_official_rss_handlers(
    policy_registry: MappingProxyType[str, OfficialRssSourcePolicy] = (
        C05_OFFICIAL_RSS_POLICIES
    ),
    *,
    session_factory: SessionFactory | None = None,
    client_factory: OfficialRssClientFactory = (
        lambda registry: OfficialRssClient(policy_registry=registry)
    ),
) -> Mapping[str, SourceHandler]:
    """Build immutable C05 handlers without production binding or activation."""

    try:
        approved_registry = validate_c05_official_rss_policy_registry(
            policy_registry
        )
    except Exception:
        raise ValueError(
            "The official RSS handler policy registry is invalid."
        ) from None
    handlers = {
        source_slug: OfficialRssSourceHandler(
            source_slug,
            policy_registry=approved_registry,
            session_factory=session_factory,
            client_factory=client_factory,
        )
        for source_slug in approved_registry
    }
    if frozenset(handlers) != C05_OFFICIAL_RSS_SOURCE_SLUGS:
        raise ValueError("The official RSS handler policy registry is incomplete.")
    return MappingProxyType(handlers)


def _previous_cursor(
    context: SourceExecutionContext,
) -> tuple[str | None, datetime | None]:
    if context.progress is None:
        return None, None
    try:
        return parse_official_rss_cursor(context.progress.value)
    except Exception:
        raise ValueError("The official RSS source cursor is invalid.") from None


def _cursor_proposal(
    context: SourceExecutionContext,
    document: OfficialRssDocument,
    previous_timestamp: datetime | None,
) -> ProgressProposal:
    candidate_timestamp = document.greatest_publication_timestamp
    effective_timestamp = _effective_cursor_timestamp(
        previous_timestamp,
        candidate_timestamp,
    )
    return ProgressProposal(
        storage=ProgressStorage.CHECKPOINT,
        kind=ProgressKind.SOURCE_CURSOR,
        name=ProgressKind.SOURCE_CURSOR.value,
        value=build_official_rss_cursor(
            document,
            effective_timestamp=effective_timestamp,
        ),
        expected_previous_version=expected_previous_version(context),
    )


def _effective_cursor_timestamp(
    previous_timestamp: datetime | None,
    candidate_timestamp: datetime | None,
) -> datetime | None:
    if previous_timestamp is None:
        return candidate_timestamp
    if candidate_timestamp is None or candidate_timestamp <= previous_timestamp:
        return previous_timestamp
    return candidate_timestamp


__all__ = [
    "C05_OFFICIAL_RSS_SOURCE_SLUGS",
    "OfficialRssSourceHandler",
    "build_c05_official_rss_handlers",
]
