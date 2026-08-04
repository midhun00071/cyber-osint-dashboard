"""Inactive, approval-gated handlers for implemented DESC metadata collectors."""

from __future__ import annotations

from collections.abc import Callable
from time import perf_counter

from app.ingestion.collectors.desc_publications_client import (
    DescCollectionResult,
    DescContentTypeError,
    DescHttpError,
    DescPublicationSource,
    DescPublicationsClient,
    DescRateLimitError,
    DescRedirectError,
    DescResponseTooLargeError,
    DescTimeoutError,
    DescTransportError,
    validate_desc_collection_result,
)
from app.ingestion.publication_pipeline import PublicationPipeline
from app.ingestion.source_registry import ImplementationStatus, get_source_definition
from app.ingestion.uae_source_policy import automated_uae_access_is_approved
from app.orchestration.contracts import (
    ClassifiedFailure,
    ContractValidationError,
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
)


DESC_NEWS_SOURCE_SLUG = "desc-news"
DESC_RESEARCH_SOURCE_SLUG = "desc-published-research"
DESC_PUBLICATION_SOURCE_SLUGS = frozenset(
    {DESC_NEWS_SOURCE_SLUG, DESC_RESEARCH_SOURCE_SLUG}
)
_SELECTORS = {
    DESC_NEWS_SOURCE_SLUG: DescPublicationSource.NEWS,
    DESC_RESEARCH_SOURCE_SLUG: DescPublicationSource.PUBLISHED_RESEARCH,
}


class DescPublicationSourceHandler:
    """Persist one approved, bounded DESC listing in an atomic transaction."""

    def __init__(
        self,
        source_slug: str,
        *,
        session_factory: SessionFactory | None = None,
        client_factory: Callable[[DescPublicationSource], DescPublicationsClient] = DescPublicationsClient,
    ) -> None:
        if source_slug not in DESC_PUBLICATION_SOURCE_SLUGS:
            raise ValueError("The DESC publication source is not supported.")
        self.source_slug = source_slug
        self._selector = _SELECTORS[source_slug]
        self._session_factory = session_factory or default_session_factory()
        self._client_factory = client_factory

    def execute(self, context: SourceExecutionContext) -> SourceExecutionResult:
        _validate_desc_context(context, self.source_slug)
        replay = load_execution_evidence(self._session_factory, context)
        if replay is not None:
            return replay
        if not automated_uae_access_is_approved(self.source_slug):
            raise ClassifiedFailure(
                FailureCategory.APPROVAL_REQUIREMENT,
                "DESC automated access remains approval pending.",
            )

        started = perf_counter()
        client = self._client_factory(self._selector)
        try:
            collection = client.fetch()
        except ClassifiedFailure:
            raise
        except Exception as error:
            raise _classified_desc_failure(error) from None
        finally:
            client.close()
        _validate_collection(collection, self.source_slug, self._selector)

        outcomes = ["failed"] * collection.rejected_record_count
        evidence = [
            OutcomeEvidence(
                outcome="failed",
                safe_detail="DESC rejected one listing metadata record safely.",
            )
            for _ in range(collection.rejected_record_count)
        ]
        proposal = scheduled_watermark_proposal(context)
        try:
            with self._session_factory() as session, session.begin():
                pipeline = PublicationPipeline(session)
                for candidate in collection.candidates:
                    persisted = pipeline.persist(candidate, observed_at=context.scheduled_for)
                    outcomes.append(persisted.outcome)
                    evidence.append(
                        OutcomeEvidence(
                            outcome=persisted.outcome,
                            source_record_id=getattr(persisted.source_record, "id", None),
                            intelligence_item_id=persisted.intelligence_item_id,
                            safe_detail="DESC processed one validated publication metadata record.",
                        )
                    )
                counters = counters_from_outcomes(outcomes)
                result = make_result(
                    source_slug=self.source_slug,
                    counters=counters,
                    metrics=SafeMetrics(
                        duration_ms=elapsed_milliseconds(started),
                        request_count=collection.fetched_listing_page_count,
                        page_count=collection.fetched_listing_page_count,
                    ),
                    progress_proposal=proposal,
                )
                persist_outcome_evidence(
                    session, run_id=context.attempt.run_id, evidence=evidence
                )
                persist_execution_evidence(session, context=context, result=result)
                session.flush()
        except ClassifiedFailure:
            raise
        except Exception as error:
            raise classified_client_failure(error, source_label="DESC publication") from None
        return result

    def reconstruct_progress(
        self,
        context: SourceExecutionContext,
        committed_counters: ReconciledCounters,
    ) -> ProgressProposal:
        _validate_desc_context(context, self.source_slug)
        return reconstruct_progress_from_evidence(
            self._session_factory, context, committed_counters
        )


def _validate_desc_context(context: SourceExecutionContext, source_slug: str) -> None:
    if not isinstance(context, SourceExecutionContext):
        raise ContractValidationError("The DESC execution context is invalid.")
    definition = get_source_definition(source_slug)
    if (
        source_slug not in DESC_PUBLICATION_SOURCE_SLUGS
        or definition.slug != source_slug
        or definition.implementation_status is not ImplementationStatus.IMPLEMENTED
        or context.policy.source_slug != source_slug
        or context.attempt.source_slug != source_slug
        or context.policy.progress_storage is not ProgressStorage.WATERMARK
        or context.policy.progress_kind is not ProgressKind.MODIFIED_SINCE
    ):
        raise ClassifiedFailure(
            FailureCategory.INVALID_SOURCE_POLICY,
            "The DESC source identity conflicts with the controlled policy.",
        )
    if context.progress is not None and (
        context.progress.storage is not ProgressStorage.WATERMARK
        or context.progress.kind is not ProgressKind.MODIFIED_SINCE
        or context.progress.name != ProgressKind.MODIFIED_SINCE.value
    ):
        raise ClassifiedFailure(
            FailureCategory.INVALID_SOURCE_POLICY,
            "The DESC progress conflicts with the controlled policy.",
        )


def _validate_collection(
    collection: DescCollectionResult,
    source_slug: str,
    selector: DescPublicationSource,
) -> None:
    try:
        validated = validate_desc_collection_result(collection)
    except (TypeError, ValueError):
        raise ClassifiedFailure(
            FailureCategory.CONTRACT_VIOLATION,
            "The DESC collection result failed safe contract validation.",
        ) from None
    if (
        validated.source is not selector
        or collection.source_slug != source_slug
        or collection.fetched_listing_page_count != 1
    ):
        raise ClassifiedFailure(
            FailureCategory.CONTRACT_VIOLATION,
            "The DESC collection result conflicts with the controlled source.",
        )


def _classified_desc_failure(error: BaseException) -> ClassifiedFailure:
    if isinstance(error, DescTimeoutError):
        return ClassifiedFailure(
            FailureCategory.APPROVED_TIMEOUT,
            "The approved DESC listing request timed out.",
        )
    if isinstance(error, DescRateLimitError):
        return ClassifiedFailure(
            FailureCategory.PROVIDER_RATE_LIMIT,
            "The approved DESC listing request was rate limited.",
        )
    if isinstance(error, DescTransportError):
        return ClassifiedFailure(
            FailureCategory.TEMPORARY_CONNECTION,
            "The approved DESC listing request failed temporarily.",
        )
    if isinstance(error, DescHttpError):
        return ClassifiedFailure(
            FailureCategory.PERMANENT_PROVIDER_REJECTION,
            "The approved DESC listing request was rejected.",
        )
    if isinstance(
        error,
        (DescContentTypeError, DescRedirectError, DescResponseTooLargeError),
    ):
        return ClassifiedFailure(
            FailureCategory.UNSUPPORTED_CONTENT,
            "The approved DESC listing response failed safe validation.",
        )
    return classified_client_failure(error, source_label="DESC listing")


__all__ = [
    "DESC_NEWS_SOURCE_SLUG",
    "DESC_PUBLICATION_SOURCE_SLUGS",
    "DESC_RESEARCH_SOURCE_SLUG",
    "DescPublicationSourceHandler",
]
