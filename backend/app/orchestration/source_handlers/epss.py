"""Bounded fair-progression C02 handler for FIRST EPSS enrichment."""

from __future__ import annotations

from collections.abc import Callable
from time import perf_counter

from sqlalchemy import select

from app.ingestion.collectors.epss_client import EpssClient
from app.ingestion.normalizers.epss import CVE_ID_PATTERN, EpssNormalizationError, normalize_epss_record
from app.ingestion.services.epss_enrichment_service import EpssEnrichmentService
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
    Vulnerability,
)
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


EPSS_SOURCE_SLUG = "first-epss"
MAX_LOCAL_CVES = 500
MAX_REQUEST_CVES = 100


class EpssSourceHandler:
    """Select fair local candidates, fetch bounded scores, and persist one transaction."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory | None = None,
        client_factory: Callable[[], EpssClient] = EpssClient,
    ) -> None:
        self._session_factory = session_factory or default_session_factory()
        self._client_factory = client_factory

    def execute(self, context: SourceExecutionContext) -> SourceExecutionResult:
        validate_handler_context(
            context,
            source_slug=EPSS_SOURCE_SLUG,
            progress_storage=ProgressStorage.WATERMARK,
            progress_kind=ProgressKind.MODIFIED_SINCE,
        )
        replay = load_execution_evidence(self._session_factory, context)
        if replay is not None:
            return replay

        try:
            candidates = self._candidate_cves()
        except Exception as error:
            raise classified_client_failure(error, source_label="EPSS") from None
        started = perf_counter()
        client = self._client_factory()
        valid_records = []
        pre_persistence_failures = 0
        request_count = 0
        try:
            for requested in client.build_batches(candidates, max_batch_size=MAX_REQUEST_CVES):
                batch = client.fetch_batch(requested)
                request_count += 1
                if batch.requested_cves != requested:
                    raise ClassifiedFailure(
                        FailureCategory.UNSUPPORTED_CONTENT,
                        "The EPSS response conflicts with the requested batch identity.",
                    )
                requested_set = set(requested)
                by_cve = {}
                invalid_cves: set[str] = set()
                for raw in batch.records:
                    try:
                        normalized = normalize_epss_record(raw)
                    except EpssNormalizationError:
                        raw_cve = raw.get("cve") if isinstance(raw, dict) else None
                        if (
                            isinstance(raw_cve, str)
                            and CVE_ID_PATTERN.fullmatch(raw_cve) is not None
                            and raw_cve.upper() in requested_set
                        ):
                            invalid_cves.add(raw_cve.upper())
                        pre_persistence_failures += 1
                        continue
                    if normalized.cve_id not in requested_set:
                        pre_persistence_failures += 1
                        continue
                    if normalized.score_date > context.scheduled_for.date():
                        invalid_cves.add(normalized.cve_id)
                        pre_persistence_failures += 1
                        by_cve.pop(normalized.cve_id, None)
                        continue
                    existing = by_cve.get(normalized.cve_id)
                    if existing is None and normalized.cve_id not in invalid_cves:
                        by_cve[normalized.cve_id] = normalized
                    elif existing is not None and existing.content_hash != normalized.content_hash:
                        invalid_cves.add(normalized.cve_id)
                        by_cve.pop(normalized.cve_id, None)
                        pre_persistence_failures += 1
                missing = requested_set - set(by_cve) - invalid_cves
                pre_persistence_failures += len(missing)
                valid_records.extend(by_cve[cve_id] for cve_id in requested if cve_id in by_cve)
        except ClassifiedFailure:
            raise
        except Exception as error:
            raise classified_client_failure(error, source_label="EPSS") from None
        finally:
            client.close()

        outcomes = ["failed"] * pre_persistence_failures
        evidence = [
            OutcomeEvidence(
                outcome="failed",
                safe_detail="C02 rejected one EPSS response outcome safely.",
            )
            for _ in range(pre_persistence_failures)
        ]
        proposal = scheduled_watermark_proposal(context)
        try:
            with self._session_factory() as session, session.begin():
                service = EpssEnrichmentService(session)
                for record in valid_records:
                    persisted = service.enrich(record, observed_at=context.scheduled_for)
                    outcomes.append(persisted.outcome)
                    evidence.append(
                        OutcomeEvidence(
                            outcome=persisted.outcome,
                            source_record_id=getattr(persisted.source_record, "id", None),
                            intelligence_item_id=persisted.intelligence_item_id,
                            safe_detail="C02 processed one validated EPSS score record.",
                        )
                    )
                counters = counters_from_outcomes(outcomes)
                result = make_result(
                    source_slug=EPSS_SOURCE_SLUG,
                    counters=counters,
                    metrics=SafeMetrics(
                        duration_ms=elapsed_milliseconds(started),
                        request_count=request_count,
                        page_count=request_count,
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
            raise classified_client_failure(error, source_label="EPSS") from None
        return result

    def reconstruct_progress(
        self,
        context: SourceExecutionContext,
        committed_counters: ReconciledCounters,
    ) -> ProgressProposal:
        validate_handler_context(
            context,
            source_slug=EPSS_SOURCE_SLUG,
            progress_storage=ProgressStorage.WATERMARK,
            progress_kind=ProgressKind.MODIFIED_SINCE,
        )
        return reconstruct_progress_from_evidence(
            self._session_factory,
            context,
            committed_counters,
        )

    def _candidate_cves(self) -> tuple[str, ...]:
        epss_source_id = (
            select(IntelligenceSource.id)
            .where(IntelligenceSource.slug == EPSS_SOURCE_SLUG)
            .scalar_subquery()
        )
        epss_date = (
            select(SourceRecord.source_modified_at)
            .where(
                SourceRecord.source_id == epss_source_id,
                SourceRecord.intelligence_item_id
                == IntelligenceItemIdentifier.intelligence_item_id,
                SourceRecord.source_external_id
                == IntelligenceItemIdentifier.normalized_value,
            )
            .correlate(IntelligenceItemIdentifier)
            .scalar_subquery()
        )
        statement = (
            select(IntelligenceItemIdentifier.normalized_value)
            .join(
                IntelligenceItem,
                IntelligenceItem.id
                == IntelligenceItemIdentifier.intelligence_item_id,
            )
            .join(
                Vulnerability,
                Vulnerability.intelligence_item_id == IntelligenceItem.id,
            )
            .where(
                IntelligenceItemIdentifier.source_id.is_(None),
                IntelligenceItemIdentifier.namespace == "cve",
            )
            .order_by(
                epss_date.asc().nullsfirst(),
                IntelligenceItemIdentifier.normalized_value.asc(),
            )
            .limit(MAX_LOCAL_CVES)
        )
        with self._session_factory() as session:
            values = tuple(session.execute(statement).scalars().all())
        if any(not isinstance(value, str) for value in values):
            raise ValueError("The local EPSS candidate identity is invalid.")
        return values


__all__ = [
    "EPSS_SOURCE_SLUG",
    "EpssSourceHandler",
    "MAX_LOCAL_CVES",
    "MAX_REQUEST_CVES",
]
