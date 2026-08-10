"""Bounded C02 handlers for the three approved publication RSS sources."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from time import perf_counter

from sqlalchemy.orm import Session

from app.ingestion.adapters.google_threat_publications import (
    GoogleThreatPublicationRecordError,
    adapt_google_threat_publication,
    parse_google_threat_feed_entries,
)
from app.ingestion.collectors.google_threat_intelligence_rss_client import (
    GoogleThreatIntelligenceRssClient,
)
from app.ingestion.collectors.rss_client import RssClient
from app.ingestion.normalizers.rss import (
    RssNormalizationError,
    normalize_rss_entry,
    parse_rss_feed_entries,
)
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationCandidateError,
    PublicationPipeline,
    PublicationSourceError,
    normalize_publication_candidate,
)
from app.ingestion.services.rss_ingestion_service import RssIngestionService
from app.models import IngestionError
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


CERT_EU_SOURCE_SLUG = "cert-eu-security-advisories"
GOOGLE_SOURCE_SLUG = "google-threat-intelligence-public-research"
MANDIANT_SOURCE_SLUG = "mandiant-public-threat-research"
PUBLICATION_SOURCE_SLUGS = frozenset(
    {CERT_EU_SOURCE_SLUG, GOOGLE_SOURCE_SLUG, MANDIANT_SOURCE_SLUG}
)
MAX_FEED_ENTRIES = 100


@dataclass(frozen=True, slots=True)
class _OwnedValidationDiagnostic:
    failure_stage: str
    diagnostic_fingerprint: str | None


class PublicationSourceHandler:
    """Fetch one complete bounded feed and persist only the active source."""

    def __init__(
        self,
        source_slug: str,
        *,
        session_factory: SessionFactory | None = None,
        cert_client_factory: Callable[[], RssClient] = RssClient,
        google_client_factory: Callable[[], GoogleThreatIntelligenceRssClient] = (
            GoogleThreatIntelligenceRssClient
        ),
    ) -> None:
        if source_slug not in PUBLICATION_SOURCE_SLUGS:
            raise ValueError("The C02 publication source is not approved.")
        self.source_slug = source_slug
        self._session_factory = session_factory or default_session_factory()
        self._cert_client_factory = cert_client_factory
        self._google_client_factory = google_client_factory

    def execute(self, context: SourceExecutionContext) -> SourceExecutionResult:
        validate_handler_context(
            context,
            source_slug=self.source_slug,
            progress_storage=ProgressStorage.WATERMARK,
            progress_kind=ProgressKind.MODIFIED_SINCE,
        )
        replay = load_execution_evidence(self._session_factory, context)
        if replay is not None:
            return replay

        started = perf_counter()
        try:
            feed_bytes = self._fetch_feed()
            (
                candidates,
                pre_persistence_failures,
                owned_validation_diagnostics,
            ) = self._parse_active_candidates(feed_bytes)
        except ClassifiedFailure:
            raise
        except Exception as error:
            raise classified_client_failure(error, source_label="publication feed") from None

        outcomes = ["failed"] * pre_persistence_failures
        evidence = [
            OutcomeEvidence(
                outcome="failed",
                safe_detail="C02 rejected one malformed publication feed record safely.",
            )
            for _ in range(pre_persistence_failures)
        ]
        proposal = scheduled_watermark_proposal(context)
        try:
            with self._session_factory() as session, session.begin():
                if self.source_slug == CERT_EU_SOURCE_SLUG:
                    service = RssIngestionService(session)
                    for candidate in candidates:
                        persisted = service.persist(
                            candidate,
                            observed_at=context.scheduled_for,
                        )
                        outcomes.append(persisted.outcome)
                        evidence.append(_outcome_evidence(persisted))
                else:
                    pipeline = PublicationPipeline(session)
                    for candidate in candidates:
                        persisted = pipeline.persist(
                            candidate,
                            observed_at=context.scheduled_for,
                        )
                        outcomes.append(persisted.outcome)
                        evidence.append(_outcome_evidence(persisted))
                counters = counters_from_outcomes(outcomes)
                result = make_result(
                    source_slug=self.source_slug,
                    counters=counters,
                    metrics=SafeMetrics(
                        duration_ms=elapsed_milliseconds(started),
                        request_count=1,
                        page_count=1,
                    ),
                    progress_proposal=proposal,
                )
                persist_outcome_evidence(
                    session,
                    run_id=context.attempt.run_id,
                    evidence=evidence,
                )
                _persist_owned_validation_diagnostics(
                    session,
                    run_id=context.attempt.run_id,
                    diagnostics=owned_validation_diagnostics,
                    occurred_at=context.scheduled_for,
                )
                persist_execution_evidence(session, context=context, result=result)
                session.flush()
        except Exception as error:
            raise classified_client_failure(error, source_label="publication") from None
        return result

    def reconstruct_progress(
        self,
        context: SourceExecutionContext,
        committed_counters: ReconciledCounters,
    ) -> ProgressProposal:
        validate_handler_context(
            context,
            source_slug=self.source_slug,
            progress_storage=ProgressStorage.WATERMARK,
            progress_kind=ProgressKind.MODIFIED_SINCE,
        )
        return reconstruct_progress_from_evidence(
            self._session_factory,
            context,
            committed_counters,
        )

    def _fetch_feed(self) -> bytes:
        if self.source_slug == CERT_EU_SOURCE_SLUG:
            client = self._cert_client_factory()
            try:
                return client.fetch_cert_eu_security_advisories().feed_bytes
            finally:
                client.close()
        client = self._google_client_factory()
        try:
            return client.fetch_publications().feed_bytes
        finally:
            client.close()

    def _parse_active_candidates(
        self,
        feed_bytes: bytes,
    ) -> tuple[list[object], int, tuple[_OwnedValidationDiagnostic, ...]]:
        if self.source_slug == CERT_EU_SOURCE_SLUG:
            entries = parse_rss_feed_entries(feed_bytes)
            if len(entries) > MAX_FEED_ENTRIES:
                raise ClassifiedFailure(
                    FailureCategory.UNSUPPORTED_CONTENT,
                    "The CERT-EU feed exceeds the approved record bound.",
                )
            records = []
            failures = 0
            external_identities: dict[str, tuple[str, str]] = {}
            url_identities: dict[str, tuple[str, str]] = {}
            for entry in entries:
                try:
                    record = normalize_rss_entry(entry)
                except RssNormalizationError:
                    failures += 1
                    continue
                accepted, conflict = _accept_identity(
                    external_id=record.source_external_id,
                    url_hash=record.canonical_url_hash,
                    content_hash=record.content_hash,
                    external_identities=external_identities,
                    url_identities=url_identities,
                )
                if accepted:
                    records.append(record)
                elif conflict:
                    failures += 1
            return records, failures, ()

        document = parse_google_threat_feed_entries(
            feed_bytes,
            max_entries=MAX_FEED_ENTRIES,
        )
        if document.was_truncated:
            raise ClassifiedFailure(
                FailureCategory.UNSUPPORTED_CONTENT,
                "The Google Threat feed exceeds the approved record bound.",
            )
        candidates: list[PublicationCandidate] = []
        failures = 0
        owned_validation_diagnostics: list[_OwnedValidationDiagnostic] = []
        external_identities: dict[str, tuple[str, str]] = {}
        url_identities: dict[str, tuple[str, str]] = {}
        for entry in document.entries:
            try:
                candidate = adapt_google_threat_publication(entry)
            except GoogleThreatPublicationRecordError as error:
                if error.source_slug == self.source_slug:
                    failures += 1
                    owned_validation_diagnostics.append(
                        _OwnedValidationDiagnostic(
                            failure_stage=error.failure_stage,
                            diagnostic_fingerprint=error.diagnostic_fingerprint,
                        )
                    )
                continue
            if candidate.source_slug != self.source_slug:
                continue
            try:
                normalized = normalize_publication_candidate(candidate)
            except (PublicationCandidateError, PublicationSourceError):
                failures += 1
                continue
            accepted, conflict = _accept_identity(
                external_id=normalized.source_external_id,
                url_hash=normalized.canonical_url_hash,
                content_hash=normalized.content_hash,
                external_identities=external_identities,
                url_identities=url_identities,
            )
            if accepted:
                candidates.append(candidate)
            elif conflict:
                failures += 1
        return candidates, failures, tuple(owned_validation_diagnostics)


def _persist_owned_validation_diagnostics(
    session: Session,
    *,
    run_id: int,
    diagnostics: tuple[_OwnedValidationDiagnostic, ...],
    occurred_at: datetime,
) -> None:
    for diagnostic in diagnostics:
        session.add(
            IngestionError(
                ingestion_run_id=run_id,
                ingestion_run_record_id=None,
                source_record_id=None,
                error_type="google_threat_publication_validation_error",
                safe_message=(
                    "A Google Threat publication failed safe validation."
                ),
                failure_stage=diagnostic.failure_stage,
                diagnostic_fingerprint=diagnostic.diagnostic_fingerprint,
                safe_context=None,
                retryable=False,
                retry_count=0,
                occurred_at=occurred_at,
            )
        )


def _outcome_evidence(persisted) -> OutcomeEvidence:
    return OutcomeEvidence(
        outcome=persisted.outcome,
        source_record_id=getattr(persisted.source_record, "id", None),
        intelligence_item_id=persisted.intelligence_item_id,
        safe_detail="C02 processed one validated publication metadata record.",
    )


def _accept_identity(
    *,
    external_id: str,
    url_hash: str,
    content_hash: str,
    external_identities: dict[str, tuple[str, str]],
    url_identities: dict[str, tuple[str, str]],
) -> tuple[bool, bool]:
    external_match = external_identities.get(external_id)
    url_match = url_identities.get(url_hash)
    if external_match is None and url_match is None:
        external_identities[external_id] = (url_hash, content_hash)
        url_identities[url_hash] = (external_id, content_hash)
        return True, False
    exact = (
        external_match == (url_hash, content_hash)
        and url_match == (external_id, content_hash)
    )
    return False, not exact


__all__ = [
    "CERT_EU_SOURCE_SLUG",
    "GOOGLE_SOURCE_SLUG",
    "MANDIANT_SOURCE_SLUG",
    "MAX_FEED_ENTRIES",
    "PUBLICATION_SOURCE_SLUGS",
    "PublicationSourceHandler",
]
