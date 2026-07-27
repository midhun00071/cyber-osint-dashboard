"""Caller-transaction-owned persistence for deterministic IOC extraction."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload

from app.indicators.text_extraction import IOCTextExtractionError, extract_iocs
from app.models import (
    Indicator,
    IndicatorProvenance,
    IntelligenceItemIndicator,
    SourceRecord,
)


ELIGIBLE_ITEM_TYPES = frozenset({"security_advisory", "threat_report"})


class IOCExtractionServiceError(RuntimeError):
    """Sanitized persistence failure for one source-record extraction."""


@dataclass(frozen=True, slots=True)
class IOCExtractionServiceResult:
    """Immutable safe counters for one source-record extraction attempt."""

    status: str
    candidates_found: int = 0
    rejected_candidates: int = 0
    indicators_created: int = 0
    indicators_existing: int = 0
    relationships_created: int = 0
    relationships_updated: int = 0
    relationships_unchanged: int = 0
    provenances_created: int = 0
    provenances_updated: int = 0
    provenances_unchanged: int = 0
    suppressed_false_positive: int = 0
    bounded: bool = False


@dataclass(slots=True)
class _Counts:
    indicators_created: int = 0
    indicators_existing: int = 0
    relationships_created: int = 0
    relationships_updated: int = 0
    relationships_unchanged: int = 0
    provenances_created: int = 0
    provenances_updated: int = 0
    provenances_unchanged: int = 0
    suppressed_false_positive: int = 0


class IOCExtractionService:
    """Extract and persist IOC metadata without owning the transaction."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def extract_source_record(
        self,
        source_record_id: int,
        *,
        observed_at: datetime | None = None,
    ) -> IOCExtractionServiceResult:
        if (
            not isinstance(source_record_id, int)
            or isinstance(source_record_id, bool)
            or source_record_id <= 0
        ):
            raise ValueError("source_record_id must be a positive integer.")
        if observed_at is not None:
            _aware_utc(observed_at)

        try:
            source_record = self._session.get(
                SourceRecord,
                source_record_id,
                options=(
                    joinedload(SourceRecord.intelligence_item),
                    joinedload(SourceRecord.source),
                ),
            )
            eligibility = self._eligibility_status(source_record)
            if eligibility is not None:
                return IOCExtractionServiceResult(status=eligibility)
            assert source_record is not None
            assert source_record.intelligence_item is not None
            assert source_record.source is not None

            item = source_record.intelligence_item
            observation_time = self._observation_time(
                source_record,
                observed_at,
            )
            excluded_urls = tuple(
                value
                for value in (
                    item.canonical_url,
                    source_record.source_url,
                    source_record.source.base_url,
                )
                if value
            )
            try:
                extraction = extract_iocs(
                    item.canonical_title,
                    item.summary,
                    excluded_urls=excluded_urls,
                )
            except IOCTextExtractionError:
                return IOCExtractionServiceResult(status="rejected_text")

            if extraction.status == "rejected_text_limit":
                return IOCExtractionServiceResult(
                    status="rejected_text_limit",
                    bounded=True,
                )
            if not extraction.observables:
                return IOCExtractionServiceResult(
                    status="no_candidates",
                    candidates_found=extraction.candidates_found,
                    rejected_candidates=extraction.rejected_candidates,
                    bounded=extraction.limit_reached,
                )

            counts = _Counts()
            for extracted in extraction.observables:
                indicator = self._find_indicator(
                    extracted.normalized.identity_sha256
                )
                if indicator is None:
                    indicator = Indicator(
                        observable_type=extracted.normalized.observable_type,
                        normalized_value=extracted.normalized.normalized_value,
                        hash_algorithm=extracted.normalized.hash_algorithm,
                        identity_sha256=extracted.normalized.identity_sha256,
                        status="active",
                        confidence=extracted.confidence,
                        context_summary=None,
                        first_seen_at=observation_time,
                        last_seen_at=observation_time,
                        revoked_at=None,
                        expires_at=None,
                    )
                    self._session.add(indicator)
                    self._session.flush()
                    counts.indicators_created += 1
                else:
                    counts.indicators_existing += 1
                    if indicator.status == "false_positive":
                        counts.suppressed_false_positive += 1
                        continue
                    self._update_indicator_observation(
                        indicator,
                        observation_time,
                        extracted.confidence,
                    )

                self._upsert_relationship(
                    item.id,
                    indicator.id,
                    observation_time,
                    extracted.confidence,
                    extracted.context_summary,
                    counts,
                )
                self._upsert_provenance(
                    indicator.id,
                    source_record.source_id,
                    source_record.id,
                    observation_time,
                    extracted.confidence,
                    extracted.context_summary,
                    counts,
                )

            return IOCExtractionServiceResult(
                status="bounded" if extraction.limit_reached else "processed",
                candidates_found=extraction.candidates_found,
                rejected_candidates=extraction.rejected_candidates,
                indicators_created=counts.indicators_created,
                indicators_existing=counts.indicators_existing,
                relationships_created=counts.relationships_created,
                relationships_updated=counts.relationships_updated,
                relationships_unchanged=counts.relationships_unchanged,
                provenances_created=counts.provenances_created,
                provenances_updated=counts.provenances_updated,
                provenances_unchanged=counts.provenances_unchanged,
                suppressed_false_positive=counts.suppressed_false_positive,
                bounded=extraction.limit_reached,
            )
        except SQLAlchemyError as exc:
            raise IOCExtractionServiceError(
                "Database error while extracting publication indicators."
            ) from exc

    @staticmethod
    def _eligibility_status(source_record: SourceRecord | None) -> str | None:
        if source_record is None:
            return "skipped_missing_source_record"
        if source_record.intelligence_item is None:
            return "skipped_missing_intelligence_item"
        if source_record.source is None:
            return "skipped_missing_intelligence_source"
        if (
            source_record.processing_status != "processed"
            or source_record.upstream_status != "present"
        ):
            return "skipped_source_record_state"
        if source_record.intelligence_item.item_type not in ELIGIBLE_ITEM_TYPES:
            return "skipped_item_type"
        return None

    @staticmethod
    def _observation_time(
        source_record: SourceRecord,
        supplied: datetime | None,
    ) -> datetime:
        assert source_record.intelligence_item is not None
        selected = (
            source_record.intelligence_item.source_published_at
            or source_record.source_published_at
            or supplied
            or source_record.first_seen_at
        )
        return _aware_utc(selected)

    def _find_indicator(self, identity_sha256: str) -> Indicator | None:
        statement = select(Indicator).where(
            Indicator.identity_sha256 == identity_sha256
        )
        return self._session.execute(statement).scalar_one_or_none()

    def _upsert_relationship(
        self,
        item_id: int,
        indicator_id: int,
        observed_at: datetime,
        confidence: Decimal,
        context_summary: str,
        counts: _Counts,
    ) -> None:
        statement = select(IntelligenceItemIndicator).where(
            IntelligenceItemIndicator.intelligence_item_id == item_id,
            IntelligenceItemIndicator.indicator_id == indicator_id,
        )
        relationship = self._session.execute(statement).scalar_one_or_none()
        if relationship is None:
            self._session.add(
                IntelligenceItemIndicator(
                    intelligence_item_id=item_id,
                    indicator_id=indicator_id,
                    relationship_type="mentioned",
                    extraction_method="deterministic_text",
                    confidence=confidence,
                    context_summary=context_summary[:500],
                    first_observed_at=observed_at,
                    last_observed_at=observed_at,
                )
            )
            counts.relationships_created += 1
            return
        if _update_evidence(
            relationship,
            observed_at,
            confidence,
            context_summary[:500],
        ):
            counts.relationships_updated += 1
        else:
            counts.relationships_unchanged += 1

    def _upsert_provenance(
        self,
        indicator_id: int,
        source_id: int,
        source_record_id: int,
        observed_at: datetime,
        confidence: Decimal,
        context_summary: str,
        counts: _Counts,
    ) -> None:
        statement = select(IndicatorProvenance).where(
            IndicatorProvenance.indicator_id == indicator_id,
            IndicatorProvenance.source_id == source_id,
            IndicatorProvenance.source_record_id == source_record_id,
        )
        provenance = self._session.execute(statement).scalar_one_or_none()
        if provenance is None:
            self._session.add(
                IndicatorProvenance(
                    indicator_id=indicator_id,
                    source_id=source_id,
                    source_record_id=source_record_id,
                    confidence=confidence,
                    context_summary=context_summary[:500],
                    first_observed_at=observed_at,
                    last_observed_at=observed_at,
                )
            )
            counts.provenances_created += 1
            return
        if _update_evidence(
            provenance,
            observed_at,
            confidence,
            context_summary[:500],
        ):
            counts.provenances_updated += 1
        else:
            counts.provenances_unchanged += 1

    @staticmethod
    def _update_indicator_observation(
        indicator: Indicator,
        observed_at: datetime,
        confidence: Decimal,
    ) -> None:
        if indicator.first_seen_at is None or observed_at < indicator.first_seen_at:
            indicator.first_seen_at = observed_at
        if indicator.last_seen_at is None or observed_at > indicator.last_seen_at:
            indicator.last_seen_at = observed_at
        if indicator.confidence is None or confidence > indicator.confidence:
            indicator.confidence = confidence


def _update_evidence(
    evidence: IntelligenceItemIndicator | IndicatorProvenance,
    observed_at: datetime,
    confidence: Decimal,
    context_summary: str,
) -> bool:
    changed = False
    if evidence.first_observed_at is None or observed_at < evidence.first_observed_at:
        evidence.first_observed_at = observed_at
        changed = True
    if evidence.last_observed_at is None or observed_at > evidence.last_observed_at:
        evidence.last_observed_at = observed_at
        changed = True
    if evidence.confidence is None or confidence > evidence.confidence:
        evidence.confidence = confidence
        evidence.context_summary = context_summary
        changed = True
    elif evidence.context_summary is None:
        evidence.context_summary = context_summary
        changed = True
    return changed


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Observation timestamps must be timezone-aware.")
    return value.astimezone(UTC)
