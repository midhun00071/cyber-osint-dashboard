"""Caller-transactional persistence for normalized FIRST EPSS records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, time

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.collectors.epss_client import FIRST_EPSS_API_URL
from app.ingestion.normalizers.epss import NormalizedEpssRecord
from app.models import (
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
)
from app.models.common import utc_now


EPSS_SOURCE_SLUG = "first-epss"
EPSS_SOURCE_NAME = "FIRST EPSS"
EPSS_SOURCE_TYPE = "api"
EPSS_SOURCE_BASE_URL = FIRST_EPSS_API_URL
EPSS_RATE_LIMIT_NOTES = "Use bounded manual requests to the public FIRST EPSS API."
VALID_OUTCOMES = {"created", "updated", "unchanged", "skipped", "failed"}


class EpssPersistenceError(RuntimeError):
    """A database operation failed without exposing database details."""


@dataclass(frozen=True)
class EpssPersistenceResult:
    """Sanitized outcome for one normalized EPSS record."""

    cve_id: str
    outcome: str
    message: str | None = None
    source_record: SourceRecord | None = None
    intelligence_item_id: int | None = None

    def __post_init__(self) -> None:
        if self.outcome not in VALID_OUTCOMES:
            raise ValueError("Invalid EPSS persistence outcome.")


class EpssEnrichmentService:
    """Persist EPSS enrichment without owning commit or rollback."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def ensure_source(self) -> IntelligenceSource:
        """Create or validate the fixed FIRST EPSS source without committing."""

        try:
            source, failure = self._get_or_create_source()
            if failure is not None:
                raise EpssPersistenceError(failure)
            return source
        except SQLAlchemyError as exc:
            raise EpssPersistenceError(
                "Database error while preparing the approved FIRST EPSS source."
            ) from exc

    def enrich(
        self,
        normalized: NormalizedEpssRecord,
        *,
        observed_at: datetime | None = None,
    ) -> EpssPersistenceResult:
        observation_time = observed_at or utc_now()
        if observation_time.tzinfo is None or observation_time.utcoffset() is None:
            return self._result(
                normalized.cve_id,
                "failed",
                "The EPSS observation time must be timezone-aware.",
            )
        observation_time = observation_time.astimezone(UTC)
        score_datetime = datetime.combine(
            normalized.score_date,
            time.min,
            tzinfo=UTC,
        )

        try:
            source, source_failure = self._get_or_create_source()
            if source_failure is not None:
                return self._result(normalized.cve_id, "failed", source_failure)

            identifier = self._find_global_cve_identifier(normalized.cve_id)
            source_record = self._find_source_record(source, normalized.cve_id)
            if identifier is None:
                return self._result(
                    normalized.cve_id,
                    "skipped",
                    "No existing local CVE item matched the EPSS record.",
                    source_record=source_record,
                )

            item = identifier.intelligence_item
            if source_record is not None and source_record.intelligence_item is not item:
                return self._result(
                    normalized.cve_id,
                    "failed",
                    "The existing EPSS source record is linked to a different item.",
                    source_record=source_record,
                    intelligence_item_id=getattr(item, "id", None),
                )
            if item is None or item.item_type != "vulnerability":
                return self._result(
                    normalized.cve_id,
                    "skipped",
                    "The matching CVE item is not a vulnerability.",
                    source_record=source_record,
                )
            vulnerability = item.vulnerability
            if vulnerability is None:
                return self._result(
                    normalized.cve_id,
                    "skipped",
                    "The matching CVE item has no vulnerability extension.",
                    source_record=source_record,
                    intelligence_item_id=getattr(item, "id", None),
                )

            if (
                source_record is not None
                and source_record.source_modified_at is not None
                and source_record.source_modified_at.astimezone(UTC) > score_datetime
            ):
                return self._result(
                    normalized.cve_id,
                    "skipped",
                    "The stored EPSS score date is newer than the received score date.",
                    source_record=source_record,
                    intelligence_item_id=getattr(item, "id", None),
                )

            if source_record is None:
                source_record = self._create_source_record(
                    source,
                    item,
                    normalized,
                    observation_time,
                    score_datetime,
                )
                vulnerability.epss_score = normalized.epss_score
                vulnerability.epss_percentile = normalized.epss_percentile
                self._session.flush()
                return self._result(
                    normalized.cve_id,
                    "created",
                    source_record=source_record,
                    intelligence_item_id=getattr(item, "id", None),
                )

            unchanged = (
                source_record.content_hash == normalized.content_hash
                and vulnerability.epss_score == normalized.epss_score
                and vulnerability.epss_percentile == normalized.epss_percentile
            )
            source_record.payload_collected_at = observation_time
            source_record.last_seen_at = observation_time
            source_record.last_processed_at = observation_time
            source_record.upstream_status = "present"
            source_record.processing_status = "processed"
            source_record.safe_error_summary = None
            if unchanged:
                self._session.flush()
                return self._result(
                    normalized.cve_id,
                    "unchanged",
                    source_record=source_record,
                    intelligence_item_id=getattr(item, "id", None),
                )

            source_record.source_url = EPSS_SOURCE_BASE_URL
            source_record.content_hash = normalized.content_hash
            source_record.raw_payload = normalized.raw_payload
            source_record.source_modified_at = score_datetime
            vulnerability.epss_score = normalized.epss_score
            vulnerability.epss_percentile = normalized.epss_percentile
            self._session.flush()
            return self._result(
                normalized.cve_id,
                "updated",
                source_record=source_record,
                intelligence_item_id=getattr(item, "id", None),
            )
        except SQLAlchemyError as exc:
            raise EpssPersistenceError(
                "Database error while persisting normalized EPSS data."
            ) from exc

    def _get_or_create_source(self) -> tuple[IntelligenceSource, str | None]:
        source = self._session.execute(
            select(IntelligenceSource).where(
                IntelligenceSource.slug == EPSS_SOURCE_SLUG
            )
        ).scalar_one_or_none()
        if source is None:
            source = IntelligenceSource(
                slug=EPSS_SOURCE_SLUG,
                name=EPSS_SOURCE_NAME,
                source_type=EPSS_SOURCE_TYPE,
                base_url=EPSS_SOURCE_BASE_URL,
                is_enabled=True,
                rate_limit_notes=EPSS_RATE_LIMIT_NOTES,
                checkpoint_value=None,
            )
            self._session.add(source)
            self._session.flush()
            return source, None

        expected = (
            source.name == EPSS_SOURCE_NAME
            and source.source_type == EPSS_SOURCE_TYPE
            and source.base_url == EPSS_SOURCE_BASE_URL
        )
        if not expected:
            return source, "The existing EPSS source configuration conflicts with the approved source."
        return source, None

    def _find_global_cve_identifier(
        self,
        cve_id: str,
    ) -> IntelligenceItemIdentifier | None:
        return self._session.execute(
            select(IntelligenceItemIdentifier)
            .where(IntelligenceItemIdentifier.source_id.is_(None))
            .where(IntelligenceItemIdentifier.namespace == "cve")
            .where(IntelligenceItemIdentifier.normalized_value == cve_id)
        ).scalar_one_or_none()

    def _find_source_record(
        self,
        source: IntelligenceSource,
        cve_id: str,
    ) -> SourceRecord | None:
        return self._session.execute(
            select(SourceRecord)
            .where(SourceRecord.source_id == source.id)
            .where(SourceRecord.source_external_id == cve_id)
        ).scalar_one_or_none()

    def _create_source_record(
        self,
        source: IntelligenceSource,
        item,
        normalized: NormalizedEpssRecord,
        observed_at: datetime,
        score_datetime: datetime,
    ) -> SourceRecord:
        source_record = SourceRecord(
            source=source,
            intelligence_item=item,
            source_external_id=normalized.cve_id,
            source_url=EPSS_SOURCE_BASE_URL,
            canonical_url_hash=None,
            content_hash=normalized.content_hash,
            is_primary_reference=False,
            raw_payload=normalized.raw_payload,
            payload_collected_at=observed_at,
            first_seen_at=observed_at,
            last_seen_at=observed_at,
            source_published_at=None,
            source_modified_at=score_datetime,
            processing_status="processed",
            last_processed_at=observed_at,
            safe_error_summary=None,
            upstream_status="present",
        )
        self._session.add(source_record)
        return source_record

    @staticmethod
    def _result(
        cve_id: str,
        outcome: str,
        message: str | None = None,
        *,
        source_record: SourceRecord | None = None,
        intelligence_item_id: int | None = None,
    ) -> EpssPersistenceResult:
        return EpssPersistenceResult(
            cve_id=cve_id,
            outcome=outcome,
            message=message,
            source_record=source_record,
            intelligence_item_id=intelligence_item_id,
        )
