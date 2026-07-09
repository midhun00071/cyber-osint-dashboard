"""Caller-transactional persistence for normalized CISA KEV entries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, time

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.collectors.cisa_kev_client import CISA_KEV_CATALOG_URL
from app.ingestion.normalizers.cisa_kev import NormalizedCisaKevEntry
from app.models import (
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
)
from app.models.common import utc_now


CISA_KEV_SOURCE_SLUG = "cisa-kev"
CISA_KEV_SOURCE_NAME = "CISA Known Exploited Vulnerabilities Catalog"
CISA_KEV_SOURCE_TYPE = "json"
CISA_KEV_SOURCE_BASE_URL = CISA_KEV_CATALOG_URL
CISA_KEV_RATE_LIMIT_NOTES = "Use bounded manual requests to the official CISA KEV JSON catalog."
VALID_OUTCOMES = {"created", "updated", "unchanged", "skipped", "failed"}


class CisaKevPersistenceError(RuntimeError):
    """A database operation failed without exposing database details."""


@dataclass(frozen=True)
class CisaKevPersistenceResult:
    """Sanitized outcome for one normalized CISA KEV entry."""

    cve_id: str
    outcome: str
    message: str | None = None
    source_record: SourceRecord | None = None
    intelligence_item_id: int | None = None

    def __post_init__(self) -> None:
        if self.outcome not in VALID_OUTCOMES:
            raise ValueError("Invalid CISA KEV persistence outcome.")


class CisaKevIngestionService:
    """Persist CISA KEV enrichment without owning commit or rollback."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def ensure_source(self) -> IntelligenceSource:
        """Create or validate the fixed CISA KEV source without committing."""

        try:
            source, failure = self._get_or_create_source()
            if failure is not None:
                raise CisaKevPersistenceError(failure)
            return source
        except SQLAlchemyError as exc:
            raise CisaKevPersistenceError(
                "Database error while preparing the approved CISA KEV source."
            ) from exc

    def enrich(
        self,
        normalized: NormalizedCisaKevEntry,
        *,
        observed_at: datetime | None = None,
    ) -> CisaKevPersistenceResult:
        observation_time = observed_at or utc_now()
        if observation_time.tzinfo is None or observation_time.utcoffset() is None:
            return self._result(
                normalized.cve_id,
                "failed",
                "The CISA KEV observation time must be timezone-aware.",
            )
        observation_time = observation_time.astimezone(UTC)
        date_added_datetime = datetime.combine(
            normalized.date_added,
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
                    "No existing local CVE item matched the CISA KEV entry.",
                    source_record=source_record,
                )

            item = identifier.intelligence_item
            if source_record is not None and source_record.intelligence_item is not item:
                return self._result(
                    normalized.cve_id,
                    "failed",
                    "The existing CISA KEV source record is linked to a different item.",
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

            if source_record is None:
                source_record = self._create_source_record(
                    source,
                    item,
                    normalized,
                    observation_time,
                    date_added_datetime,
                )
                self._apply_vulnerability_update(vulnerability, normalized, observation_time)
                self._session.flush()
                return self._result(
                    normalized.cve_id,
                    "created",
                    source_record=source_record,
                    intelligence_item_id=getattr(item, "id", None),
                )

            unchanged = (
                source_record.content_hash == normalized.content_hash
                and vulnerability.kev_status == "listed"
                and vulnerability.kev_date_added == normalized.date_added
                and vulnerability.kev_due_date == normalized.due_date
                and vulnerability.kev_required_action == normalized.required_action
                and vulnerability.known_ransomware_campaign_use
                == normalized.known_ransomware_campaign_use
            )
            source_record.payload_collected_at = observation_time
            source_record.last_seen_at = observation_time
            source_record.last_processed_at = observation_time
            source_record.upstream_status = "present"
            source_record.processing_status = "processed"
            source_record.safe_error_summary = None
            vulnerability.kev_last_checked_at = observation_time
            if unchanged:
                self._session.flush()
                return self._result(
                    normalized.cve_id,
                    "unchanged",
                    source_record=source_record,
                    intelligence_item_id=getattr(item, "id", None),
                )

            source_record.source_url = CISA_KEV_SOURCE_BASE_URL
            source_record.content_hash = normalized.content_hash
            source_record.raw_payload = normalized.raw_payload
            source_record.source_published_at = date_added_datetime
            source_record.source_modified_at = date_added_datetime
            self._apply_vulnerability_update(vulnerability, normalized, observation_time)
            self._session.flush()
            return self._result(
                normalized.cve_id,
                "updated",
                source_record=source_record,
                intelligence_item_id=getattr(item, "id", None),
            )
        except SQLAlchemyError as exc:
            raise CisaKevPersistenceError(
                "Database error while persisting normalized CISA KEV data."
            ) from exc

    def _get_or_create_source(self) -> tuple[IntelligenceSource, str | None]:
        source = self._session.execute(
            select(IntelligenceSource).where(
                IntelligenceSource.slug == CISA_KEV_SOURCE_SLUG
            )
        ).scalar_one_or_none()
        if source is None:
            source = IntelligenceSource(
                slug=CISA_KEV_SOURCE_SLUG,
                name=CISA_KEV_SOURCE_NAME,
                source_type=CISA_KEV_SOURCE_TYPE,
                base_url=CISA_KEV_SOURCE_BASE_URL,
                is_enabled=True,
                rate_limit_notes=CISA_KEV_RATE_LIMIT_NOTES,
                checkpoint_value=None,
            )
            self._session.add(source)
            self._session.flush()
            return source, None

        expected = (
            source.name == CISA_KEV_SOURCE_NAME
            and source.source_type == CISA_KEV_SOURCE_TYPE
            and source.base_url == CISA_KEV_SOURCE_BASE_URL
        )
        if not expected:
            return source, "The existing CISA KEV source configuration conflicts with the approved source."
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
        normalized: NormalizedCisaKevEntry,
        observed_at: datetime,
        date_added_datetime: datetime,
    ) -> SourceRecord:
        source_record = SourceRecord(
            source=source,
            intelligence_item=item,
            source_external_id=normalized.cve_id,
            source_url=CISA_KEV_SOURCE_BASE_URL,
            canonical_url_hash=None,
            content_hash=normalized.content_hash,
            is_primary_reference=False,
            raw_payload=normalized.raw_payload,
            payload_collected_at=observed_at,
            first_seen_at=observed_at,
            last_seen_at=observed_at,
            source_published_at=date_added_datetime,
            source_modified_at=date_added_datetime,
            processing_status="processed",
            last_processed_at=observed_at,
            safe_error_summary=None,
            upstream_status="present",
        )
        self._session.add(source_record)
        return source_record

    @staticmethod
    def _apply_vulnerability_update(
        vulnerability,
        normalized: NormalizedCisaKevEntry,
        observed_at: datetime,
    ) -> None:
        vulnerability.kev_status = "listed"
        vulnerability.kev_last_checked_at = observed_at
        vulnerability.kev_date_added = normalized.date_added
        vulnerability.kev_due_date = normalized.due_date
        vulnerability.kev_required_action = normalized.required_action
        vulnerability.known_ransomware_campaign_use = (
            normalized.known_ransomware_campaign_use
        )

    @staticmethod
    def _result(
        cve_id: str,
        outcome: str,
        message: str | None = None,
        *,
        source_record: SourceRecord | None = None,
        intelligence_item_id: int | None = None,
    ) -> CisaKevPersistenceResult:
        return CisaKevPersistenceResult(
            cve_id=cve_id,
            outcome=outcome,
            message=message,
            source_record=source_record,
            intelligence_item_id=intelligence_item_id,
        )
