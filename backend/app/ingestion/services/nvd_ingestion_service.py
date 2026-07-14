"""Caller-transactional persistence for normalized NVD CVE records."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.normalizers.nvd import NormalizedNvdCve
from app.ingestion.source_registry import get_source_definition
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
    Vulnerability,
)
from app.models.common import utc_now
from app.processing.uae_classification_service import UaeClassificationService


_NVD_SOURCE = get_source_definition("nvd")
NVD_SOURCE_SLUG = _NVD_SOURCE.slug
NVD_SOURCE_NAME = _NVD_SOURCE.display_name
NVD_SOURCE_TYPE = _NVD_SOURCE.source_type
NVD_SOURCE_BASE_URL = _NVD_SOURCE.base_url
NVD_RATE_LIMIT_NOTES = _NVD_SOURCE.rate_limit_notes
VALID_OUTCOMES = {"created", "updated", "unchanged", "failed"}


class NvdPersistenceError(RuntimeError):
    """A database operation failed without exposing database details."""


@dataclass(frozen=True)
class NvdPersistenceResult:
    """Sanitized outcome for one normalized NVD CVE."""

    cve_id: str
    outcome: str
    message: str | None = None

    def __post_init__(self) -> None:
        if self.outcome not in VALID_OUTCOMES:
            raise ValueError("Invalid NVD persistence outcome.")


class NvdIngestionService:
    """Persist normalized NVD data without owning commit or rollback."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def ensure_source(self) -> IntelligenceSource:
        """Create or validate the fixed NVD source without committing."""

        try:
            source, failure = self._get_or_create_source()
            if failure is not None:
                raise NvdPersistenceError(failure)
            return source
        except SQLAlchemyError as exc:
            raise NvdPersistenceError(
                "Database error while preparing the approved NVD source."
            ) from exc

    def persist_many(
        self,
        records: Iterable[NormalizedNvdCve],
        *,
        observed_at: datetime | None = None,
    ) -> list[NvdPersistenceResult]:
        observation_time = observed_at or utc_now()
        return [
            self.persist(record, observed_at=observation_time) for record in records
        ]

    def persist(
        self,
        normalized: NormalizedNvdCve,
        *,
        observed_at: datetime | None = None,
    ) -> NvdPersistenceResult:
        observation_time = observed_at or utc_now()
        if observation_time.tzinfo is None or observation_time.utcoffset() is None:
            return self._failed(
                normalized.cve_id,
                "The NVD observation time must be timezone-aware.",
            )

        try:
            source, source_failure = self._get_or_create_source()
            if source_failure is not None:
                return self._failed(normalized.cve_id, source_failure)

            identifier = self._find_identifier(normalized.cve_id)
            source_record = self._find_source_record(source, normalized.cve_id)
            conflict = self._conflict_message(identifier, source_record)
            if conflict is not None:
                return self._failed(normalized.cve_id, conflict)

            if identifier is None and source_record is None:
                self._create_records(source, normalized, observation_time)
                self._session.flush()
                return NvdPersistenceResult(normalized.cve_id, "created")

            item = (
                identifier.intelligence_item
                if identifier is not None
                else source_record.intelligence_item
            )
            if item is None or item.item_type != "vulnerability":
                return self._failed(
                    normalized.cve_id,
                    "The existing CVE identifier does not belong to a vulnerability.",
                )

            if source_record is None:
                source_record = self._create_source_record(
                    source,
                    item,
                    normalized,
                    observation_time,
                )
            if identifier is None:
                if any(existing.is_primary for existing in item.identifiers):
                    return self._failed(
                        normalized.cve_id,
                        "The existing vulnerability already has a different primary identifier.",
                    )
                identifier = self._create_identifier(item, source_record, normalized)

            if source_record.content_hash == normalized.content_hash:
                item.last_seen_at = observation_time
                source_record.last_seen_at = observation_time
                source_record.payload_collected_at = observation_time
                source_record.upstream_status = "present"
                _, extension_created = self._ensure_vulnerability(
                    item,
                    normalized,
                )
                self._session.flush()
                outcome = "updated" if extension_created else "unchanged"
                return NvdPersistenceResult(normalized.cve_id, outcome)

            self._apply_update(item, source_record, normalized, observation_time)
            self._session.flush()
            return NvdPersistenceResult(normalized.cve_id, "updated")
        except SQLAlchemyError as exc:
            raise NvdPersistenceError(
                "Database error while persisting normalized NVD data."
            ) from exc

    def _get_or_create_source(
        self,
    ) -> tuple[IntelligenceSource, str | None]:
        source = self._session.execute(
            select(IntelligenceSource).where(
                IntelligenceSource.slug == NVD_SOURCE_SLUG
            )
        ).scalar_one_or_none()
        if source is None:
            source = IntelligenceSource(
                slug=NVD_SOURCE_SLUG,
                name=NVD_SOURCE_NAME,
                source_type=NVD_SOURCE_TYPE,
                base_url=NVD_SOURCE_BASE_URL,
                is_enabled=True,
                rate_limit_notes=NVD_RATE_LIMIT_NOTES,
                checkpoint_value=None,
            )
            self._session.add(source)
            self._session.flush()
            return source, None

        expected = (
            source.name == NVD_SOURCE_NAME
            and source.source_type == NVD_SOURCE_TYPE
            and source.base_url == NVD_SOURCE_BASE_URL
        )
        if not expected:
            return source, "The existing NVD source configuration conflicts with the approved source."
        return source, None

    def _find_identifier(
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

    @staticmethod
    def _conflict_message(
        identifier: IntelligenceItemIdentifier | None,
        source_record: SourceRecord | None,
    ) -> str | None:
        if source_record is not None and source_record.intelligence_item is None:
            return "The existing NVD source record is not linked to an intelligence item."
        if (
            identifier is not None
            and source_record is not None
            and identifier.intelligence_item is not source_record.intelligence_item
        ):
            return "The CVE identifier and NVD source record refer to different items."
        return None

    def _create_records(
        self,
        source: IntelligenceSource,
        normalized: NormalizedNvdCve,
        observed_at: datetime,
    ) -> None:
        item = IntelligenceItem(
            item_type="vulnerability",
            canonical_title=normalized.title,
            summary=normalized.summary,
            canonical_url=normalized.canonical_url,
            source_published_at=normalized.source_published_at,
            source_modified_at=normalized.source_modified_at,
            collected_at=observed_at,
            last_seen_at=observed_at,
            status=normalized.status,
            data_confidence=Decimal("1.000"),
            geographic_scope="global",
            uae_relevance_status="unknown",
            uae_relevance_confidence=None,
            uae_relevance_reason=None,
            uae_relevance_method="unassigned",
            analyst_review_status="pending",
        )
        UaeClassificationService(self._session).classify_and_apply_if_allowed(item)
        vulnerability = Vulnerability(
            intelligence_item=item,
            severity=normalized.severity,
            cvss_score=normalized.cvss_score,
            cvss_vector=normalized.cvss_vector,
            cvss_version=normalized.cvss_version,
            epss_score=None,
            epss_percentile=None,
            kev_status="unknown",
            kev_last_checked_at=None,
            kev_date_added=None,
            kev_due_date=None,
            kev_required_action=None,
            known_ransomware_campaign_use=None,
            affected_summary=normalized.affected_summary,
            affected_products_json=normalized.affected_products,
        )
        source_record = self._create_source_record(
            source,
            item,
            normalized,
            observed_at,
        )
        identifier = self._create_identifier(item, source_record, normalized)
        self._session.add(item)
        self._session.add(vulnerability)
        self._session.add(source_record)
        self._session.add(identifier)

    def _create_source_record(
        self,
        source: IntelligenceSource,
        item: IntelligenceItem,
        normalized: NormalizedNvdCve,
        observed_at: datetime,
    ) -> SourceRecord:
        source_record = SourceRecord(
            source=source,
            intelligence_item=item,
            source_external_id=normalized.cve_id,
            source_url=normalized.canonical_url,
            canonical_url_hash=None,
            content_hash=normalized.content_hash,
            is_primary_reference=True,
            raw_payload=normalized.raw_payload,
            payload_collected_at=observed_at,
            first_seen_at=observed_at,
            last_seen_at=observed_at,
            source_published_at=normalized.source_published_at,
            source_modified_at=normalized.source_modified_at,
            processing_status="processed",
            last_processed_at=observed_at,
            safe_error_summary=None,
            upstream_status="present",
        )
        self._session.add(source_record)
        return source_record

    def _create_identifier(
        self,
        item: IntelligenceItem,
        source_record: SourceRecord,
        normalized: NormalizedNvdCve,
    ) -> IntelligenceItemIdentifier:
        identifier = IntelligenceItemIdentifier(
            intelligence_item=item,
            source=None,
            source_record=source_record,
            namespace="cve",
            identifier_value=normalized.cve_id,
            normalized_value=normalized.cve_id,
            is_primary=True,
        )
        self._session.add(identifier)
        return identifier

    def _apply_update(
        self,
        item: IntelligenceItem,
        source_record: SourceRecord,
        normalized: NormalizedNvdCve,
        observed_at: datetime,
    ) -> None:
        item.canonical_title = normalized.title
        item.summary = normalized.summary
        item.canonical_url = normalized.canonical_url
        item.source_published_at = normalized.source_published_at
        item.source_modified_at = normalized.source_modified_at
        item.last_seen_at = observed_at
        item.status = normalized.status
        UaeClassificationService(self._session).classify_and_apply_if_allowed(item)

        vulnerability, _ = self._ensure_vulnerability(item, normalized)
        vulnerability.severity = normalized.severity
        vulnerability.cvss_score = normalized.cvss_score
        vulnerability.cvss_vector = normalized.cvss_vector
        vulnerability.cvss_version = normalized.cvss_version
        vulnerability.affected_summary = normalized.affected_summary
        vulnerability.affected_products_json = normalized.affected_products

        source_record.source_url = normalized.canonical_url
        source_record.content_hash = normalized.content_hash
        source_record.raw_payload = normalized.raw_payload
        source_record.payload_collected_at = observed_at
        source_record.last_seen_at = observed_at
        source_record.source_published_at = normalized.source_published_at
        source_record.source_modified_at = normalized.source_modified_at
        source_record.processing_status = "processed"
        source_record.last_processed_at = observed_at
        source_record.safe_error_summary = None
        source_record.upstream_status = "present"

    def _ensure_vulnerability(
        self,
        item: IntelligenceItem,
        normalized: NormalizedNvdCve,
    ) -> tuple[Vulnerability, bool]:
        vulnerability = item.vulnerability
        if vulnerability is not None:
            return vulnerability, False

        vulnerability = Vulnerability(
            intelligence_item=item,
            severity=normalized.severity,
            cvss_score=normalized.cvss_score,
            cvss_vector=normalized.cvss_vector,
            cvss_version=normalized.cvss_version,
            epss_score=None,
            epss_percentile=None,
            kev_status="unknown",
            kev_last_checked_at=None,
            kev_date_added=None,
            kev_due_date=None,
            kev_required_action=None,
            known_ransomware_campaign_use=None,
            affected_summary=normalized.affected_summary,
            affected_products_json=normalized.affected_products,
        )
        self._session.add(vulnerability)
        return vulnerability, True

    @staticmethod
    def _failed(cve_id: str, message: str) -> NvdPersistenceResult:
        return NvdPersistenceResult(cve_id=cve_id, outcome="failed", message=message)
