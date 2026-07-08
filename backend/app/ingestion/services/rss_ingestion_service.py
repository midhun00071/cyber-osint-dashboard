"""Caller-transactional persistence for normalized CERT-EU RSS advisories."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.collectors.rss_client import CERT_EU_FEED_URL
from app.ingestion.normalizers.rss import NormalizedRssEntry
from app.models import IntelligenceItem, IntelligenceSource, SourceRecord
from app.models.common import utc_now


RSS_SOURCE_SLUG = "cert-eu-security-advisories"
RSS_SOURCE_NAME = "CERT-EU Security Advisories"
RSS_SOURCE_TYPE = "rss"
RSS_SOURCE_BASE_URL = CERT_EU_FEED_URL
RSS_RATE_LIMIT_NOTES = "Manual bounded requests to the approved CERT-EU RSS feed only."
VALID_OUTCOMES = {"created", "updated", "unchanged", "skipped", "failed"}


class RssPersistenceError(RuntimeError):
    """A database operation failed without exposing database details."""


@dataclass(frozen=True)
class RssPersistenceResult:
    """Sanitized outcome for one normalized RSS advisory."""

    source_external_id: str
    outcome: str
    message: str | None = None
    source_record: SourceRecord | None = None
    intelligence_item_id: int | None = None

    def __post_init__(self) -> None:
        if self.outcome not in VALID_OUTCOMES:
            raise ValueError("Invalid RSS persistence outcome.")


class RssIngestionService:
    """Persist normalized CERT-EU advisories without committing or rolling back."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def ensure_source(self) -> IntelligenceSource:
        """Create or validate the fixed CERT-EU RSS source without committing."""

        try:
            source, failure = self._get_or_create_source()
            if failure is not None:
                raise RssPersistenceError(failure)
            return source
        except SQLAlchemyError as exc:
            raise RssPersistenceError(
                "Database error while preparing the approved CERT-EU RSS source."
            ) from exc

    def persist(
        self,
        normalized: NormalizedRssEntry,
        *,
        observed_at: datetime | None = None,
    ) -> RssPersistenceResult:
        observation_time = observed_at or utc_now()
        if observation_time.tzinfo is None or observation_time.utcoffset() is None:
            return self._result(
                normalized.source_external_id,
                "failed",
                "The RSS observation time must be timezone-aware.",
            )

        try:
            source, source_failure = self._get_or_create_source()
            if source_failure is not None:
                return self._result(normalized.source_external_id, "failed", source_failure)

            by_external_id = self._find_by_external_id(source, normalized.source_external_id)
            by_url_hash = self._find_by_url_hash(source, normalized.canonical_url_hash)
            if (
                by_external_id is not None
                and by_url_hash is not None
                and by_external_id is not by_url_hash
            ):
                return self._result(
                    normalized.source_external_id,
                    "failed",
                    "The RSS external ID and URL hash refer to different source records.",
                    source_record=by_external_id,
                    intelligence_item_id=getattr(by_external_id.intelligence_item, "id", None),
                )

            source_record = by_external_id or by_url_hash
            if source_record is None:
                source_record = self._create_records(source, normalized, observation_time)
                self._session.flush()
                return self._result(
                    normalized.source_external_id,
                    "created",
                    source_record=source_record,
                    intelligence_item_id=getattr(source_record.intelligence_item, "id", None),
                )

            item = source_record.intelligence_item
            if item is None or item.item_type != "security_advisory":
                return self._result(
                    normalized.source_external_id,
                    "failed",
                    "The existing RSS source record is not linked to a security advisory.",
                    source_record=source_record,
                    intelligence_item_id=getattr(item, "id", None),
                )

            source_record.last_seen_at = observation_time
            source_record.payload_collected_at = observation_time
            source_record.last_processed_at = observation_time
            source_record.upstream_status = "present"
            source_record.processing_status = "processed"
            source_record.safe_error_summary = None
            item.last_seen_at = observation_time

            if source_record.content_hash == normalized.content_hash:
                self._session.flush()
                return self._result(
                    normalized.source_external_id,
                    "unchanged",
                    source_record=source_record,
                    intelligence_item_id=getattr(item, "id", None),
                )

            self._apply_update(item, source_record, normalized)
            self._session.flush()
            return self._result(
                normalized.source_external_id,
                "updated",
                source_record=source_record,
                intelligence_item_id=getattr(item, "id", None),
            )
        except SQLAlchemyError as exc:
            raise RssPersistenceError(
                "Database error while persisting normalized RSS data."
            ) from exc

    def _get_or_create_source(self) -> tuple[IntelligenceSource, str | None]:
        source = self._session.execute(
            select(IntelligenceSource).where(IntelligenceSource.slug == RSS_SOURCE_SLUG)
        ).scalar_one_or_none()
        if source is None:
            source = IntelligenceSource(
                slug=RSS_SOURCE_SLUG,
                name=RSS_SOURCE_NAME,
                source_type=RSS_SOURCE_TYPE,
                base_url=RSS_SOURCE_BASE_URL,
                is_enabled=True,
                rate_limit_notes=RSS_RATE_LIMIT_NOTES,
                checkpoint_value=None,
            )
            self._session.add(source)
            self._session.flush()
            return source, None

        expected = (
            source.name == RSS_SOURCE_NAME
            and source.source_type == RSS_SOURCE_TYPE
            and source.base_url == RSS_SOURCE_BASE_URL
        )
        if not expected:
            return source, "The existing RSS source configuration conflicts with the approved source."
        return source, None

    def _find_by_external_id(
        self,
        source: IntelligenceSource,
        source_external_id: str,
    ) -> SourceRecord | None:
        return self._session.execute(
            select(SourceRecord)
            .where(SourceRecord.source_id == source.id)
            .where(SourceRecord.source_external_id == source_external_id)
        ).scalar_one_or_none()

    def _find_by_url_hash(
        self,
        source: IntelligenceSource,
        canonical_url_hash: str,
    ) -> SourceRecord | None:
        return self._session.execute(
            select(SourceRecord)
            .where(SourceRecord.source_id == source.id)
            .where(SourceRecord.canonical_url_hash == canonical_url_hash)
        ).scalar_one_or_none()

    def _create_records(
        self,
        source: IntelligenceSource,
        normalized: NormalizedRssEntry,
        observed_at: datetime,
    ) -> SourceRecord:
        item = IntelligenceItem(
            item_type="security_advisory",
            canonical_title=normalized.canonical_title,
            summary=normalized.summary,
            canonical_url=normalized.canonical_url,
            source_published_at=normalized.source_published_at,
            source_modified_at=normalized.source_modified_at,
            collected_at=observed_at,
            last_seen_at=observed_at,
            status="active",
            data_confidence=Decimal("0.900"),
            geographic_scope="global",
            uae_relevance_status="unknown",
            uae_relevance_confidence=None,
            uae_relevance_reason=None,
            uae_relevance_method="unassigned",
            analyst_review_status="pending",
        )
        source_record = SourceRecord(
            source=source,
            intelligence_item=item,
            source_external_id=normalized.source_external_id,
            source_url=normalized.canonical_url,
            canonical_url_hash=normalized.canonical_url_hash,
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
        self._session.add(item)
        self._session.add(source_record)
        return source_record

    @staticmethod
    def _apply_update(
        item: IntelligenceItem,
        source_record: SourceRecord,
        normalized: NormalizedRssEntry,
    ) -> None:
        item.canonical_title = normalized.canonical_title
        item.summary = normalized.summary
        item.canonical_url = normalized.canonical_url
        item.source_published_at = normalized.source_published_at
        item.source_modified_at = normalized.source_modified_at

        source_record.source_external_id = normalized.source_external_id
        source_record.source_url = normalized.canonical_url
        source_record.canonical_url_hash = normalized.canonical_url_hash
        source_record.content_hash = normalized.content_hash
        source_record.raw_payload = normalized.raw_payload
        source_record.source_published_at = normalized.source_published_at
        source_record.source_modified_at = normalized.source_modified_at

    @staticmethod
    def _result(
        source_external_id: str,
        outcome: str,
        message: str | None = None,
        *,
        source_record: SourceRecord | None = None,
        intelligence_item_id: int | None = None,
    ) -> RssPersistenceResult:
        return RssPersistenceResult(
            source_external_id=source_external_id,
            outcome=outcome,
            message=message,
            source_record=source_record,
            intelligence_item_id=intelligence_item_id,
        )
