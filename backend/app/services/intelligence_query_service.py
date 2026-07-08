"""Read-only query service for safe intelligence item API responses."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from app.api.v1.schemas.intelligence import (
    IntelligenceItemListResponse,
    IntelligenceItemSummary,
)
from app.ingestion.services.epss_enrichment_service import EPSS_SOURCE_SLUG
from app.models import IntelligenceItem, IntelligenceItemIdentifier, SourceRecord


DEFAULT_ITEM_TYPE = "vulnerability"


class IntelligenceQueryError(RuntimeError):
    """A read query failed without exposing database internals."""


class IntelligenceNotFoundError(IntelligenceQueryError):
    """The requested intelligence item does not exist."""


@dataclass(frozen=True)
class IntelligenceQueryFilters:
    """Allow-listed filters for read-only intelligence list queries."""

    q: str | None = None
    severity: str | None = None
    source_slug: str | None = None
    item_type: str | None = None
    cve_id: str | None = None
    limit: int = 25
    offset: int = 0

    @property
    def normalized_item_type(self) -> str:
        value = self.item_type.strip().lower() if self.item_type else DEFAULT_ITEM_TYPE
        return value or DEFAULT_ITEM_TYPE

    @property
    def normalized_severity(self) -> str | None:
        if self.severity is None:
            return None
        value = self.severity.strip().lower()
        return value or None

    @property
    def normalized_source_slug(self) -> str | None:
        if self.source_slug is None:
            return None
        value = self.source_slug.strip().lower()
        return value or None

    @property
    def normalized_cve_id(self) -> str | None:
        if self.cve_id is None:
            return None
        value = self.cve_id.strip().upper()
        return value or None

    @property
    def normalized_query(self) -> str | None:
        if self.q is None:
            return None
        value = self.q.strip().lower()
        return value or None


class IntelligenceQueryService:
    """Load stored intelligence items and serialize safe public fields."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_items(
        self,
        filters: IntelligenceQueryFilters,
    ) -> IntelligenceItemListResponse:
        items = self._load_items()
        filtered = [item for item in items if self._matches_filters(item, filters)]
        filtered.sort(key=self._sort_key, reverse=True)
        page = filtered[filters.offset : filters.offset + filters.limit]
        return IntelligenceItemListResponse(
            items=[self._serialize_item(item) for item in page],
            total=len(filtered),
            limit=filters.limit,
            offset=filters.offset,
        )

    def get_item(self, item_public_id: UUID) -> IntelligenceItemSummary:
        for item in self._load_items():
            if item.public_id == item_public_id:
                return self._serialize_item(item)
        raise IntelligenceNotFoundError("Intelligence item not found.")

    def _load_items(self) -> list[IntelligenceItem]:
        statement = (
            select(IntelligenceItem)
            .options(selectinload(IntelligenceItem.vulnerability))
            .options(selectinload(IntelligenceItem.identifiers))
            .options(
                selectinload(IntelligenceItem.source_records).selectinload(
                    SourceRecord.source
                )
            )
        )
        try:
            return list(self._session.execute(statement).scalars().all())
        except SQLAlchemyError as exc:
            raise IntelligenceQueryError(
                "Database error while loading stored intelligence items."
            ) from exc

    def _matches_filters(
        self,
        item: IntelligenceItem,
        filters: IntelligenceQueryFilters,
    ) -> bool:
        if item.item_type != filters.normalized_item_type:
            return False

        vulnerability = item.vulnerability
        if filters.normalized_severity is not None:
            if vulnerability is None or vulnerability.severity != filters.normalized_severity:
                return False

        primary_source = self._primary_source_record(item)
        if filters.normalized_source_slug is not None:
            if (
                primary_source is None
                or primary_source.source is None
                or primary_source.source.slug.lower() != filters.normalized_source_slug
            ):
                return False

        primary_identifier = self._primary_identifier(item)
        if filters.normalized_cve_id is not None:
            if (
                primary_identifier is None
                or primary_identifier.normalized_value != filters.normalized_cve_id
            ):
                return False

        normalized_query = filters.normalized_query
        if normalized_query is not None and not self._matches_query(
            item,
            primary_identifier,
            normalized_query,
        ):
            return False

        return True

    @staticmethod
    def _matches_query(
        item: IntelligenceItem,
        primary_identifier: IntelligenceItemIdentifier | None,
        normalized_query: str,
    ) -> bool:
        candidates = [
            item.canonical_title,
            item.summary,
            primary_identifier.normalized_value if primary_identifier else None,
        ]
        for candidate in candidates:
            if candidate is not None and normalized_query in candidate.lower():
                return True
        return False

    @staticmethod
    def _sort_key(item: IntelligenceItem) -> tuple:
        return (
            item.source_modified_at or item.last_seen_at or item.created_at,
            item.last_seen_at,
            item.created_at,
            str(item.public_id),
        )

    @staticmethod
    def _primary_identifier(
        item: IntelligenceItem,
    ) -> IntelligenceItemIdentifier | None:
        primary = next((identifier for identifier in item.identifiers if identifier.is_primary), None)
        if primary is not None:
            return primary
        return next(
            (identifier for identifier in item.identifiers if identifier.namespace == "cve"),
            None,
        )

    @staticmethod
    def _primary_source_record(item: IntelligenceItem) -> SourceRecord | None:
        primary = next(
            (source_record for source_record in item.source_records if source_record.is_primary_reference),
            None,
        )
        if primary is not None:
            return primary
        return item.source_records[0] if item.source_records else None

    @staticmethod
    def _epss_source_record(item: IntelligenceItem) -> SourceRecord | None:
        return next(
            (
                source_record
                for source_record in item.source_records
                if source_record.source is not None
                and source_record.source.slug == EPSS_SOURCE_SLUG
            ),
            None,
        )

    def _serialize_item(self, item: IntelligenceItem) -> IntelligenceItemSummary:
        identifier = self._primary_identifier(item)
        source_record = self._primary_source_record(item)
        epss_source_record = self._epss_source_record(item)
        vulnerability = item.vulnerability

        return IntelligenceItemSummary(
            public_id=item.public_id,
            title=item.canonical_title,
            summary=item.summary,
            item_type=item.item_type,
            status=item.status,
            source_slug=source_record.source.slug if source_record and source_record.source else None,
            source_name=source_record.source.name if source_record and source_record.source else None,
            cve_id=identifier.normalized_value if identifier else None,
            severity=vulnerability.severity if vulnerability else None,
            cvss_score=self._decimal_to_float(vulnerability.cvss_score if vulnerability else None),
            cvss_version=vulnerability.cvss_version if vulnerability else None,
            cvss_vector=vulnerability.cvss_vector if vulnerability else None,
            epss_score=self._decimal_to_float(vulnerability.epss_score if vulnerability else None),
            epss_percentile=self._decimal_to_float(
                vulnerability.epss_percentile if vulnerability else None
            ),
            epss_score_date=(
                epss_source_record.source_modified_at.date()
                if epss_source_record is not None
                and epss_source_record.source_modified_at is not None
                else None
            ),
            affected_summary=vulnerability.affected_summary if vulnerability else None,
            source_url=source_record.source_url if source_record else item.canonical_url,
            source_published_at=(
                source_record.source_published_at if source_record else item.source_published_at
            ),
            source_modified_at=(
                source_record.source_modified_at if source_record else item.source_modified_at
            ),
            first_seen_at=source_record.first_seen_at if source_record else None,
            last_seen_at=item.last_seen_at,
            analyst_review_status=item.analyst_review_status,
            uae_relevance_status=item.uae_relevance_status,
            uae_relevance_confidence=self._decimal_to_float(item.uae_relevance_confidence),
            uae_relevance_reason=item.uae_relevance_reason,
            uae_relevance_method=item.uae_relevance_method,
            created_at=item.created_at,
            updated_at=item.updated_at,
        )

    @staticmethod
    def _decimal_to_float(value: Decimal | None) -> float | None:
        if value is None:
            return None
        return float(value)
