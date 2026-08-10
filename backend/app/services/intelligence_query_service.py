"""Read-only query service for safe intelligence item API responses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, load_only, raiseload, selectinload

from app.api.v1.schemas.intelligence import (
    IntelligenceItemListResponse,
    IntelligenceItemSummary,
)
from app.api.v1.query_validation import DEFAULT_LIST_SORT, LIST_SORT_VALUES
from app.ingestion.services.epss_enrichment_service import EPSS_SOURCE_SLUG
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
    Vulnerability,
)


DEFAULT_ITEM_TYPE = "vulnerability"
ACTIVE_STATUS = "active"
SEARCH_ESCAPE = "\\"


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
    published_year: int | None = None
    cve_id: str | None = None
    geographic_scope: str | None = None
    uae_relevance_status: str | None = None
    sort: str = DEFAULT_LIST_SORT
    limit: int = 25
    offset: int = 0

    def __post_init__(self) -> None:
        if self.sort not in LIST_SORT_VALUES:
            raise ValueError("Invalid intelligence list sort.")

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
    def normalized_geographic_scope(self) -> str | None:
        if self.geographic_scope is None:
            return None
        value = self.geographic_scope.strip().lower()
        return value or None

    @property
    def normalized_uae_relevance_status(self) -> str | None:
        if self.uae_relevance_status is None:
            return None
        value = self.uae_relevance_status.strip().lower()
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
        statement = self._filtered_statement(filters)
        try:
            total = int(
                self._session.execute(
                    select(func.count()).select_from(
                        statement.order_by(None).subquery()
                    )
                ).scalar_one()
                or 0
            )
            page = list(
                self._session.execute(
                    statement
                    .options(*self._public_load_options())
                    .order_by(*self._sort_expressions(filters.sort))
                    .limit(filters.limit)
                    .offset(filters.offset)
                )
                .scalars()
                .all()
            )
        except SQLAlchemyError as exc:
            raise IntelligenceQueryError(
                "Database error while loading stored intelligence items."
            ) from exc
        return IntelligenceItemListResponse(
            items=[self._serialize_item(item) for item in page],
            total=total,
            limit=filters.limit,
            offset=filters.offset,
        )

    @staticmethod
    def _sort_expressions(sort: str) -> tuple:
        if sort == "recently_ingested":
            return IntelligenceItem.created_at.desc(), IntelligenceItem.id.desc()
        if sort == "newest_published":
            return (
                IntelligenceItem.source_published_at.desc().nulls_last(),
                IntelligenceItem.id.desc(),
            )
        if sort == "oldest_published":
            return (
                IntelligenceItem.source_published_at.asc().nulls_last(),
                IntelligenceItem.id.asc(),
            )
        raise ValueError("Invalid intelligence list sort.")

    def get_item(self, item_public_id: UUID) -> IntelligenceItemSummary:
        statement = (
            select(IntelligenceItem)
            .where(
                IntelligenceItem.public_id == item_public_id,
                IntelligenceItem.status == ACTIVE_STATUS,
            )
            .options(*self._public_load_options())
        )
        try:
            items = self._session.execute(statement).scalars().all()
        except SQLAlchemyError as exc:
            raise IntelligenceQueryError(
                "Database error while loading stored intelligence item."
            ) from exc
        item = next(
            (
                candidate
                for candidate in items
                if candidate.public_id == item_public_id
                and candidate.status == ACTIVE_STATUS
            ),
            None,
        )
        if item is not None:
            return self._serialize_item(item)
        raise IntelligenceNotFoundError("Intelligence item not found.")

    @classmethod
    def _filtered_statement(
        cls,
        filters: IntelligenceQueryFilters,
    ):
        statement = select(IntelligenceItem).where(
            IntelligenceItem.status == ACTIVE_STATUS,
            IntelligenceItem.item_type == filters.normalized_item_type,
        )
        if filters.published_year is not None:
            start, end = cls._published_year_boundaries(filters.published_year)
            statement = statement.where(
                IntelligenceItem.source_published_at >= start,
                IntelligenceItem.source_published_at < end,
            )
        if filters.normalized_severity is not None:
            statement = statement.where(
                select(Vulnerability.intelligence_item_id)
                .where(
                    Vulnerability.intelligence_item_id == IntelligenceItem.id,
                    Vulnerability.severity == filters.normalized_severity,
                )
                .exists()
            )
        if filters.normalized_source_slug is not None:
            statement = statement.where(
                select(SourceRecord.id)
                .join(
                    IntelligenceSource,
                    IntelligenceSource.id == SourceRecord.source_id,
                )
                .where(
                    SourceRecord.intelligence_item_id == IntelligenceItem.id,
                    IntelligenceSource.slug == filters.normalized_source_slug,
                )
                .exists()
            )
        if filters.normalized_cve_id is not None:
            statement = statement.where(
                select(IntelligenceItemIdentifier.id)
                .where(
                    IntelligenceItemIdentifier.intelligence_item_id
                    == IntelligenceItem.id,
                    IntelligenceItemIdentifier.namespace == "cve",
                    IntelligenceItemIdentifier.normalized_value
                    == filters.normalized_cve_id,
                )
                .exists()
            )
        if filters.normalized_geographic_scope is not None:
            statement = statement.where(
                IntelligenceItem.geographic_scope
                == filters.normalized_geographic_scope
            )
        if filters.normalized_uae_relevance_status is not None:
            statement = statement.where(
                IntelligenceItem.uae_relevance_status
                == filters.normalized_uae_relevance_status
            )
        if filters.normalized_query is not None:
            pattern = f"%{cls._escape_like(filters.normalized_query)}%"
            statement = statement.where(
                or_(
                    IntelligenceItem.canonical_title.ilike(
                        pattern,
                        escape=SEARCH_ESCAPE,
                    ),
                    IntelligenceItem.summary.ilike(
                        pattern,
                        escape=SEARCH_ESCAPE,
                    ),
                    select(IntelligenceItemIdentifier.id)
                    .where(
                        IntelligenceItemIdentifier.intelligence_item_id
                        == IntelligenceItem.id,
                        IntelligenceItemIdentifier.normalized_value.ilike(
                            pattern,
                            escape=SEARCH_ESCAPE,
                        ),
                    )
                    .exists(),
                )
            )
        return statement

    @staticmethod
    def _public_load_options() -> tuple:
        return (
            load_only(
                IntelligenceItem.public_id,
                IntelligenceItem.canonical_title,
                IntelligenceItem.summary,
                IntelligenceItem.item_type,
                IntelligenceItem.status,
                IntelligenceItem.canonical_url,
                IntelligenceItem.source_published_at,
                IntelligenceItem.source_modified_at,
                IntelligenceItem.last_seen_at,
                IntelligenceItem.created_at,
                IntelligenceItem.geographic_scope,
                IntelligenceItem.uae_relevance_status,
                IntelligenceItem.uae_relevance_confidence,
                raiseload=True,
            ),
            raiseload("*"),
            selectinload(IntelligenceItem.vulnerability).options(
                load_only(
                    Vulnerability.severity,
                    Vulnerability.cvss_score,
                    Vulnerability.cvss_version,
                    Vulnerability.cvss_vector,
                    Vulnerability.epss_score,
                    Vulnerability.epss_percentile,
                    Vulnerability.kev_status,
                    Vulnerability.kev_date_added,
                    Vulnerability.kev_due_date,
                    Vulnerability.known_ransomware_campaign_use,
                    Vulnerability.affected_summary,
                    raiseload=True,
                ),
                raiseload("*"),
            ),
            selectinload(IntelligenceItem.identifiers).options(
                load_only(
                    IntelligenceItemIdentifier.namespace,
                    IntelligenceItemIdentifier.normalized_value,
                    IntelligenceItemIdentifier.is_primary,
                    raiseload=True,
                ),
                raiseload("*"),
            ),
            selectinload(IntelligenceItem.source_records).options(
                load_only(
                    SourceRecord.source_external_id,
                    SourceRecord.source_url,
                    SourceRecord.source_published_at,
                    SourceRecord.source_modified_at,
                    SourceRecord.first_seen_at,
                    SourceRecord.is_primary_reference,
                    SourceRecord.created_at,
                    raiseload=True,
                ),
                raiseload("*"),
                selectinload(SourceRecord.source).options(
                    load_only(
                        IntelligenceSource.slug,
                        IntelligenceSource.name,
                        raiseload=True,
                    ),
                    raiseload("*"),
                ),
            ),
        )

    @staticmethod
    def _published_year_boundaries(year: int) -> tuple[datetime, datetime]:
        return (
            datetime(year, 1, 1, tzinfo=UTC),
            datetime(year + 1, 1, 1, tzinfo=UTC),
        )

    @staticmethod
    def _escape_like(value: str) -> str:
        return (
            value.replace(SEARCH_ESCAPE, SEARCH_ESCAPE * 2)
            .replace("%", SEARCH_ESCAPE + "%")
            .replace("_", SEARCH_ESCAPE + "_")
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
            kev_status=vulnerability.kev_status if vulnerability else None,
            kev_date_added=vulnerability.kev_date_added if vulnerability else None,
            kev_due_date=vulnerability.kev_due_date if vulnerability else None,
            known_ransomware_campaign_use=(
                vulnerability.known_ransomware_campaign_use if vulnerability else None
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
            geographic_scope=item.geographic_scope,
            uae_relevance_status=item.uae_relevance_status,
            uae_relevance_confidence=self._decimal_to_float(item.uae_relevance_confidence),
        )

    @staticmethod
    def _decimal_to_float(value: Decimal | None) -> float | None:
        if value is None:
            return None
        return float(value)
