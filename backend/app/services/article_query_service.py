"""Read-only query service for public article list responses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import Select, func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from app.api.v1.query_validation import ARTICLE_ITEM_TYPE_VALUES
from app.api.v1.schemas.articles import ArticleListResponse, ArticleSummary
from app.models import (
    IntelligenceItem,
    IntelligenceItemTag,
    IntelligenceSource,
    SourceRecord,
    Tag,
)


ARTICLE_ITEM_TYPES = ARTICLE_ITEM_TYPE_VALUES
ACTIVE_STATUS = "active"
SEARCH_ESCAPE = "\\"


class ArticleQueryError(RuntimeError):
    """A read query failed without exposing database internals."""


class ArticleNotFoundError(LookupError):
    """No active article-like item matched the requested public ID."""


@dataclass(frozen=True)
class ArticleQueryFilters:
    """Allow-listed article list query filters."""

    q: str | None = None
    category: str | None = None
    source_slug: str | None = None
    tag_slug: str | None = None
    published_from: datetime | None = None
    published_to_exclusive: datetime | None = None
    geographic_scope: str | None = None
    uae_relevance_status: str | None = None
    limit: int = 25
    offset: int = 0

    @property
    def normalized_query(self) -> str | None:
        if self.q is None:
            return None
        value = self.q.strip()
        return value or None


class ArticleQueryService:
    """Load stored article-like intelligence items with safe SQL filtering."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_articles(self, filters: ArticleQueryFilters) -> ArticleListResponse:
        base_statement = self._filtered_statement(filters)
        try:
            total = self._session.execute(
                select(func.count()).select_from(base_statement.subquery())
            ).scalar_one()
            page_items = list(
                self._session.execute(
                    base_statement.options(
                        selectinload(IntelligenceItem.source_records).selectinload(
                            SourceRecord.source
                        )
                    )
                    .order_by(
                        IntelligenceItem.source_published_at.desc().nulls_last(),
                        IntelligenceItem.last_seen_at.desc(),
                        IntelligenceItem.id.desc(),
                    )
                    .limit(filters.limit)
                    .offset(filters.offset)
                )
                .scalars()
                .all()
            )
        except SQLAlchemyError as exc:
            raise ArticleQueryError("Database error while loading articles.") from exc

        return ArticleListResponse(
            items=[self._serialize_item(item) for item in page_items],
            total=total,
            limit=filters.limit,
            offset=filters.offset,
        )

    def get_article(self, public_id: UUID) -> ArticleSummary:
        statement = (
            self._base_article_statement()
            .where(IntelligenceItem.public_id == public_id)
            .options(
                selectinload(IntelligenceItem.source_records).selectinload(
                    SourceRecord.source
                )
            )
        )
        try:
            item = self._session.execute(statement).scalars().one_or_none()
        except SQLAlchemyError as exc:
            raise ArticleQueryError("Database error while loading article.") from exc

        if item is None:
            raise ArticleNotFoundError("Article not found.")

        return self._serialize_item(item)

    def _filtered_statement(
        self,
        filters: ArticleQueryFilters,
    ) -> Select[tuple[IntelligenceItem]]:
        statement = self._base_article_statement()
        if filters.category is not None:
            statement = statement.where(IntelligenceItem.item_type == filters.category)
        if filters.source_slug is not None:
            statement = statement.where(
                select(SourceRecord.id)
                .join(IntelligenceSource, SourceRecord.source_id == IntelligenceSource.id)
                .where(SourceRecord.intelligence_item_id == IntelligenceItem.id)
                .where(IntelligenceSource.slug == filters.source_slug)
                .exists()
            )
        if filters.tag_slug is not None:
            statement = statement.where(
                select(IntelligenceItemTag.intelligence_item_id)
                .join(Tag, IntelligenceItemTag.tag_id == Tag.id)
                .where(IntelligenceItemTag.intelligence_item_id == IntelligenceItem.id)
                .where(Tag.slug == filters.tag_slug)
                .exists()
            )
        if filters.published_from is not None:
            statement = statement.where(
                IntelligenceItem.source_published_at >= filters.published_from
            )
        if filters.published_to_exclusive is not None:
            statement = statement.where(
                IntelligenceItem.source_published_at < filters.published_to_exclusive
            )
        if filters.geographic_scope is not None:
            statement = statement.where(
                IntelligenceItem.geographic_scope == filters.geographic_scope
            )
        if filters.uae_relevance_status is not None:
            statement = statement.where(
                IntelligenceItem.uae_relevance_status == filters.uae_relevance_status
            )
        query = filters.normalized_query
        if query is not None:
            pattern = f"%{self._escape_like(query)}%"
            statement = statement.where(
                or_(
                    IntelligenceItem.canonical_title.ilike(
                        pattern,
                        escape=SEARCH_ESCAPE,
                    ),
                    IntelligenceItem.summary.ilike(pattern, escape=SEARCH_ESCAPE),
                )
            )
        return statement

    @staticmethod
    def _base_article_statement() -> Select[tuple[IntelligenceItem]]:
        return (
            select(IntelligenceItem)
            .where(IntelligenceItem.status == ACTIVE_STATUS)
            .where(IntelligenceItem.item_type.in_(ARTICLE_ITEM_TYPES))
        )

    @staticmethod
    def _escape_like(value: str) -> str:
        return (
            value.replace(SEARCH_ESCAPE, SEARCH_ESCAPE * 2)
            .replace("%", SEARCH_ESCAPE + "%")
            .replace("_", SEARCH_ESCAPE + "_")
        )

    def _serialize_item(self, item: IntelligenceItem) -> ArticleSummary:
        source_record = self._primary_source_record(item)
        return ArticleSummary(
            public_id=item.public_id,
            title=item.canonical_title,
            summary=item.summary,
            category=item.item_type,
            source_slug=(
                source_record.source.slug
                if source_record is not None and source_record.source is not None
                else None
            ),
            source_name=(
                source_record.source.name
                if source_record is not None and source_record.source is not None
                else None
            ),
            source_url=source_record.source_url if source_record else item.canonical_url,
            published_at=(
                source_record.source_published_at
                if source_record is not None
                and source_record.source_published_at is not None
                else item.source_published_at
            ),
            modified_at=(
                source_record.source_modified_at
                if source_record is not None
                and source_record.source_modified_at is not None
                else item.source_modified_at
            ),
            geographic_scope=item.geographic_scope,
            uae_relevance_status=item.uae_relevance_status,
            uae_relevance_confidence=self._decimal_to_float(
                item.uae_relevance_confidence
            ),
            last_seen_at=item.last_seen_at,
        )

    @staticmethod
    def _primary_source_record(item: IntelligenceItem) -> SourceRecord | None:
        primary = next(
            (
                source_record
                for source_record in item.source_records
                if source_record.is_primary_reference
            ),
            None,
        )
        if primary is not None:
            return primary
        if not item.source_records:
            return None
        return sorted(
            item.source_records,
            key=lambda source_record: (
                source_record.source.slug if source_record.source else "",
                source_record.source_external_id or "",
                source_record.source_url,
                source_record.created_at,
            ),
        )[0]

    @staticmethod
    def _decimal_to_float(value: Decimal | None) -> float | None:
        if value is None:
            return None
        return float(value)
