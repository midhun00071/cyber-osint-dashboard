"""Read-only database aggregation service for dashboard summary metrics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import Select, func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, load_only, raiseload, selectinload

from app.api.v1.query_validation import ARTICLE_ITEM_TYPE_VALUES
from app.api.v1.schemas.dashboard import (
    DashboardArticlePreview,
    DashboardCounts,
    DashboardIngestionFreshness,
    DashboardLatestFetch,
    DashboardMetrics,
    DashboardSummaryResponse,
    DashboardThresholds,
)
from app.models import (
    IngestionRun,
    IntelligenceItem,
    IntelligenceSource,
    SourceRecord,
    Vulnerability,
)
from app.models.common import utc_now


ACTIVE_STATUS = "active"
UAE_RELEVANT_STATUSES = ("confirmed", "probable")
HIGH_EPSS_THRESHOLD = Decimal("0.700000")
DEFAULT_LATEST_ARTICLE_LIMIT = 5
UNKNOWN_FETCH_STATUS = "unknown"


class DashboardSummaryQueryError(RuntimeError):
    """A dashboard summary query failed without exposing database internals."""


@dataclass(frozen=True)
class DashboardSummaryFilters:
    """Bounded dashboard summary query options."""

    window_days: int = 30
    latest_article_limit: int = DEFAULT_LATEST_ARTICLE_LIMIT


class DashboardSummaryService:
    """Load dashboard metrics through SQL aggregation and safe serialization."""

    def __init__(self, session: Session, *, clock=None) -> None:
        self._session = session
        self._clock = clock or utc_now

    def get_summary(
        self,
        filters: DashboardSummaryFilters | None = None,
    ) -> DashboardSummaryResponse:
        options = filters or DashboardSummaryFilters()
        generated_at = self._clock()
        if generated_at.tzinfo is None or generated_at.utcoffset() is None:
            generated_at = generated_at.replace(tzinfo=UTC)
        generated_at = generated_at.astimezone(UTC)
        window_start = generated_at - timedelta(days=options.window_days)

        try:
            active_items = self._scalar_count(
                self._active_items_statement(),
                metric="active_intelligence_items",
            )
            critical = self._scalar_count(
                self._critical_vulnerabilities_statement(),
                metric="critical_vulnerabilities",
            )
            high = self._scalar_count(
                self._high_vulnerabilities_statement(),
                metric="high_severity_vulnerabilities",
            )
            kev = self._scalar_count(
                self._kev_vulnerabilities_statement(),
                metric="cisa_kev_listed_vulnerabilities",
            )
            high_epss = self._scalar_count(
                self._high_epss_vulnerabilities_statement(),
                metric="high_epss_vulnerabilities",
            )
            uae = self._scalar_count(
                self._uae_relevant_items_statement(),
                metric="uae_relevant_intelligence",
            )
            collected = self._scalar_count(
                self._collected_in_window_statement(window_start, generated_at),
                metric="intelligence_items_collected_in_window",
            )
            active_articles = self._scalar_count(
                self._active_articles_statement(),
                metric="active_article_count",
            )
            latest_articles = self._latest_articles(options.latest_article_limit)
            last_successful = self._latest_successful_ingestion_at()
            latest_fetch = self._latest_fetch()
        except SQLAlchemyError as exc:
            raise DashboardSummaryQueryError(
                "Database error while loading dashboard summary."
            ) from exc

        counts = DashboardCounts(
            active_intelligence_items=active_items,
            critical_vulnerabilities=critical,
            high_severity_vulnerabilities=high,
            cisa_kev_listed_vulnerabilities=kev,
            high_epss_vulnerabilities=high_epss,
            uae_relevant_intelligence=uae,
            intelligence_items_collected_in_window=collected,
        )
        return DashboardSummaryResponse(
            window_days=options.window_days,
            window_start=window_start,
            window_end=generated_at,
            generated_at=generated_at,
            metrics=DashboardMetrics(
                critical_vulnerability_count=critical,
                kev_vulnerability_count=kev,
                active_article_count=active_articles,
                uae_related_item_count=uae,
            ),
            counts=counts,
            thresholds=DashboardThresholds(high_epss_minimum=float(HIGH_EPSS_THRESHOLD)),
            ingestion=DashboardIngestionFreshness(
                last_successful_ingestion_at=last_successful,
            ),
            latest_articles=latest_articles,
            latest_fetch=latest_fetch,
        )

    def _scalar_count(self, statement: Select, *, metric: str) -> int:
        return int(
            self._session.execute(
                statement.execution_options(dashboard_metric=metric)
            ).scalar_one()
            or 0
        )

    @staticmethod
    def _active_items_statement() -> Select:
        return select(func.count()).select_from(IntelligenceItem).where(
            IntelligenceItem.status == ACTIVE_STATUS
        )

    @staticmethod
    def _active_articles_statement() -> Select:
        return (
            select(func.count())
            .select_from(IntelligenceItem)
            .where(IntelligenceItem.status == ACTIVE_STATUS)
            .where(IntelligenceItem.item_type.in_(ARTICLE_ITEM_TYPE_VALUES))
        )

    @staticmethod
    def _critical_vulnerabilities_statement() -> Select:
        return DashboardSummaryService._vulnerability_count_statement().where(
            Vulnerability.severity == "critical"
        )

    @staticmethod
    def _high_vulnerabilities_statement() -> Select:
        return DashboardSummaryService._vulnerability_count_statement().where(
            Vulnerability.severity == "high"
        )

    @staticmethod
    def _kev_vulnerabilities_statement() -> Select:
        return DashboardSummaryService._vulnerability_count_statement().where(
            Vulnerability.kev_status == "listed"
        )

    @staticmethod
    def _high_epss_vulnerabilities_statement() -> Select:
        return DashboardSummaryService._vulnerability_count_statement().where(
            Vulnerability.epss_score >= HIGH_EPSS_THRESHOLD
        )

    @staticmethod
    def _vulnerability_count_statement() -> Select:
        return (
            select(func.count())
            .select_from(IntelligenceItem)
            .join(Vulnerability, Vulnerability.intelligence_item_id == IntelligenceItem.id)
            .where(IntelligenceItem.status == ACTIVE_STATUS)
            .where(IntelligenceItem.item_type == "vulnerability")
        )

    @staticmethod
    def _uae_relevant_items_statement() -> Select:
        return (
            select(func.count())
            .select_from(IntelligenceItem)
            .where(IntelligenceItem.status == ACTIVE_STATUS)
            .where(IntelligenceItem.uae_relevance_status.in_(UAE_RELEVANT_STATUSES))
        )

    @staticmethod
    def _collected_in_window_statement(
        window_start: datetime,
        window_end: datetime,
    ) -> Select:
        return (
            select(func.count())
            .select_from(IntelligenceItem)
            .where(IntelligenceItem.status == ACTIVE_STATUS)
            .where(IntelligenceItem.collected_at >= window_start)
            .where(IntelligenceItem.collected_at < window_end)
        )

    def _latest_articles(self, limit: int) -> list[DashboardArticlePreview]:
        statement = (
            select(IntelligenceItem)
            .where(IntelligenceItem.status == ACTIVE_STATUS)
            .where(IntelligenceItem.item_type.in_(ARTICLE_ITEM_TYPE_VALUES))
            .options(*self._article_load_options())
            .order_by(
                IntelligenceItem.source_published_at.desc().nulls_last(),
                IntelligenceItem.last_seen_at.desc(),
                IntelligenceItem.id.desc(),
            )
            .limit(limit)
            .execution_options(dashboard_query="latest_articles")
        )
        items = list(self._session.execute(statement).scalars().all())
        return [self._serialize_article(item) for item in items]

    def _latest_successful_ingestion_at(self) -> datetime | None:
        return self._session.execute(
            select(func.max(IntelligenceSource.last_successful_fetch_at))
            .where(IntelligenceSource.is_enabled.is_(True))
            .execution_options(dashboard_query="last_successful_ingestion")
        ).scalar_one_or_none()

    def _latest_fetch(self) -> DashboardLatestFetch | None:
        statement = (
            select(IngestionRun)
            .join(IntelligenceSource, IngestionRun.source_id == IntelligenceSource.id)
            .options(
                load_only(
                    IngestionRun.status,
                    IngestionRun.started_at,
                    IngestionRun.completed_at,
                    IngestionRun.records_fetched,
                    IngestionRun.records_created,
                    IngestionRun.records_updated,
                    IngestionRun.records_unchanged,
                    IngestionRun.records_skipped,
                    IngestionRun.records_failed,
                    raiseload=True,
                ),
                raiseload("*"),
                selectinload(IngestionRun.source).options(
                    load_only(
                        IntelligenceSource.slug,
                        IntelligenceSource.name,
                        raiseload=True,
                    ),
                    raiseload("*"),
                ),
            )
            .order_by(IngestionRun.started_at.desc(), IngestionRun.id.desc())
            .limit(1)
            .execution_options(dashboard_query="latest_fetch")
        )
        run = self._session.execute(statement).scalars().first()
        if run is None:
            return None
        processed = (
            run.records_created
            + run.records_updated
            + run.records_unchanged
            + run.records_skipped
        )
        return DashboardLatestFetch(
            source_slug=run.source.slug if run.source is not None else None,
            source_name=run.source.name if run.source is not None else None,
            status=run.status or UNKNOWN_FETCH_STATUS,
            started_at=run.started_at,
            completed_at=run.completed_at,
            fetched_count=run.records_fetched,
            processed_count=processed,
            failed_count=run.records_failed,
        )

    @staticmethod
    def _article_load_options() -> tuple:
        return (
            load_only(
                IntelligenceItem.public_id,
                IntelligenceItem.canonical_title,
                IntelligenceItem.summary,
                IntelligenceItem.item_type,
                IntelligenceItem.source_published_at,
                IntelligenceItem.last_seen_at,
                raiseload=True,
            ),
            raiseload("*"),
            selectinload(IntelligenceItem.source_records).options(
                load_only(
                    SourceRecord.source_external_id,
                    SourceRecord.source_url,
                    SourceRecord.source_published_at,
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

    def _serialize_article(self, item: IntelligenceItem) -> DashboardArticlePreview:
        source_record = self._primary_source_record(item)
        return DashboardArticlePreview(
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
            published_at=(
                source_record.source_published_at
                if source_record is not None
                and source_record.source_published_at is not None
                else item.source_published_at
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
