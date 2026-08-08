"""Safe response schemas for the read-only dashboard summary API."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictDashboardModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DashboardMetrics(StrictDashboardModel):
    """Compact KPI values used by the dashboard shell."""

    critical_vulnerability_count: int = Field(ge=0)
    kev_vulnerability_count: int = Field(ge=0)
    active_article_count: int = Field(ge=0)
    uae_related_item_count: int = Field(ge=0)


class DashboardCounts(StrictDashboardModel):
    """Expanded dashboard counts from the approved API contract."""

    active_intelligence_items: int = Field(ge=0)
    critical_vulnerabilities: int = Field(ge=0)
    high_severity_vulnerabilities: int = Field(ge=0)
    cisa_kev_listed_vulnerabilities: int = Field(ge=0)
    high_epss_vulnerabilities: int = Field(ge=0)
    uae_relevant_intelligence: int = Field(ge=0)
    intelligence_items_collected_in_window: int = Field(ge=0)


class DashboardThresholds(StrictDashboardModel):
    """Applied threshold values for dashboard classification counts."""

    high_epss_minimum: float


class DashboardIngestionFreshness(StrictDashboardModel):
    """Safe source freshness metadata without checkpoint or operator details."""

    last_successful_ingestion_at: datetime | None


class DashboardArticlePreview(StrictDashboardModel):
    """Safe latest article preview row."""

    public_id: UUID
    title: str
    summary: str | None
    category: str
    source_slug: str | None
    source_name: str | None
    published_at: datetime | None
    last_seen_at: datetime


class DashboardLatestFetch(StrictDashboardModel):
    """Safe latest ingestion-run status summary."""

    source_slug: str | None
    source_name: str | None
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    fetched_count: int = Field(ge=0)
    processed_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)


class DashboardSummaryResponse(StrictDashboardModel):
    """Read-only database-backed dashboard summary."""

    window_days: int = Field(ge=1, le=365)
    window_start: datetime
    window_end: datetime
    generated_at: datetime
    metrics: DashboardMetrics
    counts: DashboardCounts
    thresholds: DashboardThresholds
    ingestion: DashboardIngestionFreshness
    latest_articles: list[DashboardArticlePreview]
    latest_fetch: DashboardLatestFetch | None
