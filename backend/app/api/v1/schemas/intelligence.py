"""Safe response schemas for read-only intelligence item APIs."""

from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, Field


class IntelligenceItemSummary(BaseModel):
    """Safe dashboard-ready intelligence item fields."""

    public_id: UUID
    title: str
    summary: str | None
    item_type: str
    status: str
    source_slug: str | None
    source_name: str | None
    cve_id: str | None
    severity: str | None
    cvss_score: float | None
    cvss_version: str | None
    cvss_vector: str | None
    epss_score: float | None
    epss_percentile: float | None
    epss_score_date: date | None
    kev_status: str | None
    affected_summary: str | None
    source_url: str | None
    source_published_at: datetime | None
    source_modified_at: datetime | None
    first_seen_at: datetime | None
    last_seen_at: datetime
    analyst_review_status: str
    uae_relevance_status: str
    uae_relevance_confidence: float | None
    uae_relevance_reason: str | None
    uae_relevance_method: str
    created_at: datetime
    updated_at: datetime


class IntelligenceItemListResponse(BaseModel):
    """Offset-based paginated list response."""

    items: list[IntelligenceItemSummary]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)

