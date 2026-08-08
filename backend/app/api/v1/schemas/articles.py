"""Safe response schemas for read-only article APIs."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ArticleSummary(BaseModel):
    """Safe article-like intelligence item fields."""

    model_config = ConfigDict(extra="forbid")

    public_id: UUID
    title: str
    summary: str | None
    category: str
    source_slug: str | None
    source_name: str | None
    source_url: str | None
    published_at: datetime | None
    modified_at: datetime | None
    geographic_scope: str
    uae_relevance_status: str
    uae_relevance_confidence: float | None
    last_seen_at: datetime


class ArticleListResponse(BaseModel):
    """Offset-based paginated article list response."""

    model_config = ConfigDict(extra="forbid")

    items: list[ArticleSummary]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
