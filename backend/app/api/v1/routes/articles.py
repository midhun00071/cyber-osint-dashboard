"""Read-only article list routes."""

from __future__ import annotations

from datetime import date as date_type

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.v1.query_validation import (
    ARTICLE_ITEM_TYPE_VALUES,
    GEOGRAPHIC_SCOPE_VALUES,
    UAE_RELEVANCE_STATUS_VALUES,
    normalize_enum_filter,
    normalize_search_text,
    normalize_slug_filter,
    validate_article_date_range,
)
from app.api.v1.schemas.articles import ArticleListResponse
from app.db.session import get_db_session
from app.services.article_query_service import (
    ArticleQueryError,
    ArticleQueryFilters,
    ArticleQueryService,
)


router = APIRouter(prefix="/articles", tags=["articles"])


@router.get("", response_model=ArticleListResponse)
def list_articles(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    q: str | None = Query(default=None, min_length=1, max_length=120, pattern=r".*\S.*"),
    category: str | None = Query(default=None, min_length=1, max_length=40),
    source_slug: str | None = Query(default=None, min_length=1, max_length=80),
    tag_slug: str | None = Query(default=None, min_length=1, max_length=100),
    published_from: date_type | None = Query(default=None),
    published_to: date_type | None = Query(default=None),
    geographic_scope: str | None = Query(default=None, min_length=1, max_length=40),
    uae_relevance_status: str | None = Query(default=None, min_length=1, max_length=40),
    db_session: Session = Depends(get_db_session),
) -> ArticleListResponse:
    """Return stored article-like intelligence items safely."""

    service = ArticleQueryService(db_session)
    published_from_boundary, published_to_boundary = validate_article_date_range(
        published_from,
        published_to,
    )
    filters = ArticleQueryFilters(
        q=normalize_search_text(q),
        category=normalize_enum_filter(
            category,
            allowed_values=ARTICLE_ITEM_TYPE_VALUES,
            field_name="category",
        ),
        source_slug=normalize_slug_filter(source_slug, field_name="source_slug"),
        tag_slug=normalize_slug_filter(tag_slug, field_name="tag_slug"),
        published_from=published_from_boundary,
        published_to_exclusive=published_to_boundary,
        geographic_scope=normalize_enum_filter(
            geographic_scope,
            allowed_values=GEOGRAPHIC_SCOPE_VALUES,
            field_name="geographic_scope",
        ),
        uae_relevance_status=normalize_enum_filter(
            uae_relevance_status,
            allowed_values=UAE_RELEVANCE_STATUS_VALUES,
            field_name="uae_relevance_status",
        ),
        limit=limit,
        offset=offset,
    )

    try:
        return service.list_articles(filters)
    except ArticleQueryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to load articles.",
        ) from exc
