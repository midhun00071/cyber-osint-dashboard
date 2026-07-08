"""Read-only article list routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

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
    db_session: Session = Depends(get_db_session),
) -> ArticleListResponse:
    """Return stored article-like intelligence items safely."""

    service = ArticleQueryService(db_session)
    filters = ArticleQueryFilters(q=q, limit=limit, offset=offset)

    try:
        return service.list_articles(filters)
    except ArticleQueryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to load articles.",
        ) from exc
