"""Read-only article list routes."""

from __future__ import annotations

from datetime import date as date_type
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.v1.query_validation import (
    ARTICLE_ITEM_TYPE_VALUES,
    DEFAULT_LIST_SORT,
    LIST_SORT_VALUES,
    MAX_PAGINATION_OFFSET,
    MAX_SEARCH_LENGTH,
    CanonicalPublicUUID,
    GEOGRAPHIC_SCOPE_VALUES,
    UAE_RELEVANCE_STATUS_VALUES,
    normalize_enum_filter,
    normalize_search_text,
    normalize_slug_filter,
    validate_query_parameters,
    validate_article_date_range,
)
from app.api.v1.schemas.articles import ArticleListResponse, ArticleSummary
from app.db.session import get_db_session
from app.security.dependencies import require_content_read
from app.services.article_query_service import (
    ArticleNotFoundError,
    ArticleQueryError,
    ArticleQueryFilters,
    ArticleQueryService,
)


router = APIRouter(
    prefix="/articles",
    tags=["articles"],
    dependencies=[Depends(require_content_read)],
)
validate_article_list_query = validate_query_parameters(
    {
        "limit",
        "offset",
        "q",
        "category",
        "source_slug",
        "tag_slug",
        "published_from",
        "published_to",
        "geographic_scope",
        "uae_relevance_status",
        "sort",
    }
)
validate_no_query_parameters = validate_query_parameters(set())


@router.get(
    "",
    response_model=ArticleListResponse,
    dependencies=[Depends(validate_article_list_query)],
)
def list_articles(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=MAX_PAGINATION_OFFSET),
    q: str | None = Query(
        default=None,
        min_length=1,
        max_length=MAX_SEARCH_LENGTH,
        pattern=r".*\S.*",
    ),
    category: str | None = Query(default=None, min_length=1, max_length=40),
    source_slug: str | None = Query(default=None, min_length=1, max_length=80),
    tag_slug: str | None = Query(default=None, min_length=1, max_length=100),
    published_from: date_type | None = Query(default=None),
    published_to: date_type | None = Query(default=None),
    geographic_scope: str | None = Query(default=None, min_length=1, max_length=40),
    uae_relevance_status: str | None = Query(default=None, min_length=1, max_length=40),
    sort: str = Query(default=DEFAULT_LIST_SORT, min_length=1, max_length=40),
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
        sort=normalize_enum_filter(
            sort,
            allowed_values=LIST_SORT_VALUES,
            field_name="sort",
        )
        or DEFAULT_LIST_SORT,
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


@router.get(
    "/{public_id}",
    response_model=ArticleSummary,
    dependencies=[Depends(validate_no_query_parameters)],
)
def get_article(
    public_id: CanonicalPublicUUID,
    db_session: Session = Depends(get_db_session),
) -> ArticleSummary:
    """Return one active stored article-like intelligence item safely."""

    service = ArticleQueryService(db_session)
    try:
        return service.get_article(public_id)
    except ArticleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The requested article was not found.",
        ) from exc
    except ArticleQueryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to load article.",
        ) from exc
