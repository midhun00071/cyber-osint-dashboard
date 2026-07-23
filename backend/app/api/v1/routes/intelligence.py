"""Read-only intelligence item routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.v1.query_validation import (
    GEOGRAPHIC_SCOPE_VALUES,
    ITEM_TYPE_VALUES,
    MAX_PAGINATION_OFFSET,
    MAX_SEARCH_LENGTH,
    PublishedYear,
    SEVERITY_VALUES,
    UAE_RELEVANCE_STATUS_VALUES,
    CanonicalPublicUUID,
    normalize_cve_id_filter,
    normalize_enum_filter,
    normalize_search_text,
    normalize_slug_filter,
    validate_query_parameters,
    validate_vulnerability_filter_combination,
)
from app.api.v1.schemas.intelligence import (
    IntelligenceItemListResponse,
    IntelligenceItemSummary,
)
from app.db.session import get_db_session
from app.services.intelligence_query_service import (
    IntelligenceNotFoundError,
    IntelligenceQueryError,
    IntelligenceQueryFilters,
    IntelligenceQueryService,
)


router = APIRouter(prefix="/intelligence/items", tags=["intelligence"])
validate_intelligence_list_query = validate_query_parameters(
    {
        "limit",
        "offset",
        "published_year",
        "q",
        "severity",
        "source_slug",
        "item_type",
        "cve_id",
        "geographic_scope",
        "uae_relevance_status",
    }
)
validate_no_query_parameters = validate_query_parameters(set())


@router.get(
    "",
    response_model=IntelligenceItemListResponse,
    dependencies=[Depends(validate_intelligence_list_query)],
)
def list_intelligence_items(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=MAX_PAGINATION_OFFSET),
    published_year: PublishedYear | None = Query(default=None),
    q: str | None = Query(
        default=None,
        min_length=1,
        max_length=MAX_SEARCH_LENGTH,
        pattern=r".*\S.*",
    ),
    severity: str | None = Query(default=None, min_length=1, max_length=20),
    source_slug: str | None = Query(default=None, min_length=1, max_length=80),
    item_type: str | None = Query(default=None, min_length=1, max_length=40),
    cve_id: str | None = Query(default=None, min_length=1, max_length=40),
    geographic_scope: str | None = Query(default=None, min_length=1, max_length=40),
    uae_relevance_status: str | None = Query(default=None, min_length=1, max_length=40),
    db_session: Session = Depends(get_db_session),
) -> IntelligenceItemListResponse:
    """Return stored intelligence items with safe filtering and pagination."""

    service = IntelligenceQueryService(db_session)
    normalized_item_type = normalize_enum_filter(
        item_type,
        allowed_values=ITEM_TYPE_VALUES,
        field_name="item_type",
    )
    normalized_severity = normalize_enum_filter(
        severity,
        allowed_values=SEVERITY_VALUES,
        field_name="severity",
    )
    normalized_cve_id = normalize_cve_id_filter(cve_id)
    validate_vulnerability_filter_combination(
        item_type=normalized_item_type,
        severity=normalized_severity,
        cve_id=normalized_cve_id,
        published_year=published_year,
    )
    filters = IntelligenceQueryFilters(
        q=normalize_search_text(q),
        severity=normalized_severity,
        source_slug=normalize_slug_filter(source_slug, field_name="source_slug"),
        item_type=normalized_item_type,
        published_year=published_year,
        cve_id=normalized_cve_id,
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
        return service.list_items(filters)
    except IntelligenceQueryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to load intelligence items.",
        ) from exc


@router.get(
    "/{item_public_id}",
    response_model=IntelligenceItemSummary,
    dependencies=[Depends(validate_no_query_parameters)],
)
def get_intelligence_item(
    item_public_id: CanonicalPublicUUID,
    db_session: Session = Depends(get_db_session),
) -> IntelligenceItemSummary:
    """Return one stored intelligence item without raw source payloads."""

    service = IntelligenceQueryService(db_session)

    try:
        return service.get_item(item_public_id)
    except IntelligenceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The requested intelligence item was not found.",
        ) from exc
    except IntelligenceQueryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to load the requested intelligence item.",
        ) from exc

