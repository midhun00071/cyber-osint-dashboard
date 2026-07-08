"""Read-only intelligence item routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.v1.query_validation import (
    ITEM_TYPE_VALUES,
    SEVERITY_VALUES,
    normalize_cve_id_filter,
    normalize_enum_filter,
    normalize_search_text,
    normalize_slug_filter,
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


@router.get("", response_model=IntelligenceItemListResponse)
def list_intelligence_items(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    q: str | None = Query(default=None, min_length=1, max_length=120, pattern=r".*\S.*"),
    severity: str | None = Query(default=None, min_length=1, max_length=20),
    source_slug: str | None = Query(default=None, min_length=1, max_length=80),
    item_type: str | None = Query(default=None, min_length=1, max_length=40),
    cve_id: str | None = Query(default=None, min_length=1, max_length=40),
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
    )
    filters = IntelligenceQueryFilters(
        q=normalize_search_text(q),
        severity=normalized_severity,
        source_slug=normalize_slug_filter(source_slug, field_name="source_slug"),
        item_type=normalized_item_type,
        cve_id=normalized_cve_id,
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


@router.get("/{item_public_id}", response_model=IntelligenceItemSummary)
def get_intelligence_item(
    item_public_id: UUID,
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

