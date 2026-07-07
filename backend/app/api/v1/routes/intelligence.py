"""Read-only intelligence item routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

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
    q: str | None = Query(default=None, min_length=1, max_length=120),
    severity: str | None = Query(default=None, min_length=1, max_length=20),
    source_slug: str | None = Query(default=None, min_length=1, max_length=80),
    item_type: str | None = Query(default=None, min_length=1, max_length=40),
    cve_id: str | None = Query(default=None, min_length=1, max_length=40),
    db_session: Session = Depends(get_db_session),
) -> IntelligenceItemListResponse:
    """Return stored intelligence items with safe filtering and pagination."""

    service = IntelligenceQueryService(db_session)
    filters = IntelligenceQueryFilters(
        q=q,
        severity=severity,
        source_slug=source_slug,
        item_type=item_type,
        cve_id=cve_id,
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

