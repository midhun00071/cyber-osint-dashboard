"""Read-only dashboard summary routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.v1.query_validation import validate_query_parameters
from app.api.v1.schemas.dashboard import DashboardSummaryResponse
from app.db.session import get_db_session
from app.security.dependencies import require_content_read
from app.services.dashboard_summary_service import (
    DashboardSummaryFilters,
    DashboardSummaryQueryError,
    DashboardSummaryService,
)


router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_content_read)],
)
validate_dashboard_summary_query = validate_query_parameters({"window_days"})


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    dependencies=[Depends(validate_dashboard_summary_query)],
)
def get_dashboard_summary(
    window_days: int = Query(default=30, ge=1, le=365),
    db_session: Session = Depends(get_db_session),
) -> DashboardSummaryResponse:
    """Return safe database-backed dashboard KPIs and freshness status."""

    service = DashboardSummaryService(db_session)
    try:
        return service.get_summary(DashboardSummaryFilters(window_days=window_days))
    except DashboardSummaryQueryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to load dashboard summary.",
        ) from exc
