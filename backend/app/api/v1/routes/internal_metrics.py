"""Private Prometheus endpoint; the edge explicitly rejects this path."""

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.api.v1.query_validation import validate_query_parameters
from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.services.metrics_service import MetricsService


router = APIRouter(tags=["internal"])
validate_no_query_parameters = validate_query_parameters(set())
PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


@router.get(
    "/internal/metrics",
    include_in_schema=False,
    dependencies=[Depends(validate_no_query_parameters)],
)
def internal_metrics(
    db_session: Session = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> Response:
    return Response(
        content=MetricsService(db_session, settings).render(),
        media_type=PROMETHEUS_CONTENT_TYPE,
        headers={"Cache-Control": "no-store"},
    )
