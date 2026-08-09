"""Authenticated full-stack system health."""

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.api.v1.query_validation import validate_query_parameters
from app.api.v1.schemas.system import SystemHealthResponse
from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.security.contracts import AuthenticatedPrincipal
from app.security.dependencies import prevent_auth_caching, require_source_read
from app.services.system_health_service import SystemHealthService


router = APIRouter(prefix="/system", tags=["system"])
validate_no_query_parameters = validate_query_parameters(set())


@router.get(
    "/health",
    response_model=SystemHealthResponse,
    dependencies=[Depends(validate_no_query_parameters)],
)
def system_health(
    response: Response,
    principal: AuthenticatedPrincipal = Depends(require_source_read),
    db_session: Session = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> SystemHealthResponse:
    prevent_auth_caching(response)
    return SystemHealthService(db_session, settings).snapshot(
        permissions=principal.permissions
    )
