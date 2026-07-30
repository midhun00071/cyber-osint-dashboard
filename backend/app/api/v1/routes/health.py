from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from app.api.v1.query_validation import validate_query_parameters
from app.core.config import get_settings

router = APIRouter(prefix="/health", tags=["health"])
validate_no_query_parameters = validate_query_parameters(set())


@router.get("", dependencies=[Depends(validate_no_query_parameters)])
def health_check() -> dict[str, str]:
    """Return a safe health-check response for deployment and monitoring."""

    settings = get_settings()

    return {
        "status": "ok",
        "service": settings.app_name,
        # Kept as a fixed compatibility label for the existing frontend. Never
        # expose the configured environment identity through this public route.
        "environment": "not-disclosed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
