from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.v1.query_validation import validate_query_parameters
from app.core.config import get_settings

router = APIRouter(prefix="/version", tags=["version"])
validate_no_query_parameters = validate_query_parameters(set())


class VersionResponse(BaseModel):
    service: str
    version: str


@router.get(
    "",
    response_model=VersionResponse,
    dependencies=[Depends(validate_no_query_parameters)],
)
def get_version() -> VersionResponse:
    """Return safe public application version metadata."""

    settings = get_settings()

    return VersionResponse(
        service=settings.app_name,
        version=settings.app_version,
    )
