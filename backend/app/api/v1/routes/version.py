from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import get_settings

router = APIRouter(prefix="/version", tags=["version"])


class VersionResponse(BaseModel):
    service: str
    version: str


@router.get("", response_model=VersionResponse)
def get_version() -> VersionResponse:
    """Return safe public application version metadata."""

    settings = get_settings()

    return VersionResponse(
        service=settings.app_name,
        version=settings.app_version,
    )
