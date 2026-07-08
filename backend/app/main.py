import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.routes.articles import router as articles_router
from app.api.v1.routes.health import router as health_router
from app.api.v1.routes.intelligence import router as intelligence_router
from app.api.v1.routes.version import router as version_router
from app.core.config import get_settings
from app.core.logging_config import configure_logging

settings = get_settings()
configure_logging(settings.log_level)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Run application startup and shutdown tasks."""

    logger.info(
        "Starting %s backend in %s mode.",
        settings.app_name,
        settings.app_env,
    )

    yield

    logger.info("Shutting down %s backend.", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    description="Backend API for the Alpha Data Cyber OSINT Dashboard.",
    version=settings.app_version,
    debug=settings.debug,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(health_router, prefix="/api")
app.include_router(version_router, prefix="/api")
app.include_router(articles_router, prefix="/api/v1")
app.include_router(intelligence_router, prefix="/api/v1")


@app.get("/")
def root() -> dict[str, str]:
    """Return a safe root response without exposing sensitive configuration."""

    return {
        "service": settings.app_name,
        "status": "running",
        "health_url": "/api/health",
    }
