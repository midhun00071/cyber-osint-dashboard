import logging
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.v1.query_validation import (
    VALIDATION_ERROR_DETAIL,
    validate_query_parameters,
)
from app.api.v1.routes.articles import router as articles_router
from app.api.v1.routes.analyst import router as analyst_router
from app.api.v1.routes.admin_users import router as admin_users_router
from app.api.v1.routes.audit import router as audit_router
from app.api.v1.routes.auth import router as auth_router
from app.api.v1.routes.dashboard import router as dashboard_router
from app.api.v1.routes.health import router as health_router
from app.api.v1.routes.intelligence import router as intelligence_router
from app.api.v1.routes.operations import router as operations_router
from app.api.v1.routes.version import router as version_router
from app.core.config import MAX_HTTP_HOST_HEADER_BYTES, Settings, get_settings
from app.core.logging_config import configure_logging
from app.core.request_context import (
    RequestContextMiddleware,
    UnexpectedExceptionMiddleware,
)
from app.core.security_headers import SecurityHeadersMiddleware

settings = get_settings()
settings.validate_startup()
configure_logging(settings.log_level)

logger = logging.getLogger(__name__)
INVALID_HOST_RESPONSE = "Invalid host header"


class ExactHostMiddleware:
    """Enforce one exact normalized HTTP Host value without redirects."""

    def __init__(self, app: ASGIApp, allowed_hosts: Sequence[str]) -> None:
        if not allowed_hosts:
            raise ValueError("At least one trusted host is required.")
        self.app = app
        self.allowed_hosts = frozenset(allowed_hosts)

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_hosts = [
            value
            for name, value in scope.get("headers", [])
            if name.lower() == b"host"
        ]
        normalized_host: str | None = None
        if len(raw_hosts) == 1 and isinstance(raw_hosts[0], bytes):
            raw_host = raw_hosts[0]
            if len(raw_host) <= MAX_HTTP_HOST_HEADER_BYTES:
                try:
                    decoded_host = raw_host.decode("ascii")
                    normalized_host = Settings.normalize_http_host_header(
                        decoded_host
                    )
                except (UnicodeDecodeError, ValueError):
                    normalized_host = None

        if normalized_host not in self.allowed_hosts:
            response = PlainTextResponse(
                INVALID_HOST_RESPONSE,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Run application startup and shutdown tasks."""

    logger.info("event=application_starting")

    yield

    logger.info("event=application_stopped")


app = FastAPI(
    title=settings.app_name,
    description="Backend API for the Alpha Data Cyber OSINT Dashboard.",
    version=settings.app_version,
    debug=settings.debug,
    lifespan=lifespan,
)

# Added first so expected route exceptions are handled inside CORS, request-ID,
# and security-header boundaries. Starlette applies later additions outermost.
app.add_middleware(UnexpectedExceptionMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)
# Exact Host validation is independent of CORS and protects non-browser clients.
app.add_middleware(
    ExactHostMiddleware,
    allowed_hosts=settings.trusted_hosts_list,
)
# Request context wraps CORS so preflight responses also receive correlation IDs.
app.add_middleware(RequestContextMiddleware)
# Security headers remain outermost for successful and all sanitized responses.
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(health_router, prefix="/api")
app.include_router(version_router, prefix="/api")
app.include_router(articles_router, prefix="/api/v1")
app.include_router(analyst_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(intelligence_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(admin_users_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")
app.include_router(operations_router, prefix="/api/v1")
validate_no_query_parameters = validate_query_parameters(set())


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(
    _request: Request,
    _exc: RequestValidationError,
) -> JSONResponse:
    """Return a stable public error without echoing rejected request values."""

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": VALIDATION_ERROR_DETAIL},
    )


@app.get("/", dependencies=[Depends(validate_no_query_parameters)])
def root() -> dict[str, str]:
    """Return a safe root response without exposing sensitive configuration."""

    return {
        "service": settings.app_name,
        "status": "running",
        "health_url": "/api/health",
    }
