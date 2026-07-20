"""Request correlation, safe completion logging, and sanitized failures."""

from __future__ import annotations

import logging
from time import perf_counter
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette import status


REQUEST_ID_HEADER = "X-Request-ID"
UNEXPECTED_ERROR_DETAIL = "An unexpected server error occurred."
UNMATCHED_ROUTE = "unmatched"
_SAFE_METHODS = frozenset(
    {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
)

logger = logging.getLogger("app.request")


def _safe_method(request: Request) -> str:
    method = request.method.upper()
    return method if method in _SAFE_METHODS else "OTHER"


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if not isinstance(path, str) or not path:
        return UNMATCHED_ROUTE

    endpoint = request.scope.get("endpoint")
    for registered_route in request.app.routes:
        registered_path = getattr(registered_route, "path", None)
        if (
            isinstance(registered_path, str)
            and getattr(registered_route, "endpoint", None) is endpoint
        ):
            return registered_path

        included_router = getattr(registered_route, "original_router", None)
        include_context = getattr(registered_route, "include_context", None)
        include_prefix = getattr(include_context, "prefix", "")
        for included_route in getattr(included_router, "routes", ()):
            included_path = getattr(included_route, "path", None)
            if (
                isinstance(include_prefix, str)
                and isinstance(included_path, str)
                and getattr(included_route, "endpoint", None) is endpoint
            ):
                return f"{include_prefix}{included_path}"

    return path


def _duration_ms(started_at: float) -> str:
    elapsed = max(0.0, (perf_counter() - started_at) * 1000)
    return f"{elapsed:.3f}"


def _log_request(
    request: Request,
    *,
    request_id: str,
    status_code: int,
    started_at: float,
    failed_unexpectedly: bool,
) -> None:
    event = "request_failed" if failed_unexpectedly else "request_completed"
    fields = (
        f"event={event} "
        f"request_id={request_id} "
        f"method={_safe_method(request)} "
        f"route={_route_template(request)} "
        f"status_code={status_code} "
        f"duration_ms={_duration_ms(started_at)}"
    )
    if failed_unexpectedly:
        logger.error(f"{fields} error_category=unexpected_exception")
    elif status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        logger.error(f"{fields} error_category=handled_server_error")
    else:
        logger.info(fields)


class UnexpectedExceptionMiddleware(BaseHTTPMiddleware):
    """Convert unexpected request-time exceptions to a stable safe response."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        try:
            return await call_next(request)
        except Exception:
            request.state.failed_unexpectedly = True
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": UNEXPECTED_ERROR_DETAIL},
            )


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Generate a request ID, add it to responses, and emit one safe event."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        request_id = str(uuid4())
        request.state.request_id = request_id
        request.state.failed_unexpectedly = False
        started_at = perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            request.state.failed_unexpectedly = True
            response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": UNEXPECTED_ERROR_DETAIL},
            )

        response.headers[REQUEST_ID_HEADER] = request_id
        _log_request(
            request,
            request_id=request_id,
            status_code=response.status_code,
            started_at=started_at,
            failed_unexpectedly=request.state.failed_unexpectedly,
        )
        return response
