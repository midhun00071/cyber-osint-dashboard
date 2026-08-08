"""Bounded per-session throttling for authenticated read APIs."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from threading import Lock
import re
import time
from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.security.contracts import AuthenticatedPrincipal
from app.security.dependencies import require_authenticated_principal


READ_RATE_LIMIT = 600
READ_RATE_WINDOW_SECONDS = 60
MAX_RATE_LIMIT_KEYS = 10_000
_SCOPE_PATTERN = re.compile(r"^[a-z0-9_.-]{1,80}$", flags=re.ASCII)


class ReadRateLimiter:
    """A process-local, bounded sliding-window limiter keyed by session."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = MAX_RATE_LIMIT_KEYS,
    ) -> None:
        if max_keys < 1:
            raise ValueError("max_keys must be positive.")
        self._clock = clock
        self._max_keys = max_keys
        self._requests: dict[tuple[str, str], deque[float]] = {}
        self._lock = Lock()

    def allow(
        self,
        *,
        session_key: str,
        scope: str,
        limit: int,
        window_seconds: int,
    ) -> bool:
        if (
            not session_key
            or _SCOPE_PATTERN.fullmatch(scope) is None
            or limit < 1
            or window_seconds < 1
        ):
            return False

        now = self._clock()
        threshold = now - window_seconds
        key = (session_key, scope)
        with self._lock:
            bucket = self._requests.get(key)
            if bucket is None:
                self._prune_empty(threshold)
                if len(self._requests) >= self._max_keys:
                    return False
                bucket = deque()
                self._requests[key] = bucket

            while bucket and bucket[0] <= threshold:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

    def _prune_empty(self, threshold: float) -> None:
        for key, bucket in tuple(self._requests.items()):
            while bucket and bucket[0] <= threshold:
                bucket.popleft()
            if not bucket:
                del self._requests[key]


_READ_RATE_LIMITER = ReadRateLimiter()


def require_read_rate_limit(
    scope: str,
    *,
    limit: int = READ_RATE_LIMIT,
    window_seconds: int = READ_RATE_WINDOW_SECONDS,
    limiter: ReadRateLimiter = _READ_RATE_LIMITER,
):
    """Return a dependency that fails closed when the session exceeds a bound."""

    if _SCOPE_PATTERN.fullmatch(scope) is None or limit < 1 or window_seconds < 1:
        raise ValueError("Read rate-limit configuration is invalid.")

    def dependency(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(require_authenticated_principal),
        ],
    ) -> None:
        allowed = limiter.allow(
            session_key=str(principal.session_public_id),
            scope=scope,
            limit=limit,
            window_seconds=window_seconds,
        )
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Request rate limit exceeded.",
                headers={"Retry-After": str(window_seconds)},
            )

    return dependency
