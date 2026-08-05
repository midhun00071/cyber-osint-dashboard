"""Opaque browser-session creation, hashing, rotation, and cookie helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import secrets

from fastapi import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import AuthSession


SESSION_COOKIE_NAME = "alpha_session"
CSRF_COOKIE_NAME = "alpha_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
SESSION_TOKEN_BYTES = 32
CSRF_TOKEN_BYTES = 32
REVOCATION_REASONS = frozenset({"logout", "refresh", "password_change", "account_disabled", "role_changed", "admin_revocation", "session_limit"})


@dataclass(frozen=True, slots=True)
class IssuedSession:
    row: AuthSession
    session_token: str
    csrf_token: str


def utc_now() -> datetime:
    return datetime.now(UTC)


def hash_opaque_token(value: str) -> str:
    return hashlib.sha256(value.encode("ascii", errors="strict")).hexdigest()


def generate_opaque_token() -> str:
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


class SessionSecurityService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    def create(self, *, user_id: int, user_session_version: int, now: datetime | None = None, absolute_expires_at: datetime | None = None) -> IssuedSession:
        issued_at = now or utc_now()
        natural_absolute = issued_at + timedelta(minutes=self._settings.auth_session_absolute_ttl_minutes)
        absolute = min(natural_absolute, absolute_expires_at) if absolute_expires_at is not None else natural_absolute
        expires_at = min(issued_at + timedelta(minutes=self._settings.auth_session_ttl_minutes), absolute)
        if expires_at <= issued_at:
            raise ValueError("The session can no longer be refreshed.")
        self._enforce_active_limit(user_id=user_id, now=issued_at)
        session_token = generate_opaque_token()
        csrf_token = generate_csrf_token()
        row = AuthSession(
            user_id=user_id,
            token_hash=hash_opaque_token(session_token),
            csrf_token_hash=hash_opaque_token(csrf_token),
            user_session_version=user_session_version,
            issued_at=issued_at,
            expires_at=expires_at,
            absolute_expires_at=absolute,
            created_at=issued_at,
            updated_at=issued_at,
        )
        self._session.add(row)
        self._session.flush()
        return IssuedSession(row=row, session_token=session_token, csrf_token=csrf_token)

    def revoke(self, row: AuthSession, reason: str, *, now: datetime | None = None) -> None:
        if reason not in REVOCATION_REASONS:
            raise ValueError("The session revocation reason is invalid.")
        if row.revoked_at is None:
            revoked_at = now or utc_now()
            row.revoked_at = revoked_at
            row.revocation_reason = reason
            row.updated_at = revoked_at
            if reason == "refresh":
                row.rotated_at = revoked_at

    def revoke_all(self, user_id: int, reason: str, *, now: datetime | None = None) -> list[AuthSession]:
        current = now or utc_now()
        rows = self._session.execute(
            select(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None)).with_for_update()
        ).scalars().all()
        for row in rows:
            self.revoke(row, reason, now=current)
        return rows

    def _enforce_active_limit(self, *, user_id: int, now: datetime) -> None:
        active = self._session.execute(
            select(AuthSession)
            .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None), AuthSession.expires_at > now, AuthSession.absolute_expires_at > now)
            .order_by(AuthSession.issued_at.asc(), AuthSession.id.asc())
            .with_for_update()
        ).scalars().all()
        excess = len(active) - self._settings.auth_max_active_sessions + 1
        for row in active[: max(0, excess)]:
            self.revoke(row, "session_limit", now=now)


def set_auth_cookies(response: Response, issued: IssuedSession, settings: Settings) -> None:
    max_age = max(0, int((issued.row.expires_at - utc_now()).total_seconds()))
    common = {"secure": settings.auth_cookie_secure, "samesite": "strict", "path": "/", "domain": None, "max_age": max_age}
    response.set_cookie(SESSION_COOKIE_NAME, issued.session_token, httponly=True, **common)
    response.set_cookie(CSRF_COOKIE_NAME, issued.csrf_token, httponly=False, **common)


def clear_auth_cookies(response: Response, settings: Settings) -> None:
    for name, httponly in ((SESSION_COOKIE_NAME, True), (CSRF_COOKIE_NAME, False)):
        response.delete_cookie(name, path="/", domain=None, secure=settings.auth_cookie_secure, httponly=httponly, samesite="strict")
