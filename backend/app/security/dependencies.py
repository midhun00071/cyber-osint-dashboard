"""Central authentication, permission, Origin, and CSRF dependencies."""

from __future__ import annotations

from datetime import UTC, datetime
import re
import secrets
from typing import Annotated, Callable

from fastapi import Cookie, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.models import AuthSession, AuthUser, AuthUserRole
from app.security.authorization import InvalidRoleError, parse_role, permissions_for_role
from app.security.contracts import AuthenticatedPrincipal, Permission
from app.security.sessions import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME, hash_opaque_token
from app.services.security_audit_service import SecurityAuditAction, SecurityAuditError, SecurityAuditService


AUTHENTICATION_REQUIRED = "Authentication required."
PERMISSION_DENIED = "Permission denied."
REQUEST_SECURITY_DENIED = "Request security validation failed."
_OPAQUE_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{40,128}$", flags=re.ASCII)


def _unauthenticated() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTHENTICATION_REQUIRED)


def get_current_principal(
    request: Request,
    db_session: Annotated[Session, Depends(get_db_session)],
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> AuthenticatedPrincipal | None:
    if not isinstance(session_token, str) or _OPAQUE_TOKEN_PATTERN.fullmatch(session_token) is None:
        return None
    try:
        token_hash = hash_opaque_token(session_token)
        row = db_session.execute(
            select(AuthSession, AuthUser, AuthUserRole)
            .join(AuthUser, AuthUser.id == AuthSession.user_id)
            .join(AuthUserRole, AuthUserRole.user_id == AuthUser.id)
            .where(AuthSession.token_hash == token_hash)
        ).one_or_none()
    except (SQLAlchemyError, UnicodeEncodeError):
        return None
    if row is None:
        return None
    session_row, user, role_record = row
    now = datetime.now(UTC)
    if (
        session_row.revoked_at is not None
        or session_row.expires_at <= now
        or session_row.absolute_expires_at <= now
        or session_row.user_session_version != user.session_version
        or user.status != "active"
        or (user.account_expires_at is not None and user.account_expires_at <= now)
    ):
        return None
    try:
        role = parse_role(role_record.role_key)
        permissions = permissions_for_role(role)
    except InvalidRoleError:
        return None
    principal = AuthenticatedPrincipal(
        user_id=user.id,
        user_public_id=user.public_id,
        display_name=user.display_name,
        role=role,
        permissions=permissions,
        account_expires_at=user.account_expires_at,
        session_id=session_row.id,
        session_public_id=session_row.public_id,
        session_absolute_expires_at=session_row.absolute_expires_at,
        csrf_token_hash=session_row.csrf_token_hash,
    )
    request.state.principal = principal
    return principal


def require_authenticated_principal(
    principal: Annotated[AuthenticatedPrincipal | None, Depends(get_current_principal)],
) -> AuthenticatedPrincipal:
    if principal is None:
        raise _unauthenticated()
    return principal


def require_permission(permission: Permission) -> Callable[..., AuthenticatedPrincipal]:
    def dependency(
        request: Request,
        db_session: Annotated[Session, Depends(get_db_session)],
        principal: Annotated[AuthenticatedPrincipal, Depends(require_authenticated_principal)],
    ) -> AuthenticatedPrincipal:
        if principal.has_permission(permission):
            return principal
        request_id = getattr(request.state, "request_id", None)
        try:
            SecurityAuditService(db_session).append(
                action=SecurityAuditAction.AUTHORIZATION_DENIED,
                actor_type="user",
                actor_ref=str(principal.user_public_id),
                target_type="system",
                target_ref=str(request.scope.get("path", "protected_route"))[:240],
                outcome="denied",
                correlation_id=request_id,
                safe_detail={"reason": "permission_denied"},
            )
            db_session.commit()
        except (SecurityAuditError, SQLAlchemyError, ValueError):
            db_session.rollback()
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="The request could not be authorized safely.") from None
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=PERMISSION_DENIED)

    return dependency


require_content_read = require_permission(Permission.CONTENT_READ)
require_source_read = require_permission(Permission.SOURCE_READ)
require_ingestion_read = require_permission(Permission.INGESTION_READ)
require_ingestion_run = require_permission(Permission.INGESTION_RUN)
require_ingestion_retry = require_permission(Permission.INGESTION_RETRY)
require_ingestion_pause = require_permission(Permission.INGESTION_PAUSE)
require_source_manage = require_permission(Permission.SOURCE_MANAGE)
require_user_read = require_permission(Permission.USER_READ)
require_user_manage = require_permission(Permission.USER_MANAGE)
require_session_revoke = require_permission(Permission.SESSION_REVOKE)
require_audit_read = require_permission(Permission.AUDIT_READ)


def _validate_origin(request: Request, settings: Settings) -> None:
    origin = request.headers.get("origin")
    if origin is None or not any(secrets.compare_digest(origin, allowed) for allowed in settings.cors_origins_list):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=REQUEST_SECURITY_DENIED)


def _require_json(request: Request) -> None:
    content_type = request.headers.get("content-type", "")
    if content_type.split(";", maxsplit=1)[0].strip().lower() != "application/json":
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=REQUEST_SECURITY_DENIED)


def require_login_request_security(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    _validate_origin(request, settings)
    _require_json(request)


def _csrf_dependency(*, json_body: bool) -> Callable[..., AuthenticatedPrincipal]:
    def dependency(
        request: Request,
        settings: Annotated[Settings, Depends(get_settings)],
        principal: Annotated[AuthenticatedPrincipal, Depends(require_authenticated_principal)],
        csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE_NAME)] = None,
        csrf_header: Annotated[str | None, Header(alias=CSRF_HEADER_NAME)] = None,
    ) -> AuthenticatedPrincipal:
        _validate_origin(request, settings)
        if json_body:
            _require_json(request)
        if (
            not isinstance(csrf_cookie, str)
            or not isinstance(csrf_header, str)
            or _OPAQUE_TOKEN_PATTERN.fullmatch(csrf_cookie) is None
            or _OPAQUE_TOKEN_PATTERN.fullmatch(csrf_header) is None
            or not secrets.compare_digest(csrf_cookie, csrf_header)
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=REQUEST_SECURITY_DENIED)
        try:
            submitted_hash = hash_opaque_token(csrf_header)
        except UnicodeEncodeError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=REQUEST_SECURITY_DENIED) from None
        if not secrets.compare_digest(submitted_hash, principal.csrf_token_hash):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=REQUEST_SECURITY_DENIED)
        return principal

    return dependency


require_csrf = _csrf_dependency(json_body=False)
require_csrf_json = _csrf_dependency(json_body=True)


def prevent_auth_caching(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
