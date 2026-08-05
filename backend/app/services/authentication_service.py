"""Transactional local authentication, throttle, and session lifecycle service."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import AuthIdentity, AuthLocalCredential, AuthLoginThrottle, AuthSession, AuthUser, AuthUserRole
from app.security.authorization import parse_role, permissions_for_role
from app.security.contracts import AuthenticatedPrincipal
from app.security.identity import LocalIdentityProvider, canonicalize_local_username
from app.security.passwords import PasswordPolicyError, dummy_password_hash, hash_password, password_hash_needs_rehash, validate_password, verify_password
from app.security.sessions import IssuedSession, SessionSecurityService, utc_now
from app.services.security_audit_service import ANONYMOUS_AUTH_ACTOR_REF, SecurityAuditAction, SecurityAuditService


INVALID_CREDENTIALS_DETAIL = "Invalid credentials."
SAFE_AUTHENTICATION_ERROR = "Authentication could not be completed."
SAFE_PASSWORD_CHANGE_ERROR = "The password could not be changed."


class InvalidCredentialsError(ValueError):
    pass


class AuthenticationServiceError(RuntimeError):
    pass


class PasswordChangeError(ValueError):
    pass


class AuthenticationService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._sessions = SessionSecurityService(session, settings)
        self._audit = SecurityAuditService(session)

    def login(self, *, username: str, password: str, correlation_id: str, now: datetime | None = None) -> tuple[AuthenticatedPrincipal, IssuedSession]:
        current = now or datetime.now(UTC)
        canonical = canonicalize_local_username(username)
        throttle_hash = self._login_key_hash(canonical if canonical is not None else username)
        try:
            throttle = self._locked_throttle(throttle_hash, current)
            identity = (
                LocalIdentityProvider(self._session).lookup(canonical, for_update=True)
                if canonical is not None
                else None
            )
            encoded_hash = identity.password_hash if identity is not None else dummy_password_hash()
            blocked = throttle.blocked_until is not None and throttle.blocked_until > current
            password_valid = verify_password(password, encoded_hash)
            if blocked:
                self._audit.append(
                    action=SecurityAuditAction.AUTH_LOGIN_FAILED,
                    actor_type="service",
                    actor_ref=ANONYMOUS_AUTH_ACTOR_REF,
                    target_type="authentication",
                    target_ref="login_attempt",
                    outcome="failed",
                    correlation_id=correlation_id,
                    safe_detail={"reason": "invalid_credentials"},
                    occurred_at=current,
                )
                raise InvalidCredentialsError(INVALID_CREDENTIALS_DETAIL)
            account_valid = (
                identity is not None
                and identity.status == "active"
                and (identity.account_expires_at is None or identity.account_expires_at > current)
            )
            authoritative_row = None
            if password_valid and account_valid:
                assert identity is not None
                authoritative_row = self._session.execute(
                    select(AuthUser, AuthLocalCredential, AuthUserRole)
                    .join(AuthIdentity, AuthIdentity.user_id == AuthUser.id)
                    .join(AuthLocalCredential, AuthLocalCredential.identity_id == AuthIdentity.id)
                    .join(AuthUserRole, AuthUserRole.user_id == AuthUser.id)
                    .where(
                        AuthUser.id == identity.user_id,
                        AuthIdentity.id == identity.identity_id,
                        AuthIdentity.provider_key == "local",
                    )
                    .with_for_update()
                ).one_or_none()
            authoritative_state_valid = (
                authoritative_row is not None
                and identity is not None
                and authoritative_row[0].public_id == identity.user_public_id
                and authoritative_row[0].display_name == identity.display_name
                and authoritative_row[0].status == identity.status
                and authoritative_row[0].account_expires_at == identity.account_expires_at
                and authoritative_row[0].session_version == identity.session_version
                and authoritative_row[1].password_hash == identity.password_hash
                and authoritative_row[2].role_key == identity.role.value
            )
            if not password_valid or not account_valid or not authoritative_state_valid:
                self._record_login_failure(throttle, current)
                self._audit.append(
                    action=SecurityAuditAction.AUTH_LOGIN_FAILED,
                    actor_type="service",
                    actor_ref=ANONYMOUS_AUTH_ACTOR_REF,
                    target_type="authentication",
                    target_ref="login_attempt",
                    outcome="failed",
                    correlation_id=correlation_id,
                    safe_detail={"reason": "invalid_credentials"},
                    occurred_at=current,
                )
                raise InvalidCredentialsError(INVALID_CREDENTIALS_DETAIL)

            assert identity is not None
            user, credential, _role_record = authoritative_row
            if password_hash_needs_rehash(credential.password_hash):
                credential.password_hash = hash_password(password)
                credential.updated_at = current
            user.last_authenticated_at = current
            user.updated_at = current
            throttle.failure_count = 0
            throttle.window_started_at = current
            throttle.blocked_until = None
            throttle.updated_at = current
            issued = self._sessions.create(user_id=user.id, user_session_version=user.session_version, now=current)
            self._audit.append(
                action=SecurityAuditAction.AUTH_LOGIN,
                actor_type="user",
                actor_ref=str(user.public_id),
                target_type="auth_session",
                target_ref=str(issued.row.public_id),
                outcome="success",
                correlation_id=correlation_id,
                occurred_at=current,
            )
            role = identity.role
            principal = AuthenticatedPrincipal(
                user_id=user.id,
                user_public_id=user.public_id,
                display_name=user.display_name,
                role=role,
                permissions=permissions_for_role(role),
                account_expires_at=user.account_expires_at,
                session_id=issued.row.id,
                session_public_id=issued.row.public_id,
                session_absolute_expires_at=issued.row.absolute_expires_at,
                csrf_token_hash=issued.row.csrf_token_hash,
            )
            return principal, issued
        except InvalidCredentialsError:
            raise
        except (SQLAlchemyError, ValueError, RuntimeError):
            raise AuthenticationServiceError(SAFE_AUTHENTICATION_ERROR) from None

    def logout(self, principal: AuthenticatedPrincipal, *, correlation_id: str, now: datetime | None = None) -> None:
        current = now or utc_now()
        row = self._locked_current_session(principal.session_id)
        self._sessions.revoke(row, "logout", now=current)
        self._audit.append(action=SecurityAuditAction.AUTH_LOGOUT, actor_type="user", actor_ref=str(principal.user_public_id), target_type="auth_session", target_ref=str(principal.session_public_id), outcome="success", correlation_id=correlation_id, occurred_at=current)

    def refresh(self, principal: AuthenticatedPrincipal, *, correlation_id: str, now: datetime | None = None) -> IssuedSession:
        current = now or utc_now()
        old = self._locked_current_session(principal.session_id)
        self._sessions.revoke(old, "refresh", now=current)
        replacement = self._sessions.create(user_id=principal.user_id, user_session_version=old.user_session_version, now=current, absolute_expires_at=old.absolute_expires_at)
        self._audit.append(action=SecurityAuditAction.AUTH_SESSION_ROTATED, actor_type="user", actor_ref=str(principal.user_public_id), target_type="auth_session", target_ref=str(replacement.row.public_id), outcome="success", correlation_id=correlation_id, safe_detail={"reason": "refresh"}, occurred_at=current)
        return replacement

    def change_password(self, principal: AuthenticatedPrincipal, *, current_password: str, new_password: str, correlation_id: str, now: datetime | None = None) -> IssuedSession:
        current = now or utc_now()
        try:
            validate_password(new_password)
        except PasswordPolicyError:
            raise PasswordChangeError(SAFE_PASSWORD_CHANGE_ERROR) from None
        user = self._session.execute(
            select(AuthUser).where(AuthUser.id == principal.user_id).with_for_update()
        ).scalar_one_or_none()
        if user is None:
            raise PasswordChangeError(SAFE_PASSWORD_CHANGE_ERROR)
        current_session = self._session.execute(
            select(AuthSession).where(AuthSession.id == principal.session_id).with_for_update()
        ).scalar_one_or_none()
        credential = self._session.execute(
            select(AuthLocalCredential)
            .join(AuthIdentity, AuthIdentity.id == AuthLocalCredential.identity_id)
            .where(AuthIdentity.user_id == user.id, AuthIdentity.provider_key == "local")
            .with_for_update()
        ).scalar_one_or_none()
        authenticated_session_valid = (
            principal.user_id == user.id
            and user.status == "active"
            and (user.account_expires_at is None or user.account_expires_at > current)
            and current_session is not None
            and current_session.user_id == user.id
            and current_session.revoked_at is None
            and current_session.expires_at > current
            and current_session.absolute_expires_at > current
            and current_session.user_session_version == user.session_version
        )
        if (
            not authenticated_session_valid
            or credential is None
            or not verify_password(current_password, credential.password_hash)
        ):
            raise PasswordChangeError(SAFE_PASSWORD_CHANGE_ERROR)
        if verify_password(new_password, credential.password_hash):
            raise PasswordChangeError(SAFE_PASSWORD_CHANGE_ERROR)
        credential.password_hash = hash_password(new_password)
        credential.password_changed_at = current
        credential.updated_at = current
        user.session_version += 1
        user.updated_at = current
        self._sessions.revoke_all(user.id, "password_change", now=current)
        replacement = self._sessions.create(user_id=user.id, user_session_version=user.session_version, now=current)
        self._audit.append(action=SecurityAuditAction.AUTH_PASSWORD_CHANGED, actor_type="user", actor_ref=str(user.public_id), target_type="auth_user", target_ref=str(user.public_id), outcome="success", correlation_id=correlation_id, occurred_at=current)
        return replacement

    def _locked_current_session(self, session_id: int) -> AuthSession:
        row = self._session.execute(select(AuthSession).where(AuthSession.id == session_id).with_for_update()).scalar_one_or_none()
        if row is None or row.revoked_at is not None:
            raise AuthenticationServiceError(SAFE_AUTHENTICATION_ERROR)
        return row

    def _locked_throttle(self, login_key_hash: str, now: datetime) -> AuthLoginThrottle:
        row = self._session.execute(select(AuthLoginThrottle).where(AuthLoginThrottle.login_key_hash == login_key_hash).with_for_update()).scalar_one_or_none()
        if row is not None:
            return row
        try:
            with self._session.begin_nested():
                row = AuthLoginThrottle(login_key_hash=login_key_hash, failure_count=0, window_started_at=now, blocked_until=None, updated_at=now)
                self._session.add(row)
                self._session.flush()
            return row
        except IntegrityError:
            row = self._session.execute(select(AuthLoginThrottle).where(AuthLoginThrottle.login_key_hash == login_key_hash).with_for_update()).scalar_one_or_none()
            if row is None:
                raise AuthenticationServiceError(SAFE_AUTHENTICATION_ERROR)
            return row

    def _record_login_failure(self, throttle: AuthLoginThrottle, now: datetime) -> None:
        window = timedelta(seconds=self._settings.auth_login_failure_window_seconds)
        if now - throttle.window_started_at >= window:
            throttle.failure_count = 1
            throttle.window_started_at = now
            throttle.blocked_until = None
        else:
            throttle.failure_count = min(1000, throttle.failure_count + 1)
        if throttle.failure_count >= self._settings.auth_login_failure_limit:
            throttle.blocked_until = now + timedelta(seconds=self._settings.auth_login_block_seconds)
        throttle.updated_at = now

    @staticmethod
    def _login_key_hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()
