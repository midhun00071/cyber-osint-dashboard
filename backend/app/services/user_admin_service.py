"""Explicit administrator-owned local user lifecycle operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import AuthIdentity, AuthLocalCredential, AuthUser, AuthUserRole
from app.security.authorization import InvalidRoleError, parse_role, permissions_for_role
from app.security.contracts import AuthenticatedPrincipal, RoleKey
from app.security.identity import LOCAL_PROVIDER_KEY, canonicalize_local_username
from app.security.passwords import PasswordPolicyError, hash_password
from app.security.sessions import SessionSecurityService
from app.services.security_audit_service import SecurityAuditAction, SecurityAuditService


class UserNotFoundError(LookupError):
    pass


class UserConflictError(ValueError):
    pass


class AdministratorSafetyError(ValueError):
    pass


class UserAdminServiceError(RuntimeError):
    pass


class UserInputError(UserAdminServiceError):
    """Expected safe rejection of administrator-supplied user input."""


@dataclass(frozen=True, slots=True)
class AdminUserRecord:
    public_id: UUID
    display_name: str
    username: str
    status: str
    role: RoleKey
    permissions: tuple[str, ...]
    account_expires_at: datetime | None
    last_authenticated_at: datetime | None
    created_at: datetime
    updated_at: datetime


class UserAdminService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._sessions = SessionSecurityService(session, settings)
        self._audit = SecurityAuditService(session)

    def list_users(self, *, limit: int, offset: int) -> tuple[list[AdminUserRecord], int]:
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 100000:
            raise UserInputError("Invalid administrator input.")
        rows = self._session.execute(
            self._base_query().order_by(AuthUser.created_at.asc(), AuthUser.id.asc()).offset(offset).limit(limit)
        ).all()
        count = self._session.execute(
            select(func.count(AuthUser.id))
            .join(AuthIdentity, AuthIdentity.user_id == AuthUser.id)
            .where(AuthIdentity.provider_key == LOCAL_PROVIDER_KEY)
        ).scalar_one()
        return [self._record(*row) for row in rows], count

    def get_user(self, public_id: UUID) -> AdminUserRecord:
        row = self._session.execute(self._base_query().where(AuthUser.public_id == public_id)).one_or_none()
        if row is None:
            raise UserNotFoundError("The requested user was not found.")
        return self._record(*row)

    def create_user(self, *, actor: AuthenticatedPrincipal, username: str, display_name: str, password: str, role: RoleKey, account_expires_at: datetime | None, correlation_id: str, now: datetime | None = None) -> AdminUserRecord:
        current = now or datetime.now(UTC)
        canonical = canonicalize_local_username(username)
        if canonical is None:
            raise UserInputError("Invalid administrator input.")
        normalized_name = self._display_name(display_name)
        try:
            parsed_role = parse_role(role.value if isinstance(role, RoleKey) else role)
        except InvalidRoleError:
            raise UserInputError("Invalid administrator input.") from None
        expiry = self._validated_expiry(account_expires_at, minimum=current)
        try:
            password_hash = hash_password(password)
        except PasswordPolicyError:
            raise UserInputError("Invalid administrator input.") from None
        user = AuthUser(display_name=normalized_name, status="active", account_expires_at=expiry, session_version=1, created_at=current, updated_at=current)
        try:
            self._session.add(user)
            self._session.flush()
            identity = AuthIdentity(user_id=user.id, provider_key=LOCAL_PROVIDER_KEY, subject_key=canonical, created_at=current)
            self._session.add(identity)
            self._session.flush()
            self._session.add(AuthLocalCredential(identity_id=identity.id, password_hash=password_hash, password_changed_at=current, created_at=current, updated_at=current))
            self._session.add(AuthUserRole(user_id=user.id, role_key=parsed_role.value, assigned_by_user_id=actor.user_id, assigned_at=current, updated_at=current))
            self._session.flush()
            self._audit.append(action=SecurityAuditAction.ADMIN_USER_CREATED, actor_type="user", actor_ref=str(actor.user_public_id), target_type="auth_user", target_ref=str(user.public_id), outcome="success", correlation_id=correlation_id, safe_detail={"new_role": parsed_role.value}, occurred_at=current)
        except IntegrityError:
            raise UserConflictError("The user could not be created.") from None
        return AdminUserRecord(public_id=user.public_id, display_name=user.display_name, username=canonical, status=user.status, role=parsed_role, permissions=tuple(sorted(permission.value for permission in permissions_for_role(parsed_role))), account_expires_at=user.account_expires_at, last_authenticated_at=user.last_authenticated_at, created_at=user.created_at, updated_at=user.updated_at)

    def change_status(self, *, actor: AuthenticatedPrincipal, public_id: UUID, status_value: str, correlation_id: str, now: datetime | None = None) -> AdminUserRecord:
        if not isinstance(status_value, str) or status_value not in {"active", "disabled"}:
            raise UserInputError("Invalid administrator input.")
        current = now or datetime.now(UTC)
        user, role = self._locked_user_role(public_id)
        if status_value == "disabled":
            if user.id == actor.user_id:
                raise AdministratorSafetyError("Administrators cannot disable their own account.")
            if role.role_key == RoleKey.ADMINISTRATOR.value:
                self._ensure_another_active_administrator(user.id, current)
            if user.status != "disabled":
                user.status = "disabled"
                user.disabled_at = current
                user.session_version += 1
                self._sessions.revoke_all(user.id, "account_disabled", now=current)
            action = SecurityAuditAction.ADMIN_USER_DISABLED
        else:
            if user.status != "active":
                user.status = "active"
                user.disabled_at = None
                user.session_version += 1
                self._sessions.revoke_all(user.id, "admin_revocation", now=current)
            action = SecurityAuditAction.ADMIN_USER_ENABLED
        user.updated_at = current
        self._audit.append(action=action, actor_type="user", actor_ref=str(actor.user_public_id), target_type="auth_user", target_ref=str(user.public_id), outcome="success", correlation_id=correlation_id, safe_detail={"new_status": status_value}, occurred_at=current)
        return self.get_user(public_id)

    def change_role(self, *, actor: AuthenticatedPrincipal, public_id: UUID, role_value: RoleKey, correlation_id: str, now: datetime | None = None) -> AdminUserRecord:
        current = now or datetime.now(UTC)
        try:
            new_role = parse_role(role_value.value if isinstance(role_value, RoleKey) else role_value)
        except InvalidRoleError:
            raise UserInputError("Invalid administrator input.") from None
        user, role = self._locked_user_role(public_id)
        if user.id == actor.user_id:
            raise AdministratorSafetyError("Administrators cannot change their own role here.")
        prior_role = parse_role(role.role_key)
        if prior_role == RoleKey.ADMINISTRATOR and new_role != RoleKey.ADMINISTRATOR:
            self._ensure_another_active_administrator(user.id, current)
        role.role_key = new_role.value
        role.assigned_by_user_id = actor.user_id
        role.updated_at = current
        user.session_version += 1
        user.updated_at = current
        self._sessions.revoke_all(user.id, "role_changed", now=current)
        self._audit.append(action=SecurityAuditAction.ADMIN_USER_ROLE_CHANGED, actor_type="user", actor_ref=str(actor.user_public_id), target_type="auth_user", target_ref=str(user.public_id), outcome="success", correlation_id=correlation_id, safe_detail={"prior_role": prior_role.value, "new_role": new_role.value}, occurred_at=current)
        return self.get_user(public_id)

    def change_expiry(self, *, actor: AuthenticatedPrincipal, public_id: UUID, account_expires_at: datetime | None, correlation_id: str, now: datetime | None = None) -> AdminUserRecord:
        current = now or datetime.now(UTC)
        user, role = self._locked_user_role(public_id)
        expiry = self._validated_expiry(account_expires_at, minimum=user.created_at)
        previous_expiry = user.account_expires_at
        was_already_expired = (
            user.status == "active"
            and previous_expiry is not None
            and previous_expiry <= current
        )
        reaches_now = expiry is not None and expiry <= current
        reactivates_naturally_expired_account = was_already_expired and (
            expiry is None or expiry > current
        )
        if reaches_now and role.role_key == RoleKey.ADMINISTRATOR.value and user.status == "active":
            self._ensure_another_active_administrator(user.id, current)
        user.account_expires_at = expiry
        user.updated_at = current
        if reaches_now:
            user.session_version += 1
            self._sessions.revoke_all(user.id, "account_disabled", now=current)
        elif reactivates_naturally_expired_account:
            user.session_version += 1
            self._sessions.revoke_all(user.id, "admin_revocation", now=current)
        self._audit.append(action=SecurityAuditAction.ADMIN_USER_EXPIRY_CHANGED, actor_type="user", actor_ref=str(actor.user_public_id), target_type="auth_user", target_ref=str(user.public_id), outcome="success", correlation_id=correlation_id, safe_detail={"expiry_state": "expired" if reaches_now else "configured" if expiry is not None else "none"}, occurred_at=current)
        return self.get_user(public_id)

    def revoke_sessions(self, *, actor: AuthenticatedPrincipal, public_id: UUID, correlation_id: str, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        user, _role = self._locked_user_role(public_id)
        user.session_version += 1
        user.updated_at = current
        self._sessions.revoke_all(user.id, "admin_revocation", now=current)
        self._audit.append(action=SecurityAuditAction.ADMIN_USER_SESSIONS_REVOKED, actor_type="user", actor_ref=str(actor.user_public_id), target_type="auth_user", target_ref=str(user.public_id), outcome="success", correlation_id=correlation_id, safe_detail={"revoked_scope": "all"}, occurred_at=current)

    @staticmethod
    def _display_name(value: object) -> str:
        if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= 160 or any(not character.isprintable() for character in value):
            raise UserInputError("Invalid administrator input.")
        return value

    @staticmethod
    def _validated_expiry(value: object, *, minimum: datetime) -> datetime | None:
        if value is None:
            return None
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise UserInputError("Invalid administrator input.")
        if value <= minimum:
            raise UserInputError("Invalid administrator input.")
        return value

    @staticmethod
    def _base_query():
        return (
            select(AuthUser, AuthUserRole, AuthIdentity)
            .join(AuthUserRole, AuthUserRole.user_id == AuthUser.id)
            .join(AuthIdentity, AuthIdentity.user_id == AuthUser.id)
            .where(AuthIdentity.provider_key == LOCAL_PROVIDER_KEY)
        )

    def _locked_user_role(self, public_id: UUID) -> tuple[AuthUser, AuthUserRole]:
        row = self._session.execute(
            select(AuthUser, AuthUserRole).join(AuthUserRole, AuthUserRole.user_id == AuthUser.id).where(AuthUser.public_id == public_id).with_for_update()
        ).one_or_none()
        if row is None:
            raise UserNotFoundError("The requested user was not found.")
        return row[0], row[1]

    def _ensure_another_active_administrator(self, excluded_user_id: int, now: datetime) -> None:
        rows = self._session.execute(
            select(AuthUser.id)
            .join(AuthUserRole, AuthUserRole.user_id == AuthUser.id)
            .where(AuthUserRole.role_key == RoleKey.ADMINISTRATOR.value, AuthUser.status == "active", AuthUser.id != excluded_user_id, (AuthUser.account_expires_at.is_(None) | (AuthUser.account_expires_at > now)))
            .with_for_update()
        ).scalars().all()
        if not rows:
            raise AdministratorSafetyError("The last active administrator must be preserved.")

    @staticmethod
    def _record(user: AuthUser, role_record: AuthUserRole, identity: AuthIdentity) -> AdminUserRecord:
        role = parse_role(role_record.role_key)
        return AdminUserRecord(public_id=user.public_id, display_name=user.display_name, username=identity.subject_key, status=user.status, role=role, permissions=tuple(sorted(permission.value for permission in permissions_for_role(role))), account_expires_at=user.account_expires_at, last_authenticated_at=user.last_authenticated_at, created_at=user.created_at, updated_at=user.updated_at)
