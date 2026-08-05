"""Replaceable identity-provider contract and local database implementation."""

from __future__ import annotations

import re
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import AuthIdentity, AuthLocalCredential, AuthUser, AuthUserRole
from app.security.authorization import InvalidRoleError, parse_role
from app.security.contracts import VerifiedIdentity


LOCAL_PROVIDER_KEY = "local"
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 64
USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{2,63}$", flags=re.ASCII)


class IdentityLookupError(RuntimeError):
    pass


class IdentityProvider(Protocol):
    provider_key: str

    def lookup(
        self,
        canonical_subject: str,
        *,
        for_update: bool = False,
    ) -> VerifiedIdentity | None: ...


def canonicalize_local_username(username: object) -> str | None:
    if not isinstance(username, str) or not username.isascii():
        return None
    canonical = username.lower()
    if not MIN_USERNAME_LENGTH <= len(canonical) <= MAX_USERNAME_LENGTH:
        return None
    if USERNAME_PATTERN.fullmatch(canonical) is None:
        return None
    return canonical


class LocalIdentityProvider:
    provider_key = LOCAL_PROVIDER_KEY

    def __init__(self, session: Session) -> None:
        self._session = session

    def lookup(
        self,
        canonical_subject: str,
        *,
        for_update: bool = False,
    ) -> VerifiedIdentity | None:
        if canonicalize_local_username(canonical_subject) != canonical_subject:
            return None
        statement = (
            select(AuthIdentity, AuthLocalCredential, AuthUser, AuthUserRole)
            .join(AuthLocalCredential, AuthLocalCredential.identity_id == AuthIdentity.id)
            .join(AuthUser, AuthUser.id == AuthIdentity.user_id)
            .join(AuthUserRole, AuthUserRole.user_id == AuthUser.id)
            .where(AuthIdentity.provider_key == self.provider_key, AuthIdentity.subject_key == canonical_subject)
        )
        if for_update:
            statement = statement.with_for_update()
        try:
            row = self._session.execute(statement).one_or_none()
        except SQLAlchemyError:
            raise IdentityLookupError("Identity lookup failed safely.") from None
        if row is None:
            return None
        identity, credential, user, role_record = row
        try:
            role = parse_role(role_record.role_key)
        except InvalidRoleError:
            return None
        return VerifiedIdentity(
            user_id=user.id,
            user_public_id=user.public_id,
            identity_id=identity.id,
            display_name=user.display_name,
            status=user.status,
            account_expires_at=user.account_expires_at,
            session_version=user.session_version,
            role=role,
            password_hash=credential.password_hash,
        )
