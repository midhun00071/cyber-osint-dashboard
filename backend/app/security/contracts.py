"""Immutable security contracts and the closed role/permission vocabulary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class RoleKey(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    INGESTION_OPERATOR = "ingestion_operator"
    ADMINISTRATOR = "administrator"


class Permission(StrEnum):
    CONTENT_READ = "content.read"
    SOURCE_READ = "source.read"
    ANALYSIS_USE = "analysis.use"
    REPORT_READ = "report.read"
    REPORT_EXPORT = "report.export"
    INGESTION_READ = "ingestion.read"
    INGESTION_RUN = "ingestion.run"
    INGESTION_RETRY = "ingestion.retry"
    INGESTION_PAUSE = "ingestion.pause"
    USER_READ = "user.read"
    USER_MANAGE = "user.manage"
    SESSION_REVOKE = "session.revoke"
    SOURCE_MANAGE = "source.manage"
    AUDIT_READ = "audit.read"


ROLE_PERMISSIONS: dict[RoleKey, frozenset[Permission]] = {
    RoleKey.VIEWER: frozenset({Permission.CONTENT_READ, Permission.SOURCE_READ}),
    RoleKey.ANALYST: frozenset({Permission.CONTENT_READ, Permission.SOURCE_READ, Permission.ANALYSIS_USE, Permission.REPORT_READ, Permission.REPORT_EXPORT}),
    RoleKey.INGESTION_OPERATOR: frozenset({Permission.CONTENT_READ, Permission.SOURCE_READ, Permission.INGESTION_READ, Permission.INGESTION_RUN, Permission.INGESTION_RETRY, Permission.INGESTION_PAUSE}),
    RoleKey.ADMINISTRATOR: frozenset(Permission),
}


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    user_id: int
    user_public_id: UUID
    identity_id: int
    display_name: str
    status: str
    account_expires_at: datetime | None
    session_version: int
    role: RoleKey
    password_hash: str


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    user_id: int
    user_public_id: UUID
    display_name: str
    role: RoleKey
    permissions: frozenset[Permission]
    account_expires_at: datetime | None
    session_id: int
    session_public_id: UUID
    session_absolute_expires_at: datetime
    csrf_token_hash: str

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions
