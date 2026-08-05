"""Closed, append-only security audit writer using caller-owned transactions."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
import hashlib
import json
import re
from typing import Mapping
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import AuditEvent


class SecurityAuditAction(StrEnum):
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_FAILED = "auth.login.failed"
    AUTH_LOGOUT = "auth.logout"
    AUTH_SESSION_ROTATED = "auth.session.rotated"
    AUTH_PASSWORD_CHANGED = "auth.password.changed"
    AUTHORIZATION_DENIED = "authorization.denied"
    ADMIN_USER_CREATED = "admin.user.created"
    ADMIN_USER_ENABLED = "admin.user.enabled"
    ADMIN_USER_DISABLED = "admin.user.disabled"
    ADMIN_USER_ROLE_CHANGED = "admin.user.role_changed"
    ADMIN_USER_EXPIRY_CHANGED = "admin.user.expiry_changed"
    ADMIN_USER_SESSIONS_REVOKED = "admin.user.sessions_revoked"
    SYSTEM_BOOTSTRAP_ADMIN = "system.bootstrap_admin"
    INGESTION_MANUAL_REQUESTED = "ingestion.manual.requested"
    INGESTION_RETRY_REQUESTED = "ingestion.retry.requested"
    INGESTION_RUN_EXECUTION_FAILED = "ingestion.run.execution_failed"
    SOURCE_PAUSED = "source.paused"
    SOURCE_RESUMED = "source.resumed"
    SOURCE_DISABLED = "source.disabled"
    SOURCE_ENABLED = "source.enabled"
    SOURCE_STATE_CHANGED = "source.state.changed"
    REPORT_EXPORT_REQUESTED = "report.export.requested"


class SecurityAuditError(RuntimeError):
    pass


_ACTOR_TYPES = frozenset({"user", "system", "service"})
_OUTCOMES = frozenset({"success", "denied", "failed", "no_change"})
_TARGET_TYPES = frozenset(
    {
        "authentication", "auth_user", "auth_session", "system",
        "intelligence_source", "ingestion_cycle", "ingestion_run",
    }
)
_DETAIL_FIELDS = frozenset(
    {
        "reason", "prior_role", "new_role", "prior_status", "new_status",
        "expiry_state", "revoked_scope", "prior_state", "new_state",
        "trigger_type", "run_status", "operation",
    }
)
_SAFE_DETAIL_VALUE = re.compile(r"^[a-z0-9_.:-]{1,80}$", flags=re.ASCII)
ANONYMOUS_AUTH_ACTOR_REF = "security-service"


class SecurityAuditService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def append(
        self,
        *,
        action: SecurityAuditAction,
        actor_type: str,
        actor_ref: str,
        target_type: str,
        target_ref: str,
        outcome: str,
        correlation_id: str | UUID,
        safe_detail: Mapping[str, str] | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditEvent:
        if not isinstance(action, SecurityAuditAction):
            raise ValueError("The audit action is not permitted.")
        if actor_type not in _ACTOR_TYPES or outcome not in _OUTCOMES or target_type not in _TARGET_TYPES:
            raise ValueError("The audit vocabulary is invalid.")
        normalized_actor = self._bounded_reference(actor_ref, 160)
        normalized_target = self._bounded_reference(target_ref, 240)
        try:
            normalized_correlation = str(UUID(str(correlation_id)))
        except (TypeError, ValueError, AttributeError):
            raise ValueError("The audit correlation identifier is invalid.") from None
        detail_text = self._safe_detail(safe_detail)
        timestamp = occurred_at or datetime.now(UTC)
        idempotency_material = "|".join((normalized_correlation, action.value, actor_type, normalized_actor, target_type, normalized_target, outcome))
        idempotency_key = f"security:{hashlib.sha256(idempotency_material.encode('utf-8')).hexdigest()}"
        event = AuditEvent(
            idempotency_key=idempotency_key,
            actor_type=actor_type,
            actor_ref=normalized_actor,
            action=action.value,
            target_type=target_type,
            target_ref=normalized_target,
            outcome=outcome,
            correlation_id=normalized_correlation,
            safe_detail=detail_text,
            occurred_at=timestamp,
            created_at=timestamp,
        )
        try:
            self._session.add(event)
            self._session.flush()
        except SQLAlchemyError:
            raise SecurityAuditError("Security audit evidence could not be recorded.") from None
        return event

    @staticmethod
    def _bounded_reference(value: object, maximum: int) -> str:
        if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= maximum:
            raise ValueError("The audit reference is invalid.")
        if any(not character.isprintable() or character in "\r\n\x00" for character in value):
            raise ValueError("The audit reference is invalid.")
        return value

    @staticmethod
    def _safe_detail(detail: Mapping[str, str] | None) -> str | None:
        if detail is None:
            return None
        if not isinstance(detail, Mapping) or len(detail) > 6:
            raise ValueError("The audit detail is invalid.")
        normalized: dict[str, str] = {}
        for key, value in detail.items():
            if key not in _DETAIL_FIELDS or not isinstance(value, str) or _SAFE_DETAIL_VALUE.fullmatch(value) is None:
                raise ValueError("The audit detail is invalid.")
            normalized[key] = value
        rendered = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        if len(rendered) > 1000:
            raise ValueError("The audit detail is invalid.")
        return rendered
