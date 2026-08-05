"""Bounded administrator audit-event query service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import AuditEvent
from app.services.security_audit_service import SecurityAuditAction


class AuditQueryError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AuditQueryFilters:
    limit: int = 50
    offset: int = 0
    action: SecurityAuditAction | None = None
    outcome: str | None = None
    correlation_id: UUID | None = None
    occurred_from: datetime | None = None
    occurred_to: datetime | None = None


@dataclass(frozen=True, slots=True)
class AuditEventRecord:
    public_id: UUID
    actor_type: str
    actor_ref: str
    action: str
    target_type: str
    target_ref: str
    outcome: str
    correlation_id: UUID | None
    safe_detail: dict[str, str] | None
    occurred_at: datetime


class AuditQueryService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def list_events(self, filters: AuditQueryFilters) -> tuple[list[AuditEventRecord], int]:
        self._validate(filters)
        predicates = []
        if filters.action is not None:
            predicates.append(AuditEvent.action == filters.action.value)
        if filters.outcome is not None:
            predicates.append(AuditEvent.outcome == filters.outcome)
        if filters.correlation_id is not None:
            predicates.append(AuditEvent.correlation_id == str(filters.correlation_id))
        if filters.occurred_from is not None:
            predicates.append(AuditEvent.occurred_at >= filters.occurred_from)
        if filters.occurred_to is not None:
            predicates.append(AuditEvent.occurred_at < filters.occurred_to)
        try:
            total = self._session.execute(select(func.count(AuditEvent.id)).where(*predicates)).scalar_one()
            rows = self._session.execute(
                select(AuditEvent).where(*predicates).order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).offset(filters.offset).limit(filters.limit)
            ).scalars().all()
        except SQLAlchemyError:
            raise AuditQueryError("Audit events could not be loaded.") from None
        return [self._record(row) for row in rows], total

    @staticmethod
    def _validate(filters: AuditQueryFilters) -> None:
        if type(filters.limit) is not int or not 1 <= filters.limit <= 100 or type(filters.offset) is not int or not 0 <= filters.offset <= 100000:
            raise ValueError("Audit pagination is invalid.")
        if filters.outcome is not None and filters.outcome not in {"success", "denied", "failed", "no_change"}:
            raise ValueError("The audit outcome filter is invalid.")
        for value in (filters.occurred_from, filters.occurred_to):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError("Audit time filters must be UTC-aware.")
        if filters.occurred_from is not None and filters.occurred_to is not None:
            if filters.occurred_to <= filters.occurred_from or filters.occurred_to - filters.occurred_from > timedelta(days=366):
                raise ValueError("The audit time range is invalid.")

    @staticmethod
    def _record(row: AuditEvent) -> AuditEventRecord:
        detail = json.loads(row.safe_detail) if row.safe_detail is not None else None
        correlation = UUID(row.correlation_id) if row.correlation_id is not None else None
        return AuditEventRecord(public_id=row.public_id, actor_type=row.actor_type, actor_ref=row.actor_ref, action=row.action, target_type=row.target_type, target_ref=row.target_ref, outcome=row.outcome, correlation_id=correlation, safe_detail=detail, occurred_at=row.occurred_at.astimezone(UTC))
