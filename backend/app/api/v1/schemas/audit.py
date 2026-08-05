"""Strict audit-search filters and safe response fields."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)
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


class AuditEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[AuditEventResponse]
    total: int
    limit: int
    offset: int
