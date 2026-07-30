"""SQLAlchemy model for parent ingestion-cycle execution state."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
    desc,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, utc_now


if TYPE_CHECKING:
    from app.models.audit_event import AuditEvent
    from app.models.ingestion_run import IngestionRun


INGESTION_CYCLE_TRIGGER_TYPE_VALUES = ("scheduled", "manual", "legacy_import")
INGESTION_CYCLE_STATUS_VALUES = (
    "running",
    "success",
    "partial",
    "failed",
    "cancelled",
)


class IngestionCycle(BigIntPrimaryKeyMixin, PublicIdMixin, Base):
    """One scheduled, manual, or migration-only parent ingestion cycle."""

    __tablename__ = "ingestion_cycles"
    __table_args__ = (
        CheckConstraint(
            "trigger_type IN ('scheduled', 'manual', 'legacy_import')",
            name="ck_ingestion_cycles_trigger_type_allowed",
        ),
        CheckConstraint(
            "(trigger_type = 'scheduled' AND scheduled_for IS NOT NULL) OR "
            "(trigger_type IN ('manual', 'legacy_import') AND scheduled_for IS NULL)",
            name="ck_ingestion_cycles_trigger_schedule_consistency",
        ),
        CheckConstraint(
            "status IN ('running', 'success', 'partial', 'failed', 'cancelled')",
            name="ck_ingestion_cycles_status_allowed",
        ),
        CheckConstraint(
            "(status = 'running' AND completed_at IS NULL) OR "
            "(status IN ('success', 'partial', 'failed', 'cancelled') "
            "AND completed_at IS NOT NULL)",
            name="ck_ingestion_cycles_status_time_consistency",
        ),
        CheckConstraint(
            "completed_at IS NULL OR completed_at >= started_at",
            name="ck_ingestion_cycles_completed_at_order",
        ),
        CheckConstraint(
            "sources_expected >= 0 AND sources_started >= 0 "
            "AND sources_completed >= 0 AND sources_successful >= 0 "
            "AND sources_non_successful >= 0",
            name="ck_ingestion_cycles_counters_non_negative",
        ),
        CheckConstraint(
            "sources_started <= sources_expected "
            "AND sources_completed <= sources_started "
            "AND sources_successful + sources_non_successful = sources_completed",
            name="ck_ingestion_cycles_counter_relationships",
        ),
        UniqueConstraint(
            "idempotency_key",
            name="uq_ingestion_cycles_idempotency_key",
        ),
        Index(
            "ix_ingestion_cycles_status_started_at_id_desc",
            "status",
            desc("started_at"),
            desc("id"),
        ),
    )

    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    trigger_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    scheduled_for: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    sources_expected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sources_started: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sources_completed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sources_successful: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sources_non_successful: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    safe_summary: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    ingestion_runs: Mapped[list[IngestionRun]] = relationship(
        "IngestionRun",
        back_populates="cycle",
        passive_deletes=True,
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
        "AuditEvent",
        back_populates="cycle",
        foreign_keys="[AuditEvent.cycle_id]",
        passive_deletes=True,
        overlaps="ingestion_run,audit_events",
    )
