"""SQLAlchemy model for ordered append-only ingestion-run evidence."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, utc_now


if TYPE_CHECKING:
    from app.models.ingestion_run import IngestionRun
    from app.models.quarantined_record import QuarantinedRecord


INGESTION_RUN_EVENT_TYPE_VALUES = (
    "acquired",
    "started",
    "persistence_committed",
    "checkpoint_advanced",
    "completed",
    "skipped",
    "deferred",
    "partial",
    "failed",
    "cancelled",
)


class IngestionRunEvent(BigIntPrimaryKeyMixin, Base):
    """Ordered lifecycle or non-transition evidence for one source run."""

    __tablename__ = "ingestion_run_events"
    __table_args__ = (
        UniqueConstraint(
            "ingestion_run_id",
            "sequence_number",
            name="uq_ingestion_run_events_run_sequence",
        ),
        UniqueConstraint(
            "id",
            "ingestion_run_id",
            name="uq_ingestion_run_events_id_run_id",
        ),
        CheckConstraint(
            "sequence_number BETWEEN 1 AND 100000",
            name="ck_ingestion_run_events_sequence_bounded",
        ),
        CheckConstraint(
            "event_type IN ('acquired', 'started', 'persistence_committed', "
            "'checkpoint_advanced', 'completed', 'skipped', 'deferred', "
            "'partial', 'failed', 'cancelled')",
            name="ck_ingestion_run_events_event_type_allowed",
        ),
        CheckConstraint(
            "(from_status IS NULL AND to_status IS NULL) OR "
            "(from_status IS NOT NULL AND to_status IS NOT NULL)",
            name="ck_ingestion_run_events_transition_shape",
        ),
        CheckConstraint(
            "created_at >= occurred_at",
            name="ck_ingestion_run_events_created_at_order",
        ),
    )

    ingestion_run_id: Mapped[int] = mapped_column(
        ForeignKey("ingestion_runs.id", ondelete="CASCADE"), nullable=False
    )
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    safe_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    ingestion_run: Mapped[IngestionRun] = relationship(
        "IngestionRun", back_populates="events"
    )
    quarantined_records: Mapped[list[QuarantinedRecord]] = relationship(
        "QuarantinedRecord",
        back_populates="ingestion_run_event",
        primaryjoin=(
            "and_(IngestionRunEvent.id == "
            "foreign(QuarantinedRecord.ingestion_run_event_id), "
            "IngestionRunEvent.ingestion_run_id == "
            "QuarantinedRecord.ingestion_run_id)"
        ),
        foreign_keys=(
            "[QuarantinedRecord.ingestion_run_event_id, "
            "QuarantinedRecord.ingestion_run_id]"
        ),
        passive_deletes=True,
        overlaps="ingestion_run,quarantined_records",
    )
