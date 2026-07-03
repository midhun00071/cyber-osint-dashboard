"""SQLAlchemy model for source ingestion run metadata."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    desc,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, utc_now


if TYPE_CHECKING:
    from app.models.ingestion_error import IngestionError
    from app.models.ingestion_run_record import IngestionRunRecord
    from app.models.intelligence_source import IntelligenceSource


TRIGGER_TYPE_VALUES = ("scheduled", "manual", "retry")
INGESTION_RUN_STATUS_VALUES = (
    "running",
    "succeeded",
    "partial",
    "failed",
    "canceled",
)


class IngestionRun(BigIntPrimaryKeyMixin, PublicIdMixin, Base):
    """Operational metadata for one bounded source ingestion attempt."""

    __tablename__ = "ingestion_runs"
    __table_args__ = (
        CheckConstraint(
            "trigger_type IN ('scheduled', 'manual', 'retry')",
            name="ck_ingestion_runs_trigger_type_allowed",
        ),
        CheckConstraint(
            "status IN ('running', 'succeeded', 'partial', 'failed', 'canceled')",
            name="ck_ingestion_runs_status_allowed",
        ),
        CheckConstraint(
            "completed_at IS NULL OR completed_at >= started_at",
            name="ck_ingestion_runs_completed_at_order",
        ),
        CheckConstraint(
            "records_fetched >= 0 "
            "AND records_created >= 0 "
            "AND records_updated >= 0 "
            "AND records_unchanged >= 0 "
            "AND records_skipped >= 0 "
            "AND records_failed >= 0 "
            "AND error_count >= 0",
            name="ck_ingestion_runs_counters_non_negative",
        ),
        Index(
            "ix_ingestion_runs_source_id_started_at_desc",
            "source_id",
            desc("started_at"),
        ),
        Index(
            "ix_ingestion_runs_status_started_at_desc",
            "status",
            desc("started_at"),
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id", ondelete="RESTRICT"),
        nullable=False,
    )
    trigger_type: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    records_fetched: Mapped[int] = mapped_column(Integer, nullable=False)
    records_created: Mapped[int] = mapped_column(Integer, nullable=False)
    records_updated: Mapped[int] = mapped_column(Integer, nullable=False)
    records_unchanged: Mapped[int] = mapped_column(Integer, nullable=False)
    records_skipped: Mapped[int] = mapped_column(Integer, nullable=False)
    records_failed: Mapped[int] = mapped_column(Integer, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False)
    checkpoint_before: Mapped[str | None] = mapped_column(String(500), nullable=True)
    checkpoint_after: Mapped[str | None] = mapped_column(String(500), nullable=True)
    safe_summary: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    source: Mapped[IntelligenceSource] = relationship(
        "IntelligenceSource",
        back_populates="ingestion_runs",
    )
    records: Mapped[list[IngestionRunRecord]] = relationship(
        "IngestionRunRecord",
        back_populates="ingestion_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    errors: Mapped[list[IngestionError]] = relationship(
        "IngestionError",
        back_populates="ingestion_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
