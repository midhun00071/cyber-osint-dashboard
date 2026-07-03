"""SQLAlchemy model for per-record ingestion outcomes."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, utc_now


if TYPE_CHECKING:
    from app.models.ingestion_error import IngestionError
    from app.models.ingestion_run import IngestionRun
    from app.models.intelligence_item import IntelligenceItem
    from app.models.source_record import SourceRecord


INGESTION_RECORD_ACTION_VALUES = (
    "created",
    "updated",
    "unchanged",
    "skipped",
    "failed",
)


class IngestionRunRecord(BigIntPrimaryKeyMixin, Base):
    """Sanitized outcome for one source record during an ingestion run."""

    __tablename__ = "ingestion_run_records"
    __table_args__ = (
        CheckConstraint(
            "action IN ('created', 'updated', 'unchanged', 'skipped', 'failed')",
            name="ck_ingestion_run_records_action_allowed",
        ),
        Index(
            "uq_ingestion_run_records_run_source_record",
            "ingestion_run_id",
            "source_record_id",
            unique=True,
            postgresql_where=text("source_record_id IS NOT NULL"),
        ),
        Index(
            "ix_ingestion_run_records_run_id_action",
            "ingestion_run_id",
            "action",
        ),
    )

    ingestion_run_id: Mapped[int] = mapped_column(
        ForeignKey("ingestion_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("source_records.id", ondelete="SET NULL"),
        nullable=True,
    )
    intelligence_item_id: Mapped[int | None] = mapped_column(
        ForeignKey("intelligence_items.id", ondelete="SET NULL"),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    safe_detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    ingestion_run: Mapped[IngestionRun] = relationship(
        "IngestionRun",
        back_populates="records",
    )
    source_record: Mapped[SourceRecord | None] = relationship(
        "SourceRecord",
        back_populates="ingestion_run_records",
    )
    intelligence_item: Mapped[IntelligenceItem | None] = relationship(
        "IntelligenceItem",
        back_populates="ingestion_run_records",
    )
    errors: Mapped[list[IngestionError]] = relationship(
        "IngestionError",
        back_populates="ingestion_run_record",
        passive_deletes=True,
    )
