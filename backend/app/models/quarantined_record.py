"""SQLAlchemy model for bounded sanitized quarantine evidence."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    CHAR,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, utc_now


if TYPE_CHECKING:
    from app.models.ingestion_run import IngestionRun
    from app.models.ingestion_run_event import IngestionRunEvent
    from app.models.intelligence_source import IntelligenceSource


QUARANTINED_RECORD_STATUS_VALUES = (
    "pending",
    "reviewed",
    "released",
    "discarded",
)


class QuarantinedRecord(BigIntPrimaryKeyMixin, PublicIdMixin, Base):
    """Review-safe evidence for one rejected source record."""

    __tablename__ = "quarantined_records"
    __table_args__ = (
        UniqueConstraint(
            "ingestion_run_id",
            "quarantine_key",
            name="uq_quarantined_records_run_key",
        ),
        ForeignKeyConstraint(
            ["ingestion_run_id", "source_id"],
            ["ingestion_runs.id", "ingestion_runs.source_id"],
            name="fk_quarantined_records_run_source",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["ingestion_run_event_id", "ingestion_run_id"],
            ["ingestion_run_events.id", "ingestion_run_events.ingestion_run_id"],
            name="fk_quarantined_records_event_run",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "quarantine_key ~ '^[0-9a-f]{64}$'",
            name="ck_quarantined_records_key_format",
        ),
        CheckConstraint(
            "original_byte_count >= 0 AND stored_byte_count >= 0 "
            "AND stored_byte_count = "
            "octet_length(coalesce(safe_excerpt, '')) + "
            "octet_length(coalesce(safe_metadata, '')) "
            "AND stored_byte_count <= 4096 "
            "AND stored_byte_count <= original_byte_count",
            name="ck_quarantined_records_sizes_bounded",
        ),
        CheckConstraint(
            "status IN ('pending', 'reviewed', 'released', 'discarded')",
            name="ck_quarantined_records_status_allowed",
        ),
        CheckConstraint(
            "(status = 'pending' AND reviewed_at IS NULL) OR "
            "(status IN ('reviewed', 'released', 'discarded') "
            "AND reviewed_at IS NOT NULL AND reviewed_at >= quarantined_at)",
            name="ck_quarantined_records_reviewed_at_consistency",
        ),
        Index(
            "ix_quarantined_records_status_quarantined_at_id",
            "status",
            "quarantined_at",
            "id",
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id", ondelete="RESTRICT"), nullable=False
    )
    ingestion_run_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ingestion_run_event_id: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    quarantine_key: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    safe_excerpt: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    safe_metadata: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    original_byte_count: Mapped[int] = mapped_column(Integer, nullable=False)
    stored_byte_count: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    quarantined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    source: Mapped[IntelligenceSource] = relationship(
        "IntelligenceSource",
        back_populates="quarantined_records",
        foreign_keys=[source_id],
        overlaps="ingestion_run,quarantined_records",
    )
    ingestion_run: Mapped[IngestionRun] = relationship(
        "IngestionRun",
        back_populates="quarantined_records",
        primaryjoin=(
            "and_(foreign(QuarantinedRecord.ingestion_run_id) == IngestionRun.id, "
            "QuarantinedRecord.source_id == IngestionRun.source_id)"
        ),
        foreign_keys=(
            "[QuarantinedRecord.ingestion_run_id, QuarantinedRecord.source_id]"
        ),
        overlaps="source,quarantined_records,ingestion_run_event",
    )
    ingestion_run_event: Mapped[IngestionRunEvent | None] = relationship(
        "IngestionRunEvent",
        back_populates="quarantined_records",
        primaryjoin=(
            "and_(foreign(QuarantinedRecord.ingestion_run_event_id) == "
            "IngestionRunEvent.id, foreign(QuarantinedRecord.ingestion_run_id) == "
            "IngestionRunEvent.ingestion_run_id)"
        ),
        foreign_keys=(
            "[QuarantinedRecord.ingestion_run_event_id, "
            "QuarantinedRecord.ingestion_run_id]"
        ),
        overlaps="ingestion_run,quarantined_records",
    )
