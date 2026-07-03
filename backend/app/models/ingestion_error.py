"""SQLAlchemy model for sanitized ingestion error records."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
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
from app.models.common import BigIntPrimaryKeyMixin, utc_now


if TYPE_CHECKING:
    from app.models.ingestion_run import IngestionRun
    from app.models.ingestion_run_record import IngestionRunRecord
    from app.models.source_record import SourceRecord


class IngestionError(BigIntPrimaryKeyMixin, Base):
    """Sanitized error metadata without raw payloads, secrets, or stack traces."""

    __tablename__ = "ingestion_errors"
    __table_args__ = (
        CheckConstraint(
            "retry_count >= 0",
            name="ck_ingestion_errors_retry_count_non_negative",
        ),
        Index(
            "ix_ingestion_errors_run_id_occurred_at_desc",
            "ingestion_run_id",
            desc("occurred_at"),
        ),
    )

    ingestion_run_id: Mapped[int] = mapped_column(
        ForeignKey("ingestion_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    ingestion_run_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("ingestion_run_records.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("source_records.id", ondelete="SET NULL"),
        nullable=True,
    )
    error_type: Mapped[str] = mapped_column(String(80), nullable=False)
    safe_message: Mapped[str] = mapped_column(String(1000), nullable=False)
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    ingestion_run: Mapped[IngestionRun] = relationship(
        "IngestionRun",
        back_populates="errors",
    )
    ingestion_run_record: Mapped[IngestionRunRecord | None] = relationship(
        "IngestionRunRecord",
        back_populates="errors",
    )
    source_record: Mapped[SourceRecord | None] = relationship(
        "SourceRecord",
        back_populates="ingestion_errors",
    )
