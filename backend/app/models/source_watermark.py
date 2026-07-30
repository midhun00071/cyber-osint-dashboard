"""SQLAlchemy model for append-only source watermark history."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin


if TYPE_CHECKING:
    from app.models.ingestion_run import IngestionRun
    from app.models.intelligence_source import IntelligenceSource


class SourceWatermark(BigIntPrimaryKeyMixin, Base):
    """One committed version of a time-based source high-water mark."""

    __tablename__ = "source_watermarks"
    __table_args__ = (
        UniqueConstraint(
            "id", "source_id", name="uq_source_watermarks_id_source_id"
        ),
        UniqueConstraint(
            "previous_watermark_id", name="uq_source_watermarks_previous"
        ),
        ForeignKeyConstraint(
            ["advanced_by_run_id", "source_id"],
            ["ingestion_runs.id", "ingestion_runs.source_id"],
            name="fk_source_watermarks_advanced_run_source",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["previous_watermark_id", "source_id"],
            ["source_watermarks.id", "source_watermarks.source_id"],
            name="fk_source_watermarks_previous_source",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(scope_kind = 'source' AND partition_key IS NULL) OR "
            "(scope_kind = 'partition' AND partition_key IS NOT NULL "
            "AND char_length(btrim(partition_key)) BETWEEN 1 AND 160)",
            name="ck_source_watermarks_scope_identity",
        ),
        CheckConstraint(
            "version > 0", name="ck_source_watermarks_version_positive"
        ),
        CheckConstraint(
            "persistence_committed_at <= committed_at",
            name="ck_source_watermarks_commit_order",
        ),
        Index(
            "uq_source_watermarks_source_identity_version",
            "source_id",
            "watermark_name",
            "version",
            unique=True,
            postgresql_where=text(
                "scope_kind = 'source' AND partition_key IS NULL"
            ),
        ),
        Index(
            "uq_source_watermarks_partition_identity_version",
            "source_id",
            "partition_key",
            "watermark_name",
            "version",
            unique=True,
            postgresql_where=text(
                "scope_kind = 'partition' AND partition_key IS NOT NULL"
            ),
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id", ondelete="RESTRICT"), nullable=False
    )
    scope_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    partition_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    watermark_name: Mapped[str] = mapped_column(String(80), nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    watermark_value: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    previous_watermark_id: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    advanced_by_run_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    persistence_committed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    committed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    source: Mapped[IntelligenceSource] = relationship(
        "IntelligenceSource",
        back_populates="source_watermarks",
        foreign_keys=[source_id],
        overlaps="advanced_by_run,advanced_watermarks,previous_watermark,next_watermark",
    )
    advanced_by_run: Mapped[IngestionRun] = relationship(
        "IngestionRun",
        back_populates="advanced_watermarks",
        primaryjoin=(
            "and_(foreign(SourceWatermark.advanced_by_run_id) == IngestionRun.id, "
            "SourceWatermark.source_id == IngestionRun.source_id)"
        ),
        foreign_keys="[SourceWatermark.advanced_by_run_id, SourceWatermark.source_id]",
        overlaps="source,source_watermarks",
    )
    previous_watermark: Mapped[SourceWatermark | None] = relationship(
        "SourceWatermark",
        primaryjoin=(
            "and_(foreign(SourceWatermark.previous_watermark_id) == "
            "remote(SourceWatermark.id), foreign(SourceWatermark.source_id) == "
            "remote(SourceWatermark.source_id))"
        ),
        foreign_keys="[SourceWatermark.previous_watermark_id, SourceWatermark.source_id]",
        remote_side="[SourceWatermark.id, SourceWatermark.source_id]",
        back_populates="next_watermark",
        overlaps="source,source_watermarks",
    )
    next_watermark: Mapped[SourceWatermark | None] = relationship(
        "SourceWatermark",
        back_populates="previous_watermark",
        uselist=False,
        overlaps="source,source_watermarks",
    )
