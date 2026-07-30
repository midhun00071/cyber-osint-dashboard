"""SQLAlchemy model for append-only source checkpoint history."""

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


class SourceCheckpoint(BigIntPrimaryKeyMixin, Base):
    """One committed version of an opaque, bounded source cursor."""

    __tablename__ = "source_checkpoints"
    __table_args__ = (
        UniqueConstraint(
            "id", "source_id", name="uq_source_checkpoints_id_source_id"
        ),
        UniqueConstraint(
            "previous_checkpoint_id", name="uq_source_checkpoints_previous"
        ),
        ForeignKeyConstraint(
            ["advanced_by_run_id", "source_id"],
            ["ingestion_runs.id", "ingestion_runs.source_id"],
            name="fk_source_checkpoints_advanced_run_source",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["previous_checkpoint_id", "source_id"],
            ["source_checkpoints.id", "source_checkpoints.source_id"],
            name="fk_source_checkpoints_previous_source",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(scope_kind = 'source' AND partition_key IS NULL) OR "
            "(scope_kind = 'partition' AND partition_key IS NOT NULL "
            "AND char_length(btrim(partition_key)) BETWEEN 1 AND 160)",
            name="ck_source_checkpoints_scope_identity",
        ),
        CheckConstraint(
            "version > 0", name="ck_source_checkpoints_version_positive"
        ),
        CheckConstraint(
            "persistence_committed_at <= committed_at",
            name="ck_source_checkpoints_commit_order",
        ),
        Index(
            "uq_source_checkpoints_source_identity_version",
            "source_id",
            "checkpoint_name",
            "version",
            unique=True,
            postgresql_where=text(
                "scope_kind = 'source' AND partition_key IS NULL"
            ),
        ),
        Index(
            "uq_source_checkpoints_partition_identity_version",
            "source_id",
            "partition_key",
            "checkpoint_name",
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
    checkpoint_name: Mapped[str] = mapped_column(String(80), nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    checkpoint_value: Mapped[str] = mapped_column(String(500), nullable=False)
    previous_checkpoint_id: Mapped[int | None] = mapped_column(
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
        back_populates="source_checkpoints",
        foreign_keys=[source_id],
        overlaps="advanced_by_run,advanced_checkpoints,previous_checkpoint,next_checkpoint",
    )
    advanced_by_run: Mapped[IngestionRun] = relationship(
        "IngestionRun",
        back_populates="advanced_checkpoints",
        primaryjoin=(
            "and_(foreign(SourceCheckpoint.advanced_by_run_id) == IngestionRun.id, "
            "SourceCheckpoint.source_id == IngestionRun.source_id)"
        ),
        foreign_keys="[SourceCheckpoint.advanced_by_run_id, SourceCheckpoint.source_id]",
        overlaps="source,source_checkpoints",
    )
    previous_checkpoint: Mapped[SourceCheckpoint | None] = relationship(
        "SourceCheckpoint",
        primaryjoin=(
            "and_(foreign(SourceCheckpoint.previous_checkpoint_id) == "
            "remote(SourceCheckpoint.id), foreign(SourceCheckpoint.source_id) == "
            "remote(SourceCheckpoint.source_id))"
        ),
        foreign_keys="[SourceCheckpoint.previous_checkpoint_id, SourceCheckpoint.source_id]",
        remote_side="[SourceCheckpoint.id, SourceCheckpoint.source_id]",
        back_populates="next_checkpoint",
        overlaps="source,source_checkpoints",
    )
    next_checkpoint: Mapped[SourceCheckpoint | None] = relationship(
        "SourceCheckpoint",
        back_populates="previous_checkpoint",
        uselist=False,
        overlaps="source,source_checkpoints",
    )
