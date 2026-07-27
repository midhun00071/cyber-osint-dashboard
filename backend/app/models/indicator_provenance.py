"""SQLAlchemy model for indicator source provenance metadata."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Numeric,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin


if TYPE_CHECKING:
    from app.models.indicator import Indicator
    from app.models.intelligence_source import IntelligenceSource
    from app.models.source_record import SourceRecord


class IndicatorProvenance(
    BigIntPrimaryKeyMixin,
    PublicIdMixin,
    TimestampMixin,
    Base,
):
    """Bounded source attribution for a normalized indicator."""

    __tablename__ = "indicator_provenances"
    __table_args__ = (
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_indicator_provenances_confidence_range",
        ),
        CheckConstraint(
            "last_observed_at IS NULL OR first_observed_at IS NULL OR "
            "last_observed_at >= first_observed_at",
            name="ck_indicator_provenances_observed_at_order",
        ),
        ForeignKeyConstraint(
            ["source_record_id", "source_id"],
            ["source_records.id", "source_records.source_id"],
            name="fk_indicator_provenances_source_record_source_records",
            ondelete="RESTRICT",
        ),
        Index(
            "uq_indicator_provenances_indicator_source_record",
            "indicator_id",
            "source_record_id",
            unique=True,
            postgresql_where=text("source_record_id IS NOT NULL"),
        ),
        Index(
            "uq_indicator_provenances_indicator_source_without_record",
            "indicator_id",
            "source_id",
            unique=True,
            postgresql_where=text("source_record_id IS NULL"),
        ),
    )

    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_record_id: Mapped[int | None] = mapped_column(nullable=True)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    context_summary: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    first_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    indicator: Mapped[Indicator] = relationship(
        "Indicator",
        back_populates="provenances",
    )
    source: Mapped[IntelligenceSource] = relationship(
        "IntelligenceSource",
        back_populates="indicator_provenances",
    )
    source_record: Mapped[SourceRecord | None] = relationship(
        "SourceRecord",
        back_populates="indicator_provenances",
        primaryjoin=(
            "and_(foreign(IndicatorProvenance.source_record_id) == SourceRecord.id, "
            "IndicatorProvenance.source_id == SourceRecord.source_id)"
        ),
        foreign_keys="[IndicatorProvenance.source_record_id]",
    )
