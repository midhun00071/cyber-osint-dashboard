"""Association model for publication mentions of normalized indicators."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import TimestampMixin


if TYPE_CHECKING:
    from app.models.indicator import Indicator
    from app.models.intelligence_item import IntelligenceItem


RELATIONSHIP_TYPE_VALUES = ("mentioned",)
EXTRACTION_METHOD_VALUES = ("deterministic_text",)


class IntelligenceItemIndicator(TimestampMixin, Base):
    """Bounded evidence that a publication mentioned an indicator."""

    __tablename__ = "intelligence_item_indicators"
    __table_args__ = (
        CheckConstraint(
            "relationship_type IN ('mentioned')",
            name="ck_intelligence_item_indicators_relationship_type_allowed",
        ),
        CheckConstraint(
            "extraction_method IN ('deterministic_text')",
            name="ck_intelligence_item_indicators_extraction_method_allowed",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_intelligence_item_indicators_confidence_range",
        ),
        CheckConstraint(
            "last_observed_at >= first_observed_at",
            name="ck_intelligence_item_indicators_observed_at_order",
        ),
        Index(
            "ix_intelligence_item_indicators_indicator_id_item_id",
            "indicator_id",
            "intelligence_item_id",
        ),
    )

    intelligence_item_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_items.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    relationship_type: Mapped[str] = mapped_column(String(40), nullable=False)
    extraction_method: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False)
    context_summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    first_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    intelligence_item: Mapped[IntelligenceItem] = relationship(
        "IntelligenceItem",
        back_populates="indicator_relationships",
    )
    indicator: Mapped[Indicator] = relationship(
        "Indicator",
        back_populates="intelligence_item_relationships",
    )
