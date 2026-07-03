"""SQLAlchemy association model for intelligence item tag assignments."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import utc_now


if TYPE_CHECKING:
    from app.models.intelligence_item import IntelligenceItem
    from app.models.tag import Tag


ASSIGNED_BY_VALUES = ("system", "analyst", "source")


class IntelligenceItemTag(Base):
    """Association object linking intelligence items to tags with metadata."""

    __tablename__ = "intelligence_item_tags"
    __table_args__ = (
        CheckConstraint(
            "assigned_by IN ('system', 'analyst', 'source')",
            name="ck_intelligence_item_tags_assigned_by_allowed",
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_intelligence_item_tags_confidence_range",
        ),
        Index(
            "ix_intelligence_item_tags_tag_id_item_id",
            "tag_id",
            "intelligence_item_id",
        ),
    )

    intelligence_item_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_items.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    tag_id: Mapped[int] = mapped_column(
        ForeignKey("tags.id", ondelete="RESTRICT"),
        primary_key=True,
        nullable=False,
    )
    assigned_by: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    intelligence_item: Mapped[IntelligenceItem] = relationship(
        "IntelligenceItem",
        back_populates="tag_assignments",
    )
    tag: Mapped[Tag] = relationship(
        "Tag",
        back_populates="item_assignments",
    )
