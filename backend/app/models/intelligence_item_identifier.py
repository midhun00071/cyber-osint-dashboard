"""SQLAlchemy model for external intelligence item identifiers."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, utc_now


if TYPE_CHECKING:
    from app.models.intelligence_item import IntelligenceItem
    from app.models.intelligence_source import IntelligenceSource
    from app.models.source_record import SourceRecord


class IntelligenceItemIdentifier(BigIntPrimaryKeyMixin, Base):
    """External identifier owned by a normalized intelligence item."""

    __tablename__ = "intelligence_item_identifiers"
    __table_args__ = (
        Index(
            "uq_item_identifiers_global_lookup",
            "namespace",
            "normalized_value",
            unique=True,
            postgresql_where=text("source_id IS NULL"),
        ),
        Index(
            "uq_item_identifiers_source_lookup",
            "source_id",
            "namespace",
            "normalized_value",
            unique=True,
            postgresql_where=text("source_id IS NOT NULL"),
        ),
        Index(
            "uq_item_identifiers_primary_per_item",
            "intelligence_item_id",
            unique=True,
            postgresql_where=text("is_primary IS TRUE"),
        ),
    )

    intelligence_item_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_items.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_id: Mapped[int | None] = mapped_column(
        ForeignKey("intelligence_sources.id", ondelete="RESTRICT"),
        nullable=True,
    )
    source_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("source_records.id", ondelete="SET NULL"),
        nullable=True,
    )
    namespace: Mapped[str] = mapped_column(String(40), nullable=False)
    identifier_value: Mapped[str] = mapped_column(String(300), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(300), nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    intelligence_item: Mapped[IntelligenceItem] = relationship(
        "IntelligenceItem",
        back_populates="identifiers",
    )
    source: Mapped[IntelligenceSource | None] = relationship(
        "IntelligenceSource",
        back_populates="identifiers",
    )
    source_record: Mapped[SourceRecord | None] = relationship(
        "SourceRecord",
        back_populates="identifiers",
    )
