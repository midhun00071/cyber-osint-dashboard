"""SQLAlchemy model for intelligence item tags."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, utc_now


if TYPE_CHECKING:
    from app.models.intelligence_item_tag import IntelligenceItemTag


TAG_TYPE_VALUES = (
    "general",
    "vendor",
    "product",
    "sector",
    "region",
    "technique",
    "theme",
)


class Tag(BigIntPrimaryKeyMixin, Base):
    """Flexible label for intelligence item filtering and grouping."""

    __tablename__ = "tags"
    __table_args__ = (
        CheckConstraint(
            "tag_type IN ("
            "'general', "
            "'vendor', "
            "'product', "
            "'sector', "
            "'region', "
            "'technique', "
            "'theme'"
            ")",
            name="ck_tags_tag_type_allowed",
        ),
    )

    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    tag_type: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    item_assignments: Mapped[list[IntelligenceItemTag]] = relationship(
        "IntelligenceItemTag",
        back_populates="tag",
        passive_deletes=True,
    )
