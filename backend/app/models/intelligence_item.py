"""SQLAlchemy model for normalized defensive intelligence items."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    desc,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import (
    BigIntPrimaryKeyMixin,
    PublicIdMixin,
    TimestampMixin,
    utc_now,
)


ITEM_TYPE_VALUES = (
    "vulnerability",
    "security_advisory",
    "cyber_news",
    "threat_report",
    "uae_official_alert",
    "other_defensive_intel",
)
STATUS_VALUES = ("active", "superseded", "merged", "archived")
GEOGRAPHIC_SCOPE_VALUES = ("global", "regional", "uae", "unknown")
UAE_RELEVANCE_STATUS_VALUES = (
    "confirmed",
    "probable",
    "possible",
    "not_relevant",
    "unknown",
)
UAE_RELEVANCE_METHOD_VALUES = (
    "automatic",
    "manual",
    "source_declared",
    "unassigned",
)


class IntelligenceItem(
    BigIntPrimaryKeyMixin,
    PublicIdMixin,
    TimestampMixin,
    Base,
):
    """Shared normalized record for defensive intelligence items."""

    __tablename__ = "intelligence_items"
    __table_args__ = (
        CheckConstraint(
            "item_type IN ("
            "'vulnerability', "
            "'security_advisory', "
            "'cyber_news', "
            "'threat_report', "
            "'uae_official_alert', "
            "'other_defensive_intel'"
            ")",
            name="ck_intelligence_items_item_type_allowed",
        ),
        CheckConstraint(
            "status IN ('active', 'superseded', 'merged', 'archived')",
            name="ck_intelligence_items_status_allowed",
        ),
        CheckConstraint(
            "geographic_scope IN ('global', 'regional', 'uae', 'unknown')",
            name="ck_intelligence_items_geographic_scope_allowed",
        ),
        CheckConstraint(
            "uae_relevance_status IN ("
            "'confirmed', "
            "'probable', "
            "'possible', "
            "'not_relevant', "
            "'unknown'"
            ")",
            name="ck_intelligence_items_uae_relevance_status_allowed",
        ),
        CheckConstraint(
            "uae_relevance_method IN ("
            "'automatic', "
            "'manual', "
            "'source_declared', "
            "'unassigned'"
            ")",
            name="ck_intelligence_items_uae_relevance_method_allowed",
        ),
        CheckConstraint(
            "data_confidence IS NULL "
            "OR (data_confidence >= 0 AND data_confidence <= 1)",
            name="ck_intelligence_items_data_confidence_range",
        ),
        CheckConstraint(
            "uae_relevance_confidence IS NULL "
            "OR (uae_relevance_confidence >= 0 AND uae_relevance_confidence <= 1)",
            name="ck_intelligence_items_uae_relevance_confidence_range",
        ),
        CheckConstraint(
            "superseded_by_item_id IS NULL OR superseded_by_item_id <> id",
            name="ck_intelligence_items_superseded_by_not_self",
        ),
        CheckConstraint(
            "merged_into_item_id IS NULL OR merged_into_item_id <> id",
            name="ck_intelligence_items_merged_into_not_self",
        ),
        CheckConstraint(
            "superseded_by_item_id IS NULL OR merged_into_item_id IS NULL",
            name="ck_intelligence_items_single_lifecycle_pointer",
        ),
        CheckConstraint(
            "status <> 'merged' OR merged_into_item_id IS NOT NULL",
            name="ck_intelligence_items_merged_requires_target",
        ),
        CheckConstraint(
            "status <> 'superseded' OR superseded_by_item_id IS NOT NULL",
            name="ck_intelligence_items_superseded_requires_target",
        ),
        Index(
            "ix_intelligence_items_item_type_source_published_at_desc",
            "item_type",
            desc("source_published_at"),
        ),
        Index(
            "ix_intelligence_items_status_source_published_at_desc",
            "status",
            desc("source_published_at"),
        ),
        Index(
            "ix_intel_items_uae_rel_status_published_desc",
            "uae_relevance_status",
            desc("source_published_at"),
        ),
    )

    item_type: Mapped[str] = mapped_column(String(40), nullable=False)
    canonical_title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    canonical_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    source_published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    source_modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    superseded_by_item_id: Mapped[int | None] = mapped_column(
        ForeignKey("intelligence_items.id", ondelete="RESTRICT"),
        nullable=True,
    )
    merged_into_item_id: Mapped[int | None] = mapped_column(
        ForeignKey("intelligence_items.id", ondelete="RESTRICT"),
        nullable=True,
    )
    data_confidence: Mapped[Decimal | None] = mapped_column(
        Numeric(4, 3),
        nullable=True,
    )
    geographic_scope: Mapped[str] = mapped_column(String(40), nullable=False)
    uae_relevance_status: Mapped[str] = mapped_column(String(40), nullable=False)
    uae_relevance_confidence: Mapped[Decimal | None] = mapped_column(
        Numeric(4, 3),
        nullable=True,
    )
    uae_relevance_reason: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )
    uae_relevance_method: Mapped[str] = mapped_column(String(40), nullable=False)
    analyst_review_status: Mapped[str] = mapped_column(String(40), nullable=False)

    superseded_by: Mapped[IntelligenceItem | None] = relationship(
        "IntelligenceItem",
        foreign_keys=lambda: [IntelligenceItem.superseded_by_item_id],
        remote_side=lambda: [IntelligenceItem.id],
    )
    merged_into: Mapped[IntelligenceItem | None] = relationship(
        "IntelligenceItem",
        foreign_keys=lambda: [IntelligenceItem.merged_into_item_id],
        remote_side=lambda: [IntelligenceItem.id],
    )
