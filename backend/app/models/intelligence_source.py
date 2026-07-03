"""SQLAlchemy model for approved intelligence source registry rows."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin


if TYPE_CHECKING:
    from app.models.ingestion_run import IngestionRun
    from app.models.intelligence_item_identifier import IntelligenceItemIdentifier
    from app.models.source_record import SourceRecord


SOURCE_TYPE_VALUES = ("api", "rss", "csv", "json")


class IntelligenceSource(
    BigIntPrimaryKeyMixin,
    PublicIdMixin,
    TimestampMixin,
    Base,
):
    """Approved public intelligence source and safe fetch state."""

    __tablename__ = "intelligence_sources"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('api', 'rss', 'csv', 'json')",
            name="ck_intelligence_sources_source_type_allowed",
        ),
    )

    name: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    rate_limit_notes: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_successful_fetch_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    checkpoint_value: Mapped[str | None] = mapped_column(String(500), nullable=True)

    identifiers: Mapped[list[IntelligenceItemIdentifier]] = relationship(
        "IntelligenceItemIdentifier",
        back_populates="source",
        passive_deletes=True,
    )
    source_records: Mapped[list[SourceRecord]] = relationship(
        "SourceRecord",
        back_populates="source",
        passive_deletes=True,
    )
    ingestion_runs: Mapped[list[IngestionRun]] = relationship(
        "IngestionRun",
        back_populates="source",
        passive_deletes=True,
    )
