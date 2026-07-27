"""SQLAlchemy model for source provenance records."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, TimestampMixin, utc_now


if TYPE_CHECKING:
    from app.models.indicator_provenance import IndicatorProvenance
    from app.models.ingestion_error import IngestionError
    from app.models.ingestion_run_record import IngestionRunRecord
    from app.models.intelligence_item import IntelligenceItem
    from app.models.intelligence_item_identifier import IntelligenceItemIdentifier
    from app.models.intelligence_source import IntelligenceSource


PROCESSING_STATUS_VALUES = ("pending", "processed", "skipped", "failed")
UPSTREAM_STATUS_VALUES = ("present", "missing", "unavailable")


class SourceRecord(BigIntPrimaryKeyMixin, TimestampMixin, Base):
    """Source provenance and bounded source payload metadata."""

    __tablename__ = "source_records"
    __table_args__ = (
        CheckConstraint(
            "processing_status IN ('pending', 'processed', 'skipped', 'failed')",
            name="ck_source_records_processing_status_allowed",
        ),
        CheckConstraint(
            "upstream_status IN ('present', 'missing', 'unavailable')",
            name="ck_source_records_upstream_status_allowed",
        ),
        UniqueConstraint(
            "id",
            "source_id",
            name="uq_source_records_id_source_id",
        ),
        Index(
            "uq_source_records_external_id",
            "source_id",
            "source_external_id",
            unique=True,
            postgresql_where=text("source_external_id IS NOT NULL"),
        ),
        Index(
            "uq_source_records_url_hash",
            "source_id",
            "canonical_url_hash",
            unique=True,
            postgresql_where=text("canonical_url_hash IS NOT NULL"),
        ),
        Index(
            "uq_source_records_primary_ref_per_item",
            "intelligence_item_id",
            unique=True,
            postgresql_where=text(
                "is_primary_reference IS TRUE AND intelligence_item_id IS NOT NULL"
            ),
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id", ondelete="RESTRICT"),
        nullable=False,
    )
    intelligence_item_id: Mapped[int | None] = mapped_column(
        ForeignKey("intelligence_items.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_external_id: Mapped[str | None] = mapped_column(String(300), nullable=True)
    source_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    canonical_url_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_primary_reference: Mapped[bool] = mapped_column(Boolean, nullable=False)
    raw_payload: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    payload_collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    source_published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    source_modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    processing_status: Mapped[str] = mapped_column(String(40), nullable=False)
    last_processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    safe_error_summary: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    upstream_status: Mapped[str] = mapped_column(String(40), nullable=False)

    source: Mapped[IntelligenceSource] = relationship(
        "IntelligenceSource",
        back_populates="source_records",
    )
    intelligence_item: Mapped[IntelligenceItem | None] = relationship(
        "IntelligenceItem",
        back_populates="source_records",
    )
    identifiers: Mapped[list[IntelligenceItemIdentifier]] = relationship(
        "IntelligenceItemIdentifier",
        back_populates="source_record",
        passive_deletes=True,
    )
    ingestion_run_records: Mapped[list[IngestionRunRecord]] = relationship(
        "IngestionRunRecord",
        back_populates="source_record",
        passive_deletes=True,
    )
    ingestion_errors: Mapped[list[IngestionError]] = relationship(
        "IngestionError",
        back_populates="source_record",
        passive_deletes=True,
    )
    indicator_provenances: Mapped[list[IndicatorProvenance]] = relationship(
        "IndicatorProvenance",
        back_populates="source_record",
        primaryjoin=(
            "and_(SourceRecord.id == foreign(IndicatorProvenance.source_record_id), "
            "SourceRecord.source_id == IndicatorProvenance.source_id)"
        ),
        foreign_keys="[IndicatorProvenance.source_record_id]",
        passive_deletes=True,
    )
