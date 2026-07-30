"""SQLAlchemy model for approved intelligence source registry rows."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin


if TYPE_CHECKING:
    from app.models.indicator_provenance import IndicatorProvenance
    from app.models.ingestion_run import IngestionRun
    from app.models.intelligence_item_identifier import IntelligenceItemIdentifier
    from app.models.source_record import SourceRecord
    from app.models.quarantined_record import QuarantinedRecord
    from app.models.source_checkpoint import SourceCheckpoint
    from app.models.source_credential_reference import SourceCredentialReference
    from app.models.source_rate_limit_state import SourceRateLimitState
    from app.models.source_watermark import SourceWatermark


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
        foreign_keys="[IngestionRun.source_id]",
        passive_deletes=True,
        overlaps=(
            "advanced_by_run,advanced_checkpoints,advanced_watermarks,"
            "updated_by_run,updated_rate_limit_states,quarantined_records"
        ),
    )
    indicator_provenances: Mapped[list[IndicatorProvenance]] = relationship(
        "IndicatorProvenance",
        back_populates="source",
        passive_deletes=True,
    )
    source_checkpoints: Mapped[list[SourceCheckpoint]] = relationship(
        "SourceCheckpoint",
        back_populates="source",
        foreign_keys="[SourceCheckpoint.source_id]",
        passive_deletes=True,
        overlaps="advanced_by_run,advanced_checkpoints,previous_checkpoint,next_checkpoint",
    )
    source_watermarks: Mapped[list[SourceWatermark]] = relationship(
        "SourceWatermark",
        back_populates="source",
        foreign_keys="[SourceWatermark.source_id]",
        passive_deletes=True,
        overlaps="advanced_by_run,advanced_watermarks,previous_watermark,next_watermark",
    )
    source_rate_limit_states: Mapped[list[SourceRateLimitState]] = relationship(
        "SourceRateLimitState",
        back_populates="source",
        foreign_keys="[SourceRateLimitState.source_id]",
        passive_deletes=True,
        overlaps="updated_by_run,updated_rate_limit_states",
    )
    quarantined_records: Mapped[list[QuarantinedRecord]] = relationship(
        "QuarantinedRecord",
        back_populates="source",
        foreign_keys="[QuarantinedRecord.source_id]",
        passive_deletes=True,
        overlaps="ingestion_run,quarantined_records",
    )
    credential_references: Mapped[list[SourceCredentialReference]] = relationship(
        "SourceCredentialReference",
        back_populates="source",
        passive_deletes=True,
    )
