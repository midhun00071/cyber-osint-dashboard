"""SQLAlchemy model for current source rate and quota state."""

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
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, utc_now


if TYPE_CHECKING:
    from app.models.ingestion_run import IngestionRun
    from app.models.intelligence_source import IntelligenceSource


SOURCE_RATE_LIMIT_STATE_VALUES = (
    "available",
    "limited",
    "backoff",
    "quota_unavailable",
    "unknown",
)


class SourceRateLimitState(BigIntPrimaryKeyMixin, Base):
    """Provider-neutral current quota, rate-limit, and backoff metadata."""

    __tablename__ = "source_rate_limit_states"
    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "policy_key",
            name="uq_source_rate_limit_states_source_policy",
        ),
        ForeignKeyConstraint(
            ["updated_by_run_id", "source_id"],
            ["ingestion_runs.id", "ingestion_runs.source_id"],
            name="fk_source_rate_limit_states_run_source",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(request_limit IS NULL OR request_limit >= 0) "
            "AND (remaining IS NULL OR remaining >= 0) "
            "AND (request_limit IS NULL OR remaining IS NULL "
            "OR remaining <= request_limit)",
            name="ck_source_rate_limit_states_counts_valid",
        ),
        CheckConstraint(
            "window_seconds IS NULL OR window_seconds BETWEEN 1 AND 31536000",
            name="ck_source_rate_limit_states_window_bounded",
        ),
        CheckConstraint(
            "state_version > 0",
            name="ck_source_rate_limit_states_version_positive",
        ),
        CheckConstraint(
            "state IN ('available', 'limited', 'backoff', "
            "'quota_unavailable', 'unknown')",
            name="ck_source_rate_limit_states_state_allowed",
        ),
        Index(
            "ix_source_rate_limit_states_non_available_backoff",
            "state",
            "backoff_until",
            postgresql_where=text("state <> 'available'"),
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id", ondelete="RESTRICT"), nullable=False
    )
    policy_key: Mapped[str] = mapped_column(String(80), nullable=False)
    request_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)
    window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reset_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    backoff_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    state_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    updated_by_run_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    source: Mapped[IntelligenceSource] = relationship(
        "IntelligenceSource",
        back_populates="source_rate_limit_states",
        foreign_keys=[source_id],
        overlaps="updated_by_run,updated_rate_limit_states",
    )
    updated_by_run: Mapped[IngestionRun | None] = relationship(
        "IngestionRun",
        back_populates="updated_rate_limit_states",
        primaryjoin=(
            "and_(foreign(SourceRateLimitState.updated_by_run_id) == IngestionRun.id, "
            "SourceRateLimitState.source_id == IngestionRun.source_id)"
        ),
        foreign_keys=(
            "[SourceRateLimitState.updated_by_run_id, "
            "SourceRateLimitState.source_id]"
        ),
        overlaps="source,source_rate_limit_states",
    )
