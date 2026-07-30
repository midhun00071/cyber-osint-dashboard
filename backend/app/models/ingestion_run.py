"""SQLAlchemy model for source ingestion run metadata."""

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
    SmallInteger,
    String,
    UniqueConstraint,
    desc,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, utc_now


if TYPE_CHECKING:
    from app.models.audit_event import AuditEvent
    from app.models.ingestion_error import IngestionError
    from app.models.ingestion_cycle import IngestionCycle
    from app.models.ingestion_run_event import IngestionRunEvent
    from app.models.ingestion_run_record import IngestionRunRecord
    from app.models.intelligence_source import IntelligenceSource
    from app.models.quarantined_record import QuarantinedRecord
    from app.models.source_checkpoint import SourceCheckpoint
    from app.models.source_rate_limit_state import SourceRateLimitState
    from app.models.source_watermark import SourceWatermark


TRIGGER_TYPE_VALUES = ("scheduled", "manual", "retry")
INGESTION_RUN_TARGET_STATUS_VALUES = (
    "running",
    "checkpoint_pending",
    "success",
    "no_change",
    "skipped",
    "deferred_quota",
    "approval_pending",
    "disabled",
    "credentials_missing",
    "licence_required",
    "rate_limited",
    "partial",
    "failed",
    "cancelled",
)
INGESTION_RUN_COMPATIBILITY_STATUS_VALUES = (
    "running",
    "succeeded",
    "partial",
    "failed",
    "canceled",
)
INGESTION_RUN_STATUS_VALUES = (
    *INGESTION_RUN_TARGET_STATUS_VALUES,
    "succeeded",
    "canceled",
)


class IngestionRun(BigIntPrimaryKeyMixin, PublicIdMixin, Base):
    """Operational metadata for one bounded source ingestion attempt."""

    __tablename__ = "ingestion_runs"
    __table_args__ = (
        CheckConstraint(
            "trigger_type IN ('scheduled', 'manual', 'retry')",
            name="ck_ingestion_runs_trigger_type_allowed",
        ),
        CheckConstraint(
            "status IN ('running', 'checkpoint_pending', 'success', 'no_change', "
            "'skipped', 'deferred_quota', 'approval_pending', 'disabled', "
            "'credentials_missing', 'licence_required', 'rate_limited', "
            "'partial', 'failed', 'cancelled', 'succeeded', 'canceled')",
            name="ck_ingestion_runs_status_allowed",
        ),
        CheckConstraint(
            "completed_at IS NULL OR completed_at >= started_at",
            name="ck_ingestion_runs_completed_at_order",
        ),
        CheckConstraint(
            "records_fetched >= 0 "
            "AND records_created >= 0 "
            "AND records_updated >= 0 "
            "AND records_unchanged >= 0 "
            "AND records_skipped >= 0 "
            "AND records_failed >= 0 "
            "AND error_count >= 0",
            name="ck_ingestion_runs_counters_non_negative",
        ),
        CheckConstraint(
            "attempt_number IS NULL OR attempt_number BETWEEN 0 AND 10",
            name="ck_ingestion_runs_attempt_number_bounded",
        ),
        CheckConstraint(
            "(attempt_number IS NULL AND retry_of_run_id IS NULL) OR "
            "(attempt_number = 0 AND retry_of_run_id IS NULL) OR "
            "(attempt_number BETWEEN 1 AND 10 AND retry_of_run_id IS NOT NULL)",
            name="ck_ingestion_runs_retry_lineage_consistency",
        ),
        CheckConstraint(
            "(cycle_id IS NOT NULL AND idempotency_key IS NOT NULL "
            "AND attempt_number IS NOT NULL AND state_version IS NOT NULL "
            "AND status IN ('running', 'checkpoint_pending', 'success', "
            "'no_change', 'skipped', 'deferred_quota', 'approval_pending', "
            "'disabled', 'credentials_missing', 'licence_required', "
            "'rate_limited', 'partial', 'failed', 'cancelled')) OR "
            "(cycle_id IS NULL AND idempotency_key IS NULL "
            "AND attempt_number IS NULL AND retry_of_run_id IS NULL "
            "AND state_version IS NULL AND defer_reason IS NULL "
            "AND status IN ('running', 'succeeded', 'partial', 'failed', "
            "'canceled'))",
            name="ck_ingestion_runs_operational_or_compatibility_shape",
        ),
        CheckConstraint(
            "(status IN ('running', 'checkpoint_pending') AND completed_at IS NULL) "
            "OR (status IN ('success', 'no_change', 'skipped', 'deferred_quota', "
            "'approval_pending', 'disabled', 'credentials_missing', "
            "'licence_required', 'rate_limited', 'partial', 'failed', 'cancelled', "
            "'succeeded', 'canceled') "
            "AND completed_at IS NOT NULL AND completed_at >= started_at)",
            name="ck_ingestion_runs_status_time_consistency",
        ),
        CheckConstraint(
            "state_version IS NULL OR state_version > 0",
            name="ck_ingestion_runs_state_version_positive",
        ),
        UniqueConstraint(
            "idempotency_key", name="uq_ingestion_runs_idempotency_key"
        ),
        UniqueConstraint(
            "source_id",
            "cycle_id",
            "attempt_number",
            name="uq_ingestion_runs_source_cycle_attempt",
        ),
        UniqueConstraint(
            "id", "source_id", name="uq_ingestion_runs_id_source_id"
        ),
        UniqueConstraint("id", "cycle_id", name="uq_ingestion_runs_id_cycle_id"),
        ForeignKeyConstraint(
            ["retry_of_run_id", "source_id"],
            ["ingestion_runs.id", "ingestion_runs.source_id"],
            name="fk_ingestion_runs_retry_source",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["retry_of_run_id", "cycle_id"],
            ["ingestion_runs.id", "ingestion_runs.cycle_id"],
            name="fk_ingestion_runs_retry_cycle",
            ondelete="RESTRICT",
        ),
        Index(
            "ix_ingestion_runs_source_id_started_at_desc",
            "source_id",
            desc("started_at"),
        ),
        Index(
            "ix_ingestion_runs_status_started_at_desc",
            "status",
            desc("started_at"),
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id", ondelete="RESTRICT"),
        nullable=False,
    )
    cycle_id: Mapped[int | None] = mapped_column(
        ForeignKey("ingestion_cycles.id", ondelete="RESTRICT"),
        nullable=True,
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(240), nullable=True)
    attempt_number: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    retry_of_run_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    state_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    defer_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    trigger_type: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    records_fetched: Mapped[int] = mapped_column(Integer, nullable=False)
    records_created: Mapped[int] = mapped_column(Integer, nullable=False)
    records_updated: Mapped[int] = mapped_column(Integer, nullable=False)
    records_unchanged: Mapped[int] = mapped_column(Integer, nullable=False)
    records_skipped: Mapped[int] = mapped_column(Integer, nullable=False)
    records_failed: Mapped[int] = mapped_column(Integer, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False)
    checkpoint_before: Mapped[str | None] = mapped_column(String(500), nullable=True)
    checkpoint_after: Mapped[str | None] = mapped_column(String(500), nullable=True)
    safe_summary: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    source: Mapped[IntelligenceSource] = relationship(
        "IntelligenceSource",
        back_populates="ingestion_runs",
        foreign_keys=[source_id],
        overlaps=(
            "advanced_by_run,advanced_checkpoints,advanced_watermarks,"
            "updated_by_run,updated_rate_limit_states,quarantined_records"
        ),
    )
    cycle: Mapped[IngestionCycle | None] = relationship(
        "IngestionCycle",
        back_populates="ingestion_runs",
        foreign_keys=[cycle_id],
        overlaps="audit_events,ingestion_run",
    )
    retry_of_run: Mapped[IngestionRun | None] = relationship(
        "IngestionRun",
        primaryjoin="foreign(IngestionRun.retry_of_run_id) == remote(IngestionRun.id)",
        foreign_keys=[retry_of_run_id],
        remote_side="IngestionRun.id",
        back_populates="retry_attempts",
        overlaps="source,cycle,ingestion_runs",
    )
    retry_attempts: Mapped[list[IngestionRun]] = relationship(
        "IngestionRun",
        primaryjoin="IngestionRun.id == foreign(IngestionRun.retry_of_run_id)",
        foreign_keys="[IngestionRun.retry_of_run_id]",
        back_populates="retry_of_run",
        passive_deletes=True,
        overlaps="source,cycle,ingestion_runs",
    )
    records: Mapped[list[IngestionRunRecord]] = relationship(
        "IngestionRunRecord",
        back_populates="ingestion_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    errors: Mapped[list[IngestionError]] = relationship(
        "IngestionError",
        back_populates="ingestion_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    events: Mapped[list[IngestionRunEvent]] = relationship(
        "IngestionRunEvent",
        back_populates="ingestion_run",
        cascade="save-update, merge",
        passive_deletes=True,
    )
    advanced_checkpoints: Mapped[list[SourceCheckpoint]] = relationship(
        "SourceCheckpoint",
        back_populates="advanced_by_run",
        primaryjoin=(
            "and_(IngestionRun.id == foreign(SourceCheckpoint.advanced_by_run_id), "
            "IngestionRun.source_id == SourceCheckpoint.source_id)"
        ),
        foreign_keys=(
            "[SourceCheckpoint.advanced_by_run_id, SourceCheckpoint.source_id]"
        ),
        passive_deletes=True,
        overlaps="source,source_checkpoints",
    )
    advanced_watermarks: Mapped[list[SourceWatermark]] = relationship(
        "SourceWatermark",
        back_populates="advanced_by_run",
        primaryjoin=(
            "and_(IngestionRun.id == foreign(SourceWatermark.advanced_by_run_id), "
            "IngestionRun.source_id == SourceWatermark.source_id)"
        ),
        foreign_keys=(
            "[SourceWatermark.advanced_by_run_id, SourceWatermark.source_id]"
        ),
        passive_deletes=True,
        overlaps="source,source_watermarks",
    )
    updated_rate_limit_states: Mapped[list[SourceRateLimitState]] = relationship(
        "SourceRateLimitState",
        back_populates="updated_by_run",
        primaryjoin=(
            "and_(IngestionRun.id == "
            "foreign(SourceRateLimitState.updated_by_run_id), "
            "IngestionRun.source_id == SourceRateLimitState.source_id)"
        ),
        foreign_keys=(
            "[SourceRateLimitState.updated_by_run_id, "
            "SourceRateLimitState.source_id]"
        ),
        passive_deletes=True,
        overlaps="source,source_rate_limit_states",
    )
    quarantined_records: Mapped[list[QuarantinedRecord]] = relationship(
        "QuarantinedRecord",
        back_populates="ingestion_run",
        primaryjoin=(
            "and_(IngestionRun.id == foreign(QuarantinedRecord.ingestion_run_id), "
            "IngestionRun.source_id == QuarantinedRecord.source_id)"
        ),
        foreign_keys=(
            "[QuarantinedRecord.ingestion_run_id, QuarantinedRecord.source_id]"
        ),
        passive_deletes=True,
        overlaps="source,quarantined_records,ingestion_run_event",
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
        "AuditEvent",
        back_populates="ingestion_run",
        primaryjoin=(
            "and_(IngestionRun.id == foreign(AuditEvent.ingestion_run_id), "
            "IngestionRun.cycle_id == foreign(AuditEvent.cycle_id))"
        ),
        foreign_keys="[AuditEvent.ingestion_run_id, AuditEvent.cycle_id]",
        passive_deletes=True,
        overlaps="cycle,audit_events",
    )
