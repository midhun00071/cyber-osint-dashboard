"""SQLAlchemy model for append-only actor and service audit evidence."""

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
    String,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, utc_now


if TYPE_CHECKING:
    from app.models.ingestion_cycle import IngestionCycle
    from app.models.ingestion_run import IngestionRun


AUDIT_ACTOR_TYPE_VALUES = ("user", "service", "system")
AUDIT_OUTCOME_VALUES = ("success", "denied", "failed", "no_change")


class AuditEvent(BigIntPrimaryKeyMixin, PublicIdMixin, Base):
    """Immutable bounded evidence for an actor or service action."""

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint(
            "idempotency_key", name="uq_audit_events_idempotency_key"
        ),
        ForeignKeyConstraint(
            ["ingestion_run_id", "cycle_id"],
            ["ingestion_runs.id", "ingestion_runs.cycle_id"],
            name="fk_audit_events_run_cycle",
            ondelete="SET NULL",
        ),
        CheckConstraint(
            "ingestion_run_id IS NULL OR cycle_id IS NOT NULL",
            name="ck_audit_events_run_cycle_consistency",
        ),
        CheckConstraint(
            "actor_type IN ('user', 'service', 'system')",
            name="ck_audit_events_actor_type_allowed",
        ),
        CheckConstraint(
            "action ~ '^[a-z][a-z0-9_.-]{0,79}$'",
            name="ck_audit_events_action_format",
        ),
        CheckConstraint(
            "target_type ~ '^[a-z][a-z0-9_.-]{0,59}$'",
            name="ck_audit_events_target_type_format",
        ),
        CheckConstraint(
            "char_length(btrim(target_ref)) BETWEEN 1 AND 240",
            name="ck_audit_events_target_ref_length",
        ),
        CheckConstraint(
            "outcome IN ('success', 'denied', 'failed', 'no_change')",
            name="ck_audit_events_outcome_allowed",
        ),
        CheckConstraint(
            "created_at >= occurred_at",
            name="ck_audit_events_created_at_order",
        ),
        Index(
            "ix_audit_events_occurred_at_id_desc",
            text("occurred_at DESC"),
            text("id DESC"),
        ),
        Index(
            "ix_audit_events_actor_ref_occurred_at_desc",
            "actor_ref",
            text("occurred_at DESC"),
        ),
        Index(
            "ix_audit_events_action_occurred_at_desc",
            "action",
            text("occurred_at DESC"),
        ),
        Index(
            "ix_audit_events_correlation_id",
            "correlation_id",
            postgresql_where=text("correlation_id IS NOT NULL"),
        ),
    )

    idempotency_key: Mapped[str] = mapped_column(String(240), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(30), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    target_type: Mapped[str] = mapped_column(String(60), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(240), nullable=False)
    outcome: Mapped[str] = mapped_column(String(30), nullable=False)
    cycle_id: Mapped[int | None] = mapped_column(
        ForeignKey("ingestion_cycles.id", ondelete="SET NULL"), nullable=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    safe_detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    cycle: Mapped[IngestionCycle | None] = relationship(
        "IngestionCycle",
        back_populates="audit_events",
        foreign_keys=[cycle_id],
        overlaps="ingestion_run,audit_events",
    )
    ingestion_run: Mapped[IngestionRun | None] = relationship(
        "IngestionRun",
        back_populates="audit_events",
        primaryjoin=(
            "and_(foreign(AuditEvent.ingestion_run_id) == IngestionRun.id, "
            "foreign(AuditEvent.cycle_id) == IngestionRun.cycle_id)"
        ),
        foreign_keys="[AuditEvent.ingestion_run_id, AuditEvent.cycle_id]",
        overlaps="cycle,audit_events",
    )


@event.listens_for(AuditEvent, "before_update", propagate=True)
def _reject_audit_event_update(_mapper, _connection, _target) -> None:
    raise RuntimeError("Audit events are immutable.")


@event.listens_for(AuditEvent, "before_delete", propagate=True)
def _reject_audit_event_delete(_mapper, _connection, _target) -> None:
    raise RuntimeError("Audit events are immutable.")
