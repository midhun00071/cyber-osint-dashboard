"""Approved source-scoped STIX threat relationships."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKeyConstraint, Index, Numeric, String, UniqueConstraint, desc
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin

if TYPE_CHECKING:
    from app.models.threat_entity import ThreatEntity


class ThreatRelationship(BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin, Base):
    __tablename__ = "threat_relationships"
    __table_args__ = (
        CheckConstraint("relationship_type IN ('uses', 'attributed-to')", name="ck_threat_relationships_type_allowed"),
        CheckConstraint("identity_sha256 ~ '^[0-9a-f]{64}$'", name="ck_threat_relationships_identity_format"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_threat_relationships_confidence_range"),
        CheckConstraint("stix_modified_at >= stix_created_at", name="ck_threat_relationships_stix_time_order"),
        CheckConstraint("stop_time IS NULL OR start_time IS NULL OR stop_time >= start_time", name="ck_threat_relationships_active_time_order"),
        CheckConstraint("source_entity_id <> target_entity_id", name="ck_threat_relationships_not_self"),
        ForeignKeyConstraint(["source_id"], ["intelligence_sources.id"], ondelete="RESTRICT"),
        ForeignKeyConstraint(["source_record_id", "source_id"], ["source_records.id", "source_records.source_id"], name="fk_threat_relationships_source_record_source", ondelete="RESTRICT"),
        ForeignKeyConstraint(["source_entity_id", "source_id"], ["threat_entities.id", "threat_entities.source_id"], name="fk_threat_relationships_source_entity_source", ondelete="RESTRICT"),
        ForeignKeyConstraint(["target_entity_id", "source_id"], ["threat_entities.id", "threat_entities.source_id"], name="fk_threat_relationships_target_entity_source", ondelete="RESTRICT"),
        UniqueConstraint("source_id", "stix_id", name="uq_threat_relationships_source_stix_id"),
        UniqueConstraint("source_id", "source_record_id", name="uq_threat_relationships_source_record"),
        Index("uq_threat_relationships_identity_sha256", "identity_sha256", unique=True),
        Index("ix_threat_relationships_source_type", "source_id", "relationship_type"),
        Index("ix_threat_relationships_source_revoked", "source_id", "revoked"),
        Index("ix_threat_relationships_source_endpoint", "source_id", "source_entity_id"),
        Index("ix_threat_relationships_target_endpoint", "source_id", "target_entity_id"),
        Index("ix_threat_relationships_modified_desc", desc("stix_modified_at")),
    )

    source_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source_record_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source_entity_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    target_entity_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(40), nullable=False)
    stix_id: Mapped[str] = mapped_column(String(300), nullable=False)
    identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    stix_created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    stix_modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stop_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False)

    source_entity: Mapped[ThreatEntity] = relationship("ThreatEntity", foreign_keys=[source_entity_id], back_populates="outgoing_relationships")
    target_entity: Mapped[ThreatEntity] = relationship("ThreatEntity", foreign_keys=[target_entity_id], back_populates="incoming_relationships")
