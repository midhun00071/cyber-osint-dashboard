"""Reduced, source-scoped STIX threat entity model."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKeyConstraint, Index, Numeric, String, UniqueConstraint, desc
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin

if TYPE_CHECKING:
    from app.models.threat_entity_alias import ThreatEntityAlias
    from app.models.threat_relationship import ThreatRelationship

THREAT_ENTITY_TYPE_VALUES = ("threat_actor", "campaign", "malware_family", "attack_technique")


class ThreatEntity(BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin, Base):
    """A normalized threat identity derived only from source and canonical STIX ID."""

    __tablename__ = "threat_entities"
    __table_args__ = (
        CheckConstraint("entity_type IN ('threat_actor', 'campaign', 'malware_family', 'attack_technique')", name="ck_threat_entities_type_allowed"),
        CheckConstraint("char_length(name) BETWEEN 1 AND 500", name="ck_threat_entities_name_length"),
        CheckConstraint("identity_sha256 ~ '^[0-9a-f]{64}$'", name="ck_threat_entities_identity_format"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_threat_entities_confidence_range"),
        CheckConstraint("stix_modified_at >= stix_created_at", name="ck_threat_entities_stix_time_order"),
        CheckConstraint("(entity_type = 'attack_technique' AND attack_id IS NOT NULL) OR (entity_type <> 'attack_technique' AND attack_id IS NULL)", name="ck_threat_entities_attack_id_consistency"),
        CheckConstraint("attack_id IS NULL OR attack_id ~ '^T[0-9]{4}(\\.[0-9]{3})?$'", name="ck_threat_entities_attack_id_format"),
        ForeignKeyConstraint(["source_id"], ["intelligence_sources.id"], ondelete="RESTRICT"),
        ForeignKeyConstraint(["source_record_id", "source_id"], ["source_records.id", "source_records.source_id"], name="fk_threat_entities_source_record_source", ondelete="RESTRICT"),
        UniqueConstraint("id", "source_id", name="uq_threat_entities_id_source_id"),
        UniqueConstraint("id", "source_id", "source_record_id", name="uq_threat_entities_id_source_record_source"),
        UniqueConstraint("source_id", "stix_id", name="uq_threat_entities_source_stix_id"),
        UniqueConstraint("source_id", "source_record_id", name="uq_threat_entities_source_record"),
        Index("uq_threat_entities_identity_sha256", "identity_sha256", unique=True),
        Index("ix_threat_entities_source_type", "source_id", "entity_type"),
        Index("ix_threat_entities_attack_id", "attack_id"),
        Index("ix_threat_entities_source_revoked", "source_id", "revoked"),
        Index("ix_threat_entities_modified_desc", desc("stix_modified_at")),
    )

    source_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source_record_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False)
    stix_id: Mapped[str] = mapped_column(String(300), nullable=False)
    identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    attack_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    stix_created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    stix_modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False)

    aliases: Mapped[list[ThreatEntityAlias]] = relationship("ThreatEntityAlias", back_populates="entity", cascade="all, delete-orphan", passive_deletes=True)
    outgoing_relationships: Mapped[list[ThreatRelationship]] = relationship("ThreatRelationship", foreign_keys="[ThreatRelationship.source_entity_id]", back_populates="source_entity", passive_deletes=True)
    incoming_relationships: Mapped[list[ThreatRelationship]] = relationship("ThreatRelationship", foreign_keys="[ThreatRelationship.target_entity_id]", back_populates="target_entity", passive_deletes=True)
