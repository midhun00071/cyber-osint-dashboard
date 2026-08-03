"""Bounded aliases for source-scoped threat entities."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, CheckConstraint, ForeignKeyConstraint, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, TimestampMixin

if TYPE_CHECKING:
    from app.models.threat_entity import ThreatEntity


class ThreatEntityAlias(BigIntPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "threat_entity_aliases"
    __table_args__ = (
        CheckConstraint("char_length(display_value) BETWEEN 1 AND 500", name="ck_threat_entity_aliases_display_length"),
        CheckConstraint("char_length(normalized_value) BETWEEN 1 AND 500", name="ck_threat_entity_aliases_normalized_length"),
        ForeignKeyConstraint(["threat_entity_id", "source_id", "source_record_id"], ["threat_entities.id", "threat_entities.source_id", "threat_entities.source_record_id"], name="fk_threat_entity_aliases_entity_provenance", ondelete="CASCADE"),
        ForeignKeyConstraint(["source_record_id", "source_id"], ["source_records.id", "source_records.source_id"], name="fk_threat_entity_aliases_source_record_source", ondelete="RESTRICT"),
        UniqueConstraint("threat_entity_id", "normalized_value", name="uq_threat_entity_aliases_entity_identity"),
        Index("ix_threat_entity_aliases_source", "source_id"),
    )

    threat_entity_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source_record_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    display_value: Mapped[str] = mapped_column(String(500), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(500), nullable=False)

    entity: Mapped[ThreatEntity] = relationship("ThreatEntity", back_populates="aliases", foreign_keys=[threat_entity_id, source_id, source_record_id])
