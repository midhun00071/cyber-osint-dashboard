"""SQLAlchemy model for normalized defensive indicators."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, Index, Numeric, String, desc
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin


if TYPE_CHECKING:
    from app.models.indicator_provenance import IndicatorProvenance
    from app.models.intelligence_item_indicator import IntelligenceItemIndicator


OBSERVABLE_TYPE_VALUES = ("ipv4", "ipv6", "domain", "url", "file_hash")
HASH_ALGORITHM_VALUES = ("md5", "sha1", "sha256", "sha512")
INDICATOR_STATUS_VALUES = (
    "active",
    "inactive",
    "revoked",
    "false_positive",
    "archived",
)


class Indicator(BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin, Base):
    """Canonical metadata-only identity for a defensive observable."""

    __tablename__ = "indicators"
    __table_args__ = (
        CheckConstraint(
            "observable_type IN ('ipv4', 'ipv6', 'domain', 'url', 'file_hash')",
            name="ck_indicators_observable_type_allowed",
        ),
        CheckConstraint(
            "hash_algorithm IS NULL OR "
            "hash_algorithm IN ('md5', 'sha1', 'sha256', 'sha512')",
            name="ck_indicators_hash_algorithm_allowed",
        ),
        CheckConstraint(
            "(observable_type = 'file_hash' AND hash_algorithm IS NOT NULL) OR "
            "(observable_type <> 'file_hash' AND hash_algorithm IS NULL)",
            name="ck_indicators_hash_algorithm_consistency",
        ),
        CheckConstraint(
            "char_length(normalized_value) BETWEEN 1 AND 2048",
            name="ck_indicators_normalized_value_length",
        ),
        CheckConstraint(
            "identity_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_indicators_identity_sha256_format",
        ),
        CheckConstraint(
            "status IN ('active', 'inactive', 'revoked', 'false_positive', 'archived')",
            name="ck_indicators_status_allowed",
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_indicators_confidence_range",
        ),
        CheckConstraint(
            "last_seen_at IS NULL OR first_seen_at IS NULL OR "
            "last_seen_at >= first_seen_at",
            name="ck_indicators_seen_at_order",
        ),
        CheckConstraint(
            "expires_at IS NULL OR first_seen_at IS NULL OR "
            "expires_at >= first_seen_at",
            name="ck_indicators_expires_at_order",
        ),
        CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL) OR "
            "(status <> 'revoked' AND revoked_at IS NULL)",
            name="ck_indicators_revoked_at_consistency",
        ),
        Index("uq_indicators_identity_sha256", "identity_sha256", unique=True),
        Index("ix_indicators_observable_type_status", "observable_type", "status"),
        Index(
            "ix_indicators_status_last_seen_at_desc",
            "status",
            desc("last_seen_at"),
        ),
    )

    observable_type: Mapped[str] = mapped_column(String(20), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    hash_algorithm: Mapped[str | None] = mapped_column(String(20), nullable=True)
    identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    context_summary: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    provenances: Mapped[list[IndicatorProvenance]] = relationship(
        "IndicatorProvenance",
        back_populates="indicator",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    intelligence_item_relationships: Mapped[
        list[IntelligenceItemIndicator]
    ] = relationship(
        "IntelligenceItemIndicator",
        back_populates="indicator",
        passive_deletes=True,
    )
