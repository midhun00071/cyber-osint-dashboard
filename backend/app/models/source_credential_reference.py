"""SQLAlchemy model for provider-neutral non-secret credential references."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, utc_now


if TYPE_CHECKING:
    from app.models.intelligence_source import IntelligenceSource


CREDENTIAL_CONFIGURATION_STATE_VALUES = (
    "not_configured",
    "configured",
    "disabled",
    "rotation_due",
    "revoked",
)


class SourceCredentialReference(BigIntPrimaryKeyMixin, Base):
    """Non-secret provider-neutral credential-reference metadata."""

    __tablename__ = "source_credential_references"
    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "reference_name",
            "purpose",
            name="uq_source_credential_references_source_name_purpose",
        ),
        CheckConstraint(
            "configuration_state IN ('not_configured', 'configured', 'disabled', "
            "'rotation_due', 'revoked')",
            name="ck_source_credential_references_state_allowed",
        ),
        CheckConstraint(
            "(configuration_state IN ('configured', 'rotation_due') "
            "AND external_reference_id IS NOT NULL "
            "AND char_length(btrim(external_reference_id)) BETWEEN 1 AND 240) OR "
            "(configuration_state = 'not_configured' "
            "AND external_reference_id IS NULL) OR "
            "(configuration_state IN ('disabled', 'revoked') "
            "AND (external_reference_id IS NULL OR "
            "char_length(btrim(external_reference_id)) BETWEEN 1 AND 240))",
            name="ck_source_credential_references_configured_shape",
        ),
        CheckConstraint(
            "expires_at IS NULL OR last_rotated_at IS NULL "
            "OR expires_at >= last_rotated_at",
            name="ck_source_credential_references_rotation_expiry_order",
        ),
        CheckConstraint(
            "updated_at >= created_at",
            name="ck_source_credential_references_updated_at_order",
        ),
        Index(
            "ix_source_credential_references_state_source_id",
            "configuration_state",
            "source_id",
        ),
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id", ondelete="RESTRICT"), nullable=False
    )
    reference_name: Mapped[str] = mapped_column(String(80), nullable=False)
    purpose: Mapped[str] = mapped_column(String(60), nullable=False)
    external_reference_id: Mapped[str | None] = mapped_column(
        String(240), nullable=True
    )
    configuration_state: Mapped[str] = mapped_column(String(30), nullable=False)
    owner_ref: Mapped[str | None] = mapped_column(String(160), nullable=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    source: Mapped[IntelligenceSource] = relationship(
        "IntelligenceSource", back_populates="credential_references"
    )
