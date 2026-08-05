"""Local account records; identities and credentials are stored separately."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin


class AuthUser(BigIntPrimaryKeyMixin, PublicIdMixin, TimestampMixin, Base):
    """A non-deletable application account with account-wide session versioning."""

    __tablename__ = "auth_users"
    __table_args__ = (
        CheckConstraint("char_length(btrim(display_name)) BETWEEN 1 AND 160", name="ck_auth_users_display_name_length"),
        CheckConstraint("status IN ('active', 'disabled')", name="ck_auth_users_status_allowed"),
        CheckConstraint("(status = 'active' AND disabled_at IS NULL) OR (status = 'disabled' AND disabled_at IS NOT NULL)", name="ck_auth_users_status_disabled_at_consistency"),
        CheckConstraint("session_version > 0", name="ck_auth_users_session_version_positive"),
        CheckConstraint("updated_at >= created_at", name="ck_auth_users_updated_at_order"),
        CheckConstraint("account_expires_at IS NULL OR account_expires_at > created_at", name="ck_auth_users_account_expiry_order"),
    )

    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    account_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    session_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    last_authenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
