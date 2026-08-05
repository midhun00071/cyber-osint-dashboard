"""One exact local role assignment per account."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import utc_now


class AuthUserRole(Base):
    __tablename__ = "auth_user_roles"
    __table_args__ = (
        CheckConstraint("role_key IN ('viewer', 'analyst', 'ingestion_operator', 'administrator')", name="ck_auth_user_roles_role_key_allowed"),
        CheckConstraint("updated_at >= assigned_at", name="ck_auth_user_roles_updated_at_order"),
    )

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("auth_users.id", ondelete="RESTRICT"), primary_key=True)
    role_key: Mapped[str] = mapped_column(String(40), nullable=False)
    assigned_by_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("auth_users.id", ondelete="RESTRICT"), nullable=True)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
