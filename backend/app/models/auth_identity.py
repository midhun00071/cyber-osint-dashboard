"""Replaceable identity subjects and local Argon2id credentials."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, utc_now


class AuthIdentity(BigIntPrimaryKeyMixin, Base):
    __tablename__ = "auth_identities"
    __table_args__ = (
        UniqueConstraint("provider_key", "subject_key", name="uq_auth_identities_provider_subject"),
        UniqueConstraint("user_id", "provider_key", name="uq_auth_identities_user_provider"),
        CheckConstraint("provider_key ~ '^[a-z][a-z0-9_]{0,39}$'", name="ck_auth_identities_provider_key_format"),
        CheckConstraint("char_length(btrim(subject_key)) BETWEEN 1 AND 80", name="ck_auth_identities_subject_key_length"),
    )

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("auth_users.id", ondelete="RESTRICT"), nullable=False)
    provider_key: Mapped[str] = mapped_column(String(40), nullable=False)
    subject_key: Mapped[str] = mapped_column(String(80), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AuthLocalCredential(Base):
    __tablename__ = "auth_local_credentials"
    __table_args__ = (
        CheckConstraint("password_hash LIKE '$argon2id$%'", name="ck_auth_local_credentials_argon2id_prefix"),
        CheckConstraint("updated_at >= created_at", name="ck_auth_local_credentials_updated_at_order"),
    )

    identity_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("auth_identities.id", ondelete="RESTRICT"), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
