"""Opaque session hashes and privacy-preserving failed-login state."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import BigIntPrimaryKeyMixin, PublicIdMixin, utc_now


class AuthSession(BigIntPrimaryKeyMixin, PublicIdMixin, Base):
    __tablename__ = "auth_sessions"
    __table_args__ = (
        CheckConstraint("token_hash ~ '^[0-9a-f]{64}$'", name="ck_auth_sessions_token_hash_format"),
        CheckConstraint("csrf_token_hash ~ '^[0-9a-f]{64}$'", name="ck_auth_sessions_csrf_token_hash_format"),
        CheckConstraint("user_session_version > 0", name="ck_auth_sessions_user_session_version_positive"),
        CheckConstraint("expires_at > issued_at AND absolute_expires_at >= expires_at", name="ck_auth_sessions_expiry_order"),
        CheckConstraint("created_at >= issued_at AND updated_at >= created_at", name="ck_auth_sessions_timestamp_order"),
        CheckConstraint("rotated_at IS NULL OR (rotated_at >= issued_at AND rotated_at <= absolute_expires_at)", name="ck_auth_sessions_rotated_at_order"),
        CheckConstraint("(revoked_at IS NULL AND revocation_reason IS NULL) OR (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)", name="ck_auth_sessions_revocation_shape"),
        CheckConstraint("revoked_at IS NULL OR (revoked_at >= issued_at AND revoked_at <= updated_at)", name="ck_auth_sessions_revoked_at_order"),
        CheckConstraint("revocation_reason IS NULL OR revocation_reason IN ('logout', 'refresh', 'password_change', 'account_disabled', 'role_changed', 'admin_revocation', 'session_limit')", name="ck_auth_sessions_revocation_reason_allowed"),
        Index("ix_auth_sessions_user_active_expiry", "user_id", "revoked_at", "expires_at"),
        Index("ix_auth_sessions_retention_expiry", "absolute_expires_at", "id"),
    )

    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("auth_users.id", ondelete="RESTRICT"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    user_session_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class AuthLoginThrottle(BigIntPrimaryKeyMixin, Base):
    __tablename__ = "auth_login_throttles"
    __table_args__ = (
        CheckConstraint("login_key_hash ~ '^[0-9a-f]{64}$'", name="ck_auth_login_throttles_login_key_hash_format"),
        CheckConstraint("failure_count BETWEEN 0 AND 1000", name="ck_auth_login_throttles_failure_count_bounded"),
        CheckConstraint("updated_at >= window_started_at", name="ck_auth_login_throttles_updated_at_order"),
        CheckConstraint("blocked_until IS NULL OR blocked_until >= window_started_at", name="ck_auth_login_throttles_blocked_until_order"),
        Index("ix_auth_login_throttles_blocked_until", "blocked_until"),
        Index("ix_auth_login_throttles_window_updated", "window_started_at", "updated_at"),
    )

    login_key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
