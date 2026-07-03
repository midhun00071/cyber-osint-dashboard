"""Shared SQLAlchemy model utilities for core domain models."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, DateTime, Identity, Uuid
from sqlalchemy.orm import Mapped, mapped_column


def utc_now() -> datetime:
    """Return an aware UTC timestamp for Python-side ORM defaults."""

    return datetime.now(UTC)


def uuid4_public_id() -> UUID:
    """Return a UUIDv4 value for public API-safe identifiers."""

    return uuid4()


class BigIntPrimaryKeyMixin:
    """Internal PostgreSQL bigint identity primary key."""

    id: Mapped[int] = mapped_column(
        BigInteger,
        Identity(),
        primary_key=True,
    )


class PublicIdMixin:
    """Python-generated UUID public identifier."""

    public_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        unique=True,
        default=uuid4_public_id,
    )


class TimestampMixin:
    """Created and updated timestamps generated in Python."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )
