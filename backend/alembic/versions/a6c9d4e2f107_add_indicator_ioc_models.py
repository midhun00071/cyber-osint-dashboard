"""add indicator IOC models

Revision ID: a6c9d4e2f107
Revises: f8d739439ed0
Create Date: 2026-07-27 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "a6c9d4e2f107"
down_revision: str | Sequence[str] | None = "f8d739439ed0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_source_records_id_source_id",
        "source_records",
        ["id", "source_id"],
    )
    op.create_table(
        "indicators",
        sa.Column("observable_type", sa.String(length=20), nullable=False),
        sa.Column("normalized_value", sa.String(length=2048), nullable=False),
        sa.Column("hash_algorithm", sa.String(length=20), nullable=True),
        sa.Column("identity_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("confidence", sa.Numeric(precision=4, scale=3), nullable=True),
        sa.Column("context_summary", sa.String(length=1000), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(always=False),
            nullable=False,
        ),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_indicators_confidence_range",
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR first_seen_at IS NULL OR "
            "expires_at >= first_seen_at",
            name="ck_indicators_expires_at_order",
        ),
        sa.CheckConstraint(
            "hash_algorithm IS NULL OR "
            "hash_algorithm IN ('md5', 'sha1', 'sha256', 'sha512')",
            name="ck_indicators_hash_algorithm_allowed",
        ),
        sa.CheckConstraint(
            "(observable_type = 'file_hash' AND hash_algorithm IS NOT NULL) OR "
            "(observable_type <> 'file_hash' AND hash_algorithm IS NULL)",
            name="ck_indicators_hash_algorithm_consistency",
        ),
        sa.CheckConstraint(
            "identity_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_indicators_identity_sha256_format",
        ),
        sa.CheckConstraint(
            "char_length(normalized_value) BETWEEN 1 AND 2048",
            name="ck_indicators_normalized_value_length",
        ),
        sa.CheckConstraint(
            "observable_type IN ('ipv4', 'ipv6', 'domain', 'url', 'file_hash')",
            name="ck_indicators_observable_type_allowed",
        ),
        sa.CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL) OR "
            "(status <> 'revoked' AND revoked_at IS NULL)",
            name="ck_indicators_revoked_at_consistency",
        ),
        sa.CheckConstraint(
            "last_seen_at IS NULL OR first_seen_at IS NULL OR "
            "last_seen_at >= first_seen_at",
            name="ck_indicators_seen_at_order",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'inactive', 'revoked', "
            "'false_positive', 'archived')",
            name="ck_indicators_status_allowed",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_indicators")),
        sa.UniqueConstraint("public_id", name=op.f("uq_indicators_public_id")),
    )
    op.create_table(
        "indicator_provenances",
        sa.Column("indicator_id", sa.BigInteger(), nullable=False),
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("source_record_id", sa.BigInteger(), nullable=True),
        sa.Column("confidence", sa.Numeric(precision=4, scale=3), nullable=True),
        sa.Column("context_summary", sa.String(length=1000), nullable=True),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(always=False),
            nullable=False,
        ),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_indicator_provenances_confidence_range",
        ),
        sa.CheckConstraint(
            "last_observed_at IS NULL OR first_observed_at IS NULL OR "
            "last_observed_at >= first_observed_at",
            name="ck_indicator_provenances_observed_at_order",
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name=op.f("fk_indicator_provenances_indicator_id_indicators"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name=op.f(
                "fk_indicator_provenances_source_id_intelligence_sources"
            ),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["source_record_id", "source_id"],
            ["source_records.id", "source_records.source_id"],
            name="fk_indicator_provenances_source_record_source_records",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_indicator_provenances"),
        ),
        sa.UniqueConstraint(
            "public_id",
            name=op.f("uq_indicator_provenances_public_id"),
        ),
    )
    op.create_index(
        "ix_indicators_observable_type_status",
        "indicators",
        ["observable_type", "status"],
        unique=False,
    )
    op.create_index(
        "ix_indicators_status_last_seen_at_desc",
        "indicators",
        ["status", sa.literal_column("last_seen_at DESC")],
        unique=False,
    )
    op.create_index(
        "uq_indicators_identity_sha256",
        "indicators",
        ["identity_sha256"],
        unique=True,
    )
    op.create_index(
        "uq_indicator_provenances_indicator_source_record",
        "indicator_provenances",
        ["indicator_id", "source_record_id"],
        unique=True,
        postgresql_where=sa.text("source_record_id IS NOT NULL"),
    )
    op.create_index(
        "uq_indicator_provenances_indicator_source_without_record",
        "indicator_provenances",
        ["indicator_id", "source_id"],
        unique=True,
        postgresql_where=sa.text("source_record_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_indicator_provenances_indicator_source_without_record",
        table_name="indicator_provenances",
        postgresql_where=sa.text("source_record_id IS NULL"),
    )
    op.drop_index(
        "uq_indicator_provenances_indicator_source_record",
        table_name="indicator_provenances",
        postgresql_where=sa.text("source_record_id IS NOT NULL"),
    )
    op.drop_table("indicator_provenances")
    op.drop_index("uq_indicators_identity_sha256", table_name="indicators")
    op.drop_index(
        "ix_indicators_status_last_seen_at_desc",
        table_name="indicators",
    )
    op.drop_index(
        "ix_indicators_observable_type_status",
        table_name="indicators",
    )
    op.drop_table("indicators")
    op.drop_constraint(
        "uq_source_records_id_source_id",
        "source_records",
        type_="unique",
    )
