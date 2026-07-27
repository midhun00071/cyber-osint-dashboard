"""add IOC publication relationships

Revision ID: c4e8b2a91d30
Revises: a6c9d4e2f107
Create Date: 2026-07-27 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c4e8b2a91d30"
down_revision: str | Sequence[str] | None = "a6c9d4e2f107"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "intelligence_item_indicators",
        sa.Column("intelligence_item_id", sa.BigInteger(), nullable=False),
        sa.Column("indicator_id", sa.BigInteger(), nullable=False),
        sa.Column("relationship_type", sa.String(length=40), nullable=False),
        sa.Column("extraction_method", sa.String(length=40), nullable=False),
        sa.Column("confidence", sa.Numeric(precision=4, scale=3), nullable=False),
        sa.Column("context_summary", sa.String(length=500), nullable=True),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_intelligence_item_indicators_confidence_range",
        ),
        sa.CheckConstraint(
            "extraction_method IN ('deterministic_text')",
            name="ck_intelligence_item_indicators_extraction_method_allowed",
        ),
        sa.CheckConstraint(
            "last_observed_at >= first_observed_at",
            name="ck_intelligence_item_indicators_observed_at_order",
        ),
        sa.CheckConstraint(
            "relationship_type IN ('mentioned')",
            name="ck_intelligence_item_indicators_relationship_type_allowed",
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name=op.f(
                "fk_intelligence_item_indicators_indicator_id_indicators"
            ),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["intelligence_item_id"],
            ["intelligence_items.id"],
            name=op.f(
                "fk_intelligence_item_indicators_intelligence_item_id_"
                "intelligence_items"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "intelligence_item_id",
            "indicator_id",
            name=op.f("pk_intelligence_item_indicators"),
        ),
    )
    op.create_index(
        "ix_intelligence_item_indicators_indicator_id_item_id",
        "intelligence_item_indicators",
        ["indicator_id", "intelligence_item_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_intelligence_item_indicators_indicator_id_item_id",
        table_name="intelligence_item_indicators",
    )
    op.drop_table("intelligence_item_indicators")
