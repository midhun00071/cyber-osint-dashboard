"""add durable source operator state

Revision ID: c07a01b02c03
Revises: f4a1c2d3e5b6
Create Date: 2026-08-05 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c07a01b02c03"
down_revision: str | Sequence[str] | None = "f4a1c2d3e5b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "intelligence_sources",
        sa.Column("operator_state", sa.String(length=16), nullable=True),
    )

    sources = sa.table(
        "intelligence_sources",
        sa.column("is_enabled", sa.Boolean()),
        sa.column("operator_state", sa.String(length=16)),
    )
    connection = op.get_bind()
    connection.execute(
        sa.update(sources)
        .where(sources.c.is_enabled.is_(True))
        .values(operator_state="enabled")
    )
    connection.execute(
        sa.update(sources)
        .where(sources.c.is_enabled.is_(False))
        .values(operator_state="disabled")
    )
    remaining_nulls = connection.scalar(
        sa.select(sa.func.count())
        .select_from(sources)
        .where(sources.c.operator_state.is_(None))
    )
    if remaining_nulls:
        raise RuntimeError("Source operator-state backfill was incomplete.")

    op.alter_column(
        "intelligence_sources",
        "operator_state",
        existing_type=sa.String(length=16),
        nullable=False,
    )
    op.create_check_constraint(
        "ck_intelligence_sources_operator_state",
        "intelligence_sources",
        "operator_state IN ('enabled', 'paused', 'disabled')",
    )
    op.create_check_constraint(
        "ck_intelligence_sources_operator_state_enabled_consistency",
        "intelligence_sources",
        "(operator_state = 'enabled' AND is_enabled = true) OR "
        "(operator_state IN ('paused', 'disabled') AND is_enabled = false)",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_intelligence_sources_operator_state_enabled_consistency",
        "intelligence_sources",
        type_="check",
    )
    op.drop_constraint(
        "ck_intelligence_sources_operator_state",
        "intelligence_sources",
        type_="check",
    )
    op.drop_column("intelligence_sources", "operator_state")
