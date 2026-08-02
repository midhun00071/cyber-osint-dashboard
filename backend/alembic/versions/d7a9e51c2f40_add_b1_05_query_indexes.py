"""add B1-05 query indexes

Revision ID: d7a9e51c2f40
Revises: b103a71d2e4f
Create Date: 2026-07-31 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "d7a9e51c2f40"
down_revision: str | Sequence[str] | None = "b103a71d2e4f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Install only indexes supported by B1-05 PostgreSQL query-plan evidence."""

    op.drop_index(
        "ix_ingestion_runs_source_id_started_at_desc",
        table_name="ingestion_runs",
    )
    op.create_index(
        "ix_ingestion_runs_source_id_started_at_id_desc",
        "ingestion_runs",
        [
            "source_id",
            sa.literal_column("started_at DESC"),
            sa.literal_column("id DESC"),
        ],
        unique=False,
    )
    op.create_index(
        "ix_ingestion_runs_started_at_id_desc",
        "ingestion_runs",
        [sa.literal_column("started_at DESC"), sa.literal_column("id DESC")],
        unique=False,
    )


def downgrade() -> None:
    """Restore the B1-03 source-history index and remove the global index."""

    op.drop_index(
        "ix_ingestion_runs_started_at_id_desc",
        table_name="ingestion_runs",
    )
    op.drop_index(
        "ix_ingestion_runs_source_id_started_at_id_desc",
        table_name="ingestion_runs",
    )
    op.create_index(
        "ix_ingestion_runs_source_id_started_at_desc",
        "ingestion_runs",
        ["source_id", sa.literal_column("started_at DESC")],
        unique=False,
    )
