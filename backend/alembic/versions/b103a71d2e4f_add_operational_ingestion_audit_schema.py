"""add operational ingestion audit schema

Revision ID: b103a71d2e4f
Revises: c4e8b2a91d30
Create Date: 2026-07-30 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "b103a71d2e4f"
down_revision: str | Sequence[str] | None = "c4e8b2a91d30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


RUN_TERMINAL_STATUSES = (
    "success",
    "no_change",
    "skipped",
    "deferred_quota",
    "approval_pending",
    "disabled",
    "credentials_missing",
    "licence_required",
    "rate_limited",
    "partial",
    "failed",
    "cancelled",
)
OPERATIONAL_LEGACY_DOWNGRADE_STATUSES = (
    "running",
    "success",
    "partial",
    "failed",
    "cancelled",
)
COMPATIBILITY_DOWNGRADE_STATUSES = (
    "running",
    "succeeded",
    "partial",
    "failed",
    "canceled",
)


def _table(name: str, *columns: sa.Column) -> sa.TableClause:
    return sa.table(name, *columns)


def _fail(category: str, *, count: int, safe_ids: Sequence[object] = ()) -> None:
    suffix = f"; ids={list(safe_ids)}" if safe_ids else ""
    raise RuntimeError(
        f"migration validation failed: {category}; count={count}{suffix}"
    )


def _require_no_rows(
    connection: sa.Connection,
    statement: sa.Select,
    category: str,
) -> None:
    rows = connection.execute(statement.limit(11)).scalars().all()
    if rows:
        _fail(category, count=len(rows) if len(rows) <= 10 else 11, safe_ids=rows[:10])


def _run_table() -> sa.TableClause:
    return _table(
        "ingestion_runs",
        sa.column("id", sa.BigInteger()),
        sa.column("public_id", sa.Uuid()),
        sa.column("source_id", sa.BigInteger()),
        sa.column("cycle_id", sa.BigInteger()),
        sa.column("idempotency_key", sa.String(240)),
        sa.column("attempt_number", sa.SmallInteger()),
        sa.column("retry_of_run_id", sa.BigInteger()),
        sa.column("state_version", sa.Integer()),
        sa.column("defer_reason", sa.String(80)),
        sa.column("trigger_type", sa.String(40)),
        sa.column("status", sa.String(40)),
        sa.column("started_at", sa.DateTime(timezone=True)),
        sa.column("completed_at", sa.DateTime(timezone=True)),
        sa.column("checkpoint_after", sa.String(500)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )


def _source_table() -> sa.TableClause:
    return _table(
        "intelligence_sources",
        sa.column("id", sa.BigInteger()),
        sa.column("checkpoint_value", sa.String(500)),
        sa.column("last_successful_fetch_at", sa.DateTime(timezone=True)),
    )


def _create_ingestion_cycles() -> None:
    op.create_table(
        "ingestion_cycles",
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("trigger_type", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sources_expected", sa.Integer(), nullable=False),
        sa.Column("sources_started", sa.Integer(), nullable=False),
        sa.Column("sources_completed", sa.Integer(), nullable=False),
        sa.Column("sources_successful", sa.Integer(), nullable=False),
        sa.Column("sources_non_successful", sa.Integer(), nullable=False),
        sa.Column("safe_summary", sa.String(length=1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "trigger_type IN ('scheduled', 'manual', 'legacy_import')",
            name="ck_ingestion_cycles_trigger_type_allowed",
        ),
        sa.CheckConstraint(
            "(trigger_type = 'scheduled' AND scheduled_for IS NOT NULL) OR "
            "(trigger_type IN ('manual', 'legacy_import') AND scheduled_for IS NULL)",
            name="ck_ingestion_cycles_trigger_schedule_consistency",
        ),
        sa.CheckConstraint(
            "status IN ('running', 'success', 'partial', 'failed', 'cancelled')",
            name="ck_ingestion_cycles_status_allowed",
        ),
        sa.CheckConstraint(
            "(status = 'running' AND completed_at IS NULL) OR "
            "(status IN ('success', 'partial', 'failed', 'cancelled') "
            "AND completed_at IS NOT NULL)",
            name="ck_ingestion_cycles_status_time_consistency",
        ),
        sa.CheckConstraint(
            "completed_at IS NULL OR completed_at >= started_at",
            name="ck_ingestion_cycles_completed_at_order",
        ),
        sa.CheckConstraint(
            "sources_expected >= 0 AND sources_started >= 0 "
            "AND sources_completed >= 0 AND sources_successful >= 0 "
            "AND sources_non_successful >= 0",
            name="ck_ingestion_cycles_counters_non_negative",
        ),
        sa.CheckConstraint(
            "sources_started <= sources_expected "
            "AND sources_completed <= sources_started "
            "AND sources_successful + sources_non_successful = sources_completed",
            name="ck_ingestion_cycles_counter_relationships",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingestion_cycles")),
        sa.UniqueConstraint(
            "public_id", name=op.f("uq_ingestion_cycles_public_id")
        ),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_ingestion_cycles_idempotency_key"
        ),
    )


def _create_source_credential_references() -> None:
    op.create_table(
        "source_credential_references",
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("reference_name", sa.String(length=80), nullable=False),
        sa.Column("purpose", sa.String(length=60), nullable=False),
        sa.Column("external_reference_id", sa.String(length=240), nullable=True),
        sa.Column("configuration_state", sa.String(length=30), nullable=False),
        sa.Column("owner_ref", sa.String(length=160), nullable=True),
        sa.Column("last_rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.CheckConstraint(
            "configuration_state IN ('not_configured', 'configured', 'disabled', "
            "'rotation_due', 'revoked')",
            name="ck_source_credential_references_state_allowed",
        ),
        sa.CheckConstraint(
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
        sa.CheckConstraint(
            "expires_at IS NULL OR last_rotated_at IS NULL "
            "OR expires_at >= last_rotated_at",
            name="ck_source_credential_references_rotation_expiry_order",
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name="ck_source_credential_references_updated_at_order",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name=op.f(
                "fk_source_credential_references_source_id_intelligence_sources"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id", name=op.f("pk_source_credential_references")
        ),
        sa.UniqueConstraint(
            "source_id",
            "reference_name",
            "purpose",
            name="uq_source_credential_references_source_name_purpose",
        ),
    )


def _create_source_rate_limit_states() -> None:
    op.create_table(
        "source_rate_limit_states",
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("policy_key", sa.String(length=80), nullable=False),
        sa.Column("request_limit", sa.Integer(), nullable=True),
        sa.Column("remaining", sa.Integer(), nullable=True),
        sa.Column("window_seconds", sa.Integer(), nullable=True),
        sa.Column("reset_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("backoff_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("state", sa.String(length=30), nullable=False),
        sa.Column("state_version", sa.BigInteger(), nullable=False),
        sa.Column("updated_by_run_id", sa.BigInteger(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.CheckConstraint(
            "(request_limit IS NULL OR request_limit >= 0) "
            "AND (remaining IS NULL OR remaining >= 0) "
            "AND (request_limit IS NULL OR remaining IS NULL "
            "OR remaining <= request_limit)",
            name="ck_source_rate_limit_states_counts_valid",
        ),
        sa.CheckConstraint(
            "window_seconds IS NULL OR window_seconds BETWEEN 1 AND 31536000",
            name="ck_source_rate_limit_states_window_bounded",
        ),
        sa.CheckConstraint(
            "state_version > 0",
            name="ck_source_rate_limit_states_version_positive",
        ),
        sa.CheckConstraint(
            "state IN ('available', 'limited', 'backoff', "
            "'quota_unavailable', 'unknown')",
            name="ck_source_rate_limit_states_state_allowed",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name=op.f(
                "fk_source_rate_limit_states_source_id_intelligence_sources"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id", name=op.f("pk_source_rate_limit_states")
        ),
        sa.UniqueConstraint(
            "source_id",
            "policy_key",
            name="uq_source_rate_limit_states_source_policy",
        ),
    )


def _add_run_columns_and_backfill(connection: sa.Connection) -> None:
    op.add_column("ingestion_runs", sa.Column("cycle_id", sa.BigInteger(), nullable=True))
    op.add_column(
        "ingestion_runs", sa.Column("idempotency_key", sa.String(240), nullable=True)
    )
    op.add_column(
        "ingestion_runs", sa.Column("attempt_number", sa.SmallInteger(), nullable=True)
    )
    op.add_column(
        "ingestion_runs", sa.Column("retry_of_run_id", sa.BigInteger(), nullable=True)
    )
    op.add_column(
        "ingestion_runs", sa.Column("state_version", sa.Integer(), nullable=True)
    )
    op.add_column(
        "ingestion_runs", sa.Column("defer_reason", sa.String(80), nullable=True)
    )

    runs = _run_table()
    cycles = _table(
        "ingestion_cycles",
        sa.column("id", sa.BigInteger()),
        sa.column("public_id", sa.Uuid()),
        sa.column("idempotency_key", sa.String(200)),
        sa.column("trigger_type", sa.String(20)),
        sa.column("status", sa.String(30)),
        sa.column("scheduled_for", sa.DateTime(timezone=True)),
        sa.column("started_at", sa.DateTime(timezone=True)),
        sa.column("completed_at", sa.DateTime(timezone=True)),
        sa.column("sources_expected", sa.Integer()),
        sa.column("sources_started", sa.Integer()),
        sa.column("sources_completed", sa.Integer()),
        sa.column("sources_successful", sa.Integer()),
        sa.column("sources_non_successful", sa.Integer()),
        sa.column("safe_summary", sa.String(1000)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    legacy_rows = connection.execute(
        sa.select(
            runs.c.id,
            runs.c.public_id,
            runs.c.status,
            runs.c.started_at,
            runs.c.completed_at,
            runs.c.created_at,
        ).order_by(runs.c.id)
    ).mappings()
    status_map = {
        "running": "running",
        "succeeded": "success",
        "partial": "partial",
        "failed": "failed",
        "canceled": "cancelled",
    }
    for row in legacy_rows:
        mapped_status = status_map.get(row["status"])
        if mapped_status is None:
            _fail("legacy_run_status", count=1, safe_ids=[row["id"]])
        terminal = mapped_status != "running"
        completed_at = row["completed_at"]
        if not terminal and completed_at is not None:
            _fail("legacy_running_completion", count=1, safe_ids=[row["id"]])
        if terminal and (
            completed_at is None or completed_at < row["started_at"]
        ):
            _fail("legacy_terminal_completion", count=1, safe_ids=[row["id"]])
        cycle_id = connection.execute(
            sa.insert(cycles)
            .values(
                public_id=row["public_id"],
                idempotency_key=f"legacy-cycle:{row['public_id']}",
                trigger_type="legacy_import",
                status=mapped_status,
                scheduled_for=None,
                started_at=row["started_at"],
                completed_at=completed_at if terminal else None,
                sources_expected=1,
                sources_started=1,
                sources_completed=1 if terminal else 0,
                sources_successful=1 if mapped_status == "success" else 0,
                sources_non_successful=1 if terminal and mapped_status != "success" else 0,
                safe_summary=None,
                created_at=row["created_at"],
            )
            .returning(cycles.c.id)
        ).scalar_one()
        connection.execute(
            sa.update(runs)
            .where(runs.c.id == row["id"])
            .values(
                cycle_id=cycle_id,
                idempotency_key=f"legacy-run:{row['public_id']}",
                attempt_number=0,
                retry_of_run_id=None,
                state_version=1,
                defer_reason=None,
            )
        )

    _require_no_rows(
        connection,
        sa.select(runs.c.id).where(
            sa.or_(
                runs.c.cycle_id.is_(None),
                runs.c.idempotency_key.is_(None),
                runs.c.attempt_number.is_(None),
                runs.c.state_version.is_(None),
            )
        ),
        "required_run_backfill",
    )
    op.drop_constraint(
        "ck_ingestion_runs_status_allowed", "ingestion_runs", type_="check"
    )
    connection.execute(
        sa.update(runs).where(runs.c.status == "succeeded").values(status="success")
    )
    connection.execute(
        sa.update(runs).where(runs.c.status == "canceled").values(status="cancelled")
    )
    op.alter_column(
        "ingestion_runs",
        "status",
        existing_type=sa.String(40),
        type_=sa.String(30),
        existing_nullable=False,
    )


def _add_run_integrity() -> None:
    op.create_unique_constraint(
        "uq_ingestion_runs_idempotency_key", "ingestion_runs", ["idempotency_key"]
    )
    op.create_unique_constraint(
        "uq_ingestion_runs_source_cycle_attempt",
        "ingestion_runs",
        ["source_id", "cycle_id", "attempt_number"],
    )
    op.create_unique_constraint(
        "uq_ingestion_runs_id_source_id", "ingestion_runs", ["id", "source_id"]
    )
    op.create_unique_constraint(
        "uq_ingestion_runs_id_cycle_id", "ingestion_runs", ["id", "cycle_id"]
    )
    op.create_foreign_key(
        op.f("fk_ingestion_runs_cycle_id_ingestion_cycles"),
        "ingestion_runs",
        "ingestion_cycles",
        ["cycle_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_ingestion_runs_retry_source",
        "ingestion_runs",
        "ingestion_runs",
        ["retry_of_run_id", "source_id"],
        ["id", "source_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_ingestion_runs_retry_cycle",
        "ingestion_runs",
        "ingestion_runs",
        ["retry_of_run_id", "cycle_id"],
        ["id", "cycle_id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "ck_ingestion_runs_attempt_number_bounded",
        "ingestion_runs",
        "attempt_number IS NULL OR attempt_number BETWEEN 0 AND 10",
    )
    op.create_check_constraint(
        "ck_ingestion_runs_retry_lineage_consistency",
        "ingestion_runs",
        "(attempt_number IS NULL AND retry_of_run_id IS NULL) OR "
        "(attempt_number = 0 AND retry_of_run_id IS NULL) OR "
        "(attempt_number BETWEEN 1 AND 10 AND retry_of_run_id IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_ingestion_runs_state_version_positive",
        "ingestion_runs",
        "state_version IS NULL OR state_version > 0",
    )
    op.create_check_constraint(
        "ck_ingestion_runs_operational_or_compatibility_shape",
        "ingestion_runs",
        "(cycle_id IS NOT NULL AND idempotency_key IS NOT NULL "
        "AND attempt_number IS NOT NULL AND state_version IS NOT NULL "
        "AND status IN ('running', 'checkpoint_pending', 'success', "
        "'no_change', 'skipped', 'deferred_quota', 'approval_pending', "
        "'disabled', 'credentials_missing', 'licence_required', "
        "'rate_limited', 'partial', 'failed', 'cancelled')) OR "
        "(cycle_id IS NULL AND idempotency_key IS NULL "
        "AND attempt_number IS NULL AND retry_of_run_id IS NULL "
        "AND state_version IS NULL AND defer_reason IS NULL "
        "AND status IN ('running', 'succeeded', 'partial', 'failed', 'canceled'))",
    )
    op.create_check_constraint(
        "ck_ingestion_runs_status_allowed",
        "ingestion_runs",
        "status IN ('running', 'checkpoint_pending', 'success', 'no_change', "
        "'skipped', 'deferred_quota', 'approval_pending', 'disabled', "
        "'credentials_missing', 'licence_required', 'rate_limited', "
        "'partial', 'failed', 'cancelled', 'succeeded', 'canceled')",
    )
    op.create_check_constraint(
        "ck_ingestion_runs_status_time_consistency",
        "ingestion_runs",
        "(status IN ('running', 'checkpoint_pending') AND completed_at IS NULL) "
        "OR (status IN ('success', 'no_change', 'skipped', 'deferred_quota', "
        "'approval_pending', 'disabled', 'credentials_missing', "
        "'licence_required', 'rate_limited', 'partial', 'failed', 'cancelled', "
        "'succeeded', 'canceled') "
        "AND completed_at IS NOT NULL AND completed_at >= started_at)",
    )


def _create_ingestion_run_events() -> None:
    op.create_table(
        "ingestion_run_events",
        sa.Column("ingestion_run_id", sa.BigInteger(), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=60), nullable=False),
        sa.Column("from_status", sa.String(length=30), nullable=True),
        sa.Column("to_status", sa.String(length=30), nullable=True),
        sa.Column("safe_message", sa.String(length=1000), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.CheckConstraint(
            "sequence_number BETWEEN 1 AND 100000",
            name="ck_ingestion_run_events_sequence_bounded",
        ),
        sa.CheckConstraint(
            "event_type IN ('acquired', 'started', 'persistence_committed', "
            "'checkpoint_advanced', 'completed', 'skipped', 'deferred', "
            "'partial', 'failed', 'cancelled')",
            name="ck_ingestion_run_events_event_type_allowed",
        ),
        sa.CheckConstraint(
            "(from_status IS NULL AND to_status IS NULL) OR "
            "(from_status IS NOT NULL AND to_status IS NOT NULL)",
            name="ck_ingestion_run_events_transition_shape",
        ),
        sa.CheckConstraint(
            "created_at >= occurred_at",
            name="ck_ingestion_run_events_created_at_order",
        ),
        sa.ForeignKeyConstraint(
            ["ingestion_run_id"],
            ["ingestion_runs.id"],
            name=op.f("fk_ingestion_run_events_ingestion_run_id_ingestion_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingestion_run_events")),
        sa.UniqueConstraint(
            "ingestion_run_id",
            "sequence_number",
            name="uq_ingestion_run_events_run_sequence",
        ),
        sa.UniqueConstraint(
            "id",
            "ingestion_run_id",
            name="uq_ingestion_run_events_id_run_id",
        ),
    )


def _create_source_checkpoints() -> None:
    op.create_table(
        "source_checkpoints",
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("scope_kind", sa.String(length=20), nullable=False),
        sa.Column("partition_key", sa.String(length=160), nullable=True),
        sa.Column("checkpoint_name", sa.String(length=80), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("checkpoint_value", sa.String(length=500), nullable=False),
        sa.Column("previous_checkpoint_id", sa.BigInteger(), nullable=True),
        sa.Column("advanced_by_run_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "persistence_committed_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.CheckConstraint(
            "(scope_kind = 'source' AND partition_key IS NULL) OR "
            "(scope_kind = 'partition' AND partition_key IS NOT NULL "
            "AND char_length(btrim(partition_key)) BETWEEN 1 AND 160)",
            name="ck_source_checkpoints_scope_identity",
        ),
        sa.CheckConstraint(
            "version > 0", name="ck_source_checkpoints_version_positive"
        ),
        sa.CheckConstraint(
            "persistence_committed_at <= committed_at",
            name="ck_source_checkpoints_commit_order",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name=op.f("fk_source_checkpoints_source_id_intelligence_sources"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["advanced_by_run_id", "source_id"],
            ["ingestion_runs.id", "ingestion_runs.source_id"],
            name="fk_source_checkpoints_advanced_run_source",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["previous_checkpoint_id", "source_id"],
            ["source_checkpoints.id", "source_checkpoints.source_id"],
            name="fk_source_checkpoints_previous_source",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_source_checkpoints")),
        sa.UniqueConstraint(
            "id", "source_id", name="uq_source_checkpoints_id_source_id"
        ),
        sa.UniqueConstraint(
            "previous_checkpoint_id", name="uq_source_checkpoints_previous"
        ),
    )


def _create_source_watermarks() -> None:
    op.create_table(
        "source_watermarks",
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("scope_kind", sa.String(length=20), nullable=False),
        sa.Column("partition_key", sa.String(length=160), nullable=True),
        sa.Column("watermark_name", sa.String(length=80), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("watermark_value", sa.DateTime(timezone=True), nullable=False),
        sa.Column("previous_watermark_id", sa.BigInteger(), nullable=True),
        sa.Column("advanced_by_run_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "persistence_committed_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.CheckConstraint(
            "(scope_kind = 'source' AND partition_key IS NULL) OR "
            "(scope_kind = 'partition' AND partition_key IS NOT NULL "
            "AND char_length(btrim(partition_key)) BETWEEN 1 AND 160)",
            name="ck_source_watermarks_scope_identity",
        ),
        sa.CheckConstraint(
            "version > 0", name="ck_source_watermarks_version_positive"
        ),
        sa.CheckConstraint(
            "persistence_committed_at <= committed_at",
            name="ck_source_watermarks_commit_order",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name=op.f("fk_source_watermarks_source_id_intelligence_sources"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["advanced_by_run_id", "source_id"],
            ["ingestion_runs.id", "ingestion_runs.source_id"],
            name="fk_source_watermarks_advanced_run_source",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["previous_watermark_id", "source_id"],
            ["source_watermarks.id", "source_watermarks.source_id"],
            name="fk_source_watermarks_previous_source",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_source_watermarks")),
        sa.UniqueConstraint(
            "id", "source_id", name="uq_source_watermarks_id_source_id"
        ),
        sa.UniqueConstraint(
            "previous_watermark_id", name="uq_source_watermarks_previous"
        ),
    )


def _create_quarantined_records() -> None:
    op.create_table(
        "quarantined_records",
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("ingestion_run_id", sa.BigInteger(), nullable=False),
        sa.Column("ingestion_run_event_id", sa.BigInteger(), nullable=True),
        sa.Column("quarantine_key", sa.CHAR(length=64), nullable=False),
        sa.Column("reason_code", sa.String(length=80), nullable=False),
        sa.Column("safe_excerpt", sa.String(length=1000), nullable=True),
        sa.Column("safe_metadata", sa.String(length=2000), nullable=True),
        sa.Column("original_byte_count", sa.Integer(), nullable=False),
        sa.Column("stored_byte_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "quarantine_key ~ '^[0-9a-f]{64}$'",
            name="ck_quarantined_records_key_format",
        ),
        sa.CheckConstraint(
            "original_byte_count >= 0 AND stored_byte_count >= 0 "
            "AND stored_byte_count = "
            "octet_length(coalesce(safe_excerpt, '')) + "
            "octet_length(coalesce(safe_metadata, '')) "
            "AND stored_byte_count <= 4096 "
            "AND stored_byte_count <= original_byte_count",
            name="ck_quarantined_records_sizes_bounded",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'reviewed', 'released', 'discarded')",
            name="ck_quarantined_records_status_allowed",
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND reviewed_at IS NULL) OR "
            "(status IN ('reviewed', 'released', 'discarded') "
            "AND reviewed_at IS NOT NULL AND reviewed_at >= quarantined_at)",
            name="ck_quarantined_records_reviewed_at_consistency",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name=op.f("fk_quarantined_records_source_id_intelligence_sources"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["ingestion_run_id", "source_id"],
            ["ingestion_runs.id", "ingestion_runs.source_id"],
            name="fk_quarantined_records_run_source",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["ingestion_run_event_id", "ingestion_run_id"],
            ["ingestion_run_events.id", "ingestion_run_events.ingestion_run_id"],
            name="fk_quarantined_records_event_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_quarantined_records")),
        sa.UniqueConstraint(
            "public_id", name=op.f("uq_quarantined_records_public_id")
        ),
        sa.UniqueConstraint(
            "ingestion_run_id",
            "quarantine_key",
            name="uq_quarantined_records_run_key",
        ),
    )


def _extend_ingestion_errors(connection: sa.Connection) -> None:
    errors = _table(
        "ingestion_errors",
        sa.column("id", sa.BigInteger()),
        sa.column("error_type", sa.String(80)),
        sa.column("retry_count", sa.Integer()),
    )
    _require_no_rows(
        connection,
        sa.select(errors.c.id).where(
            sa.or_(errors.c.retry_count < 0, errors.c.retry_count > 10)
        ),
        "legacy_error_retry_count",
    )
    _require_no_rows(
        connection,
        sa.select(errors.c.id).where(
            sa.not_(errors.c.error_type.op("~")("^[a-z][a-z0-9_.-]{0,79}$"))
        ),
        "legacy_error_type",
    )
    op.add_column(
        "ingestion_errors", sa.Column("failure_stage", sa.String(40), nullable=True)
    )
    op.add_column(
        "ingestion_errors",
        sa.Column("diagnostic_fingerprint", sa.CHAR(64), nullable=True),
    )
    op.add_column(
        "ingestion_errors", sa.Column("safe_context", sa.String(1000), nullable=True)
    )
    op.drop_constraint(
        "ck_ingestion_errors_retry_count_non_negative",
        "ingestion_errors",
        type_="check",
    )
    op.create_check_constraint(
        "ck_ingestion_errors_retry_count_bounded",
        "ingestion_errors",
        "retry_count BETWEEN 0 AND 10",
    )
    op.create_check_constraint(
        "ck_ingestion_errors_diagnostic_fingerprint_format",
        "ingestion_errors",
        "diagnostic_fingerprint IS NULL OR "
        "diagnostic_fingerprint ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "ck_ingestion_errors_error_type_format",
        "ingestion_errors",
        "error_type ~ '^[a-z][a-z0-9_.-]{0,79}$'",
    )


def _create_audit_events() -> None:
    op.create_table(
        "audit_events",
        sa.Column("idempotency_key", sa.String(length=240), nullable=False),
        sa.Column("actor_type", sa.String(length=30), nullable=False),
        sa.Column("actor_ref", sa.String(length=160), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("target_type", sa.String(length=60), nullable=False),
        sa.Column("target_ref", sa.String(length=240), nullable=False),
        sa.Column("outcome", sa.String(length=30), nullable=False),
        sa.Column("cycle_id", sa.BigInteger(), nullable=True),
        sa.Column("ingestion_run_id", sa.BigInteger(), nullable=True),
        sa.Column("correlation_id", sa.String(length=100), nullable=True),
        sa.Column("safe_detail", sa.String(length=1000), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "ingestion_run_id IS NULL OR cycle_id IS NOT NULL",
            name="ck_audit_events_run_cycle_consistency",
        ),
        sa.CheckConstraint(
            "actor_type IN ('user', 'service', 'system')",
            name="ck_audit_events_actor_type_allowed",
        ),
        sa.CheckConstraint(
            "action ~ '^[a-z][a-z0-9_.-]{0,79}$'",
            name="ck_audit_events_action_format",
        ),
        sa.CheckConstraint(
            "target_type ~ '^[a-z][a-z0-9_.-]{0,59}$'",
            name="ck_audit_events_target_type_format",
        ),
        sa.CheckConstraint(
            "char_length(btrim(target_ref)) BETWEEN 1 AND 240",
            name="ck_audit_events_target_ref_length",
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'denied', 'failed', 'no_change')",
            name="ck_audit_events_outcome_allowed",
        ),
        sa.CheckConstraint(
            "created_at >= occurred_at", name="ck_audit_events_created_at_order"
        ),
        sa.ForeignKeyConstraint(
            ["cycle_id"],
            ["ingestion_cycles.id"],
            name=op.f("fk_audit_events_cycle_id_ingestion_cycles"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["ingestion_run_id", "cycle_id"],
            ["ingestion_runs.id", "ingestion_runs.cycle_id"],
            name="fk_audit_events_run_cycle",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
        sa.UniqueConstraint("public_id", name=op.f("uq_audit_events_public_id")),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_audit_events_idempotency_key"
        ),
    )


def _backfill_events_and_progress(connection: sa.Connection) -> None:
    runs = _run_table()
    events = _table(
        "ingestion_run_events",
        sa.column("ingestion_run_id", sa.BigInteger()),
        sa.column("sequence_number", sa.Integer()),
        sa.column("event_type", sa.String(60)),
        sa.column("from_status", sa.String(30)),
        sa.column("to_status", sa.String(30)),
        sa.column("safe_message", sa.String(1000)),
        sa.column("occurred_at", sa.DateTime(timezone=True)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    run_rows = connection.execute(
        sa.select(
            runs.c.id,
            runs.c.source_id,
            runs.c.status,
            runs.c.started_at,
            runs.c.completed_at,
            runs.c.created_at,
        ).order_by(runs.c.id)
    ).mappings()
    terminal_event = {
        "success": "completed",
        "partial": "partial",
        "failed": "failed",
        "cancelled": "cancelled",
    }
    for row in run_rows:
        connection.execute(
            sa.insert(events).values(
                ingestion_run_id=row["id"],
                sequence_number=1,
                event_type="acquired",
                from_status=None,
                to_status=None,
                safe_message=None,
                occurred_at=row["started_at"],
                created_at=max(row["started_at"], row["created_at"]),
            )
        )
        event_type = terminal_event.get(row["status"])
        if event_type is not None:
            connection.execute(
                sa.insert(events).values(
                    ingestion_run_id=row["id"],
                    sequence_number=2,
                    event_type=event_type,
                    from_status="running",
                    to_status=row["status"],
                    safe_message=None,
                    occurred_at=row["completed_at"],
                    created_at=row["completed_at"],
                )
            )

    sources = _source_table()
    checkpoints = _table(
        "source_checkpoints",
        sa.column("source_id", sa.BigInteger()),
        sa.column("scope_kind", sa.String(20)),
        sa.column("partition_key", sa.String(160)),
        sa.column("checkpoint_name", sa.String(80)),
        sa.column("version", sa.BigInteger()),
        sa.column("checkpoint_value", sa.String(500)),
        sa.column("previous_checkpoint_id", sa.BigInteger()),
        sa.column("advanced_by_run_id", sa.BigInteger()),
        sa.column("persistence_committed_at", sa.DateTime(timezone=True)),
        sa.column("committed_at", sa.DateTime(timezone=True)),
    )
    watermarks = _table(
        "source_watermarks",
        sa.column("source_id", sa.BigInteger()),
        sa.column("scope_kind", sa.String(20)),
        sa.column("partition_key", sa.String(160)),
        sa.column("watermark_name", sa.String(80)),
        sa.column("version", sa.BigInteger()),
        sa.column("watermark_value", sa.DateTime(timezone=True)),
        sa.column("previous_watermark_id", sa.BigInteger()),
        sa.column("advanced_by_run_id", sa.BigInteger()),
        sa.column("persistence_committed_at", sa.DateTime(timezone=True)),
        sa.column("committed_at", sa.DateTime(timezone=True)),
    )
    source_rows = connection.execute(
        sa.select(
            sources.c.id,
            sources.c.checkpoint_value,
            sources.c.last_successful_fetch_at,
        ).where(
            sa.or_(
                sources.c.checkpoint_value.is_not(None),
                sources.c.last_successful_fetch_at.is_not(None),
            )
        )
    ).mappings()
    for source in source_rows:
        if source["last_successful_fetch_at"] is None:
            _fail("legacy_progress_correlation", count=1, safe_ids=[source["id"]])
        candidate = sa.select(
            runs.c.id, runs.c.completed_at, runs.c.checkpoint_after
        ).where(
            runs.c.source_id == source["id"],
            runs.c.status == "success",
            runs.c.completed_at == source["last_successful_fetch_at"],
        )
        if source["checkpoint_value"] is not None:
            candidate = candidate.where(
                runs.c.checkpoint_after == source["checkpoint_value"]
            )
        candidates = connection.execute(candidate.limit(2)).mappings().all()
        if len(candidates) != 1:
            _fail("legacy_progress_correlation", count=1, safe_ids=[source["id"]])
        run = candidates[0]
        if source["checkpoint_value"] is not None:
            connection.execute(
                sa.insert(checkpoints).values(
                    source_id=source["id"],
                    scope_kind="source",
                    partition_key=None,
                    checkpoint_name="legacy_default",
                    version=1,
                    checkpoint_value=source["checkpoint_value"],
                    previous_checkpoint_id=None,
                    advanced_by_run_id=run["id"],
                    persistence_committed_at=run["completed_at"],
                    committed_at=run["completed_at"],
                )
            )
        connection.execute(
            sa.insert(watermarks).values(
                source_id=source["id"],
                scope_kind="source",
                partition_key=None,
                watermark_name="legacy_default",
                version=1,
                watermark_value=source["last_successful_fetch_at"],
                previous_watermark_id=None,
                advanced_by_run_id=run["id"],
                persistence_committed_at=run["completed_at"],
                committed_at=run["completed_at"],
            )
        )


def _create_indexes() -> None:
    op.create_index(
        "ix_ingestion_cycles_status_started_at_id_desc",
        "ingestion_cycles",
        ["status", sa.literal_column("started_at DESC"), sa.literal_column("id DESC")],
        unique=False,
    )
    op.create_index(
        "uq_source_checkpoints_source_identity_version",
        "source_checkpoints",
        ["source_id", "checkpoint_name", "version"],
        unique=True,
        postgresql_where=sa.text(
            "scope_kind = 'source' AND partition_key IS NULL"
        ),
    )
    op.create_index(
        "uq_source_checkpoints_partition_identity_version",
        "source_checkpoints",
        ["source_id", "partition_key", "checkpoint_name", "version"],
        unique=True,
        postgresql_where=sa.text(
            "scope_kind = 'partition' AND partition_key IS NOT NULL"
        ),
    )
    op.create_index(
        "uq_source_watermarks_source_identity_version",
        "source_watermarks",
        ["source_id", "watermark_name", "version"],
        unique=True,
        postgresql_where=sa.text(
            "scope_kind = 'source' AND partition_key IS NULL"
        ),
    )
    op.create_index(
        "uq_source_watermarks_partition_identity_version",
        "source_watermarks",
        ["source_id", "partition_key", "watermark_name", "version"],
        unique=True,
        postgresql_where=sa.text(
            "scope_kind = 'partition' AND partition_key IS NOT NULL"
        ),
    )
    op.create_index(
        "ix_source_rate_limit_states_non_available_backoff",
        "source_rate_limit_states",
        ["state", "backoff_until"],
        unique=False,
        postgresql_where=sa.text("state <> 'available'"),
    )
    op.create_index(
        "ix_quarantined_records_status_quarantined_at_id",
        "quarantined_records",
        ["status", "quarantined_at", "id"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_occurred_at_id_desc",
        "audit_events",
        [sa.literal_column("occurred_at DESC"), sa.literal_column("id DESC")],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_actor_ref_occurred_at_desc",
        "audit_events",
        ["actor_ref", sa.literal_column("occurred_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_action_occurred_at_desc",
        "audit_events",
        ["action", sa.literal_column("occurred_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_correlation_id",
        "audit_events",
        ["correlation_id"],
        unique=False,
        postgresql_where=sa.text("correlation_id IS NOT NULL"),
    )
    op.create_index(
        "ix_source_credential_references_state_source_id",
        "source_credential_references",
        ["configuration_state", "source_id"],
        unique=False,
    )


def upgrade() -> None:
    connection = op.get_bind()
    _create_ingestion_cycles()
    _create_source_credential_references()
    _create_source_rate_limit_states()
    _add_run_columns_and_backfill(connection)
    _add_run_integrity()
    _create_ingestion_run_events()
    _create_source_checkpoints()
    _create_source_watermarks()
    _create_quarantined_records()
    op.create_foreign_key(
        "fk_source_rate_limit_states_run_source",
        "source_rate_limit_states",
        "ingestion_runs",
        ["updated_by_run_id", "source_id"],
        ["id", "source_id"],
        ondelete="RESTRICT",
    )
    _extend_ingestion_errors(connection)
    _create_audit_events()
    _backfill_events_and_progress(connection)
    _create_indexes()


def _validate_downgrade(connection: sa.Connection) -> None:
    runs = _run_table()
    cycles = _table(
        "ingestion_cycles",
        sa.column("id", sa.BigInteger()),
        sa.column("public_id", sa.Uuid()),
        sa.column("idempotency_key", sa.String(200)),
        sa.column("trigger_type", sa.String(20)),
        sa.column("status", sa.String(30)),
        sa.column("scheduled_for", sa.DateTime(timezone=True)),
        sa.column("started_at", sa.DateTime(timezone=True)),
        sa.column("completed_at", sa.DateTime(timezone=True)),
        sa.column("sources_expected", sa.Integer()),
        sa.column("sources_started", sa.Integer()),
        sa.column("sources_completed", sa.Integer()),
        sa.column("sources_successful", sa.Integer()),
        sa.column("sources_non_successful", sa.Integer()),
        sa.column("safe_summary", sa.String(1000)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    _require_no_rows(
        connection,
        sa.select(runs.c.id).where(runs.c.status == "checkpoint_pending"),
        "checkpoint_pending_run",
    )
    deterministic_operational_shape = sa.and_(
        runs.c.cycle_id.is_not(None),
        runs.c.idempotency_key.is_not(None),
        runs.c.attempt_number.is_not(None),
        runs.c.state_version.is_not(None),
        runs.c.status.in_(OPERATIONAL_LEGACY_DOWNGRADE_STATUSES),
        runs.c.attempt_number == 0,
        runs.c.retry_of_run_id.is_(None),
        runs.c.state_version == 1,
        runs.c.defer_reason.is_(None),
        runs.c.idempotency_key
        == sa.func.concat("legacy-run:", sa.cast(runs.c.public_id, sa.String())),
    )
    compatibility_shape = sa.and_(
        runs.c.cycle_id.is_(None),
        runs.c.idempotency_key.is_(None),
        runs.c.attempt_number.is_(None),
        runs.c.retry_of_run_id.is_(None),
        runs.c.state_version.is_(None),
        runs.c.defer_reason.is_(None),
        runs.c.status.in_(COMPATIBILITY_DOWNGRADE_STATUSES),
    )
    _require_no_rows(
        connection,
        sa.select(runs.c.id).where(
            sa.not_(sa.or_(deterministic_operational_shape, compatibility_shape))
        ),
        "target_only_run_evidence",
    )
    _require_no_rows(
        connection,
        sa.select(cycles.c.id).where(cycles.c.trigger_type != "legacy_import"),
        "target_only_cycle_evidence",
    )
    _require_no_rows(
        connection,
        sa.select(runs.c.id)
        .join(cycles, cycles.c.id == runs.c.cycle_id)
        .where(
            sa.or_(
                cycles.c.public_id != runs.c.public_id,
                cycles.c.idempotency_key
                != sa.func.concat(
                    "legacy-cycle:", sa.cast(runs.c.public_id, sa.String())
                ),
                cycles.c.status != runs.c.status,
                cycles.c.scheduled_for.is_not(None),
                cycles.c.started_at != runs.c.started_at,
                cycles.c.completed_at.is_distinct_from(runs.c.completed_at),
                cycles.c.sources_expected != 1,
                cycles.c.sources_started != 1,
                cycles.c.sources_completed
                != sa.case((runs.c.status == "running", 0), else_=1),
                cycles.c.sources_successful
                != sa.case((runs.c.status == "success", 1), else_=0),
                cycles.c.sources_non_successful
                != sa.case(
                    (runs.c.status.in_(("partial", "failed", "cancelled")), 1),
                    else_=0,
                ),
                cycles.c.safe_summary.is_not(None),
                cycles.c.created_at != runs.c.created_at,
            )
        ),
        "legacy_cycle_evidence",
    )
    _require_no_rows(
        connection,
        sa.select(cycles.c.id)
        .outerjoin(runs, runs.c.cycle_id == cycles.c.id)
        .group_by(cycles.c.id)
        .having(sa.func.count(runs.c.id) != 1),
        "legacy_cycle_run_count",
    )
    simple_empty_tables = (
        "source_rate_limit_states",
        "source_credential_references",
        "quarantined_records",
        "audit_events",
    )
    for table_name in simple_empty_tables:
        table = _table(table_name, sa.column("id", sa.BigInteger()))
        _require_no_rows(
            connection,
            sa.select(table.c.id),
            f"target_only_{table_name}",
        )

    errors = _table(
        "ingestion_errors",
        sa.column("id", sa.BigInteger()),
        sa.column("failure_stage", sa.String(40)),
        sa.column("diagnostic_fingerprint", sa.CHAR(64)),
        sa.column("safe_context", sa.String(1000)),
    )
    _require_no_rows(
        connection,
        sa.select(errors.c.id).where(
            sa.or_(
                errors.c.failure_stage.is_not(None),
                errors.c.diagnostic_fingerprint.is_not(None),
                errors.c.safe_context.is_not(None),
            )
        ),
        "target_only_ingestion_error_metadata",
    )

    events = _table(
        "ingestion_run_events",
        sa.column("id", sa.BigInteger()),
        sa.column("ingestion_run_id", sa.BigInteger()),
        sa.column("sequence_number", sa.Integer()),
        sa.column("event_type", sa.String(60)),
        sa.column("from_status", sa.String(30)),
        sa.column("to_status", sa.String(30)),
        sa.column("safe_message", sa.String(1000)),
        sa.column("occurred_at", sa.DateTime(timezone=True)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    allowed_terminal = sa.or_(
        sa.and_(
            events.c.event_type == "completed",
            events.c.to_status == "success",
            runs.c.status == "success",
        ),
        sa.and_(
            events.c.event_type == "partial",
            events.c.to_status == "partial",
            runs.c.status == "partial",
        ),
        sa.and_(
            events.c.event_type == "failed",
            events.c.to_status == "failed",
            runs.c.status == "failed",
        ),
        sa.and_(
            events.c.event_type == "cancelled",
            events.c.to_status == "cancelled",
            runs.c.status == "cancelled",
        ),
    )
    _require_no_rows(
        connection,
        sa.select(events.c.id).join(runs, runs.c.id == events.c.ingestion_run_id).where(
            sa.not_(
                sa.or_(
                    sa.and_(
                        events.c.sequence_number == 1,
                        events.c.event_type == "acquired",
                        events.c.from_status.is_(None),
                        events.c.to_status.is_(None),
                        events.c.safe_message.is_(None),
                        events.c.occurred_at == runs.c.started_at,
                        events.c.created_at
                        == sa.func.greatest(runs.c.started_at, runs.c.created_at),
                    ),
                    sa.and_(
                        events.c.sequence_number == 2,
                        events.c.from_status == "running",
                        events.c.safe_message.is_(None),
                        events.c.occurred_at == runs.c.completed_at,
                        events.c.created_at == runs.c.completed_at,
                        allowed_terminal,
                    ),
                )
            )
        ),
        "target_only_run_event",
    )
    expected_event_count = sa.case(
        (runs.c.cycle_id.is_(None), 0),
        (runs.c.status == "running", 1),
        else_=2,
    )
    _require_no_rows(
        connection,
        sa.select(runs.c.id)
        .outerjoin(events, events.c.ingestion_run_id == runs.c.id)
        .group_by(runs.c.id, runs.c.status)
        .having(sa.func.count(events.c.id) != expected_event_count),
        "run_event_history_shape",
    )

    sources = _source_table()
    checkpoints = _table(
        "source_checkpoints",
        sa.column("id", sa.BigInteger()),
        sa.column("source_id", sa.BigInteger()),
        sa.column("scope_kind", sa.String(20)),
        sa.column("partition_key", sa.String(160)),
        sa.column("checkpoint_name", sa.String(80)),
        sa.column("version", sa.BigInteger()),
        sa.column("checkpoint_value", sa.String(500)),
        sa.column("previous_checkpoint_id", sa.BigInteger()),
        sa.column("advanced_by_run_id", sa.BigInteger()),
        sa.column("persistence_committed_at", sa.DateTime(timezone=True)),
        sa.column("committed_at", sa.DateTime(timezone=True)),
    )
    _require_no_rows(
        connection,
        sa.select(checkpoints.c.id)
        .join(sources, sources.c.id == checkpoints.c.source_id)
        .join(runs, runs.c.id == checkpoints.c.advanced_by_run_id)
        .where(
            sa.or_(
                checkpoints.c.scope_kind != "source",
                checkpoints.c.partition_key.is_not(None),
                checkpoints.c.checkpoint_name != "legacy_default",
                checkpoints.c.version != 1,
                checkpoints.c.previous_checkpoint_id.is_not(None),
                checkpoints.c.checkpoint_value != sources.c.checkpoint_value,
                runs.c.source_id != checkpoints.c.source_id,
                runs.c.status != "success",
                checkpoints.c.persistence_committed_at != runs.c.completed_at,
                checkpoints.c.committed_at != runs.c.completed_at,
            )
        ),
        "target_only_checkpoint_history",
    )
    watermarks = _table(
        "source_watermarks",
        sa.column("id", sa.BigInteger()),
        sa.column("source_id", sa.BigInteger()),
        sa.column("scope_kind", sa.String(20)),
        sa.column("partition_key", sa.String(160)),
        sa.column("watermark_name", sa.String(80)),
        sa.column("version", sa.BigInteger()),
        sa.column("watermark_value", sa.DateTime(timezone=True)),
        sa.column("previous_watermark_id", sa.BigInteger()),
        sa.column("advanced_by_run_id", sa.BigInteger()),
        sa.column("persistence_committed_at", sa.DateTime(timezone=True)),
        sa.column("committed_at", sa.DateTime(timezone=True)),
    )
    _require_no_rows(
        connection,
        sa.select(watermarks.c.id)
        .join(sources, sources.c.id == watermarks.c.source_id)
        .join(runs, runs.c.id == watermarks.c.advanced_by_run_id)
        .where(
            sa.or_(
                watermarks.c.scope_kind != "source",
                watermarks.c.partition_key.is_not(None),
                watermarks.c.watermark_name != "legacy_default",
                watermarks.c.version != 1,
                watermarks.c.previous_watermark_id.is_not(None),
                watermarks.c.watermark_value != sources.c.last_successful_fetch_at,
                runs.c.source_id != watermarks.c.source_id,
                runs.c.status != "success",
                watermarks.c.persistence_committed_at != runs.c.completed_at,
                watermarks.c.committed_at != runs.c.completed_at,
            )
        ),
        "target_only_watermark_history",
    )


def downgrade() -> None:
    connection = op.get_bind()
    _validate_downgrade(connection)

    for index_name in (
        "ix_audit_events_correlation_id",
        "ix_audit_events_action_occurred_at_desc",
        "ix_audit_events_actor_ref_occurred_at_desc",
        "ix_audit_events_occurred_at_id_desc",
    ):
        op.drop_index(index_name, table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_constraint(
        "ck_ingestion_errors_error_type_format", "ingestion_errors", type_="check"
    )
    op.drop_constraint(
        "ck_ingestion_errors_diagnostic_fingerprint_format",
        "ingestion_errors",
        type_="check",
    )
    op.drop_constraint(
        "ck_ingestion_errors_retry_count_bounded",
        "ingestion_errors",
        type_="check",
    )
    op.create_check_constraint(
        "ck_ingestion_errors_retry_count_non_negative",
        "ingestion_errors",
        "retry_count >= 0",
    )
    op.drop_column("ingestion_errors", "safe_context")
    op.drop_column("ingestion_errors", "diagnostic_fingerprint")
    op.drop_column("ingestion_errors", "failure_stage")

    op.drop_constraint(
        "fk_source_rate_limit_states_run_source",
        "source_rate_limit_states",
        type_="foreignkey",
    )
    op.drop_index(
        "ix_quarantined_records_status_quarantined_at_id",
        table_name="quarantined_records",
    )
    op.drop_table("quarantined_records")
    for index_name in (
        "uq_source_watermarks_partition_identity_version",
        "uq_source_watermarks_source_identity_version",
    ):
        op.drop_index(index_name, table_name="source_watermarks")
    op.drop_table("source_watermarks")
    for index_name in (
        "uq_source_checkpoints_partition_identity_version",
        "uq_source_checkpoints_source_identity_version",
    ):
        op.drop_index(index_name, table_name="source_checkpoints")
    op.drop_table("source_checkpoints")
    op.drop_table("ingestion_run_events")

    op.drop_constraint(
        "ck_ingestion_runs_status_time_consistency", "ingestion_runs", type_="check"
    )
    op.drop_constraint(
        "ck_ingestion_runs_status_allowed", "ingestion_runs", type_="check"
    )
    op.drop_constraint(
        "ck_ingestion_runs_state_version_positive", "ingestion_runs", type_="check"
    )
    op.drop_constraint(
        "ck_ingestion_runs_operational_or_compatibility_shape",
        "ingestion_runs",
        type_="check",
    )
    op.drop_constraint(
        "ck_ingestion_runs_retry_lineage_consistency",
        "ingestion_runs",
        type_="check",
    )
    op.drop_constraint(
        "ck_ingestion_runs_attempt_number_bounded",
        "ingestion_runs",
        type_="check",
    )
    op.drop_constraint(
        "fk_ingestion_runs_retry_cycle", "ingestion_runs", type_="foreignkey"
    )
    op.drop_constraint(
        "fk_ingestion_runs_retry_source", "ingestion_runs", type_="foreignkey"
    )
    op.drop_constraint(
        op.f("fk_ingestion_runs_cycle_id_ingestion_cycles"),
        "ingestion_runs",
        type_="foreignkey",
    )
    op.drop_constraint(
        "uq_ingestion_runs_id_cycle_id", "ingestion_runs", type_="unique"
    )
    op.drop_constraint(
        "uq_ingestion_runs_id_source_id", "ingestion_runs", type_="unique"
    )
    op.drop_constraint(
        "uq_ingestion_runs_source_cycle_attempt", "ingestion_runs", type_="unique"
    )
    op.drop_constraint(
        "uq_ingestion_runs_idempotency_key", "ingestion_runs", type_="unique"
    )
    op.alter_column(
        "ingestion_runs",
        "status",
        existing_type=sa.String(30),
        type_=sa.String(40),
        existing_nullable=False,
    )
    runs = _run_table()
    connection.execute(
        sa.update(runs).where(runs.c.status == "success").values(status="succeeded")
    )
    connection.execute(
        sa.update(runs).where(runs.c.status == "cancelled").values(status="canceled")
    )
    op.create_check_constraint(
        "ck_ingestion_runs_status_allowed",
        "ingestion_runs",
        "status IN ('running', 'succeeded', 'partial', 'failed', 'canceled')",
    )
    for column_name in (
        "defer_reason",
        "state_version",
        "retry_of_run_id",
        "attempt_number",
        "idempotency_key",
        "cycle_id",
    ):
        op.drop_column("ingestion_runs", column_name)

    op.drop_index(
        "ix_source_rate_limit_states_non_available_backoff",
        table_name="source_rate_limit_states",
    )
    op.drop_table("source_rate_limit_states")
    op.drop_index(
        "ix_source_credential_references_state_source_id",
        table_name="source_credential_references",
    )
    op.drop_table("source_credential_references")
    op.drop_index(
        "ix_ingestion_cycles_status_started_at_id_desc",
        table_name="ingestion_cycles",
    )
    op.drop_table("ingestion_cycles")
