from datetime import UTC
from uuid import UUID

import pytest
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Identity,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import configure_mappers
from sqlalchemy.schema import CreateIndex, CreateTable

from app.db.base import Base


IMPLEMENTED_TABLES = {
    "audit_events",
    "indicator_provenances",
    "indicators",
    "ingestion_cycles",
    "ingestion_errors",
    "ingestion_run_records",
    "ingestion_runs",
    "ingestion_run_events",
    "intelligence_item_identifiers",
    "intelligence_item_indicators",
    "intelligence_item_tags",
    "intelligence_items",
    "intelligence_sources",
    "quarantined_records",
    "source_checkpoints",
    "source_credential_references",
    "source_rate_limit_states",
    "source_records",
    "source_watermarks",
    "tags",
    "vulnerabilities",
}
EXPECTED_MODEL_EXPORTS = {
    "AuditEvent",
    "IngestionCycle",
    "IngestionError",
    "IngestionRun",
    "IngestionRunEvent",
    "IngestionRunRecord",
    "Indicator",
    "IndicatorProvenance",
    "IntelligenceItem",
    "IntelligenceItemIdentifier",
    "IntelligenceItemIndicator",
    "IntelligenceItemTag",
    "IntelligenceSource",
    "QuarantinedRecord",
    "SourceCheckpoint",
    "SourceCredentialReference",
    "SourceRateLimitState",
    "SourceRecord",
    "SourceWatermark",
    "Tag",
    "Vulnerability",
}


@pytest.fixture(scope="module")
def models():
    import app.models

    return app.models


@pytest.fixture(scope="module")
def run_table(models):
    return Base.metadata.tables["ingestion_runs"]


@pytest.fixture(scope="module")
def run_record_table(models):
    return Base.metadata.tables["ingestion_run_records"]


@pytest.fixture(scope="module")
def error_table(models):
    return Base.metadata.tables["ingestion_errors"]


def check_constraint_sql(table):
    return {
        constraint.name: str(constraint.sqltext)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }


def foreign_key_by_column(table, column_name):
    constraints = [
        constraint
        for constraint in table.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    ]
    for constraint in sorted(constraints, key=lambda item: len(item.columns)):
        constrained = next(iter(constraint.columns)).name
        if constrained == column_name:
            return constraint
    raise AssertionError(f"missing FK for {table.name}.{column_name}")


def unique_single_columns(table):
    return {
        next(iter(constraint.columns)).name
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint) and len(constraint.columns) == 1
    }


def index_ddl(table, index_name):
    indexes = {index.name: index for index in table.indexes}
    return str(CreateIndex(indexes[index_name]).compile(dialect=postgresql.dialect()))


def assert_bigint_identity_primary_key(table):
    column = table.c.id
    assert isinstance(column.type, BigInteger)
    assert isinstance(column.identity, Identity)
    assert column.primary_key is True
    assert column.nullable is False


def assert_aware_timestamp_column(column, *, nullable):
    assert isinstance(column.type, DateTime)
    assert column.type.timezone is True
    assert column.nullable is nullable


def assert_callable_utc_default(column):
    assert column.default is not None
    assert column.default.is_callable is True
    assert column.default.arg(None).tzinfo is UTC


def test_registration_and_mapper_configuration_are_database_free(monkeypatch):
    import app.db.session as db_session
    import app.models

    monkeypatch.setattr(
        db_session,
        "get_engine",
        lambda: pytest.fail("model import must not request a database engine"),
    )

    assert set(Base.metadata.tables) == IMPLEMENTED_TABLES
    assert set(app.models.__all__) == EXPECTED_MODEL_EXPORTS

    configure_mappers()


def test_ingestion_run_columns_types_nullability_and_defaults(run_table):
    assert run_table.name == "ingestion_runs"
    assert list(run_table.c.keys()) == [
        "source_id",
        "cycle_id",
        "idempotency_key",
        "attempt_number",
        "retry_of_run_id",
        "state_version",
        "defer_reason",
        "trigger_type",
        "status",
        "started_at",
        "completed_at",
        "records_fetched",
        "records_created",
        "records_updated",
        "records_unchanged",
        "records_skipped",
        "records_failed",
        "error_count",
        "checkpoint_before",
        "checkpoint_after",
        "safe_summary",
        "created_at",
        "id",
        "public_id",
    ]
    assert "updated_at" not in run_table.c
    assert_bigint_identity_primary_key(run_table)

    public_id = run_table.c.public_id
    assert public_id.nullable is False
    assert public_id.unique is True
    assert public_id.default.is_callable is True
    generated_public_id = public_id.default.arg(None)
    assert isinstance(generated_public_id, UUID)
    assert generated_public_id.version == 4

    expected_strings = {
        "trigger_type": (40, False),
        "status": (30, False),
        "idempotency_key": (240, True),
        "defer_reason": (80, True),
        "checkpoint_before": (500, True),
        "checkpoint_after": (500, True),
        "safe_summary": (1000, True),
    }
    for column_name, (length, nullable) in expected_strings.items():
        column = run_table.c[column_name]
        assert isinstance(column.type, String)
        assert column.type.length == length
        assert column.nullable is nullable

    for column_name in (
        "records_fetched",
        "records_created",
        "records_updated",
        "records_unchanged",
        "records_skipped",
        "records_failed",
        "error_count",
    ):
        column = run_table.c[column_name]
        assert isinstance(column.type, Integer)
        assert column.nullable is False
        assert column.default is None

    assert isinstance(run_table.c.attempt_number.type, SmallInteger)
    assert run_table.c.attempt_number.nullable is True
    assert run_table.c.attempt_number.default is None
    assert isinstance(run_table.c.state_version.type, Integer)
    assert run_table.c.state_version.nullable is True
    assert run_table.c.state_version.default is None
    assert run_table.c.cycle_id.nullable is True

    for column_name in ("started_at", "created_at"):
        assert_aware_timestamp_column(run_table.c[column_name], nullable=False)
        assert_callable_utc_default(run_table.c[column_name])
    assert_aware_timestamp_column(run_table.c.completed_at, nullable=True)
    assert run_table.c.completed_at.default is None


def test_ingestion_run_foreign_keys_constraints_and_indexes(run_table):
    source_fk = foreign_key_by_column(run_table, "source_id")
    source_element = next(iter(source_fk.elements))
    assert source_element.target_fullname == "intelligence_sources.id"
    assert source_element.ondelete == "RESTRICT"

    checks = check_constraint_sql(run_table)
    assert {
        "ck_ingestion_runs_trigger_type_allowed",
        "ck_ingestion_runs_status_allowed",
        "ck_ingestion_runs_completed_at_order",
        "ck_ingestion_runs_counters_non_negative",
        "ck_ingestion_runs_attempt_number_bounded",
        "ck_ingestion_runs_retry_lineage_consistency",
        "ck_ingestion_runs_operational_or_compatibility_shape",
        "ck_ingestion_runs_status_time_consistency",
        "ck_ingestion_runs_state_version_positive",
    } <= set(checks)
    assert "trigger_type IN" in checks["ck_ingestion_runs_trigger_type_allowed"]
    assert "status IN" in checks["ck_ingestion_runs_status_allowed"]
    assert "completed_at >= started_at" in checks[
        "ck_ingestion_runs_completed_at_order"
    ]
    counter_check = checks["ck_ingestion_runs_counters_non_negative"]
    for column_name in (
        "records_fetched",
        "records_created",
        "records_updated",
        "records_unchanged",
        "records_skipped",
        "records_failed",
        "error_count",
    ):
        assert f"{column_name} >= 0" in counter_check

    assert {index.name for index in run_table.indexes} == {
        "ix_ingestion_runs_source_id_started_at_id_desc",
        "ix_ingestion_runs_started_at_id_desc",
        "ix_ingestion_runs_status_started_at_desc",
    }
    assert "source_id" in index_ddl(
        run_table,
        "ix_ingestion_runs_source_id_started_at_id_desc",
    )
    assert "started_at DESC, id DESC" in index_ddl(
        run_table,
        "ix_ingestion_runs_source_id_started_at_id_desc",
    )
    assert "started_at DESC, id DESC" in index_ddl(
        run_table,
        "ix_ingestion_runs_started_at_id_desc",
    )
    assert "status" in index_ddl(run_table, "ix_ingestion_runs_status_started_at_desc")
    for index in run_table.indexes:
        assert "started_at DESC" in str(
            CreateIndex(index).compile(dialect=postgresql.dialect())
        )


def test_ingestion_run_record_columns_types_nullability_and_defaults(
    run_record_table,
):
    assert run_record_table.name == "ingestion_run_records"
    assert list(run_record_table.c.keys()) == [
        "ingestion_run_id",
        "source_record_id",
        "intelligence_item_id",
        "action",
        "safe_detail",
        "processed_at",
        "id",
    ]
    assert "public_id" not in run_record_table.c
    assert "created_at" not in run_record_table.c
    assert "updated_at" not in run_record_table.c
    assert_bigint_identity_primary_key(run_record_table)

    action = run_record_table.c.action
    assert isinstance(action.type, String)
    assert action.type.length == 40
    assert action.nullable is False
    assert isinstance(run_record_table.c.safe_detail.type, String)
    assert run_record_table.c.safe_detail.type.length == 1000
    assert run_record_table.c.safe_detail.nullable is True
    assert_aware_timestamp_column(run_record_table.c.processed_at, nullable=False)
    assert_callable_utc_default(run_record_table.c.processed_at)


def test_ingestion_run_record_foreign_keys_constraints_and_indexes(
    run_record_table,
):
    expected_fks = {
        "ingestion_run_id": ("ingestion_runs.id", "CASCADE", False),
        "source_record_id": ("source_records.id", "SET NULL", True),
        "intelligence_item_id": ("intelligence_items.id", "SET NULL", True),
    }
    for column_name, (target, ondelete, nullable) in expected_fks.items():
        constraint = foreign_key_by_column(run_record_table, column_name)
        element = next(iter(constraint.elements))
        assert element.target_fullname == target
        assert element.ondelete == ondelete
        assert run_record_table.c[column_name].nullable is nullable

    checks = check_constraint_sql(run_record_table)
    assert "ck_ingestion_run_records_action_allowed" in checks
    assert "action IN" in checks["ck_ingestion_run_records_action_allowed"]

    assert {index.name for index in run_record_table.indexes} == {
        "ix_ingestion_run_records_run_id_action",
        "uq_ingestion_run_records_run_source_record",
    }
    unique_ddl = index_ddl(
        run_record_table,
        "uq_ingestion_run_records_run_source_record",
    )
    assert "UNIQUE" in unique_ddl
    assert "(ingestion_run_id, source_record_id)" in unique_ddl
    assert "WHERE source_record_id IS NOT NULL" in unique_ddl

    action_ddl = index_ddl(run_record_table, "ix_ingestion_run_records_run_id_action")
    assert "(ingestion_run_id, action)" in action_ddl
    assert "UNIQUE" not in action_ddl


def test_ingestion_error_columns_types_nullability_and_defaults(error_table):
    assert error_table.name == "ingestion_errors"
    assert list(error_table.c.keys()) == [
        "ingestion_run_id",
        "ingestion_run_record_id",
        "source_record_id",
        "error_type",
        "safe_message",
        "failure_stage",
        "diagnostic_fingerprint",
        "safe_context",
        "retryable",
        "retry_count",
        "occurred_at",
        "id",
    ]
    assert "public_id" not in error_table.c
    assert "created_at" not in error_table.c
    assert "updated_at" not in error_table.c
    assert_bigint_identity_primary_key(error_table)

    expected_strings = {
        "error_type": (80, False),
        "safe_message": (1000, False),
        "failure_stage": (40, True),
        "diagnostic_fingerprint": (64, True),
        "safe_context": (1000, True),
    }
    for column_name, (length, nullable) in expected_strings.items():
        column = error_table.c[column_name]
        assert isinstance(column.type, String)
        assert column.type.length == length
        assert column.nullable is nullable

    retryable = error_table.c.retryable
    assert isinstance(retryable.type, Boolean)
    assert retryable.nullable is False
    assert retryable.default.arg is False

    retry_count = error_table.c.retry_count
    assert isinstance(retry_count.type, Integer)
    assert retry_count.nullable is False
    assert retry_count.default is None

    assert_aware_timestamp_column(error_table.c.occurred_at, nullable=False)
    assert_callable_utc_default(error_table.c.occurred_at)


def test_ingestion_error_foreign_keys_constraints_and_indexes(error_table):
    expected_fks = {
        "ingestion_run_id": ("ingestion_runs.id", "CASCADE", False),
        "ingestion_run_record_id": ("ingestion_run_records.id", "SET NULL", True),
        "source_record_id": ("source_records.id", "SET NULL", True),
    }
    for column_name, (target, ondelete, nullable) in expected_fks.items():
        constraint = foreign_key_by_column(error_table, column_name)
        element = next(iter(constraint.elements))
        assert element.target_fullname == target
        assert element.ondelete == ondelete
        assert error_table.c[column_name].nullable is nullable

    checks = check_constraint_sql(error_table)
    assert set(checks) == {
        "ck_ingestion_errors_retry_count_bounded",
        "ck_ingestion_errors_diagnostic_fingerprint_format",
        "ck_ingestion_errors_error_type_format",
    }
    assert "BETWEEN 0 AND 10" in checks["ck_ingestion_errors_retry_count_bounded"]

    assert {index.name for index in error_table.indexes} == {
        "ix_ingestion_errors_run_id_occurred_at_desc"
    }
    error_index_ddl = index_ddl(
        error_table,
        "ix_ingestion_errors_run_id_occurred_at_desc",
    )
    assert "(ingestion_run_id, occurred_at DESC)" in error_index_ddl
    assert "UNIQUE" not in error_index_ddl


def test_ingestion_relationships_and_cascades(models):
    run_mapper = models.IngestionRun.__mapper__
    record_mapper = models.IngestionRunRecord.__mapper__
    error_mapper = models.IngestionError.__mapper__
    event_mapper = models.IngestionRunEvent.__mapper__
    source_mapper = models.IntelligenceSource.__mapper__
    item_mapper = models.IntelligenceItem.__mapper__
    source_record_mapper = models.SourceRecord.__mapper__

    assert run_mapper.relationships["source"].back_populates == "ingestion_runs"
    assert source_mapper.relationships["ingestion_runs"].back_populates == "source"
    assert source_mapper.relationships["ingestion_runs"].cascade.delete is False
    assert source_mapper.relationships["ingestion_runs"].passive_deletes is True

    assert run_mapper.relationships["records"].back_populates == "ingestion_run"
    assert run_mapper.relationships["records"].cascade.delete_orphan is True
    assert run_mapper.relationships["records"].passive_deletes is True
    assert record_mapper.relationships["ingestion_run"].back_populates == "records"

    assert run_mapper.relationships["errors"].back_populates == "ingestion_run"
    assert run_mapper.relationships["errors"].cascade.delete_orphan is True
    assert run_mapper.relationships["errors"].passive_deletes is True
    assert error_mapper.relationships["ingestion_run"].back_populates == "errors"

    run_events = run_mapper.relationships["events"]
    assert run_events.back_populates == "ingestion_run"
    assert run_events.passive_deletes is True
    assert run_events.cascade.save_update is True
    assert run_events.cascade.merge is True
    assert run_events.cascade.delete is False
    assert run_events.cascade.delete_orphan is False
    assert event_mapper.relationships["ingestion_run"].back_populates == "events"

    assert record_mapper.relationships["source_record"].back_populates == (
        "ingestion_run_records"
    )
    source_record_run_records = source_record_mapper.relationships[
        "ingestion_run_records"
    ]
    assert source_record_run_records.cascade.delete is False
    assert source_record_run_records.passive_deletes is True
    assert record_mapper.relationships["intelligence_item"].back_populates == (
        "ingestion_run_records"
    )
    assert item_mapper.relationships["ingestion_run_records"].cascade.delete is False
    assert item_mapper.relationships["ingestion_run_records"].passive_deletes is True

    assert record_mapper.relationships["errors"].back_populates == (
        "ingestion_run_record"
    )
    assert record_mapper.relationships["errors"].cascade.delete is False
    assert record_mapper.relationships["errors"].passive_deletes is True
    assert error_mapper.relationships["source_record"].back_populates == (
        "ingestion_errors"
    )
    source_record_errors = source_record_mapper.relationships["ingestion_errors"]
    assert source_record_errors.cascade.delete is False
    assert source_record_errors.passive_deletes is True


def test_postgresql_ddl_compilation_for_ingestion_tables_without_connection(
    run_table,
    run_record_table,
    error_table,
):
    dialect = postgresql.dialect()

    for table in (run_table, run_record_table, error_table):
        ddl = str(CreateTable(table).compile(dialect=dialect))
        assert "BIGINT GENERATED" in ddl
        assert "TIMESTAMP WITH TIME ZONE" in ddl
        for index in table.indexes:
            index_ddl_text = str(CreateIndex(index).compile(dialect=dialect))
            if index.unique:
                assert "UNIQUE" in index_ddl_text
            if index.name.startswith("uq_"):
                assert "WHERE" in index_ddl_text

    run_ddl = str(CreateTable(run_table).compile(dialect=dialect))
    assert "UUID" in run_ddl
    assert "ON DELETE RESTRICT" in run_ddl

    run_record_ddl = str(CreateTable(run_record_table).compile(dialect=dialect))
    assert "ON DELETE CASCADE" in run_record_ddl
    assert "ON DELETE SET NULL" in run_record_ddl

    error_ddl = str(CreateTable(error_table).compile(dialect=dialect))
    assert "ON DELETE CASCADE" in error_ddl
    assert "ON DELETE SET NULL" in error_ddl


def test_ingestion_models_do_not_define_unsafe_repr_or_extra_uniques(models):
    assert "__repr__" not in models.IngestionRun.__dict__
    assert "__repr__" not in models.IngestionRunRecord.__dict__
    assert "__repr__" not in models.IngestionError.__dict__

    run_table = Base.metadata.tables["ingestion_runs"]
    assert unique_single_columns(run_table) == {"public_id", "idempotency_key"}
    assert unique_single_columns(Base.metadata.tables["ingestion_run_records"]) == set()
    assert unique_single_columns(Base.metadata.tables["ingestion_errors"]) == set()
