from datetime import UTC
import inspect
from uuid import UUID

import pytest
from sqlalchemy import (
    BigInteger,
    CHAR,
    CheckConstraint,
    create_engine,
    DateTime,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import configure_mappers, Session
from sqlalchemy.schema import CreateIndex, CreateTable

from app.db.base import Base


TARGET_TABLES = {
    "audit_events",
    "auth_identities",
    "auth_local_credentials",
    "auth_login_throttles",
    "auth_sessions",
    "auth_user_roles",
    "auth_users",
    "indicator_provenances",
    "indicators",
    "ingestion_cycles",
    "ingestion_errors",
    "ingestion_run_events",
    "ingestion_run_records",
    "ingestion_runs",
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
    "threat_entities",
    "threat_entity_aliases",
    "threat_relationships",
    "vulnerabilities",
}
MODEL_EXPORTS = {
    "AuditEvent",
    "AuthIdentity",
    "AuthLocalCredential",
    "AuthLoginThrottle",
    "AuthSession",
    "AuthUser",
    "AuthUserRole",
    "Indicator",
    "IndicatorProvenance",
    "IngestionCycle",
    "IngestionError",
    "IngestionRun",
    "IngestionRunEvent",
    "IngestionRunRecord",
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
    "ThreatEntity",
    "ThreatEntityAlias",
    "ThreatRelationship",
    "Vulnerability",
}
OPERATIONAL_TABLES = {
    "audit_events",
    "ingestion_cycles",
    "ingestion_run_events",
    "quarantined_records",
    "source_checkpoints",
    "source_credential_references",
    "source_rate_limit_states",
    "source_watermarks",
}


@pytest.fixture(scope="module")
def models():
    import app.models

    return app.models


def _checks(table_name):
    return {
        constraint.name: str(constraint.sqltext)
        for constraint in Base.metadata.tables[table_name].constraints
        if isinstance(constraint, CheckConstraint)
    }


def _unique_names(table_name):
    table = Base.metadata.tables[table_name]
    return {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    } | {index.name for index in table.indexes if index.unique}


def _fk(table_name, name):
    return next(
        constraint
        for constraint in Base.metadata.tables[table_name].constraints
        if isinstance(constraint, ForeignKeyConstraint) and constraint.name == name
    )


def test_exact_registration_exports_and_mapper_configuration_are_database_free(
    models, monkeypatch
):
    import app.db.session as db_session

    monkeypatch.setattr(
        db_session,
        "get_engine",
        lambda: pytest.fail("model registration must not open a database connection"),
    )
    assert set(Base.metadata.tables) == TARGET_TABLES
    assert len(Base.metadata.tables) == 30
    assert set(models.__all__) == MODEL_EXPORTS
    assert len(models.__all__) == 30
    configure_mappers()


def test_run_event_foreign_key_preserves_whole_parent_retention_behavior(models):
    event_table = Base.metadata.tables["ingestion_run_events"]
    column = event_table.c.ingestion_run_id
    assert column.nullable is False
    assert len(column.foreign_keys) == 1
    foreign_key = next(iter(column.foreign_keys))
    assert foreign_key.target_fullname == "ingestion_runs.id"
    # CASCADE is reserved for approved deletion of the complete parent run;
    # collection disassociation must never be interpreted as evidence deletion.
    assert foreign_key.ondelete == "CASCADE"


def test_run_event_collection_disassociation_cannot_silently_delete_evidence(models):
    source_table = Base.metadata.tables["intelligence_sources"]
    run_table = Base.metadata.tables["ingestion_runs"]
    event_table = Base.metadata.tables["ingestion_run_events"]
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[source_table, run_table, event_table],
    )

    try:
        with Session(engine) as session:
            source = models.IntelligenceSource(
                id=1,
                name="Append-only regression source",
                slug="append-only-regression-source",
                source_type="json",
            )
            run = models.IngestionRun(
                id=1,
                source=source,
                trigger_type="manual",
                status="running",
                records_fetched=0,
                records_created=0,
                records_updated=0,
                records_unchanged=0,
                records_skipped=0,
                records_failed=0,
                error_count=0,
            )
            session.add(run)
            session.commit()

            run_event = models.IngestionRunEvent(
                id=1,
                sequence_number=1,
                event_type="started",
            )
            run.events.append(run_event)
            session.commit()

            assert session.get(models.IngestionRunEvent, run_event.id) is run_event
            assert run_event.ingestion_run_id == run.id

            run.events.remove(run_event)
            with pytest.raises(IntegrityError):
                session.flush()
            session.rollback()

            preserved_event = session.get(models.IngestionRunEvent, 1)
            assert preserved_event is not None
            assert preserved_event.ingestion_run_id == 1
            assert session.get(models.IngestionRun, 1) is not None
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("table_name", "columns"),
    [
        (
            "ingestion_cycles",
            [
                "idempotency_key", "trigger_type", "status", "scheduled_for",
                "started_at", "completed_at", "sources_expected",
                "sources_started", "sources_completed", "sources_successful",
                "sources_non_successful", "safe_summary", "created_at", "id",
                "public_id",
            ],
        ),
        (
            "ingestion_run_events",
            [
                "ingestion_run_id", "sequence_number", "event_type",
                "from_status", "to_status", "safe_message", "occurred_at",
                "created_at", "id",
            ],
        ),
        (
            "source_checkpoints",
            [
                "source_id", "scope_kind", "partition_key", "checkpoint_name",
                "version", "checkpoint_value", "previous_checkpoint_id",
                "advanced_by_run_id", "persistence_committed_at", "committed_at",
                "id",
            ],
        ),
        (
            "source_watermarks",
            [
                "source_id", "scope_kind", "partition_key", "watermark_name",
                "version", "watermark_value", "previous_watermark_id",
                "advanced_by_run_id", "persistence_committed_at", "committed_at",
                "id",
            ],
        ),
        (
            "source_rate_limit_states",
            [
                "source_id", "policy_key", "request_limit", "remaining",
                "window_seconds", "reset_at", "backoff_until", "last_observed_at",
                "state", "state_version", "updated_by_run_id", "updated_at", "id",
            ],
        ),
        (
            "quarantined_records",
            [
                "source_id", "ingestion_run_id", "ingestion_run_event_id",
                "quarantine_key", "reason_code", "safe_excerpt", "safe_metadata",
                "original_byte_count", "stored_byte_count", "status",
                "quarantined_at", "reviewed_at", "id", "public_id",
            ],
        ),
        (
            "audit_events",
            [
                "idempotency_key", "actor_type", "actor_ref", "action",
                "target_type", "target_ref", "outcome", "cycle_id",
                "ingestion_run_id", "correlation_id", "safe_detail", "occurred_at",
                "created_at", "id", "public_id",
            ],
        ),
        (
            "source_credential_references",
            [
                "source_id", "reference_name", "purpose", "external_reference_id",
                "configuration_state", "owner_ref", "last_rotated_at", "expires_at",
                "created_at", "updated_at", "id",
            ],
        ),
    ],
)
def test_new_table_column_order_is_exact(models, table_name, columns):
    assert list(Base.metadata.tables[table_name].c) == [
        Base.metadata.tables[table_name].c[name] for name in columns
    ]


@pytest.mark.parametrize(
    ("table_name", "column_name", "type_class", "length", "nullable"),
    [
        ("ingestion_cycles", "idempotency_key", String, 200, False),
        ("ingestion_cycles", "trigger_type", String, 20, False),
        ("ingestion_cycles", "status", String, 30, False),
        ("ingestion_run_events", "event_type", String, 60, False),
        ("ingestion_run_events", "safe_message", String, 1000, True),
        ("source_checkpoints", "partition_key", String, 160, True),
        ("source_checkpoints", "checkpoint_value", String, 500, False),
        ("source_watermarks", "watermark_name", String, 80, False),
        ("source_rate_limit_states", "policy_key", String, 80, False),
        ("quarantined_records", "quarantine_key", String, 64, False),
        ("quarantined_records", "safe_metadata", String, 2000, True),
        ("audit_events", "idempotency_key", String, 240, False),
        ("audit_events", "target_ref", String, 240, False),
        ("source_credential_references", "external_reference_id", String, 240, True),
    ],
)
def test_exact_string_types_lengths_and_nullability(
    models, table_name, column_name, type_class, length, nullable
):
    column = Base.metadata.tables[table_name].c[column_name]
    assert isinstance(column.type, type_class)
    assert column.type.length == length
    assert column.nullable is nullable


def test_identity_public_id_timestamp_and_extension_defaults(models):
    for table_name in OPERATIONAL_TABLES:
        table = Base.metadata.tables[table_name]
        assert isinstance(table.c.id.type, BigInteger)
        assert isinstance(table.c.id.identity, Identity)
        if "public_id" in table.c:
            value = table.c.public_id.default.arg(None)
            assert isinstance(value, UUID)
            assert value.version == 4
        for name in (
            "scheduled_for", "started_at", "completed_at", "occurred_at",
            "created_at", "updated_at", "watermark_value",
            "persistence_committed_at", "committed_at", "reset_at",
            "backoff_until", "last_observed_at", "quarantined_at", "reviewed_at",
            "last_rotated_at", "expires_at",
        ):
            if name in table.c:
                assert isinstance(table.c[name].type, DateTime)
                assert table.c[name].type.timezone is True

    run = Base.metadata.tables["ingestion_runs"]
    assert isinstance(run.c.attempt_number.type, SmallInteger)
    assert run.c.attempt_number.nullable is True
    assert run.c.attempt_number.default is None
    assert isinstance(run.c.state_version.type, Integer)
    assert run.c.state_version.nullable is True
    assert run.c.state_version.default is None
    assert run.c.cycle_id.nullable is True
    assert run.c.idempotency_key.nullable is True
    assert run.c.cycle_id.default is None
    assert run.c.idempotency_key.default is None
    assert isinstance(
        Base.metadata.tables["quarantined_records"].c.quarantine_key.type, CHAR
    )
    assert isinstance(
        Base.metadata.tables["ingestion_errors"].c.diagnostic_fingerprint.type,
        CHAR,
    )


EXPECTED_CHECKS = {
    "ingestion_cycles": {
        "ck_ingestion_cycles_trigger_type_allowed",
        "ck_ingestion_cycles_trigger_schedule_consistency",
        "ck_ingestion_cycles_status_allowed",
        "ck_ingestion_cycles_status_time_consistency",
        "ck_ingestion_cycles_completed_at_order",
        "ck_ingestion_cycles_counters_non_negative",
        "ck_ingestion_cycles_counter_relationships",
    },
    "ingestion_runs": {
        "ck_ingestion_runs_attempt_number_bounded",
        "ck_ingestion_runs_retry_lineage_consistency",
        "ck_ingestion_runs_operational_or_compatibility_shape",
        "ck_ingestion_runs_status_allowed",
        "ck_ingestion_runs_status_time_consistency",
        "ck_ingestion_runs_state_version_positive",
    },
    "ingestion_run_events": {
        "ck_ingestion_run_events_sequence_bounded",
        "ck_ingestion_run_events_event_type_allowed",
        "ck_ingestion_run_events_transition_shape",
        "ck_ingestion_run_events_created_at_order",
    },
    "source_checkpoints": {
        "ck_source_checkpoints_scope_identity",
        "ck_source_checkpoints_version_positive",
        "ck_source_checkpoints_commit_order",
    },
    "source_watermarks": {
        "ck_source_watermarks_scope_identity",
        "ck_source_watermarks_version_positive",
        "ck_source_watermarks_commit_order",
    },
    "source_rate_limit_states": {
        "ck_source_rate_limit_states_counts_valid",
        "ck_source_rate_limit_states_window_bounded",
        "ck_source_rate_limit_states_version_positive",
        "ck_source_rate_limit_states_state_allowed",
    },
    "ingestion_errors": {
        "ck_ingestion_errors_retry_count_bounded",
        "ck_ingestion_errors_diagnostic_fingerprint_format",
        "ck_ingestion_errors_error_type_format",
    },
    "quarantined_records": {
        "ck_quarantined_records_key_format",
        "ck_quarantined_records_sizes_bounded",
        "ck_quarantined_records_status_allowed",
        "ck_quarantined_records_reviewed_at_consistency",
    },
    "audit_events": {
        "ck_audit_events_run_cycle_consistency",
        "ck_audit_events_actor_type_allowed",
        "ck_audit_events_action_format",
        "ck_audit_events_target_type_format",
        "ck_audit_events_target_ref_length",
        "ck_audit_events_outcome_allowed",
        "ck_audit_events_created_at_order",
    },
    "source_credential_references": {
        "ck_source_credential_references_state_allowed",
        "ck_source_credential_references_configured_shape",
        "ck_source_credential_references_rotation_expiry_order",
        "ck_source_credential_references_updated_at_order",
    },
}


@pytest.mark.parametrize("table_name", sorted(EXPECTED_CHECKS))
def test_named_check_manifest(models, table_name):
    assert EXPECTED_CHECKS[table_name] <= set(_checks(table_name))


EXPECTED_UNIQUES = {
    "ingestion_cycles": {"uq_ingestion_cycles_idempotency_key"},
    "ingestion_runs": {
        "uq_ingestion_runs_idempotency_key",
        "uq_ingestion_runs_source_cycle_attempt",
        "uq_ingestion_runs_id_source_id",
        "uq_ingestion_runs_id_cycle_id",
    },
    "ingestion_run_events": {
        "uq_ingestion_run_events_run_sequence",
        "uq_ingestion_run_events_id_run_id",
    },
    "source_checkpoints": {
        "uq_source_checkpoints_source_identity_version",
        "uq_source_checkpoints_partition_identity_version",
        "uq_source_checkpoints_id_source_id",
        "uq_source_checkpoints_previous",
    },
    "source_watermarks": {
        "uq_source_watermarks_source_identity_version",
        "uq_source_watermarks_partition_identity_version",
        "uq_source_watermarks_id_source_id",
        "uq_source_watermarks_previous",
    },
    "source_rate_limit_states": {"uq_source_rate_limit_states_source_policy"},
    "quarantined_records": {"uq_quarantined_records_run_key"},
    "audit_events": {"uq_audit_events_idempotency_key"},
    "source_credential_references": {
        "uq_source_credential_references_source_name_purpose"
    },
}


@pytest.mark.parametrize("table_name", sorted(EXPECTED_UNIQUES))
def test_named_unique_manifest(models, table_name):
    assert EXPECTED_UNIQUES[table_name] <= _unique_names(table_name)


COMPOSITE_FKS = [
    ("ingestion_runs", "fk_ingestion_runs_retry_source", ("retry_of_run_id", "source_id"), ("ingestion_runs.id", "ingestion_runs.source_id"), "RESTRICT"),
    ("ingestion_runs", "fk_ingestion_runs_retry_cycle", ("retry_of_run_id", "cycle_id"), ("ingestion_runs.id", "ingestion_runs.cycle_id"), "RESTRICT"),
    ("source_checkpoints", "fk_source_checkpoints_advanced_run_source", ("advanced_by_run_id", "source_id"), ("ingestion_runs.id", "ingestion_runs.source_id"), "RESTRICT"),
    ("source_checkpoints", "fk_source_checkpoints_previous_source", ("previous_checkpoint_id", "source_id"), ("source_checkpoints.id", "source_checkpoints.source_id"), "RESTRICT"),
    ("source_watermarks", "fk_source_watermarks_advanced_run_source", ("advanced_by_run_id", "source_id"), ("ingestion_runs.id", "ingestion_runs.source_id"), "RESTRICT"),
    ("source_watermarks", "fk_source_watermarks_previous_source", ("previous_watermark_id", "source_id"), ("source_watermarks.id", "source_watermarks.source_id"), "RESTRICT"),
    ("source_rate_limit_states", "fk_source_rate_limit_states_run_source", ("updated_by_run_id", "source_id"), ("ingestion_runs.id", "ingestion_runs.source_id"), "RESTRICT"),
    ("quarantined_records", "fk_quarantined_records_run_source", ("ingestion_run_id", "source_id"), ("ingestion_runs.id", "ingestion_runs.source_id"), "RESTRICT"),
    ("quarantined_records", "fk_quarantined_records_event_run", ("ingestion_run_event_id", "ingestion_run_id"), ("ingestion_run_events.id", "ingestion_run_events.ingestion_run_id"), "RESTRICT"),
    ("audit_events", "fk_audit_events_run_cycle", ("ingestion_run_id", "cycle_id"), ("ingestion_runs.id", "ingestion_runs.cycle_id"), "SET NULL"),
]


@pytest.mark.parametrize(("table_name", "name", "columns", "targets", "ondelete"), COMPOSITE_FKS)
def test_composite_fk_columns_targets_and_deletion(models, table_name, name, columns, targets, ondelete):
    constraint = _fk(table_name, name)
    assert tuple(column.name for column in constraint.columns) == columns
    assert tuple(element.target_fullname for element in constraint.elements) == targets
    assert {element.ondelete for element in constraint.elements} == {ondelete}


def test_partial_progress_indexes_have_exact_postgresql_predicates(models):
    expected = {
        "uq_source_checkpoints_source_identity_version": "scope_kind = 'source' AND partition_key IS NULL",
        "uq_source_checkpoints_partition_identity_version": "scope_kind = 'partition' AND partition_key IS NOT NULL",
        "uq_source_watermarks_source_identity_version": "scope_kind = 'source' AND partition_key IS NULL",
        "uq_source_watermarks_partition_identity_version": "scope_kind = 'partition' AND partition_key IS NOT NULL",
    }
    indexes = {
        index.name: index
        for table_name in ("source_checkpoints", "source_watermarks")
        for index in Base.metadata.tables[table_name].indexes
    }
    for name, predicate in expected.items():
        ddl = str(CreateIndex(indexes[name]).compile(dialect=postgresql.dialect()))
        assert "UNIQUE" in ddl
        assert f"WHERE {predicate}" in ddl
    assert not any("latest" in index.name for index in indexes.values())


def test_exact_vocabulary_constants_and_constraint_sql(models):
    from app.models.audit_event import AUDIT_ACTOR_TYPE_VALUES, AUDIT_OUTCOME_VALUES
    from app.models.ingestion_cycle import (
        INGESTION_CYCLE_STATUS_VALUES,
        INGESTION_CYCLE_TRIGGER_TYPE_VALUES,
    )
    from app.models.ingestion_run import (
        INGESTION_RUN_COMPATIBILITY_STATUS_VALUES,
        INGESTION_RUN_STATUS_VALUES,
        INGESTION_RUN_TARGET_STATUS_VALUES,
    )
    from app.models.ingestion_run_event import INGESTION_RUN_EVENT_TYPE_VALUES
    from app.models.quarantined_record import QUARANTINED_RECORD_STATUS_VALUES
    from app.models.source_credential_reference import CREDENTIAL_CONFIGURATION_STATE_VALUES
    from app.models.source_rate_limit_state import SOURCE_RATE_LIMIT_STATE_VALUES

    assert INGESTION_CYCLE_TRIGGER_TYPE_VALUES == ("scheduled", "manual", "legacy_import")
    assert INGESTION_CYCLE_STATUS_VALUES == ("running", "success", "partial", "failed", "cancelled")
    assert INGESTION_RUN_TARGET_STATUS_VALUES == (
        "running", "checkpoint_pending", "success", "no_change", "skipped",
        "deferred_quota", "approval_pending", "disabled", "credentials_missing",
        "licence_required", "rate_limited", "partial", "failed", "cancelled",
    )
    assert INGESTION_RUN_COMPATIBILITY_STATUS_VALUES == (
        "running", "succeeded", "partial", "failed", "canceled",
    )
    assert INGESTION_RUN_STATUS_VALUES == (
        *INGESTION_RUN_TARGET_STATUS_VALUES,
        "succeeded",
        "canceled",
    )
    assert INGESTION_RUN_EVENT_TYPE_VALUES == (
        "acquired", "started", "persistence_committed", "checkpoint_advanced",
        "completed", "skipped", "deferred", "partial", "failed", "cancelled",
    )
    assert SOURCE_RATE_LIMIT_STATE_VALUES == ("available", "limited", "backoff", "quota_unavailable", "unknown")
    assert QUARANTINED_RECORD_STATUS_VALUES == ("pending", "reviewed", "released", "discarded")
    assert AUDIT_ACTOR_TYPE_VALUES == ("user", "service", "system")
    assert AUDIT_OUTCOME_VALUES == ("success", "denied", "failed", "no_change")
    assert CREDENTIAL_CONFIGURATION_STATE_VALUES == ("not_configured", "configured", "disabled", "rotation_due", "revoked")
    assert "octet_length(coalesce(safe_excerpt, ''))" in _checks("quarantined_records")["ck_quarantined_records_sizes_bounded"]
    assert "checkpoint_pending" in _checks("ingestion_runs")["ck_ingestion_runs_status_time_consistency"]
    shape = _checks("ingestion_runs")[
        "ck_ingestion_runs_operational_or_compatibility_shape"
    ]
    for column_name in (
        "cycle_id", "idempotency_key", "attempt_number", "retry_of_run_id",
        "state_version", "defer_reason",
    ):
        assert column_name in shape
    assert "succeeded" in shape and "canceled" in shape
    assert "checkpoint_pending" in shape and "success" in shape


def test_operational_models_compile_and_have_no_secret_or_payload_shape(models):
    forbidden = ("password", "token", "secret", "authorization", "cookie", "payload", "header", "database_url", "api_key")
    for table_name in OPERATIONAL_TABLES:
        table = Base.metadata.tables[table_name]
        ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
        assert "BIGINT GENERATED" in ddl
        for column in table.c:
            assert all(fragment not in column.name.casefold() for fragment in forbidden)
        model = next(mapper.class_ for mapper in Base.registry.mappers if mapper.local_table is table)
        assert "__repr__" not in model.__dict__


def test_no_hidden_run_fallback_or_automatic_cycle_creation(models):
    run = Base.metadata.tables["ingestion_runs"]
    cycle = Base.metadata.tables["ingestion_cycles"]
    assert run.c.cycle_id.default is None
    assert run.c.idempotency_key.default is None
    assert cycle.c.idempotency_key.default is None
    run_source = inspect.getsource(inspect.getmodule(models.IngestionRun))
    cycle_source = inspect.getsource(inspect.getmodule(models.IngestionCycle))
    assert "def __init__" not in run_source
    assert "def __init__" not in cycle_source
    assert "event.listens_for" not in run_source
    assert "event.listens_for" not in cycle_source
    assert set(Base.metadata.tables) == TARGET_TABLES
