import ast
import hashlib
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
VERSIONS_DIR = BACKEND_DIR / "alembic" / "versions"
REVISION_ID = "b103a71d2e4f"
PARENT_ID = "c4e8b2a91d30"
DATABASE_OPERATIONS_REVISION_ID = "d7a9e51c2f40"
HEAD_REVISION_ID = "e91f4c2a7b60"
MIGRATION_PATH = VERSIONS_DIR / "b103a71d2e4f_add_operational_ingestion_audit_schema.py"
NEW_TABLES = [
    "ingestion_cycles",
    "source_credential_references",
    "source_rate_limit_states",
    "ingestion_run_events",
    "source_checkpoints",
    "source_watermarks",
    "quarantined_records",
    "audit_events",
]
PARTIAL_INDEXES = {
    "uq_source_checkpoints_source_identity_version",
    "uq_source_checkpoints_partition_identity_version",
    "uq_source_watermarks_source_identity_version",
    "uq_source_watermarks_partition_identity_version",
}
INTEGRITY_OBJECTS = {
    "uq_ingestion_cycles_idempotency_key",
    "ck_ingestion_cycles_trigger_type_allowed",
    "ck_ingestion_cycles_trigger_schedule_consistency",
    "ck_ingestion_cycles_status_allowed",
    "ck_ingestion_cycles_status_time_consistency",
    "ck_ingestion_cycles_completed_at_order",
    "ck_ingestion_cycles_counters_non_negative",
    "ck_ingestion_cycles_counter_relationships",
    "uq_ingestion_runs_idempotency_key",
    "uq_ingestion_runs_source_cycle_attempt",
    "uq_ingestion_runs_id_source_id",
    "uq_ingestion_runs_id_cycle_id",
    "fk_ingestion_runs_retry_source",
    "fk_ingestion_runs_retry_cycle",
    "ck_ingestion_runs_attempt_number_bounded",
    "ck_ingestion_runs_retry_lineage_consistency",
    "ck_ingestion_runs_operational_or_compatibility_shape",
    "ck_ingestion_runs_status_allowed",
    "ck_ingestion_runs_status_time_consistency",
    "uq_ingestion_run_events_run_sequence",
    "uq_ingestion_run_events_id_run_id",
    "ck_ingestion_run_events_sequence_bounded",
    "ck_ingestion_run_events_event_type_allowed",
    "ck_ingestion_run_events_transition_shape",
    "ck_ingestion_run_events_created_at_order",
    *PARTIAL_INDEXES,
    "uq_source_checkpoints_id_source_id",
    "uq_source_checkpoints_previous",
    "fk_source_checkpoints_advanced_run_source",
    "fk_source_checkpoints_previous_source",
    "ck_source_checkpoints_scope_identity",
    "ck_source_checkpoints_version_positive",
    "ck_source_checkpoints_commit_order",
    "uq_source_watermarks_id_source_id",
    "uq_source_watermarks_previous",
    "fk_source_watermarks_advanced_run_source",
    "fk_source_watermarks_previous_source",
    "ck_source_watermarks_scope_identity",
    "ck_source_watermarks_version_positive",
    "ck_source_watermarks_commit_order",
    "uq_source_rate_limit_states_source_policy",
    "fk_source_rate_limit_states_run_source",
    "ck_source_rate_limit_states_counts_valid",
    "ck_source_rate_limit_states_window_bounded",
    "ck_source_rate_limit_states_version_positive",
    "ck_ingestion_errors_retry_count_bounded",
    "ck_ingestion_errors_diagnostic_fingerprint_format",
    "uq_quarantined_records_run_key",
    "fk_quarantined_records_run_source",
    "fk_quarantined_records_event_run",
    "ck_quarantined_records_key_format",
    "ck_quarantined_records_sizes_bounded",
    "ck_quarantined_records_status_allowed",
    "ck_quarantined_records_reviewed_at_consistency",
    "uq_audit_events_idempotency_key",
    "fk_audit_events_run_cycle",
    "ck_audit_events_run_cycle_consistency",
    "ck_audit_events_actor_type_allowed",
    "ck_audit_events_action_format",
    "ck_audit_events_target_type_format",
    "ck_audit_events_target_ref_length",
    "ck_audit_events_outcome_allowed",
    "ck_audit_events_created_at_order",
    "uq_source_credential_references_source_name_purpose",
    "ck_source_credential_references_state_allowed",
    "ck_source_credential_references_configured_shape",
    "ck_source_credential_references_rotation_expiry_order",
    "ck_source_credential_references_updated_at_order",
}
PREVIOUS_NORMALIZED_HASHES = {
    "f8d739439ed0_create_initial_schema.py": "711ec7cb341f46c1dcef543e51c489e244653cd20aa350535b17362152a3f1fd",
    "a6c9d4e2f107_add_indicator_ioc_models.py": "b789bfab9ba818c0130ed8afb685a3abc5e659346793f9abb1ebb12174a86cff",
    "c4e8b2a91d30_add_ioc_publication_relationships.py": "5bf808aa569ede43645d81ab006e9b42f5172e85c2607085fcaa093222d29654",
}


def _directory():
    return ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))


def _source():
    return MIGRATION_PATH.read_text(encoding="utf-8")


def _tree():
    return ast.parse(_source())


def _function(name):
    return next(
        node
        for node in _tree().body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    )


def _op_calls(method):
    return sorted(
        (
            node
            for node in ast.walk(_tree())
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "op"
            and node.func.attr == method
        ),
        key=lambda node: node.lineno,
    )


def _literal_first_args(method):
    values = []
    for call in _op_calls(method):
        if call.args and isinstance(call.args[0], ast.Constant):
            values.append(call.args[0].value)
    return values


def test_revision_identity_and_linear_six_revision_chain():
    directory = _directory()
    revisions = list(directory.walk_revisions())
    assert directory.get_heads() == [HEAD_REVISION_ID]
    assert [revision.revision for revision in revisions] == [
        HEAD_REVISION_ID,
        DATABASE_OPERATIONS_REVISION_ID,
        REVISION_ID,
        PARENT_ID,
        "a6c9d4e2f107",
        "f8d739439ed0",
    ]
    assert [revision.down_revision for revision in revisions] == [
        DATABASE_OPERATIONS_REVISION_ID,
        REVISION_ID,
        PARENT_ID,
        "a6c9d4e2f107",
        "f8d739439ed0",
        None,
    ]
    assert all(not revision.is_branch_point for revision in revisions)
    assert all(not revision.is_merge_point for revision in revisions)


def test_upgrade_and_downgrade_are_implemented():
    for name in ("upgrade", "downgrade"):
        function = _function(name)
        assert function.body
        assert not any(isinstance(node, ast.Pass) for node in function.body)


def test_expected_tables_columns_constraints_and_indexes_are_present():
    source = _source()
    assert _literal_first_args("create_table") == NEW_TABLES
    for name in INTEGRITY_OBJECTS:
        assert name in source
    for column in (
        "cycle_id", "idempotency_key", "attempt_number", "retry_of_run_id",
        "state_version", "defer_reason", "failure_stage",
        "diagnostic_fingerprint", "safe_context",
    ):
        assert f'"{column}"' in source
    assert PARTIAL_INDEXES <= set(_literal_first_args("create_index"))


def test_upgrade_and_downgrade_use_dependency_safe_table_order():
    assert _literal_first_args("create_table") == NEW_TABLES
    dropped = _literal_first_args("drop_table")
    assert set(dropped) == set(NEW_TABLES)
    assert dropped.index("audit_events") < dropped.index("ingestion_cycles")
    assert dropped.index("quarantined_records") < dropped.index("ingestion_run_events")
    assert dropped.index("source_checkpoints") < dropped.index("ingestion_cycles")
    assert dropped.index("source_watermarks") < dropped.index("ingestion_cycles")


def test_deterministic_legacy_namespaces_and_truthful_backfill_contract():
    source = _source()
    assert "legacy-cycle:" in source
    assert "legacy-run:" in source
    assert 'trigger_type="legacy_import"' in source
    assert 'scheduled_for=None' in source
    assert 'attempt_number=0' in source
    assert 'retry_of_run_id=None' in source
    assert 'state_version=1' in source
    assert "succeeded" in source and "success" in source
    assert "canceled" in source and "cancelled" in source
    assert 'event_type="persistence_committed"' not in source
    assert 'event_type="checkpoint_advanced"' not in source
    assert 'event_type="acquired"' in source


def test_head_retains_nullable_compatibility_columns_without_hidden_identity():
    source = _source()
    tree = _tree()
    compatibility_columns = {
        "cycle_id", "idempotency_key", "attempt_number", "state_version"
    }
    for call in (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "op"
        and node.func.attr == "alter_column"
    ):
        literal_args = [
            arg.value for arg in call.args if isinstance(arg, ast.Constant)
        ]
        assert not (
            literal_args[:1] == ["ingestion_runs"]
            and compatibility_columns.intersection(literal_args[1:2])
        )
    assert "ck_ingestion_runs_operational_or_compatibility_shape" in source
    assert "COMPATIBILITY_DOWNGRADE_STATUSES" in source
    assert "'succeeded'" in source and "'canceled'" in source


def test_migration_uses_core_bound_data_work_and_no_raw_interpolated_sql():
    tree = _tree()
    source = _source().casefold()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "op":
                assert node.func.attr not in {"execute", "bulk_insert"}
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "text" and node.args:
                assert isinstance(node.args[0], ast.Constant)
    assert "sa.insert(" in source
    assert "sa.update(" in source
    assert "sa.select(" in source
    assert "insert into" not in source
    assert "create extension" not in source
    assert "sa.enum" not in source
    assert "postgresql.enum" not in source


def test_migration_contains_no_credentials_environment_machine_paths_or_payloads():
    source = _source().casefold()
    for fragment in (
        "postgresql://", "database_url", "api_key", "authorization", "bearer ",
        "cookie", "password", "os.environ", "getenv", "c:\\users\\", "/users/",
        "raw_payload", "source_payload", "seed_data",
    ):
        assert fragment not in source


def test_fail_closed_downgrade_categories_are_explicit():
    source = _source()
    for category in (
        "checkpoint_pending_run",
        "target_only_run_evidence",
        "target_only_cycle_evidence",
        "target_only_run_event",
        "target_only_checkpoint_history",
        "target_only_watermark_history",
        "target_only_ingestion_error_metadata",
    ):
        assert category in source
    assert 'f"target_only_{table_name}"' in source
    for table_name in (
        "source_rate_limit_states",
        "source_credential_references",
        "quarantined_records",
        "audit_events",
    ):
        assert f'"{table_name}"' in source


def test_previous_revision_identities_and_files_remain_separate():
    directory = _directory()
    for revision_id, filename in (
        ("f8d739439ed0", "f8d739439ed0_create_initial_schema.py"),
        ("a6c9d4e2f107", "a6c9d4e2f107_add_indicator_ioc_models.py"),
        ("c4e8b2a91d30", "c4e8b2a91d30_add_ioc_publication_relationships.py"),
    ):
        revision = directory.get_revision(revision_id)
        assert revision is not None
        assert Path(revision.path).name == filename
        assert Path(revision.path).resolve() != MIGRATION_PATH.resolve()


def test_all_previous_migration_contents_are_unchanged_after_crlf_normalization():
    for filename, expected_hash in PREVIOUS_NORMALIZED_HASHES.items():
        normalized = (VERSIONS_DIR / filename).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(normalized).hexdigest() == expected_hash
