import ast
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
VERSIONS_DIR = BACKEND_DIR / "alembic" / "versions"

APPROVED_TABLES = {
    "ingestion_errors",
    "ingestion_run_records",
    "ingestion_runs",
    "intelligence_item_identifiers",
    "intelligence_item_tags",
    "intelligence_items",
    "intelligence_sources",
    "source_records",
    "tags",
    "vulnerabilities",
}

EXPECTED_INDEXES = {
    "ix_ingestion_errors_run_id_occurred_at_desc",
    "ix_ingestion_run_records_run_id_action",
    "ix_ingestion_runs_source_id_started_at_desc",
    "ix_ingestion_runs_status_started_at_desc",
    "ix_intelligence_item_tags_tag_id_item_id",
    "ix_intel_items_uae_rel_status_published_desc",
    "ix_intelligence_items_item_type_source_published_at_desc",
    "ix_intelligence_items_status_source_published_at_desc",
    "ix_vulnerabilities_kev_status",
    "ix_vulnerabilities_severity",
    "uq_ingestion_run_records_run_source_record",
    "uq_item_identifiers_global_lookup",
    "uq_item_identifiers_primary_per_item",
    "uq_item_identifiers_source_lookup",
    "uq_source_records_external_id",
    "uq_source_records_primary_ref_per_item",
    "uq_source_records_url_hash",
}

EXPECTED_CHECK_CONSTRAINTS = {
    "ck_ingestion_errors_retry_count_non_negative",
    "ck_ingestion_run_records_action_allowed",
    "ck_ingestion_runs_completed_at_order",
    "ck_ingestion_runs_counters_non_negative",
    "ck_ingestion_runs_status_allowed",
    "ck_ingestion_runs_trigger_type_allowed",
    "ck_intelligence_item_tags_assigned_by_allowed",
    "ck_intelligence_item_tags_confidence_range",
    "ck_intelligence_items_data_confidence_range",
    "ck_intelligence_items_geographic_scope_allowed",
    "ck_intelligence_items_item_type_allowed",
    "ck_intelligence_items_merged_into_not_self",
    "ck_intelligence_items_merged_requires_target",
    "ck_intelligence_items_single_lifecycle_pointer",
    "ck_intelligence_items_status_allowed",
    "ck_intelligence_items_superseded_by_not_self",
    "ck_intelligence_items_superseded_requires_target",
    "ck_intelligence_items_uae_relevance_confidence_range",
    "ck_intelligence_items_uae_relevance_method_allowed",
    "ck_intelligence_items_uae_relevance_status_allowed",
    "ck_intelligence_sources_source_type_allowed",
    "ck_source_records_processing_status_allowed",
    "ck_source_records_upstream_status_allowed",
    "ck_tags_tag_type_allowed",
    "ck_vulnerabilities_cvss_score_range",
    "ck_vulnerabilities_epss_percentile_range",
    "ck_vulnerabilities_epss_score_range",
    "ck_vulnerabilities_kev_status_allowed",
    "ck_vulnerabilities_severity_allowed",
}

PARTIAL_INDEX_PREDICATES = {
    "source_id IS NULL",
    "source_id IS NOT NULL",
    "is_primary IS TRUE",
    "source_external_id IS NOT NULL",
    "canonical_url_hash IS NOT NULL",
    "is_primary_reference IS TRUE AND intelligence_item_id IS NOT NULL",
    "source_record_id IS NOT NULL",
}

FK_DELETE_ACTIONS = {"CASCADE", "RESTRICT", "SET NULL"}
BASE_REVISION_ID = "f8d739439ed0"


def script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))


def base_revision():
    revision = script_directory().get_revision(BASE_REVISION_ID)
    assert revision is not None
    return revision


def revision_source() -> str:
    return Path(base_revision().path).read_text(encoding="utf-8")


def revision_tree() -> ast.Module:
    return ast.parse(revision_source())


def function_body(name: str) -> list[ast.stmt]:
    for node in revision_tree().body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node.body
    raise AssertionError(f"missing function {name}")


def literal_first_arg(call: ast.Call) -> str | None:
    if call.args and isinstance(call.args[0], ast.Constant):
        value = call.args[0].value
        if isinstance(value, str):
            return value
    return None


def op_calls(method_name: str) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for node in ast.walk(revision_tree()):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == method_name
            and isinstance(func.value, ast.Name)
            and func.value.id == "op"
        ):
            calls.append(node)
    return calls


def test_original_revision_remains_the_known_base_revision():
    directory = script_directory()
    revision = base_revision()

    assert revision.revision == BASE_REVISION_ID
    assert revision.down_revision is None
    assert len(directory.get_heads()) == 1
    assert revision.is_branch_point is False
    assert revision.is_merge_point is False
    assert Path(revision.path).parent.resolve() == VERSIONS_DIR


def test_upgrade_and_downgrade_are_implemented():
    upgrade_body = function_body("upgrade")
    downgrade_body = function_body("downgrade")

    assert upgrade_body
    assert downgrade_body
    assert not any(isinstance(node, ast.Pass) for node in upgrade_body)
    assert not any(isinstance(node, ast.Pass) for node in downgrade_body)


def test_upgrade_creates_exactly_approved_application_tables():
    created_tables = {
        table_name for call in op_calls("create_table")
        if (table_name := literal_first_arg(call)) is not None
    }

    assert created_tables == APPROVED_TABLES


def test_downgrade_drops_exactly_approved_application_tables():
    dropped_tables = {
        table_name for call in op_calls("drop_table")
        if (table_name := literal_first_arg(call)) is not None
    }

    assert dropped_tables == APPROVED_TABLES


def test_revision_has_no_seed_data_extensions_raw_sql_or_native_enums():
    tree = revision_tree()
    source = revision_source().lower()

    forbidden_op_methods = {"bulk_insert", "execute", "create_exclude_constraint"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in forbidden_op_methods

    assert "insert into" not in source
    assert "create extension" not in source
    assert "sa.enum" not in source
    assert "postgresql.enum" not in source


def test_revision_does_not_contain_credentials_or_environment_values():
    source = revision_source().lower()

    forbidden_fragments = (
        "postgresql://",
        "postgresql+psycopg://",
        "database_url",
        "api_key",
        "authorization",
        "bearer ",
        "cookie",
        "password",
        "postgres_password",
        "secret",
        "c:\\",
        "/users/",
    )
    for fragment in forbidden_fragments:
        assert fragment not in source


def test_revision_preserves_expected_explicit_indexes_and_predicates():
    source = revision_source()
    created_indexes = {
        index_name for call in op_calls("create_index")
        if (index_name := literal_first_arg(call)) is not None
    }

    assert created_indexes == EXPECTED_INDEXES
    for predicate in PARTIAL_INDEX_PREDICATES:
        assert predicate in source
    assert "source_published_at DESC" in source
    assert "started_at DESC" in source
    assert "occurred_at DESC" in source


def test_revision_preserves_constraints_fk_actions_jsonb_and_numeric_types():
    source = revision_source()

    for constraint_name in EXPECTED_CHECK_CONSTRAINTS:
        assert constraint_name in source
    for action in FK_DELETE_ACTIONS:
        assert f"ondelete='{action}'" in source
    assert "postgresql.JSONB" in source
    assert "sa.Numeric(precision=4, scale=3)" in source
    assert "sa.Numeric(precision=3, scale=1)" in source
    assert "sa.Numeric(precision=7, scale=6)" in source
    assert "sa.Identity" in source
    assert "sa.Uuid" in source
    assert "timezone=True" in source


def test_revision_downgrade_drops_indexes_and_tables():
    dropped_indexes = {
        index_name for call in op_calls("drop_index")
        if (index_name := literal_first_arg(call)) is not None
    }

    assert dropped_indexes == EXPECTED_INDEXES
    assert {
        table_name for call in op_calls("drop_table")
        if (table_name := literal_first_arg(call)) is not None
    } == APPROVED_TABLES
