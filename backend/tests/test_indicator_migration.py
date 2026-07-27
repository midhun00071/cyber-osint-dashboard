import ast
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
VERSIONS_DIR = BACKEND_DIR / "alembic" / "versions"
BASE_REVISION_ID = "f8d739439ed0"
INDICATOR_REVISION_ID = "a6c9d4e2f107"
EXPECTED_TABLES = {"indicators", "indicator_provenances"}
EXPECTED_INDEXES = {
    "ix_indicators_observable_type_status",
    "ix_indicators_status_last_seen_at_desc",
    "uq_indicators_identity_sha256",
    "uq_indicator_provenances_indicator_source_record",
    "uq_indicator_provenances_indicator_source_without_record",
}
EXPECTED_CHECKS = {
    "ck_indicators_confidence_range",
    "ck_indicators_expires_at_order",
    "ck_indicators_hash_algorithm_allowed",
    "ck_indicators_hash_algorithm_consistency",
    "ck_indicators_identity_sha256_format",
    "ck_indicators_normalized_value_length",
    "ck_indicators_observable_type_allowed",
    "ck_indicators_revoked_at_consistency",
    "ck_indicators_seen_at_order",
    "ck_indicators_status_allowed",
    "ck_indicator_provenances_confidence_range",
    "ck_indicator_provenances_observed_at_order",
}


def script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))


def indicator_revision():
    revision = script_directory().get_revision(INDICATOR_REVISION_ID)
    assert revision is not None
    return revision


def revision_source() -> str:
    return Path(indicator_revision().path).read_text(encoding="utf-8")


def revision_tree() -> ast.Module:
    return ast.parse(revision_source())


def _function(name: str) -> ast.FunctionDef:
    for node in revision_tree().body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"missing function {name}")


def _op_calls(function_name: str, method_name: str) -> list[ast.Call]:
    calls = []
    for node in ast.walk(_function(function_name)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if (
            node.func.attr == method_name
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "op"
        ):
            calls.append(node)
    return sorted(calls, key=lambda call: call.lineno)


def _literal_first_args(function_name: str, method_name: str) -> list[str]:
    values = []
    for call in _op_calls(function_name, method_name):
        assert call.args and isinstance(call.args[0], ast.Constant)
        assert isinstance(call.args[0].value, str)
        values.append(call.args[0].value)
    return values


def _operation_sequence(function_name: str) -> list[tuple[str, str]]:
    operations = []
    schema_methods = {
        "create_index",
        "create_table",
        "create_unique_constraint",
        "drop_constraint",
        "drop_index",
        "drop_table",
    }
    for node in ast.walk(_function(function_name)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != "op":
            continue
        if node.func.attr not in schema_methods:
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        if isinstance(node.args[0].value, str):
            operations.append((node.lineno, node.func.attr, node.args[0].value))
    return [
        (method_name, first_argument)
        for _, method_name, first_argument in sorted(operations)
    ]


def test_indicator_revision_directly_follows_base_with_one_linear_head():
    directory = script_directory()
    revisions = list(directory.walk_revisions())
    revision = indicator_revision()

    assert revision.down_revision == BASE_REVISION_ID
    assert directory.get_heads() == [INDICATOR_REVISION_ID]
    assert [item.revision for item in revisions] == [
        INDICATOR_REVISION_ID,
        BASE_REVISION_ID,
    ]
    assert all(not item.is_branch_point for item in revisions)
    assert all(not item.is_merge_point for item in revisions)
    assert Path(revision.path).parent.resolve() == VERSIONS_DIR


def test_upgrade_and_downgrade_create_and_remove_exact_p9_08_objects():
    assert set(_literal_first_args("upgrade", "create_table")) == EXPECTED_TABLES
    assert set(_literal_first_args("upgrade", "create_index")) == EXPECTED_INDEXES
    assert set(_literal_first_args("downgrade", "drop_table")) == EXPECTED_TABLES
    assert set(_literal_first_args("downgrade", "drop_index")) == EXPECTED_INDEXES
    assert _literal_first_args("upgrade", "create_unique_constraint") == [
        "uq_source_records_id_source_id"
    ]
    assert _literal_first_args("downgrade", "drop_constraint") == [
        "uq_source_records_id_source_id"
    ]


def test_upgrade_and_downgrade_use_dependency_safe_order():
    assert _literal_first_args("upgrade", "create_table") == [
        "indicators",
        "indicator_provenances",
    ]
    assert _literal_first_args("downgrade", "drop_table") == [
        "indicator_provenances",
        "indicators",
    ]
    upgrade_operations = _operation_sequence("upgrade")
    assert upgrade_operations[:3] == [
        ("create_unique_constraint", "uq_source_records_id_source_id"),
        ("create_table", "indicators"),
        ("create_table", "indicator_provenances"),
    ]
    assert all(
        method_name == "create_index"
        for method_name, _ in upgrade_operations[3:]
    )

    downgrade_operations = _operation_sequence("downgrade")
    provenance_drop = downgrade_operations.index(
        ("drop_table", "indicator_provenances")
    )
    indicator_drop = downgrade_operations.index(("drop_table", "indicators"))
    composite_key_drop = downgrade_operations.index(
        ("drop_constraint", "uq_source_records_id_source_id")
    )
    assert provenance_drop < indicator_drop < composite_key_drop


def test_revision_contains_expected_checks_indexes_and_fk_actions():
    source = revision_source()

    for constraint_name in EXPECTED_CHECKS:
        assert constraint_name in source
    for action in ("CASCADE", "RESTRICT"):
        assert f'ondelete="{action}"' in source
    assert 'ondelete="SET NULL"' not in source
    assert 'sa.ForeignKeyConstraint(\n            ["indicator_id"]' in source
    assert 'sa.ForeignKeyConstraint(\n            ["source_id"]' in source
    assert (
        'sa.ForeignKeyConstraint(\n            ["source_record_id", "source_id"],\n'
        '            ["source_records.id", "source_records.source_id"]'
        in source
    )
    assert "uq_source_records_id_source_id" in source
    assert "identity_sha256 ~ '^[0-9a-f]{64}$'" in source
    assert "source_record_id IS NOT NULL" in source
    assert "source_record_id IS NULL" in source
    assert "last_seen_at DESC" in source
    assert "sa.Numeric(precision=4, scale=3)" in source
    assert "sa.Identity(always=False)" in source
    assert "sa.Uuid()" in source
    assert "sa.DateTime(timezone=True)" in source


def test_revision_has_no_seed_raw_sql_enum_extension_or_unsafe_content():
    tree = revision_tree()
    source = revision_source().lower()

    forbidden_op_methods = {
        "bulk_insert",
        "execute",
        "create_exclude_constraint",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "op":
                assert node.func.attr not in forbidden_op_methods

    forbidden_fragments = (
        "insert into",
        "create extension",
        "sa.enum",
        "postgresql.enum",
        "postgresql://",
        "postgresql+psycopg://",
        "database_url",
        "api_key",
        "authorization",
        "bearer ",
        "cookie",
        "password",
        "secret",
        "c:\\",
        "/users/",
    )
    for fragment in forbidden_fragments:
        assert fragment not in source


def test_revision_does_not_add_full_normalized_value_unique_index():
    source = revision_source()

    assert 'op.create_index(\n        "uq_indicators_normalized_value"' not in source
    assert "raw_payload" not in source
    assert "malware_sample" not in source
