import ast
import hashlib
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
VERSIONS_DIR = BACKEND_DIR / "alembic" / "versions"
BASE_REVISION_ID = "f8d739439ed0"
INDICATOR_REVISION_ID = "a6c9d4e2f107"
RELATIONSHIP_REVISION_ID = "c4e8b2a91d30"
OPERATIONAL_REVISION_ID = "b103a71d2e4f"
DATABASE_OPERATIONS_REVISION_ID = "d7a9e51c2f40"
THREAT_KNOWLEDGE_REVISION_ID = "e91f4c2a7b60"
PREVIOUS_MIGRATION_HASHES = {
    "f8d739439ed0_create_initial_schema.py": (
        "711ec7cb341f46c1dcef543e51c489e244653cd20aa350535b17362152a3f1fd"
    ),
    "a6c9d4e2f107_add_indicator_ioc_models.py": (
        "b789bfab9ba818c0130ed8afb685a3abc5e659346793f9abb1ebb12174a86cff"
    ),
}


def _directory():
    return ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))


def _source():
    revision = _directory().get_revision(RELATIONSHIP_REVISION_ID)
    assert revision is not None
    return Path(revision.path).read_text(encoding="utf-8")


def _tree():
    return ast.parse(_source())


def _function(name):
    return next(
        node for node in _tree().body if isinstance(node, ast.FunctionDef) and node.name == name
    )


def _op_calls(function_name, method_name):
    return sorted(
        (
            node
            for node in ast.walk(_function(function_name))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "op"
            and node.func.attr == method_name
        ),
        key=lambda node: node.lineno,
    )


def _first_args(function_name, method_name):
    values = []
    for call in _op_calls(function_name, method_name):
        assert call.args and isinstance(call.args[0], ast.Constant)
        values.append(call.args[0].value)
    return values


def test_revision_chain_is_linear_and_database_operations_follows_operational():
    directory = _directory()
    revisions = list(directory.walk_revisions())

    assert directory.get_heads() == [THREAT_KNOWLEDGE_REVISION_ID]
    assert [revision.revision for revision in revisions] == [
        THREAT_KNOWLEDGE_REVISION_ID,
        DATABASE_OPERATIONS_REVISION_ID,
        OPERATIONAL_REVISION_ID,
        RELATIONSHIP_REVISION_ID,
        INDICATOR_REVISION_ID,
        BASE_REVISION_ID,
    ]
    assert revisions[0].down_revision == DATABASE_OPERATIONS_REVISION_ID
    assert revisions[1].down_revision == OPERATIONAL_REVISION_ID
    assert revisions[2].down_revision == RELATIONSHIP_REVISION_ID
    assert revisions[3].down_revision == INDICATOR_REVISION_ID
    assert revisions[4].down_revision == BASE_REVISION_ID
    assert revisions[5].down_revision is None
    assert all(not revision.is_branch_point for revision in revisions)
    assert all(not revision.is_merge_point for revision in revisions)
    assert all(Path(revision.path).parent.resolve() == VERSIONS_DIR for revision in revisions)


def test_upgrade_and_downgrade_create_only_relationship_objects_in_safe_order():
    assert _first_args("upgrade", "create_table") == [
        "intelligence_item_indicators"
    ]
    assert _first_args("upgrade", "create_index") == [
        "ix_intelligence_item_indicators_indicator_id_item_id"
    ]
    assert _first_args("downgrade", "drop_index") == [
        "ix_intelligence_item_indicators_indicator_id_item_id"
    ]
    assert _first_args("downgrade", "drop_table") == [
        "intelligence_item_indicators"
    ]
    assert _op_calls("upgrade", "create_table")[0].lineno < _op_calls(
        "upgrade", "create_index"
    )[0].lineno
    assert _op_calls("downgrade", "drop_index")[0].lineno < _op_calls(
        "downgrade", "drop_table"
    )[0].lineno


def test_revision_contains_exact_constraints_foreign_keys_and_index():
    source = _source()
    for fragment in (
        "ck_intelligence_item_indicators_relationship_type_allowed",
        "ck_intelligence_item_indicators_extraction_method_allowed",
        "ck_intelligence_item_indicators_confidence_range",
        "ck_intelligence_item_indicators_observed_at_order",
        '["intelligence_items.id"]',
        '["indicators.id"]',
        'ondelete="CASCADE"',
        'sa.PrimaryKeyConstraint(\n            "intelligence_item_id",\n            "indicator_id"',
        '["indicator_id", "intelligence_item_id"]',
        "sa.Numeric(precision=4, scale=3)",
        "sa.DateTime(timezone=True)",
    ):
        assert fragment in source


def test_revision_has_no_seed_raw_sql_enum_extension_or_unsafe_content():
    tree = _tree()
    source = _source().lower()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "op"
        ):
            assert node.func.attr not in {"bulk_insert", "execute"}
    for fragment in (
        "insert into",
        "create extension",
        "sa.enum",
        "postgresql.enum",
        "postgresql://",
        "database_url",
        "api_key",
        "authorization",
        "cookie",
        "password",
        "secret",
        "raw_payload",
        "c:\\users\\",
        "/users/",
    ):
        assert fragment not in source


def test_previous_migration_files_are_byte_for_byte_unchanged():
    for filename, expected in PREVIOUS_MIGRATION_HASHES.items():
        digest = hashlib.sha256((VERSIONS_DIR / filename).read_bytes()).hexdigest()
        assert digest == expected
