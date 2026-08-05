from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


BACKEND = Path(__file__).resolve().parents[1]
MIGRATION = BACKEND / "alembic" / "versions" / "e91f4c2a7b60_add_threat_knowledge_models.py"


def test_revision_is_one_linear_head_with_exact_parent():
    scripts = ScriptDirectory.from_config(Config(str(BACKEND / "alembic.ini")))
    revision = scripts.get_revision("e91f4c2a7b60")
    assert revision is not None
    assert revision.down_revision == "d7a9e51c2f40"
    assert scripts.get_heads() == ["c07a01b02c03"]


def test_migration_creates_only_three_tables_and_reverses_dependencies():
    text = MIGRATION.read_text(encoding="utf-8")
    assert text.count("op.create_table(") == 3
    assert all(f'op.create_table(\n        "{name}"' in text for name in ("threat_entities", "threat_entity_aliases", "threat_relationships"))
    downgrade = text.split("def downgrade() -> None:", 1)[1]
    assert downgrade.index('drop_table("threat_relationships")') < downgrade.index('drop_table("threat_entity_aliases")') < downgrade.index('drop_table("threat_entities")')


def test_migration_has_no_seed_data_unsafe_sql_or_sensitive_configuration():
    text = MIGRATION.read_text(encoding="utf-8").lower()
    assert "op.execute" not in text
    assert "bulk_insert" not in text
    assert "postgresql://" not in text
    assert "database_url" not in text
    assert "password" not in text
    assert "authorization" not in text
    assert "cookie" not in text
    assert "c:\\" not in text


def test_migration_contains_required_composite_integrity_and_indexes():
    text = MIGRATION.read_text(encoding="utf-8")
    for token in ("fk_threat_entities_source_record_source", "fk_threat_entity_aliases_entity_provenance", "fk_threat_entity_aliases_source_record_source", "fk_threat_relationships_source_record_source", "fk_threat_relationships_source_entity_source", "fk_threat_relationships_target_entity_source", "ck_threat_relationships_not_self", "uq_threat_entities_identity_sha256", "uq_threat_relationships_identity_sha256"):
        assert token in text
