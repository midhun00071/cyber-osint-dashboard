from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

import pytest
from sqlalchemy import CheckConstraint, ForeignKeyConstraint, UniqueConstraint
from sqlalchemy.orm import configure_mappers

from app.db.base import Base
from app.ingestion.stix_taxii.threat_knowledge import (
    APPROVED_RELATIONSHIPS,
    ThreatKnowledgeError,
    map_threat_entity,
    normalize_alias,
    source_stix_identity,
)


@pytest.fixture(scope="module", autouse=True)
def models():
    import app.models
    configure_mappers()
    return app.models


def test_exact_tables_columns_and_public_uuid(models):
    entities = Base.metadata.tables["threat_entities"]
    aliases = Base.metadata.tables["threat_entity_aliases"]
    relationships = Base.metadata.tables["threat_relationships"]
    assert list(entities.c) == [entities.c[name] for name in ("source_id", "source_record_id", "entity_type", "stix_id", "identity_sha256", "name", "attack_id", "confidence", "stix_created_at", "stix_modified_at", "revoked", "id", "public_id", "created_at", "updated_at")]
    assert set(aliases.c.keys()) == {"threat_entity_id", "source_id", "source_record_id", "display_value", "normalized_value", "id", "created_at", "updated_at"}
    assert "public_id" in relationships.c
    generated = entities.c.public_id.default.arg(None)
    assert isinstance(generated, UUID) and generated.version == 4


def test_composite_source_record_and_endpoint_provenance_constraints(models):
    expected = {
        "fk_threat_relationships_source_record_source": ("source_record_id", "source_id"),
        "fk_threat_relationships_source_entity_source": ("source_entity_id", "source_id"),
        "fk_threat_relationships_target_entity_source": ("target_entity_id", "source_id"),
    }
    table = Base.metadata.tables["threat_relationships"]
    found = {constraint.name: tuple(constraint.column_keys) for constraint in table.constraints if isinstance(constraint, ForeignKeyConstraint)}
    assert all(found[name] == columns for name, columns in expected.items())
    alias_table = Base.metadata.tables["threat_entity_aliases"]
    assert any(tuple(item.column_keys) == ("threat_entity_id", "source_id", "source_record_id") for item in alias_table.constraints if isinstance(item, ForeignKeyConstraint))


def test_checks_uniques_and_query_indexes_cover_frozen_contract(models):
    entities = Base.metadata.tables["threat_entities"]
    relationships = Base.metadata.tables["threat_relationships"]
    checks = {item.name for table in (entities, relationships) for item in table.constraints if isinstance(item, CheckConstraint)}
    assert {"ck_threat_entities_type_allowed", "ck_threat_entities_confidence_range", "ck_threat_entities_stix_time_order", "ck_threat_entities_attack_id_format", "ck_threat_relationships_not_self", "ck_threat_relationships_confidence_range", "ck_threat_relationships_stix_time_order", "ck_threat_relationships_active_time_order"} <= checks
    uniques = {item.name for table in (entities, relationships) for item in table.constraints if isinstance(item, UniqueConstraint)}
    assert {"uq_threat_entities_source_stix_id", "uq_threat_entities_source_record", "uq_threat_relationships_source_stix_id", "uq_threat_relationships_source_record"} <= uniques
    indexes = {item.name for table in (entities, relationships) for item in table.indexes}
    assert {"ix_threat_entities_source_type", "ix_threat_entities_attack_id", "ix_threat_entities_source_revoked", "ix_threat_entities_modified_desc", "ix_threat_relationships_source_endpoint", "ix_threat_relationships_target_endpoint"} <= indexes


def test_identity_is_source_specific_and_never_name_based():
    stix_id = "campaign--11111111-1111-4111-8111-111111111111"
    assert source_stix_identity("source-a", stix_id) == source_stix_identity("source-a", stix_id)
    assert source_stix_identity("source-a", stix_id) != source_stix_identity("source-b", stix_id)
    other_id = "campaign--22222222-2222-4222-8222-222222222222"
    assert source_stix_identity("source-a", stix_id) != source_stix_identity("source-a", other_id)


def test_alias_normalization_collapses_unicode_whitespace_and_case():
    assert normalize_alias("  Café\tTEAM  ") == ("Café TEAM", "café team")
    assert normalize_alias("Cafe\u0301 team")[1] == "café team"


def _attack_payload(external_references):
    return {"type": "attack-pattern", "id": "attack-pattern--11111111-1111-4111-8111-111111111111", "name": "Synthetic technique", "created": "2026-08-01T00:00:00.000000Z", "modified": "2026-08-01T01:00:00.000000Z", "confidence": 75, "revoked": False, "external_references": external_references}


def test_attack_mapping_requires_one_valid_mitre_attack_identity():
    mapped = map_threat_entity(_attack_payload([{"source_name": "mitre-attack", "external_id": "T1059.001"}]))
    assert mapped is not None
    assert mapped.entity_type == "attack_technique"
    assert mapped.attack_id == "T1059.001"
    assert mapped.confidence == Decimal("0.750")
    assert map_threat_entity(_attack_payload([{"source_name": "example", "external_id": "T1059"}])) is None
    with pytest.raises(ThreatKnowledgeError, match="Conflicting"):
        map_threat_entity(_attack_payload([{"source_name": "mitre-attack", "external_id": "T1059"}, {"source_name": "mitre-attack", "external_id": "T1105"}]))


def test_approved_relationship_matrix_is_exact():
    assert APPROVED_RELATIONSHIPS == frozenset({("threat_actor", "uses", "malware_family"), ("threat_actor", "uses", "attack_technique"), ("campaign", "uses", "malware_family"), ("campaign", "uses", "attack_technique"), ("malware_family", "uses", "attack_technique"), ("campaign", "attributed-to", "threat_actor")})
