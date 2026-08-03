"""add threat knowledge models

Revision ID: e91f4c2a7b60
Revises: d7a9e51c2f40
Create Date: 2026-08-03 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "e91f4c2a7b60"
down_revision: str | Sequence[str] | None = "d7a9e51c2f40"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "threat_entities",
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("source_record_id", sa.BigInteger(), nullable=False),
        sa.Column("entity_type", sa.String(40), nullable=False),
        sa.Column("stix_id", sa.String(300), nullable=False),
        sa.Column("identity_sha256", sa.String(64), nullable=False),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("attack_id", sa.String(20), nullable=True),
        sa.Column("confidence", sa.Numeric(4, 3), nullable=True),
        sa.Column("stix_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stix_modified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("entity_type IN ('threat_actor', 'campaign', 'malware_family', 'attack_technique')", name="ck_threat_entities_type_allowed"),
        sa.CheckConstraint("char_length(name) BETWEEN 1 AND 500", name="ck_threat_entities_name_length"),
        sa.CheckConstraint("identity_sha256 ~ '^[0-9a-f]{64}$'", name="ck_threat_entities_identity_format"),
        sa.CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_threat_entities_confidence_range"),
        sa.CheckConstraint("stix_modified_at >= stix_created_at", name="ck_threat_entities_stix_time_order"),
        sa.CheckConstraint("(entity_type = 'attack_technique' AND attack_id IS NOT NULL) OR (entity_type <> 'attack_technique' AND attack_id IS NULL)", name="ck_threat_entities_attack_id_consistency"),
        sa.CheckConstraint("attack_id IS NULL OR attack_id ~ '^T[0-9]{4}(\\.[0-9]{3})?$'", name="ck_threat_entities_attack_id_format"),
        sa.ForeignKeyConstraint(["source_id"], ["intelligence_sources.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["source_record_id", "source_id"], ["source_records.id", "source_records.source_id"], name="fk_threat_entities_source_record_source", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_entities")),
        sa.UniqueConstraint("public_id", name=op.f("uq_threat_entities_public_id")),
        sa.UniqueConstraint("id", "source_id", name="uq_threat_entities_id_source_id"),
        sa.UniqueConstraint("id", "source_id", "source_record_id", name="uq_threat_entities_id_source_record_source"),
        sa.UniqueConstraint("source_id", "stix_id", name="uq_threat_entities_source_stix_id"),
        sa.UniqueConstraint("source_id", "source_record_id", name="uq_threat_entities_source_record"),
    )
    op.create_index("uq_threat_entities_identity_sha256", "threat_entities", ["identity_sha256"], unique=True)
    op.create_index("ix_threat_entities_source_type", "threat_entities", ["source_id", "entity_type"])
    op.create_index("ix_threat_entities_attack_id", "threat_entities", ["attack_id"])
    op.create_index("ix_threat_entities_source_revoked", "threat_entities", ["source_id", "revoked"])
    op.create_index("ix_threat_entities_modified_desc", "threat_entities", [sa.desc("stix_modified_at")])

    op.create_table(
        "threat_entity_aliases",
        sa.Column("threat_entity_id", sa.BigInteger(), nullable=False),
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("source_record_id", sa.BigInteger(), nullable=False),
        sa.Column("display_value", sa.String(500), nullable=False),
        sa.Column("normalized_value", sa.String(500), nullable=False),
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("char_length(display_value) BETWEEN 1 AND 500", name="ck_threat_entity_aliases_display_length"),
        sa.CheckConstraint("char_length(normalized_value) BETWEEN 1 AND 500", name="ck_threat_entity_aliases_normalized_length"),
        sa.ForeignKeyConstraint(["threat_entity_id", "source_id", "source_record_id"], ["threat_entities.id", "threat_entities.source_id", "threat_entities.source_record_id"], name="fk_threat_entity_aliases_entity_provenance", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_record_id", "source_id"], ["source_records.id", "source_records.source_id"], name="fk_threat_entity_aliases_source_record_source", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_entity_aliases")),
        sa.UniqueConstraint("threat_entity_id", "normalized_value", name="uq_threat_entity_aliases_entity_identity"),
    )
    op.create_index("ix_threat_entity_aliases_source", "threat_entity_aliases", ["source_id"])

    op.create_table(
        "threat_relationships",
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("source_record_id", sa.BigInteger(), nullable=False),
        sa.Column("source_entity_id", sa.BigInteger(), nullable=False),
        sa.Column("target_entity_id", sa.BigInteger(), nullable=False),
        sa.Column("relationship_type", sa.String(40), nullable=False),
        sa.Column("stix_id", sa.String(300), nullable=False),
        sa.Column("identity_sha256", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Numeric(4, 3), nullable=True),
        sa.Column("stix_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stix_modified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stop_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("relationship_type IN ('uses', 'attributed-to')", name="ck_threat_relationships_type_allowed"),
        sa.CheckConstraint("identity_sha256 ~ '^[0-9a-f]{64}$'", name="ck_threat_relationships_identity_format"),
        sa.CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_threat_relationships_confidence_range"),
        sa.CheckConstraint("stix_modified_at >= stix_created_at", name="ck_threat_relationships_stix_time_order"),
        sa.CheckConstraint("stop_time IS NULL OR start_time IS NULL OR stop_time >= start_time", name="ck_threat_relationships_active_time_order"),
        sa.CheckConstraint("source_entity_id <> target_entity_id", name="ck_threat_relationships_not_self"),
        sa.ForeignKeyConstraint(["source_id"], ["intelligence_sources.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["source_record_id", "source_id"], ["source_records.id", "source_records.source_id"], name="fk_threat_relationships_source_record_source", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["source_entity_id", "source_id"], ["threat_entities.id", "threat_entities.source_id"], name="fk_threat_relationships_source_entity_source", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_entity_id", "source_id"], ["threat_entities.id", "threat_entities.source_id"], name="fk_threat_relationships_target_entity_source", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_relationships")),
        sa.UniqueConstraint("public_id", name=op.f("uq_threat_relationships_public_id")),
        sa.UniqueConstraint("source_id", "stix_id", name="uq_threat_relationships_source_stix_id"),
        sa.UniqueConstraint("source_id", "source_record_id", name="uq_threat_relationships_source_record"),
    )
    op.create_index("uq_threat_relationships_identity_sha256", "threat_relationships", ["identity_sha256"], unique=True)
    op.create_index("ix_threat_relationships_source_type", "threat_relationships", ["source_id", "relationship_type"])
    op.create_index("ix_threat_relationships_source_revoked", "threat_relationships", ["source_id", "revoked"])
    op.create_index("ix_threat_relationships_source_endpoint", "threat_relationships", ["source_id", "source_entity_id"])
    op.create_index("ix_threat_relationships_target_endpoint", "threat_relationships", ["source_id", "target_entity_id"])
    op.create_index("ix_threat_relationships_modified_desc", "threat_relationships", [sa.desc("stix_modified_at")])


def downgrade() -> None:
    op.drop_table("threat_relationships")
    op.drop_table("threat_entity_aliases")
    op.drop_table("threat_entities")
