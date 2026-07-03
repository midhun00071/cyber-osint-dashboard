from datetime import UTC

import pytest
from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Identity,
    Numeric,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import configure_mappers
from sqlalchemy.schema import CreateIndex, CreateTable

from app.db.base import Base


IMPLEMENTED_TABLES = {
    "intelligence_item_identifiers",
    "intelligence_item_tags",
    "intelligence_items",
    "intelligence_sources",
    "source_records",
    "tags",
    "vulnerabilities",
}
INGESTION_TABLES = {
    "ingestion_runs",
    "ingestion_run_records",
    "ingestion_errors",
}


@pytest.fixture(scope="module")
def models():
    import app.models

    return app.models


@pytest.fixture(scope="module")
def tag_table(models):
    return Base.metadata.tables["tags"]


@pytest.fixture(scope="module")
def item_tag_table(models):
    return Base.metadata.tables["intelligence_item_tags"]


def check_constraint_sql(table):
    return {
        constraint.name: str(constraint.sqltext)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }


def foreign_key_by_column(table, column_name):
    for constraint in table.constraints:
        if isinstance(constraint, ForeignKeyConstraint):
            constrained = next(iter(constraint.columns)).name
            if constrained == column_name:
                return constraint
    raise AssertionError(f"missing FK for {table.name}.{column_name}")


def primary_key_columns(table):
    primary_key = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, PrimaryKeyConstraint)
    )
    return [column.name for column in primary_key.columns]


def unique_column_sets(table):
    return {
        tuple(column.name for column in constraint.columns)
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }


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
    assert INGESTION_TABLES.isdisjoint(Base.metadata.tables)
    assert set(app.models.__all__) == {
        "IntelligenceItem",
        "IntelligenceItemIdentifier",
        "IntelligenceItemTag",
        "IntelligenceSource",
        "SourceRecord",
        "Tag",
        "Vulnerability",
    }

    configure_mappers()


def test_tag_columns_constraints_and_defaults(tag_table):
    assert tag_table.name == "tags"
    assert list(tag_table.c.keys()) == [
        "slug",
        "display_name",
        "tag_type",
        "created_at",
        "id",
    ]
    assert "public_id" not in tag_table.c
    assert "updated_at" not in tag_table.c

    id_column = tag_table.c.id
    assert isinstance(id_column.type, BigInteger)
    assert isinstance(id_column.identity, Identity)
    assert id_column.primary_key is True
    assert id_column.nullable is False

    expected_strings = {
        "slug": (100, False),
        "display_name": (120, False),
        "tag_type": (40, False),
    }
    for column_name, (length, nullable) in expected_strings.items():
        column = tag_table.c[column_name]
        assert isinstance(column.type, String)
        assert column.type.length == length
        assert column.nullable is nullable

    assert ("slug",) in unique_column_sets(tag_table)
    assert ("display_name",) not in unique_column_sets(tag_table)
    assert ("tag_type", "display_name") not in unique_column_sets(tag_table)

    checks = check_constraint_sql(tag_table)
    assert "ck_tags_tag_type_allowed" in checks

    created_at = tag_table.c.created_at
    assert isinstance(created_at.type, DateTime)
    assert created_at.type.timezone is True
    assert created_at.nullable is False
    assert_callable_utc_default(created_at)


def test_item_tag_columns_composite_primary_key_and_defaults(item_tag_table):
    assert item_tag_table.name == "intelligence_item_tags"
    assert list(item_tag_table.c.keys()) == [
        "intelligence_item_id",
        "tag_id",
        "assigned_by",
        "confidence",
        "created_at",
    ]
    assert "id" not in item_tag_table.c
    assert "public_id" not in item_tag_table.c
    assert "updated_at" not in item_tag_table.c
    assert primary_key_columns(item_tag_table) == ["intelligence_item_id", "tag_id"]
    assert (("intelligence_item_id", "tag_id")) not in unique_column_sets(
        item_tag_table
    )

    for column_name in ("intelligence_item_id", "tag_id"):
        column = item_tag_table.c[column_name]
        assert isinstance(column.type, BigInteger)
        assert column.nullable is False
        assert column.primary_key is True

    assigned_by = item_tag_table.c.assigned_by
    assert isinstance(assigned_by.type, String)
    assert assigned_by.type.length == 40
    assert assigned_by.nullable is False
    assert assigned_by.default is None

    confidence = item_tag_table.c.confidence
    assert isinstance(confidence.type, Numeric)
    assert confidence.type.precision == 4
    assert confidence.type.scale == 3
    assert confidence.nullable is True
    assert confidence.default is None

    created_at = item_tag_table.c.created_at
    assert isinstance(created_at.type, DateTime)
    assert created_at.type.timezone is True
    assert created_at.nullable is False
    assert_callable_utc_default(created_at)


def test_item_tag_foreign_keys_and_deletion_behavior(item_tag_table):
    item_fk = foreign_key_by_column(item_tag_table, "intelligence_item_id")
    item_element = next(iter(item_fk.elements))
    assert item_element.target_fullname == "intelligence_items.id"
    assert item_element.ondelete == "CASCADE"

    tag_fk = foreign_key_by_column(item_tag_table, "tag_id")
    tag_element = next(iter(tag_fk.elements))
    assert tag_element.target_fullname == "tags.id"
    assert tag_element.ondelete == "RESTRICT"


def test_item_tag_constraints_and_reverse_index(item_tag_table):
    checks = check_constraint_sql(item_tag_table)
    assert {
        "ck_intelligence_item_tags_assigned_by_allowed",
        "ck_intelligence_item_tags_confidence_range",
    } <= set(checks)

    indexes = {index.name: index for index in item_tag_table.indexes}
    assert set(indexes) == {"ix_intelligence_item_tags_tag_id_item_id"}

    reverse_index = indexes["ix_intelligence_item_tags_tag_id_item_id"]
    assert [column.name for column in reverse_index.columns] == [
        "tag_id",
        "intelligence_item_id",
    ]
    assert reverse_index.unique is False


def test_tag_relationships_and_cascades(models):
    item_relationship = models.IntelligenceItem.__mapper__.relationships[
        "tag_assignments"
    ]
    tag_relationship = models.Tag.__mapper__.relationships["item_assignments"]
    assignment_mapper = models.IntelligenceItemTag.__mapper__

    assert item_relationship.back_populates == "intelligence_item"
    assert item_relationship.cascade.delete_orphan is True
    assert item_relationship.passive_deletes is True

    assert tag_relationship.back_populates == "tag"
    assert tag_relationship.cascade.delete is False
    assert tag_relationship.cascade.delete_orphan is False
    assert tag_relationship.passive_deletes is True

    assert (
        assignment_mapper.relationships["intelligence_item"].mapper.class_
        is models.IntelligenceItem
    )
    assert assignment_mapper.relationships["tag"].mapper.class_ is models.Tag
    assert "__repr__" not in models.Tag.__dict__
    assert "__repr__" not in models.IntelligenceItemTag.__dict__


def test_tag_tables_compile_for_postgresql_without_connection(tag_table, item_tag_table):
    dialect = postgresql.dialect()

    tag_ddl = str(CreateTable(tag_table).compile(dialect=dialect))
    assert "BIGINT GENERATED" in tag_ddl
    assert "CONSTRAINT ck_tags_tag_type_allowed" in tag_ddl
    assert "UNIQUE (slug)" in tag_ddl

    item_tag_ddl = str(CreateTable(item_tag_table).compile(dialect=dialect))
    assert "intelligence_item_id BIGINT NOT NULL" in item_tag_ddl
    assert "tag_id BIGINT NOT NULL" in item_tag_ddl
    assert "NUMERIC(4, 3)" in item_tag_ddl
    assert "CONSTRAINT ck_intelligence_item_tags_assigned_by_allowed" in item_tag_ddl
    assert "CONSTRAINT ck_intelligence_item_tags_confidence_range" in item_tag_ddl
    assert "FOREIGN KEY(intelligence_item_id)" in item_tag_ddl
    assert "ON DELETE CASCADE" in item_tag_ddl
    assert "FOREIGN KEY(tag_id)" in item_tag_ddl
    assert "ON DELETE RESTRICT" in item_tag_ddl

    reverse_index = next(iter(item_tag_table.indexes))
    reverse_ddl = str(CreateIndex(reverse_index).compile(dialect=dialect))
    assert "(tag_id, intelligence_item_id)" in reverse_ddl


def test_all_implemented_tables_compile_and_prior_indexes_remain_intact(models):
    dialect = postgresql.dialect()

    for table_name in IMPLEMENTED_TABLES:
        table = Base.metadata.tables[table_name]
        str(CreateTable(table).compile(dialect=dialect))
        for index in table.indexes:
            str(CreateIndex(index).compile(dialect=dialect))

    item_table = Base.metadata.tables["intelligence_items"]
    for index in item_table.indexes:
        if "published" in index.name:
            ddl = str(CreateIndex(index).compile(dialect=dialect))
            assert "source_published_at DESC" in ddl

    source_record_table = Base.metadata.tables["source_records"]
    source_record_ddl = str(CreateTable(source_record_table).compile(dialect=dialect))
    assert "JSONB" in source_record_ddl
    for index in source_record_table.indexes:
        ddl = str(CreateIndex(index).compile(dialect=dialect))
        if index.unique:
            assert "WHERE" in ddl

    vulnerability_ddl = str(
        CreateTable(Base.metadata.tables["vulnerabilities"]).compile(dialect=dialect)
    )
    assert "JSONB" in vulnerability_ddl


def test_ingestion_tables_remain_absent_and_no_unsafe_repr(models):
    assert INGESTION_TABLES.isdisjoint(Base.metadata.tables)
