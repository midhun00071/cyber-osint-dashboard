from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Identity,
    Numeric,
    String,
    Text,
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
FUTURE_TABLES = {
    "ingestion_runs",
    "ingestion_run_records",
    "ingestion_errors",
}


@pytest.fixture(scope="module")
def models():
    import app.models

    return app.models


@pytest.fixture(scope="module")
def source_table(models):
    return Base.metadata.tables["intelligence_sources"]


@pytest.fixture(scope="module")
def item_table(models):
    return Base.metadata.tables["intelligence_items"]


def constraint_names(table, constraint_type):
    return {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, constraint_type)
    }


def check_constraint_sql(table):
    return {
        constraint.name: str(constraint.sqltext)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }


def unique_column_names(table):
    names = set()
    for constraint in table.constraints:
        if isinstance(constraint, UniqueConstraint) and len(constraint.columns) == 1:
            names.add(next(iter(constraint.columns)).name)
    return names


def test_importing_models_registers_only_implemented_tables_without_engine(monkeypatch):
    import app.db.session as db_session

    get_engine = monkeypatch.setattr(
        db_session,
        "get_engine",
        lambda: pytest.fail("model import must not request a database engine"),
    )
    import app.models

    assert get_engine is None
    assert IMPLEMENTED_TABLES <= set(Base.metadata.tables)
    assert FUTURE_TABLES.isdisjoint(Base.metadata.tables)
    assert set(app.models.__all__) == {
        "IntelligenceItem",
        "IntelligenceItemIdentifier",
        "IntelligenceItemTag",
        "IntelligenceSource",
        "SourceRecord",
        "Tag",
        "Vulnerability",
    }


def test_mapper_configuration_succeeds_without_database_connection(models, monkeypatch):
    import app.db.session as db_session

    monkeypatch.setattr(
        db_session,
        "get_engine",
        lambda: pytest.fail("mapper configuration must not connect to a database"),
    )

    configure_mappers()


def test_shared_internal_ids_use_bigint_identity(source_table, item_table):
    for table in (source_table, item_table):
        column = table.c.id
        assert isinstance(column.type, BigInteger)
        assert isinstance(column.identity, Identity)
        assert column.primary_key is True
        assert column.nullable is False


def test_shared_public_ids_use_callable_uuid4_python_defaults(source_table, item_table):
    for table in (source_table, item_table):
        column = table.c.public_id
        assert column.nullable is False
        assert column.unique is True
        assert column.default is not None
        assert column.default.is_callable is True

        generated = column.default.arg(None)

        assert isinstance(generated, UUID)
        assert generated.version == 4


def test_shared_timestamps_are_aware_utc_callable_defaults(source_table, item_table):
    for table in (source_table, item_table):
        for column_name in ("created_at", "updated_at"):
            column = table.c[column_name]
            assert isinstance(column.type, DateTime)
            assert column.type.timezone is True
            assert column.nullable is False
            assert column.default is not None
            assert column.default.is_callable is True

            generated = column.default.arg(None)

            assert generated.tzinfo is UTC

        assert table.c.updated_at.onupdate is not None
        assert table.c.updated_at.onupdate.is_callable is True


def test_intelligence_sources_columns_match_approved_design(source_table):
    assert source_table.name == "intelligence_sources"
    assert list(source_table.c.keys()) == [
        "name",
        "slug",
        "source_type",
        "base_url",
        "is_enabled",
        "rate_limit_notes",
        "last_successful_fetch_at",
        "checkpoint_value",
        "id",
        "public_id",
        "created_at",
        "updated_at",
    ]


def test_intelligence_sources_lengths_nullability_and_defaults(source_table):
    expected_strings = {
        "name": (160, False),
        "slug": (80, False),
        "source_type": (40, False),
        "base_url": (2048, True),
        "rate_limit_notes": (500, True),
        "checkpoint_value": (500, True),
    }
    for column_name, (length, nullable) in expected_strings.items():
        column = source_table.c[column_name]
        assert isinstance(column.type, String)
        assert column.type.length == length
        assert column.nullable is nullable

    assert isinstance(source_table.c.is_enabled.type, Boolean)
    assert source_table.c.is_enabled.nullable is False
    assert source_table.c.is_enabled.default.arg is True
    assert isinstance(source_table.c.last_successful_fetch_at.type, DateTime)
    assert source_table.c.last_successful_fetch_at.type.timezone is True
    assert source_table.c.last_successful_fetch_at.nullable is True


def test_intelligence_sources_uniques_checks_and_no_credentials(source_table):
    assert {"public_id", "name", "slug"} <= unique_column_names(source_table)
    assert "ck_intelligence_sources_source_type_allowed" in constraint_names(
        source_table,
        CheckConstraint,
    )

    forbidden_fragments = ("api_key", "token", "authorization", "cookie", "secret")
    for column_name in source_table.c.keys():
        assert all(fragment not in column_name for fragment in forbidden_fragments)


def test_intelligence_items_columns_match_approved_design(item_table):
    assert item_table.name == "intelligence_items"
    assert list(item_table.c.keys()) == [
        "item_type",
        "canonical_title",
        "summary",
        "canonical_url",
        "source_published_at",
        "source_modified_at",
        "collected_at",
        "last_seen_at",
        "status",
        "superseded_by_item_id",
        "merged_into_item_id",
        "data_confidence",
        "geographic_scope",
        "uae_relevance_status",
        "uae_relevance_confidence",
        "uae_relevance_reason",
        "uae_relevance_method",
        "analyst_review_status",
        "id",
        "public_id",
        "created_at",
        "updated_at",
    ]


def test_intelligence_items_lengths_precision_scale_and_nullability(item_table):
    expected_strings = {
        "item_type": (40, False),
        "canonical_title": (500, False),
        "canonical_url": (2048, True),
        "status": (40, False),
        "geographic_scope": (40, False),
        "uae_relevance_status": (40, False),
        "uae_relevance_reason": (1000, True),
        "uae_relevance_method": (40, False),
        "analyst_review_status": (40, False),
    }
    for column_name, (length, nullable) in expected_strings.items():
        column = item_table.c[column_name]
        assert isinstance(column.type, String)
        assert column.type.length == length
        assert column.nullable is nullable

    assert isinstance(item_table.c.summary.type, Text)
    assert item_table.c.summary.nullable is True

    for column_name in (
        "source_published_at",
        "source_modified_at",
        "collected_at",
        "last_seen_at",
    ):
        column = item_table.c[column_name]
        assert isinstance(column.type, DateTime)
        assert column.type.timezone is True

    assert item_table.c.collected_at.nullable is False
    assert item_table.c.last_seen_at.nullable is False
    assert item_table.c.collected_at.default.is_callable is True
    assert item_table.c.last_seen_at.default.is_callable is True

    for column_name in ("data_confidence", "uae_relevance_confidence"):
        column = item_table.c[column_name]
        assert isinstance(column.type, Numeric)
        assert column.type.precision == 4
        assert column.type.scale == 3
        assert column.nullable is True


def test_intelligence_items_canonical_url_is_not_unique(item_table):
    assert item_table.c.canonical_url.unique is not True
    unique_sets = {
        tuple(column.name for column in constraint.columns)
        for constraint in item_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("canonical_url",) not in unique_sets


def test_intelligence_items_self_foreign_keys_use_restrict(item_table):
    self_fks = [
        constraint
        for constraint in item_table.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    ]
    assert len(self_fks) == 2

    constrained_columns = {
        next(iter(constraint.columns)).name: constraint
        for constraint in self_fks
    }
    assert set(constrained_columns) == {
        "superseded_by_item_id",
        "merged_into_item_id",
    }

    for constraint in constrained_columns.values():
        element = next(iter(constraint.elements))
        assert element.target_fullname == "intelligence_items.id"
        assert element.ondelete == "RESTRICT"


def test_intelligence_items_constraints_match_p1_11a_requirements(item_table):
    checks = check_constraint_sql(item_table)
    assert {
        "ck_intelligence_items_item_type_allowed",
        "ck_intelligence_items_status_allowed",
        "ck_intelligence_items_geographic_scope_allowed",
        "ck_intelligence_items_uae_relevance_status_allowed",
        "ck_intelligence_items_uae_relevance_method_allowed",
        "ck_intelligence_items_data_confidence_range",
        "ck_intelligence_items_uae_relevance_confidence_range",
        "ck_intelligence_items_superseded_by_not_self",
        "ck_intelligence_items_merged_into_not_self",
        "ck_intelligence_items_single_lifecycle_pointer",
        "ck_intelligence_items_merged_requires_target",
        "ck_intelligence_items_superseded_requires_target",
    } <= set(checks)
    assert "analyst_review_status" not in " ".join(checks.values())


def test_intelligence_items_required_indexes_preserve_descending_timestamp(item_table):
    expected_names = {
        "ix_intelligence_items_item_type_source_published_at_desc",
        "ix_intelligence_items_status_source_published_at_desc",
        "ix_intel_items_uae_rel_status_published_desc",
    }
    indexes = {index.name: index for index in item_table.indexes}

    assert expected_names == set(indexes)

    dialect = postgresql.dialect()
    for index_name, leading_column in {
        "ix_intelligence_items_item_type_source_published_at_desc": "item_type",
        "ix_intelligence_items_status_source_published_at_desc": "status",
        "ix_intel_items_uae_rel_status_published_desc": "uae_relevance_status",
    }.items():
        ddl = str(CreateIndex(indexes[index_name]).compile(dialect=dialect))
        assert leading_column in ddl
        assert "source_published_at DESC" in ddl


def test_intelligence_item_relationships_configure_without_ambiguity(models):
    mapper = models.IntelligenceItem.__mapper__
    superseded_by = mapper.relationships["superseded_by"]
    merged_into = mapper.relationships["merged_into"]

    assert {column.name for column in superseded_by.local_columns} == {
        "superseded_by_item_id"
    }
    assert {column.name for column in merged_into.local_columns} == {
        "merged_into_item_id"
    }
    assert superseded_by.cascade.delete is False
    assert merged_into.cascade.delete is False


def test_postgresql_table_and_index_compilation_succeeds_without_connection(
    source_table,
    item_table,
):
    dialect = postgresql.dialect()

    for table in (source_table, item_table):
        ddl = str(CreateTable(table).compile(dialect=dialect))
        assert "BIGINT GENERATED" in ddl
        assert "UUID" in ddl

    for index in item_table.indexes:
        str(CreateIndex(index).compile(dialect=dialect))


def test_model_layer_does_not_define_unsafe_repr_or_future_tables(models):
    assert "__repr__" not in models.IntelligenceSource.__dict__
    assert "__repr__" not in models.IntelligenceItem.__dict__
    assert FUTURE_TABLES.isdisjoint(Base.metadata.tables)
