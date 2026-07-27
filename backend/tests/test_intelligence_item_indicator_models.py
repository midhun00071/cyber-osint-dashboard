from datetime import UTC
import warnings

import pytest
from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Numeric,
    PrimaryKeyConstraint,
    String,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import SAWarning
from sqlalchemy.orm import configure_mappers
from sqlalchemy.schema import CreateIndex, CreateTable

from app.db.base import Base


EXPECTED_COLUMNS = [
    "intelligence_item_id",
    "indicator_id",
    "relationship_type",
    "extraction_method",
    "confidence",
    "context_summary",
    "first_observed_at",
    "last_observed_at",
    "created_at",
    "updated_at",
]


@pytest.fixture(scope="module", autouse=True)
def models():
    import app.models

    return app.models


@pytest.fixture(scope="module")
def table(models):
    return Base.metadata.tables["intelligence_item_indicators"]


def test_table_columns_composite_primary_key_and_types(table):
    assert table.name == "intelligence_item_indicators"
    assert list(table.c.keys()) == EXPECTED_COLUMNS
    primary_key = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, PrimaryKeyConstraint)
    )
    assert list(primary_key.columns.keys()) == ["intelligence_item_id", "indicator_id"]

    for name, length, nullable in (
        ("relationship_type", 40, False),
        ("extraction_method", 40, False),
        ("context_summary", 500, True),
    ):
        column = table.c[name]
        assert isinstance(column.type, String)
        assert column.type.length == length
        assert column.nullable is nullable

    assert isinstance(table.c.confidence.type, Numeric)
    assert (table.c.confidence.type.precision, table.c.confidence.type.scale) == (4, 3)
    assert table.c.confidence.nullable is False
    for name in ("first_observed_at", "last_observed_at", "created_at", "updated_at"):
        assert isinstance(table.c[name].type, DateTime)
        assert table.c[name].type.timezone is True
        assert table.c[name].nullable is False
    assert table.c.created_at.default.arg(None).tzinfo is UTC
    assert table.c.updated_at.default.arg(None).tzinfo is UTC
    assert table.c.updated_at.onupdate is not None


def test_foreign_keys_constraints_and_reverse_index(table):
    foreign_keys = {
        tuple(constraint.column_keys): (
            tuple(element.target_fullname for element in constraint.elements),
            constraint.ondelete,
        )
        for constraint in table.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    }
    assert foreign_keys == {
        ("intelligence_item_id",): (("intelligence_items.id",), "CASCADE"),
        ("indicator_id",): (("indicators.id",), "CASCADE"),
    }
    assert {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    } == {
        "ck_intelligence_item_indicators_relationship_type_allowed",
        "ck_intelligence_item_indicators_extraction_method_allowed",
        "ck_intelligence_item_indicators_confidence_range",
        "ck_intelligence_item_indicators_observed_at_order",
    }
    indexes = {index.name: index for index in table.indexes}
    assert set(indexes) == {"ix_intelligence_item_indicators_indicator_id_item_id"}
    assert [column.name for column in next(iter(indexes.values())).columns] == [
        "indicator_id",
        "intelligence_item_id",
    ]


def test_reciprocal_mappers_configure_offline_without_warnings(models, monkeypatch):
    import app.db.session as db_session
    from app.models import Indicator, IntelligenceItem, IntelligenceItemIndicator

    monkeypatch.setattr(
        db_session,
        "get_engine",
        lambda: pytest.fail("mapper configuration must remain offline"),
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", SAWarning)
        configure_mappers()

    assert not [warning for warning in caught if issubclass(warning.category, SAWarning)]
    assert IntelligenceItem.indicator_relationships.property.back_populates == (
        "intelligence_item"
    )
    assert Indicator.intelligence_item_relationships.property.back_populates == "indicator"
    assert IntelligenceItemIndicator.intelligence_item.property.back_populates == (
        "indicator_relationships"
    )
    assert IntelligenceItemIndicator.indicator.property.back_populates == (
        "intelligence_item_relationships"
    )


def test_postgresql_ddl_is_safe_metadata_only(table):
    dialect = postgresql.dialect()
    ddl = str(CreateTable(table).compile(dialect=dialect))
    index_ddl = " ".join(
        str(CreateIndex(index).compile(dialect=dialect)) for index in table.indexes
    )
    assert "TIMESTAMP WITH TIME ZONE" in ddl
    assert "ON DELETE CASCADE" in ddl
    assert "indicator_id, intelligence_item_id" in index_ddl
    forbidden = (
        "raw_payload",
        "credential",
        "secret",
        "token",
        "header",
        "cookie",
        "malware_sample",
        "stack_trace",
    )
    assert all(fragment not in column.name for column in table.c for fragment in forbidden)


def test_model_import_does_not_request_engine(monkeypatch):
    import app.db.session as db_session

    monkeypatch.setattr(
        db_session,
        "get_engine",
        lambda: pytest.fail("model import must not request an engine"),
    )
    import app.models.intelligence_item_indicator

    assert (
        app.models.intelligence_item_indicator.IntelligenceItemIndicator.__tablename__
        == "intelligence_item_indicators"
    )
