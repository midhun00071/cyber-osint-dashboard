from datetime import UTC
from uuid import UUID
import warnings

import pytest
from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Identity,
    Numeric,
    String,
    UniqueConstraint,
)
from sqlalchemy.exc import SAWarning
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import configure_mappers
from sqlalchemy.schema import CreateIndex, CreateTable

from app.db.base import Base


EXPECTED_INDICATOR_COLUMNS = [
    "observable_type",
    "normalized_value",
    "hash_algorithm",
    "identity_sha256",
    "status",
    "confidence",
    "context_summary",
    "first_seen_at",
    "last_seen_at",
    "revoked_at",
    "expires_at",
    "id",
    "public_id",
    "created_at",
    "updated_at",
]
EXPECTED_PROVENANCE_COLUMNS = [
    "indicator_id",
    "source_id",
    "source_record_id",
    "confidence",
    "context_summary",
    "first_observed_at",
    "last_observed_at",
    "id",
    "public_id",
    "created_at",
    "updated_at",
]


@pytest.fixture(scope="module", autouse=True)
def models():
    import app.models

    return app.models


@pytest.fixture(scope="module")
def indicator_table(models):
    return Base.metadata.tables["indicators"]


@pytest.fixture(scope="module")
def provenance_table(models):
    return Base.metadata.tables["indicator_provenances"]


@pytest.fixture(scope="module")
def source_record_table(models):
    return Base.metadata.tables["source_records"]


def _check_names(table):
    return {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }


def _single_column_uniques(table):
    return {
        next(iter(constraint.columns)).name
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint) and len(constraint.columns) == 1
    }


def test_indicator_and_provenance_columns_match_approved_design(
    indicator_table,
    provenance_table,
):
    assert list(indicator_table.c.keys()) == EXPECTED_INDICATOR_COLUMNS
    assert list(provenance_table.c.keys()) == EXPECTED_PROVENANCE_COLUMNS


def test_indicator_string_lengths_numeric_precision_and_aware_timestamps(
    indicator_table,
):
    expected_strings = {
        "observable_type": (20, False),
        "normalized_value": (2048, False),
        "hash_algorithm": (20, True),
        "identity_sha256": (64, False),
        "status": (40, False),
        "context_summary": (1000, True),
    }
    for name, (length, nullable) in expected_strings.items():
        column = indicator_table.c[name]
        assert isinstance(column.type, String)
        assert column.type.length == length
        assert column.nullable is nullable

    confidence = indicator_table.c.confidence
    assert isinstance(confidence.type, Numeric)
    assert (confidence.type.precision, confidence.type.scale) == (4, 3)
    assert confidence.nullable is True

    for name in ("first_seen_at", "last_seen_at", "revoked_at", "expires_at"):
        column = indicator_table.c[name]
        assert isinstance(column.type, DateTime)
        assert column.type.timezone is True
        assert column.nullable is True


def test_provenance_lengths_numeric_precision_and_aware_timestamps(
    provenance_table,
):
    context = provenance_table.c.context_summary
    assert isinstance(context.type, String)
    assert context.type.length == 1000
    assert context.nullable is True

    confidence = provenance_table.c.confidence
    assert isinstance(confidence.type, Numeric)
    assert (confidence.type.precision, confidence.type.scale) == (4, 3)
    assert confidence.nullable is True

    for name in ("first_observed_at", "last_observed_at"):
        column = provenance_table.c[name]
        assert isinstance(column.type, DateTime)
        assert column.type.timezone is True
        assert column.nullable is True


def test_both_models_use_bigint_identity_public_uuid_and_utc_timestamps(
    indicator_table,
    provenance_table,
):
    for table in (indicator_table, provenance_table):
        assert isinstance(table.c.id.type, BigInteger)
        assert isinstance(table.c.id.identity, Identity)
        assert table.c.id.primary_key is True
        assert table.c.public_id.nullable is False
        assert "public_id" in _single_column_uniques(table)
        generated_public_id = table.c.public_id.default.arg(None)
        assert isinstance(generated_public_id, UUID)
        assert generated_public_id.version == 4

        for name in ("created_at", "updated_at"):
            column = table.c[name]
            assert isinstance(column.type, DateTime)
            assert column.type.timezone is True
            assert column.nullable is False
            assert column.default.arg(None).tzinfo is UTC
        assert table.c.updated_at.onupdate is not None


def test_indicator_checks_cover_identity_lifecycle_confidence_and_time_order(
    indicator_table,
):
    assert _check_names(indicator_table) == {
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
    }
    fingerprint_constraint = next(
        constraint
        for constraint in indicator_table.constraints
        if isinstance(constraint, CheckConstraint)
        and constraint.name == "ck_indicators_identity_sha256_format"
    )
    assert str(fingerprint_constraint.sqltext) == (
        "identity_sha256 ~ '^[0-9a-f]{64}$'"
    )


def test_provenance_checks_and_foreign_key_delete_actions(provenance_table):
    assert _check_names(provenance_table) == {
        "ck_indicator_provenances_confidence_range",
        "ck_indicator_provenances_observed_at_order",
    }
    foreign_keys = {
        tuple(constraint.column_keys): (
            tuple(element.target_fullname for element in constraint.elements),
            constraint.ondelete,
        )
        for constraint in provenance_table.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    }
    assert foreign_keys == {
        ("indicator_id",): (("indicators.id",), "CASCADE"),
        ("source_id",): (("intelligence_sources.id",), "RESTRICT"),
        ("source_record_id", "source_id"): (
            ("source_records.id", "source_records.source_id"),
            "RESTRICT",
        ),
    }
    assert provenance_table.c.indicator_id.nullable is False
    assert provenance_table.c.source_id.nullable is False
    assert provenance_table.c.source_record_id.nullable is True


def test_source_records_expose_composite_key_for_provenance_integrity(
    source_record_table,
):
    matching_constraints = [
        constraint
        for constraint in source_record_table.constraints
        if isinstance(constraint, UniqueConstraint)
        and constraint.name == "uq_source_records_id_source_id"
    ]

    assert len(matching_constraints) == 1
    assert list(matching_constraints[0].columns.keys()) == ["id", "source_id"]


def test_indicator_lookup_and_provenance_partial_unique_indexes(
    indicator_table,
    provenance_table,
):
    indicator_indexes = {index.name: index for index in indicator_table.indexes}
    assert set(indicator_indexes) == {
        "ix_indicators_observable_type_status",
        "ix_indicators_status_last_seen_at_desc",
        "uq_indicators_identity_sha256",
    }
    assert indicator_indexes["uq_indicators_identity_sha256"].unique is True
    assert [
        expression.name
        for expression in indicator_indexes[
            "ix_indicators_observable_type_status"
        ].expressions
    ] == ["observable_type", "status"]

    provenance_indexes = {index.name: index for index in provenance_table.indexes}
    assert set(provenance_indexes) == {
        "uq_indicator_provenances_indicator_source_record",
        "uq_indicator_provenances_indicator_source_without_record",
    }
    dialect = postgresql.dialect()
    compiled = {
        name: str(CreateIndex(index).compile(dialect=dialect))
        for name, index in provenance_indexes.items()
    }
    assert "source_record_id IS NOT NULL" in compiled[
        "uq_indicator_provenances_indicator_source_record"
    ]
    assert "source_record_id IS NULL" in compiled[
        "uq_indicator_provenances_indicator_source_without_record"
    ]
    assert all(index.unique is True for index in provenance_indexes.values())
    assert not any(
        {column.name for column in index.columns} == {"normalized_value"}
        for index in indicator_table.indexes
    )


def test_relationship_mapper_configuration_succeeds_offline(models, monkeypatch):
    import app.db.session as db_session
    from app.models.indicator import Indicator
    from app.models.indicator_provenance import IndicatorProvenance
    from app.models.intelligence_source import IntelligenceSource
    from app.models.source_record import SourceRecord

    monkeypatch.setattr(
        db_session,
        "get_engine",
        lambda: pytest.fail("mapper configuration must remain offline"),
    )
    with warnings.catch_warnings(record=True) as caught_warnings:
        warnings.simplefilter("always", SAWarning)
        configure_mappers()

    assert not [
        warning
        for warning in caught_warnings
        if issubclass(warning.category, SAWarning)
    ]

    assert Indicator.provenances.property.back_populates == "indicator"
    assert IndicatorProvenance.indicator.property.back_populates == "provenances"
    assert IndicatorProvenance.source.property.back_populates == (
        "indicator_provenances"
    )
    assert IndicatorProvenance.source_record.property.back_populates == (
        "indicator_provenances"
    )
    assert IntelligenceSource.indicator_provenances.property.back_populates == "source"
    assert SourceRecord.indicator_provenances.property.back_populates == "source_record"
    assert IndicatorProvenance.source.property._calculated_foreign_keys == {
        IndicatorProvenance.__table__.c.source_id
    }
    assert IndicatorProvenance.source_record.property._calculated_foreign_keys == {
        IndicatorProvenance.__table__.c.source_record_id
    }
    assert SourceRecord.indicator_provenances.property._calculated_foreign_keys == {
        IndicatorProvenance.__table__.c.source_record_id
    }
    assert IndicatorProvenance.source_record.property.synchronize_pairs == [
        (
            SourceRecord.__table__.c.id,
            IndicatorProvenance.__table__.c.source_record_id,
        )
    ]


def test_new_tables_compile_for_postgresql_and_contain_no_unsafe_columns(
    indicator_table,
    provenance_table,
):
    forbidden = (
        "raw_payload",
        "credential",
        "token",
        "api_key",
        "authorization",
        "header",
        "cookie",
        "secret",
        "stack_trace",
        "malware_sample",
    )
    dialect = postgresql.dialect()
    for table in (indicator_table, provenance_table):
        ddl = str(CreateTable(table).compile(dialect=dialect))
        assert "BIGINT GENERATED BY DEFAULT AS IDENTITY" in ddl
        assert "TIMESTAMP WITH TIME ZONE" in ddl
        for column_name in table.c.keys():
            assert all(fragment not in column_name for fragment in forbidden)


def test_model_import_does_not_request_database_engine(monkeypatch):
    import app.db.session as db_session

    monkeypatch.setattr(
        db_session,
        "get_engine",
        lambda: pytest.fail("model import must not request a database engine"),
    )

    import app.models.indicator
    import app.models.indicator_provenance

    assert app.models.indicator.Indicator.__tablename__ == "indicators"
    assert app.models.indicator_provenance.IndicatorProvenance.__tablename__ == (
        "indicator_provenances"
    )
