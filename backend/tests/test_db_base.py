from app.db.base import Base, NAMING_CONVENTION
import app.models


APPROVED_NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def test_base_uses_approved_naming_convention():
    assert NAMING_CONVENTION == APPROVED_NAMING_CONVENTION
    assert Base.metadata.naming_convention == APPROVED_NAMING_CONVENTION


def test_naming_convention_includes_required_entries():
    assert set(Base.metadata.naming_convention) == {"pk", "fk", "uq", "ck", "ix"}


def test_base_metadata_has_all_implemented_tables_after_model_registration():
    assert set(Base.metadata.tables) == {
        "indicator_provenances",
        "indicators",
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


def test_implemented_domain_models_are_registered():
    assert {mapper.class_ for mapper in Base.registry.mappers} >= {
        app.models.IngestionError,
        app.models.IngestionRun,
        app.models.IngestionRunRecord,
        app.models.Indicator,
        app.models.IndicatorProvenance,
        app.models.IntelligenceItemIdentifier,
        app.models.IntelligenceItemTag,
        app.models.IntelligenceSource,
        app.models.IntelligenceItem,
        app.models.SourceRecord,
        app.models.Tag,
        app.models.Vulnerability,
    }
