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
        "audit_events",
        "indicator_provenances",
        "indicators",
        "ingestion_cycles",
        "ingestion_errors",
        "ingestion_run_records",
        "ingestion_runs",
        "ingestion_run_events",
        "intelligence_item_identifiers",
        "intelligence_item_indicators",
        "intelligence_item_tags",
        "intelligence_items",
        "intelligence_sources",
        "quarantined_records",
        "source_checkpoints",
        "source_credential_references",
        "source_rate_limit_states",
        "source_records",
        "source_watermarks",
        "tags",
        "vulnerabilities",
    }


def test_implemented_domain_models_are_registered():
    assert {mapper.class_ for mapper in Base.registry.mappers} >= {
        app.models.AuditEvent,
        app.models.IngestionCycle,
        app.models.IngestionError,
        app.models.IngestionRun,
        app.models.IngestionRunEvent,
        app.models.IngestionRunRecord,
        app.models.Indicator,
        app.models.IndicatorProvenance,
        app.models.IntelligenceItemIdentifier,
        app.models.IntelligenceItemIndicator,
        app.models.IntelligenceItemTag,
        app.models.IntelligenceSource,
        app.models.QuarantinedRecord,
        app.models.SourceCheckpoint,
        app.models.SourceCredentialReference,
        app.models.SourceRateLimitState,
        app.models.IntelligenceItem,
        app.models.SourceRecord,
        app.models.SourceWatermark,
        app.models.Tag,
        app.models.Vulnerability,
    }
