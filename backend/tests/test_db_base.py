from app.db.base import Base, NAMING_CONVENTION


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


def test_base_metadata_has_no_tables_during_p1_10():
    assert Base.metadata.tables == {}


def test_no_domain_models_are_registered_during_p1_10():
    assert list(Base.registry.mappers) == []
