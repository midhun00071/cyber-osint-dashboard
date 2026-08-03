import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url


ENV_NAME = "C03A_POSTGRESQL_TEST_DATABASE_URL"


@pytest.fixture(scope="module")
def disposable_url():
    raw = os.environ.get(ENV_NAME)
    if not raw:
        pytest.skip(f"{ENV_NAME} is not configured")
    url = make_url(raw)
    if url.get_backend_name() != "postgresql" or "test" not in (url.database or "").casefold():
        pytest.fail(f"{ENV_NAME} must identify an approved disposable PostgreSQL test database")
    return url


def test_postgresql_upgrade_constraints_indexes_and_downgrade(disposable_url):
    config = Config("alembic.ini")
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = disposable_url.render_as_string(hide_password=False)
    engine = create_engine(disposable_url)
    try:
        command.upgrade(config, "e91f4c2a7b60")
        inspector = inspect(engine)
        assert {"threat_entities", "threat_entity_aliases", "threat_relationships"} <= set(inspector.get_table_names())
        assert {item["name"] for item in inspector.get_indexes("threat_entities")} >= {"uq_threat_entities_identity_sha256", "ix_threat_entities_attack_id", "ix_threat_entities_source_revoked"}
        with engine.begin() as connection:
            with pytest.raises(Exception):
                connection.execute(text("INSERT INTO threat_relationships (source_id, source_record_id, source_entity_id, target_entity_id, relationship_type, stix_id, identity_sha256, stix_created_at, stix_modified_at, revoked, public_id, created_at, updated_at) VALUES (1,1,1,1,'uses','relationship--11111111-1111-4111-8111-111111111111',repeat('a',64),now(),now(),false,gen_random_uuid(),now(),now())"))
        command.downgrade(config, "d7a9e51c2f40")
        assert not ({"threat_entities", "threat_entity_aliases", "threat_relationships"} & set(inspect(engine).get_table_names()))
    finally:
        engine.dispose()
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
