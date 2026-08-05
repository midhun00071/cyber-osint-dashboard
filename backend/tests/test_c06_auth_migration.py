import importlib.util
from pathlib import Path


def test_c06_revision_is_exact_linear_append() -> None:
    path = Path(__file__).parents[1] / "alembic" / "versions" / "f4a1c2d3e5b6_add_identity_auth_session_rbac.py"
    spec = importlib.util.spec_from_file_location("c06_migration", path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert migration.revision == "f4a1c2d3e5b6"
    assert migration.down_revision == "e91f4c2a7b60"


def test_c06_migration_creates_only_the_six_auth_tables() -> None:
    path = Path(__file__).parents[1] / "alembic" / "versions" / "f4a1c2d3e5b6_add_identity_auth_session_rbac.py"
    source = path.read_text(encoding="utf-8")
    expected = {"auth_users", "auth_identities", "auth_local_credentials", "auth_user_roles", "auth_sessions", "auth_login_throttles"}
    assert {name for name in expected if f'op.create_table(\n        "{name}"' in source} == expected
    assert "op.bulk_insert" not in source
    assert "DATABASE_URL" not in source
    assert "password_hash LIKE '$argon2id$%'" in source


def test_c06_session_time_order_and_revocation_constraints_are_unchanged() -> None:
    path = Path(__file__).parents[1] / "alembic" / "versions" / "f4a1c2d3e5b6_add_identity_auth_session_rbac.py"
    source = path.read_text(encoding="utf-8")
    for exact_constraint in (
        'sa.CheckConstraint("expires_at > issued_at AND absolute_expires_at >= expires_at", name="ck_auth_sessions_expiry_order")',
        'sa.CheckConstraint("rotated_at IS NULL OR (rotated_at >= issued_at AND rotated_at <= absolute_expires_at)", name="ck_auth_sessions_rotated_at_order")',
        'sa.CheckConstraint("(revoked_at IS NULL AND revocation_reason IS NULL) OR (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)", name="ck_auth_sessions_revocation_shape")',
        'sa.CheckConstraint("revoked_at IS NULL OR (revoked_at >= issued_at AND revoked_at <= updated_at)", name="ck_auth_sessions_revoked_at_order")',
    ):
        assert source.count(exact_constraint) == 1


def test_c06_downgrade_removes_auth_tables_in_dependency_safe_order() -> None:
    path = Path(__file__).parents[1] / "alembic" / "versions" / "f4a1c2d3e5b6_add_identity_auth_session_rbac.py"
    source = path.read_text(encoding="utf-8").split("def downgrade() -> None:", 1)[1]
    expected = (
        "auth_login_throttles",
        "auth_sessions",
        "auth_user_roles",
        "auth_local_credentials",
        "auth_identities",
        "auth_users",
    )
    assert tuple(
        sorted(expected, key=lambda table: source.index(f'op.drop_table("{table}")'))
    ) == expected
