from sqlalchemy import inspect

from app.models import AuthIdentity, AuthLocalCredential, AuthLoginThrottle, AuthSession, AuthUser, AuthUserRole


def test_auth_models_map_exact_tables_and_primary_keys() -> None:
    models = {AuthUser: "auth_users", AuthIdentity: "auth_identities", AuthLocalCredential: "auth_local_credentials", AuthUserRole: "auth_user_roles", AuthSession: "auth_sessions", AuthLoginThrottle: "auth_login_throttles"}
    assert {model.__tablename__ for model in models} == set(models.values())
    assert [column.name for column in inspect(AuthLocalCredential).primary_key] == ["identity_id"]
    assert [column.name for column in inspect(AuthUserRole).primary_key] == ["user_id"]


def test_session_and_role_constraints_are_closed() -> None:
    role_constraints = " ".join(str(item.sqltext) for item in AuthUserRole.__table__.constraints if hasattr(item, "sqltext"))
    session_constraints = " ".join(str(item.sqltext) for item in AuthSession.__table__.constraints if hasattr(item, "sqltext"))
    for role in ("viewer", "analyst", "ingestion_operator", "administrator"):
        assert role in role_constraints
    for reason in ("logout", "refresh", "password_change", "account_disabled", "role_changed", "admin_revocation", "session_limit"):
        assert reason in session_constraints
