from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.core.config import Settings
from app.security.authorization import permissions_for_role
from app.security.contracts import AuthenticatedPrincipal, RoleKey


NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def settings(**overrides) -> Settings:
    values = {"APP_ENV": "test", "AUTH_COOKIE_SECURE": False}
    values.update(overrides)
    return Settings(_env_file=None, **values)


def principal(role: RoleKey = RoleKey.ADMINISTRATOR) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=1,
        user_public_id=uuid4(),
        display_name="Security Test User",
        role=role,
        permissions=permissions_for_role(role),
        account_expires_at=None,
        session_id=1,
        session_public_id=uuid4(),
        session_absolute_expires_at=NOW + timedelta(hours=8),
        csrf_token_hash="a" * 64,
    )
