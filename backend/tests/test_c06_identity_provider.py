from dataclasses import FrozenInstanceError
import pytest
from sqlalchemy.dialects import postgresql

from app.security.contracts import VerifiedIdentity
from app.security.identity import LOCAL_PROVIDER_KEY, LocalIdentityProvider, canonicalize_local_username


def test_local_username_is_ascii_canonical_and_confusable_safe() -> None:
    assert canonicalize_local_username("Analyst.One") == "analyst.one"
    assert canonicalize_local_username("аnalyst") is None
    assert canonicalize_local_username("two words") is None
    assert LocalIdentityProvider.provider_key == LOCAL_PROVIDER_KEY == "local"


def test_verified_identity_contract_is_frozen() -> None:
    assert VerifiedIdentity.__dataclass_params__.frozen is True


class _EmptyResult:
    def one_or_none(self):
        return None


class _CapturingSession:
    def __init__(self) -> None:
        self.statements = []

    def execute(self, statement):
        self.statements.append(statement)
        return _EmptyResult()


def test_local_provider_lookup_is_unlocked_by_default_and_locks_on_request() -> None:
    session = _CapturingSession()
    provider = LocalIdentityProvider(session)

    assert provider.lookup("analyst") is None
    assert provider.lookup("analyst", for_update=True) is None

    ordinary_sql = str(
        session.statements[0].compile(dialect=postgresql.dialect())
    ).upper()
    locked_sql = str(
        session.statements[1].compile(dialect=postgresql.dialect())
    ).upper()
    assert "FOR UPDATE" not in ordinary_sql
    assert "FOR UPDATE" in locked_sql
    for table in (
        "auth_identities",
        "auth_local_credentials",
        "auth_users",
        "auth_user_roles",
    ):
        assert table.upper() in locked_sql
