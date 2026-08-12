import inspect
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql

import app.services.authentication_service as authentication_module
from app.models import AuthSession
from app.security.contracts import RoleKey, VerifiedIdentity
from app.security.sessions import IssuedSession
from app.services.authentication_service import AuthenticationService, INVALID_CREDENTIALS_DETAIL, SAFE_PASSWORD_CHANGE_ERROR, InvalidCredentialsError, PasswordChangeError
from tests.c06_auth_test_support import NOW, principal, settings


def test_login_has_one_argon_verification_call_for_all_identity_states() -> None:
    source = inspect.getsource(AuthenticationService.login)
    assert source.count("verify_password(") == 1
    assert "dummy_password_hash()" in source
    assert "blocked" in source and "account_valid" in source


def test_public_failure_is_fixed_and_does_not_name_identity() -> None:
    assert INVALID_CREDENTIALS_DETAIL == "Invalid credentials."
    assert "username" not in INVALID_CREDENTIALS_DETAIL.lower()


@pytest.mark.parametrize(
    "new_password",
    [
        "ValidPrefix!234\x00secret-canary",
        "ValidPrefix!234\nsecret-canary",
        "ValidPrefix!234\x01secret-canary",
    ],
)
def test_password_policy_rejection_is_a_fixed_service_error_before_persistence(new_password) -> None:
    class _NoPersistenceSession:
        def execute(self, _statement):
            raise AssertionError("password-policy rejection must precede persistence")

    with pytest.raises(PasswordChangeError) as exc_info:
        AuthenticationService(_NoPersistenceSession(), settings()).change_password(
            principal=principal(),
            current_password="CurrentPassword!234",
            new_password=new_password,
            correlation_id=str(uuid4()),
            now=NOW,
        )

    assert str(exc_info.value) == SAFE_PASSWORD_CHANGE_ERROR
    assert "secret-canary" not in repr(exc_info.value)


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value

    def one_or_none(self):
        return self.value


class _LoginSession:
    def __init__(self, user, credential, role=None):
        self.user = user
        self.credential = credential
        self.role = role or SimpleNamespace(role_key=RoleKey.VIEWER.value)
        self.statements = []

    def execute(self, statement):
        self.statements.append(statement)
        return _ScalarResult((self.user, self.credential, self.role))


def _verified_identity(
    *,
    status: str = "active",
    expires_at=None,
    session_version: int = 1,
    role: RoleKey = RoleKey.VIEWER,
    password_hash: str = "encoded-real-hash",
    public_id=None,
) -> VerifiedIdentity:
    return VerifiedIdentity(
        user_id=1,
        user_public_id=public_id or uuid4(),
        identity_id=1,
        display_name="Security Test User",
        status=status,
        account_expires_at=expires_at,
        session_version=session_version,
        role=role,
        password_hash=password_hash,
    )


def _issued_session() -> IssuedSession:
    row = AuthSession(
        id=9,
        public_id=uuid4(),
        user_id=1,
        token_hash="a" * 64,
        csrf_token_hash="b" * 64,
        user_session_version=1,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        absolute_expires_at=NOW + timedelta(hours=8),
        created_at=NOW,
        updated_at=NOW,
    )
    return IssuedSession(row=row, session_token="session-token", csrf_token="csrf-token")


def test_active_login_block_is_fixed_and_resets_only_after_expiry(monkeypatch) -> None:
    identity = _verified_identity()
    user = SimpleNamespace(id=1, public_id=identity.user_public_id, display_name="Security Test User", status="active", session_version=1, account_expires_at=None, last_authenticated_at=None, updated_at=NOW)
    credential = SimpleNamespace(password_hash="encoded-real-hash", updated_at=NOW)
    throttle = SimpleNamespace(failure_count=0, window_started_at=NOW, blocked_until=None, updated_at=NOW)
    service = AuthenticationService(_LoginSession(user, credential), settings(AUTH_LOGIN_FAILURE_LIMIT=5, AUTH_LOGIN_FAILURE_WINDOW_SECONDS=900, AUTH_LOGIN_BLOCK_SECONDS=600))
    service._locked_throttle = lambda _key, _now: throttle
    service._sessions.create = lambda **_kwargs: _issued_session()
    audit_details = []
    service._audit.append = lambda **kwargs: audit_details.append(kwargs.get("safe_detail"))
    lock_requests = []
    monkeypatch.setattr(
        authentication_module.LocalIdentityProvider,
        "lookup",
        lambda _self, _canonical, *, for_update=False: lock_requests.append(for_update) or identity,
    )
    verification_calls = []

    def verify(password, encoded_hash):
        verification_calls.append((password, encoded_hash))
        return password == "CorrectPassword!234"

    monkeypatch.setattr(authentication_module, "verify_password", verify)
    monkeypatch.setattr(authentication_module, "password_hash_needs_rehash", lambda _hash: False)

    for attempt in range(5):
        with pytest.raises(InvalidCredentialsError, match="Invalid credentials"):
            service.login(username="analyst", password="WrongPassword!234", correlation_id=str(uuid4()), now=NOW + timedelta(seconds=attempt))
        assert throttle.failure_count == attempt + 1

    original_window = throttle.window_started_at
    original_block = throttle.blocked_until
    assert original_block == NOW + timedelta(seconds=604)
    for password in ("WrongPassword!234", "CorrectPassword!234", "WrongPassword!234"):
        before = len(verification_calls)
        with pytest.raises(InvalidCredentialsError, match="Invalid credentials"):
            service.login(username="analyst", password=password, correlation_id=str(uuid4()), now=NOW + timedelta(seconds=30))
        assert len(verification_calls) == before + 1
        assert throttle.failure_count == 5
        assert throttle.window_started_at == original_window
        assert throttle.blocked_until == original_block

    principal, issued = service.login(username="analyst", password="CorrectPassword!234", correlation_id=str(uuid4()), now=original_block + timedelta(seconds=1))
    assert principal.user_id == 1 and issued.row.revoked_at is None
    assert throttle.failure_count == 0
    assert throttle.window_started_at == original_block + timedelta(seconds=1)
    assert throttle.blocked_until is None
    assert all(detail in (None, {"reason": "invalid_credentials"}) for detail in audit_details)
    assert lock_requests and all(lock_requests)


@pytest.mark.parametrize(
    ("identity", "password", "blocked"),
    [
        (None, "unknown-password-canary", False),
        (_verified_identity(status="disabled"), "CorrectPassword!234", False),
        (_verified_identity(expires_at=NOW - timedelta(seconds=1)), "CorrectPassword!234", False),
        (_verified_identity(), "CorrectPassword!234", True),
        (_verified_identity(), "wrong-password-canary", False),
    ],
)
def test_all_login_denials_are_publicly_indistinguishable_and_secret_free(monkeypatch, identity, password, blocked) -> None:
    throttle = SimpleNamespace(failure_count=0, window_started_at=NOW, blocked_until=NOW + timedelta(minutes=5) if blocked else None, updated_at=NOW)
    service = AuthenticationService(SimpleNamespace(), settings())
    service._locked_throttle = lambda _key, _now: throttle
    safe_details = []
    service._audit.append = lambda **kwargs: safe_details.append(kwargs.get("safe_detail"))
    monkeypatch.setattr(
        authentication_module.LocalIdentityProvider,
        "lookup",
        lambda _self, _canonical, *, for_update=False: identity,
    )
    calls = []
    monkeypatch.setattr(authentication_module, "verify_password", lambda supplied, encoded: calls.append((supplied, encoded)) or supplied == "CorrectPassword!234")

    with pytest.raises(InvalidCredentialsError) as exc_info:
        service.login(username="unknown-user-canary", password=password, correlation_id=str(uuid4()), now=NOW)

    assert str(exc_info.value) == INVALID_CREDENTIALS_DETAIL
    assert len(calls) == 1
    rendered = repr(exc_info.value) + repr(safe_details)
    assert "unknown-user-canary" not in rendered
    assert password not in rendered


def _unblocked_throttle():
    return SimpleNamespace(
        failure_count=0,
        window_started_at=NOW,
        blocked_until=None,
        updated_at=NOW,
    )


def test_locked_lookup_observes_newer_password_and_cannot_rehash_or_issue_from_old_password(monkeypatch) -> None:
    newer_hash = "newer-password-hash-canary"
    identity = _verified_identity(password_hash=newer_hash)
    user = SimpleNamespace(
        id=1,
        public_id=identity.user_public_id,
        display_name=identity.display_name,
        status="active",
        account_expires_at=None,
        session_version=1,
        last_authenticated_at=None,
        updated_at=NOW,
    )
    credential = SimpleNamespace(password_hash=newer_hash, updated_at=NOW)
    service = AuthenticationService(_LoginSession(user, credential), settings())
    service._locked_throttle = lambda _key, _now: _unblocked_throttle()
    service._audit.append = lambda **_kwargs: None
    lock_requests = []
    monkeypatch.setattr(
        authentication_module.LocalIdentityProvider,
        "lookup",
        lambda _self, _canonical, *, for_update=False: lock_requests.append(for_update) or identity,
    )
    verification_calls = []
    monkeypatch.setattr(
        authentication_module,
        "verify_password",
        lambda supplied, encoded: verification_calls.append((supplied, encoded)) or False,
    )
    monkeypatch.setattr(
        authentication_module,
        "password_hash_needs_rehash",
        lambda _encoded: (_ for _ in ()).throw(AssertionError("rehash check must not run")),
    )
    monkeypatch.setattr(
        authentication_module,
        "hash_password",
        lambda _password: (_ for _ in ()).throw(AssertionError("new hash must not be written")),
    )
    service._sessions.create = lambda **_kwargs: (_ for _ in ()).throw(
        AssertionError("stale credentials must not issue a session")
    )

    with pytest.raises(InvalidCredentialsError) as exc_info:
        service.login(
            username="analyst",
            password="SupersededPassword!234",
            correlation_id=str(uuid4()),
            now=NOW,
        )

    assert str(exc_info.value) == INVALID_CREDENTIALS_DETAIL
    assert lock_requests == [True]
    assert verification_calls == [("SupersededPassword!234", newer_hash)]
    assert credential.password_hash == newer_hash


def test_successful_locked_login_rehashes_the_unchanged_credential(monkeypatch) -> None:
    legacy_hash = "approved-legacy-hash"
    identity = _verified_identity(password_hash=legacy_hash)
    user = SimpleNamespace(
        id=1,
        public_id=identity.user_public_id,
        display_name=identity.display_name,
        status="active",
        account_expires_at=None,
        session_version=1,
        last_authenticated_at=None,
        updated_at=NOW,
    )
    credential = SimpleNamespace(password_hash=legacy_hash, updated_at=NOW)
    session = _LoginSession(user, credential)
    service = AuthenticationService(session, settings())
    service._locked_throttle = lambda _key, _now: _unblocked_throttle()
    service._audit.append = lambda **_kwargs: None
    service._sessions.create = lambda **_kwargs: _issued_session()
    monkeypatch.setattr(
        authentication_module.LocalIdentityProvider,
        "lookup",
        lambda _self, _canonical, *, for_update=False: identity if for_update else None,
    )
    verification_calls = []
    monkeypatch.setattr(
        authentication_module,
        "verify_password",
        lambda supplied, encoded: verification_calls.append((supplied, encoded)) or True,
    )
    monkeypatch.setattr(authentication_module, "password_hash_needs_rehash", lambda encoded: encoded == legacy_hash)
    monkeypatch.setattr(authentication_module, "hash_password", lambda _password: "approved-current-hash")

    principal, _issued = service.login(
        username="analyst",
        password="UnchangedPassword!234",
        correlation_id=str(uuid4()),
        now=NOW,
    )

    assert principal.user_id == 1
    assert verification_calls == [("UnchangedPassword!234", legacy_hash)]
    assert credential.password_hash == "approved-current-hash"
    assert len(session.statements) == 1
    locked_sql = str(
        session.statements[0].compile(dialect=postgresql.dialect())
    ).upper()
    assert locked_sql.endswith(
        "FOR UPDATE OF AUTH_USERS, AUTH_LOCAL_CREDENTIALS, AUTH_USER_ROLES"
    )
    locked_targets = locked_sql.rsplit("FOR UPDATE OF ", 1)[1]
    assert "AUTH_IDENTITIES" not in locked_targets


@pytest.mark.parametrize("stale_field", ["status", "role", "session_version", "password_hash"])
def test_stale_locked_authoritative_state_cannot_issue_a_session(monkeypatch, stale_field) -> None:
    identity = _verified_identity()
    user = SimpleNamespace(
        id=1,
        public_id=identity.user_public_id,
        display_name=identity.display_name,
        status="active",
        account_expires_at=None,
        session_version=1,
        last_authenticated_at=None,
        updated_at=NOW,
    )
    credential = SimpleNamespace(password_hash=identity.password_hash, updated_at=NOW)
    role = SimpleNamespace(role_key=RoleKey.VIEWER.value)
    if stale_field == "status":
        user.status = "disabled"
    elif stale_field == "role":
        role.role_key = RoleKey.ADMINISTRATOR.value
    elif stale_field == "session_version":
        user.session_version = 2
    else:
        credential.password_hash = "newer-password-hash"
    service = AuthenticationService(_LoginSession(user, credential, role), settings())
    service._locked_throttle = lambda _key, _now: _unblocked_throttle()
    service._audit.append = lambda **_kwargs: None
    service._sessions.create = lambda **_kwargs: (_ for _ in ()).throw(
        AssertionError("stale authoritative state must not issue a session")
    )
    monkeypatch.setattr(
        authentication_module.LocalIdentityProvider,
        "lookup",
        lambda _self, _canonical, *, for_update=False: identity,
    )
    verification_calls = []
    monkeypatch.setattr(
        authentication_module,
        "verify_password",
        lambda supplied, encoded: verification_calls.append((supplied, encoded)) or True,
    )

    with pytest.raises(InvalidCredentialsError) as exc_info:
        service.login(
            username="analyst",
            password="CorrectPassword!234",
            correlation_id=str(uuid4()),
            now=NOW,
        )

    assert str(exc_info.value) == INVALID_CREDENTIALS_DETAIL
    assert len(verification_calls) == 1
