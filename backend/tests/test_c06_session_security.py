from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

from fastapi import Response
import pytest

from app.models import AuthLocalCredential, AuthSession, AuthUser
from app.security.passwords import hash_password, verify_password
from app.security.sessions import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, IssuedSession, clear_auth_cookies, generate_csrf_token, generate_opaque_token, hash_opaque_token, set_auth_cookies
from app.services.authentication_service import AuthenticationService, AuthenticationServiceError, PasswordChangeError
from app.services.user_admin_service import UserAdminService
from tests.c06_auth_test_support import NOW, principal, settings


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value

    def one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.value


class _PasswordChangeSession:
    def __init__(self, results, sessions):
        self.results = list(results)
        self.sessions = list(sessions)
        self.added = []
        self.flushes = 0

    def execute(self, _statement):
        return _Result(self.results.pop(0))

    def add(self, value):
        if isinstance(value, AuthSession) and value.id is None:
            value.id = 100 + len(self.added)
            value.public_id = uuid4()
        self.added.append(value)

    def flush(self):
        self.flushes += 1
        for row in self.sessions + [value for value in self.added if isinstance(value, AuthSession)]:
            assert row.rotated_at is None or row.issued_at <= row.rotated_at <= row.absolute_expires_at


def test_generated_tokens_are_opaque_and_only_hashes_have_database_shape() -> None:
    session_token = generate_opaque_token()
    csrf_token = generate_csrf_token()
    assert session_token != csrf_token
    assert len(hash_opaque_token(session_token)) == 64
    assert session_token not in hash_opaque_token(session_token)


def test_cookie_attributes_are_strict_and_session_is_http_only() -> None:
    row = AuthSession(id=1, user_id=1, token_hash="a" * 64, csrf_token_hash="b" * 64, user_session_version=1, issued_at=NOW, expires_at=NOW + timedelta(hours=1), absolute_expires_at=NOW + timedelta(hours=8), created_at=NOW, updated_at=NOW)
    issued = IssuedSession(row=row, session_token=generate_opaque_token(), csrf_token=generate_csrf_token())
    response = Response()
    set_auth_cookies(response, issued, settings(AUTH_COOKIE_SECURE=True))
    rendered = "\n".join(response.headers.getlist("set-cookie"))
    assert SESSION_COOKIE_NAME in rendered and CSRF_COOKIE_NAME in rendered
    assert "SameSite=strict" in rendered and "Secure" in rendered and "Path=/" in rendered
    session_cookie = next(value for value in response.headers.getlist("set-cookie") if value.startswith(SESSION_COOKIE_NAME))
    csrf_cookie = next(value for value in response.headers.getlist("set-cookie") if value.startswith(CSRF_COOKIE_NAME))
    assert "HttpOnly" in session_cookie
    assert "HttpOnly" not in csrf_cookie
    cleared = Response()
    clear_auth_cookies(cleared, settings())
    assert len(cleared.headers.getlist("set-cookie")) == 2


def _session(*, row_id: int, issued_delta: timedelta, expires_delta: timedelta, absolute_delta: timedelta, rotated_delta: timedelta | None = None) -> AuthSession:
    issued_at = NOW + issued_delta
    return AuthSession(
        id=row_id,
        public_id=uuid4(),
        user_id=1,
        token_hash=f"{row_id:064x}",
        csrf_token_hash=f"{row_id + 100:064x}",
        user_session_version=1,
        issued_at=issued_at,
        expires_at=NOW + expires_delta,
        absolute_expires_at=NOW + absolute_delta,
        rotated_at=None if rotated_delta is None else NOW + rotated_delta,
        created_at=issued_at,
        updated_at=issued_at,
    )


def test_password_change_revokes_expired_sessions_without_invalid_rotation() -> None:
    current_session = _session(row_id=1, issued_delta=timedelta(hours=-1), expires_delta=timedelta(hours=1), absolute_delta=timedelta(hours=8))
    preserved_rotation = NOW - timedelta(minutes=30)
    idle_expired = _session(row_id=2, issued_delta=timedelta(hours=-2), expires_delta=timedelta(minutes=-5), absolute_delta=timedelta(hours=6), rotated_delta=timedelta(minutes=-30))
    absolute_expired = _session(row_id=3, issued_delta=timedelta(hours=-4), expires_delta=timedelta(hours=-2), absolute_delta=timedelta(hours=-1))
    old_sessions = [current_session, idle_expired, absolute_expired]
    user = AuthUser(id=1, public_id=uuid4(), display_name="Security Test User", status="active", session_version=1, created_at=NOW - timedelta(days=1), updated_at=NOW - timedelta(days=1))
    credential = AuthLocalCredential(identity_id=1, password_hash=hash_password("CurrentPassword!234"), password_changed_at=NOW - timedelta(days=1), created_at=NOW - timedelta(days=1), updated_at=NOW - timedelta(days=1))
    db = _PasswordChangeSession([user, current_session, credential, old_sessions, []], old_sessions)

    replacement = AuthenticationService(db, settings()).change_password(
        principal(),
        current_password="CurrentPassword!234",
        new_password="ReplacementPassword!567",
        correlation_id=str(uuid4()),
        now=NOW,
    )

    assert db.flushes >= 2
    assert user.session_version == 2
    assert verify_password("ReplacementPassword!567", credential.password_hash)
    assert all(row.revoked_at == NOW and row.revocation_reason == "password_change" for row in old_sessions)
    assert all(not (row.revoked_at is None and row.user_session_version == user.session_version) for row in old_sessions)
    assert absolute_expired.rotated_at is None
    assert idle_expired.rotated_at == preserved_rotation
    assert replacement.row.revoked_at is None
    assert replacement.row.user_session_version == 2
    assert replacement.row.issued_at < replacement.row.expires_at <= replacement.row.absolute_expires_at


@pytest.mark.parametrize(
    "invalid_state",
    [
        "admin_revoked",
        "version_stale",
        "idle_expired",
        "absolute_expired",
        "disabled_user",
        "expired_account",
    ],
)
def test_password_change_revalidates_the_locked_current_session_before_mutation(invalid_state) -> None:
    current_session = _session(
        row_id=1,
        issued_delta=timedelta(hours=-1),
        expires_delta=timedelta(hours=1),
        absolute_delta=timedelta(hours=8),
    )
    user = AuthUser(
        id=1,
        public_id=uuid4(),
        display_name="Security Test User",
        status="active",
        session_version=1,
        account_expires_at=None,
        created_at=NOW - timedelta(days=1),
        updated_at=NOW - timedelta(days=1),
    )
    credential = AuthLocalCredential(
        identity_id=1,
        password_hash=hash_password("CurrentPassword!234"),
        password_changed_at=NOW - timedelta(days=1),
        created_at=NOW - timedelta(days=1),
        updated_at=NOW - timedelta(days=1),
    )
    if invalid_state == "admin_revoked":
        current_session.revoked_at = NOW - timedelta(seconds=1)
        current_session.revocation_reason = "admin_revocation"
    elif invalid_state == "version_stale":
        user.session_version = 2
    elif invalid_state == "idle_expired":
        current_session.expires_at = NOW
    elif invalid_state == "absolute_expired":
        current_session.expires_at = NOW - timedelta(seconds=1)
        current_session.absolute_expires_at = NOW
    elif invalid_state == "disabled_user":
        user.status = "disabled"
        user.disabled_at = NOW - timedelta(seconds=1)
    else:
        user.account_expires_at = NOW
    original_hash = credential.password_hash
    original_version = user.session_version
    original_revocation = (current_session.revoked_at, current_session.revocation_reason)
    db = _PasswordChangeSession([user, current_session, credential], [current_session])
    service = AuthenticationService(db, settings())
    success_audits = []
    service._audit.append = lambda **kwargs: success_audits.append(kwargs)

    with pytest.raises(PasswordChangeError, match="password could not be changed"):
        service.change_password(
            principal(),
            current_password="CurrentPassword!234",
            new_password="ReplacementPassword!567",
            correlation_id=str(uuid4()),
            now=NOW,
        )

    assert credential.password_hash == original_hash
    assert user.session_version == original_version
    assert (current_session.revoked_at, current_session.revocation_reason) == original_revocation
    assert db.added == []
    assert success_audits == []


def test_administrator_revocation_after_password_change_invalidates_replacement() -> None:
    current_session = _session(
        row_id=1,
        issued_delta=timedelta(hours=-1),
        expires_delta=timedelta(hours=1),
        absolute_delta=timedelta(hours=8),
    )
    user = AuthUser(
        id=1,
        public_id=uuid4(),
        display_name="Security Test User",
        status="active",
        session_version=1,
        created_at=NOW - timedelta(days=1),
        updated_at=NOW - timedelta(days=1),
    )
    credential = AuthLocalCredential(
        identity_id=1,
        password_hash=hash_password("CurrentPassword!234"),
        password_changed_at=NOW - timedelta(days=1),
        created_at=NOW - timedelta(days=1),
        updated_at=NOW - timedelta(days=1),
    )
    db = _PasswordChangeSession(
        [user, current_session, credential, [current_session], []],
        [current_session],
    )
    authentication = AuthenticationService(db, settings())
    authentication._audit.append = lambda **_kwargs: None
    replacement = authentication.change_password(
        principal(),
        current_password="CurrentPassword!234",
        new_password="ReplacementPassword!567",
        correlation_id=str(uuid4()),
        now=NOW,
    )
    assert replacement.row.user_session_version == 2
    assert replacement.row.revoked_at is None

    db.results.extend(
        [
            (user, SimpleNamespace(role_key="viewer")),
            [replacement.row],
        ]
    )
    administration = UserAdminService(db, settings())
    administration._audit.append = lambda **_kwargs: None
    administration.revoke_sessions(
        actor=principal(),
        public_id=user.public_id,
        correlation_id=str(uuid4()),
        now=NOW + timedelta(seconds=1),
    )

    assert user.session_version == 3
    assert replacement.row.revoked_at == NOW + timedelta(seconds=1)
    assert replacement.row.revocation_reason == "admin_revocation"


def test_refresh_rotation_preserves_rotation_evidence_and_denies_token_reuse() -> None:
    predecessor = _session(row_id=1, issued_delta=timedelta(hours=-1), expires_delta=timedelta(hours=1), absolute_delta=timedelta(hours=8))
    db = _PasswordChangeSession([predecessor, []], [predecessor])
    service = AuthenticationService(db, settings())

    replacement = service.refresh(principal(), correlation_id=str(uuid4()), now=NOW)

    assert predecessor.revoked_at == NOW
    assert predecessor.revocation_reason == "refresh"
    assert predecessor.rotated_at == NOW
    assert predecessor.rotated_at <= predecessor.absolute_expires_at
    assert replacement.row.revoked_at is None
    db.results.append(predecessor)
    with pytest.raises(AuthenticationServiceError):
        service.refresh(principal(), correlation_id=str(uuid4()), now=NOW + timedelta(seconds=1))
