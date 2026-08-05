import inspect
from datetime import datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.security.contracts import RoleKey
from app.services.user_admin_service import AdministratorSafetyError, UserAdminService, UserInputError
from tests.c06_auth_test_support import NOW, principal, settings


def test_user_admin_service_locks_security_changes_and_preserves_last_admin() -> None:
    source = inspect.getsource(UserAdminService)
    assert ".with_for_update()" in source
    assert "Administrators cannot disable their own account." in source
    assert "The last active administrator must be preserved." in source
    assert "session_version += 1" in source


class _UnusedSession:
    def add(self, _value):
        raise AssertionError("invalid input must be rejected before persistence")


class _LockedUserResult:
    def __init__(self, user, role):
        self._row = (user, role)

    def one_or_none(self):
        return self._row


class _LockedUserSession:
    def __init__(self, user, role):
        self.user = user
        self.role = role

    def execute(self, _statement):
        return _LockedUserResult(self.user, self.role)


class _QueuedResult:
    def __init__(self, value):
        self.value = value

    def one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.value


class _QueuedSession:
    def __init__(self, *results):
        self.results = list(results)

    def execute(self, _statement):
        return _QueuedResult(self.results.pop(0))


@pytest.mark.parametrize(
    "overrides",
    [
        {"username": "bad username"},
        {"display_name": "control\x00name"},
        {"password": "short"},
        {"password": "ValidPrefix!234\x00secret-canary"},
        {"password": "ValidPrefix!234\nsecret-canary"},
        {"role": "owner"},
        {"account_expires_at": NOW},
        {"account_expires_at": NOW - timedelta(seconds=1)},
        {"account_expires_at": datetime(2026, 8, 6, 12, 0)},
        {"account_expires_at": "expiry-canary"},
    ],
)
def test_create_user_expected_input_rejections_are_typed_and_secret_free(overrides) -> None:
    values = {
        "actor": principal(),
        "username": "new.user",
        "display_name": "New User",
        "password": "StrongPassword!234",
        "role": RoleKey.VIEWER,
        "account_expires_at": NOW + timedelta(days=1),
        "correlation_id": str(uuid4()),
        "now": NOW,
    }
    values.update(overrides)
    with pytest.raises(UserInputError) as exc_info:
        UserAdminService(_UnusedSession(), settings()).create_user(**values)

    rendered = str(exc_info.value) + repr(exc_info.value)
    for canary in ("secret-canary", "expiry-canary", "bad username", "control"):
        assert canary not in rendered


def test_invalid_role_status_and_expiry_updates_use_typed_input_error() -> None:
    user = SimpleNamespace(id=2, public_id=uuid4(), created_at=NOW - timedelta(days=1), account_expires_at=None, updated_at=NOW, status="active", session_version=1)
    role = SimpleNamespace(role_key=RoleKey.VIEWER.value)
    service = UserAdminService(_LockedUserSession(user, role), settings())
    common = {"actor": principal(), "public_id": user.public_id, "correlation_id": str(uuid4()), "now": NOW}

    with pytest.raises(UserInputError):
        service.change_status(status_value="suspended", **common)
    with pytest.raises(UserInputError):
        service.change_role(role_value="owner", **common)
    for invalid_expiry in (user.created_at, user.created_at - timedelta(seconds=1), datetime(2026, 8, 6, 12, 0), "expiry-canary"):
        with pytest.raises(UserInputError) as exc_info:
            service.change_expiry(account_expires_at=invalid_expiry, **common)
        assert "expiry-canary" not in repr(exc_info.value)


@pytest.mark.parametrize(("limit", "offset"), [(0, 0), (101, 0), (1, -1), (1, 100001), ("1", 0)])
def test_invalid_service_pagination_is_a_typed_input_error(limit, offset) -> None:
    with pytest.raises(UserInputError):
        UserAdminService(_UnusedSession(), settings()).list_users(limit=limit, offset=offset)


def _expiry_user(*, expiry, role_key=RoleKey.VIEWER.value):
    user = SimpleNamespace(
        id=2,
        public_id=uuid4(),
        display_name="Expiry Test User",
        created_at=NOW - timedelta(days=30),
        updated_at=NOW - timedelta(days=1),
        last_authenticated_at=NOW - timedelta(days=1),
        account_expires_at=expiry,
        status="active",
        session_version=7,
    )
    role = SimpleNamespace(role_key=role_key)
    identity = SimpleNamespace(subject_key="expiry.user")
    old_session = SimpleNamespace(
        user_id=user.id,
        issued_at=NOW - timedelta(days=2),
        absolute_expires_at=NOW + timedelta(days=2),
        revoked_at=None,
        revocation_reason=None,
        rotated_at=None,
        updated_at=NOW - timedelta(days=2),
    )
    return user, role, identity, old_session


@pytest.mark.parametrize("new_expiry", [None, NOW + timedelta(days=10)])
def test_reactivating_naturally_expired_account_invalidates_every_old_session(new_expiry) -> None:
    user, role, identity, old_session = _expiry_user(expiry=NOW - timedelta(days=1))
    db = _QueuedSession((user, role), [old_session], (user, role, identity))
    service = UserAdminService(db, settings())
    audit_details = []
    service._audit.append = lambda **kwargs: audit_details.append(kwargs.get("safe_detail"))

    record = service.change_expiry(
        actor=principal(),
        public_id=user.public_id,
        account_expires_at=new_expiry,
        correlation_id=str(uuid4()),
        now=NOW,
    )

    assert record.account_expires_at == new_expiry
    assert user.session_version == 8
    assert old_session.revoked_at == NOW
    assert old_session.revocation_reason == "admin_revocation"
    assert old_session.rotated_at is None
    assert audit_details == [
        {"expiry_state": "none" if new_expiry is None else "configured"}
    ]


def test_future_to_future_expiry_adjustment_preserves_current_sessions() -> None:
    user, role, identity, old_session = _expiry_user(expiry=NOW + timedelta(days=5))
    db = _QueuedSession((user, role), (user, role, identity))
    service = UserAdminService(db, settings())
    service._audit.append = lambda **_kwargs: None

    service.change_expiry(
        actor=principal(),
        public_id=user.public_id,
        account_expires_at=NOW + timedelta(days=10),
        correlation_id=str(uuid4()),
        now=NOW,
    )

    assert user.session_version == 7
    assert old_session.revoked_at is None
    assert len(db.results) == 0


def test_setting_reached_expiry_preserves_existing_account_revocation_reason() -> None:
    user, role, identity, old_session = _expiry_user(expiry=NOW + timedelta(days=5))
    db = _QueuedSession((user, role), [old_session], (user, role, identity))
    service = UserAdminService(db, settings())
    service._audit.append = lambda **_kwargs: None

    service.change_expiry(
        actor=principal(),
        public_id=user.public_id,
        account_expires_at=NOW - timedelta(seconds=1),
        correlation_id=str(uuid4()),
        now=NOW,
    )

    assert user.session_version == 8
    assert old_session.revoked_at == NOW
    assert old_session.revocation_reason == "account_disabled"


def test_reached_expiry_still_protects_the_last_active_administrator() -> None:
    user, role, _identity, old_session = _expiry_user(
        expiry=NOW + timedelta(days=5),
        role_key=RoleKey.ADMINISTRATOR.value,
    )
    db = _QueuedSession((user, role), [])
    service = UserAdminService(db, settings())
    service._audit.append = lambda **_kwargs: None

    with pytest.raises(AdministratorSafetyError, match="last active administrator"):
        service.change_expiry(
            actor=principal(),
            public_id=user.public_id,
            account_expires_at=NOW - timedelta(seconds=1),
            correlation_id=str(uuid4()),
            now=NOW,
        )

    assert user.account_expires_at == NOW + timedelta(days=5)
    assert user.session_version == 7
    assert old_session.revoked_at is None
