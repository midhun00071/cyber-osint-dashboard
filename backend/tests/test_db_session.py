import importlib
from unittest.mock import MagicMock

import pytest
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import Session

import app.db.session as db_session


class FakeSettings:
    def __init__(
        self,
        url: URL | None = None,
        error: Exception | None = None,
        *,
        pool_size: int = 5,
        max_overflow: int = 5,
        pool_timeout: int = 30,
        pool_recycle: int = 1800,
        connect_timeout: int = 10,
    ) -> None:
        self._url = url
        self._error = error
        self.database_pool_size = pool_size
        self.database_max_overflow = max_overflow
        self.database_pool_timeout_seconds = pool_timeout
        self.database_pool_recycle_seconds = pool_recycle
        self.database_connect_timeout_seconds = connect_timeout

    @property
    def sqlalchemy_database_url(self) -> URL:
        if self._error is not None:
            raise self._error
        assert self._url is not None
        return self._url


def make_url(password: str = "super-secret") -> URL:
    return URL.create(
        "postgresql+psycopg",
        username="cyber_osint_app",
        password=password,
        host="localhost",
        port=5432,
        database="cyber_osint",
    )


@pytest.fixture(autouse=True)
def clear_database_caches():
    db_session.dispose_database_engine()
    yield
    db_session.dispose_database_engine()


def configure_settings(monkeypatch: pytest.MonkeyPatch, settings: FakeSettings) -> None:
    monkeypatch.setattr(db_session, "get_settings", lambda: settings)


def configure_create_engine(monkeypatch: pytest.MonkeyPatch) -> tuple[MagicMock, dict]:
    engine = MagicMock(spec=Engine)
    captured: dict = {}

    def fake_create_engine(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return engine

    monkeypatch.setattr(db_session, "create_engine", fake_create_engine)
    monkeypatch.setattr(db_session.event, "listen", lambda *args, **kwargs: None)
    return engine, captured


def test_importing_session_module_does_not_create_engine():
    module = importlib.reload(db_session)
    try:
        assert module._engine is None
        assert module._session_factory is None
    finally:
        module.dispose_database_engine()


def test_get_engine_is_lazy(monkeypatch):
    engine, captured = configure_create_engine(monkeypatch)
    configure_settings(monkeypatch, FakeSettings(make_url()))

    assert captured == {}

    assert db_session.get_engine() is engine
    assert "url" in captured


def test_get_engine_uses_postgresql_psycopg_driver(monkeypatch):
    _, captured = configure_create_engine(monkeypatch)
    configure_settings(monkeypatch, FakeSettings(make_url()))

    db_session.get_engine()

    assert captured["url"].drivername == "postgresql+psycopg"


def test_get_engine_creation_does_not_open_database_connection(monkeypatch):
    engine, _ = configure_create_engine(monkeypatch)
    configure_settings(monkeypatch, FakeSettings(make_url()))

    db_session.get_engine()

    engine.connect.assert_not_called()


def test_repeated_get_engine_returns_same_cached_engine(monkeypatch):
    engine, _ = configure_create_engine(monkeypatch)
    configure_settings(monkeypatch, FakeSettings(make_url()))

    assert db_session.get_engine() is engine
    assert db_session.get_engine() is engine


def test_get_engine_uses_approved_engine_settings(monkeypatch):
    _, captured = configure_create_engine(monkeypatch)
    configure_settings(monkeypatch, FakeSettings(make_url()))

    db_session.get_engine()

    assert captured["kwargs"] == {
        "pool_pre_ping": True,
        "pool_size": 5,
        "max_overflow": 5,
        "pool_timeout": 30,
        "pool_recycle": 1800,
        "connect_args": {"connect_timeout": 10},
        "echo": False,
        "hide_parameters": True,
    }


def test_get_engine_propagates_validated_pool_settings(monkeypatch):
    _, captured = configure_create_engine(monkeypatch)
    configure_settings(
        monkeypatch,
        FakeSettings(
            make_url(),
            pool_size=2,
            max_overflow=1,
            pool_timeout=3,
            pool_recycle=600,
            connect_timeout=4,
        ),
    )

    db_session.get_engine()

    assert captured["kwargs"] == {
        "pool_pre_ping": True,
        "pool_size": 2,
        "max_overflow": 1,
        "pool_timeout": 3,
        "pool_recycle": 600,
        "connect_args": {"connect_timeout": 4},
        "echo": False,
        "hide_parameters": True,
    }


def test_initial_connection_error_is_sanitized() -> None:
    context = MagicMock()
    context.connection = None

    error = db_session._sanitize_initial_connection_error(context)

    assert isinstance(error, db_session.DatabaseConnectionError)
    assert str(error) == "The database connection could not be opened."
    assert "password" not in str(error).lower()


def test_real_initial_connection_failure_is_sanitized(monkeypatch) -> None:
    unreachable = make_url().set(port=1)
    configure_settings(
        monkeypatch,
        FakeSettings(unreachable, connect_timeout=1),
    )

    engine = db_session.get_engine()
    with pytest.raises(db_session.DatabaseConnectionError) as exc_info:
        engine.connect()

    assert str(exc_info.value) == "The database connection could not be opened."
    assert "localhost" not in str(exc_info.value)
    assert "super-secret" not in str(exc_info.value)


def test_get_session_factory_is_cached(monkeypatch):
    configure_create_engine(monkeypatch)
    configure_settings(monkeypatch, FakeSettings(make_url()))

    first_factory = db_session.get_session_factory()

    assert db_session.get_session_factory() is first_factory


def test_sessions_use_approved_settings(monkeypatch):
    configure_create_engine(monkeypatch)
    configure_settings(monkeypatch, FakeSettings(make_url()))

    factory = db_session.get_session_factory()

    assert factory.kw["autoflush"] is False
    assert factory.kw["expire_on_commit"] is False


def test_get_db_session_yields_sqlalchemy_session(monkeypatch):
    configure_create_engine(monkeypatch)
    configure_settings(monkeypatch, FakeSettings(make_url()))
    dependency = db_session.get_db_session()

    session = next(dependency)

    assert isinstance(session, Session)
    with pytest.raises(StopIteration):
        next(dependency)


def test_get_db_session_closes_session_in_finally(monkeypatch):
    fake_session = MagicMock(spec=Session)
    monkeypatch.setattr(db_session, "get_session_factory", lambda: lambda: fake_session)
    dependency = db_session.get_db_session()

    assert next(dependency) is fake_session
    with pytest.raises(StopIteration):
        next(dependency)

    fake_session.close.assert_called_once()


def test_get_db_session_does_not_auto_commit(monkeypatch):
    fake_session = MagicMock(spec=Session)
    monkeypatch.setattr(db_session, "get_session_factory", lambda: lambda: fake_session)
    dependency = db_session.get_db_session()

    next(dependency)
    with pytest.raises(StopIteration):
        next(dependency)

    fake_session.commit.assert_not_called()
    fake_session.rollback.assert_not_called()


def test_get_db_session_does_not_suppress_exceptions(monkeypatch):
    fake_session = MagicMock(spec=Session)
    monkeypatch.setattr(db_session, "get_session_factory", lambda: lambda: fake_session)
    dependency = db_session.get_db_session()

    next(dependency)
    with pytest.raises(RuntimeError, match="service failure"):
        dependency.throw(RuntimeError("service failure"))

    fake_session.close.assert_called_once()
    fake_session.commit.assert_not_called()
    fake_session.rollback.assert_not_called()


def test_dispose_disposes_existing_cached_engine(monkeypatch):
    engine, _ = configure_create_engine(monkeypatch)
    configure_settings(monkeypatch, FakeSettings(make_url()))
    db_session.get_engine()

    db_session.dispose_database_engine()

    engine.dispose.assert_called_once()


def test_dispose_clears_engine_and_session_factory_caches(monkeypatch):
    first_engine, _ = configure_create_engine(monkeypatch)
    configure_settings(monkeypatch, FakeSettings(make_url()))
    first_factory = db_session.get_session_factory()

    db_session.dispose_database_engine()
    second_engine, _ = configure_create_engine(monkeypatch)

    assert db_session.get_engine() is second_engine
    assert db_session.get_session_factory() is not first_factory
    assert db_session.get_engine() is not first_engine


def test_dispose_is_safe_before_engine_creation():
    db_session.dispose_database_engine()


def test_missing_database_settings_fail_only_when_engine_requested(monkeypatch):
    configure_create_engine(monkeypatch)
    configure_settings(
        monkeypatch,
        FakeSettings(error=ValueError("Missing database configuration: POSTGRES_HOST")),
    )

    with pytest.raises(ValueError, match="POSTGRES_HOST"):
        db_session.get_engine()


def test_database_configuration_errors_do_not_expose_passwords(monkeypatch):
    secret = "super-secret"
    configure_create_engine(monkeypatch)
    configure_settings(
        monkeypatch,
        FakeSettings(error=ValueError("Invalid database URL for configured password")),
    )

    with pytest.raises(ValueError) as exc_info:
        db_session.get_engine()

    assert secret not in str(exc_info.value)
    assert secret not in repr(exc_info.value)
