"""Lazy SQLAlchemy engine and session helpers."""

from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


class DatabaseConnectionError(RuntimeError):
    """Sanitized failure raised when a database connection cannot be opened."""


def _sanitize_initial_connection_error(exception_context):
    """Replace initial DBAPI connection details with a fixed safe exception."""

    if exception_context.connection is None:
        return DatabaseConnectionError("The database connection could not be opened.")
    return None


def get_engine() -> Engine:
    """Return the cached SQLAlchemy engine, creating it without connecting."""

    global _engine

    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.sqlalchemy_database_url,
            pool_pre_ping=True,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_timeout=settings.database_pool_timeout_seconds,
            pool_recycle=settings.database_pool_recycle_seconds,
            connect_args={
                "connect_timeout": settings.database_connect_timeout_seconds
            },
            echo=False,
            hide_parameters=True,
        )
        event.listen(
            _engine,
            "handle_error",
            _sanitize_initial_connection_error,
            retval=True,
        )

    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Return the cached synchronous session factory."""

    global _session_factory

    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            expire_on_commit=False,
        )

    return _session_factory


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session and always closes it."""

    db_session = get_session_factory()()
    try:
        yield db_session
    finally:
        db_session.close()


def dispose_database_engine() -> None:
    """Dispose the cached engine and clear database helper caches."""

    global _engine, _session_factory

    if _engine is not None:
        _engine.dispose()

    _session_factory = None
    _engine = None
