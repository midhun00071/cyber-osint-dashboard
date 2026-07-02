"""Lazy SQLAlchemy engine and session helpers."""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Return the cached SQLAlchemy engine, creating it without connecting."""

    global _engine

    if _engine is None:
        _engine = create_engine(
            get_settings().sqlalchemy_database_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=5,
            pool_timeout=30,
            pool_recycle=1800,
            connect_args={"connect_timeout": 10},
            echo=False,
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
