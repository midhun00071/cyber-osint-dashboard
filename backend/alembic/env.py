"""Alembic migration environment for the Cyber OSINT Dashboard backend."""

from __future__ import annotations

import logging
from logging.config import fileConfig
from pathlib import Path
import sys

from alembic import context
from sqlalchemy import create_engine, pool


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import get_settings  # noqa: E402
from app.db.base import Base  # noqa: E402
import app.models  # noqa: E402, F401


config = getattr(context, "config", None)


def configure_alembic_logging() -> None:
    """Configure Alembic without disabling existing application loggers."""

    if config is not None and config.config_file_name is not None:
        previously_disabled_loggers = tuple(
            logger
            for logger in logging.root.manager.loggerDict.values()
            if isinstance(logger, logging.Logger) and logger.disabled
        )
        fileConfig(
            config.config_file_name,
            disable_existing_loggers=False,
        )
        for logger in previously_disabled_loggers:
            logger.disabled = True


configure_alembic_logging()

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations without creating an engine or database connection."""

    context.configure(
        url=get_settings().sqlalchemy_database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations with a migration-specific engine."""

    connectable = create_engine(
        get_settings().sqlalchemy_database_url,
        poolclass=pool.NullPool,
    )

    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
            )

            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if config is not None:
    if context.is_offline_mode():
        run_migrations_offline()
    else:
        run_migrations_online()
