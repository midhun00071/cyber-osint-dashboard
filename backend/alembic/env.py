"""Alembic migration environment for the Cyber OSINT Dashboard backend."""

from __future__ import annotations

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


config = getattr(context, "config", None)

if config is not None and config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Future P1-11 model imports must be added here so tables register with
# Base.metadata before Alembic autogeneration runs.


def _database_url_for_offline_mode() -> str:
    """Render the configured URL only when Alembic offline mode requires it."""

    return get_settings().sqlalchemy_database_url.render_as_string(
        hide_password=False,
    ).replace("%", "%%")


def run_migrations_offline() -> None:
    """Run migrations without creating an engine or database connection."""

    context.configure(
        url=_database_url_for_offline_mode(),
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

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if config is not None:
    if context.is_offline_mode():
        run_migrations_offline()
    else:
        run_migrations_online()
