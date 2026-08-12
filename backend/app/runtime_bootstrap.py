"""Safe, idempotent local runtime bootstrap and migration integrity checks."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Iterable, Sequence

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import func, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.bootstrap_data import (
    BootstrapDataError,
    bootstrap_offline_intelligence,
)
from app.db.session import (
    DatabaseConnectionError,
    get_engine,
    get_session_factory,
)
from app.ingestion.source_registry import (
    SourceDefinition,
    list_enabled_implemented_sources,
)
from app.models.intelligence_item import IntelligenceItem
from app.models.intelligence_source import IntelligenceSource


BACKEND_DIRECTORY = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIGURATION = BACKEND_DIRECTORY / "alembic.ini"


class RuntimeBootstrapError(RuntimeError):
    """Sanitized, fail-closed bootstrap or migration-integrity failure."""


@dataclass(frozen=True, slots=True)
class MigrationState:
    expected_head: str
    current_revision: str | None
    database_kind: str


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    created_sources: int
    existing_sources: int
    reconciled_sources: int
    intelligence_items: int
    bootstrap_attempted: bool = False
    bootstrap_created: int = 0
    bootstrap_updated: int = 0
    bootstrap_unchanged: int = 0
    bootstrap_existing_state_rows: int = 0


APPROVED_LEGACY_BASE_URLS = {
    ("anomali-cyber-watch", "https://www.anomali.com/blog/"): (
        "https://www.anomali.com/blog"
    ),
}


def load_migration_graph() -> ScriptDirectory:
    """Load the committed graph and require one linear target head."""

    configuration = Config(str(ALEMBIC_CONFIGURATION))
    graph = ScriptDirectory.from_config(configuration)
    heads = tuple(graph.get_heads())
    if len(heads) != 1:
        raise RuntimeBootstrapError(
            "The Alembic graph must contain exactly one migration head."
        )
    revisions = tuple(graph.walk_revisions(base="base", head=heads[0]))
    if not revisions or revisions[-1].down_revision is not None:
        raise RuntimeBootstrapError("The Alembic graph does not have one known base.")
    if any(
        revision.is_branch_point
        or revision.is_merge_point
        or (
            index + 1 < len(revisions)
            and revision.down_revision != revisions[index + 1].revision
        )
        for index, revision in enumerate(revisions)
    ):
        raise RuntimeBootstrapError("The Alembic graph is not a single linear chain.")
    return graph


def classify_database_revision(
    graph: ScriptDirectory,
    current_heads: Sequence[str],
    table_names: Iterable[str],
    *,
    require_current: bool = False,
) -> MigrationState:
    """Classify an empty or versioned schema without guessing its history."""

    expected_head = tuple(graph.get_heads())[0]
    current = tuple(current_heads)
    application_tables = set(table_names) - {"alembic_version"}

    if len(current) > 1:
        raise RuntimeBootstrapError("The database records multiple Alembic heads.")
    if not current:
        if application_tables:
            raise RuntimeBootstrapError(
                "The database contains an unversioned application schema."
            )
        if require_current:
            raise RuntimeBootstrapError("The empty database has not been migrated.")
        return MigrationState(expected_head, None, "fresh")

    current_revision = current[0]
    known_revisions = {
        revision.revision
        for revision in graph.walk_revisions(base="base", head=expected_head)
    }
    if current_revision not in known_revisions:
        raise RuntimeBootstrapError(
            "The database revision is not part of the committed migration chain."
        )
    if require_current and current_revision != expected_head:
        raise RuntimeBootstrapError("The database is not at the expected Alembic head.")
    return MigrationState(
        expected_head,
        current_revision,
        "current" if current_revision == expected_head else "existing",
    )


def inspect_migration_state(
    *,
    engine: Engine | None = None,
    require_current: bool = False,
) -> MigrationState:
    """Inspect the committed graph and live schema through sanitized boundaries."""

    graph = load_migration_graph()
    database_engine = engine or get_engine()
    try:
        with database_engine.connect() as connection:
            current_heads = tuple(
                MigrationContext.configure(connection).get_current_heads()
            )
            table_names = tuple(inspect(connection).get_table_names())
    except (DatabaseConnectionError, SQLAlchemyError) as exc:
        raise RuntimeBootstrapError(
            "The database migration state could not be inspected safely."
        ) from exc
    return classify_database_revision(
        graph,
        current_heads,
        table_names,
        require_current=require_current,
    )


def bootstrap_source_catalog(
    session: Session,
    *,
    definitions: Sequence[SourceDefinition] | None = None,
) -> BootstrapResult:
    """Insert missing approved source identities while preserving all existing state."""

    approved = tuple(definitions or list_enabled_implemented_sources())
    approved_by_slug = {definition.slug: definition for definition in approved}
    if len(approved_by_slug) != len(approved):
        raise RuntimeBootstrapError("The approved source catalog contains duplicates.")

    existing_rows = tuple(
        session.scalars(
            select(IntelligenceSource).where(
                IntelligenceSource.slug.in_(tuple(approved_by_slug))
            )
        ).all()
    )
    existing_by_slug = {row.slug: row for row in existing_rows}
    if len(existing_by_slug) != len(existing_rows):
        raise RuntimeBootstrapError("The persisted source catalog is ambiguous.")

    reconciliations: list[tuple[IntelligenceSource, str]] = []
    for slug, row in existing_by_slug.items():
        definition = approved_by_slug[slug]
        approved_legacy_url = APPROVED_LEGACY_BASE_URLS.get((slug, row.base_url))
        if (
            row.name == definition.display_name
            and row.source_type == definition.source_type
            and approved_legacy_url == definition.base_url
        ):
            reconciliations.append((row, definition.base_url))
            continue
        conflicting_fields = tuple(
            field_name
            for field_name, persisted_value, approved_value in (
                ("name", row.name, definition.display_name),
                ("source_type", row.source_type, definition.source_type),
                ("base_url", row.base_url, definition.base_url),
            )
            if persisted_value != approved_value
        )
        if conflicting_fields:
            raise RuntimeBootstrapError(
                "Persisted source identity "
                f"'{slug}' conflicts with the approved catalog fields: "
                f"{', '.join(conflicting_fields)}."
            )

    for row, approved_base_url in reconciliations:
        row.base_url = approved_base_url

    created = 0
    for definition in approved:
        if definition.slug in existing_by_slug:
            continue
        session.add(
            IntelligenceSource(
                slug=definition.slug,
                name=definition.display_name,
                source_type=definition.source_type,
                base_url=definition.base_url,
                is_enabled=definition.enabled,
                rate_limit_notes=definition.rate_limit_notes,
                checkpoint_value=None,
            )
        )
        created += 1

    session.flush()
    intelligence_count = session.scalar(select(func.count(IntelligenceItem.id)))
    return BootstrapResult(
        created_sources=created,
        existing_sources=len(existing_rows),
        reconciled_sources=len(reconciliations),
        intelligence_items=int(intelligence_count or 0),
    )


def bootstrap_application_state() -> BootstrapResult:
    """Own one transaction for required application reference state."""

    try:
        with get_session_factory()() as session, session.begin():
            catalog_result = bootstrap_source_catalog(session)
            data_result = bootstrap_offline_intelligence(session)
            return BootstrapResult(
                created_sources=catalog_result.created_sources,
                existing_sources=catalog_result.existing_sources,
                reconciled_sources=catalog_result.reconciled_sources,
                intelligence_items=catalog_result.intelligence_items,
                bootstrap_attempted=data_result.attempted,
                bootstrap_created=data_result.created,
                bootstrap_updated=data_result.updated,
                bootstrap_unchanged=data_result.unchanged,
                bootstrap_existing_state_rows=data_result.existing_state_rows,
            )
    except BootstrapDataError as exc:
        raise RuntimeBootstrapError(
            "The offline public bootstrap transaction failed safely."
        ) from exc
    except RuntimeBootstrapError:
        raise
    except (DatabaseConnectionError, SQLAlchemyError) as exc:
        raise RuntimeBootstrapError(
            "The application bootstrap transaction failed safely."
        ) from exc


def _print_migration_state(state: MigrationState) -> None:
    print("PASS Alembic graph has exactly one linear head.")
    if state.database_kind == "fresh":
        print("PASS Database state is fresh and contains no application tables.")
    elif state.database_kind == "existing":
        print("PASS Existing database revision is on the committed forward chain.")
    else:
        print("PASS Database is at the expected Alembic head.")


def _print_bootstrap_result(result: BootstrapResult) -> None:
    print(
        "PASS Application source catalog is complete "
        f"({result.created_sources} created, {result.existing_sources} preserved, "
        f"{result.reconciled_sources} approved legacy identities reconciled)."
    )
    if result.bootstrap_attempted:
        print(
            "PASS Offline public bootstrap intelligence loaded "
            f"({result.bootstrap_created} records created from bundled snapshot)."
        )
        if result.bootstrap_updated or result.bootstrap_unchanged:
            print(
                "PASS Bundled snapshot persistence also observed "
                f"{result.bootstrap_updated} updated and "
                f"{result.bootstrap_unchanged} unchanged records."
            )
    elif result.bootstrap_existing_state_rows:
        print(
            "PASS Existing intelligence state was preserved; "
            "the bundled snapshot was not imported."
        )
    else:
        print("WARN Stored intelligence count is zero after bootstrap.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate and bootstrap the Alpha Data local runtime safely."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    migration_parser = subparsers.add_parser("migration-state")
    migration_parser.add_argument("--require-current", action="store_true")
    subparsers.add_parser("application-state")
    arguments = parser.parse_args(argv)

    try:
        if arguments.command == "migration-state":
            _print_migration_state(
                inspect_migration_state(require_current=arguments.require_current)
            )
        else:
            _print_bootstrap_result(bootstrap_application_state())
    except RuntimeBootstrapError as error:
        print(f"BLOCKED {error}", file=sys.stderr)
        return 1
    except Exception:
        print("BLOCKED Runtime bootstrap could not complete safely.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BootstrapResult",
    "MigrationState",
    "RuntimeBootstrapError",
    "bootstrap_application_state",
    "bootstrap_source_catalog",
    "classify_database_revision",
    "inspect_migration_state",
    "load_migration_graph",
    "main",
]
