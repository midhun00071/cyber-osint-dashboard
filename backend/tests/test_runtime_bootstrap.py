from __future__ import annotations

from pathlib import Path

import pytest

from app.ingestion.source_registry import list_enabled_implemented_sources
from app.models import IntelligenceSource
from app.runtime_bootstrap import (
    BootstrapResult,
    RuntimeBootstrapError,
    _print_bootstrap_result,
    bootstrap_application_state,
    bootstrap_source_catalog,
    classify_database_revision,
    load_migration_graph,
)
from app.bootstrap_data import BootstrapDataError, BootstrapDataResult


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_BOOTSTRAP = REPO_ROOT / "backend" / "app" / "runtime_bootstrap.py"
RUN_SCRIPT = REPO_ROOT / "run.ps1"
GRANT_SCRIPT = REPO_ROOT / "database" / "apply-runtime-grants.sh"


class FakeScalarRows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class FakeSession:
    def __init__(self, *, existing=(), intelligence_count=0):
        self.existing = list(existing)
        self.intelligence_count = intelligence_count
        self.added = []
        self.flush_count = 0

    def scalars(self, _statement):
        return FakeScalarRows(self.existing)

    def add(self, value):
        self.added.append(value)

    def flush(self):
        self.flush_count += 1

    def scalar(self, _statement):
        return self.intelligence_count


def source_row(definition, *, enabled=True, checkpoint="preserved"):
    return IntelligenceSource(
        slug=definition.slug,
        name=definition.display_name,
        source_type=definition.source_type,
        base_url=definition.base_url,
        is_enabled=enabled,
        operator_state="enabled" if enabled else "paused",
        rate_limit_notes="operator-preserved",
        checkpoint_value=checkpoint,
    )


def test_migration_graph_has_one_linear_head() -> None:
    graph = load_migration_graph()

    assert graph.get_heads() == ["c07a01b02c03"]
    assert len(tuple(graph.walk_revisions())) == 8


def test_migration_state_accepts_only_empty_or_known_forward_chain() -> None:
    graph = load_migration_graph()
    base = tuple(graph.walk_revisions())[-1].revision

    fresh = classify_database_revision(graph, (), ())
    existing = classify_database_revision(graph, (base,), ("intelligence_sources",))
    current = classify_database_revision(
        graph,
        (graph.get_heads()[0],),
        ("alembic_version", "intelligence_sources"),
        require_current=True,
    )

    assert fresh.database_kind == "fresh"
    assert existing.database_kind == "existing"
    assert current.database_kind == "current"


@pytest.mark.parametrize(
    "heads,tables,require_current,message",
    (
        ((), ("users",), False, "unversioned"),
        (("unknown",), ("alembic_version",), False, "not part"),
        (("one", "two"), ("alembic_version",), False, "multiple"),
        ((), (), True, "not been migrated"),
    ),
)
def test_migration_state_blocks_questionable_integrity(
    heads, tables, require_current, message
) -> None:
    with pytest.raises(RuntimeBootstrapError, match=message):
        classify_database_revision(
            load_migration_graph(),
            heads,
            tables,
            require_current=require_current,
        )


def test_fresh_catalog_bootstrap_creates_only_approved_reference_rows() -> None:
    definitions = list_enabled_implemented_sources()
    session = FakeSession(intelligence_count=0)

    result = bootstrap_source_catalog(session, definitions=definitions)  # type: ignore[arg-type]

    assert result.created_sources == len(definitions)
    assert result.existing_sources == 0
    assert result.reconciled_sources == 0
    assert result.intelligence_items == 0
    assert session.flush_count == 1
    assert {source.slug for source in session.added} == {
        definition.slug for definition in definitions
    }
    assert all(isinstance(source, IntelligenceSource) for source in session.added)


def test_existing_catalog_bootstrap_is_idempotent_and_preserves_operator_state() -> None:
    definitions = list_enabled_implemented_sources()[:2]
    existing = [source_row(definitions[0], enabled=False), source_row(definitions[1])]
    before = [
        (row.operator_state, row.is_enabled, row.checkpoint_value, row.rate_limit_notes)
        for row in existing
    ]
    session = FakeSession(existing=existing, intelligence_count=37)

    first = bootstrap_source_catalog(session, definitions=definitions)  # type: ignore[arg-type]
    second = bootstrap_source_catalog(session, definitions=definitions)  # type: ignore[arg-type]

    assert first == second
    assert first.created_sources == 0
    assert first.existing_sources == 2
    assert first.reconciled_sources == 0
    assert first.intelligence_items == 37
    assert session.added == []
    assert before == [
        (row.operator_state, row.is_enabled, row.checkpoint_value, row.rate_limit_notes)
        for row in existing
    ]


def test_conflicting_persisted_source_identity_blocks_without_mutation() -> None:
    definition = list_enabled_implemented_sources()[0]
    conflicting = source_row(definition)
    conflicting.base_url = "https://conflict.example.invalid/"
    session = FakeSession(existing=(conflicting,), intelligence_count=5)

    with pytest.raises(
        RuntimeBootstrapError,
        match="conflict.*base_url",
    ):
        bootstrap_source_catalog(session, definitions=(definition,))  # type: ignore[arg-type]

    assert session.added == []
    assert session.flush_count == 0


def test_exact_approved_legacy_source_url_is_reconciled_without_state_loss() -> None:
    definition = next(
        definition
        for definition in list_enabled_implemented_sources()
        if definition.slug == "anomali-cyber-watch"
    )
    existing = source_row(definition, enabled=False, checkpoint="legacy-checkpoint")
    existing.base_url = "https://www.anomali.com/blog/"
    before = (
        existing.operator_state,
        existing.is_enabled,
        existing.checkpoint_value,
        existing.rate_limit_notes,
    )
    session = FakeSession(existing=(existing,), intelligence_count=11)

    result = bootstrap_source_catalog(session, definitions=(definition,))  # type: ignore[arg-type]

    assert result.reconciled_sources == 1
    assert existing.base_url == definition.base_url
    assert before == (
        existing.operator_state,
        existing.is_enabled,
        existing.checkpoint_value,
        existing.rate_limit_notes,
    )


def test_runtime_bootstrap_and_runner_have_no_destructive_or_live_source_path() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8").lower()
        for path in (RUNTIME_BOOTSTRAP, RUN_SCRIPT, GRANT_SCRIPT)
    )

    for forbidden in (
        "down -v",
        "volume rm",
        "drop schema",
        "drop database",
        "alembic downgrade",
        "app.orchestration.flows",
        "parent_ingestion_cycle(",
    ):
        assert forbidden not in combined


class RecordingTransaction:
    def __init__(self) -> None:
        self.exit_exception_type = None

    def __enter__(self):
        return self

    def __exit__(self, exception_type, _exception, _traceback):
        self.exit_exception_type = exception_type
        return False


class ContextSession:
    def __init__(self) -> None:
        self.transaction = RecordingTransaction()

    def __enter__(self):
        return self

    def __exit__(self, _exception_type, _exception, _traceback):
        return False

    def begin(self):
        return self.transaction


def test_application_bootstrap_combines_catalog_and_data_in_one_transaction(
    monkeypatch,
) -> None:
    import app.runtime_bootstrap as runtime_bootstrap

    session = ContextSession()
    monkeypatch.setattr(runtime_bootstrap, "get_session_factory", lambda: lambda: session)
    monkeypatch.setattr(
        runtime_bootstrap,
        "bootstrap_source_catalog",
        lambda value: BootstrapResult(3, 9, 1, 0),
    )
    monkeypatch.setattr(
        runtime_bootstrap,
        "bootstrap_offline_intelligence",
        lambda value: BootstrapDataResult(True, 112, 0, 0, 0),
    )

    result = bootstrap_application_state()

    assert result == BootstrapResult(3, 9, 1, 0, True, 112, 0, 0, 0)
    assert session.transaction.exit_exception_type is None


def test_bootstrap_data_failure_leaves_transaction_by_exception(monkeypatch) -> None:
    import app.runtime_bootstrap as runtime_bootstrap

    session = ContextSession()
    monkeypatch.setattr(runtime_bootstrap, "get_session_factory", lambda: lambda: session)
    monkeypatch.setattr(
        runtime_bootstrap,
        "bootstrap_source_catalog",
        lambda value: BootstrapResult(3, 0, 0, 0),
    )
    monkeypatch.setattr(
        runtime_bootstrap,
        "bootstrap_offline_intelligence",
        lambda value: (_ for _ in ()).throw(BootstrapDataError("internal detail")),
    )

    with pytest.raises(RuntimeBootstrapError, match="failed safely") as exc_info:
        bootstrap_application_state()

    assert "internal detail" not in str(exc_info.value)
    assert session.transaction.exit_exception_type is BootstrapDataError


def test_operator_output_distinguishes_fresh_import_from_preservation(capsys) -> None:
    _print_bootstrap_result(BootstrapResult(2, 0, 0, 0, True, 112, 0, 0, 0))
    imported = capsys.readouterr().out
    _print_bootstrap_result(BootstrapResult(0, 12, 0, 37, False, 0, 0, 0, 91))
    preserved = capsys.readouterr().out

    assert "112 records created from bundled snapshot" in imported
    assert "not imported" not in imported
    assert "Existing intelligence state was preserved" in preserved
    assert "bundled snapshot was not imported" in preserved
