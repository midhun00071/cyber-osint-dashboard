from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.services.operations_query_service import (
    MAX_DERIVED_SOURCE_SCAN,
    OperationsQueryError,
    OperationsQueryInputError,
    OperationsQueryService,
    _duration,
    _history_filters,
    _page,
)


def test_operations_query_bounds_and_ninety_day_history_window() -> None:
    _page(1, 0, maximum=100)
    with pytest.raises(OperationsQueryInputError):
        _page(101, 0, maximum=100)
    now = datetime(2026, 8, 5, tzinfo=UTC)
    _history_filters("failed", {"failed"}, "manual", {"manual"}, now - timedelta(days=90), now)
    with pytest.raises(OperationsQueryInputError):
        _history_filters("failed", {"failed"}, "manual", {"manual"}, now - timedelta(days=91), now)


def test_duration_is_bounded_and_never_uses_an_active_end_time() -> None:
    start = datetime(2026, 8, 5, 10, tzinfo=UTC)
    assert _duration(start, None) is None
    assert _duration(start, start + timedelta(seconds=3)) == 3
    assert _duration(start, start - timedelta(seconds=3)) == 0


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _SourceSession:
    def __init__(self, rows, *, count: int | None = None) -> None:
        self.rows = list(rows)
        self.count = len(self.rows) if count is None else count
        self.scalar_statements = []
        self.scalars_statements = []

    def scalar(self, statement):
        self.scalar_statements.append(statement)
        return self.count

    def scalars(self, statement):
        self.scalars_statements.append(statement)
        offset = 0 if statement._offset_clause is None else statement._offset_clause.value
        limit = len(self.rows) if statement._limit_clause is None else statement._limit_clause.value
        return _Rows(self.rows[offset : offset + limit])


def test_source_page_uses_sql_count_limit_offset_and_materializes_only_page(monkeypatch) -> None:
    session = _SourceSession([SimpleNamespace(slug=f"source-{index}") for index in range(6)])
    service = OperationsQueryService(session)
    materialized = []
    monkeypatch.setattr(
        service,
        "_source_record",
        lambda row, _permissions: materialized.append(row.slug) or {"slug": row.slug},
    )

    items, total = service.list_sources(
        permissions=frozenset(), limit=2, offset=3
    )

    assert total == 6
    assert [item["slug"] for item in items] == ["source-3", "source-4"]
    assert materialized == ["source-3", "source-4"]
    assert len(session.scalar_statements) == 1
    statement = session.scalars_statements[0]
    assert statement._limit_clause.value == 2
    assert statement._offset_clause.value == 3
    assert "intelligence_sources.slug" in str(statement)


def test_effective_state_scan_is_bounded_and_preserves_exact_total(monkeypatch) -> None:
    rows = [SimpleNamespace(slug=f"source-{index}") for index in range(5)]
    session = _SourceSession(rows)
    service = OperationsQueryService(session)
    monkeypatch.setattr(
        service,
        "_source_record",
        lambda row, _permissions: {
            "slug": row.slug,
            "effective_state": "disabled" if row.slug in {"source-1", "source-3"} else "eligible",
        },
    )

    items, total = service.list_sources(
        permissions=frozenset(), limit=1, offset=1, effective_state="disabled"
    )

    assert total == 2
    assert [item["slug"] for item in items] == ["source-3"]
    statement = session.scalars_statements[0]
    assert statement._limit_clause.value == MAX_DERIVED_SOURCE_SCAN
    assert statement._offset_clause is None


def test_effective_state_inventory_guard_fails_before_materialization() -> None:
    session = _SourceSession([], count=MAX_DERIVED_SOURCE_SCAN + 1)
    with pytest.raises(OperationsQueryError, match="bounded derived-state"):
        OperationsQueryService(session).list_sources(
            permissions=frozenset(), limit=100, offset=0, effective_state="eligible"
        )
    assert session.scalars_statements == []
