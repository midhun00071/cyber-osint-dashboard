from datetime import UTC, datetime, timedelta

import pytest

from app.services.operations_query_service import (
    OperationsQueryInputError,
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
