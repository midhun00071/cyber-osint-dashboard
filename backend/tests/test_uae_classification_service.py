from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.models import IntelligenceItem, IntelligenceSource, SourceRecord
from app.processing.uae_classification_service import (
    MAX_CLASSIFICATION_ITEMS,
    UaeClassificationService,
    UaeClassificationServiceError,
)


OBSERVED_AT = datetime(2026, 7, 13, 10, 0, tzinfo=UTC)


class ScalarList:
    def __init__(self, items: list[IntelligenceItem]):
        self._items = items

    def all(self) -> list[IntelligenceItem]:
        return self._items


class ExecuteResult:
    def __init__(self, items: list[IntelligenceItem]):
        self._items = items

    def scalars(self) -> ScalarList:
        return ScalarList(self._items)


class FakeSession:
    def __init__(
        self,
        items: list[IntelligenceItem],
        *,
        fail_execute: bool = False,
        fail_commit: bool = False,
    ):
        self.items = items
        self.fail_execute = fail_execute
        self.fail_commit = fail_commit
        self.commits = 0
        self.rollbacks = 0
        self.closed = 0

    def execute(self, statement: Any) -> ExecuteResult:
        if self.fail_execute:
            raise SQLAlchemyError("postgresql://private-user:private-password@host/db")
        limit_clause = getattr(statement, "_limit_clause", None)
        limit = getattr(limit_clause, "value", None) or len(self.items)
        criteria = list(getattr(statement, "_where_criteria", ()))
        method = criterion_value(criteria, "uae_relevance_method")
        items = [
            item
            for item in self.items
            if method is None or item.uae_relevance_method == method
        ]
        ordered = sorted(
            items,
            key=lambda item: (
                item.source_published_at is None,
                item.source_published_at or datetime.max.replace(tzinfo=UTC),
                item.last_seen_at,
                item.id or 0,
            ),
        )
        return ExecuteResult(ordered[:limit])

    def commit(self) -> None:
        if self.fail_commit:
            raise SQLAlchemyError("private-password")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed += 1


def criterion_value(criteria: list[object], column_name: str) -> object:
    for criterion in criteria:
        left = getattr(criterion, "left", None)
        if getattr(left, "name", None) != column_name:
            continue
        right = getattr(criterion, "right", None)
        if hasattr(right, "value"):
            return right.value
    return None


def make_item(
    *,
    title: str,
    summary: str | None = None,
    method: str = "unassigned",
    status: str = "unknown",
    reason: str | None = None,
    scope: str = "global",
    source_slug: str = "nvd",
    item_id: int = 1,
) -> IntelligenceItem:
    source = IntelligenceSource(
        slug=source_slug,
        name=f"Source {source_slug}",
        source_type="api",
        base_url="https://example.com",
        is_enabled=True,
    )
    item = IntelligenceItem(
        item_type="vulnerability",
        canonical_title=title,
        summary=summary,
        collected_at=OBSERVED_AT,
        last_seen_at=OBSERVED_AT,
        status="active",
        data_confidence=Decimal("1.000"),
        geographic_scope=scope,
        uae_relevance_status=status,
        uae_relevance_confidence=None,
        uae_relevance_reason=reason,
        uae_relevance_method=method,
        analyst_review_status="pending",
    )
    item.id = item_id
    source_record = SourceRecord(
        source=source,
        intelligence_item=item,
        source_external_id=f"source-{item_id}",
        source_url="https://example.com/advisory",
        is_primary_reference=True,
        payload_collected_at=OBSERVED_AT,
        first_seen_at=OBSERVED_AT,
        last_seen_at=OBSERVED_AT,
        processing_status="processed",
        upstream_status="present",
    )
    item.source_records = [source_record]
    return item


def test_rejects_invalid_limits() -> None:
    service = UaeClassificationService(FakeSession([]))  # type: ignore[arg-type]

    for value in (0, -1, MAX_CLASSIFICATION_ITEMS + 1):
        with pytest.raises(ValueError):
            service.classify_existing(max_items=value)


def test_dry_run_counts_expected_changes_without_mutation() -> None:
    item = make_item(title="Dubai security advisory")
    session = FakeSession([item])

    counts = UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
        max_items=1
    )

    assert counts.processed == 1
    assert counts.would_update == 1
    assert counts.updated == 0
    assert item.uae_relevance_status == "unknown"
    assert item.uae_relevance_method == "unassigned"
    assert session.commits == 0
    assert session.rollbacks == 1


def test_apply_updates_eligible_rows_and_commits_once() -> None:
    item = make_item(title="United Arab Emirates vulnerability note")
    session = FakeSession([item])

    counts = UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
        max_items=1,
        apply=True,
    )

    assert counts.processed == 1
    assert counts.updated == 1
    assert item.geographic_scope == "uae"
    assert item.uae_relevance_status == "confirmed"
    assert item.uae_relevance_method == "automatic"
    assert item.uae_relevance_reason == "Matched direct UAE country phrase."
    assert session.commits == 1
    assert session.rollbacks == 0


def test_unchanged_automatic_rows_are_not_rewritten() -> None:
    item = make_item(
        title="Dubai advisory",
        method="automatic",
        status="confirmed",
        reason="Matched emirate name: Dubai.",
        scope="uae",
    )
    session = FakeSession([item])

    counts = UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
        max_items=1,
        apply=True,
    )

    assert counts.unchanged == 1
    assert counts.updated == 0
    assert session.commits == 1


@pytest.mark.parametrize("method", ["manual", "source_declared", "reviewed"])
def test_protected_or_unknown_methods_are_skipped(method: str) -> None:
    item = make_item(
        title="Dubai advisory",
        method=method,
        status="possible",
        reason="Analyst-owned reason",
    )

    counts = UaeClassificationService(FakeSession([item])).classify_existing(  # type: ignore[arg-type]
        max_items=1,
        apply=True,
    )

    assert counts.skipped_protected == 1
    assert item.uae_relevance_status == "possible"
    assert item.uae_relevance_reason == "Analyst-owned reason"
    assert item.uae_relevance_method == method


def test_deterministic_ordering_and_limit_are_applied() -> None:
    later = make_item(title="UAE later", item_id=2)
    earlier = make_item(title="UAE earlier", item_id=1)
    later.source_published_at = datetime(2026, 7, 14, tzinfo=UTC)
    earlier.source_published_at = datetime(2026, 7, 13, tzinfo=UTC)
    session = FakeSession([later, earlier])

    counts = UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
        max_items=1,
        apply=True,
    )

    assert counts.processed == 1
    assert earlier.uae_relevance_method == "automatic"
    assert later.uae_relevance_method == "unassigned"


def test_repeated_bounded_apply_runs_progress_through_unassigned_backfill() -> None:
    items = [
        make_item(title=f"Dubai advisory {index:02d}", item_id=index)
        for index in range(1, 31)
    ]
    session = FakeSession(items)
    service = UaeClassificationService(session)  # type: ignore[arg-type]

    first = service.classify_existing(max_items=20, apply=True)
    second = service.classify_existing(max_items=20, apply=True)

    assert first.processed == 20
    assert first.updated == 20
    assert second.processed == 20
    assert second.updated == 10
    assert second.unchanged == 10
    assert all(item.uae_relevance_method == "automatic" for item in items)
    assert all(item.uae_relevance_status == "confirmed" for item in items)
    assert session.commits == 2


def test_protected_records_do_not_consume_unassigned_backfill_batch() -> None:
    protected = [
        make_item(
            title=f"Protected Dubai advisory {index}",
            method="manual",
            status="possible",
            reason="Analyst-owned reason",
            item_id=index,
        )
        for index in range(1, 6)
    ]
    backfill = [
        make_item(title=f"Dubai advisory {index}", item_id=index)
        for index in range(6, 11)
    ]
    session = FakeSession(protected + backfill)

    counts = UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
        max_items=5,
        apply=True,
    )

    assert counts.processed == 5
    assert counts.updated == 5
    assert counts.skipped_protected == 0
    assert all(item.uae_relevance_method == "manual" for item in protected)
    assert all(item.uae_relevance_method == "automatic" for item in backfill)


def test_automatic_reclassification_runs_after_unassigned_backfill_is_exhausted() -> None:
    unassigned = make_item(title="Dubai backfill", item_id=1)
    automatic = make_item(
        title="United Arab Emirates automatic review",
        method="automatic",
        status="unknown",
        reason="No direct UAE evidence found.",
        item_id=2,
    )
    session = FakeSession([automatic, unassigned])

    counts = UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
        max_items=2,
        apply=True,
    )

    assert counts.processed == 2
    assert counts.updated == 2
    assert unassigned.uae_relevance_reason == "Matched emirate name: Dubai."
    assert automatic.uae_relevance_reason == "Matched direct UAE country phrase."


def test_commit_failure_rolls_back_and_raises_sanitized_error() -> None:
    session = FakeSession([make_item(title="Dubai")], fail_commit=True)

    with pytest.raises(UaeClassificationServiceError) as exc_info:
        UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
            max_items=1,
            apply=True,
        )

    message = str(exc_info.value)
    assert message == "Database error while classifying UAE relevance."
    assert "private-password" not in message
    assert "postgresql://" not in message
    assert session.rollbacks == 1


def test_database_failure_rolls_back_and_sanitizes_error() -> None:
    session = FakeSession([make_item(title="Dubai")], fail_execute=True)

    with pytest.raises(UaeClassificationServiceError) as exc_info:
        UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
            max_items=1,
            apply=True,
        )

    assert str(exc_info.value) == "Database error while classifying UAE relevance."
    assert "private-password" not in str(exc_info.value)
    assert session.rollbacks == 1
