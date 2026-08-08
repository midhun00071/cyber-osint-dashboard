from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.models import (
    IntelligenceItem,
    IntelligenceItemTag,
    IntelligenceSource,
    SourceRecord,
    Tag,
)
from app.processing.uae_classification_service import (
    MAX_CLASSIFICATION_ITEMS,
    UaeClassificationService,
    UaeClassificationServiceError,
)
from app.processing.uae_relevance_classifier import confidence_for_rule


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

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None


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
        self.tags: dict[str, Tag] = {}

    def execute(self, statement: Any) -> ExecuteResult:
        if self.fail_execute:
            raise SQLAlchemyError("postgresql://private-user:private-password@host/db")
        if getattr(statement, "is_delete", False):
            return ExecuteResult([])
        entity = statement.column_descriptions[0].get("entity")
        criteria = list(getattr(statement, "_where_criteria", ()))
        if entity is Tag:
            slug = criterion_value(criteria, "slug")
            tag = self.tags.get(str(slug))
            return ExecuteResult([tag] if tag is not None else [])
        limit_clause = getattr(statement, "_limit_clause", None)
        limit = getattr(limit_clause, "value", None) or len(self.items)
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

    def add(self, value: Tag) -> None:
        self.tags[value.slug] = value

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
    confidence: Decimal | None = None,
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
        uae_relevance_confidence=confidence,
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
    item.tag_assignments = []
    return item


def assign_tag(
    item: IntelligenceItem,
    *,
    slug: str,
    assigned_by: str,
    confidence: Decimal,
    display_name: str | None = None,
    tag_type: str = "theme",
) -> IntelligenceItemTag:
    tag = Tag(
        slug=slug,
        display_name=display_name or slug,
        tag_type=tag_type,
    )
    assignment = IntelligenceItemTag(
        intelligence_item=item,
        tag=tag,
        assigned_by=assigned_by,
        confidence=confidence,
    )
    if assignment not in item.tag_assignments:
        item.tag_assignments.append(assignment)
    return assignment


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
    assert item.uae_relevance_confidence is None
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
    assert item.uae_relevance_status == "possible"
    assert item.uae_relevance_confidence == confidence_for_rule("text_country_mention")
    assert item.uae_relevance_method == "automatic"
    assert "no attribution asserted" in item.uae_relevance_reason
    assert session.commits == 1
    assert session.rollbacks == 0


def test_automatic_rows_without_controlled_tags_are_backfilled() -> None:
    item = make_item(
        title="Dubai advisory",
        method="automatic",
        status="possible",
        reason="Potential UAE relevance from a Dubai mention; no attribution asserted.",
        scope="uae",
        confidence=confidence_for_rule("text_emirate_mention"),
    )
    session = FakeSession([item])

    counts = UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
        max_items=1,
        apply=True,
    )

    assert counts.unchanged == 0
    assert counts.updated == 1
    assert item.uae_relevance_confidence == confidence_for_rule("text_emirate_mention")
    assert {assignment.tag.slug for assignment in item.tag_assignments} >= {
        "uae-emirate-dubai",
        "language-english",
    }
    assert session.commits == 1


def test_automatic_row_with_missing_confidence_is_recalculated() -> None:
    item = make_item(
        title="Dubai advisory",
        method="automatic",
        status="possible",
        reason="Potential UAE relevance from a Dubai mention; no attribution asserted.",
        scope="uae",
        confidence=None,
    )
    session = FakeSession([item])

    counts = UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
        max_items=1,
        apply=True,
    )

    assert counts.updated == 1
    assert item.uae_relevance_confidence == confidence_for_rule("text_emirate_mention")


@pytest.mark.parametrize("source_slug", ["nvd", "cert-eu"])
def test_automatic_ingestion_classification_applies_controlled_tags(
    source_slug: str,
) -> None:
    item = make_item(title="Dubai defensive advisory", source_slug=source_slug)
    session = FakeSession([item])

    UaeClassificationService(session).classify_and_apply_if_allowed(item)  # type: ignore[arg-type]

    assert item.uae_relevance_method == "automatic"
    assert {assignment.tag.slug for assignment in item.tag_assignments} == {
        "language-english",
        "uae-emirate-dubai",
    }
    assert len(item.tag_assignments) == 2
    assert all(
        assignment.assigned_by == "system"
        for assignment in item.tag_assignments
    )
    assert session.commits == 0
    assert session.rollbacks == 0


def test_automatic_reclassification_removes_only_stale_system_tags() -> None:
    item = make_item(title="Abu Dhabi defensive advisory", method="automatic")
    stale = assign_tag(
        item,
        slug="uae-emirate-dubai",
        assigned_by="system",
        confidence=Decimal("0.700"),
        display_name="Dubai",
        tag_type="region",
    )
    analyst = assign_tag(
        item,
        slug="analyst-priority",
        assigned_by="analyst",
        confidence=Decimal("0.900"),
        display_name="Analyst priority",
    )
    protected_controlled = assign_tag(
        item,
        slug="uae-sector-finance",
        assigned_by="analyst",
        confidence=Decimal("0.800"),
        display_name="Finance",
        tag_type="sector",
    )
    session = FakeSession([item])

    service = UaeClassificationService(session)  # type: ignore[arg-type]
    service.classify_and_apply_if_allowed(item)
    first_assignments = list(item.tag_assignments)
    service.classify_and_apply_if_allowed(item)

    assert stale not in item.tag_assignments
    assert analyst in item.tag_assignments
    assert protected_controlled in item.tag_assignments
    assert {assignment.tag.slug for assignment in item.tag_assignments} >= {
        "language-english",
        "uae-emirate-abu-dhabi",
        "uae-sector-finance",
        "analyst-priority",
    }
    assert item.tag_assignments == first_assignments
    assert analyst.assigned_by == "analyst"
    assert analyst.confidence == Decimal("0.900")


def test_protected_classification_leaves_all_tags_untouched() -> None:
    item = make_item(
        title="Dubai advisory",
        method="reviewed",
        status="confirmed",
        reason="Reviewed analyst evidence",
        confidence=Decimal("0.950"),
    )
    analyst = assign_tag(
        item,
        slug="uae-emirate-abu-dhabi",
        assigned_by="analyst",
        confidence=Decimal("0.850"),
        display_name="Abu Dhabi",
        tag_type="region",
    )
    session = FakeSession([item])

    UaeClassificationService(session).classify_and_apply_if_allowed(item)  # type: ignore[arg-type]

    assert item.tag_assignments == [analyst]
    assert item.uae_relevance_reason == "Reviewed analyst evidence"
    assert session.commits == 0
    assert session.rollbacks == 0


@pytest.mark.parametrize("method", ["manual", "source_declared", "reviewed"])
def test_protected_or_unknown_methods_are_skipped(method: str) -> None:
    item = make_item(
        title="Dubai advisory",
        method=method,
        status="possible",
        reason="Analyst-owned reason",
        confidence=Decimal("0.333"),
    )

    counts = UaeClassificationService(FakeSession([item])).classify_existing(  # type: ignore[arg-type]
        max_items=1,
        apply=True,
    )

    assert counts.skipped_protected == 1
    assert item.uae_relevance_status == "possible"
    assert item.uae_relevance_confidence == Decimal("0.333")
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
    assert all(item.uae_relevance_status == "possible" for item in items)
    assert all(
        item.uae_relevance_confidence == confidence_for_rule("text_emirate_mention")
        for item in items
    )
    assert session.commits == 2


def test_protected_records_do_not_consume_unassigned_backfill_batch() -> None:
    protected = [
        make_item(
            title=f"Protected Dubai advisory {index}",
            method="manual",
            status="possible",
            reason="Analyst-owned reason",
            confidence=Decimal("0.250"),
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
    assert all(item.uae_relevance_confidence == Decimal("0.250") for item in protected)
    assert all(item.uae_relevance_method == "automatic" for item in backfill)
    assert all(
        item.uae_relevance_confidence == confidence_for_rule("text_emirate_mention")
        for item in backfill
    )


def test_automatic_reclassification_runs_after_unassigned_backfill_is_exhausted() -> None:
    unassigned = make_item(title="Dubai backfill", item_id=1)
    automatic = make_item(
        title="United Arab Emirates automatic review",
        method="automatic",
        status="unknown",
        reason="No direct UAE evidence found.",
        confidence=None,
        item_id=2,
    )
    session = FakeSession([automatic, unassigned])

    counts = UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
        max_items=2,
        apply=True,
    )

    assert counts.processed == 2
    assert counts.updated == 2
    assert "no attribution asserted" in unassigned.uae_relevance_reason
    assert "no attribution asserted" in automatic.uae_relevance_reason
    assert unassigned.uae_relevance_confidence == confidence_for_rule(
        "text_emirate_mention"
    )
    assert automatic.uae_relevance_confidence == confidence_for_rule(
        "text_country_mention"
    )


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


def test_controlled_tag_conflict_rolls_back_without_commit_or_partial_success() -> None:
    item = make_item(title="Dubai defensive advisory")
    original = (
        item.geographic_scope,
        item.uae_relevance_status,
        item.uae_relevance_confidence,
        item.uae_relevance_reason,
        item.uae_relevance_method,
    )
    session = FakeSession([item])
    session.tags["uae-emirate-dubai"] = Tag(
        slug="uae-emirate-dubai",
        display_name="Conflicting label",
        tag_type="region",
    )

    with pytest.raises(UaeClassificationServiceError) as exc_info:
        UaeClassificationService(session).classify_existing(  # type: ignore[arg-type]
            max_items=1,
            apply=True,
        )

    assert str(exc_info.value) == (
        "Controlled UAE classification tag conflicts with stored metadata."
    )
    assert session.rollbacks == 1
    assert session.commits == 0
    assert (
        item.geographic_scope,
        item.uae_relevance_status,
        item.uae_relevance_confidence,
        item.uae_relevance_reason,
        item.uae_relevance_method,
    ) == original
