from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.services.database_retention_service import (
    DatabaseRetentionService,
    MAX_RETENTION_PLAN_RESULTS,
    RetentionPlanningError,
)


class FakeResult:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def __iter__(self):
        return iter(self.rows)

    def mappings(self):
        return self

    def scalars(self):
        return self


def empty_results():
    return [FakeResult() for _ in range(9)]


def test_cutoff_must_be_timezone_aware() -> None:
    service = DatabaseRetentionService(MagicMock())

    with pytest.raises(ValueError, match="timezone-aware"):
        service.plan(cutoff=datetime(2026, 7, 31), limit=10)


@pytest.mark.parametrize("limit", [0, 1001, True, 1.0, "1"])
def test_result_limit_is_strict_and_bounded(limit) -> None:
    service = DatabaseRetentionService(MagicMock())

    with pytest.raises(ValueError, match="result limit"):
        service.plan(cutoff=datetime.now(UTC), limit=limit)


def test_no_policy_returns_approval_required_non_candidate_plan() -> None:
    session = MagicMock()
    session.execute.side_effect = empty_results()

    plan = DatabaseRetentionService(session).plan(
        cutoff=datetime(2026, 7, 31, tzinfo=UTC),
        limit=MAX_RETENTION_PLAN_RESULTS,
    )

    assert plan.policy_state == "approval_required"
    assert plan.candidate_count == 0
    assert plan.protected_count == 0
    assert plan.records == ()
    assert session.execute.call_count == 9
    session.add.assert_not_called()
    session.flush.assert_not_called()
    session.execute.assert_called()
    session.commit.assert_not_called()
    session.rollback.assert_not_called()


def test_running_checkpoint_retry_progress_and_quarantine_evidence_are_protected() -> None:
    session = MagicMock()
    run_id = UUID("00000000-0000-4000-8000-000000000001")
    session.execute.side_effect = [
        FakeResult(
            [
                {
                    "public_id": run_id,
                    "status": "checkpoint_pending",
                    "retry_of_run_id": 9,
                    "has_retry_child": True,
                    "has_checkpoint": True,
                    "has_watermark": True,
                    "has_unresolved_quarantine": True,
                }
            ]
        ),
        FakeResult(),
        FakeResult(),
        FakeResult(),
        FakeResult(),
        FakeResult(),
        FakeResult(),
        FakeResult(),
        FakeResult(),
        FakeResult(),
    ]

    plan = DatabaseRetentionService(session).plan(
        cutoff=datetime.now(UTC),
        limit=10,
    )

    assert plan.candidate_count == 0
    assert plan.protected_count == 1
    record = plan.records[0]
    assert record.disposition == "protected"
    assert set(record.protection_reasons) >= {
        "retention_policy_approval_required",
        "pending_ingestion_evidence",
        "checkpoint_pending_evidence",
        "active_lifecycle_state",
        "retry_linked_evidence",
        "checkpoint_linked_evidence",
        "watermark_linked_evidence",
        "unresolved_quarantine_evidence",
    }


def test_append_only_audit_and_run_events_are_protected_and_sanitized() -> None:
    session = MagicMock()
    session.execute.side_effect = [
        FakeResult(),
        FakeResult(),
        FakeResult([101]),
        FakeResult([UUID("00000000-0000-4000-8000-000000000002")]),
        FakeResult(),
        FakeResult(),
        FakeResult(),
        FakeResult(),
        FakeResult(),
        FakeResult(),
    ]

    plan = DatabaseRetentionService(session).plan(
        cutoff=datetime.now(UTC),
        limit=10,
    )

    assert {record.category for record in plan.records} == {
        "audit_event",
        "ingestion_run_event",
    }
    assert all(record.disposition == "protected" for record in plan.records)
    rendered = repr(plan)
    for prohibited in ("SELECT ", "checkpoint_value", "safe_excerpt", "password"):
        assert prohibited not in rendered


def test_unknown_state_defaults_to_protected() -> None:
    session = MagicMock()
    session.execute.side_effect = [
        FakeResult(
            [
                {
                    "public_id": UUID("00000000-0000-4000-8000-000000000003"),
                    "status": "unexpected",
                    "retry_of_run_id": None,
                    "has_retry_child": False,
                    "has_checkpoint": False,
                    "has_watermark": False,
                    "has_unresolved_quarantine": False,
                }
            ]
        ),
        *[FakeResult() for _ in range(8)],
    ]

    plan = DatabaseRetentionService(session).plan(
        cutoff=datetime.now(UTC),
        limit=10,
    )

    assert plan.records[0].disposition == "protected"
    assert "unknown_or_inconsistent_state" in plan.records[0].protection_reasons


def test_running_ingestion_is_protected_as_active_lifecycle_evidence() -> None:
    session = MagicMock()
    session.execute.side_effect = [
        FakeResult(
            [
                {
                    "public_id": UUID("00000000-0000-4000-8000-000000000004"),
                    "status": "running",
                    "retry_of_run_id": None,
                    "has_retry_child": False,
                    "has_checkpoint": False,
                    "has_watermark": False,
                    "has_unresolved_quarantine": False,
                }
            ]
        ),
        *[FakeResult() for _ in range(8)],
    ]

    plan = DatabaseRetentionService(session).plan(
        cutoff=datetime.now(UTC),
        limit=10,
    )

    assert set(plan.records[0].protection_reasons) >= {
        "running_ingestion_evidence",
        "active_lifecycle_state",
    }


def test_results_are_deterministically_ordered_and_strictly_limited() -> None:
    session = MagicMock()
    session.execute.side_effect = [
        FakeResult(),
        FakeResult(),
        FakeResult([20, 10]),
        FakeResult([UUID("00000000-0000-4000-8000-000000000005")]),
        *[FakeResult() for _ in range(5)],
    ]

    plan = DatabaseRetentionService(session).plan(
        cutoff=datetime.now(UTC),
        limit=2,
    )

    assert plan.truncated is True
    assert plan.returned_count == 2
    assert [record.identifier for record in plan.records] == sorted(
        record.identifier for record in plan.records
    )


def test_query_failure_is_sanitized_and_never_allows_deletion() -> None:
    session = MagicMock()
    session.execute.side_effect = SQLAlchemyError(
        "raw connection and SQL details synthetic-secret"
    )

    with pytest.raises(RetentionPlanningError) as exc_info:
        DatabaseRetentionService(session).plan(
            cutoff=datetime.now(UTC),
            limit=10,
        )

    message = str(exc_info.value)
    assert message == "Retention planning could not be completed safely."
    assert "synthetic-secret" not in message
    session.commit.assert_not_called()
    session.rollback.assert_not_called()


def test_intelligence_sources_are_never_queried_or_returned() -> None:
    session = MagicMock()
    session.execute.side_effect = empty_results()

    plan = DatabaseRetentionService(session).plan(
        cutoff=datetime.now(UTC),
        limit=10,
    )

    statements = "\n".join(str(call.args[0]) for call in session.execute.call_args_list)
    assert "intelligence_sources" not in statements
    assert all(record.category != "intelligence_source" for record in plan.records)


def test_planner_emits_only_select_statements() -> None:
    session = MagicMock()
    session.execute.side_effect = empty_results()

    DatabaseRetentionService(session).plan(cutoff=datetime.now(UTC), limit=10)

    statements = "\n".join(str(call.args[0]).upper() for call in session.execute.call_args_list)
    assert "UPDATE " not in statements
    assert "DELETE " not in statements
    assert "INSERT " not in statements
