from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta, timezone
import inspect

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.ingestion.services.operational_persistence_service import (
    DeferReason,
    OperationalConflictError,
    OperationalLockUnavailableError,
    OperationalPersistenceService,
    OperationalValidationError,
    RunCounters,
    _checkpoint_value,
    _persisted_safe_summary,
    _required_utc_timestamp,
)
from app.models.ingestion_run import IngestionRun


def test_run_counters_are_immutable_bounded_and_reconciled() -> None:
    counters = RunCounters(5, 1, 1, 1, 1, 1, 1)
    assert counters.fetched == 5
    with pytest.raises((AttributeError, TypeError)):
        counters.fetched = 6  # type: ignore[misc]
    for values in (
        (1, -1, 0, 0, 0, 0, 0),
        (1, 0, 0, 0, 0, 0, 0),
        (1, 0, 0, 0, 0, 1, 0),
        (2_147_483_648, 2_147_483_648, 0, 0, 0, 0, 0),
        (True, 1, 0, 0, 0, 0, 0),
    ):
        with pytest.raises(OperationalValidationError):
            RunCounters(*values)  # type: ignore[arg-type]


def test_service_has_no_transaction_or_session_ownership_calls() -> None:
    source = inspect.getsource(
        inspect.getmodule(OperationalPersistenceService)
    )
    tree = ast.parse(source)
    prohibited_attributes = {"commit", "rollback", "close", "begin"}
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in prohibited_attributes
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"Session", "sessionmaker", "create_engine"}
        for node in ast.walk(tree)
    )


def test_scheduled_cycle_acquisition_uses_deterministic_lock_order() -> None:
    source = inspect.getsource(OperationalPersistenceService.acquire_cycle)
    identity_lock = source.index(
        'self._advisory_lock("cycle-idempotency", cycle_key)'
    )
    exact_return = source.index("return existing")
    scheduled_lock = source.index("_SCHEDULED_CYCLE_LOCK_NAMESPACE")
    ordered_overlap = source.index(".order_by(IngestionCycle.id)")
    cycle_insert = source.index("cycle = IngestionCycle(")

    assert identity_lock < exact_return < scheduled_lock < ordered_overlap < cycle_insert
    assert source.count("_SCHEDULED_CYCLE_LOCK_IDENTITY") == 1


def test_every_mutation_requires_an_active_caller_transaction() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        with Session(engine) as session:
            service = OperationalPersistenceService(session)
            with pytest.raises(OperationalValidationError, match="caller-owned"):
                service.acquire_cycle(
                    trigger_type="manual",
                    manual_request_key="opaque-request",
                    sources_expected=1,
                )
    finally:
        engine.dispose()


def test_locking_fails_closed_on_non_postgresql_dialect() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        with Session(engine) as session, session.begin():
            service = OperationalPersistenceService(session)
            with pytest.raises(OperationalLockUnavailableError, match="PostgreSQL"):
                service.acquire_cycle(
                    trigger_type="manual",
                    manual_request_key="opaque-request",
                    sources_expected=1,
                    occurred_at=datetime(2026, 8, 1, tzinfo=UTC),
                )
    finally:
        engine.dispose()


def test_compatibility_rows_are_rejected_without_mutation() -> None:
    run = IngestionRun(
        source_id=1,
        cycle_id=None,
        idempotency_key=None,
        attempt_number=None,
        retry_of_run_id=None,
        state_version=None,
        defer_reason=None,
        trigger_type="manual",
        status="running",
        records_fetched=0,
        records_created=0,
        records_updated=0,
        records_unchanged=0,
        records_skipped=0,
        records_failed=0,
        error_count=0,
    )

    with pytest.raises(OperationalConflictError, match="compatibility"):
        OperationalPersistenceService._require_operational_run(run)
    assert run.status == "running"
    assert run.state_version is None


def test_public_api_is_narrow_and_contains_no_generic_status_or_event_setter() -> None:
    public = {
        name
        for name, value in inspect.getmembers(OperationalPersistenceService)
        if callable(value) and not name.startswith("_")
    }
    assert public == {
        "abandon_pending_progress",
        "acquire_cycle",
        "acquire_retry",
        "acquire_source_run",
        "advance_checkpoint",
        "advance_watermark",
        "complete_non_request",
        "complete_partial_or_failure",
        "finalize_cycle",
        "record_persistence_commit",
        "update_rate_limit_state",
    }
    assert "append_event" not in public
    assert "set_status" not in public


def test_closed_defer_reason_vocabulary_is_safe() -> None:
    assert {reason.value for reason in DeferReason} == {
        "quota",
        "approval",
        "source_disabled",
        "credentials_missing",
        "licence_required",
        "rate_limited",
    }


def test_all_database_mutations_fail_closed_on_sqlite() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        with Session(engine) as session, session.begin():
            service = OperationalPersistenceService(session)
            with pytest.raises(OperationalLockUnavailableError) as exc_info:
                service.acquire_retry(
                    prior_run_id=1,
                    occurred_at=datetime(2026, 8, 1, tzinfo=UTC),
                )
            message = str(exc_info.value)
            assert "SELECT" not in message
            assert "ingestion_cycles" not in message
            assert "sqlite" not in message.casefold()
    finally:
        engine.dispose()


def test_required_watermark_timestamp_never_defaults_and_normalizes_to_utc() -> None:
    for invalid in (None, datetime(2026, 8, 1, 12, 0)):
        with pytest.raises(OperationalValidationError) as exc_info:
            _required_utc_timestamp(invalid)
        assert str(invalid) not in str(exc_info.value)

    offset_value = datetime(
        2026, 8, 1, 12, 0, tzinfo=timezone(timedelta(hours=4))
    )
    assert _required_utc_timestamp(offset_value) == datetime(
        2026, 8, 1, 8, 0, tzinfo=UTC
    )


UNSAFE_PERSISTED_TEXT = (
    "postgresql://service:secret@localhost:5432/database",
    "Authorization: Bearer secret-token",
    "Authorization=Basic dXNlcjpwYXNz",
    "Basic dXNlcjpwYXNz",
    "password=hunter2",
    "api-key=secret-value",
    "cookie=session=secret-value",
    "-----BEGIN PRIVATE KEY-----",
    "Traceback (most recent call last):",
    "Stack trace: internal application frame",
    "SELECT secret_value FROM credentials;",
    "INSERT INTO audit_events VALUES (...);",
    "UPDATE intelligence_sources SET is_enabled = false;",
    "DELETE FROM source_records;",
    "DROP TABLE source_records;",
    "DROP DATABASE operational_records;",
    "ALTER TABLE ingestion_runs ADD COLUMN x integer;",
    "CREATE TABLE leaked_records (id integer);",
    "SQL: SELECT secret_value FROM credentials;",
    "Query failed: DELETE FROM source_records;",
    "Statement: INSERT INTO audit_events VALUES (...);",
    "Database statement was DROP TABLE source_records;",
    "Raw query: ALTER TABLE ingestion_runs ADD COLUMN x integer;",
    "Executed query: UPDATE intelligence_sources SET is_enabled = false;",
    "Diagnostic: CREATE TABLE leaked_records (id integer);",
    "summary\x00secret",
)


@pytest.mark.parametrize("canary", UNSAFE_PERSISTED_TEXT)
def test_persisted_safe_summary_rejects_secret_and_diagnostic_canaries(canary) -> None:
    with pytest.raises(OperationalValidationError) as exc_info:
        _persisted_safe_summary(canary)
    assert canary not in str(exc_info.value)


def test_persisted_safe_summary_accepts_none_and_ordinary_operational_prose() -> None:
    assert _persisted_safe_summary(None) is None
    assert _persisted_safe_summary("  Ingestion completed with bounded results.  ") == (
        "Ingestion completed with bounded results."
    )
    assert _persisted_safe_summary("Basic operation completed safely.") == (
        "Basic operation completed safely."
    )


@pytest.mark.parametrize(
    "prose",
    (
        "Selected 10 records from the approved feed.",
        "Update completed successfully.",
        "Delete request was not issued.",
        "The source returned results from its public catalogue.",
        "Basic operation completed safely.",
        "The ingestion statement count remained within limits.",
    ),
)
def test_persisted_safe_summary_accepts_database_related_operational_prose(prose) -> None:
    assert _persisted_safe_summary(prose) == prose


@pytest.mark.parametrize(
    "canary",
    (
        "   ",
        "mysql://service:secret@localhost/database",
        "mssql://service:secret@localhost/database",
        "redis://service:secret@localhost/0",
        "Authorization: Bearer secret-token",
        "Basic dXNlcjpwYXNz",
        "access_token=secret-value",
        "-----BEGIN RSA PRIVATE KEY-----",
    ),
)
def test_checkpoint_values_reject_empty_and_credential_material(canary) -> None:
    with pytest.raises(OperationalValidationError) as exc_info:
        _checkpoint_value(canary)
    assert canary not in str(exc_info.value)


def test_checkpoint_value_preserves_ordinary_opaque_content_exactly() -> None:
    value = "  cursor::opaque/segment==  "
    assert _checkpoint_value(value) == value
