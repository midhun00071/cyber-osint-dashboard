from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
import re

import pytest

from app.ingestion.services.operational_idempotency import (
    OperationalIdentityValidationError,
    build_advisory_lock_key,
    build_audit_event_key,
    build_manual_cycle_key,
    build_scheduled_cycle_key,
    build_source_attempt_run_key,
)


SLOT = datetime(2026, 8, 1, 0, 0, tzinfo=UTC)


def test_database_keys_are_deterministic_safe_and_bounded() -> None:
    scheduled = build_scheduled_cycle_key("ingestion-main", SLOT)
    manual = build_manual_cycle_key("opaque-request-42")
    run = build_source_attempt_run_key(scheduled, "nvd", 0)
    audit = build_audit_event_key("ingestion.cycle.acquired", scheduled)

    assert scheduled == build_scheduled_cycle_key("ingestion-main", SLOT)
    assert manual == build_manual_cycle_key("opaque-request-42")
    assert run == build_source_attempt_run_key(scheduled, "nvd", 0)
    assert audit == build_audit_event_key("ingestion.cycle.acquired", scheduled)
    for value in (scheduled, manual, run, audit):
        assert len(value) <= 240
        assert re.fullmatch(r"b104[a-z]+-[0-9a-f]{64}", value)


def test_equivalent_scheduled_instants_normalize_to_utc() -> None:
    dubai = SLOT.astimezone(timezone(timedelta(hours=4)))
    assert build_scheduled_cycle_key("ingestion-main", SLOT) == build_scheduled_cycle_key(
        "ingestion-main", dubai
    )


def test_manual_request_value_never_appears_in_keys_or_errors() -> None:
    canary = "opaque-secret-shaped-request-value"
    assert canary not in build_manual_cycle_key(canary)
    rejected = canary + "\x00"
    with pytest.raises(OperationalIdentityValidationError) as exc_info:
        build_manual_cycle_key(rejected)
    assert canary not in str(exc_info.value)
    assert rejected not in str(exc_info.value)


@pytest.mark.parametrize("value", ["", "x\n", "x\t", "x\x00", "x" * 513])
def test_manual_request_bounds_are_enforced(value: str) -> None:
    with pytest.raises(OperationalIdentityValidationError):
        build_manual_cycle_key(value)


def test_naive_scheduled_timestamp_is_rejected_safely() -> None:
    with pytest.raises(OperationalIdentityValidationError) as exc_info:
        build_scheduled_cycle_key("ingestion-main", datetime(2026, 8, 1))
    assert "2026" not in str(exc_info.value)


@pytest.mark.parametrize("attempt", [-1, 11, True, 1.5, "1"])
def test_attempt_bounds_are_exact(attempt: object) -> None:
    cycle = build_scheduled_cycle_key("ingestion-main", SLOT)
    with pytest.raises(OperationalIdentityValidationError):
        build_source_attempt_run_key(cycle, "nvd", attempt)  # type: ignore[arg-type]


@pytest.mark.parametrize("slug", ["NVD", "nvd_unsafe", "-nvd", "nvd-", "a" * 81])
def test_source_slug_validation_is_closed(slug: str) -> None:
    cycle = build_scheduled_cycle_key("ingestion-main", SLOT)
    with pytest.raises(OperationalIdentityValidationError):
        build_source_attempt_run_key(cycle, slug, 0)


def test_advisory_lock_keys_are_stable_signed_bigints_and_namespaced() -> None:
    values = {
        namespace: build_advisory_lock_key(namespace, "same-safe-identity")
        for namespace in (
            "cycle-idempotency",
            "source-no-overlap",
            "progress-identity",
            "rate-state-identity",
        )
    }
    assert len(set(values.values())) == 4
    for namespace, value in values.items():
        assert value == build_advisory_lock_key(namespace, "same-safe-identity")
        assert -(2**63) <= value <= 2**63 - 1


def test_unsupported_action_and_lock_namespace_are_rejected() -> None:
    cycle = build_scheduled_cycle_key("ingestion-main", SLOT)
    with pytest.raises(OperationalIdentityValidationError):
        build_audit_event_key("UNSAFE ACTION", cycle)
    with pytest.raises(OperationalIdentityValidationError):
        build_advisory_lock_key("caller-selected", "identity")
