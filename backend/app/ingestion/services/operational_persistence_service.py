"""Caller-transaction-owned B1-04 operational persistence primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from functools import wraps
import re
from typing import Callable, ParamSpec, TypeVar

from sqlalchemy import func, literal_column, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.source_registry import ProgressContract, SourceRegistryError, get_source_definition
from app.ingestion.services.operational_idempotency import (
    OperationalIdentityValidationError,
    build_advisory_lock_key,
    build_audit_event_key,
    build_manual_cycle_key,
    build_scheduled_cycle_key,
    build_source_attempt_run_key,
)
from app.models.audit_event import AuditEvent
from app.models.ingestion_cycle import IngestionCycle
from app.models.ingestion_run import IngestionRun
from app.models.ingestion_run_event import IngestionRunEvent
from app.models.intelligence_source import IntelligenceSource
from app.models.source_checkpoint import SourceCheckpoint
from app.models.source_rate_limit_state import SourceRateLimitState
from app.models.source_watermark import SourceWatermark


class OperationalPersistenceError(RuntimeError):
    """Base class for sanitized B1-04 service failures."""


class OperationalValidationError(OperationalPersistenceError):
    """A caller supplied an invalid bounded value or transition intent."""


class OperationalMissingRecordError(OperationalPersistenceError):
    """A required operational record does not exist."""


class OperationalLockUnavailableError(OperationalPersistenceError):
    """A required transaction-scoped advisory lock is unavailable."""


class OperationalConflictError(OperationalPersistenceError):
    """Existing immutable operational evidence conflicts with the request."""


class OperationalStaleStateError(OperationalConflictError):
    """An optimistic state/version expectation is stale."""


class OperationalPersistenceFailure(OperationalPersistenceError):
    """The database operation failed and the caller must roll back."""


class DeferReason(str, Enum):
    """Closed non-secret reasons retained for deferred terminal outcomes."""

    QUOTA = "quota"
    APPROVAL = "approval"
    SOURCE_DISABLED = "source_disabled"
    CREDENTIALS = "credentials_missing"
    LICENCE = "licence_required"
    RATE_LIMIT = "rate_limited"


MAX_COUNTER = 2_147_483_647
MAX_EVENT_SEQUENCE = 100_000
_CYCLE_AUDIT_ACTION = "ingestion.cycle.acquired"
_SCHEDULED_CYCLE_LOCK_NAMESPACE = "scheduled-cycle-acquisition"
_SCHEDULED_CYCLE_LOCK_IDENTITY = "all-scheduled-cycles"
_TERMINAL_CYCLE_STATUSES = frozenset({"success", "partial", "failed", "cancelled"})
_SAFE_ACTOR_TYPES = frozenset({"user", "service", "system"})
_SAFE_ACTOR_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,159}$")
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_ACTIVE_RUN_STATUSES = ("running", "checkpoint_pending")
_TERMINAL_RUN_STATUSES = frozenset(
    {
        "success", "no_change", "skipped", "deferred_quota", "approval_pending",
        "disabled", "credentials_missing", "licence_required", "rate_limited",
        "partial", "failed", "cancelled",
    }
)
_NON_REQUEST_EVENTS = {
    "skipped": "skipped",
    "deferred_quota": "deferred",
    "approval_pending": "deferred",
    "disabled": "deferred",
    "credentials_missing": "deferred",
    "licence_required": "deferred",
    "rate_limited": "deferred",
}
_STATUS_DEFER_REASONS = {
    "deferred_quota": DeferReason.QUOTA,
    "approval_pending": DeferReason.APPROVAL,
    "disabled": DeferReason.SOURCE_DISABLED,
    "credentials_missing": DeferReason.CREDENTIALS,
    "licence_required": DeferReason.LICENCE,
    "rate_limited": DeferReason.RATE_LIMIT,
}
_RATE_STATES = frozenset({"available", "limited", "backoff", "quota_unavailable", "unknown"})
_CREDENTIAL_URL = re.compile(
    r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@",
    re.IGNORECASE,
)
_AUTHORIZATION_VALUE = re.compile(
    r"\bauthorization\s*[:=]\s*(?:bearer|basic)\s+\S+|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\bbasic\s+(?-i:(?=[A-Za-z0-9+/=]*[A-Z0-9+/])"
    r"(?=[A-Za-z0-9+/=]*[a-z])[A-Za-z0-9+/]{8,}={0,2})",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|token|cookie|set-cookie)"
    r"\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----",
    re.IGNORECASE,
)
_DIAGNOSTIC_CONTENT = re.compile(
    r"traceback\s*\(most recent call last\)|\bstack\s*trace\b|"
    r"(?:^|\n)\s*at\s+[\w.$<>]+\([^\n)]*:\d+\)",
    re.IGNORECASE,
)
_RAW_SQL = re.compile(
    r"(?:^|[;\n]|:\s*|"
    r"\b(?:sql|query|statement|database\s+statement|raw\s+query|executed\s+query)"
    r"(?:\s+(?:failed|was|executed)){0,2}\s+)\s*"
    r"(?:select\b[^;\n]{1,900}?\bfrom\b|insert\s+into\b|"
    r"update\s+\S+\s+set\b|delete\s+from\b|drop\s+(?:table|database)\b|"
    r"alter\s+table\b|create\s+table\b)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class RunCounters:
    """Immutable reconciled counters for one bounded operational run."""

    fetched: int
    created: int
    updated: int
    unchanged: int
    skipped: int
    failed: int
    error_count: int

    def __post_init__(self) -> None:
        values = (
            self.fetched, self.created, self.updated, self.unchanged,
            self.skipped, self.failed, self.error_count,
        )
        if any(type(value) is not int for value in values):
            raise OperationalValidationError("Run counters must be integers.")
        if any(value < 0 or value > MAX_COUNTER for value in values):
            raise OperationalValidationError("Run counters are outside the supported range.")
        if self.fetched != self.created + self.updated + self.unchanged + self.skipped + self.failed:
            raise OperationalValidationError("Run counters do not reconcile.")
        if self.error_count < self.failed:
            raise OperationalValidationError("Run error counters do not reconcile.")


P = ParamSpec("P")
R = TypeVar("R")


def _translate_database_errors(method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return method(*args, **kwargs)
        except OperationalPersistenceError:
            raise
        except (OperationalIdentityValidationError, SourceRegistryError) as exc:
            raise OperationalValidationError("Operational input validation failed.") from exc
        except SQLAlchemyError as exc:
            raise OperationalPersistenceFailure(
                "The operational database operation failed."
            ) from exc

    return wrapped


class OperationalPersistenceService:
    """Mutate operational evidence inside an existing caller-owned transaction."""

    def __init__(self, session: Session) -> None:
        if not isinstance(session, Session):
            raise OperationalValidationError("An existing SQLAlchemy session is required.")
        self._session = session

    @_translate_database_errors
    def acquire_cycle(
        self,
        *,
        trigger_type: str,
        sources_expected: int,
        scheduled_for: datetime | None = None,
        deployment_ref: str | None = None,
        manual_request_key: str | None = None,
        actor_type: str = "service",
        actor_ref: str = "ingestion-service",
        occurred_at: datetime | None = None,
        safe_summary: str | None = None,
    ) -> IngestionCycle:
        """Acquire or create one deterministic scheduled/manual running cycle."""

        self._require_transaction()
        now = _utc_timestamp(occurred_at)
        if type(sources_expected) is not int or not 0 <= sources_expected <= 10_000:
            raise OperationalValidationError("The expected source count is invalid.")
        if trigger_type == "scheduled":
            if scheduled_for is None or deployment_ref is None or manual_request_key is not None:
                raise OperationalValidationError("Scheduled cycle inputs are invalid.")
            normalized_slot = _utc_timestamp(scheduled_for)
            cycle_key = build_scheduled_cycle_key(deployment_ref, normalized_slot)
        elif trigger_type == "manual":
            if manual_request_key is None or scheduled_for is not None or deployment_ref is not None:
                raise OperationalValidationError("Manual cycle inputs are invalid.")
            normalized_slot = None
            cycle_key = build_manual_cycle_key(manual_request_key)
        else:
            raise OperationalValidationError("The runtime cycle trigger is unsupported.")
        safe_actor_type, safe_actor_ref = _actor(actor_type, actor_ref)
        summary = _persisted_safe_summary(safe_summary)
        self._advisory_lock("cycle-idempotency", cycle_key)
        existing = self._session.scalars(
            select(IngestionCycle)
            .where(IngestionCycle.idempotency_key == cycle_key)
            .with_for_update()
        ).first()
        if existing is not None:
            if (
                existing.trigger_type != trigger_type
                or _normalize_db_timestamp(existing.scheduled_for) != normalized_slot
                or existing.sources_expected != sources_expected
            ):
                raise OperationalConflictError("The cycle identity conflicts with existing evidence.")
            return existing

        if trigger_type == "scheduled":
            self._advisory_lock(
                _SCHEDULED_CYCLE_LOCK_NAMESPACE,
                _SCHEDULED_CYCLE_LOCK_IDENTITY,
            )
            overlapping = self._session.scalars(
                select(IngestionCycle)
                .where(
                    IngestionCycle.trigger_type == "scheduled",
                    IngestionCycle.status == "running",
                )
                .order_by(IngestionCycle.id)
                .limit(1)
                .with_for_update()
            ).first()
            if overlapping is not None:
                raise OperationalConflictError(
                    "Another scheduled cycle is already active."
                )

        cycle = IngestionCycle(
            idempotency_key=cycle_key,
            trigger_type=trigger_type,
            status="running",
            scheduled_for=normalized_slot,
            started_at=now,
            completed_at=None,
            sources_expected=sources_expected,
            sources_started=0,
            sources_completed=0,
            sources_successful=0,
            sources_non_successful=0,
            safe_summary=summary,
            created_at=now,
        )
        self._session.add(cycle)
        self._session.flush()
        self._session.add(
            AuditEvent(
                idempotency_key=build_audit_event_key(_CYCLE_AUDIT_ACTION, cycle_key),
                actor_type=safe_actor_type,
                actor_ref=safe_actor_ref,
                action=_CYCLE_AUDIT_ACTION,
                target_type="ingestion_cycle",
                target_ref=cycle_key,
                outcome="success",
                cycle_id=cycle.id,
                ingestion_run_id=None,
                correlation_id=None,
                safe_detail=None,
                occurred_at=now,
                created_at=now,
            )
        )
        self._session.flush()
        return cycle

    @_translate_database_errors
    def finalize_cycle(
        self,
        *,
        cycle_id: int,
        status: str,
        sources_started: int,
        sources_completed: int,
        sources_successful: int,
        sources_non_successful: int,
        safe_summary: str | None = None,
        occurred_at: datetime | None = None,
    ) -> IngestionCycle:
        """Finalize one locked parent cycle with exact, reconciled evidence."""

        self._require_transaction()
        if status not in _TERMINAL_CYCLE_STATUSES:
            raise OperationalValidationError("The cycle terminal status is unsupported.")
        counters = (
            sources_started,
            sources_completed,
            sources_successful,
            sources_non_successful,
        )
        if any(type(value) is not int for value in counters):
            raise OperationalValidationError("Cycle counters must be integers.")
        if any(value < 0 or value > 10_000 for value in counters):
            raise OperationalValidationError("Cycle counters are outside the supported range.")
        summary = _persisted_safe_summary(safe_summary)
        cycle = self._lock_cycle(cycle_id)
        expected = cycle.sources_expected
        if not (
            sources_completed <= sources_started <= expected
            and sources_successful + sources_non_successful == sources_completed
        ):
            raise OperationalValidationError("Cycle counters do not reconcile.")
        latest_statuses = self._cycle_run_statuses(cycle.id)
        if _cycle_counts_from_statuses(latest_statuses) != (
            sources_started,
            sources_completed,
            sources_successful,
            sources_non_successful,
        ):
            raise OperationalConflictError(
                "Cycle counters conflict with committed source-run evidence."
            )
        _validate_cycle_outcome(
            status=status,
            expected=expected,
            started=sources_started,
            completed=sources_completed,
            successful=sources_successful,
            non_successful=sources_non_successful,
        )
        if (
            status == "cancelled"
            and "cancelled" not in latest_statuses
            and sources_completed == expected
        ):
            raise OperationalConflictError(
                "Cancelled cycle evidence conflicts with committed source outcomes."
            )

        if cycle.status in _TERMINAL_CYCLE_STATUSES:
            repeated = (
                cycle.status == status
                and cycle.sources_started == sources_started
                and cycle.sources_completed == sources_completed
                and cycle.sources_successful == sources_successful
                and cycle.sources_non_successful == sources_non_successful
                and cycle.safe_summary == summary
            )
            if not repeated:
                raise OperationalConflictError(
                    "The cycle completion conflicts with existing evidence."
                )
            if occurred_at is not None and _normalize_db_timestamp(
                cycle.completed_at
            ) != _utc_timestamp(occurred_at):
                raise OperationalConflictError(
                    "The cycle completion conflicts with existing evidence."
                )
            return cycle
        if cycle.status != "running":
            raise OperationalConflictError("The cycle cannot be finalized.")

        if cycle.trigger_type == "scheduled":
            overlapping = self._session.scalars(
                select(IngestionCycle)
                .where(
                    IngestionCycle.id != cycle.id,
                    IngestionCycle.trigger_type == "scheduled",
                    IngestionCycle.status == "running",
                )
                .with_for_update()
            ).first()
            if overlapping is not None:
                raise OperationalConflictError(
                    "An overlapping scheduled cycle is active."
                )

        now = _utc_timestamp(occurred_at)
        _ensure_not_before(now, cycle.started_at)
        cycle.status = status
        cycle.completed_at = now
        cycle.sources_started = sources_started
        cycle.sources_completed = sources_completed
        cycle.sources_successful = sources_successful
        cycle.sources_non_successful = sources_non_successful
        cycle.safe_summary = summary
        self._session.flush()
        return cycle

    @_translate_database_errors
    def acquire_source_run(
        self,
        *,
        cycle_id: int,
        source_slug: str,
        occurred_at: datetime | None = None,
    ) -> IngestionRun:
        """Acquire attempt zero while enforcing participating-writer no-overlap."""

        self._require_transaction()
        now = _utc_timestamp(occurred_at)
        requested_definition = get_source_definition(source_slug)
        self._advisory_lock("source-no-overlap", requested_definition.slug)
        cycle = self._lock_cycle(cycle_id)
        if cycle.status != "running":
            raise OperationalConflictError("The cycle is not available for source acquisition.")
        _ensure_not_before(now, cycle.started_at)
        source, definition = self._lock_source_by_slug(source_slug)
        run_key = build_source_attempt_run_key(cycle.idempotency_key, source.slug, 0)
        existing = self._session.scalars(
            select(IngestionRun)
            .where(IngestionRun.idempotency_key == run_key)
            .with_for_update()
        ).first()
        if existing is not None:
            if not _matches_attempt(existing, source.id, cycle.id, 0, None):
                raise OperationalConflictError("The run identity conflicts with existing evidence.")
            self._verify_registry_source(source, definition.slug)
            return existing
        overlap = self._session.scalars(
            select(IngestionRun)
            .where(
                IngestionRun.source_id == source.id,
                IngestionRun.status.in_(_ACTIVE_RUN_STATUSES),
            )
            .with_for_update()
        ).first()
        if overlap is not None:
            raise OperationalConflictError("An active source run already exists.")
        run = self._new_run(
            source=source,
            cycle=cycle,
            run_key=run_key,
            attempt_number=0,
            retry_of_run_id=None,
            trigger_type=cycle.trigger_type,
            now=now,
        )
        self._session.add(run)
        self._session.flush()
        self._session.add(
            IngestionRunEvent(
                ingestion_run_id=run.id,
                sequence_number=1,
                event_type="acquired",
                from_status=None,
                to_status=None,
                safe_message=None,
                occurred_at=now,
                created_at=now,
            )
        )
        self._session.flush()
        return run

    @_translate_database_errors
    def acquire_retry(
        self,
        *,
        prior_run_id: int,
        occurred_at: datetime | None = None,
    ) -> IngestionRun:
        """Acquire exactly the next non-branching retry attempt."""

        self._require_transaction()
        now = _utc_timestamp(occurred_at)
        source_slug = self._source_slug_for_run(prior_run_id)
        self._advisory_lock("source-no-overlap", source_slug)
        prior = self._lock_run(prior_run_id)
        self._require_operational_run(prior)
        source = self._lock_source_by_id(prior.source_id)
        definition = self._definition_for_source(source)
        self._verify_registry_source(source, definition.slug)
        if prior.status not in _TERMINAL_RUN_STATUSES:
            raise OperationalConflictError("The retry parent is not terminal.")
        _ensure_not_before(now, prior.completed_at or prior.started_at)
        highest = self._session.scalars(
            select(IngestionRun)
            .where(IngestionRun.source_id == prior.source_id, IngestionRun.cycle_id == prior.cycle_id)
            .order_by(IngestionRun.attempt_number.desc())
            .with_for_update()
        ).first()
        if highest is None:
            raise OperationalMissingRecordError("The retry lineage is unavailable.")
        next_attempt = prior.attempt_number + 1  # type: ignore[operator]
        if next_attempt > 10:
            raise OperationalValidationError("The retry attempt limit has been reached.")
        cycle = self._lock_cycle(prior.cycle_id)  # type: ignore[arg-type]
        run_key = build_source_attempt_run_key(cycle.idempotency_key, source.slug, next_attempt)
        existing = self._session.scalars(
            select(IngestionRun).where(IngestionRun.idempotency_key == run_key).with_for_update()
        ).first()
        if existing is not None:
            if (
                highest.id == existing.id
                and _matches_attempt(existing, source.id, cycle.id, next_attempt, prior.id)
            ):
                return existing
            raise OperationalConflictError("The retry identity conflicts with existing evidence.")
        if highest.id != prior.id or highest.attempt_number != prior.attempt_number:
            raise OperationalConflictError("The retry parent is stale.")
        overlap = self._session.scalars(
            select(IngestionRun)
            .where(IngestionRun.source_id == source.id, IngestionRun.status.in_(_ACTIVE_RUN_STATUSES))
            .with_for_update()
        ).first()
        if overlap is not None:
            raise OperationalConflictError("An active source run already exists.")
        retry = self._new_run(
            source=source,
            cycle=cycle,
            run_key=run_key,
            attempt_number=next_attempt,
            retry_of_run_id=prior.id,
            trigger_type="retry",
            now=now,
        )
        self._session.add(retry)
        self._session.flush()
        self._session.add(
            IngestionRunEvent(
                ingestion_run_id=retry.id,
                sequence_number=1,
                event_type="acquired",
                from_status=None,
                to_status=None,
                safe_message=None,
                occurred_at=now,
                created_at=now,
            )
        )
        self._session.flush()
        return retry

    @_translate_database_errors
    def record_persistence_commit(
        self,
        *,
        run_id: int,
        expected_state_version: int,
        counters: RunCounters,
        safe_summary: str | None = None,
        occurred_at: datetime | None = None,
    ) -> IngestionRun:
        """Record durable persistence and either pend progress or finish a no-progress run."""

        self._require_transaction()
        now = _utc_timestamp(occurred_at)
        summary = _persisted_safe_summary(safe_summary)
        run = self._lock_versioned_run(run_id, expected_state_version, required_status="running")
        _ensure_not_before(now, run.started_at)
        definition = self._definition_for_run(run)
        _validate_persistence_counters(counters)
        self._apply_counters(run, counters)
        run.safe_summary = summary
        if definition.progress_contract is ProgressContract.NONE:
            outcome = _successful_outcome(counters)
            run.status = outcome
            run.completed_at = now
            run.defer_reason = None
            self._append_events(
                run,
                now,
                (
                    ("persistence_committed", "running", outcome),
                    ("completed", None, None),
                ),
            )
        else:
            run.status = "checkpoint_pending"
            run.completed_at = None
            run.defer_reason = None
            self._append_events(
                run, now, (("persistence_committed", "running", "checkpoint_pending"),)
            )
        run.state_version = expected_state_version + 1
        self._session.flush()
        return run

    @_translate_database_errors
    def complete_non_request(
        self,
        *,
        run_id: int,
        expected_state_version: int,
        status: str,
        defer_reason: DeferReason | str | None = None,
        safe_summary: str | None = None,
        occurred_at: datetime | None = None,
    ) -> IngestionRun:
        """Finish a zero-record non-request/deferred outcome from running."""

        self._require_transaction()
        if status not in _NON_REQUEST_EVENTS:
            raise OperationalValidationError("The non-request outcome is unsupported.")
        expected_reason = _STATUS_DEFER_REASONS.get(status)
        normalized_reason = _defer_reason(defer_reason)
        if normalized_reason is not expected_reason:
            raise OperationalValidationError("The defer reason does not match the outcome.")
        now = _utc_timestamp(occurred_at)
        summary = _persisted_safe_summary(safe_summary)
        run = self._lock_versioned_run(run_id, expected_state_version, required_status="running")
        _ensure_not_before(now, run.started_at)
        self._apply_counters(run, RunCounters(0, 0, 0, 0, 0, 0, 0))
        run.status = status
        run.completed_at = now
        run.defer_reason = normalized_reason.value if normalized_reason is not None else None
        run.safe_summary = summary
        run.state_version = expected_state_version + 1
        self._append_events(run, now, ((_NON_REQUEST_EVENTS[status], "running", status),))
        self._session.flush()
        return run

    @_translate_database_errors
    def complete_partial_or_failure(
        self,
        *,
        run_id: int,
        expected_state_version: int,
        status: str,
        counters: RunCounters,
        run_level_error: bool = False,
        safe_summary: str | None = None,
        occurred_at: datetime | None = None,
    ) -> IngestionRun:
        """Finish a truthful partial, failed, or acknowledged cancelled run."""

        self._require_transaction()
        if not isinstance(counters, RunCounters) or type(run_level_error) is not bool:
            raise OperationalValidationError("Validated run failure evidence is required.")
        if status == "partial":
            if counters.created + counters.updated + counters.unchanged < 1 or counters.skipped + counters.failed < 1:
                raise OperationalValidationError("Partial-run counters are invalid.")
            event = "partial"
        elif status == "failed":
            if counters.failed < 1 and run_level_error is not True:
                raise OperationalValidationError("A failed run requires failure evidence.")
            event = "failed"
        elif status == "cancelled":
            if counters != RunCounters(0, 0, 0, 0, 0, 0, 0) or run_level_error:
                raise OperationalValidationError("A cancelled non-request run requires zero counters.")
            event = "cancelled"
        else:
            raise OperationalValidationError("The terminal outcome is unsupported.")
        now = _utc_timestamp(occurred_at)
        summary = _persisted_safe_summary(safe_summary)
        run = self._lock_versioned_run(run_id, expected_state_version, required_status="running")
        _ensure_not_before(now, run.started_at)
        self._apply_counters(run, counters)
        run.status = status
        run.completed_at = now
        run.defer_reason = None
        run.safe_summary = summary
        run.state_version = expected_state_version + 1
        self._append_events(run, now, ((event, "running", status),))
        self._session.flush()
        return run

    @_translate_database_errors
    def abandon_pending_progress(
        self,
        *,
        run_id: int,
        expected_state_version: int,
        status: str,
        safe_summary: str | None = None,
        occurred_at: datetime | None = None,
    ) -> IngestionRun:
        """Explicitly stop progress recovery as failed or cancelled."""

        self._require_transaction()
        if status not in {"failed", "cancelled"}:
            raise OperationalValidationError("The progress-abandonment outcome is unsupported.")
        now = _utc_timestamp(occurred_at)
        summary = _persisted_safe_summary(safe_summary)
        run = self._lock_versioned_run(
            run_id, expected_state_version, required_status="checkpoint_pending"
        )
        _ensure_not_before(now, run.started_at)
        run.status = status
        run.completed_at = now
        run.defer_reason = None
        run.safe_summary = summary
        run.state_version = expected_state_version + 1
        self._append_events(run, now, ((status, "checkpoint_pending", status),))
        self._session.flush()
        return run

    @_translate_database_errors
    def advance_checkpoint(
        self,
        *,
        run_id: int,
        expected_run_state_version: int,
        scope_kind: str,
        partition_key: str | None,
        checkpoint_name: str,
        checkpoint_value: str,
        expected_previous_version: int,
        committed_at: datetime | None = None,
    ) -> SourceCheckpoint:
        """Advance one linear checkpoint and atomically finalize its pending run."""

        self._require_transaction()
        scope, partition, name = _progress_identity(scope_kind, partition_key, checkpoint_name)
        value = _checkpoint_value(checkpoint_value)
        expected_previous = _expected_previous_version(expected_previous_version)
        now = _utc_timestamp(committed_at)
        source_slug = self._source_slug_for_run(run_id)
        identity = f"{source_slug}:{scope}:{partition or ''}:{name}"
        self._advisory_lock("progress-identity", identity)
        run = self._lock_run(run_id)
        self._require_operational_run(run)
        source = self._lock_source_by_id(run.source_id)
        definition = self._definition_for_source(source)
        if definition.progress_contract is not ProgressContract.CHECKPOINT:
            raise OperationalConflictError("The source does not use checkpoint progress.")
        terminal_existing = self._existing_checkpoint_retry(
            run, expected_run_state_version, scope, partition, name, value, expected_previous
        )
        if terminal_existing is not None:
            return terminal_existing
        self._require_run_version(run, expected_run_state_version)
        if run.status != "checkpoint_pending":
            raise OperationalConflictError("The run is not awaiting checkpoint advancement.")
        persistence_time = self._persistence_committed_time(run.id)
        if now < persistence_time:
            raise OperationalValidationError("The progress commit time is invalid.")
        current = self._current_checkpoint(source.id, scope, partition, name)
        _verify_previous(current, expected_previous)
        if current is not None and current.checkpoint_value == value:
            self._finalize_unchanged_progress_run(
                run, expected_run_state_version, now
            )
            self._session.flush()
            return current
        checkpoint = SourceCheckpoint(
            source_id=source.id,
            scope_kind=scope,
            partition_key=partition,
            checkpoint_name=name,
            version=expected_previous + 1,
            checkpoint_value=value,
            previous_checkpoint_id=current.id if current is not None else None,
            advanced_by_run_id=run.id,
            persistence_committed_at=persistence_time,
            committed_at=now,
        )
        self._session.add(checkpoint)
        self._finalize_progress_run(run, expected_run_state_version, now)
        self._session.flush()
        return checkpoint

    @_translate_database_errors
    def advance_watermark(
        self,
        *,
        run_id: int,
        expected_run_state_version: int,
        scope_kind: str,
        partition_key: str | None,
        watermark_name: str,
        watermark_value: datetime,
        expected_previous_version: int,
        committed_at: datetime | None = None,
    ) -> SourceWatermark:
        """Advance a strictly increasing UTC watermark and finalize its pending run."""

        self._require_transaction()
        scope, partition, name = _progress_identity(scope_kind, partition_key, watermark_name)
        value = _required_utc_timestamp(watermark_value)
        expected_previous = _expected_previous_version(expected_previous_version)
        now = _utc_timestamp(committed_at)
        source_slug = self._source_slug_for_run(run_id)
        identity = f"{source_slug}:{scope}:{partition or ''}:{name}"
        self._advisory_lock("progress-identity", identity)
        run = self._lock_run(run_id)
        self._require_operational_run(run)
        source = self._lock_source_by_id(run.source_id)
        definition = self._definition_for_source(source)
        if definition.progress_contract is not ProgressContract.WATERMARK:
            raise OperationalConflictError("The source does not use watermark progress.")
        terminal_existing = self._existing_watermark_retry(
            run, expected_run_state_version, scope, partition, name, value, expected_previous
        )
        if terminal_existing is not None:
            return terminal_existing
        self._require_run_version(run, expected_run_state_version)
        if run.status != "checkpoint_pending":
            raise OperationalConflictError("The run is not awaiting watermark advancement.")
        persistence_time = self._persistence_committed_time(run.id)
        if now < persistence_time:
            raise OperationalValidationError("The progress commit time is invalid.")
        current = self._current_watermark(source.id, scope, partition, name)
        _verify_previous(current, expected_previous)
        if current is not None:
            current_value = _normalize_db_timestamp(current.watermark_value)
            if value == current_value:
                self._finalize_unchanged_progress_run(
                    run, expected_run_state_version, now
                )
                self._session.flush()
                return current
            if value < current_value:
                raise OperationalConflictError("The watermark must advance monotonically.")
        watermark = SourceWatermark(
            source_id=source.id,
            scope_kind=scope,
            partition_key=partition,
            watermark_name=name,
            version=expected_previous + 1,
            watermark_value=value,
            previous_watermark_id=current.id if current is not None else None,
            advanced_by_run_id=run.id,
            persistence_committed_at=persistence_time,
            committed_at=now,
        )
        self._session.add(watermark)
        self._finalize_progress_run(run, expected_run_state_version, now)
        self._session.flush()
        return watermark

    @_translate_database_errors
    def update_rate_limit_state(
        self,
        *,
        source_slug: str,
        policy_key: str,
        expected_state_version: int | None,
        state: str,
        request_limit: int | None = None,
        remaining: int | None = None,
        window_seconds: int | None = None,
        reset_at: datetime | None = None,
        backoff_until: datetime | None = None,
        last_observed_at: datetime | None = None,
        updated_by_run_id: int | None = None,
        updated_at: datetime | None = None,
    ) -> SourceRateLimitState:
        """Create/update normalized rate state with exact-version compare-and-swap."""

        self._require_transaction()
        policy = _safe_name(policy_key)
        if state not in _RATE_STATES:
            raise OperationalValidationError("The rate-state value is unsupported.")
        limit = _nullable_count(request_limit)
        remaining_count = _nullable_count(remaining)
        if limit is not None and remaining_count is not None and remaining_count > limit:
            raise OperationalValidationError("The rate-state counts are invalid.")
        if window_seconds is not None and (
            type(window_seconds) is not int or not 1 <= window_seconds <= 31_536_000
        ):
            raise OperationalValidationError("The rate-state window is invalid.")
        normalized_times = tuple(
            _utc_timestamp(value) if value is not None else None
            for value in (reset_at, backoff_until, last_observed_at)
        )
        now = _utc_timestamp(updated_at)
        requested_definition = get_source_definition(source_slug)
        self._advisory_lock(
            "rate-state-identity", f"{requested_definition.slug}:{policy}"
        )
        source, definition = self._lock_source_by_slug(source_slug)
        self._verify_registry_source(source, definition.slug)
        if updated_by_run_id is not None:
            updater = self._lock_run(updated_by_run_id)
            self._require_operational_run(updater)
            if updater.source_id != source.id:
                raise OperationalConflictError("The rate-state updater does not match the source.")
        existing = self._session.scalars(
            select(SourceRateLimitState)
            .where(SourceRateLimitState.source_id == source.id, SourceRateLimitState.policy_key == policy)
            .with_for_update()
        ).first()
        if existing is None:
            if expected_state_version is not None:
                raise OperationalStaleStateError("The rate-state version is stale.")
            row = SourceRateLimitState(source_id=source.id, policy_key=policy, state_version=1)
            self._session.add(row)
        else:
            if type(expected_state_version) is not int or existing.state_version != expected_state_version:
                raise OperationalStaleStateError("The rate-state version is stale.")
            row = existing
            row.state_version = existing.state_version + 1
        row.request_limit = limit
        row.remaining = remaining_count
        row.window_seconds = window_seconds
        row.reset_at, row.backoff_until, row.last_observed_at = normalized_times
        row.state = state
        row.updated_by_run_id = updated_by_run_id
        row.updated_at = now
        self._session.flush()
        return row

    def _require_transaction(self) -> None:
        transaction = self._session.get_transaction()
        if transaction is None or not transaction.is_active:
            raise OperationalValidationError("An active caller-owned transaction is required.")
        if self._session.get_bind().dialect.name != "postgresql":
            raise OperationalLockUnavailableError("PostgreSQL operational locking is required.")

    def _advisory_lock(self, namespace: str, identity: str) -> None:
        bind = self._session.get_bind()
        if bind.dialect.name != "postgresql":
            raise OperationalLockUnavailableError("PostgreSQL operational locking is required.")
        key = build_advisory_lock_key(namespace, identity)
        acquired = self._session.scalar(select(func.pg_try_advisory_xact_lock(key)))
        if acquired is not True:
            raise OperationalLockUnavailableError("The operational lock is unavailable.")

    def _lock_cycle(self, cycle_id: int) -> IngestionCycle:
        if type(cycle_id) is not int or cycle_id <= 0:
            raise OperationalValidationError("A valid cycle identity is required.")
        cycle = self._session.scalars(
            select(IngestionCycle).where(IngestionCycle.id == cycle_id).with_for_update()
        ).first()
        if cycle is None:
            raise OperationalMissingRecordError("The ingestion cycle was not found.")
        return cycle

    def _cycle_run_statuses(self, cycle_id: int) -> tuple[str, ...]:
        latest_attempts = (
            select(
                IngestionRun.source_id.label("source_id"),
                func.max(IngestionRun.attempt_number).label("attempt_number"),
            )
            .where(IngestionRun.cycle_id == cycle_id)
            .group_by(IngestionRun.source_id)
            .subquery()
        )
        return tuple(self._session.scalars(
            select(IngestionRun.status)
            .join(
                latest_attempts,
                (IngestionRun.source_id == latest_attempts.c.source_id)
                & (IngestionRun.attempt_number == latest_attempts.c.attempt_number),
            )
            .where(IngestionRun.cycle_id == cycle_id)
        ).all())

    def _lock_source_by_slug(self, source_slug: str):
        definition = get_source_definition(source_slug)
        source = self._session.scalars(
            select(IntelligenceSource).where(IntelligenceSource.slug == definition.slug).with_for_update()
        ).first()
        if source is None:
            raise OperationalMissingRecordError("The intelligence source was not found.")
        self._verify_registry_source(source, definition.slug)
        return source, definition

    def _lock_source_by_id(self, source_id: int) -> IntelligenceSource:
        source = self._session.scalars(
            select(IntelligenceSource).where(IntelligenceSource.id == source_id).with_for_update()
        ).first()
        if source is None:
            raise OperationalMissingRecordError("The intelligence source was not found.")
        return source

    def _lock_run(self, run_id: int) -> IngestionRun:
        if type(run_id) is not int or run_id <= 0:
            raise OperationalValidationError("A valid run identity is required.")
        run = self._session.scalars(
            select(IngestionRun).where(IngestionRun.id == run_id).with_for_update()
        ).first()
        if run is None:
            raise OperationalMissingRecordError("The ingestion run was not found.")
        return run

    def _source_slug_for_run(self, run_id: int) -> str:
        if type(run_id) is not int or run_id <= 0:
            raise OperationalValidationError("A valid run identity is required.")
        slug = self._session.scalar(
            select(IntelligenceSource.slug)
            .join(IngestionRun, IngestionRun.source_id == IntelligenceSource.id)
            .where(IngestionRun.id == run_id)
        )
        if slug is None:
            raise OperationalMissingRecordError("The ingestion run was not found.")
        definition = get_source_definition(slug)
        return definition.slug

    def _lock_versioned_run(self, run_id: int, expected: int, *, required_status: str) -> IngestionRun:
        run = self._lock_run(run_id)
        self._require_operational_run(run)
        self._require_run_version(run, expected)
        if run.status in _TERMINAL_RUN_STATUSES or run.status != required_status:
            raise OperationalConflictError("The run lifecycle transition is not allowed.")
        self._definition_for_run(run)
        return run

    @staticmethod
    def _require_operational_run(run: IngestionRun) -> None:
        if any(
            value is None
            for value in (run.cycle_id, run.idempotency_key, run.attempt_number, run.state_version)
        ):
            raise OperationalConflictError("A compatibility run cannot be mutated operationally.")

    @staticmethod
    def _require_run_version(run: IngestionRun, expected: int) -> None:
        if type(expected) is not int or expected <= 0:
            raise OperationalValidationError("A positive expected state version is required.")
        if run.state_version != expected:
            raise OperationalStaleStateError("The run state version is stale.")

    @staticmethod
    def _verify_registry_source(source: IntelligenceSource, expected_slug: str) -> None:
        if source.slug != expected_slug:
            raise OperationalConflictError("The source registry identity does not match persistence.")

    def _definition_for_source(self, source: IntelligenceSource):
        try:
            definition = get_source_definition(source.slug)
        except SourceRegistryError as exc:
            raise OperationalConflictError("The persisted source is not registered.") from exc
        self._verify_registry_source(source, definition.slug)
        return definition

    def _definition_for_run(self, run: IngestionRun):
        return self._definition_for_source(self._lock_source_by_id(run.source_id))

    @staticmethod
    def _new_run(*, source, cycle, run_key, attempt_number, retry_of_run_id, trigger_type, now):
        return IngestionRun(
            source_id=source.id,
            cycle_id=cycle.id,
            idempotency_key=run_key,
            attempt_number=attempt_number,
            retry_of_run_id=retry_of_run_id,
            state_version=1,
            defer_reason=None,
            trigger_type=trigger_type,
            status="running",
            started_at=now,
            completed_at=None,
            records_fetched=0,
            records_created=0,
            records_updated=0,
            records_unchanged=0,
            records_skipped=0,
            records_failed=0,
            error_count=0,
            checkpoint_before=None,
            checkpoint_after=None,
            safe_summary=None,
            created_at=now,
        )

    @staticmethod
    def _apply_counters(run: IngestionRun, counters: RunCounters) -> None:
        run.records_fetched = counters.fetched
        run.records_created = counters.created
        run.records_updated = counters.updated
        run.records_unchanged = counters.unchanged
        run.records_skipped = counters.skipped
        run.records_failed = counters.failed
        run.error_count = counters.error_count

    def _append_events(self, run: IngestionRun, occurred_at: datetime, events) -> None:
        last_sequence = self._session.scalar(
            select(func.max(IngestionRunEvent.sequence_number)).where(
                IngestionRunEvent.ingestion_run_id == run.id
            )
        ) or 0
        if last_sequence + len(events) > MAX_EVENT_SEQUENCE:
            raise OperationalConflictError("The run event sequence limit has been reached.")
        for offset, (event_type, from_status, to_status) in enumerate(events, start=1):
            self._session.add(
                IngestionRunEvent(
                    ingestion_run_id=run.id,
                    sequence_number=last_sequence + offset,
                    event_type=event_type,
                    from_status=from_status,
                    to_status=to_status,
                    safe_message=None,
                    occurred_at=occurred_at,
                    created_at=occurred_at,
                )
            )

    def _persistence_committed_time(self, run_id: int) -> datetime:
        committed_before_snapshot = func.pg_visible_in_snapshot(
            literal_column("ingestion_run_events.xmin::text::xid8"),
            func.pg_current_snapshot(),
        )
        rows = self._session.execute(
            select(IngestionRunEvent.occurred_at, committed_before_snapshot).where(
                IngestionRunEvent.ingestion_run_id == run_id,
                IngestionRunEvent.event_type == "persistence_committed",
            )
        ).all()
        if len(rows) != 1 or rows[0][1] is not True:
            raise OperationalConflictError("Committed persistence evidence is unavailable.")
        return _required_utc_timestamp(rows[0][0])

    def _current_checkpoint(self, source_id, scope, partition, name):
        # advance_checkpoint holds the transaction-scoped progress-identity
        # advisory lock before reading this append-only history. A row lock
        # would incorrectly require UPDATE privilege on immutable evidence.
        query = select(SourceCheckpoint).where(
            SourceCheckpoint.source_id == source_id,
            SourceCheckpoint.scope_kind == scope,
            SourceCheckpoint.checkpoint_name == name,
        )
        query = query.where(
            SourceCheckpoint.partition_key.is_(None)
            if partition is None
            else SourceCheckpoint.partition_key == partition
        )
        return self._session.scalars(
            query.order_by(SourceCheckpoint.version.desc()).limit(1)
        ).first()

    def _current_watermark(self, source_id, scope, partition, name):
        # advance_watermark holds the transaction-scoped progress-identity
        # advisory lock before reading this append-only history. A row lock
        # would incorrectly require UPDATE privilege on immutable evidence.
        query = select(SourceWatermark).where(
            SourceWatermark.source_id == source_id,
            SourceWatermark.scope_kind == scope,
            SourceWatermark.watermark_name == name,
        )
        query = query.where(
            SourceWatermark.partition_key.is_(None)
            if partition is None
            else SourceWatermark.partition_key == partition
        )
        return self._session.scalars(
            query.order_by(SourceWatermark.version.desc()).limit(1)
        ).first()

    def _existing_checkpoint_retry(self, run, expected, scope, partition, name, value, previous):
        if run.status not in {"success", "no_change"}:
            return None
        rows = self._session.scalars(
            select(SourceCheckpoint).where(SourceCheckpoint.advanced_by_run_id == run.id)
        ).all()
        if len(rows) == 1:
            row = rows[0]
            if (
                run.state_version == expected + 1
                and row.scope_kind == scope and row.partition_key == partition
                and row.checkpoint_name == name and row.checkpoint_value == value
                and row.version == previous + 1
            ):
                return row
        if len(rows) == 0 and run.status == "no_change" and run.state_version == expected + 1:
            current = self._current_checkpoint(run.source_id, scope, partition, name)
            if (
                current is not None
                and current.version == previous
                and current.checkpoint_value == value
            ):
                return current
        raise OperationalConflictError("The checkpoint retry conflicts with committed evidence.")

    def _existing_watermark_retry(self, run, expected, scope, partition, name, value, previous):
        if run.status not in {"success", "no_change"}:
            return None
        rows = self._session.scalars(
            select(SourceWatermark).where(SourceWatermark.advanced_by_run_id == run.id)
        ).all()
        if len(rows) == 1:
            row = rows[0]
            if (
                run.state_version == expected + 1
                and row.scope_kind == scope and row.partition_key == partition
                and row.watermark_name == name
                and _normalize_db_timestamp(row.watermark_value) == value
                and row.version == previous + 1
            ):
                return row
        if len(rows) == 0 and run.status == "no_change" and run.state_version == expected + 1:
            current = self._current_watermark(run.source_id, scope, partition, name)
            if (
                current is not None
                and current.version == previous
                and _normalize_db_timestamp(current.watermark_value) == value
            ):
                return current
        raise OperationalConflictError("The watermark retry conflicts with committed evidence.")

    def _finalize_progress_run(self, run, expected_version, now):
        outcome = _successful_outcome(
            RunCounters(
                run.records_fetched, run.records_created, run.records_updated,
                run.records_unchanged, run.records_skipped, run.records_failed,
                run.error_count,
            )
        )
        run.status = outcome
        run.completed_at = now
        run.defer_reason = None
        run.state_version = expected_version + 1
        self._append_events(
            run,
            now,
            (
                ("checkpoint_advanced", "checkpoint_pending", outcome),
                ("completed", None, None),
            ),
        )

    def _finalize_unchanged_progress_run(self, run, expected_version, now):
        outcome = _successful_outcome(
            RunCounters(
                run.records_fetched,
                run.records_created,
                run.records_updated,
                run.records_unchanged,
                run.records_skipped,
                run.records_failed,
                run.error_count,
            )
        )
        if outcome != "no_change":
            raise OperationalConflictError(
                "Unchanged progress conflicts with successful processing."
            )
        run.status = "no_change"
        run.completed_at = now
        run.defer_reason = None
        run.state_version = expected_version + 1
        self._append_events(
            run,
            now,
            (("completed", "checkpoint_pending", "no_change"),),
        )


def _utc_timestamp(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, datetime):
        raise OperationalValidationError("A timezone-aware timestamp is required.")
    try:
        offset = value.utcoffset()
    except Exception as exc:
        raise OperationalValidationError("A timezone-aware timestamp is required.") from exc
    if value.tzinfo is None or offset is None:
        raise OperationalValidationError("A timezone-aware timestamp is required.")
    return value.astimezone(UTC)


def _required_utc_timestamp(value: object) -> datetime:
    if not isinstance(value, datetime):
        raise OperationalValidationError("A required timezone-aware timestamp is invalid.")
    try:
        offset = value.utcoffset()
    except Exception as exc:
        raise OperationalValidationError(
            "A required timezone-aware timestamp is invalid."
        ) from exc
    if value.tzinfo is None or offset is None:
        raise OperationalValidationError("A required timezone-aware timestamp is invalid.")
    return value.astimezone(UTC)


def _normalize_db_timestamp(value: datetime | None) -> datetime | None:
    return None if value is None else _utc_timestamp(value)


def _ensure_not_before(value: datetime, lower_bound: datetime) -> None:
    if value < _utc_timestamp(lower_bound):
        raise OperationalValidationError("The operational event time is invalid.")


def _persisted_safe_summary(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 1000:
        raise OperationalValidationError("The persisted safe summary is invalid.")
    normalized = value.strip()
    if (
        _has_control_characters(normalized)
        or _contains_credential_material(normalized)
        or _DIAGNOSTIC_CONTENT.search(normalized) is not None
        or _RAW_SQL.search(normalized) is not None
    ):
        raise OperationalValidationError("The persisted safe summary is invalid.")
    return normalized


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _contains_credential_material(value: str) -> bool:
    return any(
        pattern.search(value) is not None
        for pattern in (
            _CREDENTIAL_URL,
            _AUTHORIZATION_VALUE,
            _SECRET_ASSIGNMENT,
            _PRIVATE_KEY_BLOCK,
        )
    )


def _actor(actor_type: str, actor_ref: str) -> tuple[str, str]:
    if actor_type not in _SAFE_ACTOR_TYPES or not isinstance(actor_ref, str) or _SAFE_ACTOR_REF.fullmatch(actor_ref) is None:
        raise OperationalValidationError("The audit actor identity is invalid.")
    return actor_type, actor_ref


def _safe_name(value: object) -> str:
    if not isinstance(value, str) or _SAFE_NAME.fullmatch(value) is None:
        raise OperationalValidationError("A safe operational name is required.")
    return value


def _defer_reason(value: DeferReason | str | None) -> DeferReason | None:
    if value is None:
        return None
    try:
        return value if isinstance(value, DeferReason) else DeferReason(value)
    except (TypeError, ValueError) as exc:
        raise OperationalValidationError("The defer reason is unsupported.") from exc


def _validate_persistence_counters(counters: RunCounters) -> None:
    if not isinstance(counters, RunCounters):
        raise OperationalValidationError("Reconciled run counters are required.")
    if counters.failed or counters.skipped:
        raise OperationalValidationError("Persistence completion counters contain partial work.")
    _successful_outcome(counters)


def _validate_cycle_outcome(
    *,
    status: str,
    expected: int,
    started: int,
    completed: int,
    successful: int,
    non_successful: int,
) -> None:
    if status == "success":
        if not (
            started == completed == expected
            and successful == completed
            and non_successful == 0
        ):
            raise OperationalValidationError("Successful cycle evidence is incomplete.")
    elif status == "partial":
        if successful < 1 or (non_successful == 0 and completed == expected):
            raise OperationalValidationError("Partial cycle evidence is invalid.")
    elif status == "failed":
        if successful != 0 or (non_successful == 0 and completed == expected):
            raise OperationalValidationError("Failed cycle evidence is invalid.")
    elif status == "cancelled":
        if (
            completed == expected
            and successful == expected
            and non_successful == 0
        ):
            raise OperationalValidationError("Cancelled cycle evidence is invalid.")


def _cycle_counts_from_statuses(statuses: tuple[str, ...]) -> tuple[int, int, int, int]:
    started = len(statuses)
    completed_statuses = [
        status for status in statuses if status in _TERMINAL_RUN_STATUSES
    ]
    completed = len(completed_statuses)
    successful = sum(
        status in {"success", "no_change"} for status in completed_statuses
    )
    return started, completed, successful, completed - successful


def _successful_outcome(counters: RunCounters) -> str:
    if counters.failed or counters.skipped:
        raise OperationalValidationError("Successful completion counters are invalid.")
    if counters.created + counters.updated > 0:
        return "success"
    if counters.created == counters.updated == counters.failed == counters.skipped == 0:
        return "no_change"
    raise OperationalValidationError("Successful completion counters are invalid.")


def _matches_attempt(run, source_id, cycle_id, attempt, prior_id) -> bool:
    return (
        run.source_id == source_id and run.cycle_id == cycle_id
        and run.attempt_number == attempt and run.retry_of_run_id == prior_id
        and run.state_version is not None
    )


def _progress_identity(scope_kind, partition_key, name):
    if scope_kind not in {"source", "partition"}:
        raise OperationalValidationError("The progress scope is unsupported.")
    safe_name = _safe_name(name)
    if scope_kind == "source":
        if partition_key is not None:
            raise OperationalValidationError("The source progress identity is invalid.")
        return scope_kind, None, safe_name
    if not isinstance(partition_key, str) or not partition_key.strip() or len(partition_key) > 160:
        raise OperationalValidationError("The partition progress identity is invalid.")
    partition = partition_key.strip()
    if any(ord(character) < 32 or ord(character) == 127 for character in partition):
        raise OperationalValidationError("The partition progress identity is invalid.")
    return scope_kind, partition, safe_name


def _checkpoint_value(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 500:
        raise OperationalValidationError("The checkpoint value is invalid.")
    if _has_control_characters(value) or _contains_credential_material(value):
        raise OperationalValidationError("The checkpoint value is invalid.")
    return value


def _expected_previous_version(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 9_223_372_036_854_775_806:
        raise OperationalValidationError("The expected progress version is invalid.")
    return value


def _verify_previous(current, expected: int) -> None:
    actual = 0 if current is None else current.version
    if actual != expected:
        raise OperationalStaleStateError("The progress version is stale.")


def _nullable_count(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= MAX_COUNTER:
        raise OperationalValidationError("A normalized rate-state count is invalid.")
    return value


__all__ = [
    "DeferReason",
    "OperationalConflictError",
    "OperationalLockUnavailableError",
    "OperationalMissingRecordError",
    "OperationalPersistenceError",
    "OperationalPersistenceFailure",
    "OperationalPersistenceService",
    "OperationalStaleStateError",
    "OperationalValidationError",
    "RunCounters",
]
