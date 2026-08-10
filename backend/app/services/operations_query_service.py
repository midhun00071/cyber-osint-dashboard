"""Bounded allow-listed read models for sources and ingestion operations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
from typing import Iterable
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.source_registry import (
    ImplementationStatus,
    ProgressContract,
    SourceRegistryError,
    get_source_definition,
)
from app.models import (
    IngestionCycle,
    IngestionError,
    IngestionRun,
    IngestionRunEvent,
    IntelligenceSource,
    SourceCheckpoint,
    SourceCredentialReference,
    SourceRateLimitState,
    SourceWatermark,
)
from app.orchestration.flows import DEFAULT_SOURCE_HANDLERS
from app.security.contracts import Permission


ACTIVE_RUN_STATUSES = frozenset({"running", "checkpoint_pending"})
HISTORY_STATUSES = frozenset(
    {
        "running", "checkpoint_pending", "success", "no_change", "skipped",
        "deferred_quota", "approval_pending", "disabled",
        "credentials_missing", "licence_required", "rate_limited", "partial",
        "failed", "cancelled", "succeeded", "canceled",
    }
)
TRIGGER_TYPES = frozenset({"scheduled", "manual", "retry"})
CYCLE_STATUSES = frozenset({"running", "success", "partial", "failed", "cancelled"})
CYCLE_TRIGGERS = frozenset({"scheduled", "manual", "legacy_import"})
MAX_DERIVED_SOURCE_SCAN = 500
SOURCE_EFFECTIVE_STATES = frozenset(
    {
        "not_implemented", "policy_disabled", "disabled", "paused",
        "licence_required", "credentials_required", "quota_unavailable",
        "rate_limited", "active", "eligible",
    }
)


class OperationsQueryError(RuntimeError):
    pass


class OperationsQueryInputError(ValueError):
    pass


class OperationsNotFoundError(LookupError):
    pass


class OperationsQueryService:
    def __init__(
        self,
        session: Session,
        *,
        execution_slugs: Iterable[str] | None = None,
    ) -> None:
        self._session = session
        self._execution_slugs = frozenset(
            DEFAULT_SOURCE_HANDLERS if execution_slugs is None else execution_slugs
        )

    def list_sources(
        self,
        *,
        permissions: frozenset[Permission],
        limit: int,
        offset: int,
        operator_state: str | None = None,
        effective_state: str | None = None,
    ) -> tuple[list[dict[str, object]], int]:
        _page(limit, offset, maximum=100)
        if operator_state is not None and operator_state not in {"enabled", "paused", "disabled"}:
            raise OperationsQueryInputError("Invalid source query.")
        if effective_state is not None and effective_state not in SOURCE_EFFECTIVE_STATES:
            raise OperationsQueryInputError("Invalid source query.")
        query = select(IntelligenceSource)
        count_query = select(func.count(IntelligenceSource.id))
        if operator_state is not None:
            query = query.where(IntelligenceSource.operator_state == operator_state)
            count_query = count_query.where(IntelligenceSource.operator_state == operator_state)
        try:
            inventory_count = int(self._session.scalar(count_query) or 0)
            ordered = query.order_by(IntelligenceSource.slug)
            if effective_state is None:
                rows = self._session.scalars(
                    ordered.offset(offset).limit(limit)
                ).all()
                return [self._source_record(row, permissions) for row in rows], inventory_count
            if inventory_count > MAX_DERIVED_SOURCE_SCAN:
                raise OperationsQueryError(
                    "Source operations exceed the bounded derived-state inventory limit."
                )
            rows = self._session.scalars(
                ordered.limit(MAX_DERIVED_SOURCE_SCAN)
            ).all()
            items = [self._source_record(row, permissions) for row in rows]
        except (SQLAlchemyError, SourceRegistryError):
            raise OperationsQueryError("Source operations could not be loaded.") from None
        items = [item for item in items if item["effective_state"] == effective_state]
        total = len(items)
        return items[offset : offset + limit], total

    def get_source(
        self,
        source_slug: str,
        *,
        permissions: frozenset[Permission],
    ) -> dict[str, object]:
        try:
            row = self._session.scalar(
                select(IntelligenceSource).where(IntelligenceSource.slug == source_slug)
            )
            if row is None:
                raise OperationsNotFoundError("Source not found.")
            return self._source_record(row, permissions)
        except OperationsNotFoundError:
            raise
        except (SQLAlchemyError, SourceRegistryError):
            raise OperationsQueryError("Source operations could not be loaded.") from None

    def operations_summary(self) -> dict[str, object]:
        try:
            active_cycles = self._session.scalar(
                select(func.count(IngestionCycle.id)).where(IngestionCycle.status == "running")
            ) or 0
            active_runs = self._session.scalar(
                select(func.count(IngestionRun.id)).where(IngestionRun.status.in_(ACTIVE_RUN_STATUSES))
            ) or 0
            status_rows = self._session.execute(
                select(IngestionRun.status, func.count(IngestionRun.id)).group_by(IngestionRun.status)
            ).all()
            attention = self._session.scalar(
                select(func.count(IntelligenceSource.id)).where(
                    IntelligenceSource.operator_state != "enabled"
                )
            ) or 0
            latest = self._session.scalars(
                select(IngestionCycle).order_by(IngestionCycle.started_at.desc(), IngestionCycle.id.desc()).limit(1)
            ).first()
        except SQLAlchemyError:
            raise OperationsQueryError("Operational summary could not be loaded.") from None
        return {
            "generated_at": datetime.now(UTC),
            "deployment_state": "available" if self._execution_slugs else "inactive",
            "configured_handler_count": len(self._execution_slugs),
            "active_cycle_count": int(active_cycles),
            "active_run_count": int(active_runs),
            "source_attention_count": int(attention),
            "run_counts_by_status": {status: int(count) for status, count in status_rows},
            "latest_cycle": None if latest is None else self._cycle_record(latest),
        }

    def list_cycles(
        self,
        *,
        limit: int,
        offset: int,
        status: str | None,
        trigger_type: str | None,
        occurred_from: datetime | None,
        occurred_to: datetime | None,
    ) -> tuple[list[dict[str, object]], int]:
        _page(limit, offset, maximum=100)
        _history_filters(status, CYCLE_STATUSES, trigger_type, CYCLE_TRIGGERS, occurred_from, occurred_to)
        query = select(IngestionCycle)
        count_query = select(func.count(IngestionCycle.id))
        conditions = []
        if status is not None:
            conditions.append(IngestionCycle.status == status)
        if trigger_type is not None:
            conditions.append(IngestionCycle.trigger_type == trigger_type)
        if occurred_from is not None:
            conditions.append(IngestionCycle.started_at >= occurred_from)
        if occurred_to is not None:
            conditions.append(IngestionCycle.started_at < occurred_to)
        try:
            rows = self._session.scalars(
                query.where(*conditions).order_by(IngestionCycle.started_at.desc(), IngestionCycle.id.desc()).offset(offset).limit(limit)
            ).all()
            total = self._session.scalar(count_query.where(*conditions)) or 0
        except SQLAlchemyError:
            raise OperationsQueryError("Cycle history could not be loaded.") from None
        return [self._cycle_record(row) for row in rows], int(total)

    def list_runs(
        self,
        *,
        limit: int,
        offset: int,
        source_slug: str | None,
        status: str | None,
        trigger_type: str | None,
        retryable: bool | None,
        occurred_from: datetime | None,
        occurred_to: datetime | None,
    ) -> tuple[list[dict[str, object]], int]:
        _page(limit, offset, maximum=100)
        _history_filters(status, HISTORY_STATUSES, trigger_type, TRIGGER_TYPES, occurred_from, occurred_to)
        conditions = []
        if source_slug is not None:
            conditions.append(IntelligenceSource.slug == source_slug)
        if status is not None:
            conditions.append(IngestionRun.status == status)
        if trigger_type is not None:
            conditions.append(IngestionRun.trigger_type == trigger_type)
        if occurred_from is not None:
            conditions.append(IngestionRun.started_at >= occurred_from)
        if occurred_to is not None:
            conditions.append(IngestionRun.started_at < occurred_to)
        retryable_exists = select(IngestionError.id).where(
            IngestionError.ingestion_run_id == IngestionRun.id,
            IngestionError.retryable.is_(True),
        ).exists()
        if retryable is not None:
            conditions.append(retryable_exists if retryable else ~retryable_exists)
        base = select(IngestionRun, IntelligenceSource).join(
            IntelligenceSource, IntelligenceSource.id == IngestionRun.source_id
        ).where(*conditions)
        count_query = select(func.count(IngestionRun.id)).join(
            IntelligenceSource, IntelligenceSource.id == IngestionRun.source_id
        ).where(*conditions)
        try:
            rows = self._session.execute(
                base.order_by(IngestionRun.started_at.desc(), IngestionRun.id.desc()).offset(offset).limit(limit)
            ).all()
            total = self._session.scalar(count_query) or 0
            items = [self._run_record(run, source) for run, source in rows]
        except SQLAlchemyError:
            raise OperationsQueryError("Run history could not be loaded.") from None
        return items, int(total)

    def get_run(self, public_id: UUID) -> dict[str, object]:
        try:
            row = self._session.execute(
                select(IngestionRun, IntelligenceSource)
                .join(IntelligenceSource, IntelligenceSource.id == IngestionRun.source_id)
                .where(IngestionRun.public_id == public_id)
            ).one_or_none()
            if row is None:
                raise OperationsNotFoundError("Run not found.")
            return self._run_record(row[0], row[1])
        except OperationsNotFoundError:
            raise
        except SQLAlchemyError:
            raise OperationsQueryError("Run history could not be loaded.") from None

    def list_run_events(
        self, public_id: UUID, *, limit: int, offset: int
    ) -> tuple[list[dict[str, object]], int]:
        _page(limit, offset, maximum=500)
        try:
            run_id = self._session.scalar(
                select(IngestionRun.id).where(IngestionRun.public_id == public_id)
            )
            if run_id is None:
                raise OperationsNotFoundError("Run not found.")
            rows = self._session.scalars(
                select(IngestionRunEvent)
                .where(IngestionRunEvent.ingestion_run_id == run_id)
                .order_by(IngestionRunEvent.sequence_number)
                .offset(offset).limit(limit)
            ).all()
            total = self._session.scalar(
                select(func.count(IngestionRunEvent.id)).where(IngestionRunEvent.ingestion_run_id == run_id)
            ) or 0
        except OperationsNotFoundError:
            raise
        except SQLAlchemyError:
            raise OperationsQueryError("Run events could not be loaded.") from None
        return [
            {
                "sequence": row.sequence_number,
                "event_type": row.event_type,
                "from_status": row.from_status,
                "to_status": row.to_status,
                "message": row.safe_message,
                "occurred_at": row.occurred_at,
            }
            for row in rows
        ], int(total)

    def _source_record(
        self, source: IntelligenceSource, permissions: frozenset[Permission]
    ) -> dict[str, object]:
        definition = get_source_definition(source.slug)
        configured = self._credential_configured(source.id, definition.authentication_required)
        rate = self._session.scalars(
            select(SourceRateLimitState).where(SourceRateLimitState.source_id == source.id)
            .order_by(SourceRateLimitState.updated_at.desc(), SourceRateLimitState.id.desc()).limit(1)
        ).first()
        active = bool(self._session.scalar(
            select(IngestionRun.id).where(
                IngestionRun.source_id == source.id,
                IngestionRun.status.in_(ACTIVE_RUN_STATUSES),
            ).limit(1)
        ))
        execution_available = source.slug in self._execution_slugs
        effective = _effective_state(source, definition, configured, rate, active)
        latest_run = self._session.scalars(
            select(IngestionRun).where(IngestionRun.source_id == source.id)
            .order_by(IngestionRun.started_at.desc(), IngestionRun.id.desc()).limit(1)
        ).first()
        return {
            "public_id": source.public_id,
            "slug": source.slug,
            "name": definition.display_name,
            "source_type": source.source_type,
            "content_type": definition.content_family.value,
            "access_class": definition.access_method.value,
            "policy_state": _policy_state(definition, configured),
            "operator_state": source.operator_state,
            "effective_state": effective,
            "credential_required": definition.authentication_required,
            "credential_configured": configured,
            "execution_available": execution_available,
            "freshness": _freshness(source, definition),
            "progress": self._progress(source, definition.progress_contract),
            "latest_run": None if latest_run is None else {
                "public_id": latest_run.public_id,
                "status": latest_run.status,
                "trigger_type": latest_run.trigger_type,
                "attempt_number": latest_run.attempt_number or 0,
                "started_at": latest_run.started_at,
                "finished_at": latest_run.completed_at,
            },
            "quota_state": None if rate is None else rate.state,
            "backoff_until": None if rate is None else rate.backoff_until,
            "next_scheduled_at": None,
            "available_actions": _available_actions(source, definition, permissions, execution_available, active),
        }

    def _credential_configured(self, source_id: int, required: bool) -> bool:
        if not required:
            return True
        return bool(self._session.scalar(
            select(SourceCredentialReference.id).where(
                SourceCredentialReference.source_id == source_id,
                SourceCredentialReference.configuration_state.in_({"configured", "rotation_due"}),
                SourceCredentialReference.external_reference_id.is_not(None),
            ).limit(1)
        ))

    def _progress(self, source: IntelligenceSource, contract: ProgressContract) -> dict[str, object]:
        if contract is ProgressContract.NONE:
            return {"kind": "none", "version": None, "committed_at": None, "fingerprint": None}
        if contract is ProgressContract.CHECKPOINT:
            row = self._session.scalars(
                select(SourceCheckpoint).where(SourceCheckpoint.source_id == source.id)
                .order_by(SourceCheckpoint.committed_at.desc(), SourceCheckpoint.id.desc()).limit(1)
            ).first()
            kind = "checkpoint"
        else:
            row = self._session.scalars(
                select(SourceWatermark).where(SourceWatermark.source_id == source.id)
                .order_by(SourceWatermark.committed_at.desc(), SourceWatermark.id.desc()).limit(1)
            ).first()
            kind = "watermark"
        if row is None:
            return {"kind": kind, "version": None, "committed_at": None, "fingerprint": None}
        material = f"{source.public_id}|{kind}|{row.version}|{row.committed_at.isoformat()}"
        return {
            "kind": kind,
            "version": row.version,
            "committed_at": row.committed_at,
            "fingerprint": hashlib.sha256(material.encode("utf-8")).hexdigest(),
        }

    def _run_record(self, run: IngestionRun, source: IntelligenceSource) -> dict[str, object]:
        cycle_public_id = None
        if run.cycle_id is not None:
            cycle = self._session.get(IngestionCycle, run.cycle_id)
            if cycle is None:
                raise OperationsQueryError("Run cycle evidence is unavailable.")
            cycle_public_id = cycle.public_id
        prior_public_id = None
        if run.retry_of_run_id is not None:
            prior_public_id = self._session.scalar(
                select(IngestionRun.public_id).where(IngestionRun.id == run.retry_of_run_id)
            )
        retryable = bool(self._session.scalar(
            select(IngestionError.id).where(
                IngestionError.ingestion_run_id == run.id,
                IngestionError.retryable.is_(True),
            ).limit(1)
        ))
        return {
            "public_id": run.public_id,
            "cycle_public_id": cycle_public_id,
            "source_public_id": source.public_id,
            "source_slug": source.slug,
            "source_name": source.name,
            "trigger_type": run.trigger_type,
            "status": run.status,
            "attempt_number": run.attempt_number or 0,
            "retry_of_public_id": prior_public_id,
            "accepted_at": run.created_at,
            "started_at": run.started_at,
            "finished_at": run.completed_at,
            "duration_seconds": _duration(run.started_at, run.completed_at),
            "retryable": retryable,
            "summary_message": run.safe_summary,
            "counters": {
                "fetched": run.records_fetched,
                "created": run.records_created,
                "updated": run.records_updated,
                "unchanged": run.records_unchanged,
                "skipped": run.records_skipped,
                "failed": run.records_failed,
                "error_count": run.error_count,
            },
        }

    @staticmethod
    def _cycle_record(cycle: IngestionCycle) -> dict[str, object]:
        return {
            "public_id": cycle.public_id,
            "trigger_type": cycle.trigger_type,
            "status": cycle.status,
            "started_at": cycle.started_at,
            "finished_at": cycle.completed_at,
            "duration_seconds": _duration(cycle.started_at, cycle.completed_at),
            "sources_expected": cycle.sources_expected,
            "sources_started": cycle.sources_started,
            "sources_completed": cycle.sources_completed,
            "sources_successful": cycle.sources_successful,
            "sources_non_successful": cycle.sources_non_successful,
            "summary_message": cycle.safe_summary,
        }


def _page(limit: int, offset: int, *, maximum: int) -> None:
    if type(limit) is not int or not 1 <= limit <= maximum or type(offset) is not int or not 0 <= offset <= 100000:
        raise OperationsQueryInputError("Invalid operations query.")


def _history_filters(status, statuses, trigger, triggers, lower, upper) -> None:
    if status is not None and status not in statuses:
        raise OperationsQueryInputError("Invalid operations query.")
    if trigger is not None and trigger not in triggers:
        raise OperationsQueryInputError("Invalid operations query.")
    if lower is not None and (lower.tzinfo is None or lower.utcoffset() is None):
        raise OperationsQueryInputError("Invalid operations query.")
    if upper is not None and (upper.tzinfo is None or upper.utcoffset() is None):
        raise OperationsQueryInputError("Invalid operations query.")
    if lower is not None and upper is not None and (upper <= lower or upper - lower > timedelta(days=90)):
        raise OperationsQueryInputError("Invalid operations query.")


def _policy_state(definition, credential_configured: bool) -> str:
    if definition.implementation_status is not ImplementationStatus.IMPLEMENTED:
        return "not_implemented"
    if not definition.enabled:
        return "policy_disabled"
    if definition.authentication_required and not credential_configured:
        return "credentials_required"
    return "implemented_enabled"


def _effective_state(source, definition, credential_configured, rate, active: bool) -> str:
    if definition.implementation_status is not ImplementationStatus.IMPLEMENTED:
        return "not_implemented"
    if not definition.enabled:
        return "policy_disabled"
    if source.operator_state == "disabled":
        return "disabled"
    if source.operator_state == "paused":
        return "paused"
    if definition.authentication_required and not credential_configured:
        return "credentials_required"
    if rate is not None and rate.state == "quota_unavailable":
        return "quota_unavailable"
    now = datetime.now(UTC)
    if rate is not None and (rate.state in {"limited", "backoff"}) and (
        rate.backoff_until is None or _aware(rate.backoff_until) > now
    ):
        return "rate_limited"
    if active:
        return "active"
    return "eligible"


def _available_actions(source, definition, permissions, execution_available, active) -> list[str]:
    actions: list[str] = []
    policy_enabled = definition.enabled and definition.implementation_status is ImplementationStatus.IMPLEMENTED
    if Permission.INGESTION_PAUSE in permissions and not active:
        if source.operator_state == "enabled":
            actions.extend(["pause", "disable"])
        elif source.operator_state == "paused":
            actions.extend(["resume", "disable"])
    if Permission.SOURCE_MANAGE in permissions and not active and policy_enabled and source.operator_state == "disabled":
        actions.append("enable")
    if Permission.INGESTION_RUN in permissions and policy_enabled and source.operator_state == "enabled" and execution_available and not active:
        actions.append("manual_run")
    return actions


def _freshness(source, definition) -> str:
    if not definition.enabled or definition.implementation_status is not ImplementationStatus.IMPLEMENTED:
        return "not_applicable"
    if source.last_successful_fetch_at is None:
        return "never"
    return "fresh" if datetime.now(UTC) - _aware(source.last_successful_fetch_at) <= timedelta(hours=4) else "stale"


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _duration(started: datetime, finished: datetime | None) -> float | None:
    if finished is None:
        return None
    return max(0.0, (_aware(finished) - _aware(started)).total_seconds())


__all__ = [
    "CYCLE_STATUSES", "CYCLE_TRIGGERS", "HISTORY_STATUSES", "TRIGGER_TYPES",
    "OperationsNotFoundError", "OperationsQueryError", "OperationsQueryInputError",
    "OperationsQueryService",
]
