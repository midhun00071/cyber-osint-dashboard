"""Bounded, non-mutating retention planning for operational database evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import exists, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import (
    AuditEvent,
    IngestionCycle,
    IngestionError,
    IngestionRun,
    IngestionRunEvent,
    IngestionRunRecord,
    QuarantinedRecord,
    SourceCheckpoint,
    SourceWatermark,
)


MAX_RETENTION_PLAN_RESULTS = 1000
_KNOWN_RUN_STATUSES = frozenset(
    {
        "running",
        "checkpoint_pending",
        "success",
        "no_change",
        "skipped",
        "deferred_quota",
        "approval_pending",
        "disabled",
        "credentials_missing",
        "licence_required",
        "rate_limited",
        "partial",
        "failed",
        "cancelled",
        "succeeded",
        "canceled",
    }
)
_KNOWN_CYCLE_STATUSES = frozenset(
    {"running", "success", "partial", "failed", "cancelled"}
)


class RetentionPlanningError(RuntimeError):
    """Fixed, non-diagnostic failure at the public planning boundary."""


@dataclass(frozen=True, slots=True)
class RetentionPlanRecord:
    """One safely identified record and the reasons it cannot be deleted."""

    identifier: str
    category: str
    disposition: str
    protection_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RetentionPlan:
    """Bounded dry-run output; it is never an execution or deletion result."""

    policy_state: str
    cutoff_utc: datetime
    result_limit: int
    returned_count: int
    protected_count: int
    candidate_count: int
    truncated: bool
    records: tuple[RetentionPlanRecord, ...]


class DatabaseRetentionService:
    """Read only operational evidence and produce a deny-by-default plan."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def plan(self, *, cutoff: datetime, limit: int) -> RetentionPlan:
        """Return a bounded approval-required plan without mutating any row."""

        normalized_cutoff = self._validated_cutoff(cutoff)
        validated_limit = self._validated_limit(limit)
        try:
            records = self._collect_records(normalized_cutoff, validated_limit)
        except SQLAlchemyError:
            raise RetentionPlanningError(
                "Retention planning could not be completed safely."
            ) from None

        ordered = sorted(
            records,
            key=lambda record: (record.category, record.identifier),
        )
        truncated = len(ordered) > validated_limit
        bounded = tuple(ordered[:validated_limit])
        return RetentionPlan(
            policy_state="approval_required",
            cutoff_utc=normalized_cutoff,
            result_limit=validated_limit,
            returned_count=len(bounded),
            protected_count=len(bounded),
            candidate_count=0,
            truncated=truncated,
            records=bounded,
        )

    @staticmethod
    def _validated_cutoff(cutoff: datetime) -> datetime:
        if not isinstance(cutoff, datetime) or cutoff.tzinfo is None:
            raise ValueError("A timezone-aware retention cutoff is required.")
        if cutoff.utcoffset() is None:
            raise ValueError("A timezone-aware retention cutoff is required.")
        return cutoff.astimezone(UTC)

    @staticmethod
    def _validated_limit(limit: int) -> int:
        if type(limit) is not int or not 1 <= limit <= MAX_RETENTION_PLAN_RESULTS:
            raise ValueError(
                f"The retention result limit must be an integer from 1 to "
                f"{MAX_RETENTION_PLAN_RESULTS}."
            )
        return limit

    def _collect_records(
        self,
        cutoff: datetime,
        limit: int,
    ) -> list[RetentionPlanRecord]:
        records: list[RetentionPlanRecord] = []
        query_limit = limit + 1

        parent_run = IngestionRun.__table__.alias("retention_parent_run")
        run_rows = self._session.execute(
            select(
                parent_run.c.public_id,
                parent_run.c.status,
                parent_run.c.retry_of_run_id,
                exists(
                    select(IngestionRun.id).where(
                        IngestionRun.retry_of_run_id == parent_run.c.id
                    )
                ).label("has_retry_child"),
                exists(
                    select(SourceCheckpoint.id).where(
                        SourceCheckpoint.advanced_by_run_id == parent_run.c.id
                    )
                ).label("has_checkpoint"),
                exists(
                    select(SourceWatermark.id).where(
                        SourceWatermark.advanced_by_run_id == parent_run.c.id
                    )
                ).label("has_watermark"),
                exists(
                    select(QuarantinedRecord.id).where(
                        QuarantinedRecord.ingestion_run_id == parent_run.c.id,
                        QuarantinedRecord.status == "pending",
                    )
                ).label("has_unresolved_quarantine"),
            )
            .select_from(parent_run)
            .where(parent_run.c.started_at < cutoff)
            .order_by(parent_run.c.started_at.asc(), parent_run.c.id.asc())
            .limit(query_limit)
        ).mappings()
        for row in run_rows:
            reasons = ["retention_policy_approval_required"]
            status = row["status"]
            if status == "running":
                reasons.extend(
                    ("running_ingestion_evidence", "active_lifecycle_state")
                )
            elif status == "checkpoint_pending":
                reasons.extend(
                    (
                        "pending_ingestion_evidence",
                        "checkpoint_pending_evidence",
                        "active_lifecycle_state",
                    )
                )
            elif status not in _KNOWN_RUN_STATUSES:
                reasons.append("unknown_or_inconsistent_state")
            if row["retry_of_run_id"] is not None or row["has_retry_child"]:
                reasons.append("retry_linked_evidence")
            if row["has_checkpoint"]:
                reasons.append("checkpoint_linked_evidence")
            if row["has_watermark"]:
                reasons.append("watermark_linked_evidence")
            if row["has_unresolved_quarantine"]:
                reasons.append("unresolved_quarantine_evidence")
            records.append(
                self._protected_record(
                    "ingestion_run",
                    str(row["public_id"]),
                    reasons,
                )
            )

        cycle_rows = self._session.execute(
            select(
                IngestionCycle.public_id,
                IngestionCycle.status,
            )
            .where(IngestionCycle.started_at < cutoff)
            .order_by(IngestionCycle.started_at.asc(), IngestionCycle.id.asc())
            .limit(query_limit)
        )
        for public_id, status in cycle_rows:
            reasons = ["retention_policy_approval_required"]
            if status == "running":
                reasons.extend(
                    ("pending_ingestion_evidence", "active_lifecycle_state")
                )
            elif status not in _KNOWN_CYCLE_STATUSES:
                reasons.append("unknown_or_inconsistent_state")
            records.append(
                self._protected_record("ingestion_cycle", str(public_id), reasons)
            )

        records.extend(
            self._simple_records(
                category="ingestion_run_event",
                identifier_column=IngestionRunEvent.id,
                timestamp_column=IngestionRunEvent.occurred_at,
                cutoff=cutoff,
                limit=query_limit,
                reason="append_only_run_event_evidence",
            )
        )
        records.extend(
            self._simple_records(
                category="audit_event",
                identifier_column=AuditEvent.public_id,
                timestamp_column=AuditEvent.occurred_at,
                cutoff=cutoff,
                limit=query_limit,
                reason="append_only_audit_evidence",
            )
        )
        records.extend(
            self._simple_records(
                category="source_checkpoint",
                identifier_column=SourceCheckpoint.id,
                timestamp_column=SourceCheckpoint.committed_at,
                cutoff=cutoff,
                limit=query_limit,
                reason="checkpoint_linked_evidence",
            )
        )
        records.extend(
            self._simple_records(
                category="source_watermark",
                identifier_column=SourceWatermark.id,
                timestamp_column=SourceWatermark.committed_at,
                cutoff=cutoff,
                limit=query_limit,
                reason="watermark_linked_evidence",
            )
        )
        records.extend(
            self._simple_records(
                category="ingestion_error",
                identifier_column=IngestionError.id,
                timestamp_column=IngestionError.occurred_at,
                cutoff=cutoff,
                limit=query_limit,
                reason="append_only_ingestion_error_evidence",
            )
        )
        records.extend(
            self._simple_records(
                category="ingestion_run_record",
                identifier_column=IngestionRunRecord.id,
                timestamp_column=IngestionRunRecord.processed_at,
                cutoff=cutoff,
                limit=query_limit,
                reason="run_record_evidence",
            )
        )

        quarantine_rows = self._session.execute(
            select(QuarantinedRecord.public_id, QuarantinedRecord.status)
            .where(QuarantinedRecord.quarantined_at < cutoff)
            .order_by(
                QuarantinedRecord.quarantined_at.asc(),
                QuarantinedRecord.id.asc(),
            )
            .limit(query_limit)
        )
        for public_id, status in quarantine_rows:
            reasons = ["retention_policy_approval_required"]
            if status == "pending":
                reasons.append("unresolved_quarantine_evidence")
            elif status not in {"reviewed", "released", "discarded"}:
                reasons.append("unknown_or_inconsistent_state")
            records.append(
                self._protected_record("quarantined_record", str(public_id), reasons)
            )

        return records

    def _simple_records(
        self,
        *,
        category: str,
        identifier_column,
        timestamp_column,
        cutoff: datetime,
        limit: int,
        reason: str,
    ) -> list[RetentionPlanRecord]:
        rows = self._session.execute(
            select(identifier_column)
            .where(timestamp_column < cutoff)
            .order_by(timestamp_column.asc(), identifier_column.asc())
            .limit(limit)
        ).scalars()
        return [
            self._protected_record(
                category,
                str(identifier),
                ("retention_policy_approval_required", reason),
            )
            for identifier in rows
        ]

    @staticmethod
    def _protected_record(
        category: str,
        identifier: str,
        reasons,
    ) -> RetentionPlanRecord:
        return RetentionPlanRecord(
            identifier=f"{category}:{identifier}",
            category=category,
            disposition="protected",
            protection_reasons=tuple(sorted(set(reasons))),
        )
