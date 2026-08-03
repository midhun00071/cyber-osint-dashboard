"""Transaction-owning persistence adapter for source-neutral flow code."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import get_session_factory
from app.ingestion.services.operational_persistence_service import (
    DeferReason,
    OperationalConflictError,
    OperationalPersistenceService,
    RunCounters,
)
from app.models.ingestion_cycle import IngestionCycle
from app.models.ingestion_run import IngestionRun
from app.models.intelligence_source import IntelligenceSource
from app.models.source_checkpoint import SourceCheckpoint
from app.models.source_rate_limit_state import SourceRateLimitState
from app.models.source_watermark import SourceWatermark
from app.orchestration.contracts import (
    ContractValidationError,
    CycleEvidence,
    CycleHandle,
    CycleResult,
    ProgressProposal,
    ProgressSnapshot,
    ProgressStorage,
    QuotaObservation,
    RateState,
    ReconciledCounters,
    ResultStatus,
    RunHandle,
    SourceAttemptIdentity,
    SourceExecutionResult,
    SourcePolicy,
)


DEPLOYMENT_REFERENCE = "alpha-data-ingestion-cycle"
_NON_REQUEST_DEFER = {
    ResultStatus.SKIPPED: None,
    ResultStatus.DEFERRED_QUOTA: DeferReason.QUOTA,
    ResultStatus.APPROVAL_PENDING: DeferReason.APPROVAL,
    ResultStatus.DISABLED: DeferReason.SOURCE_DISABLED,
    ResultStatus.CREDENTIALS_MISSING: DeferReason.CREDENTIALS,
    ResultStatus.LICENCE_REQUIRED: DeferReason.LICENCE,
    ResultStatus.RATE_LIMITED: DeferReason.RATE_LIMIT,
}


class OrchestrationPersistenceAdapter:
    """Own short transactions while delegating mutations to the B1-04 service."""

    def __init__(
        self,
        session_factory: Callable[[], Session] | sessionmaker[Session] | None = None,
    ) -> None:
        self._session_factory = session_factory or get_session_factory()

    def acquire_scheduled_cycle(
        self,
        scheduled_for: datetime,
        sources_expected: int,
    ) -> CycleHandle:
        with self._session_factory() as session, session.begin():
            row = OperationalPersistenceService(session).acquire_cycle(
                trigger_type="scheduled",
                scheduled_for=scheduled_for,
                deployment_ref=DEPLOYMENT_REFERENCE,
                sources_expected=sources_expected,
                safe_summary="Scheduled parent cycle acquired.",
            )
            return CycleHandle(
                cycle_id=row.id,
                idempotency_key=row.idempotency_key,
                scheduled_for=row.scheduled_for,
            )

    def acquire_source_run(self, cycle_id: int, source_slug: str) -> RunHandle:
        with self._session_factory() as session, session.begin():
            row = OperationalPersistenceService(session).acquire_source_run(
                cycle_id=cycle_id,
                source_slug=source_slug,
            )
            return _run_handle(row, source_slug)

    def acquire_retry(self, prior_run_id: int) -> RunHandle:
        with self._session_factory() as session, session.begin():
            service = OperationalPersistenceService(session)
            row = service.acquire_retry(prior_run_id=prior_run_id)
            source_slug = session.scalar(
                select(IntelligenceSource.slug).where(
                    IntelligenceSource.id == row.source_id
                )
            )
            if source_slug is None:
                raise OperationalConflictError("The retry source identity is unavailable.")
            return _run_handle(row, source_slug)

    def read_progress(self, policy: SourcePolicy) -> ProgressSnapshot | None:
        if policy.progress_storage is ProgressStorage.NONE:
            return None
        with self._session_factory() as session, session.begin():
            source_id = session.scalar(
                select(IntelligenceSource.id).where(
                    IntelligenceSource.slug == policy.source_slug,
                    IntelligenceSource.is_enabled.is_(True),
                )
            )
            if source_id is None:
                raise OperationalConflictError("The progress source is unavailable.")
            assert policy.progress_kind is not None
            name = policy.progress_kind.value
            if policy.progress_storage is ProgressStorage.CHECKPOINT:
                row = session.scalars(
                    select(SourceCheckpoint)
                    .where(
                        SourceCheckpoint.source_id == source_id,
                        SourceCheckpoint.scope_kind == "source",
                        SourceCheckpoint.partition_key.is_(None),
                        SourceCheckpoint.checkpoint_name == name,
                    )
                    .order_by(SourceCheckpoint.version.desc())
                    .limit(1)
                ).first()
                if row is None:
                    return None
                return ProgressSnapshot(
                    storage=ProgressStorage.CHECKPOINT,
                    kind=policy.progress_kind,
                    name=name,
                    value=row.checkpoint_value,
                    version=row.version,
                )
            row = session.scalars(
                select(SourceWatermark)
                .where(
                    SourceWatermark.source_id == source_id,
                    SourceWatermark.scope_kind == "source",
                    SourceWatermark.partition_key.is_(None),
                    SourceWatermark.watermark_name == name,
                )
                .order_by(SourceWatermark.version.desc())
                .limit(1)
            ).first()
            if row is None:
                return None
            return ProgressSnapshot(
                storage=ProgressStorage.WATERMARK,
                kind=policy.progress_kind,
                name=name,
                value=row.watermark_value,
                version=row.version,
            )

    def read_quota(self, policy: SourcePolicy) -> QuotaObservation:
        with self._session_factory() as session, session.begin():
            row = session.scalars(
                select(SourceRateLimitState)
                .join(
                    IntelligenceSource,
                    IntelligenceSource.id == SourceRateLimitState.source_id,
                )
                .where(
                    IntelligenceSource.slug == policy.source_slug,
                    SourceRateLimitState.policy_key == policy.quota_policy_key,
                )
            ).first()
            if row is None:
                return QuotaObservation(policy_key=policy.quota_policy_key)
            return QuotaObservation(
                policy_key=policy.quota_policy_key,
                state=RateState(row.state),
                state_version=row.state_version,
                remaining=row.remaining,
                backoff_until=row.backoff_until,
            )

    def record_result(
        self,
        run: RunHandle,
        result: SourceExecutionResult,
    ) -> RunHandle:
        if run.identity.source_slug != result.source_slug or run.status != "running":
            raise ContractValidationError("The result does not match an active run.")
        counters = _service_counters(result.counters)
        with self._session_factory() as session, session.begin():
            service = OperationalPersistenceService(session)
            if result.status in _NON_REQUEST_DEFER:
                row = service.complete_non_request(
                    run_id=run.identity.run_id,
                    expected_state_version=run.identity.state_version,
                    status=result.status.value,
                    defer_reason=_NON_REQUEST_DEFER[result.status],
                    safe_summary=result.safe_message,
                )
            elif result.status in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}:
                row = service.record_persistence_commit(
                    run_id=run.identity.run_id,
                    expected_state_version=run.identity.state_version,
                    counters=counters,
                    safe_summary=result.safe_message,
                )
                if row.status not in {"checkpoint_pending", result.status.value}:
                    raise OperationalConflictError(
                        "The successful result conflicts with committed counters."
                    )
            elif result.status in {
                ResultStatus.PARTIAL,
                ResultStatus.FAILED,
                ResultStatus.CANCELLED,
            }:
                row = service.complete_partial_or_failure(
                    run_id=run.identity.run_id,
                    expected_state_version=run.identity.state_version,
                    status=result.status.value,
                    counters=counters,
                    run_level_error=(
                        result.status is ResultStatus.FAILED
                        and result.counters.failed == 0
                    ),
                    safe_summary=result.safe_message,
                )
            else:
                raise ContractValidationError("The result status is unsupported.")
            return _run_handle(row, result.source_slug)

    def advance_progress(
        self,
        run: RunHandle,
        proposal: ProgressProposal,
    ) -> RunHandle:
        if run.status != "checkpoint_pending":
            raise ContractValidationError("The run is not awaiting progress.")
        with self._session_factory() as session, session.begin():
            service = OperationalPersistenceService(session)
            if proposal.storage is ProgressStorage.CHECKPOINT:
                if not isinstance(proposal.value, str):
                    raise ContractValidationError("Checkpoint progress must be opaque text.")
                service.advance_checkpoint(
                    run_id=run.identity.run_id,
                    expected_run_state_version=run.identity.state_version,
                    scope_kind="source",
                    partition_key=None,
                    checkpoint_name=proposal.name,
                    checkpoint_value=proposal.value,
                    expected_previous_version=proposal.expected_previous_version,
                )
            elif proposal.storage is ProgressStorage.WATERMARK:
                if not isinstance(proposal.value, datetime):
                    raise ContractValidationError("Watermark progress must be a timestamp.")
                service.advance_watermark(
                    run_id=run.identity.run_id,
                    expected_run_state_version=run.identity.state_version,
                    scope_kind="source",
                    partition_key=None,
                    watermark_name=proposal.name,
                    watermark_value=proposal.value,
                    expected_previous_version=proposal.expected_previous_version,
                )
            else:
                raise ContractValidationError("The progress storage is unsupported.")
            row = session.get(IngestionRun, run.identity.run_id)
            if row is None:
                raise OperationalConflictError("The progressed run is unavailable.")
            return _run_handle(row, run.identity.source_slug)

    def abandon_pending_progress(
        self,
        run: RunHandle,
        status: ResultStatus,
        safe_message: str,
    ) -> RunHandle:
        if run.status != "checkpoint_pending" or status not in {
            ResultStatus.FAILED,
            ResultStatus.CANCELLED,
        }:
            raise ContractValidationError("The pending-progress transition is invalid.")
        with self._session_factory() as session, session.begin():
            row = OperationalPersistenceService(session).abandon_pending_progress(
                run_id=run.identity.run_id,
                expected_state_version=run.identity.state_version,
                status=status.value,
                safe_summary=safe_message,
            )
            return _run_handle(row, run.identity.source_slug)

    def read_cycle_evidence(self, cycle_id: int) -> CycleEvidence:
        if type(cycle_id) is not int or cycle_id < 1:
            raise ContractValidationError("The cycle identity is invalid.")
        with self._session_factory() as session, session.begin():
            cycle = session.get(IngestionCycle, cycle_id)
            if cycle is None:
                raise OperationalConflictError("The cycle evidence is unavailable.")
            maximum_attempts = (
                select(
                    IngestionRun.source_id.label("source_id"),
                    func.max(IngestionRun.attempt_number).label("attempt_number"),
                )
                .where(IngestionRun.cycle_id == cycle_id)
                .group_by(IngestionRun.source_id)
                .subquery()
            )
            rows = session.execute(
                select(IngestionRun, IntelligenceSource.slug)
                .join(
                    IntelligenceSource,
                    IntelligenceSource.id == IngestionRun.source_id,
                )
                .join(
                    maximum_attempts,
                    (IngestionRun.source_id == maximum_attempts.c.source_id)
                    & (
                        IngestionRun.attempt_number
                        == maximum_attempts.c.attempt_number
                    ),
                )
                .where(IngestionRun.cycle_id == cycle_id)
                .order_by(IntelligenceSource.slug)
            ).all()
            terminal = {status.value for status in ResultStatus}
            results: list[SourceExecutionResult] = []
            incomplete: list[str] = []
            for row, source_slug in rows:
                if row.status not in terminal:
                    incomplete.append(source_slug)
                    continue
                results.append(
                    SourceExecutionResult(
                        source_slug=source_slug,
                        status=ResultStatus(row.status),
                        counters=_contract_counters(row),
                        safe_message=(
                            row.safe_summary
                            or "Committed source outcome is available."
                        ),
                    )
                )
            successful = sum(
                result.status in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}
                for result in results
            )
            return CycleEvidence(
                cycle_id=cycle_id,
                sources_expected=cycle.sources_expected,
                sources_started=len(rows),
                sources_completed=len(results),
                sources_successful=successful,
                sources_non_successful=len(results) - successful,
                source_results=tuple(results),
                incomplete_source_slugs=tuple(incomplete),
            )

    def finalize_cycle(self, result: CycleResult, safe_summary: str) -> None:
        with self._session_factory() as session, session.begin():
            OperationalPersistenceService(session).finalize_cycle(
                cycle_id=result.cycle_id,
                status=result.status.value,
                sources_started=result.sources_started,
                sources_completed=result.sources_completed,
                sources_successful=result.sources_successful,
                sources_non_successful=result.sources_non_successful,
                safe_summary=safe_summary,
            )


def _service_counters(counters: ReconciledCounters) -> RunCounters:
    return RunCounters(
        fetched=counters.fetched,
        created=counters.created,
        updated=counters.updated,
        unchanged=counters.unchanged,
        skipped=counters.skipped,
        failed=counters.failed,
        error_count=counters.error_count,
    )


def _contract_counters(row: IngestionRun) -> ReconciledCounters:
    return ReconciledCounters(
        fetched=row.records_fetched,
        created=row.records_created,
        updated=row.records_updated,
        unchanged=row.records_unchanged,
        skipped=row.records_skipped,
        failed=row.records_failed,
        error_count=row.error_count,
    )


def _run_handle(row: IngestionRun, source_slug: str) -> RunHandle:
    if row.id is None or row.cycle_id is None or row.attempt_number is None or row.state_version is None:
        raise OperationalConflictError("The operational run identity is incomplete.")
    return RunHandle(
        identity=SourceAttemptIdentity(
            source_slug=source_slug,
            cycle_id=row.cycle_id,
            run_id=row.id,
            attempt_number=row.attempt_number,
            state_version=row.state_version,
        ),
        status=row.status,
        counters=_contract_counters(row),
    )


__all__ = ["DEPLOYMENT_REFERENCE", "OrchestrationPersistenceAdapter"]
