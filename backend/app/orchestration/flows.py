"""Deterministic Prefect source flow and two-hour parent ingestion cycle."""

from __future__ import annotations

from asyncio import CancelledError
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
import time
from zoneinfo import ZoneInfo

from prefect import flow, task
from prefect.context import FlowRunContext
from prefect.utilities.timeout import timeout as prefect_timeout

from app.orchestration.contracts import (
    ContractValidationError,
    CycleEvidence,
    CycleResult,
    CycleStatus,
    EligibilityMode,
    FailureCategory,
    FailureClassification,
    PersistenceAdapter,
    ProgressProposal,
    ProgressStorage,
    RateState,
    ReconciledCounters,
    ResultStatus,
    SafeMetrics,
    SOURCE_POLICIES,
    SourceExecutionContext,
    SourceExecutionResult,
    SourceHandler,
    SourcePolicy,
    classify_failure,
    eligibility_for_policy,
    list_source_policies,
)
from app.orchestration.persistence import (
    DEPLOYMENT_REFERENCE,
    OrchestrationPersistenceAdapter,
)
from app.orchestration.source_handlers import build_c02_source_handlers


PARENT_FLOW_NAME = "alpha-data-parent-ingestion-cycle"
SOURCE_FLOW_NAME = "alpha-data-source-ingestion"
SOURCE_EXECUTION_TIMEOUT_SECONDS = 900
SCHEDULE_TIMEZONE = ZoneInfo("Asia/Dubai")
DEFAULT_SOURCE_HANDLERS: Mapping[str, SourceHandler] = build_c02_source_handlers()
_SUCCESSFUL_SOURCE_STATUSES = frozenset(
    {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}
)


class SourceRunIncomplete(RuntimeError):
    """The latest operational run lacks terminal committed evidence."""


def validate_scheduled_slot(value: datetime) -> datetime:
    """Validate the fixed Dubai cron slot, then normalize it to UTC."""

    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ContractValidationError("The scheduled slot must be timezone-aware.")
    try:
        if value.utcoffset() is None:
            raise ContractValidationError("The scheduled slot must be timezone-aware.")
        local_slot = value.astimezone(SCHEDULE_TIMEZONE)
    except (OverflowError, ValueError) as exc:
        raise ContractValidationError("The scheduled slot is invalid.") from exc
    if (
        local_slot.hour % 2 != 0
        or local_slot.minute != 17
        or local_slot.second != 0
        or local_slot.microsecond != 0
    ):
        raise ContractValidationError("The scheduled slot is not aligned to the fixed cron.")
    return local_slot.astimezone(UTC)


def resolve_scheduled_slot(explicit_slot: datetime | None) -> datetime:
    """Use an explicit slot or the deployed Prefect run's expected start time."""

    context = FlowRunContext.get()
    if explicit_slot is not None:
        normalized = validate_scheduled_slot(explicit_slot)
        if context is not None and context.flow_run.deployment_id is not None:
            authoritative = validate_scheduled_slot(
                context.flow_run.expected_start_time
            )
            if normalized != authoritative:
                raise ContractValidationError(
                    "The explicit slot conflicts with the deployed scheduled slot."
                )
        return normalized
    if context is None or context.flow_run.deployment_id is None:
        raise ContractValidationError(
            "An explicit or authoritative deployed scheduled slot is required."
        )
    return validate_scheduled_slot(context.flow_run.expected_start_time)


@task(name="alpha-data-deterministic-stagger", persist_result=False)
def deterministic_stagger(delay_seconds: int) -> None:
    """Apply the fixed developer-controlled stagger for one source."""

    if type(delay_seconds) is not int or not 0 <= delay_seconds <= 300:
        raise ContractValidationError("The source stagger is invalid.")
    if delay_seconds:
        time.sleep(delay_seconds)


def _non_request_result(policy: SourcePolicy, status: ResultStatus, message: str) -> SourceExecutionResult:
    return SourceExecutionResult(
        source_slug=policy.source_slug,
        status=status,
        safe_message=message,
    )


def _failed_result(
    policy: SourcePolicy,
    failure: FailureClassification,
    *,
    counters: ReconciledCounters | None = None,
) -> SourceExecutionResult:
    return SourceExecutionResult(
        source_slug=policy.source_slug,
        status=ResultStatus.FAILED,
        counters=counters or ReconciledCounters(),
        safe_message=failure.safe_message,
        failure=failure,
    )


def _result_for_failure(
    policy: SourcePolicy,
    failure: FailureClassification,
) -> SourceExecutionResult:
    non_request_status = {
        FailureCategory.PROVIDER_RATE_LIMIT: ResultStatus.RATE_LIMITED,
        FailureCategory.MISSING_CREDENTIAL: ResultStatus.CREDENTIALS_MISSING,
        FailureCategory.MISSING_LICENCE: ResultStatus.LICENCE_REQUIRED,
        FailureCategory.APPROVAL_REQUIREMENT: ResultStatus.APPROVAL_PENDING,
    }.get(failure.category)
    if non_request_status is not None:
        return _non_request_result(
            policy,
            non_request_status,
            failure.safe_message,
        )
    return _failed_result(policy, failure)


def _validate_progress_proposal(
    policy: SourcePolicy,
    proposal: ProgressProposal | None,
    current_version: int,
) -> ProgressProposal | None:
    if policy.progress_storage is ProgressStorage.NONE:
        if proposal is not None:
            raise ContractValidationError("A no-progress source proposed progress.")
        return None
    if proposal is None:
        raise ContractValidationError("A progress-enabled result omitted its proposal.")
    if (
        proposal.storage is not policy.progress_storage
        or proposal.kind is not policy.progress_kind
        or proposal.name != policy.progress_kind.value
        or proposal.expected_previous_version != current_version
    ):
        raise ContractValidationError("The progress proposal conflicts with source policy.")
    return proposal


def _quota_result(
    policy: SourcePolicy,
    persistence: PersistenceAdapter,
    now: datetime,
) -> SourceExecutionResult | None:
    observation = persistence.read_quota(policy)
    if observation.state is RateState.QUOTA_UNAVAILABLE or observation.remaining == 0:
        return _non_request_result(
            policy,
            ResultStatus.DEFERRED_QUOTA,
            "The source request was deferred by its quota policy.",
        )
    if observation.state in {RateState.BACKOFF, RateState.LIMITED} and (
        observation.backoff_until is None or observation.backoff_until > now
    ):
        return _non_request_result(
            policy,
            ResultStatus.RATE_LIMITED,
            "The source request remains in bounded rate-limit backoff.",
        )
    return None


def _validate_source_boundary(
    *,
    policy: SourcePolicy,
    cycle_id: int,
    scheduled_for: datetime,
    handler: SourceHandler | None,
    persistence: PersistenceAdapter,
) -> datetime:
    if not isinstance(policy, SourcePolicy):
        raise ContractValidationError("A valid source policy is required.")
    if policy.execution_timeout_seconds != SOURCE_EXECUTION_TIMEOUT_SECONDS:
        raise ContractValidationError("The source execution bound is invalid.")
    if type(cycle_id) is not int or cycle_id < 1:
        raise ContractValidationError("A positive cycle identity is required.")
    slot = validate_scheduled_slot(scheduled_for)
    if handler is not None and not isinstance(handler, SourceHandler):
        raise ContractValidationError("The source handler does not satisfy its contract.")
    if not isinstance(persistence, PersistenceAdapter):
        raise ContractValidationError(
            "The persistence adapter does not satisfy its contract."
        )
    return slot


def _result_from_committed_run(
    *,
    policy: SourcePolicy,
    run,
    safe_message: str,
    metrics: SafeMetrics | None = None,
    failure: FailureClassification | None = None,
) -> SourceExecutionResult:
    try:
        status = ResultStatus(run.status)
    except ValueError:
        raise SourceRunIncomplete(
            "The source run does not have terminal committed evidence."
        ) from None
    return SourceExecutionResult(
        source_slug=policy.source_slug,
        status=status,
        counters=run.counters,
        metrics=metrics or SafeMetrics(),
        safe_message=safe_message,
        failure=(
            failure
            if status in {ResultStatus.FAILED, ResultStatus.PARTIAL}
            else None
        ),
    )


def _record_terminal_result(
    *,
    policy: SourcePolicy,
    persistence: PersistenceAdapter,
    run,
    result: SourceExecutionResult,
) -> tuple[SourceExecutionResult | None, object]:
    try:
        committed = persistence.record_result(run, result)
    except Exception:
        raise SourceRunIncomplete(
            "The source result lacks terminal committed evidence."
        ) from None
    committed_result = (
        None
        if committed.status == "checkpoint_pending"
        else _result_from_committed_run(
            policy=policy,
            run=committed,
            safe_message=result.safe_message,
            metrics=result.metrics,
            failure=result.failure,
        )
    )
    return committed_result, committed


def _abandon_pending_run(
    *,
    policy: SourcePolicy,
    persistence: PersistenceAdapter,
    run,
    status: ResultStatus,
    safe_message: str,
    failure: FailureClassification | None = None,
) -> SourceExecutionResult:
    try:
        committed = persistence.abandon_pending_progress(
            run,
            status,
            safe_message,
        )
    except Exception:
        raise SourceRunIncomplete(
            "The pending source run remains safely resumable."
        ) from None
    return _result_from_committed_run(
        policy=policy,
        run=committed,
        safe_message=safe_message,
        failure=failure,
    )


def run_source_once(
    *,
    policy: SourcePolicy,
    cycle_id: int,
    scheduled_for: datetime,
    handler: SourceHandler | None,
    persistence: PersistenceAdapter,
    retry_sleep: Callable[[int], None] = time.sleep,
) -> SourceExecutionResult:
    """Execute one source and return only terminal committed run evidence."""

    slot = _validate_source_boundary(
        policy=policy,
        cycle_id=cycle_id,
        scheduled_for=scheduled_for,
        handler=handler,
        persistence=persistence,
    )
    eligibility = eligibility_for_policy(policy, handler_bound=handler is not None)
    run = persistence.acquire_source_run(cycle_id, policy.source_slug)

    if run.status == "checkpoint_pending":
        if handler is None:
            failure = FailureClassification(
                FailureCategory.CONTRACT_VIOLATION,
                False,
                "Pending progress cannot resume without a bound source handler.",
            )
            return _abandon_pending_run(
                policy=policy,
                persistence=persistence,
                run=run,
                status=ResultStatus.FAILED,
                safe_message=failure.safe_message,
                failure=failure,
            )
        try:
            progress = persistence.read_progress(policy)
            context = SourceExecutionContext(
                policy=policy,
                attempt=run.identity,
                scheduled_for=slot,
                deployment_ref=DEPLOYMENT_REFERENCE,
                progress=progress,
                quota=persistence.read_quota(policy),
            )
            proposal = handler.reconstruct_progress(context, run.counters)
            _validate_progress_proposal(
                policy,
                proposal,
                0 if progress is None else progress.version,
            )
            completed = persistence.advance_progress(run, proposal)
        except CancelledError:
            return _abandon_pending_run(
                policy=policy,
                persistence=persistence,
                run=run,
                status=ResultStatus.CANCELLED,
                safe_message="Pending source recovery was cancelled.",
            )
        except Exception as error:
            failure = classify_failure(error)
            if failure.transient:
                raise SourceRunIncomplete(
                    "The pending source run remains safely resumable."
                ) from None
            return _abandon_pending_run(
                policy=policy,
                persistence=persistence,
                run=run,
                status=ResultStatus.FAILED,
                safe_message=failure.safe_message,
                failure=failure,
            )
        return _result_from_committed_run(
            policy=policy,
            run=completed,
            safe_message="Previously committed source progress resumed safely.",
        )

    if run.status != "running":
        return _result_from_committed_run(
            policy=policy,
            run=run,
            safe_message="The existing source attempt was reused without duplicate execution.",
        )

    if not eligibility.request_allowed:
        assert eligibility.status is not None
        result = _non_request_result(
            policy,
            eligibility.status,
            eligibility.safe_message,
        )
        committed_result, _ = _record_terminal_result(
            policy=policy,
            persistence=persistence,
            run=run,
            result=result,
        )
        assert committed_result is not None
        return committed_result

    try:
        quota_result = _quota_result(policy, persistence, slot)
    except Exception as error:
        failure = classify_failure(error)
        committed_result, _ = _record_terminal_result(
            policy=policy,
            persistence=persistence,
            run=run,
            result=_failed_result(policy, failure),
        )
        assert committed_result is not None
        return committed_result
    if quota_result is not None:
        committed_result, _ = _record_terminal_result(
            policy=policy,
            persistence=persistence,
            run=run,
            result=quota_result,
        )
        assert committed_result is not None
        return committed_result

    assert handler is not None
    try:
        progress = persistence.read_progress(policy)
    except Exception as error:
        failure = classify_failure(error)
        committed_result, _ = _record_terminal_result(
            policy=policy,
            persistence=persistence,
            run=run,
            result=_failed_result(policy, failure),
        )
        assert committed_result is not None
        return committed_result
    current_version = 0 if progress is None else progress.version
    for attempt_index in range(policy.retry_plan.maximum_attempts):
        if attempt_index:
            retry_sleep(policy.retry_plan.delays_seconds[attempt_index - 1])
            try:
                run = persistence.acquire_retry(run.identity.run_id)
            except Exception:
                return committed_result
        try:
            context = SourceExecutionContext(
                policy=policy,
                attempt=run.identity,
                scheduled_for=slot,
                deployment_ref=DEPLOYMENT_REFERENCE,
                progress=progress,
                quota=persistence.read_quota(policy),
            )
            with prefect_timeout(policy.execution_timeout_seconds):
                result = handler.execute(context)
            if not isinstance(result, SourceExecutionResult):
                raise ContractValidationError("The source handler returned an invalid result.")
            if result.source_slug != policy.source_slug:
                raise ContractValidationError("The source handler returned a conflicting identity.")
            if result.status in _SUCCESSFUL_SOURCE_STATUSES:
                _validate_progress_proposal(
                    policy,
                    result.progress_proposal,
                    current_version,
                )
        except CancelledError:
            result = SourceExecutionResult(
                source_slug=policy.source_slug,
                status=ResultStatus.CANCELLED,
                safe_message="The source execution was cancelled.",
            )
        except Exception as error:
            failure = classify_failure(error)
            result = _result_for_failure(policy, failure)

        committed_result, committed = _record_terminal_result(
            policy=policy,
            persistence=persistence,
            run=run,
            result=result,
        )
        if result.status in _SUCCESSFUL_SOURCE_STATUSES:
            if result.progress_proposal is not None:
                try:
                    committed = persistence.advance_progress(
                        committed,
                        result.progress_proposal,
                    )
                except Exception:
                    raise SourceRunIncomplete(
                        "Committed source data is awaiting safe progress recovery."
                    ) from None
            if committed.status not in {status.value for status in _SUCCESSFUL_SOURCE_STATUSES}:
                raise SourceRunIncomplete(
                    "Committed source data is awaiting safe progress recovery."
                )
            return _result_from_committed_run(
                policy=policy,
                run=committed,
                safe_message=result.safe_message,
                metrics=result.metrics,
            )

        assert committed_result is not None
        failure = result.failure
        if (
            result.status is ResultStatus.FAILED
            and failure is not None
            and failure.transient
            and attempt_index + 1 < policy.retry_plan.maximum_attempts
            and failure.category is not FailureCategory.PROVIDER_RATE_LIMIT
        ):
            continue
        return committed_result

    raise SourceRunIncomplete(
        "The bounded retry plan ended without terminal committed evidence."
    )


@flow(
    name=SOURCE_FLOW_NAME,
    persist_result=False,
    validate_parameters=True,
    timeout_seconds=SOURCE_EXECUTION_TIMEOUT_SECONDS,
)
def source_ingestion_flow(
    source_slug: str,
    cycle_id: int,
    scheduled_for: datetime,
) -> SourceExecutionResult:
    """Serializable production subflow boundary with fixed C01 dependencies."""

    policy = SOURCE_POLICIES.get(source_slug)
    if policy is None:
        raise ContractValidationError("The source flow slug is not configured.")
    return run_source_once(
        policy=policy,
        cycle_id=cycle_id,
        scheduled_for=scheduled_for,
        handler=DEFAULT_SOURCE_HANDLERS.get(source_slug),
        persistence=OrchestrationPersistenceAdapter(),
    )


def _cycle_status(evidence: CycleEvidence) -> CycleStatus:
    if any(
        result.status is ResultStatus.CANCELLED
        for result in evidence.source_results
    ):
        return CycleStatus.CANCELLED
    if (
        evidence.sources_completed == evidence.sources_expected
        and evidence.sources_successful == evidence.sources_expected
    ):
        return CycleStatus.SUCCESS
    if evidence.sources_successful:
        return CycleStatus.PARTIAL
    return CycleStatus.FAILED


def run_parent_cycle(
    *,
    scheduled_for: datetime,
    persistence: PersistenceAdapter,
    handlers: Mapping[str, SourceHandler],
    stagger: Callable[[int], None] = time.sleep,
    source_runner: Callable[..., SourceExecutionResult] = run_source_once,
) -> CycleResult:
    """Run every scheduled policy in deterministic order and finalize truthfully."""

    slot = validate_scheduled_slot(scheduled_for)
    if not isinstance(persistence, PersistenceAdapter):
        raise ContractValidationError(
            "The persistence adapter does not satisfy its contract."
        )
    policies = tuple(
        policy
        for policy in list_source_policies()
        if policy.eligibility_mode is EligibilityMode.SCHEDULED
    )
    allowed = {policy.source_slug for policy in policies}
    if not set(handlers).issubset(allowed) or any(
        not isinstance(handler, SourceHandler) for handler in handlers.values()
    ):
        raise ContractValidationError("The parent source bindings are invalid.")
    cycle = persistence.acquire_scheduled_cycle(slot, len(policies))
    for policy in policies:
        stagger(policy.stagger_seconds)
        try:
            source_runner(
                policy=policy,
                cycle_id=cycle.cycle_id,
                scheduled_for=slot,
                handler=handlers.get(policy.source_slug),
                persistence=persistence,
            )
        except Exception:
            continue

    evidence = persistence.read_cycle_evidence(cycle.cycle_id)
    if (
        evidence.cycle_id != cycle.cycle_id
        or evidence.sources_expected != len(policies)
    ):
        raise ContractValidationError("The parent cycle evidence conflicts.")
    cycle_result = CycleResult(
        cycle_id=cycle.cycle_id,
        status=_cycle_status(evidence),
        sources_expected=evidence.sources_expected,
        sources_started=evidence.sources_started,
        sources_completed=evidence.sources_completed,
        sources_successful=evidence.sources_successful,
        sources_non_successful=evidence.sources_non_successful,
        source_results=evidence.source_results,
    )
    persistence.finalize_cycle(
        cycle_result,
        "Parent cycle completed with bounded reconciled source outcomes.",
    )
    return cycle_result


@flow(
    name=PARENT_FLOW_NAME,
    persist_result=False,
    validate_parameters=True,
)
def parent_ingestion_cycle(
    scheduled_for: datetime | None = None,
) -> CycleResult:
    """Deployed parent flow using the reviewed immutable production bindings."""

    slot = resolve_scheduled_slot(scheduled_for)

    def invoke_source(**kwargs) -> SourceExecutionResult:
        return source_ingestion_flow(
            source_slug=kwargs["policy"].source_slug,
            cycle_id=kwargs["cycle_id"],
            scheduled_for=kwargs["scheduled_for"],
        )

    return run_parent_cycle(
        scheduled_for=slot,
        persistence=OrchestrationPersistenceAdapter(),
        handlers=DEFAULT_SOURCE_HANDLERS,
        stagger=lambda seconds: deterministic_stagger(seconds),
        source_runner=invoke_source,
    )


__all__ = [
    "DEFAULT_SOURCE_HANDLERS",
    "PARENT_FLOW_NAME",
    "SOURCE_FLOW_NAME",
    "SOURCE_EXECUTION_TIMEOUT_SECONDS",
    "SourceRunIncomplete",
    "deterministic_stagger",
    "parent_ingestion_cycle",
    "run_parent_cycle",
    "run_source_once",
    "resolve_scheduled_slot",
    "source_ingestion_flow",
    "validate_scheduled_slot",
]
