from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from contextlib import contextmanager
import inspect
from types import SimpleNamespace
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest

from app.orchestration.contracts import (
    ClassifiedFailure,
    ContractValidationError,
    CycleEvidence,
    CycleHandle,
    CycleStatus,
    EligibilityMode,
    FailureCategory,
    ProgressProposal,
    ProgressKind,
    ProgressStorage,
    QuotaObservation,
    ReconciledCounters,
    ResultStatus,
    RunHandle,
    SourceAttemptIdentity,
    SourceExecutionResult,
    eligibility_for_policy,
    list_source_policies,
)
from app.orchestration.flows import run_parent_cycle, run_source_once
from app.orchestration.flows import (
    DEFAULT_SOURCE_HANDLERS,
    SOURCE_EXECUTION_TIMEOUT_SECONDS,
    SourceRunIncomplete,
    parent_ingestion_cycle,
    resolve_scheduled_slot,
    source_ingestion_flow,
    validate_scheduled_slot,
)
from app.orchestration.source_handlers import C02_BOUND_SOURCE_SLUGS
from app.orchestration.source_handlers.cisa_kev import CisaKevSourceHandler
from app.orchestration.source_handlers.epss import EpssSourceHandler
from app.orchestration.source_handlers.nvd import NvdSourceHandler
from app.orchestration.source_handlers.publications import PublicationSourceHandler


SLOT = datetime(2026, 8, 3, 8, 17, tzinfo=UTC)


def test_production_source_handlers_are_exact_typed_and_immutable() -> None:
    assert frozenset(DEFAULT_SOURCE_HANDLERS) == C02_BOUND_SOURCE_SLUGS
    assert isinstance(DEFAULT_SOURCE_HANDLERS["nvd"], NvdSourceHandler)
    assert isinstance(DEFAULT_SOURCE_HANDLERS["first-epss"], EpssSourceHandler)
    assert isinstance(DEFAULT_SOURCE_HANDLERS["cisa-kev"], CisaKevSourceHandler)
    for source_slug in (
        "cert-eu-security-advisories",
        "google-threat-intelligence-public-research",
        "mandiant-public-threat-research",
    ):
        assert isinstance(
            DEFAULT_SOURCE_HANDLERS[source_slug],
            PublicationSourceHandler,
        )
    with pytest.raises(TypeError):
        DEFAULT_SOURCE_HANDLERS["unapproved-source"] = DEFAULT_SOURCE_HANDLERS[  # type: ignore[index]
            "nvd"
        ]


def test_scheduled_policy_set_equals_the_exact_production_binding_set() -> None:
    scheduled = frozenset(
        policy.source_slug
        for policy in list_source_policies()
        if policy.eligibility_mode is EligibilityMode.SCHEDULED
    )
    assert scheduled == C02_BOUND_SOURCE_SLUGS


def test_source_flow_resolves_its_handler_from_the_production_mapping(monkeypatch) -> None:
    captured = {}
    expected = success_result("nvd")

    def fake_run_source_once(**kwargs):
        captured.update(kwargs)
        return expected

    monkeypatch.setattr("app.orchestration.flows.run_source_once", fake_run_source_once)
    monkeypatch.setattr(
        "app.orchestration.flows.OrchestrationPersistenceAdapter",
        lambda: object(),
    )

    result = source_ingestion_flow.fn("nvd", 1, SLOT)

    assert result is expected
    assert captured["handler"] is DEFAULT_SOURCE_HANDLERS["nvd"]


def test_parent_flow_supplies_the_same_production_mapping(monkeypatch) -> None:
    captured = {}
    expected = object()

    def fake_run_parent_cycle(**kwargs):
        captured.update(kwargs)
        return expected

    monkeypatch.setattr("app.orchestration.flows.run_parent_cycle", fake_run_parent_cycle)
    monkeypatch.setattr(
        "app.orchestration.flows.OrchestrationPersistenceAdapter",
        lambda: object(),
    )

    result = parent_ingestion_cycle.fn(SLOT)

    assert result is expected
    assert captured["handlers"] is DEFAULT_SOURCE_HANDLERS


class FakePersistence:
    def __init__(self) -> None:
        self.next_run_id = 10
        self.recorded: list[SourceExecutionResult] = []
        self.finalized = None
        self.retry_count = 0
        self.quota = None
        self.expected_sources = 0
        self.runs: dict[str, RunHandle] = {}
        self.acquire_count = 0
        self.record_error = False
        self.quota_error: Exception | None = None
        self.progress_error: Exception | None = None
        self.advance_error: Exception | None = None
        self.abandoned: list[tuple[str, ResultStatus]] = []

    def acquire_scheduled_cycle(self, scheduled_for, sources_expected):
        self.expected_sources = sources_expected
        return CycleHandle(1, "scheduled-cycle", scheduled_for)

    def acquire_source_run(self, cycle_id, source_slug):
        self.acquire_count += 1
        if self.expected_sources == 0:
            self.expected_sources = 1
        if source_slug not in self.runs:
            self.runs[source_slug] = self._run(source_slug, 0)
        return self.runs[source_slug]

    def acquire_retry(self, prior_run_id):
        self.retry_count += 1
        source_slug = self.recorded[-1].source_slug
        self.runs[source_slug] = self._run(source_slug, self.retry_count)
        return self.runs[source_slug]

    def _run(self, source_slug, attempt):
        self.next_run_id += 1
        return RunHandle(
            SourceAttemptIdentity(
                source_slug=source_slug,
                cycle_id=1,
                run_id=self.next_run_id,
                attempt_number=attempt,
                state_version=1,
            ),
            "running",
        )

    def read_progress(self, policy):
        if self.progress_error is not None:
            raise self.progress_error
        return None

    def read_quota(self, policy):
        if self.quota_error is not None:
            raise self.quota_error
        return self.quota or QuotaObservation(policy.quota_policy_key)

    def record_result(self, run, result):
        if self.record_error:
            raise RuntimeError("synthetic persistence failure")
        self.recorded.append(result)
        policy = next(
            policy
            for policy in list_source_policies()
            if policy.source_slug == result.source_slug
        )
        status = (
            "checkpoint_pending"
            if result.status in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}
            and policy.progress_storage is not ProgressStorage.NONE
            else result.status.value
        )
        committed = replace(run, status=status, counters=result.counters)
        self.runs[result.source_slug] = committed
        return committed

    def advance_progress(self, run, proposal):
        if self.advance_error is not None:
            raise self.advance_error
        status = "success" if run.counters.created + run.counters.updated else "no_change"
        committed = replace(
            run,
            status=status,
            identity=replace(run.identity, state_version=run.identity.state_version + 1),
        )
        self.runs[run.identity.source_slug] = committed
        return committed

    def abandon_pending_progress(self, run, status, safe_message):
        self.abandoned.append((run.identity.source_slug, status))
        committed = replace(
            run,
            status=status.value,
            identity=replace(run.identity, state_version=run.identity.state_version + 1),
        )
        self.runs[run.identity.source_slug] = committed
        return committed

    def read_cycle_evidence(self, cycle_id):
        terminal = {status.value for status in ResultStatus}
        results = tuple(
            SourceExecutionResult(
                source_slug=slug,
                status=ResultStatus(run.status),
                counters=run.counters,
                safe_message="Committed fake source evidence.",
            )
            for slug, run in sorted(self.runs.items())
            if run.status in terminal
        )
        incomplete = tuple(
            slug
            for slug, run in sorted(self.runs.items())
            if run.status not in terminal
        )
        successful = sum(
            result.status in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}
            for result in results
        )
        return CycleEvidence(
            cycle_id=cycle_id,
            sources_expected=self.expected_sources,
            sources_started=len(self.runs),
            sources_completed=len(results),
            sources_successful=successful,
            sources_non_successful=len(results) - successful,
            source_results=results,
            incomplete_source_slugs=incomplete,
        )

    def finalize_cycle(self, result, safe_summary):
        self.finalized = result


class SequenceHandler:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.attempts = []

    def execute(self, context):
        self.attempts.append(context.attempt.attempt_number)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def reconstruct_progress(self, context, committed_counters) -> ProgressProposal:
        raise AssertionError("resume was not expected")


def scheduled_no_progress_policy():
    policy = next(
        policy
        for policy in list_source_policies()
        if policy.source_slug == "censys-arc-research"
    )
    return replace(policy, eligibility_mode=EligibilityMode.SCHEDULED)


def success_result(slug: str) -> SourceExecutionResult:
    return SourceExecutionResult(
        source_slug=slug,
        status=ResultStatus.SUCCESS,
        counters=ReconciledCounters(fetched=1, created=1),
        safe_message="The source committed one bounded record.",
    )


def commit_fake_result(
    persistence: FakePersistence,
    policy,
    run: RunHandle,
    result: SourceExecutionResult,
) -> RunHandle:
    committed = persistence.record_result(run, result)
    if committed.status != "checkpoint_pending":
        return committed
    assert policy.progress_kind is not None
    value = (
        SLOT
        if policy.progress_kind is ProgressKind.MODIFIED_SINCE
        else "bounded-progress-token"
    )
    return persistence.advance_progress(
        committed,
        ProgressProposal(
            storage=policy.progress_storage,
            kind=policy.progress_kind,
            name=policy.progress_kind.value,
            value=value,
            expected_previous_version=0,
        ),
    )


def test_transient_failure_retries_linearly_then_succeeds() -> None:
    policy = scheduled_no_progress_policy()
    persistence = FakePersistence()
    handler = SequenceHandler(
        [
            ClassifiedFailure(
                FailureCategory.APPROVED_TIMEOUT,
                "The approved source operation timed out.",
            ),
            success_result(policy.source_slug),
        ]
    )
    delays = []

    result = run_source_once(
        policy=policy,
        cycle_id=1,
        scheduled_for=SLOT,
        handler=handler,
        persistence=persistence,
        retry_sleep=delays.append,
    )

    assert result.status is ResultStatus.SUCCESS
    assert handler.attempts == [0, 1]
    assert delays == [policy.retry_plan.delays_seconds[0]]
    assert [result.status for result in persistence.recorded] == [
        ResultStatus.FAILED,
        ResultStatus.SUCCESS,
    ]


def test_unknown_permanent_failure_is_not_retried_or_reported_success() -> None:
    policy = scheduled_no_progress_policy()
    persistence = FakePersistence()
    handler = SequenceHandler([RuntimeError("raw provider details")])

    result = run_source_once(
        policy=policy,
        cycle_id=1,
        scheduled_for=SLOT,
        handler=handler,
        persistence=persistence,
        retry_sleep=lambda _: (_ for _ in ()).throw(AssertionError("no retry")),
    )

    assert result.status is ResultStatus.FAILED
    assert result.failure.category is FailureCategory.CONTRACT_VIOLATION
    assert handler.attempts == [0]


def test_missing_scheduled_handler_is_a_truthful_failure() -> None:
    policy = scheduled_no_progress_policy()
    persistence = FakePersistence()
    result = run_source_once(
        policy=policy,
        cycle_id=1,
        scheduled_for=SLOT,
        handler=None,
        persistence=persistence,
        retry_sleep=lambda _: None,
    )
    assert result.status is ResultStatus.FAILED
    assert persistence.recorded[-1].status is ResultStatus.FAILED


def test_non_request_eligibility_outcomes_remain_distinct() -> None:
    base = scheduled_no_progress_policy()
    expected = {
        EligibilityMode.MANUAL_ONLY: ResultStatus.APPROVAL_PENDING,
        EligibilityMode.APPROVAL_REQUIRED: ResultStatus.APPROVAL_PENDING,
        EligibilityMode.DISABLED: ResultStatus.DISABLED,
        EligibilityMode.CREDENTIALS_REQUIRED: ResultStatus.CREDENTIALS_MISSING,
        EligibilityMode.LICENCE_REQUIRED: ResultStatus.LICENCE_REQUIRED,
    }
    for mode, status in expected.items():
        eligibility = eligibility_for_policy(
            replace(base, eligibility_mode=mode), handler_bound=False
        )
        assert eligibility.status is status
        assert eligibility.request_allowed is False


def test_parent_cycle_orders_scheduled_policies_and_isolates_failure() -> None:
    persistence = FakePersistence()
    seen = []
    stagger = []

    def source_runner(**kwargs):
        slug = kwargs["policy"].source_slug
        seen.append(slug)
        run = persistence.acquire_source_run(kwargs["cycle_id"], slug)
        if len(seen) == 2:
            raise RuntimeError("unclassified failure")
        result = success_result(slug)
        commit_fake_result(persistence, kwargs["policy"], run, result)
        return result

    result = run_parent_cycle(
        scheduled_for=SLOT,
        persistence=persistence,
        handlers={},
        stagger=stagger.append,
        source_runner=source_runner,
    )

    policies = tuple(
        policy
        for policy in list_source_policies()
        if policy.eligibility_mode is EligibilityMode.SCHEDULED
    )
    assert seen == [policy.source_slug for policy in policies]
    assert stagger == [policy.stagger_seconds for policy in policies]
    assert result.sources_expected == result.sources_started == len(policies)
    assert result.sources_completed == len(policies) - 1
    assert result.status is CycleStatus.PARTIAL
    evidence = persistence.read_cycle_evidence(result.cycle_id)
    assert evidence.incomplete_source_slugs == (policies[1].source_slug,)
    assert all(item.status is ResultStatus.SUCCESS for item in result.source_results)
    assert persistence.finalized == result


def test_healthy_parent_cycle_runs_only_scheduled_policies() -> None:
    persistence = FakePersistence()
    policies_before = list_source_policies()
    scheduled = tuple(
        policy
        for policy in policies_before
        if policy.eligibility_mode is EligibilityMode.SCHEDULED
    )
    manual_only = tuple(
        policy
        for policy in policies_before
        if policy.eligibility_mode is EligibilityMode.MANUAL_ONLY
    )
    seen = []

    def source_runner(**kwargs):
        policy = kwargs["policy"]
        seen.append(policy.source_slug)
        run = persistence.acquire_source_run(kwargs["cycle_id"], policy.source_slug)
        status = (
            ResultStatus.SUCCESS
            if len(seen) % 2
            else ResultStatus.NO_CHANGE
        )
        result = SourceExecutionResult(
            source_slug=policy.source_slug,
            status=status,
            counters=(
                ReconciledCounters(fetched=1, created=1)
                if status is ResultStatus.SUCCESS
                else ReconciledCounters()
            ),
            safe_message="The scheduled source completed truthfully.",
        )
        commit_fake_result(persistence, policy, run, result)
        return result

    result = run_parent_cycle(
        scheduled_for=SLOT,
        persistence=persistence,
        handlers={},
        stagger=lambda _: None,
        source_runner=source_runner,
    )

    assert len(policies_before) == 11
    assert len(scheduled) == 6
    assert len(manual_only) == 5
    assert seen == [policy.source_slug for policy in scheduled]
    assert not set(seen).intersection(policy.source_slug for policy in manual_only)
    assert persistence.expected_sources == 6
    assert result.status is CycleStatus.SUCCESS
    assert result.sources_expected == 6
    assert result.sources_started == 6
    assert result.sources_completed == 6
    assert result.sources_successful == 6
    assert result.sources_non_successful == 0
    assert list_source_policies() == policies_before
    assert all(
        policy.eligibility_mode is EligibilityMode.MANUAL_ONLY
        for policy in manual_only
    )


def test_parent_cycle_rejects_manual_only_handler_binding_before_mutation() -> None:
    persistence = FakePersistence()
    manual_policy = next(
        policy
        for policy in list_source_policies()
        if policy.eligibility_mode is EligibilityMode.MANUAL_ONLY
    )

    with pytest.raises(ContractValidationError, match="bindings"):
        run_parent_cycle(
            scheduled_for=SLOT,
            persistence=persistence,
            handlers={
                manual_policy.source_slug: next(
                    iter(DEFAULT_SOURCE_HANDLERS.values())
                )
            },
            stagger=lambda _: None,
            source_runner=lambda **_: pytest.fail("manual-only handler was executed"),
        )

    assert persistence.expected_sources == 0
    assert persistence.acquire_count == 0


def test_parent_never_reports_success_for_non_request_or_cancelled_results() -> None:
    for terminal, expected in (
        (ResultStatus.DISABLED, CycleStatus.FAILED),
        (ResultStatus.CANCELLED, CycleStatus.CANCELLED),
    ):
        persistence = FakePersistence()

        def source_runner(**kwargs):
            result = SourceExecutionResult(
                source_slug=kwargs["policy"].source_slug,
                status=terminal,
                safe_message="The source did not complete a request.",
            )
            run = persistence.acquire_source_run(
                kwargs["cycle_id"], kwargs["policy"].source_slug
            )
            persistence.record_result(run, result)
            return result

        result = run_parent_cycle(
            scheduled_for=SLOT,
            persistence=persistence,
            handlers={},
            stagger=lambda _: None,
            source_runner=source_runner,
        )
        assert result.status is expected


def test_scheduled_slots_are_strictly_aligned_and_normalize_consistently() -> None:
    dubai = ZoneInfo("Asia/Dubai")
    local = datetime(2026, 8, 3, 12, 17, tzinfo=dubai)
    assert validate_scheduled_slot(local) == SLOT
    assert validate_scheduled_slot(SLOT) == SLOT

    for invalid in (
        datetime(2026, 8, 3, 12, 17),
        datetime(2026, 8, 3, 13, 17, tzinfo=dubai),
        datetime(2026, 8, 3, 12, 18, tzinfo=dubai),
        datetime(2026, 8, 3, 12, 17, 1, tzinfo=dubai),
        datetime(2026, 8, 3, 12, 17, 0, 1, tzinfo=dubai),
    ):
        with pytest.raises(ContractValidationError):
            validate_scheduled_slot(invalid)


def test_authoritative_prefect_slot_survives_delay_and_rerun(monkeypatch) -> None:
    context = SimpleNamespace(
        flow_run=SimpleNamespace(
            deployment_id=uuid4(),
            expected_start_time=SLOT,
        )
    )
    monkeypatch.setattr(
        "app.orchestration.flows.FlowRunContext",
        SimpleNamespace(get=lambda: context),
    )

    assert resolve_scheduled_slot(None) == SLOT
    assert resolve_scheduled_slot(None) == SLOT
    with pytest.raises(ContractValidationError, match="conflicts"):
        resolve_scheduled_slot(datetime(2026, 8, 3, 10, 17, tzinfo=UTC))


def test_direct_invocation_cannot_manufacture_a_future_slot(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.orchestration.flows.FlowRunContext",
        SimpleNamespace(get=lambda: None),
    )
    with pytest.raises(ContractValidationError, match="authoritative"):
        resolve_scheduled_slot(None)
    source = inspect.getsource(
        __import__("app.orchestration.flows", fromlist=["parent_ingestion_cycle"])
    )
    assert "datetime.now" not in source
    assert ".replace(minute=17" not in source


def test_source_boundary_rejects_invalid_values_before_mutation() -> None:
    policy = scheduled_no_progress_policy()
    invalid_cases = (
        dict(policy=object(), cycle_id=1, scheduled_for=SLOT, handler=None),
        dict(
            policy=replace(policy, execution_timeout_seconds=901),
            cycle_id=1,
            scheduled_for=SLOT,
            handler=None,
        ),
        dict(policy=policy, cycle_id=0, scheduled_for=SLOT, handler=None),
        dict(
            policy=policy,
            cycle_id=1,
            scheduled_for=datetime(2026, 8, 3, 8, 18, tzinfo=UTC),
            handler=None,
        ),
        dict(policy=policy, cycle_id=1, scheduled_for=SLOT, handler=object()),
    )
    for arguments in invalid_cases:
        persistence = FakePersistence()
        with pytest.raises(ContractValidationError):
            run_source_once(
                **arguments,
                persistence=persistence,
                retry_sleep=lambda _: None,
            )
        assert persistence.acquire_count == 0

    with pytest.raises(ContractValidationError, match="persistence"):
        run_source_once(
            policy=policy,
            cycle_id=1,
            scheduled_for=SLOT,
            handler=None,
            persistence=object(),
            retry_sleep=lambda _: None,
        )


def test_source_flow_uses_strict_serializable_validation_and_timeout() -> None:
    assert source_ingestion_flow.should_validate_parameters is True
    assert source_ingestion_flow.timeout_seconds == SOURCE_EXECUTION_TIMEOUT_SECONDS
    assert source_ingestion_flow.timeout_seconds == 900
    assert set(source_ingestion_flow.fn.__annotations__) == {
        "source_slug",
        "cycle_id",
        "scheduled_for",
        "return",
    }
    source = inspect.getsource(
        __import__("app.orchestration.flows", fromlist=["run_source_once"])
    )
    assert "with prefect_timeout(policy.execution_timeout_seconds)" in source
    assert "validate_parameters=False" not in source


def test_handler_timeout_is_safely_persisted_and_bounded(monkeypatch) -> None:
    policy = scheduled_no_progress_policy()
    persistence = FakePersistence()
    handler = SequenceHandler([success_result(policy.source_slug)])
    delays: list[int] = []

    @contextmanager
    def immediate_timeout(seconds):
        assert seconds == 900
        raise TimeoutError("raw timeout detail must not escape")
        yield

    monkeypatch.setattr("app.orchestration.flows.prefect_timeout", immediate_timeout)
    result = run_source_once(
        policy=policy,
        cycle_id=1,
        scheduled_for=SLOT,
        handler=handler,
        persistence=persistence,
        retry_sleep=delays.append,
    )

    assert result.status is ResultStatus.FAILED
    assert result.failure.category is FailureCategory.APPROVED_TIMEOUT
    assert "raw timeout" not in result.safe_message
    assert delays == [30, 60]
    assert persistence.retry_count == 2


@pytest.mark.parametrize("failure_attribute", ("quota_error", "progress_error"))
def test_preparation_failure_after_acquisition_is_terminally_persisted(
    failure_attribute,
) -> None:
    policy = scheduled_no_progress_policy()
    persistence = FakePersistence()
    setattr(persistence, failure_attribute, RuntimeError("raw preparation detail"))
    result = run_source_once(
        policy=policy,
        cycle_id=1,
        scheduled_for=SLOT,
        handler=SequenceHandler([success_result(policy.source_slug)]),
        persistence=persistence,
        retry_sleep=lambda _: None,
    )

    evidence = persistence.read_cycle_evidence(1)
    assert result.status is ResultStatus.FAILED
    assert evidence.sources_started == evidence.sources_completed == 1
    assert evidence.sources_non_successful == 1
    assert evidence.incomplete_source_slugs == ()


def checkpoint_policy():
    policy = next(
        policy for policy in list_source_policies() if policy.source_slug == "cisa-kev"
    )
    assert policy.progress_storage is ProgressStorage.CHECKPOINT
    return replace(policy, eligibility_mode=EligibilityMode.SCHEDULED)


class RecoveryHandler:
    def __init__(self, reconstruction_error: BaseException) -> None:
        self.reconstruction_error = reconstruction_error

    def execute(self, context):
        raise AssertionError("a pending run must not execute source collection")

    def reconstruct_progress(self, context, committed_counters):
        raise self.reconstruction_error


def pending_fake_run(persistence: FakePersistence, policy) -> RunHandle:
    run = persistence.acquire_source_run(1, policy.source_slug)
    pending = replace(
        run,
        status="checkpoint_pending",
        counters=ReconciledCounters(fetched=1, created=1),
    )
    persistence.runs[policy.source_slug] = pending
    return pending


def test_transient_checkpoint_reconstruction_remains_resumable() -> None:
    policy = checkpoint_policy()
    persistence = FakePersistence()
    pending_fake_run(persistence, policy)
    handler = RecoveryHandler(
        ClassifiedFailure(
            FailureCategory.APPROVED_TIMEOUT,
            "The approved recovery operation timed out.",
        )
    )

    with pytest.raises(SourceRunIncomplete, match="resumable"):
        run_source_once(
            policy=policy,
            cycle_id=1,
            scheduled_for=SLOT,
            handler=handler,
            persistence=persistence,
            retry_sleep=lambda _: None,
        )
    assert persistence.runs[policy.source_slug].status == "checkpoint_pending"
    assert persistence.abandoned == []


def test_permanent_checkpoint_conflict_uses_explicit_abandon_transition() -> None:
    policy = checkpoint_policy()
    persistence = FakePersistence()
    pending_fake_run(persistence, policy)

    result = run_source_once(
        policy=policy,
        cycle_id=1,
        scheduled_for=SLOT,
        handler=RecoveryHandler(ContractValidationError("conflicting proposal")),
        persistence=persistence,
        retry_sleep=lambda _: None,
    )

    assert result.status is ResultStatus.FAILED
    assert persistence.abandoned == [(policy.source_slug, ResultStatus.FAILED)]
    assert persistence.runs[policy.source_slug].status == "failed"


def test_crash_before_record_leaves_running_evidence_incomplete() -> None:
    policy = scheduled_no_progress_policy()
    persistence = FakePersistence()
    persistence.record_error = True
    with pytest.raises(SourceRunIncomplete, match="terminal committed"):
        run_source_once(
            policy=policy,
            cycle_id=1,
            scheduled_for=SLOT,
            handler=SequenceHandler([success_result(policy.source_slug)]),
            persistence=persistence,
            retry_sleep=lambda _: None,
        )
    evidence = persistence.read_cycle_evidence(1)
    assert evidence.sources_started == 1
    assert evidence.sources_completed == 0
    assert evidence.incomplete_source_slugs == (policy.source_slug,)


def test_crash_after_operational_commit_preserves_checkpoint_pending() -> None:
    policy = checkpoint_policy()
    persistence = FakePersistence()
    persistence.advance_error = RuntimeError("synthetic progress failure")
    result = SourceExecutionResult(
        source_slug=policy.source_slug,
        status=ResultStatus.SUCCESS,
        counters=ReconciledCounters(fetched=1, created=1),
        progress_proposal=ProgressProposal(
            storage=policy.progress_storage,
            kind=policy.progress_kind,
            name=policy.progress_kind.value,
            value="next-content-hash",
            expected_previous_version=0,
        ),
        safe_message="Source data committed before progress.",
    )
    with pytest.raises(SourceRunIncomplete, match="progress recovery"):
        run_source_once(
            policy=policy,
            cycle_id=1,
            scheduled_for=SLOT,
            handler=SequenceHandler([result]),
            persistence=persistence,
            retry_sleep=lambda _: None,
        )
    evidence = persistence.read_cycle_evidence(1)
    assert evidence.sources_started == 1
    assert evidence.sources_completed == 0
    assert evidence.incomplete_source_slugs == (policy.source_slug,)
