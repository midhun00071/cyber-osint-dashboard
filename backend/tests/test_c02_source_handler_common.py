from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime

import pytest

from app.models import IngestionRunRecord
from app.orchestration.contracts import (
    ContractValidationError,
    ProgressKind,
    ProgressProposal,
    ProgressStorage,
    QuotaObservation,
    ReconciledCounters,
    ResultStatus,
    SOURCE_POLICIES,
    SafeMetrics,
    SourceAttemptIdentity,
    SourceExecutionContext,
    SourceExecutionResult,
)
from app.orchestration.source_handlers import (
    C02_BOUND_SOURCE_SLUGS,
    build_c02_source_handlers,
)
from app.orchestration.source_handlers.common import (
    EVIDENCE_PREFIX,
    OutcomeEvidence,
    counters_from_outcomes,
    load_execution_evidence,
    persist_execution_evidence,
    reconstruct_progress_from_evidence,
    status_for_counters,
)


SLOT = datetime(2026, 8, 3, 8, 17, tzinfo=UTC)


class ScalarRows:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values


class FakeSession:
    def __init__(self):
        self.records: list[IngestionRunRecord] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def begin(self):
        return nullcontext()

    def add(self, record):
        self.records.append(record)

    def execute(self, statement):
        del statement
        return ScalarRows(
            [
                record.safe_detail
                for record in self.records
                if record.safe_detail.startswith(EVIDENCE_PREFIX)
            ]
        )


def context(source_slug: str, *, run_id: int = 11) -> SourceExecutionContext:
    policy = SOURCE_POLICIES[source_slug]
    return SourceExecutionContext(
        policy=policy,
        attempt=SourceAttemptIdentity(source_slug, 7, run_id, 0, 1),
        scheduled_for=SLOT,
        deployment_ref="alpha-data-ingestion-cycle",
        progress=None,
        quota=QuotaObservation(policy.quota_policy_key),
    )


def test_c02_builder_is_immutable_and_binds_only_six_flow_ready_sources() -> None:
    handlers = build_c02_source_handlers(session_factory=FakeSession)

    assert frozenset(handlers) == C02_BOUND_SOURCE_SLUGS
    assert len(handlers) == 6
    with pytest.raises(TypeError):
        handlers["nvd"] = handlers["nvd"]  # type: ignore[index]


def test_manual_only_sources_remain_unbound() -> None:
    assert C02_BOUND_SOURCE_SLUGS.isdisjoint(
        {
            "anomali-cyber-watch",
            "censys-arc-research",
            "censys-rapid-response-advisories",
            "ibm-x-force-public-research",
            "ibm-x-force-public-osint-advisories",
        }
    )


@pytest.mark.parametrize(
    ("outcomes", "status"),
    [
        (("created", "unchanged"), ResultStatus.SUCCESS),
        (("unchanged",), ResultStatus.NO_CHANGE),
        (("created", "failed"), ResultStatus.PARTIAL),
        (("skipped",), ResultStatus.FAILED),
        ((), ResultStatus.NO_CHANGE),
    ],
)
def test_outcome_counters_and_status_are_reconciled(outcomes, status) -> None:
    counters = counters_from_outcomes(outcomes)

    assert counters.fetched == len(outcomes)
    assert status_for_counters(counters) is status


def test_outcome_evidence_rejects_unbounded_or_unknown_values() -> None:
    with pytest.raises(ContractValidationError):
        OutcomeEvidence(outcome="success")
    with pytest.raises(ContractValidationError):
        OutcomeEvidence(outcome="failed", safe_detail="x" * 1001)


def test_execution_evidence_round_trips_watermark_without_network_state() -> None:
    session = FakeSession()
    execution_context = context("nvd")
    counters = ReconciledCounters(fetched=1, unchanged=1)
    proposal = ProgressProposal(
        storage=ProgressStorage.WATERMARK,
        kind=ProgressKind.MODIFIED_SINCE,
        name="modified_since",
        value=SLOT,
        expected_previous_version=0,
    )
    result = SourceExecutionResult(
        source_slug="nvd",
        status=ResultStatus.NO_CHANGE,
        counters=counters,
        metrics=SafeMetrics(request_count=1, page_count=1),
        progress_proposal=proposal,
    )
    persist_execution_evidence(session, context=execution_context, result=result)

    recovered = load_execution_evidence(lambda: session, execution_context)
    reconstructed = reconstruct_progress_from_evidence(
        lambda: session,
        execution_context,
        counters,
    )

    assert recovered == result.__class__(
        source_slug="nvd",
        status=ResultStatus.NO_CHANGE,
        counters=counters,
        metrics=result.metrics,
        safe_message="Previously committed bounded source evidence was reused.",
        progress_proposal=proposal,
    )
    assert reconstructed == proposal


def test_reconstruction_fails_closed_on_counter_conflict() -> None:
    session = FakeSession()
    execution_context = context("first-epss")
    result = SourceExecutionResult(
        source_slug="first-epss",
        status=ResultStatus.NO_CHANGE,
        progress_proposal=ProgressProposal(
            storage=ProgressStorage.WATERMARK,
            kind=ProgressKind.MODIFIED_SINCE,
            name="modified_since",
            value=SLOT,
            expected_previous_version=0,
        ),
    )
    persist_execution_evidence(session, context=execution_context, result=result)

    with pytest.raises(Exception, match="unavailable or conflicting"):
        reconstruct_progress_from_evidence(
            lambda: session,
            execution_context,
            ReconciledCounters(fetched=1, unchanged=1),
        )
