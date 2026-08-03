from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime

import pytest

from app.ingestion.source_registry import list_enabled_implemented_sources
from app.orchestration.contracts import (
    ClassifiedFailure,
    ContractValidationError,
    CycleEvidence,
    CycleResult,
    CycleStatus,
    EligibilityMode,
    FailureCategory,
    ProgressKind,
    ProgressProposal,
    ProgressStorage,
    ReconciledCounters,
    ResultStatus,
    RetryPlan,
    SafeMetrics,
    SourcePolicy,
    SourceExecutionResult,
    build_source_policies,
    classify_failure,
    list_source_policies,
    sanitize_diagnostic,
)


def test_exact_result_vocabulary_is_preserved() -> None:
    assert {status.value for status in ResultStatus} == {
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
    }


def test_enabled_implemented_sources_have_exactly_one_deterministic_policy() -> None:
    expected = tuple(
        source.slug for source in list_enabled_implemented_sources()
    )
    policies = list_source_policies()
    assert tuple(policy.source_slug for policy in policies) == tuple(sorted(expected))
    assert len(policies) == len(set(expected))
    assert all(policy.source_concurrency_limit == 1 for policy in policies)
    assert tuple(policy.stagger_seconds for policy in policies) == tuple(
        index * 5 for index in range(len(policies))
    )


def test_policies_are_immutable_and_strictly_bounded() -> None:
    policy = list_source_policies()[0]
    with pytest.raises((FrozenInstanceError, AttributeError)):
        policy.stagger_seconds = 1  # type: ignore[misc]
    with pytest.raises(ContractValidationError):
        replace(policy, source_concurrency_limit=2)
    with pytest.raises(ContractValidationError):
        replace(policy, stagger_seconds=301)
    with pytest.raises(ContractValidationError):
        replace(policy, source_slug="unknown-source")
    with pytest.raises(ContractValidationError):
        RetryPlan(maximum_attempts=3, delays_seconds=(20, 10))
    with pytest.raises(ContractValidationError):
        RetryPlan(maximum_attempts=11, delays_seconds=tuple(range(1, 11)))


def test_policy_builder_rejects_duplicates_and_missing_sources() -> None:
    policies = list_source_policies()
    with pytest.raises(ContractValidationError, match="duplicated"):
        build_source_policies((*policies, policies[0]))
    with pytest.raises(ContractValidationError, match="exactly one"):
        build_source_policies(policies[:-1])


def test_progress_contracts_are_typed_bounded_and_utc() -> None:
    proposal = ProgressProposal(
        storage=ProgressStorage.WATERMARK,
        kind=ProgressKind.MODIFIED_SINCE,
        name="modified_since",
        value=datetime(2026, 8, 3, 12, tzinfo=UTC),
        expected_previous_version=0,
    )
    assert proposal.value.tzinfo is UTC
    with pytest.raises(ContractValidationError):
        replace(proposal, value=datetime(2026, 8, 3, 12))
    with pytest.raises(ContractValidationError):
        ProgressProposal(
            storage=ProgressStorage.CHECKPOINT,
            kind=ProgressKind.SOURCE_CURSOR,
            name="source_cursor",
            value="x" * 501,
            expected_previous_version=0,
        )


def test_counters_and_metrics_are_reconciled_and_bounded() -> None:
    assert ReconciledCounters(fetched=2, created=1, unchanged=1).fetched == 2
    with pytest.raises(ContractValidationError):
        ReconciledCounters(fetched=1)
    with pytest.raises(ContractValidationError):
        ReconciledCounters(fetched=True, created=True)
    with pytest.raises(ContractValidationError):
        SafeMetrics(request_count=10_001)


@pytest.mark.parametrize(
    "unsafe",
    (
        "Authorization: Bearer synthetic-value",
        "cookie=session-value",
        "Traceback (most recent call last):",
        "SELECT value FROM protected_table",
        "https://unapproved.example/path",
        "message\x00tail",
    ),
)
def test_diagnostics_are_bounded_and_sanitized(unsafe: str) -> None:
    with pytest.raises(ContractValidationError) as exc_info:
        sanitize_diagnostic(unsafe)
    assert unsafe not in str(exc_info.value)


def test_unknown_failures_are_permanent_and_allow_list_is_closed() -> None:
    unknown = classify_failure(RuntimeError("raw provider details"))
    assert unknown.category is FailureCategory.CONTRACT_VIOLATION
    assert unknown.transient is False
    assert "raw provider details" not in unknown.safe_message

    transient = classify_failure(
        ClassifiedFailure(
            FailureCategory.RETRYABLE_SERVER_RESPONSE,
            "The provider returned a retryable server response.",
        )
    )
    assert transient.transient is True


def test_manual_catalogue_policies_remain_non_scheduled() -> None:
    assert all(
        policy.eligibility_mode is EligibilityMode.MANUAL_ONLY
        for policy in list_source_policies()
        if policy.source_slug
        in {
            "anomali-cyber-watch",
            "censys-arc-research",
            "censys-rapid-response-advisories",
            "ibm-x-force-public-osint-advisories",
            "ibm-x-force-public-research",
        }
    )


def test_cycle_contracts_reject_synthetic_or_contradictory_results() -> None:
    slug = list_source_policies()[0].source_slug
    failed = SourceExecutionResult(
        source_slug=slug,
        status=ResultStatus.FAILED,
        safe_message="The committed source failed safely.",
    )
    with pytest.raises(ContractValidationError, match="status conflicts"):
        CycleResult(
            cycle_id=1,
            status=CycleStatus.SUCCESS,
            sources_expected=1,
            sources_started=1,
            sources_completed=1,
            sources_successful=0,
            sources_non_successful=1,
            source_results=(failed,),
        )
    with pytest.raises(ContractValidationError, match="evidence outcomes"):
        CycleEvidence(
            cycle_id=1,
            sources_expected=1,
            sources_started=1,
            sources_completed=1,
            sources_successful=1,
            sources_non_successful=0,
            source_results=(failed,),
        )
