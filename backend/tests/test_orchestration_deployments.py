from __future__ import annotations

from inspect import signature
from types import SimpleNamespace

import pytest
from prefect.client.schemas.objects import ConcurrencyLimitStrategy
from prefect.client.schemas.schedules import CronSchedule

from app.orchestration.contracts import (
    ContractValidationError,
    EligibilityMode,
    list_source_policies,
)
from app.orchestration.deployments import (
    CRON,
    DEPLOYMENT_CONCURRENCY,
    DEPLOYMENT_NAME,
    PROCESS_WORKING_DIR,
    TIMEZONE,
    WORK_POOL_NAME,
    build_runner_deployment,
    deployment_specification,
    register_deployment,
    validate_activation,
    validate_existing_schedules,
)
from app.orchestration.flows import DEFAULT_SOURCE_HANDLERS, PARENT_FLOW_NAME
from app.orchestration.source_handlers import C02_BOUND_SOURCE_SLUGS


class FakeHandler:
    def execute(self, context):
        raise AssertionError("registration must not execute a source handler")

    def reconstruct_progress(self, context, committed_counters):
        raise AssertionError("registration must not reconstruct source progress")


def scheduled_bindings():
    return {
        policy.source_slug: FakeHandler()
        for policy in list_source_policies()
        if policy.eligibility_mode is EligibilityMode.SCHEDULED
    }


def test_fixed_deployment_contract_is_exact_and_paused_by_default() -> None:
    spec = deployment_specification()
    assert (
        spec.flow_name,
        spec.deployment_name,
        spec.work_pool_name,
        spec.cron,
        spec.timezone,
        spec.concurrency_limit,
        spec.paused,
    ) == (
        PARENT_FLOW_NAME,
        DEPLOYMENT_NAME,
        WORK_POOL_NAME,
        CRON,
        TIMEZONE,
        DEPLOYMENT_CONCURRENCY,
        True,
    )

    deployment = build_runner_deployment()
    assert deployment.name == DEPLOYMENT_NAME
    assert deployment.work_pool_name == WORK_POOL_NAME
    assert deployment.job_variables == {
        "working_dir": "/opt/alpha-data/backend"
    } == {"working_dir": PROCESS_WORKING_DIR}
    assert deployment.entrypoint.replace("\\", "/") == (
        "app/orchestration/flows.py:parent_ingestion_cycle"
    )
    assert deployment.parameters == {}
    assert deployment.paused is True
    assert deployment.concurrency_limit == 1
    assert (
        deployment.concurrency_options.collision_strategy
        is ConcurrencyLimitStrategy.CANCEL_NEW
    )
    assert len(deployment.schedules) == 1
    schedule = deployment.schedules[0].schedule
    assert (schedule.cron, schedule.timezone) == (CRON, TIMEZONE)


def test_working_directory_is_fixed_and_not_accepted_from_callers() -> None:
    assert PROCESS_WORKING_DIR == "/opt/alpha-data/backend"
    assert "working_dir" not in signature(build_runner_deployment).parameters
    assert "working_dir" not in signature(register_deployment).parameters


def test_duplicate_or_conflicting_schedules_fail_closed() -> None:
    fixed = SimpleNamespace(schedule=CronSchedule(cron=CRON, timezone=TIMEZONE))
    validate_existing_schedules([fixed])
    with pytest.raises(ContractValidationError, match="exactly one"):
        validate_existing_schedules([])
    with pytest.raises(ContractValidationError, match="exactly one"):
        validate_existing_schedules([fixed, fixed])
    with pytest.raises(ContractValidationError, match="conflicts"):
        validate_existing_schedules(
            [SimpleNamespace(schedule=CronSchedule(cron="0 * * * *", timezone=TIMEZONE))]
        )


@pytest.mark.parametrize(
    "app_env,confirmed,handlers,pool_valid",
    (
        ("production", True, scheduled_bindings(), True),
        ("staging", False, scheduled_bindings(), True),
        ("staging", True, {}, True),
        ("staging", True, scheduled_bindings(), False),
    ),
)
def test_activation_gates_fail_closed(app_env, confirmed, handlers, pool_valid) -> None:
    with pytest.raises(ContractValidationError):
        validate_activation(
            activate=True,
            app_env=app_env,
            controlled_staging_evidence_confirmed=confirmed,
            handlers=handlers,
            work_pool_valid=pool_valid,
        )


def test_paused_registration_is_idempotent_and_does_not_run_sources() -> None:
    applied = []
    existing = SimpleNamespace(
        name=DEPLOYMENT_NAME,
        work_pool_name=WORK_POOL_NAME,
        schedules=[
            SimpleNamespace(
                schedule=CronSchedule(cron=CRON, timezone=TIMEZONE)
            )
        ],
    )

    result = register_deployment(
        inspect_existing=lambda activate: (existing, not activate),
        apply_deployment=lambda deployment: applied.append(deployment) or "fixed-id",
    )

    assert result == "fixed-id"
    assert len(applied) == 1
    assert applied[0].paused is True
    assert applied[0].job_variables == {
        "working_dir": "/opt/alpha-data/backend"
    }
    assert len(applied[0].schedules) == 1


def test_activation_contract_can_pass_only_with_all_explicit_staging_gates() -> None:
    validate_activation(
        activate=True,
        app_env="staging",
        controlled_staging_evidence_confirmed=True,
        handlers=scheduled_bindings(),
        work_pool_valid=True,
    )


def test_exact_production_bindings_satisfy_activation_completeness_validation() -> None:
    expected_scheduled_sources = frozenset(
        {
            "cert-eu-security-advisories",
            "cisa-kev",
            "first-epss",
            "google-threat-intelligence-public-research",
            "mandiant-public-threat-research",
            "nvd",
        }
    )
    scheduled_policy_sources = frozenset(
        policy.source_slug
        for policy in list_source_policies()
        if policy.eligibility_mode is EligibilityMode.SCHEDULED
    )
    assert C02_BOUND_SOURCE_SLUGS == expected_scheduled_sources
    assert frozenset(DEFAULT_SOURCE_HANDLERS) == expected_scheduled_sources
    assert scheduled_policy_sources == expected_scheduled_sources
    validate_activation(
        activate=True,
        app_env="staging",
        controlled_staging_evidence_confirmed=True,
        handlers=DEFAULT_SOURCE_HANDLERS,
        work_pool_valid=True,
    )


def test_missing_production_binding_fails_activation_closed() -> None:
    handlers = dict(DEFAULT_SOURCE_HANDLERS)
    handlers.pop("nvd")
    with pytest.raises(ContractValidationError, match="must be bound"):
        validate_activation(
            activate=True,
            app_env="staging",
            controlled_staging_evidence_confirmed=True,
            handlers=handlers,
            work_pool_valid=True,
        )


def test_unknown_extra_binding_fails_activation_closed() -> None:
    handlers = dict(DEFAULT_SOURCE_HANDLERS)
    handlers["unapproved-source"] = FakeHandler()
    with pytest.raises(ContractValidationError, match="unknown source binding"):
        validate_activation(
            activate=True,
            app_env="staging",
            controlled_staging_evidence_confirmed=True,
            handlers=handlers,
            work_pool_valid=True,
        )


def test_invalid_required_handler_fails_activation_closed() -> None:
    handlers = dict(DEFAULT_SOURCE_HANDLERS)
    handlers["nvd"] = object()
    with pytest.raises(ContractValidationError, match="binding is invalid"):
        validate_activation(
            activate=True,
            app_env="staging",
            controlled_staging_evidence_confirmed=True,
            handlers=handlers,  # type: ignore[arg-type]
            work_pool_valid=True,
        )
