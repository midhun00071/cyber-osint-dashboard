"""Deterministic, paused-by-default Prefect 3.8.1 deployment registration."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Callable, Iterable, Mapping
import os
from typing import Any

from prefect import get_client
from prefect.client.schemas.objects import (
    ConcurrencyLimitConfig,
    ConcurrencyLimitStrategy,
)
from prefect.client.schemas.schedules import CronSchedule
from prefect.deployments.runner import RunnerDeployment
from prefect.exceptions import ObjectNotFound

from app.orchestration.contracts import (
    ContractValidationError,
    DeploymentSpecification,
    EligibilityMode,
    SourceHandler,
    list_source_policies,
)
from app.orchestration.flows import (
    DEFAULT_SOURCE_HANDLERS,
    PARENT_FLOW_NAME,
    parent_ingestion_cycle,
)
from app.orchestration.persistence import DEPLOYMENT_REFERENCE


DEPLOYMENT_NAME = "alpha-data-ingestion-cycle"
WORK_POOL_NAME = "alpha-data-process"
CRON = "17 */2 * * *"
TIMEZONE = "Asia/Dubai"
DEPLOYMENT_CONCURRENCY = 1


def deployment_specification(*, paused: bool = True) -> DeploymentSpecification:
    return DeploymentSpecification(
        flow_name=PARENT_FLOW_NAME,
        deployment_name=DEPLOYMENT_NAME,
        work_pool_name=WORK_POOL_NAME,
        cron=CRON,
        timezone=TIMEZONE,
        concurrency_limit=DEPLOYMENT_CONCURRENCY,
        paused=paused,
        deployment_ref=DEPLOYMENT_REFERENCE,
    )


def build_runner_deployment(*, paused: bool = True) -> RunnerDeployment:
    """Build exactly one fixed schedule using APIs present in Prefect 3.8.1."""

    spec = deployment_specification(paused=paused)
    return RunnerDeployment.from_flow(
        flow=parent_ingestion_cycle,
        name=spec.deployment_name,
        schedule=CronSchedule(cron=spec.cron, timezone=spec.timezone),
        paused=spec.paused,
        concurrency_limit=ConcurrencyLimitConfig(
            limit=spec.concurrency_limit,
            collision_strategy=ConcurrencyLimitStrategy.CANCEL_NEW,
        ),
        parameters={},
        work_pool_name=spec.work_pool_name,
        description="C01 parent ingestion cycle; source bindings are supplied by C02.",
        tags=["alpha-data", "c01", "ingestion"],
    )


def validate_existing_schedules(schedules: Iterable[Any]) -> None:
    """Reject duplicate or conflicting schedules before applying the deployment."""

    rows = tuple(schedules)
    if len(rows) != 1:
        raise ContractValidationError(
            "The existing deployment must contain exactly one schedule."
        )
    schedule = getattr(rows[0], "schedule", rows[0])
    if not isinstance(schedule, CronSchedule):
        raise ContractValidationError("The existing deployment schedule type conflicts.")
    if schedule.cron != CRON or schedule.timezone != TIMEZONE:
        raise ContractValidationError("The existing deployment schedule conflicts.")


def validate_activation(
    *,
    activate: bool,
    app_env: str,
    controlled_staging_evidence_confirmed: bool,
    handlers: Mapping[str, SourceHandler],
    work_pool_valid: bool,
) -> None:
    """Fail closed unless every frozen staging activation gate is explicit."""

    if not activate:
        return
    if app_env.strip().casefold() != "staging":
        raise ContractValidationError("Deployment activation is staging-only.")
    if controlled_staging_evidence_confirmed is not True:
        raise ContractValidationError(
            "Controlled staging evidence must be explicitly confirmed."
        )
    if work_pool_valid is not True:
        raise ContractValidationError("The fixed process work pool is unavailable.")
    required = {
        policy.source_slug
        for policy in list_source_policies()
        if policy.eligibility_mode is EligibilityMode.SCHEDULED
    }
    allowed = {policy.source_slug for policy in list_source_policies()}
    if not set(handlers).issubset(allowed):
        raise ContractValidationError("An unknown source binding is configured.")
    if not required.issubset(handlers):
        raise ContractValidationError(
            "All scheduled-eligible source handlers must be bound before activation."
        )
    if any(not isinstance(handlers[slug], SourceHandler) for slug in required):
        raise ContractValidationError("A scheduled source binding is invalid.")


async def _read_existing_and_pool_valid(activate: bool) -> tuple[Any | None, bool]:
    async with get_client() as client:
        try:
            existing = await client.read_deployment_by_name(
                f"{PARENT_FLOW_NAME}/{DEPLOYMENT_NAME}"
            )
        except ObjectNotFound:
            existing = None
        pool_valid = not activate
        if activate:
            try:
                pool = await client.read_work_pool(WORK_POOL_NAME)
            except ObjectNotFound:
                pool_valid = False
            else:
                pool_valid = (
                    pool.name == WORK_POOL_NAME
                    and pool.type == "process"
                    and pool.is_paused is False
                )
        return existing, pool_valid


def register_deployment(
    *,
    activate: bool = False,
    controlled_staging_evidence_confirmed: bool = False,
    handlers: Mapping[str, SourceHandler] = DEFAULT_SOURCE_HANDLERS,
    app_env: str | None = None,
    inspect_existing: Callable[[bool], tuple[Any | None, bool]] | None = None,
    apply_deployment: Callable[[RunnerDeployment], Any] | None = None,
) -> Any:
    """Validate and idempotently apply the single fixed deployment."""

    if inspect_existing is None:
        existing, pool_valid = asyncio.run(_read_existing_and_pool_valid(activate))
    else:
        existing, pool_valid = inspect_existing(activate)
    if existing is not None:
        if getattr(existing, "name", DEPLOYMENT_NAME) != DEPLOYMENT_NAME:
            raise ContractValidationError("The existing deployment identity conflicts.")
        if getattr(existing, "work_pool_name", WORK_POOL_NAME) != WORK_POOL_NAME:
            raise ContractValidationError("The existing work-pool identity conflicts.")
        validate_existing_schedules(getattr(existing, "schedules", ()))
    validate_activation(
        activate=activate,
        app_env=app_env if app_env is not None else os.getenv("APP_ENV", "local"),
        controlled_staging_evidence_confirmed=controlled_staging_evidence_confirmed,
        handlers=handlers,
        work_pool_valid=pool_valid,
    )
    deployment = build_runner_deployment(paused=not activate)
    if apply_deployment is not None:
        return apply_deployment(deployment)
    return deployment.apply()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Register the fixed C01 Prefect deployment (paused by default)."
    )
    parser.add_argument("--activate", action="store_true")
    parser.add_argument(
        "--confirm-controlled-staging-evidence",
        action="store_true",
    )
    arguments = parser.parse_args(argv)
    register_deployment(
        activate=arguments.activate,
        controlled_staging_evidence_confirmed=(
            arguments.confirm_controlled_staging_evidence
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CRON",
    "DEPLOYMENT_CONCURRENCY",
    "DEPLOYMENT_NAME",
    "TIMEZONE",
    "WORK_POOL_NAME",
    "build_runner_deployment",
    "deployment_specification",
    "main",
    "register_deployment",
    "validate_activation",
    "validate_existing_schedules",
]
