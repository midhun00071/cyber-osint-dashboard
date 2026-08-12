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
PROCESS_WORKING_DIR = "/opt/alpha-data/backend"
CRON = "17 */2 * * *"
TIMEZONE = "Asia/Dubai"
DEPLOYMENT_CONCURRENCY = 1
EXPECTED_SCHEDULED_SOURCE_SLUGS = frozenset(
    {
        "cert-eu-security-advisories",
        "cisa-kev",
        "first-epss",
        "google-threat-intelligence-public-research",
        "mandiant-public-threat-research",
        "nvd",
    }
)


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
        job_variables={"working_dir": PROCESS_WORKING_DIR},
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


def resolve_registration_paused(*, activate: bool, existing: Any | None) -> bool:
    """Resolve registration state without changing an existing activation choice."""

    if activate:
        return False
    if existing is None:
        return True
    existing_paused = getattr(existing, "paused", None)
    if not isinstance(existing_paused, bool):
        raise ContractValidationError(
            "The existing deployment activation state is unavailable."
        )
    return existing_paused


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
    deployment = build_runner_deployment(
        paused=resolve_registration_paused(activate=activate, existing=existing)
    )
    if apply_deployment is not None:
        return apply_deployment(deployment)
    return deployment.apply()


def validate_registered_runtime(
    *,
    deployment: Any,
    work_pool: Any,
    workers: Iterable[Any],
    handlers: Mapping[str, SourceHandler] = DEFAULT_SOURCE_HANDLERS,
    expected_paused: bool | None = None,
) -> None:
    """Validate durable deployment, pool, worker, and source bindings."""

    if getattr(work_pool, "name", None) != WORK_POOL_NAME:
        raise ContractValidationError("The fixed process work pool is unavailable.")
    if getattr(work_pool, "type", None) != "process" or getattr(
        work_pool, "is_paused", True
    ):
        raise ContractValidationError("The fixed process work pool is unavailable.")
    if getattr(work_pool, "default_queue_id", None) is None:
        raise ContractValidationError("The fixed work queue is unavailable.")

    online_workers = tuple(
        worker
        for worker in workers
        if str(getattr(getattr(worker, "status", None), "value", "")).casefold()
        == "online"
    )
    if not online_workers:
        raise ContractValidationError("No online worker is polling the fixed work pool.")

    if getattr(deployment, "name", None) != DEPLOYMENT_NAME:
        raise ContractValidationError("The registered deployment identity conflicts.")
    if getattr(deployment, "work_pool_name", None) != WORK_POOL_NAME:
        raise ContractValidationError("The registered deployment work pool conflicts.")
    if getattr(deployment, "work_queue_name", None) in {None, ""}:
        raise ContractValidationError("The registered deployment queue is unavailable.")
    paused = getattr(deployment, "paused", None)
    if not isinstance(paused, bool):
        raise ContractValidationError(
            "The registered deployment activation state is unavailable."
        )
    if expected_paused is not None and paused is not expected_paused:
        raise ContractValidationError(
            "The registered deployment activation state conflicts."
        )
    validate_existing_schedules(getattr(deployment, "schedules", ()))
    if getattr(deployment, "job_variables", None) != {
        "working_dir": PROCESS_WORKING_DIR
    }:
        raise ContractValidationError("The registered process working directory conflicts.")
    entrypoint = str(getattr(deployment, "entrypoint", "")).replace("\\", "/")
    if entrypoint != "app/orchestration/flows.py:parent_ingestion_cycle":
        raise ContractValidationError("The registered deployment entrypoint conflicts.")

    if frozenset(handlers) != EXPECTED_SCHEDULED_SOURCE_SLUGS:
        raise ContractValidationError("The scheduled source bindings conflict.")
    if any(not isinstance(handler, SourceHandler) for handler in handlers.values()):
        raise ContractValidationError("A scheduled source binding is invalid.")


async def _read_registered_runtime() -> tuple[Any, Any, tuple[Any, ...]]:
    async with get_client() as client:
        deployment = await client.read_deployment_by_name(
            f"{PARENT_FLOW_NAME}/{DEPLOYMENT_NAME}"
        )
        work_pool = await client.read_work_pool(WORK_POOL_NAME)
        workers = tuple(
            await client.read_workers_for_work_pool(WORK_POOL_NAME, limit=100)
        )
        return deployment, work_pool, workers


def verify_registered_runtime(
    *,
    inspect_runtime: Callable[[], tuple[Any, Any, tuple[Any, ...]]] | None = None,
    expected_paused: bool | None = None,
) -> None:
    """Read and validate the registered runtime without executing a flow."""

    if inspect_runtime is None:
        deployment, work_pool, workers = asyncio.run(_read_registered_runtime())
    else:
        deployment, work_pool, workers = inspect_runtime()
    validate_registered_runtime(
        deployment=deployment,
        work_pool=work_pool,
        workers=workers,
        expected_paused=expected_paused,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Register the fixed C01 Prefect deployment (paused by default)."
    )
    parser.add_argument("--activate", action="store_true")
    parser.add_argument(
        "--confirm-controlled-staging-evidence",
        action="store_true",
    )
    parser.add_argument(
        "--verify-registration",
        action="store_true",
        help="Verify the registered deployment without changing activation state.",
    )
    parser.add_argument(
        "--verify-paused",
        action="store_true",
        help="Verify the registered paused deployment without running it.",
    )
    arguments = parser.parse_args(argv)
    if arguments.verify_registration and arguments.verify_paused:
        parser.error("Choose only one deployment verification mode.")
    if (arguments.verify_registration or arguments.verify_paused) and (
        arguments.activate or arguments.confirm_controlled_staging_evidence
    ):
        parser.error("Verification cannot be combined with activation options.")
    try:
        if arguments.verify_registration or arguments.verify_paused:
            verify_registered_runtime(
                expected_paused=True if arguments.verify_paused else None
            )
            state_description = (
                "paused deployment"
                if arguments.verify_paused
                else "deployment activation state"
            )
            print(
                f"PASS Prefect pool, worker, queue, {state_description}, schedule, "
                "working directory, and six bindings are valid."
            )
        else:
            register_deployment(
                activate=arguments.activate,
                controlled_staging_evidence_confirmed=(
                    arguments.confirm_controlled_staging_evidence
                ),
            )
            print("PASS Prefect deployment registration completed.")
    except (ContractValidationError, ObjectNotFound):
        print("BLOCKED Prefect deployment integrity validation failed.")
        return 1
    except Exception:
        print("BLOCKED Prefect deployment registration could not complete safely.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CRON",
    "DEPLOYMENT_CONCURRENCY",
    "DEPLOYMENT_NAME",
    "EXPECTED_SCHEDULED_SOURCE_SLUGS",
    "PROCESS_WORKING_DIR",
    "TIMEZONE",
    "WORK_POOL_NAME",
    "build_runner_deployment",
    "deployment_specification",
    "main",
    "register_deployment",
    "resolve_registration_paused",
    "validate_activation",
    "validate_existing_schedules",
    "validate_registered_runtime",
    "verify_registered_runtime",
]
