"""Manual complete-catalog reconciliation of local CISA KEV status."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
import sys
from typing import TextIO

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.ingestion.collectors.cisa_kev_client import (
    CISA_KEV_CATALOG_URL,
    CisaKevClient,
    CisaKevClientError,
)
from app.ingestion.services.cisa_kev_ingestion_service import (
    CisaKevIngestionService,
    CisaKevPersistenceError,
)
from app.ingestion.services.cisa_kev_reconciliation_service import (
    CisaKevCatalogValidationError,
    CisaKevReconciliationPersistenceError,
    CisaKevReconciliationResult,
    CisaKevReconciliationService,
    ValidatedCisaKevCatalog,
    validate_complete_cisa_kev_catalog,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord
from app.models.common import utc_now


DEFAULT_MAX_CVES = 500
MIN_MAX_CVES = 1
MAX_MAX_CVES = 500
DEFAULT_BATCH_SIZE = 100
MIN_BATCH_SIZE = 1
MAX_BATCH_SIZE = 100
SOURCE_SLUG = "cisa-kev"


@dataclass(frozen=True)
class CatalogPreparationFailure:
    """Sanitized complete-catalog failure suitable for persisted audit."""

    error_type: str
    safe_message: str
    retryable: bool


class CliArgumentError(ValueError):
    """The manual CISA KEV reconciliation arguments were invalid."""


class CisaKevReconciliationClockError(RuntimeError):
    """The injected workflow clock did not return a safe ordered UTC time."""


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CliArgumentError(
            "Invalid manual CISA KEV reconciliation arguments."
        )


def _bounded_integer(name: str, minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer.") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}."
            )
        return parsed

    return parse


def _build_parser() -> CliArgumentParser:
    parser = CliArgumentParser(
        description=(
            "Manually reconcile bounded local CVEs against one completely "
            "validated CISA KEV catalog."
        )
    )
    parser.add_argument(
        "--max-cves",
        type=_bounded_integer("maximum CVEs", MIN_MAX_CVES, MAX_MAX_CVES),
        default=DEFAULT_MAX_CVES,
    )
    parser.add_argument(
        "--batch-size",
        type=_bounded_integer("batch size", MIN_BATCH_SIZE, MAX_BATCH_SIZE),
        default=DEFAULT_BATCH_SIZE,
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Show the fixed bounded plan without network or database access.",
    )
    return parser


def _valid_integer(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _read_utc_time(
    clock: Callable[[], datetime],
    *,
    not_before: datetime | None = None,
) -> datetime:
    try:
        value = clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError("Invalid workflow clock value.")
        normalized = value.astimezone(UTC)
    except Exception as exc:
        raise CisaKevReconciliationClockError(
            "The manual CISA KEV reconciliation clock was invalid."
        ) from exc
    if not_before is not None and normalized < not_before:
        raise CisaKevReconciliationClockError(
            "The manual CISA KEV reconciliation clock moved backwards."
        )
    return normalized


def _result_status(result: CisaKevReconciliationResult) -> str:
    if result.failed:
        return "failed"
    if result.skipped or result.unknown_remaining:
        return "partial"
    return "succeeded"


def run_reconciliation(
    *,
    max_cves: int,
    batch_size: int,
    plan: bool = False,
    clock: Callable[[], datetime] = utc_now,
    client_factory: Callable[..., CisaKevClient] = CisaKevClient,
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    catalog_validator: Callable[[dict], ValidatedCisaKevCatalog] = (
        validate_complete_cisa_kev_catalog
    ),
    source_service_factory: Callable[..., CisaKevIngestionService] = (
        CisaKevIngestionService
    ),
    reconciliation_service_factory: Callable[
        ..., CisaKevReconciliationService
    ] = CisaKevReconciliationService,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run one caller-transactional local reconciliation and return an exit code."""

    if not (
        _valid_integer(max_cves, MIN_MAX_CVES, MAX_MAX_CVES)
        and _valid_integer(batch_size, MIN_BATCH_SIZE, MAX_BATCH_SIZE)
        and isinstance(plan, bool)
    ):
        print("Invalid manual CISA KEV reconciliation parameters.", file=stderr)
        return 2

    if plan:
        _print_plan(max_cves=max_cves, batch_size=batch_size, stdout=stdout)
        return 0

    try:
        started_at = _read_utc_time(clock)
    except CisaKevReconciliationClockError:
        print(
            "Manual CISA KEV reconciliation requires valid timezone-aware "
            "workflow timestamps.",
            file=stderr,
        )
        return 1

    prepared = _fetch_and_validate_catalog(
        client_factory=client_factory,
        catalog_validator=catalog_validator,
    )
    if isinstance(prepared, CatalogPreparationFailure):
        try:
            completed_at = _read_utc_time(clock, not_before=started_at)
        except CisaKevReconciliationClockError:
            print(
                "Manual CISA KEV reconciliation requires valid timezone-aware "
                "workflow timestamps.",
                file=stderr,
            )
            return 1
        return _record_catalog_failure(
            prepared,
            started_at=started_at,
            completed_at=completed_at,
            session_factory=session_factory,
            source_service_factory=source_service_factory,
            stdout=stdout,
            stderr=stderr,
        )
    validated = prepared

    session: Session | None = None
    try:
        session = session_factory()
        source_service = source_service_factory(session)
        source = source_service.ensure_source()
        run = IngestionRun(
            source=source,
            trigger_type="manual",
            status="running",
            started_at=started_at,
            completed_at=None,
            records_fetched=0,
            records_created=0,
            records_updated=0,
            records_unchanged=0,
            records_skipped=0,
            records_failed=0,
            error_count=0,
            checkpoint_before=source.checkpoint_value,
            checkpoint_after=None,
            safe_summary="Manual CISA KEV local reconciliation started.",
            created_at=started_at,
        )
        session.add(run)
        session.flush()

        checked_at = _read_utc_time(clock, not_before=started_at)
        result = reconciliation_service_factory(session).reconcile(
            validated.cve_ids,
            max_cves=max_cves,
            batch_size=batch_size,
            checked_at=checked_at,
        )
        _add_audit_records(session, run, result, checked_at)
        completed_at = _read_utc_time(clock, not_before=checked_at)
        run.records_fetched = result.inspected
        run.records_updated = result.updated
        run.records_unchanged = result.unchanged
        run.records_skipped = result.skipped
        run.records_failed = result.failed
        run.error_count = result.failed
        run.status = _result_status(result)
        run.completed_at = completed_at
        run.checkpoint_after = (
            f"catalog-version:{validated.catalog_version};"
            f"raw-records:{validated.raw_record_count};"
            f"unique-cves:{validated.cve_count}"
        )
        run.safe_summary = _safe_summary(run, result, validated)
        session.flush()
        session.commit()
        _print_summary(run, result, validated, stdout)
        if run.status == "partial":
            print(
                "Controlled partial result: one or more selected local rows "
                "were skipped or remain unknown.",
                file=stdout,
            )
        return 0 if run.status == "succeeded" else 1
    except CisaKevReconciliationClockError:
        if session is not None:
            session.rollback()
        print(
            "Manual CISA KEV reconciliation requires valid timezone-aware "
            "workflow timestamps.",
            file=stderr,
        )
        return 1
    except (
        CisaKevPersistenceError,
        CisaKevReconciliationPersistenceError,
        SQLAlchemyError,
    ):
        if session is not None:
            session.rollback()
        print(
            "Manual CISA KEV reconciliation failed during a database operation.",
            file=stderr,
        )
        return 1
    except Exception:
        if session is not None:
            session.rollback()
        print("Manual CISA KEV reconciliation failed unexpectedly.", file=stderr)
        return 1
    finally:
        if session is not None:
            session.close()


def _fetch_and_validate_catalog(
    *,
    client_factory: Callable[..., CisaKevClient],
    catalog_validator: Callable[[dict], ValidatedCisaKevCatalog],
) -> ValidatedCisaKevCatalog | CatalogPreparationFailure:
    try:
        with client_factory() as client:
            fetched = client.fetch_catalog()
        return catalog_validator(fetched.catalog)
    except CisaKevCatalogValidationError:
        return CatalogPreparationFailure(
            error_type="cisa_kev_catalog_validation_error",
            safe_message="The CISA KEV catalog failed complete validation.",
            retryable=False,
        )
    except CisaKevClientError:
        return CatalogPreparationFailure(
            error_type="cisa_kev_catalog_fetch_error",
            safe_message="The CISA KEV catalog fetch did not complete safely.",
            retryable=True,
        )
    except Exception:
        return CatalogPreparationFailure(
            error_type="cisa_kev_catalog_preparation_error",
            safe_message="The CISA KEV catalog could not be prepared safely.",
            retryable=False,
        )


def _record_catalog_failure(
    failure: CatalogPreparationFailure,
    *,
    started_at: datetime,
    completed_at: datetime,
    session_factory: Callable[[], Session],
    source_service_factory: Callable[..., CisaKevIngestionService],
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    """Persist only safe failure evidence; no reconciliation service is invoked."""

    session: Session | None = None
    try:
        session = session_factory()
        source = source_service_factory(session).ensure_source()
        run = IngestionRun(
            source=source,
            trigger_type="manual",
            status="failed",
            started_at=started_at,
            completed_at=completed_at,
            records_fetched=0,
            records_created=0,
            records_updated=0,
            records_unchanged=0,
            records_skipped=0,
            records_failed=0,
            error_count=1,
            checkpoint_before=source.checkpoint_value,
            checkpoint_after=None,
            safe_summary=(
                "Manual CISA KEV local reconciliation failed before local "
                "processing; full_catalog_validated=false."
            ),
            created_at=started_at,
        )
        session.add(run)
        session.add(
            IngestionError(
                ingestion_run=run,
                ingestion_run_record=None,
                source_record=None,
                error_type=failure.error_type,
                safe_message=failure.safe_message,
                retryable=failure.retryable,
                retry_count=0,
                occurred_at=completed_at,
            )
        )
        session.flush()
        session.commit()
        _print_failed_summary(run, stdout=stdout)
        print(failure.safe_message, file=stderr)
        return 1
    except (CisaKevPersistenceError, SQLAlchemyError):
        if session is not None:
            session.rollback()
        print(
            "Manual CISA KEV reconciliation failed during a database operation.",
            file=stderr,
        )
        return 1
    except Exception:
        if session is not None:
            session.rollback()
        print("Manual CISA KEV reconciliation failed unexpectedly.", file=stderr)
        return 1
    finally:
        if session is not None:
            session.close()


def _add_audit_records(
    session: Session,
    run: IngestionRun,
    result: CisaKevReconciliationResult,
    checked_at: datetime,
) -> None:
    for record in result.records:
        session.add(
            IngestionRunRecord(
                ingestion_run=run,
                source_record=None,
                intelligence_item_id=record.intelligence_item_id,
                action=record.outcome,
                safe_detail=record.safe_detail,
                processed_at=checked_at,
            )
        )


def _safe_summary(
    run: IngestionRun,
    result: CisaKevReconciliationResult,
    catalog: ValidatedCisaKevCatalog,
) -> str:
    return (
        f"Manual CISA KEV local reconciliation {run.status}; "
        f"catalog_version={catalog.catalog_version}; "
        f"catalog_raw_records={catalog.raw_record_count}; "
        f"catalog_unique_cves={catalog.cve_count}; "
        f"local_inspected={result.inspected}; "
        f"listed={result.listed}; not_listed={result.not_listed}; "
        f"updated={result.updated}; unchanged={result.unchanged}; "
        f"skipped={result.skipped}; failed={result.failed}; "
        f"unknown_remaining={result.unknown_remaining}; "
        "full_catalog_validated=true."
    )


def _print_plan(*, max_cves: int, batch_size: int, stdout: TextIO) -> None:
    print("Manual CISA KEV local reconciliation plan.", file=stdout)
    print(f"Approved source: {SOURCE_SLUG}", file=stdout)
    print(f"Fixed endpoint: {CISA_KEV_CATALOG_URL}", file=stdout)
    print(f"Local CVE limit: {max_cves}", file=stdout)
    print(f"Database batch size: {batch_size}", file=stdout)
    print("Network access: none (plan mode)", file=stdout)
    print("Database access: none (plan mode)", file=stdout)


def _print_failed_summary(run: IngestionRun, *, stdout: TextIO) -> None:
    print("Manual CISA KEV local reconciliation completed.", file=stdout)
    print(f"Run ID: {run.public_id}", file=stdout)
    print("Status: failed", file=stdout)
    print("Catalog raw record count: 0", file=stdout)
    print("Catalog unique CVE count: 0", file=stdout)
    print("Local CVEs inspected: 0", file=stdout)
    print("Listed: 0", file=stdout)
    print("Not listed: 0", file=stdout)
    print("Updated: 0", file=stdout)
    print("Unchanged: 0", file=stdout)
    print("Skipped: 0", file=stdout)
    print("Failed: 0", file=stdout)
    print("Unknown remaining in processed set: 0", file=stdout)
    print("Full catalog validated: false", file=stdout)
    print(f"Summary: {run.safe_summary}", file=stdout)


def _print_summary(
    run: IngestionRun,
    result: CisaKevReconciliationResult,
    catalog: ValidatedCisaKevCatalog,
    stdout: TextIO,
) -> None:
    print("Manual CISA KEV local reconciliation completed.", file=stdout)
    print(f"Run ID: {run.public_id}", file=stdout)
    print(f"Status: {run.status}", file=stdout)
    print(f"Catalog version: {catalog.catalog_version}", file=stdout)
    print(f"Catalog raw record count: {catalog.raw_record_count}", file=stdout)
    print(f"Catalog unique CVE count: {catalog.cve_count}", file=stdout)
    print(f"Local CVEs inspected: {result.inspected}", file=stdout)
    print(f"Listed: {result.listed}", file=stdout)
    print(f"Not listed: {result.not_listed}", file=stdout)
    print(f"Updated: {result.updated}", file=stdout)
    print(f"Unchanged: {result.unchanged}", file=stdout)
    print(f"Skipped: {result.skipped}", file=stdout)
    print(f"Failed: {result.failed}", file=stdout)
    print(
        f"Unknown remaining in processed set: {result.unknown_remaining}",
        file=stdout,
    )
    print("Full catalog validated: true", file=stdout)
    print(f"Summary: {run.safe_summary}", file=stdout)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _build_parser().parse_args(argv)
    except CliArgumentError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    return run_reconciliation(
        max_cves=arguments.max_cves,
        batch_size=arguments.batch_size,
        plan=arguments.plan,
    )


if __name__ == "__main__":
    raise SystemExit(main())
