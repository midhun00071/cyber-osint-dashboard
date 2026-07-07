"""Manual, bounded NVD ingestion command with sanitized audit records."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
import sys
import time
from typing import TextIO

from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_session_factory
from app.ingestion.collectors.nvd_client import (
    AUTHENTICATED_DELAY_SECONDS,
    NvdClient,
    NvdClientError,
    UNAUTHENTICATED_DELAY_SECONDS,
)
from app.ingestion.normalizers.nvd import NvdNormalizationError, normalize_nvd_cve
from app.ingestion.services.nvd_ingestion_service import (
    NvdIngestionService,
    NvdPersistenceError,
    NvdPersistenceResult,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord


DEFAULT_WINDOW_MINUTES = 60
DEFAULT_RESULTS_PER_PAGE = 25
DEFAULT_MAX_RECORDS = 25
MIN_WINDOW_MINUTES = 1
MAX_WINDOW_MINUTES = 1440
MIN_RESULTS_PER_PAGE = 1
MAX_RESULTS_PER_PAGE = 100
MIN_MAX_RECORDS = 1
MAX_MAX_RECORDS = 100


class CliArgumentError(ValueError):
    """The manual ingestion command arguments were invalid."""


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CliArgumentError("Invalid manual NVD ingestion arguments.")


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
        description="Manually fetch and store a bounded window of public NVD CVEs.",
    )
    parser.add_argument(
        "--window-minutes",
        type=_bounded_integer("window minutes", 1, 1440),
        default=DEFAULT_WINDOW_MINUTES,
    )
    parser.add_argument(
        "--results-per-page",
        type=_bounded_integer("results per page", 1, 100),
        default=DEFAULT_RESULTS_PER_PAGE,
    )
    parser.add_argument(
        "--max-records",
        type=_bounded_integer("maximum records", 1, 100),
        default=DEFAULT_MAX_RECORDS,
    )
    return parser


def _valid_integer(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def run_ingestion(
    *,
    window_minutes: int,
    results_per_page: int,
    max_records: int,
    api_key: SecretStr | None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    client_factory: Callable[..., NvdClient] = NvdClient,
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    normalizer: Callable = normalize_nvd_cve,
    service_factory: Callable[..., NvdIngestionService] = NvdIngestionService,
    sleeper: Callable[[float], None] = time.sleep,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run one caller-transactional manual ingestion and return an exit code."""

    if not (
        _valid_integer(window_minutes, MIN_WINDOW_MINUTES, MAX_WINDOW_MINUTES)
        and _valid_integer(
            results_per_page,
            MIN_RESULTS_PER_PAGE,
            MAX_RESULTS_PER_PAGE,
        )
        and _valid_integer(max_records, MIN_MAX_RECORDS, MAX_MAX_RECORDS)
    ):
        print("Invalid manual NVD ingestion parameters.", file=stderr)
        return 2

    end = clock()
    if end.tzinfo is None or end.utcoffset() is None:
        print("Manual NVD ingestion requires a timezone-aware clock.", file=stderr)
        return 1
    end = end.astimezone(UTC)
    start = end - timedelta(minutes=window_minutes)
    session: Session | None = None

    try:
        session = session_factory()
        service = service_factory(session)
        source = service.ensure_source()
        run = IngestionRun(
            source=source,
            trigger_type="manual",
            status="running",
            started_at=end,
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
            safe_summary="Manual bounded NVD ingestion started.",
            created_at=end,
        )
        session.add(run)
        session.flush()

        capped = False
        fetch_failed = False
        start_index = 0
        with client_factory(api_key=api_key) as client:
            while run.records_fetched < max_records:
                remaining = max_records - run.records_fetched
                requested_page_size = min(results_per_page, remaining)
                try:
                    page = client.fetch_page(
                        last_modified_start=start,
                        last_modified_end=end,
                        start_index=start_index,
                        results_per_page=requested_page_size,
                    )
                except NvdClientError:
                    fetch_failed = True
                    _add_error(
                        session,
                        run,
                        "nvd_fetch_error",
                        "The NVD fetch did not complete.",
                        retryable=True,
                        occurred_at=end,
                    )
                    break

                if page.start_index != start_index:
                    fetch_failed = True
                    _add_error(
                        session,
                        run,
                        "nvd_fetch_error",
                        "The NVD response page did not match the requested index.",
                        retryable=True,
                        occurred_at=end,
                    )
                    break

                wrappers = page.vulnerabilities[:remaining]
                for wrapper in wrappers:
                    run.records_fetched += 1
                    outcome = _process_wrapper(
                        session,
                        run,
                        wrapper,
                        service,
                        normalizer,
                        end,
                    )
                    _increment_outcome(run, outcome)

                next_index = page.start_index + len(page.vulnerabilities)
                if next_index >= page.total_results:
                    break
                if not page.vulnerabilities or next_index <= start_index:
                    fetch_failed = True
                    _add_error(
                        session,
                        run,
                        "nvd_fetch_error",
                        "NVD pagination stopped before the requested window completed.",
                        retryable=True,
                        occurred_at=end,
                    )
                    break
                start_index = next_index
                if run.records_fetched >= max_records:
                    capped = True
                    break
                secret_value = (
                    api_key.get_secret_value() if api_key is not None else ""
                )
                delay = (
                    AUTHENTICATED_DELAY_SECONDS
                    if secret_value
                    else UNAUTHENTICATED_DELAY_SECONDS
                )
                sleeper(delay)

        if fetch_failed and run.records_fetched == 0:
            run.status = "failed"
        elif fetch_failed or run.records_failed > 0 or capped:
            run.status = "partial"
        else:
            run.status = "succeeded"

        run.completed_at = end
        run.error_count = len(run.errors)
        run.safe_summary = _safe_run_summary(run, capped)
        if run.status == "succeeded":
            checkpoint = end.isoformat().replace("+00:00", "Z")
            run.checkpoint_after = checkpoint
            source.checkpoint_value = checkpoint
            source.last_successful_fetch_at = end

        session.commit()
        _print_summary(run, capped, stdout)
        if run.status != "succeeded":
            print("Manual NVD ingestion completed with a controlled failure.", file=stderr)
            return 1
        return 0
    except (NvdPersistenceError, SQLAlchemyError):
        if session is not None:
            session.rollback()
        print("Manual NVD ingestion failed during a database operation.", file=stderr)
        return 1
    except Exception:
        if session is not None:
            session.rollback()
        print("Manual NVD ingestion failed unexpectedly.", file=stderr)
        return 1
    finally:
        if session is not None:
            session.close()


def _process_wrapper(
    session: Session,
    run: IngestionRun,
    wrapper: dict,
    service: NvdIngestionService,
    normalizer: Callable,
    observed_at: datetime,
) -> str:
    try:
        nested = session.begin_nested() if hasattr(session, "begin_nested") else nullcontext()
        with nested:
            normalized = normalizer(wrapper)
            result: NvdPersistenceResult = service.persist(
                normalized,
                observed_at=observed_at,
            )
            if result.outcome == "failed":
                raise NvdPersistenceError("The normalized NVD record conflicted.")
            session.add(
                IngestionRunRecord(
                    ingestion_run=run,
                    source_record=None,
                    intelligence_item=None,
                    action=result.outcome,
                    safe_detail=f"NVD CVE record {result.outcome}.",
                    processed_at=observed_at,
                )
            )
            return result.outcome
    except NvdNormalizationError:
        error_type = "nvd_normalization_error"
        message = "An NVD record failed normalization."
    except NvdPersistenceError:
        error_type = "nvd_persistence_error"
        message = "An NVD record could not be persisted safely."
    except SQLAlchemyError:
        error_type = "nvd_persistence_error"
        message = "An NVD record database operation failed."
    except Exception:
        error_type = "nvd_record_error"
        message = "An NVD record failed unexpectedly."

    failed_record = IngestionRunRecord(
        ingestion_run=run,
        source_record=None,
        intelligence_item=None,
        action="failed",
        safe_detail=message,
        processed_at=observed_at,
    )
    session.add(failed_record)
    session.add(
        IngestionError(
            ingestion_run=run,
            ingestion_run_record=failed_record,
            source_record=None,
            error_type=error_type,
            safe_message=message,
            retryable=False,
            retry_count=0,
            occurred_at=observed_at,
        )
    )
    return "failed"


def _add_error(
    session: Session,
    run: IngestionRun,
    error_type: str,
    message: str,
    *,
    retryable: bool,
    occurred_at: datetime,
) -> None:
    session.add(
        IngestionError(
            ingestion_run=run,
            ingestion_run_record=None,
            source_record=None,
            error_type=error_type,
            safe_message=message,
            retryable=retryable,
            retry_count=0,
            occurred_at=occurred_at,
        )
    )


def _increment_outcome(run: IngestionRun, outcome: str) -> None:
    if outcome == "created":
        run.records_created += 1
    elif outcome == "updated":
        run.records_updated += 1
    elif outcome == "unchanged":
        run.records_unchanged += 1
    else:
        run.records_failed += 1


def _safe_run_summary(run: IngestionRun, capped: bool) -> str:
    return (
        f"Manual NVD ingestion {run.status}; fetched={run.records_fetched}; "
        f"created={run.records_created}; updated={run.records_updated}; "
        f"unchanged={run.records_unchanged}; failed={run.records_failed}; "
        f"capped={str(capped).lower()}."
    )


def _print_summary(run: IngestionRun, capped: bool, stdout: TextIO) -> None:
    print("Manual NVD ingestion completed.", file=stdout)
    print(f"Run ID: {run.public_id}", file=stdout)
    print(f"Status: {run.status}", file=stdout)
    print(f"Fetched/processed: {run.records_fetched}", file=stdout)
    print(f"Created: {run.records_created}", file=stdout)
    print(f"Updated: {run.records_updated}", file=stdout)
    print(f"Unchanged: {run.records_unchanged}", file=stdout)
    print(f"Failed: {run.records_failed}", file=stdout)
    print(f"Capped: {str(capped).lower()}", file=stdout)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _build_parser().parse_args(argv)
    except CliArgumentError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    settings = get_settings()
    return run_ingestion(
        window_minutes=arguments.window_minutes,
        results_per_page=arguments.results_per_page,
        max_records=arguments.max_records,
        api_key=settings.nvd_api_key,
    )


if __name__ == "__main__":
    raise SystemExit(main())
