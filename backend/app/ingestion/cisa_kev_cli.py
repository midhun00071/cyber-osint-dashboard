"""Manual, bounded CISA KEV enrichment command with sanitized audit records."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from datetime import UTC, datetime
import sys
from typing import TextIO

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.ingestion.collectors.cisa_kev_client import (
    CisaKevClient,
    CisaKevClientError,
    CisaKevContentTypeError,
    CisaKevFetchResult,
    CisaKevHttpError,
    CisaKevRateLimitError,
    CisaKevRedirectError,
    CisaKevRequestError,
    CisaKevResponseError,
    CisaKevResponseTooLargeError,
)
from app.ingestion.normalizers.cisa_kev import (
    CisaKevNormalizationError,
    NormalizedCisaKevEntry,
    extract_cisa_kev_entries,
    normalize_cisa_kev_entry,
)
from app.ingestion.services.cisa_kev_ingestion_service import (
    CisaKevIngestionService,
    CisaKevPersistenceError,
    CisaKevPersistenceResult,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord
from app.models.common import utc_now


DEFAULT_MAX_RECORDS = 25
MIN_MAX_RECORDS = 1
MAX_MAX_RECORDS = 500


class CliArgumentError(ValueError):
    """The manual CISA KEV command arguments were invalid."""


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CliArgumentError("Invalid manual CISA KEV ingestion arguments.")


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
        description="Manually enrich existing local CVEs with public CISA KEV status.",
    )
    parser.add_argument(
        "--max-records",
        type=_bounded_integer("maximum records", MIN_MAX_RECORDS, MAX_MAX_RECORDS),
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
    max_records: int,
    clock: Callable[[], datetime] = utc_now,
    client_factory: Callable[..., CisaKevClient] = CisaKevClient,
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    catalog_entry_extractor: Callable[[dict], list[dict]] = extract_cisa_kev_entries,
    entry_normalizer: Callable[[dict], NormalizedCisaKevEntry] = normalize_cisa_kev_entry,
    service_factory: Callable[..., CisaKevIngestionService] = CisaKevIngestionService,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run one caller-transactional manual CISA KEV ingestion and return an exit code."""

    if not _valid_integer(max_records, MIN_MAX_RECORDS, MAX_MAX_RECORDS):
        print("Invalid manual CISA KEV ingestion parameters.", file=stderr)
        return 2

    observed_at = clock()
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        print("Manual CISA KEV ingestion requires a timezone-aware clock.", file=stderr)
        return 1
    observed_at = observed_at.astimezone(UTC)
    session: Session | None = None

    try:
        session = session_factory()
        service = service_factory(session)
        source = service.ensure_source()
        run = IngestionRun(
            source=source,
            trigger_type="manual",
            status="running",
            started_at=observed_at,
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
            safe_summary="Manual bounded CISA KEV ingestion started.",
            created_at=observed_at,
        )
        session.add(run)
        session.flush()

        capped = False
        fetch_failed = False
        catalog = _fetch_catalog(client_factory, session, run, observed_at)
        if catalog is None:
            fetch_failed = True
        else:
            entries = _extract_entries(
                catalog,
                session,
                run,
                catalog_entry_extractor,
                observed_at,
            )
            if entries is not None:
                capped = len(entries) > max_records
                _process_entries(
                    session,
                    run,
                    entries[:max_records],
                    entry_normalizer,
                    service,
                    observed_at,
                )

        if fetch_failed:
            run.status = "failed"
        elif run.records_failed > 0 and _processed_count(run) == run.records_failed:
            run.status = "failed"
        elif capped or run.records_failed > 0 or run.records_skipped > 0:
            run.status = "partial"
        else:
            run.status = "succeeded"

        run.completed_at = observed_at
        run.error_count = len(run.errors)
        run.safe_summary = _safe_run_summary(run, capped)
        if run.status == "succeeded":
            checkpoint = observed_at.isoformat().replace("+00:00", "Z")
            run.checkpoint_after = checkpoint
            source.checkpoint_value = checkpoint
            source.last_successful_fetch_at = observed_at

        session.commit()
        _print_summary(run, capped, stdout)
        if run.status != "succeeded":
            print("Manual CISA KEV ingestion completed with a controlled failure.", file=stderr)
            return 1
        return 0
    except (CisaKevPersistenceError, SQLAlchemyError):
        if session is not None:
            session.rollback()
        print("Manual CISA KEV ingestion failed during a database operation.", file=stderr)
        return 1
    except Exception:
        if session is not None:
            session.rollback()
        print("Manual CISA KEV ingestion failed unexpectedly.", file=stderr)
        return 1
    finally:
        if session is not None:
            session.close()


def _fetch_catalog(
    client_factory: Callable[..., CisaKevClient],
    session: Session,
    run: IngestionRun,
    observed_at: datetime,
) -> CisaKevFetchResult | None:
    try:
        with client_factory() as client:
            return client.fetch_catalog()
    except CisaKevRateLimitError:
        _add_error(
            session,
            run,
            "cisa_kev_rate_limit",
            "The CISA KEV catalog rate limit was reached.",
            retryable=True,
            occurred_at=observed_at,
        )
    except (CisaKevRequestError, CisaKevHttpError):
        _add_error(
            session,
            run,
            "cisa_kev_fetch_error",
            "The CISA KEV fetch did not complete.",
            retryable=True,
            occurred_at=observed_at,
        )
    except (
        CisaKevRedirectError,
        CisaKevResponseTooLargeError,
        CisaKevContentTypeError,
        CisaKevResponseError,
    ):
        _add_error(
            session,
            run,
            "cisa_kev_fetch_rejected",
            "The CISA KEV fetch was rejected by safety controls.",
            retryable=False,
            occurred_at=observed_at,
        )
    except CisaKevClientError:
        _add_error(
            session,
            run,
            "cisa_kev_fetch_error",
            "The CISA KEV fetch did not complete.",
            retryable=True,
            occurred_at=observed_at,
        )
    run.records_failed += 1
    return None


def _extract_entries(
    feed: CisaKevFetchResult,
    session: Session,
    run: IngestionRun,
    catalog_entry_extractor: Callable[[dict], list[dict]],
    observed_at: datetime,
) -> list[dict] | None:
    try:
        entries = catalog_entry_extractor(feed.catalog)
        run.records_fetched = len(entries)
        return entries
    except CisaKevNormalizationError:
        _record_failure(
            session,
            run,
            "cisa_kev_normalization_error",
            "The CISA KEV catalog failed safe normalization.",
            observed_at,
        )
        return None


def _process_entries(
    session: Session,
    run: IngestionRun,
    entries: list[dict],
    entry_normalizer: Callable[[dict], NormalizedCisaKevEntry],
    service: CisaKevIngestionService,
    observed_at: datetime,
) -> None:
    by_cve: dict[str, NormalizedCisaKevEntry] = {}
    terminal_cves: set[str] = set()
    for entry in entries:
        identifiable_cve = _safe_cve(entry)
        try:
            normalized = entry_normalizer(entry)
        except CisaKevNormalizationError:
            if identifiable_cve is not None and identifiable_cve in terminal_cves:
                continue
            _record_failure(
                session,
                run,
                "cisa_kev_normalization_error",
                "A CISA KEV entry failed safe normalization.",
                observed_at,
            )
            if identifiable_cve is not None:
                terminal_cves.add(identifiable_cve)
                by_cve.pop(identifiable_cve, None)
            continue

        if normalized.cve_id in terminal_cves:
            continue
        existing = by_cve.get(normalized.cve_id)
        if existing is None:
            by_cve[normalized.cve_id] = normalized
            continue
        if existing.content_hash != normalized.content_hash:
            _record_failure(
                session,
                run,
                "cisa_kev_duplicate_conflict",
                "Conflicting duplicate CISA KEV entries were returned.",
                observed_at,
            )
            terminal_cves.add(normalized.cve_id)
            by_cve.pop(normalized.cve_id, None)

    for normalized in by_cve.values():
        _process_normalized(session, run, normalized, service, observed_at)


def _safe_cve(entry: object) -> str | None:
    if not isinstance(entry, dict):
        return None
    value = entry.get("cveID")
    if not isinstance(value, str):
        return None
    value = value.upper()
    return value if value.startswith("CVE-") else None


def _process_normalized(
    session: Session,
    run: IngestionRun,
    normalized: NormalizedCisaKevEntry,
    service: CisaKevIngestionService,
    observed_at: datetime,
) -> None:
    try:
        nested = session.begin_nested() if hasattr(session, "begin_nested") else nullcontext()
        with nested:
            result: CisaKevPersistenceResult = service.enrich(
                normalized,
                observed_at=observed_at,
            )
            session.add(
                IngestionRunRecord(
                    ingestion_run=run,
                    source_record=result.source_record,
                    intelligence_item_id=result.intelligence_item_id,
                    action=result.outcome,
                    safe_detail=result.message or f"CISA KEV CVE record {result.outcome}.",
                    processed_at=observed_at,
                )
            )
            _increment_outcome(run, result.outcome)
            if result.outcome == "failed":
                _add_error(
                    session,
                    run,
                    "cisa_kev_persistence_error",
                    "A CISA KEV entry could not be persisted safely.",
                    retryable=False,
                    occurred_at=observed_at,
                )
    except (CisaKevPersistenceError, SQLAlchemyError):
        _record_failure(
            session,
            run,
            "cisa_kev_persistence_error",
            "A CISA KEV entry database operation failed.",
            observed_at,
        )


def _record_failure(
    session: Session,
    run: IngestionRun,
    error_type: str,
    message: str,
    observed_at: datetime,
) -> None:
    failed_record = IngestionRunRecord(
        ingestion_run=run,
        source_record=None,
        intelligence_item_id=None,
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
    run.records_failed += 1


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
    elif outcome == "skipped":
        run.records_skipped += 1
    else:
        run.records_failed += 1


def _processed_count(run: IngestionRun) -> int:
    return (
        run.records_created
        + run.records_updated
        + run.records_unchanged
        + run.records_skipped
        + run.records_failed
    )


def _safe_run_summary(run: IngestionRun, capped: bool) -> str:
    return (
        f"Manual CISA KEV ingestion {run.status}; fetched={run.records_fetched}; "
        f"created={run.records_created}; updated={run.records_updated}; "
        f"unchanged={run.records_unchanged}; skipped={run.records_skipped}; "
        f"failed={run.records_failed}; capped={str(capped).lower()}."
    )


def _print_summary(run: IngestionRun, capped: bool, stdout: TextIO) -> None:
    print("Manual CISA KEV ingestion completed.", file=stdout)
    print(f"Run ID: {run.public_id}", file=stdout)
    print(f"Status: {run.status}", file=stdout)
    print(f"Fetched: {run.records_fetched}", file=stdout)
    print(f"Created: {run.records_created}", file=stdout)
    print(f"Updated: {run.records_updated}", file=stdout)
    print(f"Unchanged: {run.records_unchanged}", file=stdout)
    print(f"Skipped: {run.records_skipped}", file=stdout)
    print(f"Failed: {run.records_failed}", file=stdout)
    print(f"Capped: {str(capped).lower()}", file=stdout)
    if capped:
        print("Record cap reached; not all fetched KEV entries were processed.", file=stdout)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _build_parser().parse_args(argv)
    except CliArgumentError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    return run_ingestion(max_records=arguments.max_records)


if __name__ == "__main__":
    raise SystemExit(main())
