"""Manual, bounded FIRST EPSS enrichment command with sanitized audit records."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from datetime import UTC, datetime
import sys
from typing import TextIO

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.ingestion.collectors.epss_client import (
    DEFAULT_MAX_BATCH_SIZE,
    EpssClient,
    EpssClientError,
    EpssRateLimitError,
)
from app.ingestion.normalizers.epss import (
    CVE_ID_PATTERN,
    EpssNormalizationError,
    NormalizedEpssRecord,
    normalize_epss_record,
)
from app.ingestion.services.epss_enrichment_service import (
    EpssEnrichmentService,
    EpssPersistenceError,
    EpssPersistenceResult,
)
from app.models import (
    IngestionError,
    IngestionRun,
    IngestionRunRecord,
    IntelligenceItemIdentifier,
)
from app.models.common import utc_now


DEFAULT_MAX_CVES = 25
MAX_MAX_CVES = 500
MIN_MAX_CVES = 1
MIN_BATCH_SIZE = 1
MAX_BATCH_SIZE = 100


class CliArgumentError(ValueError):
    """The manual EPSS command arguments were invalid."""


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CliArgumentError("Invalid manual EPSS enrichment arguments.")


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
        description="Manually enrich existing local CVEs with public FIRST EPSS scores.",
    )
    parser.add_argument(
        "--max-cves",
        type=_bounded_integer("maximum CVEs", MIN_MAX_CVES, MAX_MAX_CVES),
        default=DEFAULT_MAX_CVES,
    )
    parser.add_argument(
        "--batch-size",
        type=_bounded_integer("batch size", MIN_BATCH_SIZE, MAX_BATCH_SIZE),
        default=DEFAULT_MAX_BATCH_SIZE,
    )
    return parser


def _valid_integer(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def run_enrichment(
    *,
    max_cves: int,
    batch_size: int,
    clock: Callable[[], datetime] = utc_now,
    client_factory: Callable[..., EpssClient] = EpssClient,
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    normalizer: Callable[[dict], NormalizedEpssRecord] = normalize_epss_record,
    service_factory: Callable[..., EpssEnrichmentService] = EpssEnrichmentService,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run one caller-transactional manual EPSS enrichment and return an exit code."""

    if not (
        _valid_integer(max_cves, MIN_MAX_CVES, MAX_MAX_CVES)
        and _valid_integer(batch_size, MIN_BATCH_SIZE, MAX_BATCH_SIZE)
    ):
        print("Invalid manual EPSS enrichment parameters.", file=stderr)
        return 2

    started_at = clock()
    if started_at.tzinfo is None or started_at.utcoffset() is None:
        print("Manual EPSS enrichment requires a timezone-aware clock.", file=stderr)
        return 1
    started_at = started_at.astimezone(UTC)
    session: Session | None = None
    client = None

    try:
        session = session_factory()
        service = service_factory(session)
        source = service.ensure_source()
        requested_cves = _load_local_cve_ids(session, max_cves)
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
            safe_summary="Manual bounded FIRST EPSS enrichment started.",
            created_at=started_at,
        )
        session.add(run)
        session.flush()

        if not requested_cves:
            run.status = "succeeded"
            run.completed_at = started_at
            run.safe_summary = _safe_run_summary(run)
            checkpoint = started_at.isoformat().replace("+00:00", "Z")
            run.checkpoint_after = checkpoint
            source.checkpoint_value = checkpoint
            source.last_successful_fetch_at = started_at
            session.commit()
            _print_summary(run, stdout)
            return 0

        fetch_failed = False
        client = client_factory()
        with client:
            for batch in client.build_batches(requested_cves, max_batch_size=batch_size):
                try:
                    response_batch = client.fetch_batch(batch)
                except EpssRateLimitError:
                    fetch_failed = True
                    _add_error(
                        session,
                        run,
                        "epss_rate_limit",
                        "The FIRST EPSS API rate limit was reached.",
                        retryable=True,
                        occurred_at=started_at,
                    )
                    break
                except EpssClientError:
                    fetch_failed = True
                    _add_error(
                        session,
                        run,
                        "epss_fetch_error",
                        "The FIRST EPSS fetch did not complete.",
                        retryable=True,
                        occurred_at=started_at,
                    )
                    break

                run.records_fetched += len(response_batch.records)
                _process_batch(
                    session,
                    run,
                    response_batch.requested_cves,
                    response_batch.records,
                    service,
                    normalizer,
                    started_at,
                )

        if fetch_failed and _processed_count(run) == 0:
            run.status = "failed"
        elif fetch_failed or run.records_failed > 0 or run.records_skipped > 0:
            run.status = "partial"
        else:
            run.status = "succeeded"

        run.completed_at = started_at
        run.error_count = len(run.errors)
        run.safe_summary = _safe_run_summary(run)
        if run.status == "succeeded":
            checkpoint = started_at.isoformat().replace("+00:00", "Z")
            run.checkpoint_after = checkpoint
            source.checkpoint_value = checkpoint
            source.last_successful_fetch_at = started_at

        session.commit()
        _print_summary(run, stdout)
        if run.status != "succeeded":
            print("Manual EPSS enrichment completed with a controlled failure.", file=stderr)
            return 1
        return 0
    except (EpssPersistenceError, SQLAlchemyError):
        if session is not None:
            session.rollback()
        print("Manual EPSS enrichment failed during a database operation.", file=stderr)
        return 1
    except Exception:
        if session is not None:
            session.rollback()
        print("Manual EPSS enrichment failed unexpectedly.", file=stderr)
        return 1
    finally:
        if session is not None:
            session.close()


def _load_local_cve_ids(session: Session, max_cves: int) -> list[str]:
    statement = (
        select(IntelligenceItemIdentifier.normalized_value)
        .where(IntelligenceItemIdentifier.source_id.is_(None))
        .where(IntelligenceItemIdentifier.namespace == "cve")
        .order_by(IntelligenceItemIdentifier.normalized_value.asc())
        .limit(max_cves)
    )
    rows = session.execute(statement).all()
    return [row[0] for row in rows]


def _process_batch(
    session: Session,
    run: IngestionRun,
    requested_cves: tuple[str, ...],
    records: list[dict],
    service: EpssEnrichmentService,
    normalizer: Callable[[dict], NormalizedEpssRecord],
    observed_at: datetime,
) -> None:
    requested_set = set(requested_cves)
    normalized_by_cve: dict[str, NormalizedEpssRecord] = {}
    terminal_cves: set[str] = set()

    for record in records:
        identifiable_cve = _safe_requested_cve(record, requested_set)
        try:
            normalized = normalizer(record)
        except EpssNormalizationError:
            if identifiable_cve is not None:
                if identifiable_cve not in terminal_cves:
                    _record_failure(
                        session,
                        run,
                        "epss_normalization_error",
                        "An EPSS record failed normalization.",
                        observed_at,
                    )
                    terminal_cves.add(identifiable_cve)
                normalized_by_cve.pop(identifiable_cve, None)
            else:
                _record_failure(
                    session,
                    run,
                    "epss_normalization_error",
                    "An EPSS response record failed normalization.",
                    observed_at,
                )
            continue
        if normalized.cve_id not in requested_set:
            _record_failure(
                session,
                run,
                "epss_unexpected_record",
                "An EPSS response record was not requested.",
                observed_at,
            )
            continue
        if normalized.cve_id in terminal_cves:
            continue
        existing = normalized_by_cve.get(normalized.cve_id)
        if existing is None:
            normalized_by_cve[normalized.cve_id] = normalized
            continue
        if existing.content_hash != normalized.content_hash:
            if normalized.cve_id not in terminal_cves:
                _record_failure(
                    session,
                    run,
                    "epss_duplicate_conflict",
                    "Conflicting duplicate EPSS records were returned for one CVE.",
                    observed_at,
                )
                terminal_cves.add(normalized.cve_id)
            normalized_by_cve.pop(normalized.cve_id, None)

    for cve_id in requested_cves:
        if cve_id in terminal_cves:
            continue
        normalized = normalized_by_cve.get(cve_id)
        if normalized is None:
            _record_skipped(
                session,
                run,
                "The FIRST EPSS response omitted this requested CVE.",
                observed_at,
            )
            continue
        _process_normalized(session, run, normalized, service, observed_at)


def _safe_requested_cve(record: object, requested_cves: set[str]) -> str | None:
    if not isinstance(record, dict):
        return None
    value = record.get("cve")
    if not isinstance(value, str) or CVE_ID_PATTERN.fullmatch(value) is None:
        return None
    cve_id = value.upper()
    return cve_id if cve_id in requested_cves else None


def _process_normalized(
    session: Session,
    run: IngestionRun,
    normalized: NormalizedEpssRecord,
    service: EpssEnrichmentService,
    observed_at: datetime,
) -> None:
    try:
        nested = session.begin_nested() if hasattr(session, "begin_nested") else nullcontext()
        with nested:
            result: EpssPersistenceResult = service.enrich(
                normalized,
                observed_at=observed_at,
            )
            session.add(
                IngestionRunRecord(
                    ingestion_run=run,
                    source_record=result.source_record,
                    intelligence_item_id=result.intelligence_item_id,
                    action=result.outcome,
                    safe_detail=result.message or f"EPSS CVE record {result.outcome}.",
                    processed_at=observed_at,
                )
            )
            _increment_outcome(run, result.outcome)
            if result.outcome == "failed":
                _add_error(
                    session,
                    run,
                    "epss_persistence_error",
                    "An EPSS record could not be persisted safely.",
                    retryable=False,
                    occurred_at=observed_at,
                )
    except (EpssPersistenceError, SQLAlchemyError):
        _record_failure(
            session,
            run,
            "epss_persistence_error",
            "An EPSS record database operation failed.",
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


def _record_skipped(
    session: Session,
    run: IngestionRun,
    message: str,
    observed_at: datetime,
) -> None:
    session.add(
        IngestionRunRecord(
            ingestion_run=run,
            source_record=None,
            intelligence_item_id=None,
            action="skipped",
            safe_detail=message,
            processed_at=observed_at,
        )
    )
    run.records_skipped += 1


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


def _safe_run_summary(run: IngestionRun) -> str:
    return (
        f"Manual EPSS enrichment {run.status}; fetched={run.records_fetched}; "
        f"created={run.records_created}; updated={run.records_updated}; "
        f"unchanged={run.records_unchanged}; skipped={run.records_skipped}; "
        f"failed={run.records_failed}."
    )


def _print_summary(run: IngestionRun, stdout: TextIO) -> None:
    print("Manual EPSS enrichment completed.", file=stdout)
    print(f"Run ID: {run.public_id}", file=stdout)
    print(f"Status: {run.status}", file=stdout)
    print(f"Fetched: {run.records_fetched}", file=stdout)
    print(f"Created: {run.records_created}", file=stdout)
    print(f"Updated: {run.records_updated}", file=stdout)
    print(f"Unchanged: {run.records_unchanged}", file=stdout)
    print(f"Skipped: {run.records_skipped}", file=stdout)
    print(f"Failed: {run.records_failed}", file=stdout)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _build_parser().parse_args(argv)
    except CliArgumentError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    return run_enrichment(
        max_cves=arguments.max_cves,
        batch_size=arguments.batch_size,
    )


if __name__ == "__main__":
    raise SystemExit(main())
