"""Manual bounded live ingestion for public Anomali Cyber Watch publications."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
import sys
from typing import TextIO
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.ingestion.adapters.anomali_publications import ANOMALI_SOURCE_SLUG
from app.ingestion.collectors.anomali_publications_client import (
    MAX_RECORDS,
    MIN_RECORDS,
    AnomaliCollectionResult,
    AnomaliCollectorError,
    AnomaliFailureReason,
    AnomaliPublicationsClient,
)
from app.ingestion.publication_pipeline import PublicationCandidate
from app.ingestion.services.anomali_publications_ingestion_service import (
    AnomaliIngestionDatabaseError,
    AnomaliIngestionError,
    AnomaliIngestionInputError,
    AnomaliIngestionResult,
    AnomaliIngestionTrigger,
    AnomaliPublicationsIngestionService,
    collector_failure_audit_kind,
)
from app.models.common import utc_now


DEFAULT_MAX_RECORDS = 5
_SYSTEM_EXCEPTIONS = (MemoryError, KeyboardInterrupt, SystemExit, GeneratorExit)
_ARGUMENT_FAILURE_MESSAGE = "Invalid manual Anomali live ingestion arguments."
_COLLECTION_FAILURE_MESSAGE = "Anomali live collection failed safely."
_DATABASE_FAILURE_MESSAGE = (
    "Manual Anomali live ingestion failed during a database operation."
)
_INGESTION_FAILURE_MESSAGE = "Manual Anomali live ingestion failed safely."
_COMPLETED_STATUSES = frozenset({"succeeded", "partial", "failed"})


@dataclass(frozen=True, slots=True)
class _LiveIngestionSummary:
    """Validated primitive values safe to retain after session closure."""

    source_slug: str
    public_id: UUID
    status: str
    records_fetched: int
    records_created: int
    records_updated: int
    records_unchanged: int
    records_skipped: int
    records_failed: int
    capped: bool


class LiveCliArgumentError(ValueError):
    """The manual live Anomali arguments were invalid."""


class LiveCliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise LiveCliArgumentError(_ARGUMENT_FAILURE_MESSAGE)


class _StoreOnce(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        del option_string
        if hasattr(namespace, self.dest):
            parser.error("Duplicate option.")
        setattr(namespace, self.dest, values)


def _bounded_max_records(value: str) -> int:
    try:
        parsed = int(value, 10)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("Invalid maximum record count.") from None
    if str(parsed) != value or not MIN_RECORDS <= parsed <= MAX_RECORDS:
        raise argparse.ArgumentTypeError("Invalid maximum record count.")
    return parsed


def _build_parser() -> LiveCliArgumentParser:
    parser = LiveCliArgumentParser(
        description="Run bounded manual live Anomali publication ingestion.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--max-records",
        type=_bounded_max_records,
        action=_StoreOnce,
        default=argparse.SUPPRESS,
    )
    return parser


def run_live_ingestion(
    *,
    max_records: int,
    collector_factory: Callable[[], AnomaliPublicationsClient] = (
        AnomaliPublicationsClient
    ),
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    service_factory: Callable[..., AnomaliPublicationsIngestionService] = (
        AnomaliPublicationsIngestionService
    ),
    clock: Callable[[], datetime] = utc_now,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Collect before opening a database session, then persist one manual run."""

    if (
        type(max_records) is not int
        or not MIN_RECORDS <= max_records <= MAX_RECORDS
    ):
        print(_ARGUMENT_FAILURE_MESSAGE, file=stderr)
        return 2

    try:
        collection = _collect_publications(
            max_records=max_records,
            collector_factory=collector_factory,
        )
        _validate_collection_result(collection, max_records)
        failure_kinds = tuple(
            collector_failure_audit_kind(reason)
            for reason in collection.failure_reasons
        )
        observed_at = clock()
        if (
            not isinstance(observed_at, datetime)
            or observed_at.tzinfo is None
            or observed_at.utcoffset() is None
        ):
            raise AnomaliIngestionInputError(
                "The Anomali live ingestion time is invalid."
            )
    except _SYSTEM_EXCEPTIONS:
        raise
    except (AnomaliCollectorError, AnomaliIngestionInputError):
        print(_COLLECTION_FAILURE_MESSAGE, file=stderr)
        return 1
    except Exception:
        print(_COLLECTION_FAILURE_MESSAGE, file=stderr)
        return 1

    session: Session | None = None
    summary: _LiveIngestionSummary | None = None
    failure_message: str | None = None
    close_failed = False
    system_exception_active = False
    try:
        session = session_factory()
        service = service_factory(session)
        ingestion_result = service.ingest(
            source_slug=ANOMALI_SOURCE_SLUG,
            candidates=collection.candidates,
            failure_kinds=failure_kinds,
            records_fetched=collection.discovered_approved_link_count,
            capped=collection.capped,
            trigger=AnomaliIngestionTrigger.LIVE,
            observed_at=observed_at,
        )
        summary = _snapshot_ingestion_result(
            ingestion_result,
            source_slug=ANOMALI_SOURCE_SLUG,
            expected_records_fetched=collection.discovered_approved_link_count,
            expected_capped=collection.capped,
        )
    except _SYSTEM_EXCEPTIONS:
        system_exception_active = True
        raise
    except AnomaliIngestionDatabaseError:
        failure_message = _DATABASE_FAILURE_MESSAGE
    except AnomaliIngestionError:
        failure_message = _INGESTION_FAILURE_MESSAGE
    except Exception:
        failure_message = _DATABASE_FAILURE_MESSAGE
    finally:
        if session is not None:
            try:
                session.close()
            except _SYSTEM_EXCEPTIONS:
                if not system_exception_active:
                    raise
            except Exception:
                if not system_exception_active:
                    close_failed = True

    if close_failed:
        print(failure_message or _DATABASE_FAILURE_MESSAGE, file=stderr)
        return 1
    if failure_message is not None or summary is None:
        print(failure_message or _INGESTION_FAILURE_MESSAGE, file=stderr)
        return 1

    try:
        _print_summary(summary, stdout=stdout)
        status = summary.status
    except _SYSTEM_EXCEPTIONS:
        raise
    except Exception:
        print(_INGESTION_FAILURE_MESSAGE, file=stderr)
        return 1
    if status != "succeeded":
        print(
            "Manual Anomali live ingestion completed with a controlled failure.",
            file=stderr,
        )
        return 1
    return 0


def _collect_publications(
    *,
    max_records: int,
    collector_factory: Callable[[], AnomaliPublicationsClient],
) -> AnomaliCollectionResult:
    """Own the collector context without losing an active system exception."""

    active_system_exception = None
    active_system_traceback = None
    collection: AnomaliCollectionResult
    try:
        with collector_factory() as collector:
            try:
                collection = collector.fetch_publications(max_records=max_records)
            except _SYSTEM_EXCEPTIONS as exc:
                active_system_exception = exc
                active_system_traceback = exc.__traceback__
                raise
    except _SYSTEM_EXCEPTIONS:
        if active_system_exception is not None:
            raise active_system_exception.with_traceback(active_system_traceback)
        raise
    except Exception:
        if active_system_exception is not None:
            raise active_system_exception.with_traceback(active_system_traceback)
        raise
    if active_system_exception is not None:
        raise active_system_exception.with_traceback(active_system_traceback)
    return collection


def _validate_collection_result(result: object, max_records: int) -> None:
    if (
        not isinstance(result, AnomaliCollectionResult)
        or type(result.source_slug) is not str
        or result.source_slug != ANOMALI_SOURCE_SLUG
        or not isinstance(result.candidates, tuple)
        or any(
            not isinstance(candidate, PublicationCandidate)
            or candidate.source_slug != ANOMALI_SOURCE_SLUG
            for candidate in result.candidates
        )
        or not isinstance(result.failure_reasons, tuple)
        or any(
            not isinstance(reason, AnomaliFailureReason)
            for reason in result.failure_reasons
        )
        or type(result.failure_count) is not int
        or result.failure_count < 0
        or type(result.discovered_approved_link_count) is not int
        or result.discovered_approved_link_count < 0
        or type(result.capped) is not bool
        or result.discovered_approved_link_count > max_records
        or (
            result.capped
            and result.discovered_approved_link_count != max_records
        )
        or result.discovered_approved_link_count
        != len(result.candidates) + result.failure_count
        or result.failure_count != len(result.failure_reasons)
    ):
        raise AnomaliIngestionInputError(
            "The Anomali collection result is invalid."
        )


def _snapshot_ingestion_result(
    result: object,
    *,
    source_slug: str,
    expected_records_fetched: int,
    expected_capped: bool,
) -> _LiveIngestionSummary:
    """Copy and validate service output before database resources are closed."""

    try:
        if not isinstance(result, AnomaliIngestionResult):
            raise AnomaliIngestionInputError(
                "The Anomali ingestion result is invalid."
            )
        run = result.run
        public_id = run.public_id
        status = run.status
        records_fetched = run.records_fetched
        records_created = run.records_created
        records_updated = run.records_updated
        records_unchanged = run.records_unchanged
        records_skipped = run.records_skipped
        records_failed = run.records_failed
        capped = result.capped

        counters = (
            records_fetched,
            records_created,
            records_updated,
            records_unchanged,
            records_skipped,
            records_failed,
        )
        if (
            type(public_id) is not UUID
            or type(status) is not str
            or status not in _COMPLETED_STATUSES
            or any(type(value) is not int or value < 0 for value in counters)
            or sum(counters[1:]) != records_fetched
            or records_fetched != expected_records_fetched
            or type(capped) is not bool
            or capped is not expected_capped
        ):
            raise AnomaliIngestionInputError(
                "The Anomali ingestion result is invalid."
            )
        return _LiveIngestionSummary(
            source_slug=source_slug,
            public_id=public_id,
            status=status,
            records_fetched=records_fetched,
            records_created=records_created,
            records_updated=records_updated,
            records_unchanged=records_unchanged,
            records_skipped=records_skipped,
            records_failed=records_failed,
            capped=capped,
        )
    except _SYSTEM_EXCEPTIONS:
        raise
    except AnomaliIngestionInputError:
        raise
    except Exception:
        raise AnomaliIngestionInputError(
            "The Anomali ingestion result could not be validated safely."
        ) from None


def _print_summary(
    summary: _LiveIngestionSummary,
    *,
    stdout: TextIO,
) -> None:
    print("Manual Anomali live ingestion completed.", file=stdout)
    print(f"Source: {summary.source_slug}", file=stdout)
    print(f"Run ID: {summary.public_id}", file=stdout)
    print(f"Status: {summary.status}", file=stdout)
    print(f"Fetched: {summary.records_fetched}", file=stdout)
    print(f"Created: {summary.records_created}", file=stdout)
    print(f"Updated: {summary.records_updated}", file=stdout)
    print(f"Unchanged: {summary.records_unchanged}", file=stdout)
    print(f"Skipped: {summary.records_skipped}", file=stdout)
    print(f"Failed: {summary.records_failed}", file=stdout)
    print(f"Capped: {str(summary.capped).lower()}", file=stdout)


def main(
    argv: Sequence[str] | None = None,
    *,
    collector_factory: Callable[[], AnomaliPublicationsClient] = (
        AnomaliPublicationsClient
    ),
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    service_factory: Callable[..., AnomaliPublicationsIngestionService] = (
        AnomaliPublicationsIngestionService
    ),
    clock: Callable[[], datetime] = utc_now,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    try:
        arguments = _build_parser().parse_args(argv)
        max_records = getattr(arguments, "max_records", DEFAULT_MAX_RECORDS)
    except LiveCliArgumentError:
        print(_ARGUMENT_FAILURE_MESSAGE, file=errors)
        return 2
    return run_live_ingestion(
        max_records=max_records,
        collector_factory=collector_factory,
        session_factory=session_factory,
        service_factory=service_factory,
        clock=clock,
        stdout=output,
        stderr=errors,
    )


if __name__ == "__main__":
    raise SystemExit(main())
