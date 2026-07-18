"""Manual bounded live ingestion for approved public Censys publications."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import datetime
import sys
from typing import TextIO

from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.ingestion.adapters.censys_publications import (
    CENSYS_ARC_RESEARCH_SLUG,
    CENSYS_RAPID_RESPONSE_SLUG,
)
from app.ingestion.collectors.censys_publications_client import (
    CensysCollectionResult,
    CensysCollectorError,
    CensysFailureReason,
    CensysPublicationSource,
    CensysPublicationsClient,
)
from app.ingestion.publication_pipeline import PublicationCandidate
from app.ingestion.services.censys_publications_ingestion_service import (
    CensysIngestionDatabaseError,
    CensysIngestionError,
    CensysIngestionInputError,
    CensysIngestionResult,
    CensysIngestionTrigger,
    CensysPublicationsIngestionService,
    collector_failure_audit_kind,
)
from app.models.common import utc_now


_SOURCE_SLUGS = {
    CensysPublicationSource.ARC: CENSYS_ARC_RESEARCH_SLUG,
    CensysPublicationSource.RAPID_RESPONSE: CENSYS_RAPID_RESPONSE_SLUG,
}
_SYSTEM_EXCEPTIONS = (MemoryError, KeyboardInterrupt, SystemExit, GeneratorExit)
_COLLECTION_FAILURE_MESSAGE = "Censys live collection failed safely."
_DATABASE_FAILURE_MESSAGE = (
    "Manual Censys live ingestion failed during a database operation."
)
_INGESTION_FAILURE_MESSAGE = "Manual Censys live ingestion failed safely."


class LiveCliArgumentError(ValueError):
    """The manual live Censys arguments were invalid."""


class LiveCliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise LiveCliArgumentError("Invalid manual Censys live ingestion arguments.")


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
    if str(parsed) != value or not 1 <= parsed <= 20:
        raise argparse.ArgumentTypeError("Invalid maximum record count.")
    return parsed


def _build_parser() -> LiveCliArgumentParser:
    parser = LiveCliArgumentParser(
        description="Run bounded manual live Censys publication ingestion.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--source",
        required=True,
        choices=tuple(source.value for source in CensysPublicationSource),
        action=_StoreOnce,
        default=argparse.SUPPRESS,
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
    source: CensysPublicationSource,
    max_records: int,
    collector_factory: Callable[[], CensysPublicationsClient] = (
        CensysPublicationsClient
    ),
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    service_factory: Callable[..., CensysPublicationsIngestionService] = (
        CensysPublicationsIngestionService
    ),
    clock: Callable[[], datetime] = utc_now,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Collect before opening a database session, then persist one manual run."""

    if (
        not isinstance(source, CensysPublicationSource)
        or type(max_records) is not int
        or not 1 <= max_records <= 20
    ):
        print("Invalid manual Censys live ingestion arguments.", file=stderr)
        return 2

    try:
        collection = _collect_publications(
            source=source,
            max_records=max_records,
            collector_factory=collector_factory,
        )
        _validate_collection_result(collection, source, max_records)
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
            raise CensysIngestionInputError(
                "The Censys live ingestion time is invalid."
            )
    except _SYSTEM_EXCEPTIONS:
        raise
    except (CensysCollectorError, CensysIngestionInputError):
        print(_COLLECTION_FAILURE_MESSAGE, file=stderr)
        return 1
    except Exception:
        print(_COLLECTION_FAILURE_MESSAGE, file=stderr)
        return 1

    session: Session | None = None
    ingestion_result: CensysIngestionResult | None = None
    failure_message: str | None = None
    close_failed = False
    system_exception_active = False
    try:
        session = session_factory()
        service = service_factory(session)
        ingestion_result = service.ingest(
            source_slug=collection.source_slug,
            candidates=collection.candidates,
            failure_kinds=failure_kinds,
            records_fetched=collection.discovered_approved_link_count,
            trigger=CensysIngestionTrigger.LIVE,
            observed_at=observed_at,
        )
    except _SYSTEM_EXCEPTIONS:
        system_exception_active = True
        raise
    except CensysIngestionDatabaseError:
        failure_message = _DATABASE_FAILURE_MESSAGE
    except CensysIngestionError:
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
        print(_DATABASE_FAILURE_MESSAGE, file=stderr)
        return 1
    if failure_message is not None or ingestion_result is None:
        print(
            failure_message or _INGESTION_FAILURE_MESSAGE,
            file=stderr,
        )
        return 1

    try:
        _print_summary(
            ingestion_result,
            source_slug=collection.source_slug,
            capped=collection.capped,
            stdout=stdout,
        )
        status = ingestion_result.run.status
    except _SYSTEM_EXCEPTIONS:
        raise
    except Exception:
        print(_INGESTION_FAILURE_MESSAGE, file=stderr)
        return 1
    if status != "succeeded":
        print(
            "Manual Censys live ingestion completed with a controlled failure.",
            file=stderr,
        )
        return 1
    return 0


def _collect_publications(
    *,
    source: CensysPublicationSource,
    max_records: int,
    collector_factory: Callable[[], CensysPublicationsClient],
) -> CensysCollectionResult:
    """Own the collector context without losing an active system exception."""

    active_system_exception = None
    active_system_traceback = None
    collection: CensysCollectionResult
    try:
        with collector_factory() as collector:
            try:
                collection = collector.fetch_publications(
                    source,
                    max_records=max_records,
                )
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


def _validate_collection_result(
    result: object,
    source: CensysPublicationSource,
    max_records: int,
) -> None:
    if (
        not isinstance(result, CensysCollectionResult)
        or result.source is not source
        or result.source_slug != _SOURCE_SLUGS[source]
        or not isinstance(result.candidates, tuple)
        or any(
            not isinstance(candidate, PublicationCandidate)
            or candidate.source_slug != result.source_slug
            for candidate in result.candidates
        )
        or not isinstance(result.failure_reasons, tuple)
        or any(
            not isinstance(reason, CensysFailureReason)
            for reason in result.failure_reasons
        )
        or type(result.failure_count) is not int
        or result.failure_count < 0
        or type(result.discovered_approved_link_count) is not int
        or result.discovered_approved_link_count < 0
        or type(result.capped) is not bool
        or result.discovered_approved_link_count > max_records
        or result.discovered_approved_link_count
        != len(result.candidates) + result.failure_count
        or result.failure_count != len(result.failure_reasons)
    ):
        raise CensysIngestionInputError(
            "The Censys collection result is invalid."
        )


def _print_summary(
    result: CensysIngestionResult,
    *,
    source_slug: str,
    capped: bool,
    stdout: TextIO,
) -> None:
    run = result.run
    print("Manual Censys live ingestion completed.", file=stdout)
    print(f"Source: {source_slug}", file=stdout)
    print(f"Run ID: {run.public_id}", file=stdout)
    print(f"Status: {run.status}", file=stdout)
    print(f"Fetched: {run.records_fetched}", file=stdout)
    print(f"Created: {run.records_created}", file=stdout)
    print(f"Updated: {run.records_updated}", file=stdout)
    print(f"Unchanged: {run.records_unchanged}", file=stdout)
    print(f"Skipped: {run.records_skipped}", file=stdout)
    print(f"Failed: {run.records_failed}", file=stdout)
    print(f"Capped: {str(capped).lower()}", file=stdout)


def main(
    argv: Sequence[str] | None = None,
    *,
    collector_factory: Callable[[], CensysPublicationsClient] = (
        CensysPublicationsClient
    ),
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    service_factory: Callable[..., CensysPublicationsIngestionService] = (
        CensysPublicationsIngestionService
    ),
    clock: Callable[[], datetime] = utc_now,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    try:
        arguments = _build_parser().parse_args(argv)
        source = CensysPublicationSource(arguments.source)
        max_records = getattr(arguments, "max_records", 5)
    except (LiveCliArgumentError, ValueError) as exc:
        del exc
        print("Invalid manual Censys live ingestion arguments.", file=errors)
        return 2
    return run_live_ingestion(
        source=source,
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
