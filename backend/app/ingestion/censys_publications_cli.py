"""Manual local-file ingestion for official public Censys publications."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
import os
import sys
from typing import TextIO

from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.ingestion.adapters.censys_publications import (
    CensysPublicationDocument,
    CensysPublicationFileError,
    CensysPublicationRecordError,
    adapt_censys_publication,
    load_censys_publication_file,
)
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPipeline,
)
from app.ingestion.services.censys_publications_ingestion_service import (
    CensysFailureAuditKind,
    CensysIngestionDatabaseError,
    CensysIngestionError,
    CensysIngestionTrigger,
    CensysPublicationsIngestionService,
)
from app.models import IngestionRun
from app.models.common import utc_now


_SYSTEM_EXCEPTIONS = (MemoryError, KeyboardInterrupt, SystemExit, GeneratorExit)
_LOCAL_FAILURE_MESSAGE = "Manual Censys local-file import failed safely."
_DATABASE_FAILURE_MESSAGE = (
    "Manual Censys import failed during a database operation."
)
_UNEXPECTED_FAILURE_MESSAGE = "Manual Censys import failed unexpectedly."


class CliArgumentError(ValueError):
    """The manual Censys import arguments were invalid."""


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CliArgumentError("Invalid manual Censys import arguments.")


def _build_parser() -> CliArgumentParser:
    parser = CliArgumentParser(
        description="Import approved public Censys metadata from a local JSON file.",
    )
    parser.add_argument("--file", required=True, dest="file_path")
    return parser


def run_import(
    *,
    file_path: str | os.PathLike[str],
    clock: Callable[[], datetime] = utc_now,
    loader: Callable[[str | os.PathLike[str]], CensysPublicationDocument] = (
        load_censys_publication_file
    ),
    adapter: Callable[[str, object], PublicationCandidate] = adapt_censys_publication,
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    pipeline_factory: Callable[[Session], PublicationPipeline] = PublicationPipeline,
    service_factory: Callable[..., CensysPublicationsIngestionService] = (
        CensysPublicationsIngestionService
    ),
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run one caller-transactional Censys local-file import."""

    try:
        document = loader(file_path)
    except MemoryError:
        raise
    except CensysPublicationFileError:
        print("The Censys publication file was rejected safely.", file=stderr)
        return 2
    except Exception:
        print(_LOCAL_FAILURE_MESSAGE, file=stderr)
        return 1

    try:
        observed_at = clock()
        if (
            not isinstance(observed_at, datetime)
            or observed_at.tzinfo is None
            or observed_at.utcoffset() is None
        ):
            raise ValueError("Invalid Censys import clock.")
        observed_at = observed_at.astimezone(UTC)
    except MemoryError:
        raise
    except Exception:
        print("Manual Censys import requires a timezone-aware clock.", file=stderr)
        return 1

    candidates: list[PublicationCandidate] = []
    failure_kinds: list[CensysFailureAuditKind] = []
    try:
        for record in document.publications:
            try:
                candidates.append(adapter(document.source_slug, record))
            except CensysPublicationRecordError:
                failure_kinds.append(CensysFailureAuditKind.VALIDATION_REJECTED)
    except MemoryError:
        raise
    except Exception:
        print(_UNEXPECTED_FAILURE_MESSAGE, file=stderr)
        return 1

    session: Session | None = None
    run: IngestionRun | None = None
    failure_message: str | None = None
    close_failed = False
    system_exception_active = False

    try:
        session = session_factory()
        service = service_factory(
            session,
            pipeline_factory=pipeline_factory,
        )
        result = service.ingest(
            source_slug=document.source_slug,
            candidates=tuple(candidates),
            failure_kinds=tuple(failure_kinds),
            records_fetched=len(document.publications),
            trigger=CensysIngestionTrigger.LOCAL_FILE,
            observed_at=observed_at,
        )
        run = result.run
    except _SYSTEM_EXCEPTIONS:
        system_exception_active = True
        raise
    except CensysIngestionDatabaseError:
        failure_message = _DATABASE_FAILURE_MESSAGE
    except CensysIngestionError:
        failure_message = _UNEXPECTED_FAILURE_MESSAGE
    except Exception:
        failure_message = _UNEXPECTED_FAILURE_MESSAGE
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
    if failure_message is not None or run is None:
        print(failure_message or _UNEXPECTED_FAILURE_MESSAGE, file=stderr)
        return 1

    try:
        _print_summary(run, stdout)
        status = run.status
    except _SYSTEM_EXCEPTIONS:
        raise
    except Exception:
        print(_UNEXPECTED_FAILURE_MESSAGE, file=stderr)
        return 1
    if status != "succeeded":
        print(
            "Manual Censys import completed with a controlled failure.",
            file=stderr,
        )
        return 1
    return 0


def _print_summary(run: IngestionRun, stdout: TextIO) -> None:
    print("Manual Censys import completed.", file=stdout)
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
    return run_import(file_path=arguments.file_path)


if __name__ == "__main__":
    raise SystemExit(main())
