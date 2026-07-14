"""Manual local-file ingestion for official public Censys publications."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from datetime import UTC, datetime
import os
import sys
from typing import TextIO

from sqlalchemy.exc import SQLAlchemyError
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
    PublicationPersistenceError,
    PublicationPersistenceResult,
    PublicationPipeline,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord
from app.models.common import utc_now


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
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run one caller-transactional Censys local-file import."""

    try:
        document = loader(file_path)
    except CensysPublicationFileError:
        print("The Censys publication file was rejected safely.", file=stderr)
        return 2

    observed_at = clock()
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        print("Manual Censys import requires a timezone-aware clock.", file=stderr)
        return 1
    observed_at = observed_at.astimezone(UTC)
    session: Session | None = None

    try:
        session = session_factory()
        pipeline = pipeline_factory(session)
        source = pipeline.ensure_source(document.source_slug)
        run = IngestionRun(
            source=source,
            trigger_type="manual",
            status="running",
            started_at=observed_at,
            completed_at=None,
            records_fetched=len(document.publications),
            records_created=0,
            records_updated=0,
            records_unchanged=0,
            records_skipped=0,
            records_failed=0,
            error_count=0,
            checkpoint_before=source.checkpoint_value,
            checkpoint_after=None,
            safe_summary="Manual Censys local-file publication import started.",
            created_at=observed_at,
        )
        session.add(run)
        session.flush()

        candidates_by_external_id: dict[str, PublicationCandidate] = {}
        for record in document.publications:
            try:
                candidate = adapter(document.source_slug, record)
            except CensysPublicationRecordError:
                _record_validation_failure(session, run, observed_at)
                continue
            existing = candidates_by_external_id.get(candidate.source_external_id)
            if existing is not None and existing != candidate:
                _record_validation_failure(session, run, observed_at)
                continue
            if existing is None:
                candidates_by_external_id[candidate.source_external_id] = candidate
            _persist_candidate(session, run, pipeline, candidate, observed_at)

        run.status = _run_status(run)
        run.completed_at = observed_at
        run.error_count = run.records_failed
        run.safe_summary = _safe_run_summary(run)
        session.commit()
        _print_summary(run, stdout)
        if run.status != "succeeded":
            print(
                "Manual Censys import completed with a controlled failure.",
                file=stderr,
            )
            return 1
        return 0
    except (PublicationPersistenceError, SQLAlchemyError):
        if session is not None:
            session.rollback()
        print("Manual Censys import failed during a database operation.", file=stderr)
        return 1
    except Exception:
        if session is not None:
            session.rollback()
        print("Manual Censys import failed unexpectedly.", file=stderr)
        return 1
    finally:
        if session is not None:
            session.close()


def _persist_candidate(
    session: Session,
    run: IngestionRun,
    pipeline: PublicationPipeline,
    candidate: PublicationCandidate,
    observed_at: datetime,
) -> None:
    nested = session.begin_nested() if hasattr(session, "begin_nested") else nullcontext()
    with nested:
        result = pipeline.persist(candidate, observed_at=observed_at)
        _record_persistence_result(session, run, result, observed_at)


def _record_persistence_result(
    session: Session,
    run: IngestionRun,
    result: PublicationPersistenceResult,
    observed_at: datetime,
) -> None:
    safe_detail = result.message or f"Censys publication {result.outcome}."
    audit_record = IngestionRunRecord(
        ingestion_run=run,
        source_record=result.source_record,
        intelligence_item_id=result.intelligence_item_id,
        action=result.outcome,
        safe_detail=safe_detail,
        processed_at=observed_at,
    )
    session.add(audit_record)
    _increment_outcome(run, result.outcome)
    if result.outcome == "failed":
        session.add(
            IngestionError(
                ingestion_run=run,
                ingestion_run_record=audit_record,
                source_record=result.source_record,
                error_type="censys_publication_persistence_error",
                safe_message="A Censys publication could not be persisted safely.",
                retryable=False,
                retry_count=0,
                occurred_at=observed_at,
            )
        )


def _record_validation_failure(
    session: Session,
    run: IngestionRun,
    observed_at: datetime,
) -> None:
    message = "A Censys publication failed safe validation."
    audit_record = IngestionRunRecord(
        ingestion_run=run,
        source_record=None,
        intelligence_item_id=None,
        action="failed",
        safe_detail=message,
        processed_at=observed_at,
    )
    session.add(audit_record)
    session.add(
        IngestionError(
            ingestion_run=run,
            ingestion_run_record=audit_record,
            source_record=None,
            error_type="censys_publication_validation_error",
            safe_message=message,
            retryable=False,
            retry_count=0,
            occurred_at=observed_at,
        )
    )
    run.records_failed += 1


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


def _run_status(run: IngestionRun) -> str:
    processed = (
        run.records_created
        + run.records_updated
        + run.records_unchanged
        + run.records_skipped
        + run.records_failed
    )
    if run.records_failed and processed == run.records_failed:
        return "failed"
    if run.records_failed or run.records_skipped:
        return "partial"
    return "succeeded"


def _safe_run_summary(run: IngestionRun) -> str:
    return (
        f"Manual Censys import {run.status}; fetched={run.records_fetched}; "
        f"created={run.records_created}; updated={run.records_updated}; "
        f"unchanged={run.records_unchanged}; skipped={run.records_skipped}; "
        f"failed={run.records_failed}."
    )


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
