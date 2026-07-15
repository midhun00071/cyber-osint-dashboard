"""Manual local-file ingestion for Anomali Cyber Watch publications."""

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
from app.ingestion.adapters.anomali_publications import (
    ANOMALI_SOURCE_SLUG,
    AnomaliPublicationDocument,
    AnomaliPublicationFileError,
    AnomaliPublicationRecordError,
    adapt_anomali_publication,
    load_anomali_publication_file,
)
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPersistenceError,
    PublicationPersistenceResult,
    PublicationPipeline,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord, IntelligenceSource
from app.models.common import utc_now


class CliArgumentError(ValueError):
    """The manual Anomali import arguments were invalid."""


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CliArgumentError("Invalid manual Anomali import arguments.")


def _build_parser() -> CliArgumentParser:
    parser = CliArgumentParser(
        description="Import approved Anomali Cyber Watch metadata from local JSON.",
    )
    parser.add_argument("--file", required=True, dest="file_path")
    return parser


def run_import(
    *,
    file_path: str | os.PathLike[str],
    clock: Callable[[], datetime] = utc_now,
    loader: Callable[[str | os.PathLike[str]], AnomaliPublicationDocument] = (
        load_anomali_publication_file
    ),
    adapter: Callable[[object], PublicationCandidate] = adapt_anomali_publication,
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    pipeline_factory: Callable[[Session], PublicationPipeline] = PublicationPipeline,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run one caller-transactional Anomali local catalogue import."""

    try:
        document = loader(file_path)
    except AnomaliPublicationFileError:
        print("The Anomali publication file was rejected safely.", file=stderr)
        return 1
    except Exception:
        print(
            "Manual Anomali publication ingestion could not load the local "
            "catalogue safely.",
            file=stderr,
        )
        return 1
    observed_at = _safe_observation_time(clock)
    if observed_at is None:
        print(
            "Manual Anomali publication ingestion could not establish a safe observation time.",
            file=stderr,
        )
        return 1

    session: Session | None = None
    run_to_report: IngestionRun | None = None
    primary_error: str | None = None
    intended_exit_code = 1
    rollback_succeeded = True
    close_succeeded = True
    try:
        session = session_factory()
        pipeline = pipeline_factory(session)
        source = pipeline.ensure_source(ANOMALI_SOURCE_SLUG)
        run = _create_run(session, source, observed_at)
        _process_records(
            session,
            run,
            document.publications,
            adapter,
            pipeline,
            observed_at,
        )
        run.status = _run_status(run)
        run.completed_at = observed_at
        run.error_count = run.records_failed
        run.safe_summary = _safe_run_summary(run)
        session.commit()
        run_to_report = run
        if run.status != "succeeded":
            primary_error = (
                "Manual Anomali publication ingestion completed with a controlled "
                "failure."
            )
        else:
            intended_exit_code = 0
    except (PublicationPersistenceError, SQLAlchemyError):
        if session is not None:
            rollback_succeeded = _safe_rollback(session)
        primary_error = (
            "Manual Anomali publication ingestion failed during a database operation."
        )
    except Exception:
        if session is not None:
            rollback_succeeded = _safe_rollback(session)
        primary_error = "Manual Anomali publication ingestion failed unexpectedly."
    finally:
        if session is not None:
            close_succeeded = _safe_close(session)

    cleanup_failed = not rollback_succeeded or not close_succeeded
    if not cleanup_failed and run_to_report is not None:
        _print_summary(run_to_report, stdout)
    if primary_error is not None:
        print(primary_error, file=stderr)
    if not rollback_succeeded:
        print(
            "Manual Anomali publication ingestion could not roll back database "
            "changes safely.",
            file=stderr,
        )
    if not close_succeeded:
        print(
            "Manual Anomali publication ingestion could not close database resources "
            "safely.",
            file=stderr,
        )
    return 1 if cleanup_failed else intended_exit_code


def _safe_rollback(session: Session) -> bool:
    try:
        session.rollback()
        return True
    except Exception:
        return False


def _safe_close(session: Session) -> bool:
    try:
        session.close()
        return True
    except Exception:
        return False


def _safe_observation_time(clock: Callable[[], datetime]) -> datetime | None:
    try:
        observed_at = clock()
        if not isinstance(observed_at, datetime):
            return None
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            return None
        return observed_at.astimezone(UTC)
    except Exception:
        return None


def _create_run(
    session: Session,
    source: IntelligenceSource,
    observed_at: datetime,
) -> IngestionRun:
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
        safe_summary="Manual Anomali local-file publication ingestion started.",
        created_at=observed_at,
    )
    session.add(run)
    session.flush()
    return run


def _process_records(
    session: Session,
    run: IngestionRun,
    records: Sequence[object],
    adapter: Callable[[object], PublicationCandidate],
    pipeline: PublicationPipeline,
    observed_at: datetime,
) -> None:
    seen: dict[str, tuple[PublicationCandidate, PublicationPersistenceResult]] = {}
    for record in records:
        run.records_fetched += 1
        try:
            candidate = adapter(record)
        except AnomaliPublicationRecordError:
            _record_failure(
                session,
                run,
                "anomali_publication_validation_error",
                "An Anomali Cyber Watch publication failed safe validation.",
                observed_at,
            )
            continue
        existing = seen.get(candidate.source_external_id)
        if existing is not None and existing[0] != candidate:
            _record_failure(
                session,
                run,
                "anomali_publication_duplicate_conflict",
                "Conflicting duplicate Anomali Cyber Watch publications were rejected.",
                observed_at,
            )
            continue
        if existing is not None:
            _record_identical_duplicate(session, run, existing[1], observed_at)
            continue
        result = _persist_candidate(session, run, pipeline, candidate, observed_at)
        seen[candidate.source_external_id] = (candidate, result)


def _persist_candidate(
    session: Session,
    run: IngestionRun,
    pipeline: PublicationPipeline,
    candidate: PublicationCandidate,
    observed_at: datetime,
) -> PublicationPersistenceResult:
    nested = session.begin_nested() if hasattr(session, "begin_nested") else nullcontext()
    with nested:
        result = pipeline.persist(candidate, observed_at=observed_at)
        _record_persistence_result(session, run, result, observed_at)
    return result


def _record_identical_duplicate(
    session: Session,
    run: IngestionRun,
    first_result: PublicationPersistenceResult,
    observed_at: datetime,
) -> None:
    if first_result.outcome in {"created", "updated", "unchanged"}:
        action = "unchanged"
        intelligence_item_id = first_result.intelligence_item_id
        safe_detail = "Identical duplicate Anomali Cyber Watch publication ignored."
    elif first_result.outcome == "skipped":
        action = "skipped"
        intelligence_item_id = None
        safe_detail = "Identical duplicate Anomali Cyber Watch publication skipped."
    else:
        _record_failure(
            session,
            run,
            "anomali_publication_duplicate_persistence_error",
            "An identical duplicate Anomali Cyber Watch publication repeated a "
            "failed persistence outcome.",
            observed_at,
        )
        return

    session.add(
        IngestionRunRecord(
            ingestion_run=run,
            source_record=None,
            intelligence_item_id=intelligence_item_id,
            action=action,
            safe_detail=safe_detail,
            processed_at=observed_at,
        )
    )
    _increment_outcome(run, action)


def _record_persistence_result(
    session: Session,
    run: IngestionRun,
    result: PublicationPersistenceResult,
    observed_at: datetime,
) -> None:
    audit_record = IngestionRunRecord(
        ingestion_run=run,
        source_record=result.source_record,
        intelligence_item_id=result.intelligence_item_id,
        action=result.outcome,
        safe_detail=result.message or f"Anomali Cyber Watch publication {result.outcome}.",
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
                error_type="anomali_publication_persistence_error",
                safe_message="An Anomali Cyber Watch publication could not be persisted safely.",
                retryable=False,
                retry_count=0,
                occurred_at=observed_at,
            )
        )


def _record_failure(
    session: Session,
    run: IngestionRun,
    error_type: str,
    message: str,
    observed_at: datetime,
) -> None:
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
            error_type=error_type,
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
        f"Manual Anomali publication ingestion {run.status}; "
        f"fetched={run.records_fetched}; created={run.records_created}; "
        f"updated={run.records_updated}; unchanged={run.records_unchanged}; "
        f"skipped={run.records_skipped}; failed={run.records_failed}."
    )


def _print_summary(run: IngestionRun, stdout: TextIO) -> None:
    print("Manual Anomali publication ingestion completed.", file=stdout)
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
        return 1
    return run_import(file_path=arguments.file_path)


if __name__ == "__main__":
    raise SystemExit(main())
