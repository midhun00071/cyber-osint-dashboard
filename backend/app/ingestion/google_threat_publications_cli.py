"""Manual ingestion for Google TI and Mandiant public threat publications."""

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
from app.ingestion.adapters.google_threat_publications import (
    GoogleThreatFeedError,
    GoogleThreatPublicationDocument,
    GoogleThreatPublicationRecordError,
    adapt_google_threat_publication,
    parse_google_threat_feed_entries,
)
from app.ingestion.collectors.google_threat_intelligence_rss_client import (
    GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
    MANDIANT_THREAT_RESEARCH_SOURCE_SLUG,
    GoogleThreatIntelligenceRssClient,
    GoogleThreatRssClientError,
    GoogleThreatRssContentTypeError,
    GoogleThreatRssFetchResult,
    GoogleThreatRssHttpError,
    GoogleThreatRssRateLimitError,
    GoogleThreatRssRedirectError,
    GoogleThreatRssRequestError,
    GoogleThreatRssResponseTooLargeError,
)
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPersistenceError,
    PublicationPersistenceResult,
    PublicationPipeline,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord
from app.models.common import utc_now


DEFAULT_MAX_RECORDS = 25
MIN_MAX_RECORDS = 1
MAX_MAX_RECORDS = 100
SOURCE_SLUGS = (
    GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
    MANDIANT_THREAT_RESEARCH_SOURCE_SLUG,
)


class CliArgumentError(ValueError):
    """The manual Google Threat publication arguments were invalid."""


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CliArgumentError("Invalid manual Google Threat publication arguments.")


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
        description="Manually fetch approved Google TI and Mandiant publications.",
    )
    parser.add_argument(
        "--max-records",
        type=_bounded_integer("maximum records", MIN_MAX_RECORDS, MAX_MAX_RECORDS),
        default=DEFAULT_MAX_RECORDS,
    )
    return parser


def run_ingestion(
    *,
    max_records: int,
    clock: Callable[[], datetime] = utc_now,
    client_factory: Callable[..., GoogleThreatIntelligenceRssClient] = (
        GoogleThreatIntelligenceRssClient
    ),
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    feed_parser: Callable[..., GoogleThreatPublicationDocument] = (
        parse_google_threat_feed_entries
    ),
    adapter: Callable[[object], PublicationCandidate] = adapt_google_threat_publication,
    pipeline_factory: Callable[[Session], PublicationPipeline] = PublicationPipeline,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run one caller-transactional shared-feed ingestion and return an exit code."""

    if not _valid_integer(max_records, MIN_MAX_RECORDS, MAX_MAX_RECORDS):
        print("Invalid manual Google Threat publication parameters.", file=stderr)
        return 2
    observed_at = _safe_observation_time(clock)
    if observed_at is None:
        print(
            "Manual Google Threat publication ingestion could not establish a safe observation time.",
            file=stderr,
        )
        return 1
    session: Session | None = None
    unassigned_failed = 0
    capped = False

    try:
        session = session_factory()
        pipeline = pipeline_factory(session)
        runs = {
            slug: _create_run(session, pipeline, slug, observed_at)
            for slug in SOURCE_SLUGS
        }
        feed = _fetch_feed(client_factory, session, runs, observed_at)
        if feed is not None:
            entries = _parse_feed_entries(feed, session, runs, feed_parser, observed_at)
            if entries is not None:
                capped = entries.was_truncated or len(entries.entries) > max_records
                unassigned_failed = _process_entries(
                    session,
                    runs,
                    entries.entries[:max_records],
                    adapter,
                    pipeline,
                    observed_at,
                )
        for run in runs.values():
            run.status = _run_status(run, capped=capped, unassigned_failed=unassigned_failed)
            run.completed_at = observed_at
            run.error_count = len(run.errors)
            run.safe_summary = _safe_run_summary(run, capped, unassigned_failed)
        session.commit()
        _print_summary(runs, capped, unassigned_failed, stdout)
        if any(run.status != "succeeded" for run in runs.values()) or unassigned_failed:
            print(
                "Manual Google Threat publication ingestion completed with a controlled failure.",
                file=stderr,
            )
            return 1
        return 0
    except (PublicationPersistenceError, SQLAlchemyError):
        if session is not None:
            session.rollback()
        print(
            "Manual Google Threat publication ingestion failed during a database operation.",
            file=stderr,
        )
        return 1
    except Exception:
        if session is not None:
            session.rollback()
        print("Manual Google Threat publication ingestion failed unexpectedly.", file=stderr)
        return 1
    finally:
        if session is not None:
            session.close()


def _valid_integer(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


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
    pipeline: PublicationPipeline,
    source_slug: str,
    observed_at: datetime,
) -> IngestionRun:
    source = pipeline.ensure_source(source_slug)
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
        safe_summary="Manual Google Threat shared-feed publication ingestion started.",
        created_at=observed_at,
    )
    session.add(run)
    session.flush()
    return run


def _fetch_feed(
    client_factory: Callable[..., GoogleThreatIntelligenceRssClient],
    session: Session,
    runs: dict[str, IngestionRun],
    observed_at: datetime,
) -> GoogleThreatRssFetchResult | None:
    try:
        with client_factory() as client:
            return client.fetch_publications()
    except GoogleThreatRssRateLimitError:
        _record_global_error(session, runs, "google_threat_rss_rate_limit", "The Google Threat RSS feed rate limit was reached.", True, observed_at)
    except (GoogleThreatRssRequestError, GoogleThreatRssHttpError):
        _record_global_error(session, runs, "google_threat_rss_fetch_error", "The Google Threat RSS fetch did not complete.", True, observed_at)
    except (
        GoogleThreatRssRedirectError,
        GoogleThreatRssResponseTooLargeError,
        GoogleThreatRssContentTypeError,
    ):
        _record_global_error(session, runs, "google_threat_rss_fetch_rejected", "The Google Threat RSS fetch was rejected by safety controls.", False, observed_at)
    except GoogleThreatRssClientError:
        _record_global_error(session, runs, "google_threat_rss_fetch_error", "The Google Threat RSS fetch did not complete.", True, observed_at)
    return None


def _parse_feed_entries(
    feed: GoogleThreatRssFetchResult,
    session: Session,
    runs: dict[str, IngestionRun],
    feed_parser: Callable[..., GoogleThreatPublicationDocument],
    observed_at: datetime,
) -> GoogleThreatPublicationDocument | None:
    try:
        document = feed_parser(feed.feed_bytes, max_entries=MAX_MAX_RECORDS)
        return document
    except GoogleThreatFeedError:
        _record_global_error(session, runs, "google_threat_feed_parse_error", "The Google Threat RSS feed failed safe parsing.", False, observed_at)
        return None


def _process_entries(
    session: Session,
    runs: dict[str, IngestionRun],
    entries: Sequence[object],
    adapter: Callable[[object], PublicationCandidate],
    pipeline: PublicationPipeline,
    observed_at: datetime,
) -> int:
    seen: dict[
        str,
        dict[str, tuple[PublicationCandidate, PublicationPersistenceResult]],
    ] = {slug: {} for slug in SOURCE_SLUGS}
    unassigned_failed = 0
    for entry in entries:
        try:
            candidate = adapter(entry)
        except GoogleThreatPublicationRecordError as exc:
            if exc.source_slug in runs:
                run = runs[exc.source_slug]
                run.records_fetched += 1
                _record_failure(
                    session,
                    run,
                    "google_threat_publication_validation_error",
                    "A Google Threat publication failed safe validation.",
                    observed_at,
                    failure_stage=exc.failure_stage,
                    diagnostic_fingerprint=exc.diagnostic_fingerprint,
                )
            else:
                unassigned_failed += 1
                _record_unassigned_error(session, runs, observed_at)
            continue
        run = runs[candidate.source_slug]
        run.records_fetched += 1
        existing = seen[candidate.source_slug].get(candidate.source_external_id)
        if existing is not None and existing[0] != candidate:
            _record_failure(session, run, "google_threat_duplicate_conflict", "Conflicting duplicate Google Threat publications were returned.", observed_at)
            continue
        if existing is not None:
            _record_identical_duplicate(session, run, existing[1], observed_at)
            continue
        result = _persist_candidate(session, run, pipeline, candidate, observed_at)
        seen[candidate.source_slug][candidate.source_external_id] = (candidate, result)
    return unassigned_failed


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
    session.add(
        IngestionRunRecord(
            ingestion_run=run,
            source_record=None,
            intelligence_item_id=first_result.intelligence_item_id,
            action="unchanged",
            safe_detail="Identical duplicate Google Threat publication ignored.",
            processed_at=observed_at,
        )
    )
    run.records_unchanged += 1


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
        safe_detail=result.message or f"Google Threat publication {result.outcome}.",
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
                error_type="google_threat_publication_persistence_error",
                safe_message="A Google Threat publication could not be persisted safely.",
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
    *,
    failure_stage: str | None = None,
    diagnostic_fingerprint: str | None = None,
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
            failure_stage=failure_stage,
            diagnostic_fingerprint=diagnostic_fingerprint,
            safe_context=None,
            retryable=False,
            retry_count=0,
            occurred_at=observed_at,
        )
    )
    run.records_failed += 1


def _record_global_error(
    session: Session,
    runs: dict[str, IngestionRun],
    error_type: str,
    message: str,
    retryable: bool,
    observed_at: datetime,
) -> None:
    for run in runs.values():
        session.add(
            IngestionError(
                ingestion_run=run,
                ingestion_run_record=None,
                source_record=None,
                error_type=error_type,
                safe_message=message,
                retryable=retryable,
                retry_count=0,
                occurred_at=observed_at,
            )
        )
        run.records_failed += 1


def _record_unassigned_error(
    session: Session,
    runs: dict[str, IngestionRun],
    observed_at: datetime,
) -> None:
    message = (
        "A shared Google Threat feed entry could not be attributed to an approved "
        "publication owner."
    )
    for run in runs.values():
        session.add(
            IngestionError(
                ingestion_run=run,
                ingestion_run_record=None,
                source_record=None,
                error_type="google_threat_unassigned_feed_entry",
                safe_message=message,
                retryable=False,
                retry_count=0,
                occurred_at=observed_at,
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


def _run_status(run: IngestionRun, *, capped: bool, unassigned_failed: int) -> str:
    processed = (
        run.records_created
        + run.records_updated
        + run.records_unchanged
        + run.records_skipped
        + run.records_failed
    )
    if run.records_failed and processed == run.records_failed:
        return "failed"
    if capped or unassigned_failed or run.records_failed or run.records_skipped:
        return "partial"
    return "succeeded"


def _safe_run_summary(run: IngestionRun, capped: bool, unassigned_failed: int) -> str:
    return (
        f"Manual Google Threat publication ingestion {run.status}; "
        f"source={run.source.slug}; fetched={run.records_fetched}; "
        f"created={run.records_created}; updated={run.records_updated}; "
        f"unchanged={run.records_unchanged}; skipped={run.records_skipped}; "
        f"failed={run.records_failed}; unassigned={unassigned_failed}; "
        f"capped={str(capped).lower()}."
    )


def _print_summary(
    runs: dict[str, IngestionRun],
    capped: bool,
    unassigned_failed: int,
    stdout: TextIO,
) -> None:
    print("Manual Google Threat publication ingestion completed.", file=stdout)
    for slug in SOURCE_SLUGS:
        run = runs[slug]
        print(f"Source: {slug}", file=stdout)
        print(f"Run ID: {run.public_id}", file=stdout)
        print(f"Status: {run.status}", file=stdout)
        print(f"Fetched: {run.records_fetched}", file=stdout)
        print(f"Created: {run.records_created}", file=stdout)
        print(f"Updated: {run.records_updated}", file=stdout)
        print(f"Unchanged: {run.records_unchanged}", file=stdout)
        print(f"Skipped: {run.records_skipped}", file=stdout)
        print(f"Failed: {run.records_failed}", file=stdout)
    print(f"Unassigned rejected: {unassigned_failed}", file=stdout)
    print(f"Capped: {str(capped).lower()}", file=stdout)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _build_parser().parse_args(argv)
    except CliArgumentError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return run_ingestion(max_records=arguments.max_records)


if __name__ == "__main__":
    raise SystemExit(main())
