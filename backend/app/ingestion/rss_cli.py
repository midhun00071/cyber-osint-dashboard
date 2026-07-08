"""Manual, bounded CERT-EU RSS ingestion command with sanitized audit records."""

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
from app.ingestion.collectors.rss_client import (
    RssClient,
    RssClientError,
    RssContentTypeError,
    RssFetchResult,
    RssHttpError,
    RssRateLimitError,
    RssRedirectError,
    RssRequestError,
    RssResponseTooLargeError,
)
from app.ingestion.normalizers.rss import (
    NormalizedRssEntry,
    RssNormalizationError,
    normalize_rss_entry,
    parse_rss_feed_entries,
)
from app.ingestion.services.rss_ingestion_service import (
    RssIngestionService,
    RssPersistenceError,
    RssPersistenceResult,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord
from app.models.common import utc_now


DEFAULT_MAX_RECORDS = 25
MIN_MAX_RECORDS = 1
MAX_MAX_RECORDS = 100


class CliArgumentError(ValueError):
    """The manual RSS command arguments were invalid."""


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CliArgumentError("Invalid manual RSS ingestion arguments.")


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
        description="Manually fetch and store approved public CERT-EU RSS advisories.",
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
    client_factory: Callable[..., RssClient] = RssClient,
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    feed_parser: Callable[[bytes], list[dict]] = parse_rss_feed_entries,
    entry_normalizer: Callable[[object], NormalizedRssEntry] = normalize_rss_entry,
    service_factory: Callable[..., RssIngestionService] = RssIngestionService,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run one caller-transactional manual RSS ingestion and return an exit code."""

    if not _valid_integer(max_records, MIN_MAX_RECORDS, MAX_MAX_RECORDS):
        print("Invalid manual RSS ingestion parameters.", file=stderr)
        return 2

    observed_at = clock()
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        print("Manual RSS ingestion requires a timezone-aware clock.", file=stderr)
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
            safe_summary="Manual bounded CERT-EU RSS ingestion started.",
            created_at=observed_at,
        )
        session.add(run)
        session.flush()

        capped = False
        feed = _fetch_feed(client_factory, session, run, observed_at)
        if feed is not None:
            entries = _parse_feed_entries(
                feed,
                session,
                run,
                feed_parser,
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

        if capped:
            run.status = "partial"
        elif run.records_failed > 0 and _processed_count(run) == run.records_failed:
            run.status = "failed"
        elif run.records_failed > 0 or run.records_skipped > 0:
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
            print("Manual RSS ingestion completed with a controlled failure.", file=stderr)
            return 1
        return 0
    except (RssPersistenceError, SQLAlchemyError):
        if session is not None:
            session.rollback()
        print("Manual RSS ingestion failed during a database operation.", file=stderr)
        return 1
    except Exception:
        if session is not None:
            session.rollback()
        print("Manual RSS ingestion failed unexpectedly.", file=stderr)
        return 1
    finally:
        if session is not None:
            session.close()


def _fetch_feed(
    client_factory: Callable[..., RssClient],
    session: Session,
    run: IngestionRun,
    observed_at: datetime,
) -> RssFetchResult | None:
    try:
        with client_factory() as client:
            return client.fetch_cert_eu_security_advisories()
    except RssRateLimitError:
        _add_error(
            session,
            run,
            "rss_rate_limit",
            "The CERT-EU RSS feed rate limit was reached.",
            retryable=True,
            occurred_at=observed_at,
        )
    except (RssRequestError, RssHttpError):
        _add_error(
            session,
            run,
            "rss_fetch_error",
            "The CERT-EU RSS fetch did not complete.",
            retryable=True,
            occurred_at=observed_at,
        )
    except (RssRedirectError, RssResponseTooLargeError, RssContentTypeError):
        _add_error(
            session,
            run,
            "rss_fetch_rejected",
            "The CERT-EU RSS fetch was rejected by safety controls.",
            retryable=False,
            occurred_at=observed_at,
        )
    except RssClientError:
        _add_error(
            session,
            run,
            "rss_fetch_error",
            "The CERT-EU RSS fetch did not complete.",
            retryable=True,
            occurred_at=observed_at,
        )
    run.records_failed += 1
    return None


def _parse_feed_entries(
    feed: RssFetchResult,
    session: Session,
    run: IngestionRun,
    feed_parser: Callable[[bytes], list[dict]],
    observed_at: datetime,
) -> list[dict] | None:
    try:
        entries = feed_parser(feed.feed_bytes)
        run.records_fetched = len(entries)
        return entries
    except RssNormalizationError:
        _record_failure(
            session,
            run,
            "rss_normalization_error",
            "The CERT-EU RSS feed failed safe normalization.",
            observed_at,
        )
        return None


def _process_entries(
    session: Session,
    run: IngestionRun,
    entries: list[dict],
    entry_normalizer: Callable[[object], NormalizedRssEntry],
    service: RssIngestionService,
    observed_at: datetime,
) -> None:
    by_external_id: dict[str, NormalizedRssEntry] = {}
    by_url_hash: dict[str, NormalizedRssEntry] = {}
    for entry in entries:
        try:
            normalized = entry_normalizer(entry)
        except RssNormalizationError:
            _record_failure(
                session,
                run,
                "rss_normalization_error",
                "A CERT-EU RSS advisory failed safe normalization.",
                observed_at,
            )
            continue

        external_match = by_external_id.get(normalized.source_external_id)
        url_match = by_url_hash.get(normalized.canonical_url_hash)
        existing = external_match or url_match
        if existing is not None:
            if (
                (
                    external_match is not None
                    and external_match.canonical_url_hash != normalized.canonical_url_hash
                )
                or (
                    url_match is not None
                    and url_match.source_external_id != normalized.source_external_id
                )
                or existing.content_hash != normalized.content_hash
            ):
                _record_failure(
                    session,
                    run,
                    "rss_duplicate_conflict",
                    "Conflicting duplicate CERT-EU RSS advisories were returned.",
                    observed_at,
                )
            continue

        by_external_id[normalized.source_external_id] = normalized
        by_url_hash[normalized.canonical_url_hash] = normalized
        _process_normalized(session, run, normalized, service, observed_at)


def _process_normalized(
    session: Session,
    run: IngestionRun,
    normalized: NormalizedRssEntry,
    service: RssIngestionService,
    observed_at: datetime,
) -> None:
    try:
        nested = session.begin_nested() if hasattr(session, "begin_nested") else nullcontext()
        with nested:
            result: RssPersistenceResult = service.persist(
                normalized,
                observed_at=observed_at,
            )
            session.add(
                IngestionRunRecord(
                    ingestion_run=run,
                    source_record=result.source_record,
                    intelligence_item_id=result.intelligence_item_id,
                    action=result.outcome,
                    safe_detail=result.message or f"CERT-EU RSS advisory {result.outcome}.",
                    processed_at=observed_at,
                )
            )
            _increment_outcome(run, result.outcome)
            if result.outcome == "failed":
                _add_error(
                    session,
                    run,
                    "rss_persistence_error",
                    "A CERT-EU RSS advisory could not be persisted safely.",
                    retryable=False,
                    occurred_at=observed_at,
                )
    except (RssPersistenceError, SQLAlchemyError):
        _record_failure(
            session,
            run,
            "rss_persistence_error",
            "A CERT-EU RSS advisory database operation failed.",
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
        f"Manual RSS ingestion {run.status}; fetched={run.records_fetched}; "
        f"created={run.records_created}; updated={run.records_updated}; "
        f"unchanged={run.records_unchanged}; skipped={run.records_skipped}; "
        f"failed={run.records_failed}; capped={str(capped).lower()}."
    )


def _print_summary(run: IngestionRun, capped: bool, stdout: TextIO) -> None:
    print("Manual RSS ingestion completed.", file=stdout)
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
        print("Record cap reached; not all fetched feed entries were processed.", file=stdout)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _build_parser().parse_args(argv)
    except CliArgumentError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    return run_ingestion(max_records=arguments.max_records)


if __name__ == "__main__":
    raise SystemExit(main())
