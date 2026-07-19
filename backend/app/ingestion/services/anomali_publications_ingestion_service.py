"""Transactional persistence and safe audit service for Anomali publications."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from types import MappingProxyType

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.adapters.anomali_publications import ANOMALI_SOURCE_SLUG
from app.ingestion.collectors.anomali_publications_client import (
    MAX_RECORDS,
    AnomaliFailureReason,
)
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPersistenceError,
    PublicationPersistenceResult,
    PublicationPipeline,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord, SourceRecord
from app.models.common import utc_now


_SYSTEM_EXCEPTIONS = (MemoryError, KeyboardInterrupt, SystemExit, GeneratorExit)
_BATCH_DUPLICATE_DETAIL = (
    "A duplicate Anomali publication matched an earlier batch entry."
)
_REPEATED_SOURCE_RECORD_DETAIL = (
    "An Anomali publication outcome matched an earlier linked audit entry."
)


class AnomaliIngestionError(RuntimeError):
    """An Anomali ingestion batch could not complete safely."""


class AnomaliIngestionInputError(AnomaliIngestionError, ValueError):
    """The service received data outside its closed validated interface."""


class AnomaliIngestionDatabaseError(AnomaliIngestionError):
    """The Anomali transaction failed without exposing database details."""


class AnomaliIngestionTrigger(str, Enum):
    """Closed manual entry point for this persistence service."""

    LIVE = "live"


class AnomaliFailureAuditKind(str, Enum):
    """Closed safe reasons that may create pre-persistence audit failures."""

    VALIDATION_REJECTED = "validation_rejected"
    TRANSPORT_FAILURE = "transport_failure"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    HTTP_FAILURE = "http_failure"
    REDIRECT_REJECTED = "redirect_rejected"
    CONTENT_TYPE_REJECTED = "content_type_rejected"
    RESPONSE_TOO_LARGE = "response_too_large"
    METADATA_REJECTED = "metadata_rejected"


COLLECTOR_FAILURE_AUDIT_KINDS = MappingProxyType(
    {
        AnomaliFailureReason.TRANSPORT_FAILURE: (
            AnomaliFailureAuditKind.TRANSPORT_FAILURE
        ),
        AnomaliFailureReason.TIMEOUT: AnomaliFailureAuditKind.TIMEOUT,
        AnomaliFailureReason.RATE_LIMITED: AnomaliFailureAuditKind.RATE_LIMITED,
        AnomaliFailureReason.HTTP_FAILURE: AnomaliFailureAuditKind.HTTP_FAILURE,
        AnomaliFailureReason.REDIRECT_REJECTED: (
            AnomaliFailureAuditKind.REDIRECT_REJECTED
        ),
        AnomaliFailureReason.CONTENT_TYPE_REJECTED: (
            AnomaliFailureAuditKind.CONTENT_TYPE_REJECTED
        ),
        AnomaliFailureReason.RESPONSE_TOO_LARGE: (
            AnomaliFailureAuditKind.RESPONSE_TOO_LARGE
        ),
        AnomaliFailureReason.METADATA_REJECTED: (
            AnomaliFailureAuditKind.METADATA_REJECTED
        ),
    }
)

_FAILURE_DETAILS = MappingProxyType(
    {
        AnomaliFailureAuditKind.VALIDATION_REJECTED: (
            "An Anomali publication failed safe validation."
        ),
        AnomaliFailureAuditKind.TRANSPORT_FAILURE: (
            "An Anomali publication request failed during transport."
        ),
        AnomaliFailureAuditKind.TIMEOUT: "An Anomali publication request timed out.",
        AnomaliFailureAuditKind.RATE_LIMITED: (
            "An Anomali publication response was rate limited."
        ),
        AnomaliFailureAuditKind.HTTP_FAILURE: (
            "An Anomali publication response returned an unsuccessful status."
        ),
        AnomaliFailureAuditKind.REDIRECT_REJECTED: (
            "An Anomali publication redirect was rejected."
        ),
        AnomaliFailureAuditKind.CONTENT_TYPE_REJECTED: (
            "An Anomali publication response used an unsupported content type."
        ),
        AnomaliFailureAuditKind.RESPONSE_TOO_LARGE: (
            "An Anomali publication response exceeded the allowed size."
        ),
        AnomaliFailureAuditKind.METADATA_REJECTED: (
            "Anomali publication metadata could not be safely normalized."
        ),
    }
)


@dataclass(frozen=True, slots=True)
class AnomaliIngestionResult:
    """Committed run metadata safe for CLI reporting."""

    run: IngestionRun
    capped: bool


class AnomaliPublicationsIngestionService:
    """Persist one ordered Anomali batch and its safe audit records atomically."""

    def __init__(
        self,
        session: Session,
        *,
        pipeline_factory: Callable[[Session], PublicationPipeline] = (
            PublicationPipeline
        ),
    ) -> None:
        self._session = session
        self._pipeline_factory = pipeline_factory

    def ingest(
        self,
        *,
        source_slug: str,
        candidates: Sequence[PublicationCandidate],
        failure_kinds: Sequence[AnomaliFailureAuditKind] = (),
        records_fetched: int,
        capped: bool,
        trigger: AnomaliIngestionTrigger,
        observed_at: datetime | None = None,
    ) -> AnomaliIngestionResult:
        """Create, audit, and commit one caller-session Anomali ingestion run."""

        (
            normalized_candidates,
            normalized_failures,
            normalized_capped,
            observed,
        ) = _validate_batch(
            source_slug=source_slug,
            candidates=candidates,
            failure_kinds=failure_kinds,
            records_fetched=records_fetched,
            capped=capped,
            trigger=trigger,
            observed_at=observed_at,
        )
        try:
            pipeline = self._pipeline_factory(self._session)
            source = pipeline.ensure_source(source_slug)
            run = IngestionRun(
                source=source,
                trigger_type="manual",
                status="running",
                started_at=observed,
                completed_at=None,
                records_fetched=records_fetched,
                records_created=0,
                records_updated=0,
                records_unchanged=0,
                records_skipped=0,
                records_failed=0,
                error_count=0,
                checkpoint_before=source.checkpoint_value,
                checkpoint_after=None,
                safe_summary=(
                    "Bounded manual live Anomali publication ingestion started."
                ),
                created_at=observed,
            )
            self._session.add(run)
            self._session.flush()

            for failure_kind in normalized_failures:
                _record_pre_persistence_failure(
                    self._session,
                    run,
                    failure_kind,
                    observed,
                )

            candidates_by_external_id: dict[str, PublicationCandidate] = {}
            candidates_by_canonical_url: dict[str, PublicationCandidate] = {}
            linked_source_records: list[SourceRecord] = []
            for candidate in normalized_candidates:
                existing_external_id = candidates_by_external_id.get(
                    candidate.source_external_id
                )
                existing_canonical_url = candidates_by_canonical_url.get(
                    candidate.canonical_url
                )
                if (
                    existing_external_id is not None
                    or existing_canonical_url is not None
                ):
                    if (
                        existing_external_id == candidate
                        and existing_canonical_url == candidate
                    ):
                        _record_batch_duplicate(self._session, run, observed)
                    else:
                        _record_pre_persistence_failure(
                            self._session,
                            run,
                            AnomaliFailureAuditKind.VALIDATION_REJECTED,
                            observed,
                        )
                    continue
                candidates_by_external_id[candidate.source_external_id] = candidate
                candidates_by_canonical_url[candidate.canonical_url] = candidate
                _persist_candidate(
                    self._session,
                    run,
                    pipeline,
                    candidate,
                    observed,
                    linked_source_records,
                )

            run.status = _run_status(run)
            run.completed_at = observed
            run.error_count = run.records_failed
            run.safe_summary = _completed_summary(run, capped=normalized_capped)
            self._session.commit()
            return AnomaliIngestionResult(run=run, capped=normalized_capped)
        except _SYSTEM_EXCEPTIONS:
            _rollback_safely(self._session, system_exception_active=True)
            raise
        except (PublicationPersistenceError, SQLAlchemyError):
            _rollback_safely(self._session)
            raise AnomaliIngestionDatabaseError(
                "Manual Anomali ingestion failed during a database operation."
            ) from None
        except Exception:
            _rollback_safely(self._session)
            raise AnomaliIngestionError(
                "Manual Anomali ingestion failed unexpectedly."
            ) from None


def collector_failure_audit_kind(
    reason: AnomaliFailureReason,
) -> AnomaliFailureAuditKind:
    """Map one collector allow-list value to its closed audit reason."""

    if not isinstance(reason, AnomaliFailureReason):
        raise AnomaliIngestionInputError(
            "The Anomali collector failure reason is invalid."
        )
    return COLLECTOR_FAILURE_AUDIT_KINDS[reason]


def _validate_batch(
    *,
    source_slug: str,
    candidates: Sequence[PublicationCandidate],
    failure_kinds: Sequence[AnomaliFailureAuditKind],
    records_fetched: int,
    capped: bool,
    trigger: AnomaliIngestionTrigger,
    observed_at: datetime | None,
) -> tuple[
    tuple[PublicationCandidate, ...],
    tuple[AnomaliFailureAuditKind, ...],
    bool,
    datetime,
]:
    try:
        if type(source_slug) is not str or source_slug != ANOMALI_SOURCE_SLUG:
            raise AnomaliIngestionInputError(
                "The Anomali ingestion source is invalid."
            )
        if not isinstance(trigger, AnomaliIngestionTrigger):
            raise AnomaliIngestionInputError(
                "The Anomali ingestion trigger is invalid."
            )
        if isinstance(candidates, (str, bytes, bytearray)) or not isinstance(
            candidates, Sequence
        ):
            raise AnomaliIngestionInputError(
                "The Anomali candidate batch is invalid."
            )
        if isinstance(failure_kinds, (str, bytes, bytearray)) or not isinstance(
            failure_kinds, Sequence
        ):
            raise AnomaliIngestionInputError(
                "The Anomali failure batch is invalid."
            )
        normalized_candidates = tuple(candidates)
        normalized_failures = tuple(failure_kinds)
        if type(capped) is not bool:
            raise AnomaliIngestionInputError(
                "The Anomali capped state is invalid."
            )
        if any(
            not isinstance(candidate, PublicationCandidate)
            or candidate.source_slug != source_slug
            for candidate in normalized_candidates
        ):
            raise AnomaliIngestionInputError(
                "The Anomali candidate batch is invalid."
            )
        if any(
            not isinstance(failure_kind, AnomaliFailureAuditKind)
            for failure_kind in normalized_failures
        ):
            raise AnomaliIngestionInputError(
                "The Anomali failure batch is invalid."
            )
        if (
            type(records_fetched) is not int
            or records_fetched < 0
            or records_fetched > MAX_RECORDS
            or len(normalized_candidates) + len(normalized_failures) > MAX_RECORDS
            or records_fetched
            != len(normalized_candidates) + len(normalized_failures)
        ):
            raise AnomaliIngestionInputError(
                "The Anomali fetched count is invalid."
            )
        observed = utc_now() if observed_at is None else observed_at
        if (
            not isinstance(observed, datetime)
            or observed.tzinfo is None
            or observed.utcoffset() is None
        ):
            raise AnomaliIngestionInputError(
                "The Anomali ingestion time is invalid."
            )
        normalized_observed = observed.astimezone(UTC)
    except _SYSTEM_EXCEPTIONS:
        raise
    except AnomaliIngestionInputError:
        raise
    except Exception:
        raise AnomaliIngestionInputError(
            "The Anomali ingestion input could not be validated safely."
        ) from None
    return (
        normalized_candidates,
        normalized_failures,
        capped,
        normalized_observed,
    )


def _persist_candidate(
    session: Session,
    run: IngestionRun,
    pipeline: PublicationPipeline,
    candidate: PublicationCandidate,
    observed_at: datetime,
    linked_source_records: list[SourceRecord],
) -> None:
    nested = session.begin_nested() if hasattr(session, "begin_nested") else nullcontext()
    with nested:
        result = pipeline.persist(candidate, observed_at=observed_at)
        _record_persistence_result(
            session,
            run,
            result,
            observed_at,
            linked_source_records,
        )


def _record_persistence_result(
    session: Session,
    run: IngestionRun,
    result: PublicationPersistenceResult,
    observed_at: datetime,
    linked_source_records: list[SourceRecord],
) -> None:
    safe_detail = result.message or f"Anomali publication {result.outcome}."
    source_record = result.source_record
    intelligence_item_id = result.intelligence_item_id
    if source_record is not None:
        if _source_record_was_linked(source_record, linked_source_records):
            source_record = None
            intelligence_item_id = None
            safe_detail = _REPEATED_SOURCE_RECORD_DETAIL
        else:
            linked_source_records.append(source_record)
    audit_record = IngestionRunRecord(
        ingestion_run=run,
        source_record=source_record,
        intelligence_item_id=intelligence_item_id,
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
                source_record=source_record,
                error_type="anomali_publication_persistence_error",
                safe_message="An Anomali publication could not be persisted safely.",
                retryable=False,
                retry_count=0,
                occurred_at=observed_at,
            )
        )


def _source_record_was_linked(
    source_record: SourceRecord,
    linked_source_records: Sequence[SourceRecord],
) -> bool:
    source_record_id = _valid_database_id(getattr(source_record, "id", None))
    for linked_source_record in linked_source_records:
        if linked_source_record is source_record:
            return True
        linked_source_record_id = _valid_database_id(
            getattr(linked_source_record, "id", None)
        )
        if (
            source_record_id is not None
            and linked_source_record_id == source_record_id
        ):
            return True
    return False


def _valid_database_id(value: object) -> int | None:
    return value if type(value) is int and value > 0 else None


def _record_batch_duplicate(
    session: Session,
    run: IngestionRun,
    observed_at: datetime,
) -> None:
    session.add(
        IngestionRunRecord(
            ingestion_run=run,
            source_record=None,
            intelligence_item_id=None,
            action="unchanged",
            safe_detail=_BATCH_DUPLICATE_DETAIL,
            processed_at=observed_at,
        )
    )
    run.records_unchanged += 1


def _record_pre_persistence_failure(
    session: Session,
    run: IngestionRun,
    failure_kind: AnomaliFailureAuditKind,
    observed_at: datetime,
) -> None:
    message = _FAILURE_DETAILS[failure_kind]
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
            error_type=(
                "anomali_publication_validation_error"
                if failure_kind is AnomaliFailureAuditKind.VALIDATION_REJECTED
                else f"anomali_{failure_kind.value}"
            ),
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


def _completed_summary(run: IngestionRun, *, capped: bool) -> str:
    return (
        f"Bounded manual Anomali live ingestion {run.status}; "
        f"fetched={run.records_fetched}; created={run.records_created}; "
        f"updated={run.records_updated}; unchanged={run.records_unchanged}; "
        f"skipped={run.records_skipped}; failed={run.records_failed}; "
        f"capped={str(capped).lower()}."
    )


def _rollback_safely(
    session: Session,
    *,
    system_exception_active: bool = False,
) -> None:
    try:
        session.rollback()
    except _SYSTEM_EXCEPTIONS:
        if not system_exception_active:
            raise
    except Exception:
        pass
