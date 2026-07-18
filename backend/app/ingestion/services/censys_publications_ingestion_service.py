"""Shared transactional persistence and audit service for Censys publications."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from types import MappingProxyType

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.adapters.censys_publications import (
    CENSYS_ARC_RESEARCH_SLUG,
    CENSYS_RAPID_RESPONSE_SLUG,
)
from app.ingestion.collectors.censys_publications_client import CensysFailureReason
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPersistenceError,
    PublicationPersistenceResult,
    PublicationPipeline,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord, SourceRecord
from app.models.common import utc_now


APPROVED_CENSYS_SOURCE_SLUGS = frozenset(
    {CENSYS_ARC_RESEARCH_SLUG, CENSYS_RAPID_RESPONSE_SLUG}
)
_SYSTEM_EXCEPTIONS = (MemoryError, KeyboardInterrupt, SystemExit, GeneratorExit)
_BATCH_DUPLICATE_DETAIL = (
    "A duplicate Censys publication matched an earlier batch entry."
)
_REPEATED_SOURCE_RECORD_DETAIL = (
    "A Censys publication outcome matched an earlier linked audit entry."
)


class CensysIngestionError(RuntimeError):
    """A Censys ingestion batch could not complete safely."""


class CensysIngestionInputError(CensysIngestionError, ValueError):
    """The service received data outside its closed validated interface."""


class CensysIngestionDatabaseError(CensysIngestionError):
    """The Censys transaction failed without exposing database details."""


class CensysIngestionTrigger(str, Enum):
    """Closed manual entry points sharing this persistence service."""

    LOCAL_FILE = "local-file"
    LIVE = "live"


class CensysFailureAuditKind(str, Enum):
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
        CensysFailureReason.TRANSPORT_FAILURE: CensysFailureAuditKind.TRANSPORT_FAILURE,
        CensysFailureReason.TIMEOUT: CensysFailureAuditKind.TIMEOUT,
        CensysFailureReason.RATE_LIMITED: CensysFailureAuditKind.RATE_LIMITED,
        CensysFailureReason.HTTP_FAILURE: CensysFailureAuditKind.HTTP_FAILURE,
        CensysFailureReason.REDIRECT_REJECTED: CensysFailureAuditKind.REDIRECT_REJECTED,
        CensysFailureReason.CONTENT_TYPE_REJECTED: (
            CensysFailureAuditKind.CONTENT_TYPE_REJECTED
        ),
        CensysFailureReason.RESPONSE_TOO_LARGE: (
            CensysFailureAuditKind.RESPONSE_TOO_LARGE
        ),
        CensysFailureReason.METADATA_REJECTED: CensysFailureAuditKind.METADATA_REJECTED,
    }
)

_FAILURE_DETAILS = MappingProxyType(
    {
        CensysFailureAuditKind.VALIDATION_REJECTED: (
            "A Censys publication failed safe validation."
        ),
        CensysFailureAuditKind.TRANSPORT_FAILURE: (
            "A Censys publication request failed during transport."
        ),
        CensysFailureAuditKind.TIMEOUT: "A Censys publication request timed out.",
        CensysFailureAuditKind.RATE_LIMITED: (
            "A Censys publication response was rate limited."
        ),
        CensysFailureAuditKind.HTTP_FAILURE: (
            "A Censys publication response returned an unsuccessful status."
        ),
        CensysFailureAuditKind.REDIRECT_REJECTED: (
            "A Censys publication redirect was rejected."
        ),
        CensysFailureAuditKind.CONTENT_TYPE_REJECTED: (
            "A Censys publication response used an unsupported content type."
        ),
        CensysFailureAuditKind.RESPONSE_TOO_LARGE: (
            "A Censys publication response exceeded the allowed size."
        ),
        CensysFailureAuditKind.METADATA_REJECTED: (
            "Censys publication metadata could not be safely normalized."
        ),
    }
)


@dataclass(frozen=True, slots=True)
class CensysIngestionResult:
    """Committed run metadata safe for CLI reporting."""

    run: IngestionRun


class CensysPublicationsIngestionService:
    """Persist one ordered Censys batch and its safe audit records atomically."""

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
        failure_kinds: Sequence[CensysFailureAuditKind] = (),
        records_fetched: int,
        trigger: CensysIngestionTrigger,
        observed_at: datetime | None = None,
    ) -> CensysIngestionResult:
        """Create, audit, and commit one caller-session Censys ingestion run."""

        normalized_candidates, normalized_failures, observed = _validate_batch(
            source_slug=source_slug,
            candidates=candidates,
            failure_kinds=failure_kinds,
            records_fetched=records_fetched,
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
                safe_summary=_started_summary(trigger),
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
                        _record_batch_duplicate(
                            self._session,
                            run,
                            observed,
                        )
                    else:
                        _record_pre_persistence_failure(
                            self._session,
                            run,
                            CensysFailureAuditKind.VALIDATION_REJECTED,
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
            run.safe_summary = _completed_summary(run, trigger)
            self._session.commit()
            return CensysIngestionResult(run=run)
        except _SYSTEM_EXCEPTIONS:
            _rollback_safely(
                self._session,
                system_exception_active=True,
            )
            raise
        except (PublicationPersistenceError, SQLAlchemyError):
            _rollback_safely(self._session)
            raise CensysIngestionDatabaseError(
                "Manual Censys ingestion failed during a database operation."
            ) from None
        except Exception:
            _rollback_safely(self._session)
            raise CensysIngestionError(
                "Manual Censys ingestion failed unexpectedly."
            ) from None


def collector_failure_audit_kind(
    reason: CensysFailureReason,
) -> CensysFailureAuditKind:
    """Map one collector allow-list value to its closed audit reason."""

    if not isinstance(reason, CensysFailureReason):
        raise CensysIngestionInputError(
            "The Censys collector failure reason is invalid."
        )
    return COLLECTOR_FAILURE_AUDIT_KINDS[reason]


def _validate_batch(
    *,
    source_slug: str,
    candidates: Sequence[PublicationCandidate],
    failure_kinds: Sequence[CensysFailureAuditKind],
    records_fetched: int,
    trigger: CensysIngestionTrigger,
    observed_at: datetime | None,
) -> tuple[
    tuple[PublicationCandidate, ...],
    tuple[CensysFailureAuditKind, ...],
    datetime,
]:
    try:
        if (
            not isinstance(source_slug, str)
            or source_slug not in APPROVED_CENSYS_SOURCE_SLUGS
        ):
            raise CensysIngestionInputError(
                "The Censys ingestion source is invalid."
            )
        if not isinstance(trigger, CensysIngestionTrigger):
            raise CensysIngestionInputError(
                "The Censys ingestion trigger is invalid."
            )
        if isinstance(candidates, (str, bytes, bytearray)) or not isinstance(
            candidates,
            Sequence,
        ):
            raise CensysIngestionInputError(
                "The Censys candidate batch is invalid."
            )
        if isinstance(failure_kinds, (str, bytes, bytearray)) or not isinstance(
            failure_kinds,
            Sequence,
        ):
            raise CensysIngestionInputError(
                "The Censys failure batch is invalid."
            )
        normalized_candidates = tuple(candidates)
        normalized_failures = tuple(failure_kinds)
        if any(
            not isinstance(candidate, PublicationCandidate)
            or candidate.source_slug != source_slug
            for candidate in normalized_candidates
        ):
            raise CensysIngestionInputError(
                "The Censys candidate batch is invalid."
            )
        if any(
            not isinstance(failure_kind, CensysFailureAuditKind)
            for failure_kind in normalized_failures
        ):
            raise CensysIngestionInputError(
                "The Censys failure batch is invalid."
            )
        if (
            type(records_fetched) is not int
            or records_fetched < 0
            or records_fetched
            != len(normalized_candidates) + len(normalized_failures)
        ):
            raise CensysIngestionInputError(
                "The Censys fetched count is invalid."
            )
        observed = utc_now() if observed_at is None else observed_at
        if (
            not isinstance(observed, datetime)
            or observed.tzinfo is None
            or observed.utcoffset() is None
        ):
            raise CensysIngestionInputError(
                "The Censys ingestion time is invalid."
            )
        normalized_observed = observed.astimezone(UTC)
    except _SYSTEM_EXCEPTIONS:
        raise
    except CensysIngestionInputError:
        raise
    except Exception:
        raise CensysIngestionInputError(
            "The Censys ingestion input could not be validated safely."
        ) from None
    return normalized_candidates, normalized_failures, normalized_observed


def _persist_candidate(
    session: Session,
    run: IngestionRun,
    pipeline: PublicationPipeline,
    candidate: PublicationCandidate,
    observed_at: datetime,
    linked_source_records: list[SourceRecord],
) -> None:
    nested = (
        session.begin_nested()
        if hasattr(session, "begin_nested")
        else nullcontext()
    )
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
    safe_detail = result.message or f"Censys publication {result.outcome}."
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
                error_type="censys_publication_persistence_error",
                safe_message="A Censys publication could not be persisted safely.",
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
    failure_kind: CensysFailureAuditKind,
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
                "censys_publication_validation_error"
                if failure_kind is CensysFailureAuditKind.VALIDATION_REJECTED
                else f"censys_{failure_kind.value}"
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


def _started_summary(trigger: CensysIngestionTrigger) -> str:
    if trigger is CensysIngestionTrigger.LIVE:
        return "Bounded manual live Censys publication ingestion started."
    return "Manual Censys local-file publication import started."


def _completed_summary(
    run: IngestionRun,
    trigger: CensysIngestionTrigger,
) -> str:
    label = (
        "Bounded manual Censys live ingestion"
        if trigger is CensysIngestionTrigger.LIVE
        else "Manual Censys import"
    )
    return (
        f"{label} {run.status}; fetched={run.records_fetched}; "
        f"created={run.records_created}; updated={run.records_updated}; "
        f"unchanged={run.records_unchanged}; skipped={run.records_skipped}; "
        f"failed={run.records_failed}."
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
