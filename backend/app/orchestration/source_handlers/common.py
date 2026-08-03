"""Shared fail-closed helpers for bounded C02 source handlers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import re
from time import perf_counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.ingestion.source_registry import ImplementationStatus, get_source_definition
from app.models import IngestionRunRecord
from app.orchestration.contracts import (
    ClassifiedFailure,
    ContractValidationError,
    FailureCategory,
    FailureClassification,
    ProgressKind,
    ProgressProposal,
    ProgressStorage,
    ReconciledCounters,
    ResultStatus,
    SafeMetrics,
    SourceExecutionContext,
    SourceExecutionResult,
)


SessionFactory = Callable[[], Session]
EVIDENCE_PREFIX = "c02-evidence-v1:"
MAX_SAFE_DETAIL_LENGTH = 1_000
_OUTCOMES = frozenset({"created", "updated", "unchanged", "skipped", "failed"})


@dataclass(frozen=True, slots=True)
class OutcomeEvidence:
    """One sanitized persistence outcome awaiting run-linked audit storage."""

    outcome: str
    source_record_id: int | None = None
    intelligence_item_id: int | None = None
    safe_detail: str = "C02 processed one approved source record."

    def __post_init__(self) -> None:
        if self.outcome not in _OUTCOMES:
            raise ContractValidationError("The source outcome is invalid.")
        for value in (self.source_record_id, self.intelligence_item_id):
            if value is not None and (type(value) is not int or value < 1):
                raise ContractValidationError("The source outcome identity is invalid.")
        _safe_detail(self.safe_detail)


def default_session_factory() -> SessionFactory:
    """Resolve the application session factory lazily for import-safe handlers."""

    return get_session_factory()


def validate_handler_context(
    context: SourceExecutionContext,
    *,
    source_slug: str,
    progress_storage: ProgressStorage,
    progress_kind: ProgressKind,
) -> None:
    """Validate the orchestration, policy, and registry source identity together."""

    if not isinstance(context, SourceExecutionContext):
        raise ContractValidationError("The source execution context is invalid.")
    definition = get_source_definition(source_slug)
    if (
        definition.slug != source_slug
        or definition.implementation_status is not ImplementationStatus.IMPLEMENTED
        or definition.enabled is not True
        or context.policy.source_slug != source_slug
        or context.attempt.source_slug != source_slug
        or context.policy.progress_storage is not progress_storage
        or context.policy.progress_kind is not progress_kind
    ):
        raise ClassifiedFailure(
            FailureCategory.INVALID_SOURCE_POLICY,
            "The source identity conflicts with the approved policy.",
        )
    if context.progress is not None and (
        context.progress.storage is not progress_storage
        or context.progress.kind is not progress_kind
        or context.progress.name != progress_kind.value
    ):
        raise ClassifiedFailure(
            FailureCategory.INVALID_SOURCE_POLICY,
            "The source progress conflicts with the approved policy.",
        )


def expected_previous_version(context: SourceExecutionContext) -> int:
    return 0 if context.progress is None else context.progress.version


def scheduled_watermark_proposal(context: SourceExecutionContext) -> ProgressProposal:
    return ProgressProposal(
        storage=ProgressStorage.WATERMARK,
        kind=ProgressKind.MODIFIED_SINCE,
        name=ProgressKind.MODIFIED_SINCE.value,
        value=context.scheduled_for,
        expected_previous_version=expected_previous_version(context),
    )


def counters_from_outcomes(outcomes: Iterable[str]) -> ReconciledCounters:
    values = tuple(outcomes)
    if any(value not in _OUTCOMES for value in values):
        raise ContractValidationError("The source outcomes are invalid.")
    return ReconciledCounters(
        fetched=len(values),
        created=values.count("created"),
        updated=values.count("updated"),
        unchanged=values.count("unchanged"),
        skipped=values.count("skipped"),
        failed=values.count("failed"),
        error_count=values.count("failed"),
    )


def status_for_counters(counters: ReconciledCounters) -> ResultStatus:
    """Return a truthful status accepted by the C01 persistence contract."""

    successful = counters.created + counters.updated + counters.unchanged
    non_successful = counters.skipped + counters.failed
    if non_successful:
        return ResultStatus.PARTIAL if successful else ResultStatus.FAILED
    if counters.created + counters.updated:
        return ResultStatus.SUCCESS
    return ResultStatus.NO_CHANGE


def failure_for_status(status: ResultStatus) -> FailureClassification | None:
    if status not in {ResultStatus.PARTIAL, ResultStatus.FAILED}:
        return None
    return FailureClassification(
        category=FailureCategory.UNSUPPORTED_CONTENT,
        transient=False,
        safe_message="The source completed with controlled non-success outcomes.",
    )


def elapsed_milliseconds(started: float) -> int:
    return min(max(int((perf_counter() - started) * 1_000), 0), 86_400_000)


def make_result(
    *,
    source_slug: str,
    counters: ReconciledCounters,
    metrics: SafeMetrics,
    progress_proposal: ProgressProposal | None,
) -> SourceExecutionResult:
    status = status_for_counters(counters)
    return SourceExecutionResult(
        source_slug=source_slug,
        status=status,
        counters=counters,
        metrics=metrics,
        safe_message=(
            "The approved source completed with committed bounded outcomes."
            if status in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}
            else "The approved source completed with controlled non-success outcomes."
        ),
        progress_proposal=(
            progress_proposal
            if status in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}
            else None
        ),
        failure=failure_for_status(status),
    )


def persist_outcome_evidence(
    session: Session,
    *,
    run_id: int,
    evidence: Iterable[OutcomeEvidence],
) -> None:
    for item in evidence:
        session.add(
            IngestionRunRecord(
                ingestion_run_id=run_id,
                source_record_id=item.source_record_id,
                intelligence_item_id=item.intelligence_item_id,
                action=item.outcome,
                safe_detail=_safe_detail(item.safe_detail),
            )
        )


def persist_execution_evidence(
    session: Session,
    *,
    context: SourceExecutionContext,
    result: SourceExecutionResult,
) -> None:
    """Store one immutable compact replay/reconstruction record in the data commit."""

    payload: dict[str, Any] = {
        "s": result.source_slug,
        "st": result.status.value,
        "c": [
            result.counters.fetched,
            result.counters.created,
            result.counters.updated,
            result.counters.unchanged,
            result.counters.skipped,
            result.counters.failed,
            result.counters.error_count,
        ],
        "m": [
            result.metrics.duration_ms,
            result.metrics.request_count,
            result.metrics.page_count,
        ],
    }
    proposal = result.progress_proposal
    if proposal is not None:
        payload["p"] = {
            "st": proposal.storage.value,
            "k": proposal.kind.value,
            "n": proposal.name,
            "v": (
                proposal.value.astimezone(UTC).isoformat()
                if isinstance(proposal.value, datetime)
                else proposal.value
            ),
            "pv": proposal.expected_previous_version,
        }
    detail = EVIDENCE_PREFIX + json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    session.add(
        IngestionRunRecord(
            ingestion_run_id=context.attempt.run_id,
            source_record_id=None,
            intelligence_item_id=None,
            action="unchanged",
            safe_detail=_safe_detail(detail),
        )
    )


def load_execution_evidence(
    session_factory: SessionFactory,
    context: SourceExecutionContext,
) -> SourceExecutionResult | None:
    """Read immutable prior handler evidence without making a source request."""

    with session_factory() as session:
        details = tuple(
            session.execute(
                select(IngestionRunRecord.safe_detail).where(
                    IngestionRunRecord.ingestion_run_id == context.attempt.run_id,
                    IngestionRunRecord.safe_detail.like(f"{EVIDENCE_PREFIX}%"),
                )
            ).scalars().all()
        )
    if not details:
        return None
    if len(details) != 1:
        raise ClassifiedFailure(
            FailureCategory.CONTRACT_VIOLATION,
            "The committed source execution evidence conflicts.",
        )
    return _decode_execution_evidence(details[0], context)


def reconstruct_progress_from_evidence(
    session_factory: SessionFactory,
    context: SourceExecutionContext,
    committed_counters: ReconciledCounters,
) -> ProgressProposal:
    result = load_execution_evidence(session_factory, context)
    if (
        result is None
        or result.status not in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}
        or result.progress_proposal is None
        or result.counters != committed_counters
    ):
        raise ClassifiedFailure(
            FailureCategory.CONTRACT_VIOLATION,
            "Committed source progress evidence is unavailable or conflicting.",
        )
    return result.progress_proposal


def classified_client_failure(error: BaseException, *, source_label: str) -> ClassifiedFailure:
    """Map only sanitized client exception types/names to fixed diagnostics."""

    name = type(error).__name__.casefold()
    if "ratelimit" in name:
        category = FailureCategory.PROVIDER_RATE_LIMIT
        message = f"The approved {source_label} request was rate limited."
    elif "request" in name:
        category = FailureCategory.TEMPORARY_CONNECTION
        message = f"The approved {source_label} request failed temporarily."
    elif (
        "persistence" in name
        or "database" in name
        or type(error).__module__.startswith("sqlalchemy")
    ):
        category = FailureCategory.PERSISTENCE_CONTENTION
        message = f"The approved {source_label} persistence transaction failed safely."
    elif "http" in name:
        status_match = re.search(r"\bHTTP ([0-9]{3})\b", str(error), re.ASCII)
        if status_match is not None and int(status_match.group(1)) >= 500:
            category = FailureCategory.RETRYABLE_SERVER_RESPONSE
            message = f"The approved {source_label} service failed temporarily."
        else:
            category = FailureCategory.PERMANENT_PROVIDER_REJECTION
            message = f"The approved {source_label} request was rejected."
    elif any(token in name for token in ("response", "contenttype", "redirect", "feed")):
        category = FailureCategory.UNSUPPORTED_CONTENT
        message = f"The approved {source_label} response failed safe validation."
    else:
        category = FailureCategory.VALIDATION_FAILURE
        message = f"The approved {source_label} data failed safe validation."
    return ClassifiedFailure(category, message)


def _decode_execution_evidence(
    detail: object,
    context: SourceExecutionContext,
) -> SourceExecutionResult:
    try:
        if not isinstance(detail, str) or not detail.startswith(EVIDENCE_PREFIX):
            raise ValueError
        payload = json.loads(detail[len(EVIDENCE_PREFIX) :])
        if not isinstance(payload, dict) or payload.get("s") != context.policy.source_slug:
            raise ValueError
        counter_values = payload["c"]
        metric_values = payload["m"]
        if not isinstance(counter_values, list) or len(counter_values) != 7:
            raise ValueError
        if not isinstance(metric_values, list) or len(metric_values) != 3:
            raise ValueError
        counters = ReconciledCounters(*counter_values)
        metrics = SafeMetrics(*metric_values)
        status = ResultStatus(payload["st"])
        proposal_payload = payload.get("p")
        proposal = None
        if proposal_payload is not None:
            storage = ProgressStorage(proposal_payload["st"])
            kind = ProgressKind(proposal_payload["k"])
            raw_value = proposal_payload["v"]
            value: str | datetime
            if kind is ProgressKind.MODIFIED_SINCE:
                value = datetime.fromisoformat(raw_value).astimezone(UTC)
            else:
                value = raw_value
            proposal = ProgressProposal(
                storage=storage,
                kind=kind,
                name=proposal_payload["n"],
                value=value,
                expected_previous_version=proposal_payload["pv"],
            )
        result = SourceExecutionResult(
            source_slug=context.policy.source_slug,
            status=status,
            counters=counters,
            metrics=metrics,
            safe_message="Previously committed bounded source evidence was reused.",
            progress_proposal=proposal,
            failure=failure_for_status(status),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ClassifiedFailure(
            FailureCategory.CONTRACT_VIOLATION,
            "The committed source execution evidence is malformed.",
        ) from None
    return result


def _safe_detail(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_SAFE_DETAIL_LENGTH
        or any(not character.isprintable() for character in value)
    ):
        raise ContractValidationError("The run record detail is invalid.")
    return value


__all__ = [
    "OutcomeEvidence",
    "SessionFactory",
    "classified_client_failure",
    "counters_from_outcomes",
    "default_session_factory",
    "elapsed_milliseconds",
    "expected_previous_version",
    "load_execution_evidence",
    "make_result",
    "persist_execution_evidence",
    "persist_outcome_evidence",
    "reconstruct_progress_from_evidence",
    "scheduled_watermark_proposal",
    "status_for_counters",
    "validate_handler_context",
]
