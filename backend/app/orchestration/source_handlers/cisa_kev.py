"""Bounded C02 handler for the official CISA KEV catalogue."""

from __future__ import annotations

from collections.abc import Callable
from hashlib import sha256
import json
import re
from time import perf_counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ingestion.collectors.cisa_kev_client import CisaKevClient
from app.ingestion.normalizers.cisa_kev import (
    deduplicate_cisa_kev_entries,
    extract_cisa_kev_entries,
    normalize_cisa_kev_entry,
)
from app.ingestion.services.cisa_kev_ingestion_service import CisaKevIngestionService
from app.ingestion.services.cisa_kev_reconciliation_service import (
    CisaKevReconciliationService,
    validate_complete_cisa_kev_catalog,
)
from app.models import IntelligenceItemIdentifier
from app.orchestration.contracts import (
    ClassifiedFailure,
    FailureCategory,
    ProgressKind,
    ProgressProposal,
    ProgressStorage,
    ReconciledCounters,
    SafeMetrics,
    SourceExecutionContext,
    SourceExecutionResult,
)
from app.orchestration.source_handlers.common import (
    OutcomeEvidence,
    SessionFactory,
    classified_client_failure,
    counters_from_outcomes,
    default_session_factory,
    elapsed_milliseconds,
    expected_previous_version,
    load_execution_evidence,
    make_result,
    persist_execution_evidence,
    persist_outcome_evidence,
    reconstruct_progress_from_evidence,
    validate_handler_context,
)


CISA_KEV_SOURCE_SLUG = "cisa-kev"
MAX_CATALOG_RECORDS = 2_000
MAX_LOCAL_RECONCILIATION_ROWS = 500
LOCAL_RECONCILIATION_BATCH_SIZE = 100
LOCAL_IDENTIFIER_LOOKUP_BATCH_SIZE = 100
_TOKEN_PATTERN = re.compile(r"^sha256=([0-9a-f]{64});cursor=([0-9]{1,20})$", re.ASCII)


class CisaKevSourceHandler:
    """Fetch, fully validate, persist, and locally reconcile one KEV catalogue."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory | None = None,
        client_factory: Callable[[], CisaKevClient] = CisaKevClient,
    ) -> None:
        self._session_factory = session_factory or default_session_factory()
        self._client_factory = client_factory

    def execute(self, context: SourceExecutionContext) -> SourceExecutionResult:
        validate_handler_context(
            context,
            source_slug=CISA_KEV_SOURCE_SLUG,
            progress_storage=ProgressStorage.CHECKPOINT,
            progress_kind=ProgressKind.CONTENT_HASH,
        )
        replay = load_execution_evidence(self._session_factory, context)
        if replay is not None:
            return replay

        started = perf_counter()
        client = self._client_factory()
        try:
            fetched = client.fetch_catalog()
        except Exception as error:
            raise classified_client_failure(error, source_label="CISA KEV") from None
        finally:
            client.close()

        catalog = fetched.catalog
        declared_count = catalog.get("count") if isinstance(catalog, dict) else None
        if (
            type(declared_count) is not int
            or not 1 <= declared_count <= MAX_CATALOG_RECORDS
        ):
            raise ClassifiedFailure(
                FailureCategory.UNSUPPORTED_CONTENT,
                "The CISA KEV catalogue record count is outside the approved bound.",
            )
        try:
            validated = validate_complete_cisa_kev_catalog(catalog)
            normalized = deduplicate_cisa_kev_entries(
                [normalize_cisa_kev_entry(entry) for entry in extract_cisa_kev_entries(catalog)]
            )
            catalog_hash = _catalog_sha256(catalog)
            start_after_id = _start_cursor(context, catalog_hash)
        except Exception as error:
            raise classified_client_failure(error, source_label="CISA KEV") from None

        outcomes: list[str] = []
        evidence: list[OutcomeEvidence] = []
        try:
            with self._session_factory() as session, session.begin():
                ingestion = CisaKevIngestionService(session)
                local_catalog_cves = _locally_known_catalog_cves(session, normalized)
                for record in normalized:
                    if record.cve_id not in local_catalog_cves:
                        continue
                    persisted = ingestion.enrich(record, observed_at=context.scheduled_for)
                    outcomes.append(persisted.outcome)
                    evidence.append(
                        OutcomeEvidence(
                            outcome=persisted.outcome,
                            source_record_id=getattr(persisted.source_record, "id", None),
                            intelligence_item_id=persisted.intelligence_item_id,
                            safe_detail="C02 processed one validated CISA KEV catalogue record.",
                        )
                    )

                reconciliation = CisaKevReconciliationService(session).reconcile(
                    validated.cve_ids,
                    max_cves=MAX_LOCAL_RECONCILIATION_ROWS,
                    batch_size=LOCAL_RECONCILIATION_BATCH_SIZE,
                    checked_at=context.scheduled_for,
                    start_after_id=start_after_id,
                    wrap_around=True,
                )
                for record in reconciliation.records:
                    outcomes.append(record.outcome)
                    evidence.append(
                        OutcomeEvidence(
                            outcome=record.outcome,
                            intelligence_item_id=record.intelligence_item_id,
                            safe_detail="C02 reconciled one local vulnerability against the complete KEV catalogue.",
                        )
                    )

                counters = counters_from_outcomes(outcomes)
                proposal = ProgressProposal(
                    storage=ProgressStorage.CHECKPOINT,
                    kind=ProgressKind.CONTENT_HASH,
                    name=ProgressKind.CONTENT_HASH.value,
                    value=_progress_token(catalog_hash, reconciliation.next_cursor),
                    expected_previous_version=expected_previous_version(context),
                )
                result = make_result(
                    source_slug=CISA_KEV_SOURCE_SLUG,
                    counters=counters,
                    metrics=SafeMetrics(
                        duration_ms=elapsed_milliseconds(started),
                        request_count=1,
                        page_count=1,
                    ),
                    progress_proposal=proposal,
                )
                persist_outcome_evidence(
                    session,
                    run_id=context.attempt.run_id,
                    evidence=evidence,
                )
                persist_execution_evidence(session, context=context, result=result)
                session.flush()
        except Exception as error:
            raise classified_client_failure(error, source_label="CISA KEV") from None
        return result

    def reconstruct_progress(
        self,
        context: SourceExecutionContext,
        committed_counters: ReconciledCounters,
    ) -> ProgressProposal:
        validate_handler_context(
            context,
            source_slug=CISA_KEV_SOURCE_SLUG,
            progress_storage=ProgressStorage.CHECKPOINT,
            progress_kind=ProgressKind.CONTENT_HASH,
        )
        return reconstruct_progress_from_evidence(
            self._session_factory,
            context,
            committed_counters,
        )


def _locally_known_catalog_cves(
    session: Session,
    normalized_records: tuple[object, ...] | list[object],
) -> frozenset[str]:
    cve_ids = tuple(getattr(record, "cve_id", None) for record in normalized_records)
    if any(not isinstance(cve_id, str) for cve_id in cve_ids):
        raise ValueError("The normalized CISA KEV catalogue identity is invalid.")

    known: set[str] = set()
    for offset in range(0, len(cve_ids), LOCAL_IDENTIFIER_LOOKUP_BATCH_SIZE):
        chunk = cve_ids[offset : offset + LOCAL_IDENTIFIER_LOOKUP_BATCH_SIZE]
        values = tuple(
            session.execute(
                select(IntelligenceItemIdentifier.normalized_value)
                .where(
                    IntelligenceItemIdentifier.source_id.is_(None),
                    IntelligenceItemIdentifier.namespace == "cve",
                    IntelligenceItemIdentifier.normalized_value.in_(chunk),
                )
                .order_by(IntelligenceItemIdentifier.normalized_value.asc())
            ).scalars().all()
        )
        if any(not isinstance(value, str) or value not in chunk for value in values):
            raise ValueError("The local CISA KEV identifier lookup is inconsistent.")
        known.update(values)
    return frozenset(known)


def _catalog_sha256(catalog: dict[str, object]) -> str:
    try:
        canonical = json.dumps(
            catalog,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("The CISA KEV catalogue could not be hashed safely.") from exc
    return sha256(canonical).hexdigest()


def _progress_token(catalog_hash: str, cursor: int) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", catalog_hash) or type(cursor) is not int or cursor < 0:
        raise ValueError("The CISA KEV progress token is invalid.")
    return f"sha256={catalog_hash};cursor={cursor}"


def _start_cursor(context: SourceExecutionContext, catalog_hash: str) -> int:
    if context.progress is None:
        return 0
    value = context.progress.value
    if not isinstance(value, str):
        raise ValueError("The CISA KEV progress token is invalid.")
    match = _TOKEN_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError("The CISA KEV progress token is invalid.")
    previous_hash, cursor_text = match.groups()
    return int(cursor_text) if previous_hash == catalog_hash else 0


__all__ = [
    "CISA_KEV_SOURCE_SLUG",
    "CisaKevSourceHandler",
    "LOCAL_IDENTIFIER_LOOKUP_BATCH_SIZE",
    "LOCAL_RECONCILIATION_BATCH_SIZE",
    "MAX_CATALOG_RECORDS",
    "MAX_LOCAL_RECONCILIATION_ROWS",
]
