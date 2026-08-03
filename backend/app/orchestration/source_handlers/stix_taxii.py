"""Inactive, policy-gated C03A TAXII source handler."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from hashlib import sha256
import json
import re
from time import perf_counter
from types import MappingProxyType

from app.ingestion.stix_taxii.bounded_json import thaw_json
from app.ingestion.stix_taxii.import_service import StixBundleImportService
from app.ingestion.stix_taxii.policy import (
    ApprovedTaxiiCollectionPolicy,
    PRODUCTION_TAXII_COLLECTION_POLICIES,
    validate_taxii_collection_policy,
)
from app.ingestion.stix_taxii.stix_validation import (
    ValidatedStixDocument,
    validate_persistable_stix_document,
)
from app.ingestion.stix_taxii.taxii_client import (
    TaxiiCollectionClient,
    TaxiiCollectionResult,
)
from app.orchestration.contracts import (
    ClassifiedFailure,
    FailureCategory,
    ProgressKind,
    ProgressProposal,
    ProgressStorage,
    ReconciledCounters,
    ResultStatus,
    SafeMetrics,
    SourceExecutionContext,
    SourceExecutionResult,
    SourceHandler,
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


PRODUCTION_TAXII_LICENCE_REQUIRED = frozenset({"licensed-taxii"})
_SAFE_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
TaxiiClientFactory = Callable[[MappingProxyType[str, ApprovedTaxiiCollectionPolicy]], TaxiiCollectionClient]


def production_taxii_access_state(source_slug: str) -> ResultStatus | None:
    """Evaluate inactive production access without constructing a client."""

    if not isinstance(source_slug, str) or _SAFE_SLUG.fullmatch(source_slug) is None:
        return ResultStatus.DISABLED
    if source_slug in PRODUCTION_TAXII_COLLECTION_POLICIES:
        return None
    if source_slug in PRODUCTION_TAXII_LICENCE_REQUIRED:
        return ResultStatus.LICENCE_REQUIRED
    return ResultStatus.DISABLED


class StixTaxiiSourceHandler:
    """Fetch a complete bounded TAXII collection before one atomic DB transaction."""

    def __init__(
        self,
        source_slug: str,
        *,
        policy_registry: MappingProxyType[str, ApprovedTaxiiCollectionPolicy],
        session_factory: SessionFactory | None = None,
        client_factory: TaxiiClientFactory = lambda registry: TaxiiCollectionClient(policy_registry=registry),
    ) -> None:
        if not isinstance(policy_registry, MappingProxyType):
            raise ValueError("The TAXII handler policy registry must be immutable.")
        normalized: dict[str, ApprovedTaxiiCollectionPolicy] = {}
        for key, value in policy_registry.items():
            policy = validate_taxii_collection_policy(value)
            if key != policy.source_slug:
                raise ValueError("The TAXII handler policy identity is invalid.")
            normalized[key] = policy
        if source_slug not in normalized:
            raise ValueError("The TAXII handler source is not approved.")
        self._source_slug = source_slug
        self._policy_registry = MappingProxyType(normalized)
        self._policy = normalized[source_slug]
        self._session_factory = session_factory or default_session_factory()
        self._client_factory = client_factory

    def execute(self, context: SourceExecutionContext) -> SourceExecutionResult:
        self._validate_context(context)
        replay = load_execution_evidence(self._session_factory, context)
        if replay is not None:
            return replay
        started = perf_counter()
        try:
            client = self._client_factory(self._policy_registry)
            collected = client.collect(self._source_slug)
            canonical_document = _validated_collection_document(
                collected,
                self._policy,
            )
            document_hash = canonical_document_sha256(canonical_document)
        except Exception as error:
            raise classified_client_failure(error, source_label="STIX TAXII") from None
        try:
            with self._session_factory() as session, session.begin():
                source_id = _source_id_for_slug(session, self._source_slug)
                imported = StixBundleImportService(session).import_document(
                    source_id,
                    self._policy.stix_policy,
                    canonical_document,
                    observed_at=context.scheduled_for,
                )
                outcomes = tuple(item.action for item in imported.record_outcomes)
                counters = counters_from_outcomes(outcomes)
                proposal = ProgressProposal(
                    storage=ProgressStorage.CHECKPOINT,
                    kind=ProgressKind.CONTENT_HASH,
                    name=ProgressKind.CONTENT_HASH.value,
                    value=document_hash,
                    expected_previous_version=expected_previous_version(context),
                )
                result = make_result(
                    source_slug=self._source_slug,
                    counters=counters,
                    metrics=SafeMetrics(
                        duration_ms=elapsed_milliseconds(started),
                        request_count=collected.pages_collected,
                        page_count=collected.pages_collected,
                    ),
                    progress_proposal=proposal,
                )
                persist_outcome_evidence(
                    session,
                    run_id=context.attempt.run_id,
                    evidence=(
                        OutcomeEvidence(
                            outcome=item.action,
                            source_record_id=item.source_record_id,
                            safe_detail="C03A processed one validated STIX source record.",
                        )
                        for item in imported.record_outcomes
                    ),
                )
                persist_execution_evidence(session, context=context, result=result)
                session.flush()
        except Exception as error:
            raise classified_client_failure(error, source_label="STIX TAXII") from None
        return result

    def reconstruct_progress(self, context: SourceExecutionContext, committed_counters: ReconciledCounters) -> ProgressProposal:
        self._validate_context(context)
        return reconstruct_progress_from_evidence(self._session_factory, context, committed_counters)

    def _validate_context(self, context: SourceExecutionContext) -> None:
        validate_handler_context(
            context,
            source_slug=self._source_slug,
            progress_storage=ProgressStorage.CHECKPOINT,
            progress_kind=ProgressKind.CONTENT_HASH,
        )
        if context.policy.source_slug != self._policy.source_slug:
            raise ClassifiedFailure(FailureCategory.INVALID_SOURCE_POLICY, "The TAXII source identity conflicts with the approved policy.")


def build_c03_stix_taxii_handlers(
    policy_registry: MappingProxyType[str, ApprovedTaxiiCollectionPolicy] = PRODUCTION_TAXII_COLLECTION_POLICIES,
    *,
    session_factory: SessionFactory | None = None,
    client_factory: TaxiiClientFactory = lambda registry: TaxiiCollectionClient(policy_registry=registry),
) -> Mapping[str, SourceHandler]:
    """Build immutable reviewed handlers; the production default remains empty."""

    if not isinstance(policy_registry, MappingProxyType):
        raise ValueError("The TAXII handler policy registry must be immutable.")
    handlers = {
        source_slug: StixTaxiiSourceHandler(
            source_slug,
            policy_registry=policy_registry,
            session_factory=session_factory,
            client_factory=client_factory,
        )
        for source_slug in policy_registry
    }
    return MappingProxyType(handlers)


def canonical_document_sha256(document: ValidatedStixDocument) -> str:
    if not isinstance(document, ValidatedStixDocument):
        raise ValueError("A validated STIX document is required.")
    versions = sorted(
        document.validated_versions,
        key=lambda item: (item.stix_id, item.modified or item.created, item.content_hash),
    )
    payload = [thaw_json(item.safe_payload) for item in versions]
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return sha256(encoded).hexdigest()


def _validated_collection_document(
    collected: TaxiiCollectionResult,
    policy: ApprovedTaxiiCollectionPolicy,
) -> ValidatedStixDocument:
    if (
        not isinstance(collected, TaxiiCollectionResult)
        or type(collected.pages_collected) is not int
        or not 1 <= collected.pages_collected <= policy.maximum_pages
        or type(collected.response_bytes_collected) is not int
        or not 0 <= collected.response_bytes_collected <= policy.maximum_total_response_bytes
        or type(collected.objects_received) is not int
        or not 0 <= collected.objects_received <= policy.maximum_total_objects
        or type(collected.objects_validated) is not int
        or collected.objects_validated != collected.objects_received
        or collected.pagination_complete is not True
    ):
        raise ValueError("The TAXII collection result is invalid.")
    canonical = validate_persistable_stix_document(
        collected.validated_document,
        policy.stix_policy,
    )
    if (
        canonical.objects_received != collected.objects_received
        or canonical.objects_validated != collected.objects_validated
    ):
        raise ValueError("The TAXII collection counters conflict.")
    return canonical


def _source_id_for_slug(session, source_slug: str) -> int:
    from sqlalchemy import select
    from app.models import IntelligenceSource

    source = session.execute(select(IntelligenceSource).where(IntelligenceSource.slug == source_slug)).scalar_one_or_none()
    if source is None or source.slug != source_slug:
        raise ValueError("The approved STIX source does not exist.")
    return source.id


__all__ = ["PRODUCTION_TAXII_LICENCE_REQUIRED", "StixTaxiiSourceHandler", "build_c03_stix_taxii_handlers", "canonical_document_sha256", "production_taxii_access_state"]
