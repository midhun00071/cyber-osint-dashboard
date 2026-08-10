from contextlib import nullcontext
from datetime import UTC, datetime
from types import MappingProxyType, SimpleNamespace

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion.stix_taxii.import_service import (
    StixImportPersistenceError,
    StixImportServiceError,
    StixRecordOutcome,
)
from app.ingestion.stix_taxii.object_mapping import StagedStixObject, canonical_safe_content_hash, freeze_mapping
from app.ingestion.stix_taxii.policy import ApprovedStixSourcePolicy, ApprovedTaxiiCollectionPolicy, StixInputTransport, build_taxii_policy_registry
from app.ingestion.stix_taxii.stix_validation import ValidatedStixDocument
from app.ingestion.stix_taxii.taxii_client import TaxiiCollectionResult
from app.models import IngestionRunRecord, IntelligenceSource
from app.orchestration.contracts import ClassifiedFailure, FailureCategory, QuotaObservation, ReconciledCounters, ResultStatus, SOURCE_POLICIES, SourceAttemptIdentity, SourceExecutionContext, classify_failure
from app.orchestration.flows import DEFAULT_SOURCE_HANDLERS
from app.orchestration.source_handlers import C02_BOUND_SOURCE_SLUGS
from app.orchestration.source_handlers.common import EVIDENCE_PREFIX
from app.orchestration.source_handlers.stix_taxii import StixTaxiiSourceHandler, build_c03_stix_taxii_handlers, canonical_document_sha256, production_taxii_access_state


SLOT = datetime(2026, 8, 3, 8, 17, tzinfo=UTC)
BASE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def registry():
    stix = ApprovedStixSourcePolicy(source_slug="cisa-kev", allowed_transport=StixInputTransport.TAXII_21_COLLECTION, policy_base_url=BASE_URL)
    return build_taxii_policy_registry((ApprovedTaxiiCollectionPolicy(stix_policy=stix, api_root_url="https://www.cisa.gov/taxii2", collection_id="synthetic"),))


def document(name="Synthetic"):
    payload = {"type": "identity", "id": "identity--11111111-1111-4111-8111-111111111111", "spec_version": "2.1", "created": "2026-08-03T08:17:00.000000Z", "modified": "2026-08-03T08:17:00.000000Z", "name": name, "identity_class": "organization"}
    staged = StagedStixObject(stix_type="identity", stix_id=payload["id"], created=SLOT, modified=SLOT, safe_payload=freeze_mapping(payload), content_hash=canonical_safe_content_hash(payload), observables=())
    return ValidatedStixDocument(objects=(staged,), validated_versions=(staged,), objects_received=1, objects_validated=1, relationships_validated=0, markings_validated=0)


def collection(*, pages=1, name="Synthetic"):
    validated = document(name)
    return TaxiiCollectionResult(
        pages_collected=pages,
        response_bytes_collected=100,
        objects_received=1,
        objects_validated=1,
        pagination_complete=True,
        validated_document=validated,
    )


def context(run_id=2):
    policy = SOURCE_POLICIES["cisa-kev"]
    return SourceExecutionContext(policy=policy, attempt=SourceAttemptIdentity("cisa-kev", 1, run_id, 0, 1), scheduled_for=SLOT, deployment_ref="alpha-data-ingestion-cycle", progress=None, quota=QuotaObservation(policy.quota_policy_key))


class Rows:
    def __init__(self, value): self.value = value
    def scalar_one_or_none(self): return self.value
    def scalars(self): return self
    def all(self): return self.value


class FakeSession:
    def __init__(self, events):
        self.events = events
        self.records = []
        self.source = IntelligenceSource(id=7, name="Synthetic", slug="cisa-kev", source_type="json", base_url=BASE_URL, is_enabled=True)
    def __enter__(self): self.events.append("session"); return self
    def __exit__(self, *args): return None
    def begin(self): self.events.append("begin"); return nullcontext()
    def execute(self, statement):
        expr = statement.column_descriptions[0]
        if expr.get("entity") is IntelligenceSource: return Rows(self.source)
        if getattr(expr.get("expr"), "name", None) == "safe_detail":
            return Rows([record.safe_detail for record in self.records if record.safe_detail and record.safe_detail.startswith(EVIDENCE_PREFIX)])
        raise AssertionError("unexpected query")
    def get(self, model, identity): return self.source if model is IntelligenceSource and identity == 7 else None
    def add(self, value):
        if isinstance(value, IngestionRunRecord): self.records.append(value)
    def flush(self): self.events.append("flush")


class FakeClient:
    def __init__(self, events, result): self.events, self.result = events, result
    def collect(self, source_slug): self.events.append("network"); assert source_slug == "cisa-kev"; return self.result


def test_empty_production_registry_is_disabled_without_transport():
    called = False
    def forbidden(_):
        nonlocal called; called = True; raise AssertionError
    assert production_taxii_access_state("missing-taxii") is ResultStatus.DISABLED
    assert build_c03_stix_taxii_handlers(client_factory=forbidden) == {}
    assert called is False


def test_licence_required_requires_explicit_fixed_entry_and_no_transport():
    assert production_taxii_access_state("licensed-taxii") is ResultStatus.LICENCE_REQUIRED
    assert production_taxii_access_state("other-taxii") is ResultStatus.DISABLED


def test_synthetic_builder_is_immutable_and_separate_from_production_bindings():
    handlers = build_c03_stix_taxii_handlers(registry(), session_factory=lambda: FakeSession([]))
    assert tuple(handlers) == ("cisa-kev",)
    assert isinstance(handlers, MappingProxyType)
    with pytest.raises(TypeError): handlers["cisa-kev"] = handlers["cisa-kev"]
    assert isinstance(DEFAULT_SOURCE_HANDLERS, MappingProxyType)
    assert frozenset(DEFAULT_SOURCE_HANDLERS) == C02_BOUND_SOURCE_SLUGS
    assert handlers["cisa-kev"] is not DEFAULT_SOURCE_HANDLERS["cisa-kev"]
    assert not any(
        isinstance(handler, StixTaxiiSourceHandler)
        for handler in DEFAULT_SOURCE_HANDLERS.values()
    )


def test_handler_requires_immutable_validated_policy_registry():
    with pytest.raises(ValueError, match="immutable"):
        StixTaxiiSourceHandler("cisa-kev", policy_registry=dict(registry()))  # type: ignore[arg-type]


def test_canonical_hash_includes_all_versions_deterministically():
    first = document("First")
    assert canonical_document_sha256(first) == canonical_document_sha256(first)
    changed = document("Changed")
    assert canonical_document_sha256(first) != canonical_document_sha256(changed)


def test_network_finishes_before_transaction_and_atomic_evidence_is_written(monkeypatch):
    events = []
    session = FakeSession(events)
    collected = collection(pages=2)
    client = FakeClient(events, collected)
    class Importer:
        def __init__(self, value): self.value = value
        def import_document(self, *args, **kwargs): events.append("import"); return SimpleNamespace(record_outcomes=(StixRecordOutcome(9, "identity--11111111-1111-4111-8111-111111111111", "created"),))
    monkeypatch.setattr("app.orchestration.source_handlers.stix_taxii.StixBundleImportService", Importer)
    handler = StixTaxiiSourceHandler("cisa-kev", policy_registry=registry(), session_factory=lambda: session, client_factory=lambda _: client)
    result = handler.execute(context())
    assert events.index("network") < events.index("begin") < events.index("import") < events.index("flush")
    assert result.status is ResultStatus.SUCCESS and result.counters.created == 1
    assert result.progress_proposal is not None and len(result.progress_proposal.value) == 64
    assert any(record.source_record_id == 9 and record.ingestion_run_id == 2 for record in session.records)


def test_committed_replay_and_reconstruction_are_network_free(monkeypatch):
    events = []
    session = FakeSession(events)
    class Importer:
        def __init__(self, value): pass
        def import_document(self, *args, **kwargs): return SimpleNamespace(record_outcomes=(StixRecordOutcome(9, "identity--11111111-1111-4111-8111-111111111111", "unchanged"),))
    monkeypatch.setattr("app.orchestration.source_handlers.stix_taxii.StixBundleImportService", Importer)
    calls = 0
    def factory(_):
        nonlocal calls; calls += 1; return FakeClient(events, collection())
    handler = StixTaxiiSourceHandler("cisa-kev", policy_registry=registry(), session_factory=lambda: session, client_factory=factory)
    first = handler.execute(context())
    replay = handler.execute(context())
    proposal = handler.reconstruct_progress(context(), ReconciledCounters(fetched=1, unchanged=1))
    assert calls == 1
    assert replay.status is ResultStatus.NO_CHANGE
    assert proposal == first.progress_proposal


def test_stale_outcome_is_controlled_non_success_without_progress(monkeypatch):
    session = FakeSession([])
    class Importer:
        def __init__(self, value): pass
        def import_document(self, *args, **kwargs): return SimpleNamespace(record_outcomes=(StixRecordOutcome(9, "identity--11111111-1111-4111-8111-111111111111", "skipped"),))
    monkeypatch.setattr("app.orchestration.source_handlers.stix_taxii.StixBundleImportService", Importer)
    handler = StixTaxiiSourceHandler("cisa-kev", policy_registry=registry(), session_factory=lambda: session, client_factory=lambda _: FakeClient([], collection()))
    result = handler.execute(context(3))
    assert result.status is ResultStatus.FAILED
    assert result.progress_proposal is None


def test_persistence_import_failure_is_transient_and_writes_no_evidence(monkeypatch):
    session = FakeSession([])
    raw_detail = "secret SQL parameters and database URL"

    class Importer:
        def __init__(self, value):
            pass

        def import_document(self, *args, **kwargs):
            try:
                raise SQLAlchemyError(raw_detail)
            except SQLAlchemyError as error:
                raise StixImportPersistenceError(
                    "Database error while importing validated STIX metadata."
                ) from error

    monkeypatch.setattr(
        "app.orchestration.source_handlers.stix_taxii.StixBundleImportService",
        Importer,
    )
    handler = StixTaxiiSourceHandler(
        "cisa-kev",
        policy_registry=registry(),
        session_factory=lambda: session,
        client_factory=lambda _: FakeClient([], collection()),
    )

    with pytest.raises(ClassifiedFailure) as caught:
        handler.execute(context(4))

    classification = classify_failure(caught.value)
    assert classification.category is FailureCategory.PERSISTENCE_CONTENTION
    assert classification.transient is True
    assert classification.safe_message == (
        "The approved STIX TAXII persistence transaction failed safely."
    )
    assert raw_detail not in str(caught.value)
    assert raw_detail not in classification.safe_message
    assert session.records == []


def test_threat_import_conflict_is_non_transient_and_writes_no_evidence(monkeypatch):
    session = FakeSession([])
    raw_detail = "corrupted alias and upstream object text"

    class Importer:
        def __init__(self, value):
            pass

        def import_document(self, *args, **kwargs):
            try:
                raise ValueError(raw_detail)
            except ValueError as error:
                raise StixImportServiceError(
                    "Validated STIX threat knowledge conflicts."
                ) from error

    monkeypatch.setattr(
        "app.orchestration.source_handlers.stix_taxii.StixBundleImportService",
        Importer,
    )
    handler = StixTaxiiSourceHandler(
        "cisa-kev",
        policy_registry=registry(),
        session_factory=lambda: session,
        client_factory=lambda _: FakeClient([], collection()),
    )

    with pytest.raises(ClassifiedFailure) as caught:
        handler.execute(context(5))

    classification = classify_failure(caught.value)
    assert classification.category is FailureCategory.VALIDATION_FAILURE
    assert classification.transient is False
    assert classification.safe_message == (
        "The approved STIX TAXII data failed safe validation."
    )
    assert raw_detail not in str(caught.value)
    assert raw_detail not in classification.safe_message
    assert session.records == []
