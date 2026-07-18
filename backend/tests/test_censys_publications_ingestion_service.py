from __future__ import annotations

from collections.abc import Sequence
from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import operators

from app.ingestion.adapters.censys_publications import (
    CENSYS_ARC_RESEARCH_SLUG,
    CENSYS_RAPID_RESPONSE_SLUG,
    adapt_censys_publication,
)
from app.ingestion.collectors.censys_publications_client import CensysFailureReason
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPersistenceResult,
    PublicationPipeline,
)
from app.ingestion.services.censys_publications_ingestion_service import (
    CensysFailureAuditKind,
    CensysIngestionDatabaseError,
    CensysIngestionInputError,
    CensysIngestionTrigger,
    CensysPublicationsIngestionService,
    collector_failure_audit_kind,
)
from app.models import (
    IngestionError,
    IngestionRun,
    IngestionRunRecord,
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
)


NOW = datetime(2026, 7, 17, 8, 0, tzinfo=UTC)


class FakeSession:
    def __init__(
        self,
        *,
        commit_error: Exception | None = None,
        rollback_error: Exception | None = None,
        flush_error: Exception | None = None,
    ) -> None:
        self.commit_error = commit_error
        self.rollback_error = rollback_error
        self.flush_error = flush_error
        self.added: list[object] = []
        self.commits = 0
        self.rollbacks = 0
        self.flushes = 0
        self.nested_transactions = 0

    def add(self, record: object) -> None:
        self.added.append(record)

    def flush(self) -> None:
        if self.flush_error is not None:
            raise self.flush_error
        self.flushes += 1
        for record in self.added:
            if isinstance(record, IngestionRun) and record.id is None:
                record.id = 1
                record.public_id = uuid4()

    def begin_nested(self):
        self.nested_transactions += 1
        return nullcontext()

    def commit(self) -> None:
        if self.commit_error is not None:
            raise self.commit_error
        self.commits += 1

    def rollback(self) -> None:
        if self.rollback_error is not None:
            raise self.rollback_error
        self.rollbacks += 1


class FakePipeline:
    def __init__(
        self,
        session: FakeSession,
        *,
        outcomes: list[str] | None = None,
        error: Exception | None = None,
        source_error: Exception | None = None,
    ) -> None:
        self.session = session
        self.outcomes = list(outcomes) if outcomes is not None else None
        self.error = error
        self.source_error = source_error
        self.persist_calls: list[PublicationCandidate] = []
        self.identities: set[tuple[str, str]] = set()
        self.canonical_items: set[str] = set()
        self.sources = {
            slug: IntelligenceSource(
                slug=slug,
                name=slug,
                source_type="json",
                base_url="https://censys.com/",
                is_enabled=True,
                checkpoint_value=None,
            )
            for slug in (CENSYS_ARC_RESEARCH_SLUG, CENSYS_RAPID_RESPONSE_SLUG)
        }

    def ensure_source(self, source_slug: str) -> IntelligenceSource:
        if self.source_error is not None:
            raise self.source_error
        return self.sources[source_slug]

    def persist(self, candidate: PublicationCandidate, *, observed_at: datetime):
        assert observed_at == NOW
        self.persist_calls.append(candidate)
        if self.error is not None:
            raise self.error
        identity = (candidate.source_slug, candidate.source_external_id)
        if self.outcomes is not None:
            outcome = self.outcomes.pop(0)
        else:
            outcome = "unchanged" if identity in self.identities else "created"
        if outcome in {"created", "updated", "unchanged"}:
            self.identities.add(identity)
            self.canonical_items.add(candidate.canonical_url)
        return PublicationPersistenceResult(
            candidate.source_external_id,
            outcome,
            None,
            None,
            101,
        )


def candidate(
    source_slug: str = CENSYS_ARC_RESEARCH_SLUG,
    *,
    identifier: str = "publication-1",
    url: str | None = None,
) -> PublicationCandidate:
    path = "blog" if source_slug == CENSYS_ARC_RESEARCH_SLUG else "advisory"
    return PublicationCandidate(
        source_slug=source_slug,
        source_external_id=f"{source_slug}:{identifier}",
        canonical_title="Approved public Censys metadata",
        canonical_url=url or f"https://censys.com/{path}/{identifier}/",
        safe_source_payload={"authors": ("Censys",)},
    )


def ingest(
    *,
    source_slug: str = CENSYS_ARC_RESEARCH_SLUG,
    candidates: tuple[PublicationCandidate, ...] | list[PublicationCandidate] = (),
    failure_kinds: tuple[CensysFailureAuditKind, ...] = (),
    outcomes: list[str] | None = None,
    session: FakeSession | None = None,
    pipeline: FakePipeline | None = None,
):
    active_session = session or FakeSession()
    active_pipeline = pipeline or FakePipeline(active_session, outcomes=outcomes)
    result = CensysPublicationsIngestionService(
        active_session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: active_pipeline,  # type: ignore[arg-type]
    ).ingest(
        source_slug=source_slug,
        candidates=candidates,
        failure_kinds=failure_kinds,
        records_fetched=len(candidates) + len(failure_kinds),
        trigger=CensysIngestionTrigger.LIVE,
        observed_at=NOW,
    )
    return result.run, active_session, active_pipeline


@pytest.mark.parametrize(
    ("source_slug", "expected_path"),
    [
        (CENSYS_ARC_RESEARCH_SLUG, "/blog/"),
        (CENSYS_RAPID_RESPONSE_SLUG, "/advisory/"),
    ],
)
def test_approved_source_candidate_persists_and_commits(
    source_slug: str,
    expected_path: str,
) -> None:
    record = candidate(source_slug)

    run, session, pipeline = ingest(source_slug=source_slug, candidates=(record,))

    assert run.status == "succeeded"
    assert run.trigger_type == "manual"
    assert run.records_fetched == 1
    assert run.records_created == 1
    assert expected_path in pipeline.persist_calls[0].canonical_url
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.nested_transactions == 1


@pytest.mark.parametrize(
    ("outcome", "counter", "status"),
    [
        ("created", "records_created", "succeeded"),
        ("updated", "records_updated", "succeeded"),
        ("unchanged", "records_unchanged", "succeeded"),
        ("skipped", "records_skipped", "partial"),
        ("failed", "records_failed", "failed"),
    ],
)
def test_pipeline_outcomes_are_counted_once(
    outcome: str,
    counter: str,
    status: str,
) -> None:
    run, session, _ = ingest(candidates=(candidate(),), outcomes=[outcome])

    assert getattr(run, counter) == 1
    assert run.status == status
    assert session.commits == 1
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert len(errors) == (1 if outcome == "failed" else 0)


def test_exact_batch_duplicate_is_unlinked_unchanged_without_second_persist() -> None:
    session = FakeSession()
    pipeline = FakePipeline(session)
    source_record = SourceRecord(id=77)
    publication = PublicationCandidate(
        source_slug=CENSYS_ARC_RESEARCH_SLUG,
        source_external_id="private-external-id",
        canonical_title="Sensitive Alpha Research Title",
        canonical_url="https://censys.com/blog/private-publication/",
        safe_source_payload={"private-payload": "must-not-appear"},
    )

    def persist(record: PublicationCandidate, *, observed_at: datetime):
        pipeline.persist_calls.append(record)
        return PublicationPersistenceResult(
            source_external_id=record.source_external_id,
            outcome="created",
            source_record=source_record,
            intelligence_item_id=501,
        )

    pipeline.persist = persist  # type: ignore[method-assign]

    run, session, pipeline = ingest(
        candidates=(publication, publication),
        session=session,
        pipeline=pipeline,
    )
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    linked = [audit for audit in audits if audit.source_record is not None]
    unlinked = [audit for audit in audits if audit.source_record is None]

    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_unchanged == 1
    assert run.records_failed == 0
    assert run.status == "succeeded"
    assert len(pipeline.persist_calls) == 1
    assert [audit.action for audit in audits] == ["created", "unchanged"]
    assert len(linked) == 1
    assert len(unlinked) == 1
    assert unlinked[0].intelligence_item_id is None
    assert unlinked[0].safe_detail == (
        "A duplicate Censys publication matched an earlier batch entry."
    )
    private_values = (
        publication.canonical_title,
        publication.canonical_url,
        publication.source_external_id,
        "private-payload",
    )
    assert all(value not in unlinked[0].safe_detail for value in private_values)
    assert errors == []
    assert session.commits == 1
    assert session.rollbacks == 0


@pytest.mark.parametrize(
    "conflict",
    [
        "external_id_content",
        "external_id_url",
        "canonical_url_external_id",
    ],
)
def test_batch_identity_conflict_fails_once_and_later_candidate_continues(
    conflict: str,
) -> None:
    first = candidate(identifier="first")
    if conflict == "external_id_content":
        conflicting = replace(first, canonical_title="Conflicting private title")
    elif conflict == "external_id_url":
        conflicting = replace(
            first,
            canonical_url="https://censys.com/blog/conflicting-url/",
        )
    else:
        conflicting = replace(
            first,
            source_external_id="censys-arc-research:different-private-id",
        )
    later = candidate(identifier="later")

    run, session, pipeline = ingest(
        candidates=(first, conflicting, later),
        outcomes=["created", "created"],
    )

    assert run.records_fetched == 3
    assert run.records_created == 2
    assert run.records_failed == 1
    assert run.status == "partial"
    assert pipeline.persist_calls == [first, later]
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    assert [audit.action for audit in audits] == ["created", "failed", "created"]
    assert session.commits == 1


def test_repeated_source_record_result_uses_unlinked_audit_without_losing_outcome(
) -> None:
    session = FakeSession()
    pipeline = FakePipeline(session)
    shared_source_record = SourceRecord()
    first = candidate(identifier="first")
    second = candidate(identifier="second")

    def persist(record: PublicationCandidate, *, observed_at: datetime):
        del observed_at
        if pipeline.persist_calls:
            shared_source_record.id = 88
        pipeline.persist_calls.append(record)
        return PublicationPersistenceResult(
            source_external_id=record.source_external_id,
            outcome="created",
            message="Injected detail that must not replace the static guard.",
            source_record=shared_source_record,
            intelligence_item_id=601,
        )

    pipeline.persist = persist  # type: ignore[method-assign]

    run, session, pipeline = ingest(
        candidates=(first, second),
        session=session,
        pipeline=pipeline,
    )
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    linked = [audit for audit in audits if audit.source_record is not None]
    unlinked = [audit for audit in audits if audit.source_record is None]

    assert len(pipeline.persist_calls) == 2
    assert run.records_created == 2
    assert run.records_failed == 0
    assert len(linked) == 1
    assert len(unlinked) == 1
    assert unlinked[0].action == "created"
    assert unlinked[0].intelligence_item_id is None
    assert unlinked[0].safe_detail == (
        "A Censys publication outcome matched an earlier linked audit entry."
    )
    assert "Injected" not in unlinked[0].safe_detail


@pytest.mark.parametrize(
    ("database_ids", "expected_linked"),
    [((91, 91), 1), ((91, 92), 2)],
)
def test_distinct_source_record_objects_compare_current_database_ids(
    database_ids: tuple[int, int],
    expected_linked: int,
) -> None:
    session = FakeSession()
    pipeline = FakePipeline(session)
    source_records = tuple(SourceRecord(id=value) for value in database_ids)
    publications = (
        candidate(identifier="first"),
        candidate(identifier="second"),
    )

    def persist(record: PublicationCandidate, *, observed_at: datetime):
        del observed_at
        index = len(pipeline.persist_calls)
        pipeline.persist_calls.append(record)
        return PublicationPersistenceResult(
            source_external_id=record.source_external_id,
            outcome="created",
            message="Private injected pipeline detail.",
            source_record=source_records[index],
            intelligence_item_id=700 + index,
        )

    pipeline.persist = persist  # type: ignore[method-assign]

    run, session, _ = ingest(
        candidates=publications,
        session=session,
        pipeline=pipeline,
    )
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    linked = [audit for audit in audits if audit.source_record is not None]
    unlinked = [audit for audit in audits if audit.source_record is None]

    assert run.records_created == 2
    assert len(linked) == expected_linked
    assert len(unlinked) == 2 - expected_linked
    if database_ids[0] == database_ids[1]:
        assert unlinked[0].intelligence_item_id is None
        assert unlinked[0].safe_detail == (
            "A Censys publication outcome matched an earlier linked audit entry."
        )
        assert "Private" not in unlinked[0].safe_detail


@pytest.mark.parametrize(
    ("trigger", "expected_prefix"),
    [
        (CensysIngestionTrigger.LIVE, "Bounded manual Censys live ingestion"),
        (CensysIngestionTrigger.LOCAL_FILE, "Manual Censys import"),
    ],
)
def test_completed_summary_preserves_operation_context(
    trigger: CensysIngestionTrigger,
    expected_prefix: str,
) -> None:
    session = FakeSession()
    pipeline = FakePipeline(session)

    result = CensysPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
    ).ingest(
        source_slug=CENSYS_ARC_RESEARCH_SLUG,
        candidates=(candidate(),),
        records_fetched=1,
        trigger=trigger,
        observed_at=NOW,
    )

    assert result.run.safe_summary.startswith(expected_prefix)
    assert "fetched=1" in result.run.safe_summary


def test_mixed_collector_failure_is_audited_once_without_private_detail() -> None:
    run, session, _ = ingest(
        candidates=(candidate(),),
        failure_kinds=(CensysFailureAuditKind.TIMEOUT,),
    )
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    failure_audit = next(item for item in audits if item.action == "failed")

    assert run.status == "partial"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_failed == 1
    assert run.error_count == 1
    assert failure_audit.source_record is None
    assert failure_audit.safe_detail == "A Censys publication request timed out."
    assert errors[0].error_type == "censys_timeout"
    serialized = " ".join(
        [failure_audit.safe_detail or "", errors[0].safe_message]
    ).lower()
    assert "https://" not in serialized
    assert "private" not in serialized


def test_all_collector_failures_create_failed_committed_run() -> None:
    run, session, _ = ingest(
        failure_kinds=(
            CensysFailureAuditKind.TRANSPORT_FAILURE,
            CensysFailureAuditKind.METADATA_REJECTED,
        )
    )

    assert run.status == "failed"
    assert run.records_fetched == 2
    assert run.records_failed == 2
    assert session.commits == 1


def test_every_collector_failure_reason_has_a_static_mapping() -> None:
    mapped = {
        reason: collector_failure_audit_kind(reason)
        for reason in CensysFailureReason
    }

    assert set(mapped) == set(CensysFailureReason)
    assert {kind.value for kind in mapped.values()} == {
        reason.value for reason in CensysFailureReason
    }


def test_reprocessing_identity_delegates_deduplication_to_shared_pipeline() -> None:
    session = FakeSession()
    pipeline = FakePipeline(session)
    first = candidate()

    first_run, _, _ = ingest(
        candidates=(first,), session=session, pipeline=pipeline
    )
    second_run, _, _ = ingest(
        candidates=(first,), session=session, pipeline=pipeline
    )

    assert first_run.records_created == 1
    assert second_run.records_unchanged == 1
    assert len(pipeline.identities) == 1
    assert len(pipeline.canonical_items) == 1


def test_arc_and_rapid_response_source_identities_remain_separate() -> None:
    session = FakeSession()
    pipeline = FakePipeline(session)
    arc = candidate(identifier="shared-name")
    rapid = candidate(
        CENSYS_RAPID_RESPONSE_SLUG,
        identifier="shared-name",
    )

    ingest(candidates=(arc,), session=session, pipeline=pipeline)
    ingest(
        source_slug=CENSYS_RAPID_RESPONSE_SLUG,
        candidates=(rapid,),
        session=session,
        pipeline=pipeline,
    )

    assert len(pipeline.identities) == 2
    assert len(pipeline.canonical_items) == 2


@pytest.mark.parametrize(
    ("source_slug", "records"),
    [
        ("unsupported", ()),
        (CENSYS_RAPID_RESPONSE_SLUG, (candidate(),)),
        (CENSYS_ARC_RESEARCH_SLUG, ({"raw": "payload"},)),
    ],
)
def test_closed_service_interface_rejects_unsupported_or_raw_input_before_mutation(
    source_slug: str,
    records: tuple[object, ...],
) -> None:
    session = FakeSession()
    pipeline_created = False

    def pipeline_factory(_: object):
        nonlocal pipeline_created
        pipeline_created = True
        return FakePipeline(session)

    with pytest.raises(CensysIngestionInputError):
        CensysPublicationsIngestionService(
            session,  # type: ignore[arg-type]
            pipeline_factory=pipeline_factory,  # type: ignore[arg-type]
        ).ingest(
            source_slug=source_slug,
            candidates=records,  # type: ignore[arg-type]
            records_fetched=len(records),
            trigger=CensysIngestionTrigger.LIVE,
            observed_at=NOW,
        )

    assert pipeline_created is False
    assert session.added == []
    assert session.commits == 0
    assert session.rollbacks == 0


@pytest.mark.parametrize("failure_point", ["persist", "commit"])
def test_database_failure_rolls_back_without_commit_or_partial_commit(
    failure_point: str,
) -> None:
    secret = "postgresql://private:password@host/database params=secret"
    session = FakeSession(
        commit_error=SQLAlchemyError(secret) if failure_point == "commit" else None
    )
    pipeline = FakePipeline(
        session,
        error=SQLAlchemyError(secret) if failure_point == "persist" else None,
    )

    with pytest.raises(CensysIngestionDatabaseError) as exc_info:
        ingest(candidates=(candidate(),), session=session, pipeline=pipeline)

    assert session.commits == 0
    assert session.rollbacks == 1
    assert secret not in str(exc_info.value)
    assert "database operation" in str(exc_info.value)


@pytest.mark.parametrize(
    "failure_point",
    ["pipeline_factory", "source", "flush", "persist", "commit"],
)
def test_service_memory_error_propagates_from_transaction_boundaries(
    failure_point: str,
) -> None:
    memory_error = MemoryError(f"private service {failure_point}")
    session = FakeSession(
        commit_error=memory_error if failure_point == "commit" else None,
        flush_error=memory_error if failure_point == "flush" else None,
    )
    pipeline = FakePipeline(
        session,
        error=memory_error if failure_point == "persist" else None,
        source_error=memory_error if failure_point == "source" else None,
    )

    def pipeline_factory(_: object):
        if failure_point == "pipeline_factory":
            raise memory_error
        return pipeline

    service = CensysPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=pipeline_factory,  # type: ignore[arg-type]
    )

    with pytest.raises(MemoryError) as exc_info:
        service.ingest(
            source_slug=CENSYS_ARC_RESEARCH_SLUG,
            candidates=(candidate(),),
            records_fetched=1,
            trigger=CensysIngestionTrigger.LIVE,
            observed_at=NOW,
        )

    assert exc_info.value is memory_error
    assert session.commits == 0
    assert session.rollbacks == 1


def test_rollback_cleanup_does_not_swallow_memory_error() -> None:
    rollback_error = MemoryError("private rollback memory marker")
    session = FakeSession(rollback_error=rollback_error)
    pipeline = FakePipeline(
        session,
        error=SQLAlchemyError("ordinary private database marker"),
    )

    with pytest.raises(MemoryError) as exc_info:
        ingest(candidates=(candidate(),), session=session, pipeline=pipeline)

    assert exc_info.value is rollback_error
    assert session.commits == 0


def test_rollback_cleanup_does_not_replace_active_system_exception() -> None:
    primary_error = MemoryError("primary private memory marker")
    session = FakeSession(
        rollback_error=MemoryError("secondary private rollback marker")
    )
    pipeline = FakePipeline(session, error=primary_error)

    with pytest.raises(MemoryError) as exc_info:
        ingest(candidates=(candidate(),), session=session, pipeline=pipeline)

    assert exc_info.value is primary_error


@pytest.mark.parametrize(
    "system_exception",
    [KeyboardInterrupt(), SystemExit(7), GeneratorExit()],
)
def test_service_preserves_non_memory_system_exceptions(system_exception) -> None:
    session = FakeSession()
    pipeline = FakePipeline(session, error=system_exception)

    with pytest.raises(type(system_exception)) as exc_info:
        ingest(candidates=(candidate(),), session=session, pipeline=pipeline)

    assert exc_info.value is system_exception
    assert session.rollbacks == 1


class FailingSequence(Sequence[object]):
    def __init__(self, error) -> None:
        self.error = error

    def __len__(self) -> int:
        return 1

    def __getitem__(self, index: int) -> object:
        del index
        raise self.error


@pytest.mark.parametrize("target", ["candidates", "failure_kinds"])
def test_failing_sequence_is_sanitized_before_pipeline_or_session_mutation(
    target: str,
) -> None:
    secret = f"private {target} iterator https://private.example/"
    failing_sequence = FailingSequence(RuntimeError(secret))
    session = FakeSession()
    pipeline_created = False

    def pipeline_factory(_: object):
        nonlocal pipeline_created
        pipeline_created = True
        return FakePipeline(session)

    service = CensysPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=pipeline_factory,  # type: ignore[arg-type]
    )
    arguments = {
        "source_slug": CENSYS_ARC_RESEARCH_SLUG,
        "candidates": failing_sequence if target == "candidates" else (),
        "failure_kinds": failing_sequence if target == "failure_kinds" else (),
        "records_fetched": 0,
        "trigger": CensysIngestionTrigger.LIVE,
        "observed_at": NOW,
    }

    with pytest.raises(CensysIngestionInputError) as exc_info:
        service.ingest(**arguments)  # type: ignore[arg-type]

    assert str(exc_info.value) == (
        "The Censys ingestion input could not be validated safely."
    )
    assert secret not in str(exc_info.value)
    assert pipeline_created is False
    assert session.added == []
    assert session.commits == 0
    assert session.rollbacks == 0


def test_sequence_materialization_memory_error_propagates_without_mutation() -> None:
    memory_error = MemoryError("private sequence memory marker")
    session = FakeSession()
    pipeline_created = False

    def pipeline_factory(_: object):
        nonlocal pipeline_created
        pipeline_created = True
        return FakePipeline(session)

    service = CensysPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=pipeline_factory,  # type: ignore[arg-type]
    )

    with pytest.raises(MemoryError) as exc_info:
        service.ingest(
            source_slug=CENSYS_ARC_RESEARCH_SLUG,
            candidates=FailingSequence(memory_error),  # type: ignore[arg-type]
            records_fetched=0,
            trigger=CensysIngestionTrigger.LIVE,
            observed_at=NOW,
        )

    assert exc_info.value is memory_error
    assert pipeline_created is False
    assert session.added == []
    assert session.rollbacks == 0


def test_datetime_normalization_failure_is_sanitized_before_mutation() -> None:
    secret = "private timezone normalization marker"
    session = FakeSession()
    pipeline_created = False

    class BrokenDateTime(datetime):
        def astimezone(self, tz=None):
            del tz
            raise RuntimeError(secret)

    def pipeline_factory(_: object):
        nonlocal pipeline_created
        pipeline_created = True
        return FakePipeline(session)

    service = CensysPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=pipeline_factory,  # type: ignore[arg-type]
    )

    with pytest.raises(CensysIngestionInputError) as exc_info:
        service.ingest(
            source_slug=CENSYS_ARC_RESEARCH_SLUG,
            candidates=(),
            records_fetched=0,
            trigger=CensysIngestionTrigger.LIVE,
            observed_at=BrokenDateTime(2026, 7, 17, 8, 0, tzinfo=UTC),
        )

    assert str(exc_info.value) == (
        "The Censys ingestion input could not be validated safely."
    )
    assert secret not in str(exc_info.value)
    assert pipeline_created is False
    assert session.added == []
    assert session.rollbacks == 0


class ScalarResult:
    def __init__(self, value: object | None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object | None:
        return self.value


def criterion_value(criteria: list[object], column_name: str) -> object:
    for criterion in criteria:
        left = getattr(criterion, "left", None)
        if getattr(left, "name", None) != column_name:
            continue
        right = getattr(criterion, "right", None)
        if hasattr(right, "value"):
            return right.value
    return None


class RealPipelineSession:
    """Established offline pipeline-session pattern plus Task 2 audit models."""

    def __init__(self) -> None:
        self.sources: list[IntelligenceSource] = []
        self.items: list[IntelligenceItem] = []
        self.source_records: list[SourceRecord] = []
        self.identifiers: list[IntelligenceItemIdentifier] = []
        self.runs: list[IngestionRun] = []
        self.run_records: list[IngestionRunRecord] = []
        self.errors: list[IngestionError] = []
        self.commits = 0
        self.rollbacks = 0
        self.unique_index_checks = 0

    def add(self, record: object) -> None:
        collections = {
            IntelligenceSource: self.sources,
            IntelligenceItem: self.items,
            SourceRecord: self.source_records,
            IntelligenceItemIdentifier: self.identifiers,
            IngestionRun: self.runs,
            IngestionRunRecord: self.run_records,
            IngestionError: self.errors,
        }
        for record_type, collection in collections.items():
            if isinstance(record, record_type):
                if record not in collection:
                    collection.append(record)
                return
        raise AssertionError(f"Unexpected record type: {type(record)}")

    def flush(self) -> None:
        collections = (
            self.sources,
            self.items,
            self.source_records,
            self.identifiers,
            self.runs,
            self.run_records,
            self.errors,
        )
        for collection in collections:
            for index, record in enumerate(collection, start=1):
                if getattr(record, "id", None) is None:
                    record.id = index
                if isinstance(record, SourceRecord):
                    record.source_id = record.source.id
                    record.intelligence_item_id = record.intelligence_item.id
                elif isinstance(record, IntelligenceItemIdentifier):
                    record.intelligence_item_id = record.intelligence_item.id
                    if record.source is not None:
                        record.source_id = record.source.id
                    if record.source_record is not None:
                        record.source_record_id = record.source_record.id
                elif isinstance(record, IngestionRun):
                    record.source_id = record.source.id
                    if record.public_id is None:
                        record.public_id = uuid4()
                elif isinstance(record, IngestionRunRecord):
                    record.ingestion_run_id = record.ingestion_run.id
                    record.source_record_id = (
                        record.source_record.id
                        if record.source_record is not None
                        else None
                    )
        linked_audit_keys: set[tuple[int, int]] = set()
        for audit_record in self.run_records:
            if audit_record.source_record_id is None:
                continue
            key = (
                audit_record.ingestion_run_id,
                audit_record.source_record_id,
            )
            if key in linked_audit_keys:
                raise SQLAlchemyError(
                    "Duplicate linked ingestion audit rejected by test constraint."
                )
            linked_audit_keys.add(key)
        self.unique_index_checks += 1

    def execute(self, statement: Any) -> ScalarResult:
        entity = statement.column_descriptions[0]["entity"]
        criteria = list(statement._where_criteria)
        if entity is IntelligenceSource:
            slug = criterion_value(criteria, "slug")
            return ScalarResult(
                next((source for source in self.sources if source.slug == slug), None)
            )
        if entity is SourceRecord:
            source_id = criterion_value(criteria, "source_id")
            external_id = criterion_value(criteria, "source_external_id")
            url_hash = criterion_value(criteria, "canonical_url_hash")
            return ScalarResult(
                next(
                    (
                        record
                        for record in self.source_records
                        if record.source_id == source_id
                        and (
                            (
                                external_id is not None
                                and record.source_external_id == external_id
                            )
                            or (
                                url_hash is not None
                                and record.canonical_url_hash == url_hash
                            )
                        )
                    ),
                    None,
                )
            )
        if entity is IntelligenceItemIdentifier:
            namespace = criterion_value(criteria, "namespace")
            normalized_value = criterion_value(criteria, "normalized_value")
            source_is_null = any(
                getattr(getattr(criterion, "left", None), "name", None)
                == "source_id"
                and getattr(criterion, "operator", None) is operators.is_
                for criterion in criteria
            )
            matches = [
                identifier
                for identifier in self.identifiers
                if (not source_is_null or identifier.source_id is None)
                and identifier.namespace == namespace
                and identifier.normalized_value == normalized_value
            ]
            return ScalarResult(matches[0] if matches else None)
        raise AssertionError(f"Unexpected select entity: {entity}")

    def begin_nested(self):
        return nullcontext()

    def commit(self) -> None:
        self.flush()
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def test_delayed_id_on_prior_record_blocks_distinct_same_id_link() -> None:
    session = RealPipelineSession()
    first_source_record = SourceRecord()
    second_source_record = SourceRecord(id=77)
    source = IntelligenceSource(
        slug=CENSYS_ARC_RESEARCH_SLUG,
        name="Censys ARC Research",
        source_type="json",
        base_url="https://censys.com/",
        is_enabled=True,
    )

    class DelayedIdentityPipeline:
        def __init__(self) -> None:
            self.persist_calls: list[PublicationCandidate] = []

        def ensure_source(self, source_slug: str) -> IntelligenceSource:
            assert source_slug == CENSYS_ARC_RESEARCH_SLUG
            if source not in session.sources:
                session.add(source)
                session.flush()
            return source

        def persist(
            self,
            record: PublicationCandidate,
            *,
            observed_at: datetime,
        ) -> PublicationPersistenceResult:
            del observed_at
            self.persist_calls.append(record)
            if len(self.persist_calls) == 1:
                return PublicationPersistenceResult(
                    source_external_id=record.source_external_id,
                    outcome="created",
                    message="Private first pipeline detail.",
                    source_record=first_source_record,
                    intelligence_item_id=801,
                )
            first_source_record.id = 77
            return PublicationPersistenceResult(
                source_external_id=record.source_external_id,
                outcome="created",
                message="Private second pipeline detail containing ID 77.",
                source_record=second_source_record,
                intelligence_item_id=802,
            )

    pipeline = DelayedIdentityPipeline()
    service = CensysPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
    )

    result = service.ingest(
        source_slug=CENSYS_ARC_RESEARCH_SLUG,
        candidates=(
            candidate(identifier="first"),
            candidate(identifier="second"),
        ),
        records_fetched=2,
        trigger=CensysIngestionTrigger.LIVE,
        observed_at=NOW,
    )

    linked = [
        audit for audit in session.run_records if audit.source_record_id is not None
    ]
    unlinked = [
        audit for audit in session.run_records if audit.source_record_id is None
    ]
    linked_pairs = {
        (audit.ingestion_run_id, audit.source_record_id) for audit in linked
    }
    assert result.run.records_created == 2
    assert result.run.records_failed == 0
    assert len(pipeline.persist_calls) == 2
    assert len(linked) == 1
    assert len(unlinked) == 1
    assert unlinked[0].source_record is None
    assert unlinked[0].intelligence_item_id is None
    assert unlinked[0].safe_detail == (
        "A Censys publication outcome matched an earlier linked audit entry."
    )
    assert "Private" not in unlinked[0].safe_detail
    assert "77" not in unlinked[0].safe_detail
    assert len(linked_pairs) == len(linked)
    assert session.commits == 1
    assert session.rollbacks == 0


def test_shared_service_real_pipeline_reprocessing_does_not_duplicate_identity(
) -> None:
    session = RealPipelineSession()
    record = {
        "title": "Censys ARC Research",
        "url": "https://censys.com/blog/arc-research/",
        "summary": "Safe public research summary.",
        "published_at": "2026-07-01T12:00:00Z",
        "modified_at": None,
        "authors": ["Censys Research"],
        "categories": ["Research"],
    }
    publication = adapt_censys_publication(CENSYS_ARC_RESEARCH_SLUG, record)
    service = CensysPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=PublicationPipeline,
    )

    first = service.ingest(
        source_slug=CENSYS_ARC_RESEARCH_SLUG,
        candidates=(publication,),
        records_fetched=1,
        trigger=CensysIngestionTrigger.LOCAL_FILE,
        observed_at=NOW,
    )
    second = service.ingest(
        source_slug=CENSYS_ARC_RESEARCH_SLUG,
        candidates=(publication,),
        records_fetched=1,
        trigger=CensysIngestionTrigger.LIVE,
        observed_at=NOW,
    )

    assert first.run.records_created == 1
    assert second.run.records_unchanged == 1
    assert len(session.source_records) == 1
    assert len(session.items) == 1
    assert len(session.sources) == 1
    assert session.commits == 2
    assert session.rollbacks == 0


def test_real_pipeline_identical_batch_satisfies_linked_audit_unique_index() -> None:
    session = RealPipelineSession()
    publication = adapt_censys_publication(
        CENSYS_ARC_RESEARCH_SLUG,
        {
            "title": "Censys ARC Research",
            "url": "https://censys.com/blog/arc-research/",
            "summary": "Safe public research summary.",
            "published_at": "2026-07-01T12:00:00Z",
            "modified_at": None,
            "authors": ["Censys Research"],
            "categories": ["Research"],
        },
    )
    service = CensysPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=PublicationPipeline,
    )

    result = service.ingest(
        source_slug=CENSYS_ARC_RESEARCH_SLUG,
        candidates=(publication, publication),
        records_fetched=2,
        trigger=CensysIngestionTrigger.LOCAL_FILE,
        observed_at=NOW,
    )

    linked_audits = [
        audit for audit in session.run_records if audit.source_record_id is not None
    ]
    unlinked_audits = [
        audit for audit in session.run_records if audit.source_record_id is None
    ]
    assert result.run.status == "succeeded"
    assert result.run.records_created == 1
    assert result.run.records_unchanged == 1
    assert result.run.records_failed == 0
    assert len(session.source_records) == 1
    assert len(session.items) == 1
    assert len(linked_audits) == 1
    assert len(unlinked_audits) == 1
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.unique_index_checks > 0
