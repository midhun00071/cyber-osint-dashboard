from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion.adapters.anomali_publications import ANOMALI_SOURCE_SLUG
from app.ingestion.collectors.anomali_publications_client import (
    MAX_RECORDS,
    AnomaliFailureReason,
)
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPersistenceError,
    PublicationPersistenceResult,
)
from app.ingestion.services import anomali_publications_ingestion_service as service_module
from app.ingestion.services.anomali_publications_ingestion_service import (
    COLLECTOR_FAILURE_AUDIT_KINDS,
    AnomaliFailureAuditKind,
    AnomaliIngestionDatabaseError,
    AnomaliIngestionError,
    AnomaliIngestionInputError,
    AnomaliIngestionResult,
    AnomaliIngestionTrigger,
    AnomaliPublicationsIngestionService,
    collector_failure_audit_kind,
)
from app.models import (
    IngestionError,
    IngestionRun,
    IngestionRunRecord,
    IntelligenceSource,
    SourceRecord,
)


NOW = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
ROLLBACK_FAILURE_EVENT = (
    "event=ingestion_rollback_failed source=anomali-publications "
    "error_category=transaction_cleanup_failed"
)


class ErrorLogRecorder:
    def __init__(self, error: BaseException | None = None) -> None:
        self.raised_error = error
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def error(self, *args: object, **kwargs: object) -> None:
        self.calls.append((args, kwargs))
        if self.raised_error is not None:
            raise self.raised_error


def _rollback_log_recorder(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException | None = None,
) -> ErrorLogRecorder:
    recorder = ErrorLogRecorder(error)
    monkeypatch.setattr(service_module, "_LOGGER", recorder)
    return recorder


def _assert_single_sanitized_rollback_log(recorder: ErrorLogRecorder) -> None:
    assert recorder.calls == [((ROLLBACK_FAILURE_EVENT,), {})]


class FakeSession:
    def __init__(
        self,
        *,
        commit_error: BaseException | None = None,
        rollback_error: BaseException | None = None,
        invalidation_error: BaseException | None = None,
        flush_error: BaseException | None = None,
        audit_error: BaseException | None = None,
    ) -> None:
        self.commit_error = commit_error
        self.rollback_error = rollback_error
        self.invalidation_error = invalidation_error
        self.flush_error = flush_error
        self.audit_error = audit_error
        self.added: list[object] = []
        self.commits = 0
        self.rollbacks = 0
        self.invalidations = 0
        self.flushes = 0
        self.nested_transactions = 0

    def add(self, record: object) -> None:
        if self.audit_error is not None and isinstance(record, IngestionRunRecord):
            raise self.audit_error
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
        self.rollbacks += 1
        if self.rollback_error is not None:
            raise self.rollback_error

    def invalidate(self) -> None:
        self.invalidations += 1
        if self.invalidation_error is not None:
            raise self.invalidation_error


class FakePipeline:
    def __init__(
        self,
        *,
        outcomes: list[str] | None = None,
        error: BaseException | None = None,
        source_error: BaseException | None = None,
        source_records: list[SourceRecord | None] | None = None,
    ) -> None:
        self.outcomes = list(outcomes) if outcomes is not None else None
        self.error = error
        self.source_error = source_error
        self.source_records = list(source_records or [])
        self.persist_calls: list[PublicationCandidate] = []
        self.seen: set[tuple[str, str]] = set()
        self.source = IntelligenceSource(
            slug=ANOMALI_SOURCE_SLUG,
            name="Anomali Cyber Watch",
            source_type="json",
            base_url="https://www.anomali.com/blog/",
            is_enabled=True,
            checkpoint_value=None,
        )

    def ensure_source(self, source_slug: str) -> IntelligenceSource:
        if self.source_error is not None:
            raise self.source_error
        assert source_slug == ANOMALI_SOURCE_SLUG
        return self.source

    def persist(
        self,
        record: PublicationCandidate,
        *,
        observed_at: datetime,
    ) -> PublicationPersistenceResult:
        assert observed_at == NOW
        self.persist_calls.append(record)
        if self.error is not None:
            raise self.error
        identity = (record.source_external_id, record.canonical_url)
        if self.outcomes is None:
            outcome = "unchanged" if identity in self.seen else "created"
        else:
            outcome = self.outcomes.pop(0)
        self.seen.add(identity)
        source_record = self.source_records.pop(0) if self.source_records else None
        return PublicationPersistenceResult(
            source_external_id=record.source_external_id,
            outcome=outcome,
            message=None,
            source_record=source_record,
            intelligence_item_id=101,
        )


class TrackingPipelineFactory:
    def __init__(self, pipeline: FakePipeline) -> None:
        self.pipeline = pipeline
        self.calls = 0

    def __call__(self, session: object) -> FakePipeline:
        del session
        self.calls += 1
        return self.pipeline


def candidate(
    identifier: str = "publication-1",
    *,
    title: str = "Anomali Cyber Watch publication",
    url: str | None = None,
) -> PublicationCandidate:
    return PublicationCandidate(
        source_slug=ANOMALI_SOURCE_SLUG,
        source_external_id=f"{ANOMALI_SOURCE_SLUG}:{identifier}",
        canonical_title=title,
        canonical_url=url or f"https://www.anomali.com/blog/{identifier}",
        safe_source_payload={"authors": ("Anomali",)},
    )


def ingest(
    *,
    candidates: tuple[PublicationCandidate, ...] | list[PublicationCandidate] = (),
    failure_kinds: tuple[AnomaliFailureAuditKind, ...] = (),
    session: FakeSession | None = None,
    pipeline: FakePipeline | None = None,
    capped: bool = False,
):
    active_session = session or FakeSession()
    active_pipeline = pipeline or FakePipeline()
    result = AnomaliPublicationsIngestionService(
        active_session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: active_pipeline,  # type: ignore[arg-type]
    ).ingest(
        source_slug=ANOMALI_SOURCE_SLUG,
        candidates=candidates,
        failure_kinds=failure_kinds,
        records_fetched=len(candidates) + len(failure_kinds),
        capped=capped,
        trigger=AnomaliIngestionTrigger.LIVE,
        observed_at=NOW,
    )
    return result.run, active_session, active_pipeline


def invoke_service(
    service: AnomaliPublicationsIngestionService,
) -> AnomaliIngestionResult:
    return service.ingest(
        source_slug=ANOMALI_SOURCE_SLUG,
        candidates=(candidate(),),
        records_fetched=1,
        capped=False,
        trigger=AnomaliIngestionTrigger.LIVE,
        observed_at=NOW,
    )


def test_successful_creation_owns_source_and_commits_safe_run() -> None:
    record = candidate()

    run, session, pipeline = ingest(candidates=(record,))

    assert run.source.slug == ANOMALI_SOURCE_SLUG
    assert run.status == "succeeded"
    assert run.trigger_type == "manual"
    assert run.records_fetched == 1
    assert run.records_created == 1
    assert run.error_count == 0
    assert pipeline.persist_calls == [record]
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.nested_transactions == 1
    assert "Anomali" in (run.safe_summary or "")
    assert "capped=false" in (run.safe_summary or "")


def test_exactly_max_records_are_accepted_and_committed() -> None:
    records = tuple(candidate(f"accepted-{index}") for index in range(MAX_RECORDS))

    run, session, pipeline = ingest(candidates=records, capped=True)

    assert run.status == "succeeded"
    assert run.records_fetched == MAX_RECORDS
    assert run.records_created == MAX_RECORDS
    assert len(pipeline.persist_calls) == MAX_RECORDS
    assert session.nested_transactions == MAX_RECORDS
    assert session.commits == 1
    assert "capped=true" in (run.safe_summary or "")


@pytest.mark.parametrize(
    ("records", "failure_kinds"),
    [
        (
            tuple(candidate(f"oversized-{index}") for index in range(MAX_RECORDS + 1)),
            (),
        ),
        (
            (),
            (AnomaliFailureAuditKind.TIMEOUT,) * (MAX_RECORDS + 1),
        ),
        (
            tuple(candidate(f"mixed-{index}") for index in range(10)),
            (AnomaliFailureAuditKind.HTTP_FAILURE,) * 11,
        ),
    ],
    ids=["candidates", "failures", "mixed"],
)
def test_oversized_batch_is_rejected_before_pipeline_or_session_mutation(
    records: tuple[PublicationCandidate, ...],
    failure_kinds: tuple[AnomaliFailureAuditKind, ...],
) -> None:
    session = FakeSession()
    pipeline = FakePipeline()
    factory = TrackingPipelineFactory(pipeline)
    service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=factory,  # type: ignore[arg-type]
    )

    with pytest.raises(AnomaliIngestionInputError) as exc_info:
        service.ingest(
            source_slug=ANOMALI_SOURCE_SLUG,
            candidates=records,
            failure_kinds=failure_kinds,
            records_fetched=len(records) + len(failure_kinds),
            capped=False,
            trigger=AnomaliIngestionTrigger.LIVE,
            observed_at=NOW,
        )

    message = str(exc_info.value)
    assert factory.calls == 0
    assert pipeline.persist_calls == []
    assert session.added == []
    assert session.nested_transactions == 0
    assert session.commits == session.rollbacks == 0
    assert "oversized-20" not in message
    assert str(MAX_RECORDS + 1) not in message


@pytest.mark.parametrize("records_fetched", [True, False, -1, 21, "1", 1.0])
def test_invalid_fetched_count_is_rejected_without_mutation_or_raw_value(
    records_fetched: object,
) -> None:
    session = FakeSession()
    pipeline = FakePipeline()
    factory = TrackingPipelineFactory(pipeline)
    service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=factory,  # type: ignore[arg-type]
    )

    with pytest.raises(AnomaliIngestionInputError) as exc_info:
        service.ingest(
            source_slug=ANOMALI_SOURCE_SLUG,
            candidates=(),
            failure_kinds=(),
            records_fetched=records_fetched,  # type: ignore[arg-type]
            capped=False,
            trigger=AnomaliIngestionTrigger.LIVE,
            observed_at=NOW,
        )

    assert str(exc_info.value) == "The Anomali fetched count is invalid."
    assert repr(records_fetched) not in str(exc_info.value)
    assert factory.calls == 0
    assert session.added == []
    assert session.nested_transactions == 0
    assert session.commits == session.rollbacks == 0


@pytest.mark.parametrize("capped", [False, True])
def test_capped_state_is_preserved_in_result_and_safe_summary(capped: bool) -> None:
    session = FakeSession()
    service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: FakePipeline(),  # type: ignore[arg-type]
    )

    result = service.ingest(
        source_slug=ANOMALI_SOURCE_SLUG,
        candidates=(),
        records_fetched=0,
        capped=capped,
        trigger=AnomaliIngestionTrigger.LIVE,
        observed_at=NOW,
    )

    assert result.capped is capped
    assert f"capped={str(capped).lower()}" in (result.run.safe_summary or "")
    assert len(result.run.safe_summary or "") <= 1000
    assert session.commits == 1


@pytest.mark.parametrize("capped", [0, 1, "false", None])
def test_non_bool_capped_is_rejected_before_mutation(capped: object) -> None:
    session = FakeSession()
    pipeline = FakePipeline()
    factory = TrackingPipelineFactory(pipeline)
    service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=factory,  # type: ignore[arg-type]
    )

    with pytest.raises(AnomaliIngestionInputError) as exc_info:
        service.ingest(
            source_slug=ANOMALI_SOURCE_SLUG,
            candidates=(),
            records_fetched=0,
            capped=capped,  # type: ignore[arg-type]
            trigger=AnomaliIngestionTrigger.LIVE,
            observed_at=NOW,
        )

    assert str(exc_info.value) == "The Anomali capped state is invalid."
    assert repr(capped) not in str(exc_info.value)
    assert factory.calls == 0
    assert session.added == []
    assert session.nested_transactions == 0
    assert session.commits == session.rollbacks == 0


def test_repeated_candidate_delegates_deduplication_and_becomes_unchanged() -> None:
    record = candidate()
    pipeline = FakePipeline()

    first, first_session, _ = ingest(candidates=(record,), pipeline=pipeline)
    second, second_session, _ = ingest(candidates=(record,), pipeline=pipeline)

    assert first.records_created == 1
    assert second.records_unchanged == 1
    assert len(pipeline.seen) == 1
    assert first_session.commits == second_session.commits == 1


def test_approved_update_and_all_pipeline_outcomes_are_counted() -> None:
    records = tuple(candidate(str(index)) for index in range(5))
    pipeline = FakePipeline(
        outcomes=["created", "updated", "unchanged", "skipped", "failed"]
    )

    run, session, _ = ingest(candidates=records, pipeline=pipeline)

    assert run.status == "partial"
    assert (
        run.records_created,
        run.records_updated,
        run.records_unchanged,
        run.records_skipped,
        run.records_failed,
    ) == (1, 1, 1, 1, 1)
    assert run.error_count == 1
    assert session.commits == 1
    assert len([item for item in session.added if isinstance(item, IngestionError)]) == 1


def test_multiple_candidates_preserve_deterministic_input_order_and_snapshot() -> None:
    records = [candidate("first"), candidate("second"), candidate("third")]
    pipeline = FakePipeline()

    run, _, _ = ingest(candidates=records, pipeline=pipeline)
    records.reverse()

    assert run.records_created == 3
    assert [item.source_external_id for item in pipeline.persist_calls] == [
        f"{ANOMALI_SOURCE_SLUG}:first",
        f"{ANOMALI_SOURCE_SLUG}:second",
        f"{ANOMALI_SOURCE_SLUG}:third",
    ]


def test_identical_batch_duplicate_is_unlinked_unchanged_and_persisted_once() -> None:
    record = candidate()

    run, session, pipeline = ingest(candidates=(record, record))
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]

    assert run.status == "succeeded"
    assert run.records_created == 1
    assert run.records_unchanged == 1
    assert len(pipeline.persist_calls) == 1
    assert [audit.action for audit in audits] == ["created", "unchanged"]
    assert audits[1].source_record is None
    assert "duplicate" in (audits[1].safe_detail or "").lower()


def test_conflicting_batch_identity_is_safe_failure_and_later_record_continues() -> None:
    first = candidate("same", title="First title")
    conflict = candidate("same", title="SECRET conflicting title")
    later = candidate("later")

    run, session, pipeline = ingest(candidates=(first, conflict, later))
    persisted_text = " ".join(
        [
            *(item.safe_detail or "" for item in session.added if isinstance(item, IngestionRunRecord)),
            *(item.safe_message for item in session.added if isinstance(item, IngestionError)),
        ]
    )

    assert run.status == "partial"
    assert run.records_created == 2
    assert run.records_failed == 1
    assert pipeline.persist_calls == [first, later]
    assert "SECRET" not in persisted_text


def test_collector_failures_use_closed_static_audit_data_and_counts() -> None:
    kinds = tuple(collector_failure_audit_kind(reason) for reason in AnomaliFailureReason)

    run, session, pipeline = ingest(failure_kinds=kinds)
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    persisted_text = " ".join(
        [*(item.safe_message for item in errors), *((item.safe_detail or "") for item in audits)]
    )

    assert set(COLLECTOR_FAILURE_AUDIT_KINDS) == set(AnomaliFailureReason)
    assert run.status == "failed"
    assert run.records_fetched == len(AnomaliFailureReason)
    assert run.records_failed == len(AnomaliFailureReason)
    assert run.error_count == len(AnomaliFailureReason)
    assert len(errors) == len(audits) == len(AnomaliFailureReason)
    assert pipeline.persist_calls == []
    assert "http://" not in persisted_text
    assert "SECRET" not in persisted_text


def test_repeated_source_record_is_unlinked_to_protect_unique_audit_index() -> None:
    shared = SourceRecord(id=55)
    pipeline = FakePipeline(
        outcomes=["created", "updated"],
        source_records=[shared, shared],
    )

    run, session, _ = ingest(
        candidates=(candidate("first"), candidate("second")),
        pipeline=pipeline,
    )
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]

    assert run.records_created == 1
    assert run.records_updated == 1
    assert audits[0].source_record is shared
    assert audits[1].source_record is None
    assert audits[1].intelligence_item_id is None
    assert "earlier linked audit" in (audits[1].safe_detail or "")


@pytest.mark.parametrize("failure_point", ["persist", "audit", "flush", "commit"])
def test_database_failure_rolls_back_without_partial_commit_or_detail(
    failure_point: str,
) -> None:
    secret = f"SECRET postgresql://private/{failure_point}"
    session = FakeSession(
        audit_error=SQLAlchemyError(secret) if failure_point == "audit" else None,
        flush_error=SQLAlchemyError(secret) if failure_point == "flush" else None,
        commit_error=SQLAlchemyError(secret) if failure_point == "commit" else None,
    )
    pipeline = FakePipeline(
        error=(
            PublicationPersistenceError(secret)
            if failure_point == "persist"
            else None
        )
    )

    with pytest.raises(AnomaliIngestionDatabaseError) as exc_info:
        ingest(candidates=(candidate(),), session=session, pipeline=pipeline)

    assert session.commits == 0
    assert session.rollbacks == 1
    assert "SECRET" not in str(exc_info.value)
    assert "database operation" in str(exc_info.value)


def test_unexpected_failure_rolls_back_and_is_sanitized() -> None:
    session = FakeSession()
    pipeline = FakePipeline(error=RuntimeError("SECRET raw payload and SQL"))

    with pytest.raises(AnomaliIngestionError) as exc_info:
        ingest(candidates=(candidate(),), session=session, pipeline=pipeline)

    assert type(exc_info.value) is AnomaliIngestionError
    assert session.commits == 0
    assert session.rollbacks == 1
    assert "SECRET" not in str(exc_info.value)


@pytest.mark.parametrize(
    "error",
    [MemoryError("memory"), KeyboardInterrupt(), SystemExit(7), GeneratorExit()],
)
def test_system_exceptions_propagate_after_rollback(error: BaseException) -> None:
    session = FakeSession()
    pipeline = FakePipeline(error=error)

    with pytest.raises(type(error)) as exc_info:
        ingest(candidates=(candidate(),), session=session, pipeline=pipeline)

    assert exc_info.value is error
    assert session.commits == 0
    assert session.rollbacks == 1


@pytest.mark.parametrize(
    "primary",
    [MemoryError("primary"), KeyboardInterrupt(), SystemExit(7), GeneratorExit()],
)
def test_active_system_exception_is_not_replaced_by_rollback_failure(
    primary: BaseException,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _rollback_log_recorder(monkeypatch)
    session = FakeSession(rollback_error=RuntimeError("secondary secret"))

    with pytest.raises(type(primary)) as exc_info:
        ingest(
            candidates=(candidate(),),
            session=session,
            pipeline=FakePipeline(error=primary),
        )

    assert exc_info.value is primary
    assert session.commits == 0
    assert session.invalidations == 1
    _assert_single_sanitized_rollback_log(recorder)


@pytest.mark.parametrize(
    "rollback_error",
    [RuntimeError("rollback secret"), MemoryError("rollback memory secret")],
)
def test_ordinary_failure_plus_rollback_failure_is_sanitized_and_invalidated(
    rollback_error: BaseException,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _rollback_log_recorder(monkeypatch)
    primary_secret = "postgresql://user:password@host/database SELECT secret"
    session = FakeSession(rollback_error=rollback_error)

    with pytest.raises(AnomaliIngestionDatabaseError) as exc_info:
        ingest(
            candidates=(candidate(),),
            session=session,
            pipeline=FakePipeline(error=SQLAlchemyError(primary_secret)),
        )

    assert str(exc_info.value) == (
        "Manual Anomali ingestion failed during transaction cleanup."
    )
    assert session.commits == 0
    assert session.invalidations == 1
    _assert_single_sanitized_rollback_log(recorder)


@pytest.mark.parametrize(
    "primary",
    [
        MemoryError("primary-memory-canary"),
        KeyboardInterrupt(),
        SystemExit(7),
        GeneratorExit(),
    ],
)
def test_logger_and_invalidation_failures_cannot_replace_system_exception(
    primary: BaseException,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _rollback_log_recorder(
        monkeypatch, MemoryError("logger-failure-canary")
    )
    session = FakeSession(
        rollback_error=RuntimeError("rollback-failure-canary"),
        invalidation_error=SystemExit("invalidation-failure-canary"),
    )
    service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=TrackingPipelineFactory(FakePipeline(error=primary)),
    )

    with pytest.raises(type(primary)) as exc_info:
        invoke_service(service)

    assert exc_info.value is primary
    assert session.invalidations == 1
    assert session.commits == 0
    assert getattr(session, service_module._SESSION_POISON_ATTRIBUTE) is True
    _assert_single_sanitized_rollback_log(recorder)
    exposed = str(exc_info.value)
    assert "logger-failure-canary" not in exposed
    assert "invalidation-failure-canary" not in exposed
    assert "rollback-failure-canary" not in exposed


@pytest.mark.parametrize(
    "invalidation_error",
    [
        RuntimeError("invalidation-runtime-canary"),
        MemoryError("invalidation-memory-canary"),
        KeyboardInterrupt(),
        SystemExit("invalidation-system-exit-canary"),
        GeneratorExit(),
    ],
)
def test_cleanup_failures_poison_session_and_keep_ordinary_error_sanitized(
    invalidation_error: BaseException,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _rollback_log_recorder(
        monkeypatch, KeyboardInterrupt("logger-keyboard-canary")
    )
    session = FakeSession(
        rollback_error=MemoryError("rollback-memory-canary"),
        invalidation_error=invalidation_error,
    )
    service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=TrackingPipelineFactory(
            FakePipeline(
                error=SQLAlchemyError(
                    "postgresql://user:password@private/primary-sql-canary"
                )
            )
        ),
    )

    with pytest.raises(AnomaliIngestionDatabaseError) as exc_info:
        invoke_service(service)

    assert str(exc_info.value) == (
        "Manual Anomali ingestion failed during transaction cleanup."
    )
    assert session.invalidations == 1
    assert session.commits == 0
    assert getattr(session, service_module._SESSION_POISON_ATTRIBUTE) is True
    _assert_single_sanitized_rollback_log(recorder)
    exposed = str(exc_info.value)
    assert "password" not in exposed
    assert "logger-keyboard-canary" not in exposed
    assert "invalidation" not in exposed
    assert "rollback-memory-canary" not in exposed


def test_same_and_new_service_reject_poisoned_session_before_pipeline_activity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _rollback_log_recorder(monkeypatch)
    session = FakeSession(
        rollback_error=RuntimeError("rollback-secret"),
        invalidation_error=MemoryError("invalidation-secret"),
    )
    first_factory = TrackingPipelineFactory(
        FakePipeline(error=SQLAlchemyError("primary SQL and password"))
    )
    service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=first_factory,
    )

    with pytest.raises(AnomaliIngestionDatabaseError, match="transaction cleanup"):
        invoke_service(service)

    activity = (
        len(session.added),
        session.flushes,
        session.nested_transactions,
        session.rollbacks,
        session.invalidations,
    )
    first_factory.pipeline = FakePipeline()
    with pytest.raises(AnomaliIngestionDatabaseError, match="unsafe database session"):
        invoke_service(service)
    assert first_factory.calls == 1
    assert session.commits == 0
    assert (
        len(session.added),
        session.flushes,
        session.nested_transactions,
        session.rollbacks,
        session.invalidations,
    ) == activity

    new_factory = TrackingPipelineFactory(FakePipeline())
    new_service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=new_factory,
    )
    with pytest.raises(AnomaliIngestionDatabaseError, match="unsafe database session"):
        invoke_service(new_service)
    assert new_factory.calls == 0
    assert session.commits == 0


def test_successful_rollback_does_not_poison_session() -> None:
    session = FakeSession()
    failing_service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=TrackingPipelineFactory(
            FakePipeline(error=SQLAlchemyError("ordinary private database error"))
        ),
    )

    with pytest.raises(AnomaliIngestionDatabaseError, match="database operation"):
        invoke_service(failing_service)

    assert not hasattr(session, service_module._SESSION_POISON_ATTRIBUTE)
    result = invoke_service(
        AnomaliPublicationsIngestionService(
            session,  # type: ignore[arg-type]
            pipeline_factory=TrackingPipelineFactory(FakePipeline()),
        )
    )
    assert result.run.status == "succeeded"
    assert session.rollbacks == 1
    assert session.commits == 1


@pytest.mark.parametrize("invalidation_kind", ["absent", "not-callable"])
def test_missing_or_noncallable_invalidation_still_poison_session(
    invalidation_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RollbackOnlySession:
        def __init__(self) -> None:
            self.rollbacks = 0

        def rollback(self) -> None:
            self.rollbacks += 1
            raise RuntimeError("rollback-canary")

    session = RollbackOnlySession()
    if invalidation_kind == "not-callable":
        session.invalidate = object()  # type: ignore[attr-defined]
    recorder = _rollback_log_recorder(monkeypatch)

    def failing_pipeline_factory(_: object) -> FakePipeline:
        raise SQLAlchemyError("primary-password-canary")

    service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=failing_pipeline_factory,
    )
    with pytest.raises(AnomaliIngestionDatabaseError) as exc_info:
        invoke_service(service)

    assert str(exc_info.value) == (
        "Manual Anomali ingestion failed during transaction cleanup."
    )
    assert session.rollbacks == 1
    assert getattr(session, service_module._SESSION_POISON_ATTRIBUTE) is True
    _assert_single_sanitized_rollback_log(recorder)

    denied_factory = TrackingPipelineFactory(FakePipeline())
    denied_service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=denied_factory,
    )
    with pytest.raises(AnomaliIngestionDatabaseError, match="unsafe database session"):
        invoke_service(denied_service)
    assert denied_factory.calls == 0


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"source_slug": "not-anomali"}, "source"),
        ({"candidates": (candidate(),), "records_fetched": 0}, "fetched"),
        ({"candidates": "raw"}, "candidate"),
        ({"failure_kinds": ("raw",)}, "failure"),
        ({"trigger": "live"}, "trigger"),
    ],
)
def test_closed_input_interface_rejects_before_session_mutation(
    arguments: dict[str, object],
    message: str,
) -> None:
    session = FakeSession()
    factory_called = False

    def pipeline_factory(_: object):
        nonlocal factory_called
        factory_called = True
        return FakePipeline()

    service = AnomaliPublicationsIngestionService(
        session,  # type: ignore[arg-type]
        pipeline_factory=pipeline_factory,  # type: ignore[arg-type]
    )
    values: dict[str, object] = {
        "source_slug": ANOMALI_SOURCE_SLUG,
        "candidates": (),
        "failure_kinds": (),
        "records_fetched": 0,
        "capped": False,
        "trigger": AnomaliIngestionTrigger.LIVE,
        "observed_at": NOW,
    }
    values.update(arguments)

    with pytest.raises(AnomaliIngestionInputError) as exc_info:
        service.ingest(**values)  # type: ignore[arg-type]

    assert message in str(exc_info.value).lower()
    assert factory_called is False
    assert session.added == []
    assert session.commits == session.rollbacks == 0


def test_invalid_collector_reason_is_rejected_without_raw_representation() -> None:
    secret = SimpleNamespace(value="SECRET raw reason")

    with pytest.raises(AnomaliIngestionInputError) as exc_info:
        collector_failure_audit_kind(secret)  # type: ignore[arg-type]

    assert "SECRET" not in str(exc_info.value)
