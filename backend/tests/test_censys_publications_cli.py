from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from io import StringIO
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion import censys_publications_cli
from app.ingestion.collectors import censys_publications_client
from app.ingestion.adapters.censys_publications import (
    CENSYS_ARC_RESEARCH_SLUG,
    CensysPublicationDocument,
    CensysPublicationRecordError,
)
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPersistenceResult,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord, IntelligenceSource


NOW = datetime(2026, 7, 14, 8, 0, tzinfo=UTC)


class FakeSession:
    def __init__(self, *, fail_commit: bool = False) -> None:
        self.fail_commit = fail_commit
        self.added: list[object] = []
        self.commits = 0
        self.rollbacks = 0
        self.flushes = 0
        self.closed = False
        self.nested_transactions = 0

    def add(self, record: object) -> None:
        self.added.append(record)

    def flush(self) -> None:
        self.flushes += 1
        for record in self.added:
            if isinstance(record, IngestionRun) and getattr(record, "id", None) is None:
                record.id = 1
                record.public_id = uuid4()

    def begin_nested(self):
        self.nested_transactions += 1
        return nullcontext()

    def commit(self) -> None:
        if self.fail_commit:
            raise SQLAlchemyError("postgresql://private:password@host/database")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class FakePipeline:
    def __init__(
        self,
        session: FakeSession,
        *,
        outcomes: list[str] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.session = session
        self.outcomes = list(outcomes) if outcomes is not None else None
        self.error = error
        self.persist_calls: list[PublicationCandidate] = []
        self.intelligence_item_ids: set[str] = set()
        self.source = IntelligenceSource(
            slug=CENSYS_ARC_RESEARCH_SLUG,
            name="Censys ARC Research",
            source_type="json",
            base_url="https://censys.com/blog/",
            is_enabled=True,
            checkpoint_value="existing-checkpoint",
            last_successful_fetch_at=datetime(2026, 7, 13, 8, 0, tzinfo=UTC),
        )

    def ensure_source(self, source_slug: str) -> IntelligenceSource:
        assert source_slug == CENSYS_ARC_RESEARCH_SLUG
        return self.source

    def persist(self, candidate: PublicationCandidate, *, observed_at: datetime):
        assert observed_at == NOW
        self.persist_calls.append(candidate)
        if self.error is not None:
            raise self.error
        if self.outcomes is None:
            outcome = (
                "unchanged"
                if candidate.source_external_id in self.intelligence_item_ids
                else "created"
            )
        else:
            outcome = self.outcomes.pop(0)
        if outcome in {"created", "updated", "unchanged"}:
            self.intelligence_item_ids.add(candidate.source_external_id)
        return PublicationPersistenceResult(
            candidate.source_external_id,
            outcome,
            None,
            None,
            123,
        )


def candidate(identifier: str) -> PublicationCandidate:
    return PublicationCandidate(
        source_slug=CENSYS_ARC_RESEARCH_SLUG,
        source_external_id=identifier,
        canonical_title="Censys publication",
        canonical_url=f"https://censys.com/blog/{identifier}/",
    )


def run_fake(
    *,
    records: tuple[object, ...] = ("valid",),
    session: FakeSession | None = None,
    outcomes: list[str] | None = None,
    pipeline_error: Exception | None = None,
):
    fake_session = session or FakeSession()
    pipeline = FakePipeline(
        fake_session,
        outcomes=outcomes,
        error=pipeline_error,
    )
    stdout = StringIO()
    stderr = StringIO()

    def adapter(source_slug: str, record: object) -> PublicationCandidate:
        assert source_slug == CENSYS_ARC_RESEARCH_SLUG
        if record == "invalid":
            raise CensysPublicationRecordError("local secret and path")
        return candidate(str(record))

    exit_code = censys_publications_cli.run_import(
        file_path="not-read.json",
        clock=lambda: NOW,
        loader=lambda _: CensysPublicationDocument(
            CENSYS_ARC_RESEARCH_SLUG,
            records,
        ),
        adapter=adapter,
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), fake_session, pipeline


def test_successful_import_creates_audit_and_commits_once() -> None:
    exit_code, stdout, stderr, session, pipeline = run_fake()
    run = next(item for item in session.added if isinstance(item, IngestionRun))

    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 1
    assert run.records_created == 1
    assert run.error_count == 0
    assert run.checkpoint_before == "existing-checkpoint"
    assert run.checkpoint_after is None
    assert run.source.checkpoint_value == "existing-checkpoint"
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed is True
    assert session.nested_transactions == 1
    assert len(pipeline.persist_calls) == 1
    assert "Created: 1" in stdout
    assert stderr == ""


def test_mixed_batch_audits_failure_and_processes_later_record() -> None:
    exit_code, stdout, stderr, session, pipeline = run_fake(
        records=("first", "invalid", "later"),
        outcomes=["created", "unchanged"],
    )
    run = next(item for item in session.added if isinstance(item, IngestionRun))

    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 3
    assert run.records_created == 1
    assert run.records_unchanged == 1
    assert run.records_failed == 1
    assert run.error_count == 1
    assert len(pipeline.persist_calls) == 2
    assert pipeline.persist_calls[-1].source_external_id == "later"
    assert session.commits == 1
    assert session.rollbacks == 0
    assert len([item for item in session.added if isinstance(item, IngestionRunRecord)]) == 3
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert len(errors) == 1
    assert errors[0].error_type == "censys_publication_validation_error"
    assert "Status: partial" in stdout
    assert "local secret" not in stderr


def test_identical_file_duplicate_is_created_then_audited_as_unchanged() -> None:
    exit_code, stdout, stderr, session, pipeline = run_fake(records=("same", "same"))
    run = next(item for item in session.added if isinstance(item, IngestionRun))
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]

    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_updated == 0
    assert run.records_unchanged == 1
    assert run.records_skipped == 0
    assert run.records_failed == 0
    assert [audit.action for audit in audits] == ["created", "unchanged"]
    assert len(pipeline.persist_calls) == 1
    assert len(pipeline.intelligence_item_ids) == 1
    assert session.nested_transactions == 1
    assert session.commits == 1
    assert session.rollbacks == 0
    duplicate_audit = audits[1]
    assert duplicate_audit.source_record is None
    assert duplicate_audit.intelligence_item_id is None
    assert duplicate_audit.safe_detail == (
        "A duplicate Censys publication matched an earlier batch entry."
    )
    assert "https://" not in duplicate_audit.safe_detail
    assert "same" not in duplicate_audit.safe_detail
    assert not [item for item in session.added if isinstance(item, IngestionError)]
    assert "Unchanged: 1" in stdout
    assert stderr == ""


def test_conflicting_file_duplicate_is_a_controlled_failure() -> None:
    fake_session = FakeSession()
    pipeline = FakePipeline(fake_session, outcomes=["created"])
    stdout = StringIO()
    stderr = StringIO()

    def conflicting_adapter(
        source_slug: str,
        record: object,
    ) -> PublicationCandidate:
        del source_slug
        return PublicationCandidate(
            source_slug=CENSYS_ARC_RESEARCH_SLUG,
            source_external_id="same-identity",
            canonical_title=str(record),
            canonical_url="https://censys.com/blog/same/",
        )

    exit_code = censys_publications_cli.run_import(
        file_path="not-read.json",
        clock=lambda: NOW,
        loader=lambda _: CensysPublicationDocument(
            CENSYS_ARC_RESEARCH_SLUG,
            ("first", "conflict"),
        ),
        adapter=conflicting_adapter,
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    run = next(item for item in fake_session.added if isinstance(item, IngestionRun))

    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_unchanged == 0
    assert run.records_failed == 1
    assert len(pipeline.persist_calls) == 1
    assert len(pipeline.intelligence_item_ids) == 1
    assert len(
        [item for item in fake_session.added if isinstance(item, IngestionRunRecord)]
    ) == 2
    assert fake_session.commits == 1
    assert "conflict" not in stderr.getvalue()


def test_pipeline_failure_outcome_is_audited() -> None:
    exit_code, _, _, session, _ = run_fake(outcomes=["failed"])
    run = next(item for item in session.added if isinstance(item, IngestionRun))

    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_failed == 1
    assert len([item for item in session.added if isinstance(item, IngestionError)]) == 1
    assert session.commits == 1


def test_database_error_rolls_back_entire_run_without_disclosure() -> None:
    secret = "postgresql://private:password@host/database"
    exit_code, stdout, stderr, session, _ = run_fake(
        records=("first", "second"),
        pipeline_error=SQLAlchemyError(secret),
    )

    assert exit_code == 1
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed is True
    assert stdout == ""
    assert secret not in stderr
    assert "database operation" in stderr


def test_commit_error_rolls_back_entire_run_without_disclosure() -> None:
    session = FakeSession(fail_commit=True)
    exit_code, _, stderr, session, _ = run_fake(session=session)

    assert exit_code == 1
    assert session.commits == 0
    assert session.rollbacks == 1
    assert "private" not in stderr


def test_http_file_is_rejected_before_database_session() -> None:
    stderr = StringIO()

    exit_code = censys_publications_cli.run_import(
        file_path="https://censys.com/publications.json",
        clock=lambda: (_ for _ in ()).throw(AssertionError("clock must not run")),
        session_factory=lambda: (_ for _ in ()).throw(
            AssertionError("session must not open")
        ),
        stderr=stderr,
    )

    assert exit_code == 2
    assert "https://" not in stderr.getvalue()
    assert "rejected safely" in stderr.getvalue()


def test_cli_arguments_are_deterministic(monkeypatch, capsys) -> None:
    monkeypatch.setattr(censys_publications_cli, "run_import", lambda **_: 0)

    assert censys_publications_cli.main(["--file", "input.json"]) == 0
    assert censys_publications_cli.main([]) == 2
    assert "Invalid manual Censys import arguments." in capsys.readouterr().err


def test_local_file_cli_delegates_to_shared_service_without_live_collector(
    monkeypatch,
) -> None:
    collector_created = False
    service_calls: list[dict[str, object]] = []
    session = FakeSession()
    pipeline = FakePipeline(session)
    stdout = StringIO()

    def forbidden_collector(*args, **kwargs):
        del args, kwargs
        nonlocal collector_created
        collector_created = True
        raise AssertionError("local import must not instantiate the live collector")

    class CapturingService:
        def __init__(self, created_session, *, pipeline_factory) -> None:
            assert created_session is session
            assert pipeline_factory(session) is pipeline

        def ingest(self, **kwargs):
            service_calls.append(kwargs)
            run = IngestionRun(
                public_id=uuid4(),
                source_id=1,
                trigger_type="manual",
                status="succeeded",
                started_at=NOW,
                completed_at=NOW,
                records_fetched=1,
                records_created=1,
                records_updated=0,
                records_unchanged=0,
                records_skipped=0,
                records_failed=0,
                error_count=0,
                checkpoint_before=None,
                checkpoint_after=None,
                safe_summary="Safe local test run.",
                created_at=NOW,
            )
            return type("Result", (), {"run": run})()

    monkeypatch.setattr(
        censys_publications_client,
        "CensysPublicationsClient",
        forbidden_collector,
    )

    exit_code = censys_publications_cli.run_import(
        file_path="not-read.json",
        clock=lambda: NOW,
        loader=lambda _: CensysPublicationDocument(
            CENSYS_ARC_RESEARCH_SLUG,
            ("valid",),
        ),
        adapter=lambda source_slug, _: candidate(source_slug),
        session_factory=lambda: session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        service_factory=CapturingService,  # type: ignore[arg-type]
        stdout=stdout,
    )

    assert exit_code == 0
    assert collector_created is False
    assert len(service_calls) == 1
    assert service_calls[0]["source_slug"] == CENSYS_ARC_RESEARCH_SLUG
    assert service_calls[0]["candidates"] == (candidate(CENSYS_ARC_RESEARCH_SLUG),)
    assert session.closed is True


def test_unexpected_loader_failure_is_sanitized_before_session_creation() -> None:
    secret = "C:\\private\\catalogue.json token=secret"
    stderr = StringIO()
    session_requested = False

    def session_factory():
        nonlocal session_requested
        session_requested = True
        raise AssertionError("session must not be requested")

    exit_code = censys_publications_cli.run_import(
        file_path="not-read.json",
        loader=lambda _: (_ for _ in ()).throw(RuntimeError(secret)),
        session_factory=session_factory,
        stderr=stderr,
    )

    assert exit_code == 1
    assert session_requested is False
    assert stderr.getvalue() == "Manual Censys local-file import failed safely.\n"
    assert secret not in stderr.getvalue()


@pytest.mark.parametrize(
    "clock",
    [
        lambda: (_ for _ in ()).throw(RuntimeError("private clock detail")),
        lambda: "2026-07-17T08:00:00Z",
        lambda: datetime(2026, 7, 17, 8, 0),
    ],
)
def test_invalid_or_failing_clock_is_sanitized_before_session_creation(
    clock,
) -> None:
    stderr = StringIO()
    session_requested = False

    def session_factory():
        nonlocal session_requested
        session_requested = True
        raise AssertionError("session must not be requested")

    exit_code = censys_publications_cli.run_import(
        file_path="not-read.json",
        loader=lambda _: CensysPublicationDocument(
            CENSYS_ARC_RESEARCH_SLUG,
            (),
        ),
        clock=clock,
        session_factory=session_factory,
        stderr=stderr,
    )

    assert exit_code == 1
    assert session_requested is False
    assert stderr.getvalue() == (
        "Manual Censys import requires a timezone-aware clock.\n"
    )
    assert "private" not in stderr.getvalue()


def test_unexpected_adapter_failure_is_sanitized_before_session_creation() -> None:
    secret = "private record payload https://private.example/"
    stderr = StringIO()
    session_requested = False

    def session_factory():
        nonlocal session_requested
        session_requested = True
        raise AssertionError("session must not be requested")

    exit_code = censys_publications_cli.run_import(
        file_path="not-read.json",
        loader=lambda _: CensysPublicationDocument(
            CENSYS_ARC_RESEARCH_SLUG,
            ("private-record",),
        ),
        adapter=lambda *_: (_ for _ in ()).throw(RuntimeError(secret)),
        session_factory=session_factory,
        clock=lambda: NOW,
        stderr=stderr,
    )

    assert exit_code == 1
    assert session_requested is False
    assert stderr.getvalue() == "Manual Censys import failed unexpectedly.\n"
    assert secret not in stderr.getvalue()


def test_local_session_close_failure_is_sanitized_without_false_rollback() -> None:
    secret = "postgresql://private:password@host/database"

    class CloseFailSession(FakeSession):
        def close(self) -> None:
            self.closed = True
            raise RuntimeError(secret)

    session = CloseFailSession()
    exit_code, stdout, stderr, session, _ = run_fake(session=session)

    assert exit_code == 1
    assert session.closed is True
    assert session.commits == 1
    assert session.rollbacks == 0
    assert stdout == ""
    assert stderr == "Manual Censys import failed during a database operation.\n"
    assert secret not in stderr


@pytest.mark.parametrize("failure_point", ["loader", "clock", "adapter", "close"])
def test_local_memory_error_propagates(failure_point: str) -> None:
    memory_error = MemoryError(f"private {failure_point}")
    session = FakeSession()
    loader = lambda _: CensysPublicationDocument(  # noqa: E731
        CENSYS_ARC_RESEARCH_SLUG,
        ("valid",),
    )
    clock = lambda: NOW  # noqa: E731
    adapter = lambda source_slug, _: candidate(source_slug)  # noqa: E731

    if failure_point == "loader":
        loader = lambda _: (_ for _ in ()).throw(memory_error)
    elif failure_point == "clock":
        clock = lambda: (_ for _ in ()).throw(memory_error)
    elif failure_point == "adapter":
        adapter = lambda *_: (_ for _ in ()).throw(memory_error)
    else:
        session.close = (  # type: ignore[method-assign]
            lambda: (_ for _ in ()).throw(memory_error)
        )

    with pytest.raises(MemoryError) as exc_info:
        censys_publications_cli.run_import(
            file_path="not-read.json",
            loader=loader,
            clock=clock,
            adapter=adapter,
            session_factory=lambda: session,  # type: ignore[arg-type]
            pipeline_factory=lambda _: FakePipeline(session),  # type: ignore[arg-type]
            stderr=StringIO(),
        )

    assert exc_info.value is memory_error


@pytest.mark.parametrize("failure_point", ["session_factory", "service_factory"])
def test_local_session_and_service_creation_memory_error_propagates(
    failure_point: str,
) -> None:
    memory_error = MemoryError(f"private {failure_point}")
    session = FakeSession()

    def session_factory():
        if failure_point == "session_factory":
            raise memory_error
        return session

    def service_factory(*args, **kwargs):
        del args, kwargs
        raise memory_error

    with pytest.raises(MemoryError) as exc_info:
        censys_publications_cli.run_import(
            file_path="not-read.json",
            loader=lambda _: CensysPublicationDocument(
                CENSYS_ARC_RESEARCH_SLUG,
                (),
            ),
            clock=lambda: NOW,
            session_factory=session_factory,
            service_factory=service_factory,
            stderr=StringIO(),
        )

    assert exc_info.value is memory_error


def test_local_cleanup_does_not_replace_active_memory_error() -> None:
    primary_error = MemoryError("primary private service marker")

    class CleanupFailSession(FakeSession):
        def close(self) -> None:
            raise RuntimeError("secondary private cleanup marker")

    session = CleanupFailSession()

    with pytest.raises(MemoryError) as exc_info:
        censys_publications_cli.run_import(
            file_path="not-read.json",
            loader=lambda _: CensysPublicationDocument(
                CENSYS_ARC_RESEARCH_SLUG,
                (),
            ),
            clock=lambda: NOW,
            session_factory=lambda: session,  # type: ignore[arg-type]
            service_factory=lambda *args, **kwargs: (_ for _ in ()).throw(
                primary_error
            ),
            stderr=StringIO(),
        )

    assert exc_info.value is primary_error
