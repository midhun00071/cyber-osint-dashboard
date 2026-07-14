from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from io import StringIO
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError

from app.ingestion import censys_publications_cli
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
    assert len([item for item in session.added if isinstance(item, IngestionError)]) == 1
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
    assert len(pipeline.persist_calls) == 2
    assert len(pipeline.intelligence_item_ids) == 1
    assert session.nested_transactions == 2
    assert session.commits == 1
    assert session.rollbacks == 0
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
