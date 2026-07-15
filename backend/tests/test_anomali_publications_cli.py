from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from io import StringIO
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion import anomali_publications_cli
from app.ingestion.adapters.anomali_publications import (
    ANOMALI_SOURCE_SLUG,
    AnomaliPublicationDocument,
    AnomaliPublicationFileError,
    AnomaliPublicationRecordError,
)
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPersistenceError,
    PublicationPersistenceResult,
)
from app.models import (
    IngestionError,
    IngestionRun,
    IngestionRunRecord,
    IntelligenceSource,
    SourceRecord,
)


NOW = datetime(2026, 7, 15, 10, 0, tzinfo=UTC)


class FakeSession:
    def __init__(
        self,
        *,
        fail_commit: bool = False,
        fail_nested: bool = False,
        fail_rollback: bool = False,
        fail_close: bool = False,
    ) -> None:
        self.fail_commit = fail_commit
        self.fail_nested = fail_nested
        self.fail_rollback = fail_rollback
        self.fail_close = fail_close
        self.added: list[object] = []
        self.commits = 0
        self.rollbacks = 0
        self.flushes = 0
        self.closed = False
        self.close_attempts = 0
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
        if self.fail_nested:
            raise SQLAlchemyError("private nested transaction detail")
        return nullcontext()

    def commit(self) -> None:
        if self.fail_commit:
            raise SQLAlchemyError("postgresql://private:password@host/database")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1
        if self.fail_rollback:
            raise RuntimeError("SECRET ROLLBACK database URL and SQL")

    def close(self) -> None:
        self.close_attempts += 1
        if self.fail_close:
            raise RuntimeError("SECRET CLOSE credentials and local path")
        self.closed = True


class FakePipeline:
    def __init__(
        self,
        session: FakeSession,
        *,
        outcomes: list[str] | None = None,
        error: Exception | None = None,
        source_record: SourceRecord | None = None,
    ) -> None:
        self.session = session
        self.outcomes = list(outcomes) if outcomes is not None else None
        self.error = error
        self.source_record = source_record
        self.persist_calls: list[PublicationCandidate] = []
        self.source = IntelligenceSource(
            slug=ANOMALI_SOURCE_SLUG,
            name="Anomali Cyber Watch",
            source_type="json",
            base_url="https://www.anomali.com/blog/",
            is_enabled=True,
            checkpoint_value="existing-checkpoint",
        )

    def ensure_source(self, source_slug: str) -> IntelligenceSource:
        assert source_slug == ANOMALI_SOURCE_SLUG
        return self.source

    def persist(self, candidate: PublicationCandidate, *, observed_at: datetime):
        assert observed_at == NOW
        self.persist_calls.append(candidate)
        if self.error is not None:
            raise self.error
        outcome = self.outcomes.pop(0) if self.outcomes is not None else "created"
        return PublicationPersistenceResult(
            candidate.source_external_id,
            outcome,
            None,
            self.source_record,
            321,
        )


def candidate(identifier: str, *, title: str | None = None) -> PublicationCandidate:
    return PublicationCandidate(
        source_slug=ANOMALI_SOURCE_SLUG,
        source_external_id=identifier,
        canonical_title=title or f"Anomali Cyber Watch: {identifier}",
        canonical_url=f"https://www.anomali.com/blog/anomali-cyber-watch-{identifier}",
    )


def run_fake(
    *,
    records: tuple[object, ...] = ("valid",),
    session: FakeSession | None = None,
    outcomes: list[str] | None = None,
    pipeline_error: Exception | None = None,
    source_record: SourceRecord | None = None,
):
    fake_session = session or FakeSession()
    pipeline = FakePipeline(
        fake_session,
        outcomes=outcomes,
        error=pipeline_error,
        source_record=source_record,
    )
    stdout = StringIO()
    stderr = StringIO()

    def adapter(record: object) -> PublicationCandidate:
        if record == "invalid":
            raise AnomaliPublicationRecordError(
                "private title URL IOC and local path detail"
            )
        return candidate(str(record))

    exit_code = anomali_publications_cli.run_import(
        file_path="not-read.json",
        clock=lambda: NOW,
        loader=lambda _: AnomaliPublicationDocument(ANOMALI_SOURCE_SLUG, records),
        adapter=adapter,
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), fake_session, pipeline


def get_run(session: FakeSession) -> IngestionRun:
    return next(item for item in session.added if isinstance(item, IngestionRun))


def test_successful_created_import_has_one_commit_and_safe_audit() -> None:
    exit_code, stdout, stderr, session, pipeline = run_fake(outcomes=["created"])
    run = get_run(session)
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]

    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 1
    assert run.records_created == 1
    assert run.records_updated == 0
    assert run.records_unchanged == 0
    assert run.records_skipped == 0
    assert run.records_failed == 0
    assert run.error_count == 0
    assert run.checkpoint_before == "existing-checkpoint"
    assert run.checkpoint_after is None
    assert audits[0].action == "created"
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed is True
    assert session.nested_transactions == 1
    assert len(pipeline.persist_calls) == 1
    assert "Created: 1" in stdout
    assert stderr == ""


@pytest.mark.parametrize("outcome", ["updated", "unchanged"])
def test_successful_update_and_unchanged_outcomes(outcome: str) -> None:
    exit_code, _, stderr, session, _ = run_fake(outcomes=[outcome])
    run = get_run(session)

    assert exit_code == 0
    assert run.status == "succeeded"
    assert getattr(run, f"records_{outcome}") == 1
    assert session.commits == 1
    assert stderr == ""


def test_mixed_create_update_and_unchanged_accounting() -> None:
    exit_code, _, stderr, session, pipeline = run_fake(
        records=("one", "two", "three"),
        outcomes=["created", "updated", "unchanged"],
    )
    run = get_run(session)

    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 3
    assert run.records_created == 1
    assert run.records_updated == 1
    assert run.records_unchanged == 1
    assert len(pipeline.persist_calls) == 3
    assert session.commits == 1
    assert stderr == ""


def test_identical_duplicate_uses_no_second_non_null_source_record_audit() -> None:
    shared_source_record = SourceRecord()
    exit_code, stdout, stderr, session, pipeline = run_fake(
        records=("same", "same"),
        outcomes=["created"],
        source_record=shared_source_record,
    )
    run = get_run(session)
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]

    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_unchanged == 1
    assert run.records_failed == 0
    assert len(pipeline.persist_calls) == 1
    assert session.nested_transactions == 1
    assert len(audits) == 2
    assert audits[0].source_record is shared_source_record
    assert audits[1].source_record is None
    assert audits[1].intelligence_item_id == 321
    assert [audit.action for audit in audits] == ["created", "unchanged"]
    assert session.commits == 1
    assert "Unchanged: 1" in stdout
    assert stderr == ""


def test_failed_identical_duplicate_repeats_sanitized_failed_accounting() -> None:
    shared_source_record = SourceRecord()
    exit_code, stdout, stderr, session, pipeline = run_fake(
        records=("private-record-secret", "private-record-secret"),
        outcomes=["failed"],
        source_record=shared_source_record,
    )
    run = get_run(session)
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    errors = [item for item in session.added if isinstance(item, IngestionError)]

    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_fetched == 2
    assert run.records_created == 0
    assert run.records_unchanged == 0
    assert run.records_failed == 2
    assert len(pipeline.persist_calls) == 1
    assert session.nested_transactions == 1
    assert [audit.action for audit in audits] == ["failed", "failed"]
    assert audits[0].source_record is shared_source_record
    assert audits[1].source_record is None
    assert audits[1].intelligence_item_id is None
    assert len(errors) == 2
    assert errors[0].source_record is shared_source_record
    assert errors[1].source_record is None
    assert errors[1].error_type == "anomali_publication_duplicate_persistence_error"
    persistent_text = " ".join(
        [
            *(audit.safe_detail or "" for audit in audits),
            *(error.safe_message for error in errors),
        ]
    )
    assert "private-record-secret" not in persistent_text
    assert "Unchanged: 0" in stdout
    assert "controlled failure" in stderr


def test_skipped_identical_duplicate_repeats_controlled_skipped_accounting() -> None:
    shared_source_record = SourceRecord()
    exit_code, stdout, stderr, session, pipeline = run_fake(
        records=("same", "same"),
        outcomes=["skipped"],
        source_record=shared_source_record,
    )
    run = get_run(session)
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]

    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 2
    assert run.records_skipped == 2
    assert run.records_unchanged == 0
    assert run.records_failed == 0
    assert len(pipeline.persist_calls) == 1
    assert session.nested_transactions == 1
    assert [audit.action for audit in audits] == ["skipped", "skipped"]
    assert audits[0].source_record is shared_source_record
    assert audits[1].source_record is None
    assert audits[1].intelligence_item_id is None
    assert "Skipped: 2" in stdout
    assert "controlled failure" in stderr


def test_unsupported_duplicate_outcome_fails_closed_with_valid_audit_action() -> None:
    session = FakeSession()
    source = IntelligenceSource(checkpoint_value=None)
    run = anomali_publications_cli._create_run(session, source, NOW)
    unsupported_result = SimpleNamespace(
        outcome="private-unsupported-outcome",
        intelligence_item_id=999,
        source_record=SourceRecord(),
    )

    anomali_publications_cli._record_identical_duplicate(
        session,
        run,
        unsupported_result,  # type: ignore[arg-type]
        NOW,
    )

    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert run.records_failed == 1
    assert run.records_unchanged == 0
    assert len(audits) == 1
    assert audits[0].action == "failed"
    assert audits[0].source_record is None
    assert audits[0].intelligence_item_id is None
    assert len(errors) == 1
    assert errors[0].source_record is None
    assert "private-unsupported-outcome" not in (
        (audits[0].safe_detail or "") + errors[0].safe_message
    )


def test_conflicting_duplicate_is_sanitized_and_pipeline_runs_once() -> None:
    fake_session = FakeSession()
    pipeline = FakePipeline(fake_session, outcomes=["created"])
    stdout = StringIO()
    stderr = StringIO()

    def conflicting(record: object) -> PublicationCandidate:
        return candidate("same", title=f"Anomali Cyber Watch: {record}")

    exit_code = anomali_publications_cli.run_import(
        file_path="private-catalogue.json",
        clock=lambda: NOW,
        loader=lambda _: AnomaliPublicationDocument(
            ANOMALI_SOURCE_SLUG,
            ("first private title", "second private title"),
        ),
        adapter=conflicting,
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    run = get_run(fake_session)
    audits = [item for item in fake_session.added if isinstance(item, IngestionRunRecord)]
    errors = [item for item in fake_session.added if isinstance(item, IngestionError)]

    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_failed == 1
    assert len(pipeline.persist_calls) == 1
    assert audits[1].source_record is None
    assert errors[0].source_record is None
    assert errors[0].error_type == "anomali_publication_duplicate_conflict"
    combined = stdout.getvalue() + stderr.getvalue() + str(audits[1].safe_detail)
    assert "first private title" not in combined
    assert "second private title" not in combined
    assert "private-catalogue" not in combined
    assert fake_session.commits == 1


@pytest.mark.parametrize(
    "records",
    [("invalid", "valid"), ("valid", "invalid")],
)
def test_invalid_and_valid_records_produce_partial_committed_run(
    records: tuple[object, ...],
) -> None:
    exit_code, stdout, stderr, session, pipeline = run_fake(
        records=records,
        outcomes=["created"],
    )
    run = get_run(session)
    errors = [item for item in session.added if isinstance(item, IngestionError)]

    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_failed == 1
    assert run.error_count == 1
    assert len(pipeline.persist_calls) == 1
    assert len(errors) == 1
    assert errors[0].error_type == "anomali_publication_validation_error"
    assert session.commits == 1
    assert session.rollbacks == 0
    combined = stdout + stderr + str(errors[0].safe_message)
    assert "private title" not in combined
    assert "IOC" not in combined


def test_all_invalid_file_has_failed_status_and_commits_audit_evidence() -> None:
    exit_code, _, stderr, session, pipeline = run_fake(
        records=("invalid", "invalid"),
    )
    run = get_run(session)

    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_fetched == 2
    assert run.records_failed == 2
    assert run.error_count == 2
    assert len(pipeline.persist_calls) == 0
    assert session.commits == 1
    assert session.rollbacks == 0
    assert "controlled failure" in stderr


def test_empty_valid_catalogue_succeeds_with_zero_counts_and_one_commit() -> None:
    exit_code, stdout, stderr, session, pipeline = run_fake(records=())
    run = get_run(session)

    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 0
    assert run.records_created == 0
    assert run.records_updated == 0
    assert run.records_unchanged == 0
    assert run.records_skipped == 0
    assert run.records_failed == 0
    assert len(pipeline.persist_calls) == 0
    assert session.commits == 1
    assert "Fetched: 0" in stdout
    assert stderr == ""


def test_pipeline_failed_result_is_audited_without_raw_detail() -> None:
    shared_source_record = SourceRecord()
    exit_code, stdout, stderr, session, _ = run_fake(
        outcomes=["failed"],
        source_record=shared_source_record,
    )
    run = get_run(session)
    errors = [item for item in session.added if isinstance(item, IngestionError)]

    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_failed == 1
    assert errors[0].source_record is shared_source_record
    assert errors[0].error_type == "anomali_publication_persistence_error"
    assert session.commits == 1
    assert "controlled failure" in stderr
    assert "private" not in stdout + stderr


@pytest.mark.parametrize(
    "error",
    [
        PublicationPersistenceError("postgresql://private/database"),
        SQLAlchemyError("private SQL statement"),
    ],
)
def test_database_failure_rolls_back_without_disclosure(error: Exception) -> None:
    exit_code, stdout, stderr, session, _ = run_fake(
        records=("one", "two"),
        pipeline_error=error,
    )

    assert exit_code == 1
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed is True
    assert stdout == ""
    assert "private" not in stderr
    assert "database operation" in stderr


def test_nested_transaction_and_final_commit_failures_roll_back() -> None:
    nested_session = FakeSession(fail_nested=True)
    exit_code, _, stderr, nested_session, _ = run_fake(session=nested_session)
    assert exit_code == 1
    assert nested_session.commits == 0
    assert nested_session.rollbacks == 1
    assert nested_session.closed is True
    assert "private" not in stderr

    commit_session = FakeSession(fail_commit=True)
    exit_code, _, stderr, commit_session, _ = run_fake(session=commit_session)
    assert exit_code == 1
    assert commit_session.commits == 0
    assert commit_session.rollbacks == 1
    assert commit_session.closed is True
    assert "private" not in stderr


@pytest.mark.parametrize(
    "error",
    [
        PublicationPersistenceError("SECRET PERSISTENCE database URL"),
        SQLAlchemyError("SECRET SQL statement"),
    ],
)
def test_database_failure_with_rollback_failure_is_sanitized_and_closes(
    error: Exception,
) -> None:
    session = FakeSession(fail_rollback=True)

    exit_code, stdout, stderr, session, _ = run_fake(
        session=session,
        pipeline_error=error,
    )

    assert exit_code == 1
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.close_attempts == 1
    assert session.closed is True
    assert stdout == ""
    assert stderr == (
        "Manual Anomali publication ingestion failed during a database operation.\n"
        "Manual Anomali publication ingestion could not roll back database changes "
        "safely.\n"
    )
    assert "SECRET" not in stderr
    assert "Traceback" not in stderr


def test_unexpected_processing_failure_with_rollback_failure_is_sanitized() -> None:
    session = FakeSession(fail_rollback=True)

    exit_code, stdout, stderr, session, _ = run_fake(
        session=session,
        pipeline_error=RuntimeError("SECRET PROCESSING object representation"),
    )

    assert exit_code == 1
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.close_attempts == 1
    assert session.closed is True
    assert stdout == ""
    assert stderr == (
        "Manual Anomali publication ingestion failed unexpectedly.\n"
        "Manual Anomali publication ingestion could not roll back database changes "
        "safely.\n"
    )
    assert "SECRET" not in stderr
    assert "Traceback" not in stderr


def test_successful_commit_with_close_failure_returns_sanitized_failure() -> None:
    session = FakeSession(fail_close=True)

    exit_code, stdout, stderr, session, _ = run_fake(session=session)

    assert exit_code == 1
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.close_attempts == 1
    assert session.closed is False
    assert stdout == ""
    assert stderr == (
        "Manual Anomali publication ingestion could not close database resources "
        "safely.\n"
    )
    assert "SECRET CLOSE" not in stderr
    assert "Traceback" not in stderr


def test_controlled_failed_run_with_close_failure_keeps_committed_audit() -> None:
    session = FakeSession(fail_close=True)

    exit_code, stdout, stderr, session, _ = run_fake(
        session=session,
        outcomes=["failed"],
    )
    run = get_run(session)

    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_failed == 1
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.close_attempts == 1
    assert stdout == ""
    assert stderr == (
        "Manual Anomali publication ingestion completed with a controlled failure.\n"
        "Manual Anomali publication ingestion could not close database resources "
        "safely.\n"
    )
    assert "SECRET CLOSE" not in stderr


def test_database_failure_then_close_failure_keeps_both_paths_sanitized() -> None:
    session = FakeSession(fail_close=True)

    exit_code, stdout, stderr, session, _ = run_fake(
        session=session,
        pipeline_error=SQLAlchemyError("SECRET SQL and database URL"),
    )

    assert exit_code == 1
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.close_attempts == 1
    assert stdout == ""
    assert stderr == (
        "Manual Anomali publication ingestion failed during a database operation.\n"
        "Manual Anomali publication ingestion could not close database resources "
        "safely.\n"
    )
    assert "SECRET" not in stderr
    assert "Traceback" not in stderr


def test_session_creation_failure_does_not_attempt_transaction_cleanup() -> None:
    untouched_session = FakeSession()
    stdout = StringIO()
    stderr = StringIO()

    exit_code = anomali_publications_cli.run_import(
        file_path="not-read.json",
        loader=lambda _: AnomaliPublicationDocument(ANOMALI_SOURCE_SLUG, ()),
        clock=lambda: NOW,
        session_factory=lambda: (_ for _ in ()).throw(
            RuntimeError("SECRET SESSION CREATION database URL")
        ),
        pipeline_factory=lambda _: pytest.fail("pipeline must not be created"),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert untouched_session.rollbacks == 0
    assert untouched_session.close_attempts == 0
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "Manual Anomali publication ingestion failed unexpectedly.\n"
    )
    assert "SECRET" not in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()


def test_file_envelope_failure_creates_no_session_or_partial_state() -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = anomali_publications_cli.run_import(
        file_path="C:\\private\\secret-catalogue.json",
        loader=lambda _: (_ for _ in ()).throw(
            AnomaliPublicationFileError("private file path and JSON")
        ),
        clock=lambda: pytest.fail("clock must not run"),
        session_factory=lambda: pytest.fail("session must not be created"),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "The Anomali publication file was rejected safely.\n"


def test_unexpected_loader_failure_is_sanitized_before_clock_or_database() -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = anomali_publications_cli.run_import(
        file_path="C:\\private\\secret-catalogue.json",
        loader=lambda _: (_ for _ in ()).throw(
            RuntimeError("secret JSON env database and local path detail")
        ),
        clock=lambda: pytest.fail("clock must not run"),
        session_factory=lambda: pytest.fail("session must not be created"),
        pipeline_factory=lambda _: pytest.fail("pipeline must not be created"),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "Manual Anomali publication ingestion could not load the local catalogue safely.\n"
    )


class BrokenTimezoneDatetime(datetime):
    def utcoffset(self):
        raise RuntimeError("private timezone detail")


def _raising_clock() -> datetime:
    raise RuntimeError("private clock detail")


@pytest.mark.parametrize(
    "clock",
    [
        _raising_clock,
        lambda: "private non-datetime",
        lambda: datetime(2026, 7, 15, 10, 0),
        lambda: BrokenTimezoneDatetime(2026, 7, 15, 10, 0, tzinfo=UTC),
    ],
    ids=["raises", "non-datetime", "naive", "broken-timezone"],
)
def test_unsafe_clock_is_sanitized_before_session_creation(clock) -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = anomali_publications_cli.run_import(
        file_path="not-read.json",
        loader=lambda _: AnomaliPublicationDocument(ANOMALI_SOURCE_SLUG, ()),
        clock=clock,
        session_factory=lambda: pytest.fail("session must not be created"),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "Manual Anomali publication ingestion could not establish a safe observation "
        "time.\n"
    )


def test_cli_arguments_are_required_and_deterministic(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    monkeypatch.setattr(anomali_publications_cli, "run_import", lambda **_: 0)

    assert anomali_publications_cli.main(["--file", "input.json"]) == 0
    assert anomali_publications_cli.main([]) == 1
    assert anomali_publications_cli.main(["--url", "https://www.anomali.com"]) == 1
    assert "Invalid manual Anomali import arguments." in capsys.readouterr().err


def test_manual_import_path_performs_no_network_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def network_forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("Network access is not approved for P9-06.")

    import socket

    monkeypatch.setattr(socket, "create_connection", network_forbidden)
    exit_code, _, _, session, pipeline = run_fake(records=("offline",))

    assert exit_code == 0
    assert session.commits == 1
    assert len(pipeline.persist_calls) == 1
