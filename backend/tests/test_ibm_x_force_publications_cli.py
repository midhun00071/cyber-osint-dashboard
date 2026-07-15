from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from io import StringIO
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion import ibm_x_force_publications_cli
from app.ingestion.adapters.ibm_x_force_publications import (
    IBM_X_FORCE_OSINT_SOURCE_SLUG,
    IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
    IbmXForcePublicationDocument,
    IbmXForcePublicationFileError,
    IbmXForcePublicationRecordError,
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


NOW = datetime(2026, 7, 16, 10, 0, tzinfo=UTC)


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
        self.close_attempts = 0
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
        if self.fail_nested:
            raise SQLAlchemyError("SECRET nested SQL")
        return nullcontext()

    def commit(self) -> None:
        if self.fail_commit:
            raise SQLAlchemyError("SECRET commit database URL")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1
        if self.fail_rollback:
            raise RuntimeError("SECRET ROLLBACK SQL")

    def close(self) -> None:
        self.close_attempts += 1
        if self.fail_close:
            raise RuntimeError("SECRET CLOSE environment and credentials")
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
        self.ensure_calls: list[str] = []

    def ensure_source(self, source_slug: str) -> IntelligenceSource:
        self.ensure_calls.append(source_slug)
        host = (
            "www.ibm.com"
            if source_slug == IBM_X_FORCE_RESEARCH_SOURCE_SLUG
            else "exchange.xforce.ibmcloud.com"
        )
        return IntelligenceSource(
            slug=source_slug,
            name="IBM X-Force",
            source_type="json",
            base_url=f"https://{host}/",
            is_enabled=True,
            checkpoint_value="existing-checkpoint",
        )

    def persist(self, candidate: PublicationCandidate, *, observed_at: datetime):
        assert observed_at == NOW
        self.persist_calls.append(candidate)
        if self.error is not None:
            raise self.error
        outcome = self.outcomes.pop(0) if self.outcomes is not None else "created"
        return PublicationPersistenceResult(
            candidate.source_external_id,
            outcome,
            "SECRET pipeline detail must not be audited",
            self.source_record,
            721,
        )


def candidate(
    source_slug: str,
    identifier: str,
    *,
    title: str | None = None,
) -> PublicationCandidate:
    if source_slug == IBM_X_FORCE_RESEARCH_SOURCE_SLUG:
        url = f"https://www.ibm.com/think/x-force/{identifier}"
    else:
        guid = (identifier.encode().hex() + ("0" * 32))[:32]
        url = f"https://exchange.xforce.ibmcloud.com/osint/guid%3A{guid}"
    return PublicationCandidate(
        source_slug=source_slug,
        source_external_id=identifier,
        canonical_title=title or f"IBM X-Force publication {identifier}",
        canonical_url=url,
    )


def run_fake(
    *,
    source_slug: str = IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
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

    def adapter(document_source: str, record: object) -> PublicationCandidate:
        assert document_source == source_slug
        if record == "invalid":
            raise IbmXForcePublicationRecordError(
                "SECRET IBM title URL GUID IOC and path"
            )
        return candidate(source_slug, str(record))

    exit_code = ibm_x_force_publications_cli.run_import(
        file_path="not-read.json",
        clock=lambda: NOW,
        loader=lambda _: IbmXForcePublicationDocument(source_slug, records),
        adapter=adapter,
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), fake_session, pipeline


def get_run(session: FakeSession) -> IngestionRun:
    return next(item for item in session.added if isinstance(item, IngestionRun))


@pytest.mark.parametrize(
    "source_slug",
    [IBM_X_FORCE_RESEARCH_SOURCE_SLUG, IBM_X_FORCE_OSINT_SOURCE_SLUG],
)
def test_source_specific_created_import_commits_one_safe_run(source_slug: str) -> None:
    source_record = SourceRecord()
    exit_code, stdout, stderr, session, pipeline = run_fake(
        source_slug=source_slug,
        source_record=source_record,
    )
    run = get_run(session)
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    assert exit_code == 0
    assert run.source.slug == source_slug
    assert run.status == "succeeded"
    assert run.records_fetched == 1
    assert run.records_created == 1
    assert run.records_updated == 0
    assert run.records_unchanged == 0
    assert run.records_skipped == 0
    assert run.records_failed == 0
    assert pipeline.ensure_calls == [source_slug]
    assert len(pipeline.persist_calls) == 1
    assert pipeline.persist_calls[0].source_slug == source_slug
    assert session.nested_transactions == 1
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.close_attempts == 1
    assert audits[0].source_record is source_record
    assert "SECRET" not in (audits[0].safe_detail or "")
    assert "Created: 1" in stdout
    assert stderr == ""


@pytest.mark.parametrize("outcome", ["updated", "unchanged"])
def test_update_and_unchanged_outcomes(outcome: str) -> None:
    exit_code, _, stderr, session, _ = run_fake(outcomes=[outcome])
    run = get_run(session)
    assert exit_code == 0
    assert run.status == "succeeded"
    assert getattr(run, f"records_{outcome}") == 1
    assert session.commits == 1
    assert stderr == ""


def test_mixed_outcomes_have_honest_counters_and_one_final_commit() -> None:
    exit_code, _, stderr, session, pipeline = run_fake(
        records=("one", "two", "three"),
        outcomes=["created", "updated", "unchanged"],
    )
    run = get_run(session)
    assert exit_code == 0
    assert run.status == "succeeded"
    assert (run.records_created, run.records_updated, run.records_unchanged) == (1, 1, 1)
    assert len(pipeline.persist_calls) == 3
    assert session.nested_transactions == 3
    assert session.commits == 1
    assert stderr == ""


def test_identical_duplicate_after_created_uses_one_non_null_source_record() -> None:
    source_record = SourceRecord()
    exit_code, _, stderr, session, pipeline = run_fake(
        records=("same", "same"),
        outcomes=["created"],
        source_record=source_record,
    )
    run = get_run(session)
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    assert exit_code == 0
    assert run.records_created == 1
    assert run.records_unchanged == 1
    assert len(pipeline.persist_calls) == 1
    assert [audit.action for audit in audits] == ["created", "unchanged"]
    assert audits[0].source_record is source_record
    assert audits[1].source_record is None
    assert audits[1].intelligence_item_id == 721
    assert stderr == ""


def test_identical_duplicate_after_failed_repeats_sanitized_failure() -> None:
    source_record = SourceRecord()
    exit_code, stdout, stderr, session, pipeline = run_fake(
        records=("private-guid", "private-guid"),
        outcomes=["failed"],
        source_record=source_record,
    )
    run = get_run(session)
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_failed == 2
    assert run.records_unchanged == 0
    assert len(pipeline.persist_calls) == 1
    assert [audit.action for audit in audits] == ["failed", "failed"]
    assert audits[0].source_record is source_record
    assert audits[1].source_record is None
    assert audits[1].intelligence_item_id is None
    assert errors[0].source_record is source_record
    assert errors[1].source_record is None
    assert "private-guid" not in " ".join(
        [stdout, stderr, *(audit.safe_detail or "" for audit in audits)]
    )


def test_identical_duplicate_after_skipped_repeats_skipped_accounting() -> None:
    exit_code, _, stderr, session, pipeline = run_fake(
        records=("same", "same"),
        outcomes=["skipped"],
    )
    run = get_run(session)
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_skipped == 2
    assert run.records_unchanged == 0
    assert len(pipeline.persist_calls) == 1
    assert [audit.action for audit in audits] == ["skipped", "skipped"]
    assert audits[1].source_record is None
    assert "controlled failure" in stderr


def test_unsupported_duplicate_outcome_fails_closed_with_valid_audit_action() -> None:
    session = FakeSession()
    source = IntelligenceSource(checkpoint_value=None)
    run = ibm_x_force_publications_cli._create_run(session, source, NOW)
    unsupported = SimpleNamespace(
        outcome="SECRET unsupported outcome",
        intelligence_item_id=999,
        source_record=SourceRecord(),
    )
    ibm_x_force_publications_cli._record_identical_duplicate(
        session,
        run,
        unsupported,  # type: ignore[arg-type]
        NOW,
    )
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert run.records_failed == 1
    assert audits[0].action == "failed"
    assert audits[0].source_record is None
    assert audits[0].intelligence_item_id is None
    assert errors[0].source_record is None
    assert "SECRET" not in (audits[0].safe_detail or "") + errors[0].safe_message


def test_conflicting_duplicate_is_failed_without_overwrite() -> None:
    session = FakeSession()
    pipeline = FakePipeline(session, outcomes=["created"])
    stdout = StringIO()
    stderr = StringIO()

    def conflicting(source_slug: str, record: object) -> PublicationCandidate:
        return candidate(source_slug, "same", title=f"SECRET IBM title {record}")

    exit_code = ibm_x_force_publications_cli.run_import(
        file_path="C:\\SECRET\\ibm.json",
        clock=lambda: NOW,
        loader=lambda _: IbmXForcePublicationDocument(
            IBM_X_FORCE_RESEARCH_SOURCE_SLUG, ("first", "second")
        ),
        adapter=conflicting,
        session_factory=lambda: session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    run = get_run(session)
    audits = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_created == 1
    assert run.records_failed == 1
    assert len(pipeline.persist_calls) == 1
    assert audits[1].source_record is None
    assert errors[0].source_record is None
    assert "SECRET" not in stdout.getvalue() + stderr.getvalue() + (audits[1].safe_detail or "")


def test_adapter_source_mismatch_is_rejected_before_pipeline() -> None:
    session = FakeSession()
    pipeline = FakePipeline(session)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = ibm_x_force_publications_cli.run_import(
        file_path="not-read.json",
        clock=lambda: NOW,
        loader=lambda _: IbmXForcePublicationDocument(
            IBM_X_FORCE_RESEARCH_SOURCE_SLUG, ("one",)
        ),
        adapter=lambda _source, _record: candidate(IBM_X_FORCE_OSINT_SOURCE_SLUG, "one"),
        session_factory=lambda: session,  # type: ignore[arg-type]
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    run = get_run(session)
    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_failed == 1
    assert len(pipeline.persist_calls) == 0
    assert session.commits == 1


@pytest.mark.parametrize("records", [("invalid", "valid"), ("valid", "invalid")])
def test_invalid_and_valid_records_commit_partial_evidence(records: tuple[object, ...]) -> None:
    exit_code, stdout, stderr, session, pipeline = run_fake(records=records)
    run = get_run(session)
    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_failed == 1
    assert len(pipeline.persist_calls) == 1
    assert session.commits == 1
    assert session.rollbacks == 0
    assert "SECRET" not in stdout + stderr


def test_all_invalid_is_failed_and_empty_catalogue_succeeds() -> None:
    exit_code, _, _, session, pipeline = run_fake(records=("invalid", "invalid"))
    run = get_run(session)
    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_failed == 2
    assert len(pipeline.persist_calls) == 0
    assert session.commits == 1

    exit_code, stdout, stderr, session, pipeline = run_fake(
        source_slug=IBM_X_FORCE_OSINT_SOURCE_SLUG,
        records=(),
    )
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


@pytest.mark.parametrize(
    "error",
    [
        PublicationPersistenceError("SECRET persistence database URL"),
        SQLAlchemyError("SECRET SQL statement"),
    ],
)
def test_database_failures_roll_back_and_close_without_disclosure(error: Exception) -> None:
    exit_code, stdout, stderr, session, _ = run_fake(pipeline_error=error)
    assert exit_code == 1
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.close_attempts == 1
    assert stdout == ""
    assert "database operation" in stderr
    assert "SECRET" not in stderr


def test_nested_and_commit_failures_roll_back() -> None:
    for session in (FakeSession(fail_nested=True), FakeSession(fail_commit=True)):
        exit_code, stdout, stderr, session, _ = run_fake(session=session)
        assert exit_code == 1
        assert session.commits == 0
        assert session.rollbacks == 1
        assert session.close_attempts == 1
        assert stdout == ""
        assert "SECRET" not in stderr


def test_rollback_failure_is_sanitized_and_close_is_still_attempted() -> None:
    session = FakeSession(fail_rollback=True)
    exit_code, stdout, stderr, session, _ = run_fake(
        session=session,
        pipeline_error=RuntimeError("SECRET processing exception"),
    )
    assert exit_code == 1
    assert session.rollbacks == 1
    assert session.close_attempts == 1
    assert session.closed is True
    assert stdout == ""
    assert "failed unexpectedly" in stderr
    assert "could not roll back" in stderr
    assert "SECRET" not in stderr
    assert "Traceback" not in stderr


@pytest.mark.parametrize("outcomes", [None, ["failed"]])
def test_close_failure_after_commit_never_reports_success(outcomes: list[str] | None) -> None:
    session = FakeSession(fail_close=True)
    exit_code, stdout, stderr, session, _ = run_fake(
        session=session,
        outcomes=outcomes,
    )
    assert exit_code == 1
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.close_attempts == 1
    assert stdout == ""
    assert "could not close database resources safely" in stderr
    assert "SECRET" not in stderr


def test_session_creation_loader_and_clock_failures_create_no_partial_state() -> None:
    stdout = StringIO()
    stderr = StringIO()
    exit_code = ibm_x_force_publications_cli.run_import(
        file_path="C:\\SECRET\\catalogue.json",
        loader=lambda _: (_ for _ in ()).throw(
            IbmXForcePublicationFileError("SECRET path JSON")
        ),
        clock=lambda: pytest.fail("clock must not run"),
        session_factory=lambda: pytest.fail("session must not be created"),
        stdout=stdout,
        stderr=stderr,
    )
    assert exit_code == 1
    assert stderr.getvalue() == "The IBM X-Force publication file was rejected safely.\n"

    stdout = StringIO()
    stderr = StringIO()
    exit_code = ibm_x_force_publications_cli.run_import(
        file_path="C:\\SECRET\\catalogue.json",
        loader=lambda _: (_ for _ in ()).throw(RuntimeError("SECRET loader")),
        clock=lambda: pytest.fail("clock must not run"),
        session_factory=lambda: pytest.fail("session must not be created"),
        stdout=stdout,
        stderr=stderr,
    )
    assert exit_code == 1
    assert "could not load the local catalogue safely" in stderr.getvalue()
    assert "SECRET" not in stderr.getvalue()

    stdout = StringIO()
    stderr = StringIO()
    exit_code = ibm_x_force_publications_cli.run_import(
        file_path="not-read.json",
        loader=lambda _: IbmXForcePublicationDocument(
            IBM_X_FORCE_RESEARCH_SOURCE_SLUG, ()
        ),
        clock=lambda: NOW,
        session_factory=lambda: (_ for _ in ()).throw(
            RuntimeError("SECRET session database URL")
        ),
        pipeline_factory=lambda _: pytest.fail("pipeline must not be created"),
        stdout=stdout,
        stderr=stderr,
    )
    assert exit_code == 1
    assert stderr.getvalue() == (
        "Manual IBM X-Force publication ingestion failed unexpectedly.\n"
    )


class BrokenTimezoneDatetime(datetime):
    def utcoffset(self):
        raise RuntimeError("SECRET timezone")


@pytest.mark.parametrize(
    "clock",
    [
        lambda: (_ for _ in ()).throw(RuntimeError("SECRET clock")),
        lambda: "not-a-datetime",
        lambda: datetime(2026, 7, 16, 10, 0),
        lambda: BrokenTimezoneDatetime(2026, 7, 16, 10, 0, tzinfo=UTC),
    ],
)
def test_unsafe_clocks_are_rejected_before_session(clock) -> None:
    stdout = StringIO()
    stderr = StringIO()
    exit_code = ibm_x_force_publications_cli.run_import(
        file_path="not-read.json",
        loader=lambda _: IbmXForcePublicationDocument(
            IBM_X_FORCE_RESEARCH_SOURCE_SLUG, ()
        ),
        clock=clock,
        session_factory=lambda: pytest.fail("session must not be created"),
        stdout=stdout,
        stderr=stderr,
    )
    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert "safe observation time" in stderr.getvalue()
    assert "SECRET" not in stderr.getvalue()


def test_cli_accepts_only_required_file_argument(monkeypatch, capsys) -> None:
    monkeypatch.setattr(ibm_x_force_publications_cli, "run_import", lambda **_: 0)
    assert ibm_x_force_publications_cli.main(["--file", "input.json"]) == 0
    for arguments in (
        [],
        ["--url", "https://www.ibm.com"],
        ["--source", IBM_X_FORCE_RESEARCH_SOURCE_SLUG],
        ["--api-key", "SECRET"],
    ):
        assert ibm_x_force_publications_cli.main(arguments) == 1
    assert "Invalid manual IBM X-Force import arguments." in capsys.readouterr().err


def test_manual_import_performs_no_network_call(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("IBM network access is not approved"),
    )
    exit_code, _, _, session, pipeline = run_fake()
    assert exit_code == 0
    assert session.commits == 1
    assert len(pipeline.persist_calls) == 1
