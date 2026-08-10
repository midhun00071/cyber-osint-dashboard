from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from io import StringIO
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion import google_threat_publications_cli
from app.ingestion.adapters.google_threat_publications import (
    GoogleThreatPublicationDocument,
    GoogleThreatPublicationRecordError,
)
from app.ingestion.collectors.google_threat_intelligence_rss_client import (
    GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
    GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
    MANDIANT_THREAT_RESEARCH_SOURCE_SLUG,
    GoogleThreatRssFetchResult,
    GoogleThreatRssRedirectError,
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


NOW = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)


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
                record.id = len([item for item in self.added if isinstance(item, IngestionRun)])
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


class FakeClient:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.closed = True

    def fetch_publications(self) -> GoogleThreatRssFetchResult:
        if self.error is not None:
            raise self.error
        return GoogleThreatRssFetchResult(
            feed_bytes=b"<rss></rss>",
            source_url=GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
            final_url=GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
            content_type="application/rss+xml",
            byte_count=11,
        )


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
        self.source_by_slug = {
            GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG: IntelligenceSource(
                slug=GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
                name="Google Threat Intelligence Public Research",
                source_type="rss",
                base_url=GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
                is_enabled=True,
                checkpoint_value="existing-google-checkpoint",
            ),
            MANDIANT_THREAT_RESEARCH_SOURCE_SLUG: IntelligenceSource(
                slug=MANDIANT_THREAT_RESEARCH_SOURCE_SLUG,
                name="Mandiant Public Threat Research",
                source_type="rss",
                base_url=GOOGLE_THREAT_INTELLIGENCE_FEED_URL,
                is_enabled=True,
                checkpoint_value="existing-mandiant-checkpoint",
            ),
        }

    def ensure_source(self, source_slug: str) -> IntelligenceSource:
        return self.source_by_slug[source_slug]

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
            123,
        )


def candidate(source_slug: str, identifier: str) -> PublicationCandidate:
    return PublicationCandidate(
        source_slug=source_slug,
        source_external_id=identifier,
        canonical_title=f"Publication {identifier}",
        canonical_url=f"https://cloud.google.com/blog/topics/threat-intelligence/{identifier}/",
    )


def run_fake(
    *,
    records: tuple[object, ...] = ("google", "mandiant"),
    session: FakeSession | None = None,
    client: FakeClient | None = None,
    outcomes: list[str] | None = None,
    pipeline_error: Exception | None = None,
    max_records: int = 25,
):
    fake_session = session or FakeSession()
    fake_client = client or FakeClient()
    pipeline = FakePipeline(fake_session, outcomes=outcomes, error=pipeline_error)
    stdout = StringIO()
    stderr = StringIO()

    def adapter(record: object) -> PublicationCandidate:
        if record == "invalid":
            raise GoogleThreatPublicationRecordError("private invalid author")
        if record == "google-invalid":
            raise GoogleThreatPublicationRecordError(
                "private invalid title",
                source_slug=GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
                failure_stage="adapter.title_required",
                diagnostic_fingerprint="a" * 64,
            )
        if record == "google-invalid-two":
            raise GoogleThreatPublicationRecordError(
                "private invalid summary canary",
                source_slug=GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
                failure_stage="adapter.text_unsupported_characters",
                diagnostic_fingerprint="b" * 64,
            )
        if record == "mandiant-invalid":
            raise GoogleThreatPublicationRecordError(
                "private invalid Mandiant title",
                source_slug=MANDIANT_THREAT_RESEARCH_SOURCE_SLUG,
                failure_stage="adapter.title_required",
                diagnostic_fingerprint="c" * 64,
            )
        if record == "mandiant":
            return candidate(MANDIANT_THREAT_RESEARCH_SOURCE_SLUG, "mandiant")
        if record == "google-conflict":
            return candidate(GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG, "google")
        return candidate(GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG, str(record))

    exit_code = google_threat_publications_cli.run_ingestion(
        max_records=max_records,
        clock=lambda: NOW,
        client_factory=lambda: fake_client,  # type: ignore[arg-type]
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        feed_parser=lambda *_args, **_kwargs: GoogleThreatPublicationDocument(records),
        adapter=adapter,
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), fake_session, fake_client, pipeline


def runs(session: FakeSession) -> list[IngestionRun]:
    return [item for item in session.added if isinstance(item, IngestionRun)]


def test_successful_shared_feed_run_creates_two_source_audits_and_commits_once() -> None:
    exit_code, stdout, stderr, session, client, pipeline = run_fake(
        outcomes=["created", "created"],
    )
    google_run, mandiant_run = runs(session)

    assert exit_code == 0
    assert google_run.status == "succeeded"
    assert google_run.records_fetched == 1
    assert google_run.records_created == 1
    assert mandiant_run.status == "succeeded"
    assert mandiant_run.records_fetched == 1
    assert mandiant_run.records_created == 1
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed is True
    assert client.closed is True
    assert session.nested_transactions == 2
    assert len(pipeline.persist_calls) == 2
    assert "Unassigned rejected: 0" in stdout
    assert stderr == ""


def test_mixed_invalid_author_continues_without_false_source_audit() -> None:
    exit_code, stdout, stderr, session, _, pipeline = run_fake(
        records=("invalid", "google", "mandiant"),
        outcomes=["created", "unchanged"],
    )
    google_run, mandiant_run = runs(session)

    assert exit_code == 1
    assert google_run.status == "partial"
    assert mandiant_run.status == "partial"
    assert google_run.records_created == 1
    assert mandiant_run.records_unchanged == 1
    assert google_run.records_failed == 0
    assert mandiant_run.records_failed == 0
    assert "unassigned=1" in google_run.safe_summary
    assert "unassigned=1" in mandiant_run.safe_summary
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert [error.error_type for error in errors] == [
        "google_threat_unassigned_feed_entry",
        "google_threat_unassigned_feed_entry",
    ]
    assert all(error.ingestion_run_record is None for error in errors)
    assert len(pipeline.persist_calls) == 2
    assert session.commits == 1
    assert session.rollbacks == 0
    assert "Unassigned rejected: 1" in stdout
    assert "private invalid author" not in stdout
    assert "private invalid author" not in stderr
    assert not any(
        isinstance(item, IngestionRunRecord) and "private" in (item.safe_detail or "")
        for item in session.added
    )


def test_identical_duplicate_uses_one_non_null_source_record_audit() -> None:
    fake_session = FakeSession()
    shared_source_record = SourceRecord()
    pipeline = FakePipeline(
        fake_session,
        outcomes=["created"],
        source_record=shared_source_record,
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = google_threat_publications_cli.run_ingestion(
        max_records=25,
        clock=lambda: NOW,
        client_factory=lambda: FakeClient(),  # type: ignore[arg-type]
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        feed_parser=lambda *_args, **_kwargs: GoogleThreatPublicationDocument(
            ("google", "google")
        ),
        adapter=lambda record: candidate(
            GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
            str(record),
        ),
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    google_run = runs(fake_session)[0]
    audit_records = [
        item
        for item in fake_session.added
        if isinstance(item, IngestionRunRecord) and item.ingestion_run is google_run
    ]

    assert exit_code == 0
    assert google_run.status == "succeeded"
    assert google_run.records_fetched == 2
    assert google_run.records_created == 1
    assert google_run.records_unchanged == 1
    assert len(pipeline.persist_calls) == 1
    assert fake_session.nested_transactions == 1
    assert len(audit_records) == 2
    assert audit_records[0].source_record is shared_source_record
    assert audit_records[1].source_record is None
    assert audit_records[1].intelligence_item_id == 123
    assert [record.action for record in audit_records] == ["created", "unchanged"]
    assert fake_session.commits == 1
    assert fake_session.rollbacks == 0
    assert "Unchanged: 1" in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_conflicting_in_feed_duplicate_is_a_controlled_failure() -> None:
    def conflicting(record: object) -> PublicationCandidate:
        title = "Changed" if record == "google-conflict" else "Original"
        return PublicationCandidate(
            source_slug=GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
            source_external_id="same-id",
            canonical_title=title,
            canonical_url="https://cloud.google.com/blog/topics/threat-intelligence/same/",
        )

    fake_session = FakeSession()
    pipeline = FakePipeline(fake_session, outcomes=["created"])
    stdout = StringIO()
    stderr = StringIO()
    exit_code = google_threat_publications_cli.run_ingestion(
        max_records=25,
        clock=lambda: NOW,
        client_factory=lambda: FakeClient(),  # type: ignore[arg-type]
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        feed_parser=lambda *_args, **_kwargs: GoogleThreatPublicationDocument(("google", "google-conflict")),
        adapter=conflicting,
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    google_run = runs(fake_session)[0]

    assert exit_code == 1
    assert google_run.status == "partial"
    assert google_run.records_created == 1
    assert google_run.records_failed == 1
    assert len(pipeline.persist_calls) == 1
    assert "google-conflict" not in stdout.getvalue()
    assert "google-conflict" not in stderr.getvalue()


def test_all_invalid_feed_returns_controlled_failure_without_persistence() -> None:
    exit_code, stdout, stderr, session, _, pipeline = run_fake(records=("invalid",))

    assert exit_code == 1
    assert all(run.status == "partial" for run in runs(session))
    assert all(run.records_failed == 0 for run in runs(session))
    assert all("unassigned=1" in run.safe_summary for run in runs(session))
    assert len(pipeline.persist_calls) == 0
    assert session.commits == 1
    assert "Unassigned rejected: 1" in stdout
    assert "controlled failure" in stderr


def test_known_owner_invalid_record_is_audited_to_only_that_source() -> None:
    exit_code, stdout, stderr, session, _, pipeline = run_fake(
        records=("google-invalid", "mandiant"),
        outcomes=["created"],
    )
    google_run, mandiant_run = runs(session)

    assert exit_code == 1
    assert google_run.status == "failed"
    assert google_run.records_fetched == 1
    assert google_run.records_failed == 1
    assert mandiant_run.status == "succeeded"
    assert mandiant_run.records_fetched == 1
    assert mandiant_run.records_created == 1
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert [error.error_type for error in errors] == [
        "google_threat_publication_validation_error"
    ]
    assert errors[0].failure_stage == "adapter.title_required"
    assert errors[0].diagnostic_fingerprint == "a" * 64
    assert errors[0].safe_context is None
    records = [item for item in session.added if isinstance(item, IngestionRunRecord)]
    assert any(record.ingestion_run is google_run for record in records)
    assert not any(
        isinstance(item, IngestionError) and item.ingestion_run is mandiant_run
        for item in session.added
    )
    assert len(pipeline.persist_calls) == 1
    assert "private invalid title" not in stdout
    assert "private invalid title" not in stderr
    assert "private invalid title" not in " ".join(
        filter(
            None,
            [
                errors[0].error_type,
                errors[0].safe_message,
                errors[0].failure_stage,
                errors[0].diagnostic_fingerprint,
                errors[0].safe_context,
            ],
        )
    )


def test_mandiant_owned_rejection_records_only_sanitized_diagnostics() -> None:
    exit_code, stdout, stderr, session, _, pipeline = run_fake(
        records=("google", "mandiant-invalid"),
        outcomes=["created"],
    )
    google_run, mandiant_run = runs(session)
    errors = [item for item in session.added if isinstance(item, IngestionError)]

    assert exit_code == 1
    assert google_run.status == "succeeded"
    assert google_run.records_created == 1
    assert mandiant_run.status == "failed"
    assert mandiant_run.records_failed == 1
    assert len(errors) == 1
    assert errors[0].ingestion_run is mandiant_run
    assert errors[0].failure_stage == "adapter.title_required"
    assert errors[0].diagnostic_fingerprint == "c" * 64
    assert errors[0].safe_context is None
    assert len(pipeline.persist_calls) == 1
    persisted_evidence = " ".join(
        filter(
            None,
            [
                errors[0].error_type,
                errors[0].safe_message,
                errors[0].failure_stage,
                errors[0].diagnostic_fingerprint,
                errors[0].safe_context,
            ],
        )
    )
    assert "private invalid Mandiant title" not in persisted_evidence
    assert "private invalid Mandiant title" not in stdout
    assert "private invalid Mandiant title" not in stderr


def test_same_source_rejections_keep_distinct_opaque_diagnostic_identifiers() -> None:
    exit_code, _, _, session, _, pipeline = run_fake(
        records=("google-invalid", "google-invalid-two"),
    )
    google_run, mandiant_run = runs(session)
    errors = [item for item in session.added if isinstance(item, IngestionError)]

    assert exit_code == 1
    assert google_run.status == "failed"
    assert google_run.records_failed == 2
    assert mandiant_run.status == "succeeded"
    assert [error.diagnostic_fingerprint for error in errors] == ["a" * 64, "b" * 64]
    assert len({error.diagnostic_fingerprint for error in errors}) == 2
    assert len(pipeline.persist_calls) == 0
    assert "private invalid summary canary" not in " ".join(
        error.safe_message for error in errors
    )


def test_feed_truncation_marks_both_runs_partial_and_limits_processing() -> None:
    records = tuple(f"google-{index}" for index in range(101))
    fake_session = FakeSession()
    pipeline = FakePipeline(fake_session, outcomes=["created"] * 100)
    stdout = StringIO()
    stderr = StringIO()

    exit_code = google_threat_publications_cli.run_ingestion(
        max_records=100,
        clock=lambda: NOW,
        client_factory=lambda: FakeClient(),  # type: ignore[arg-type]
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        feed_parser=lambda *_args, **_kwargs: GoogleThreatPublicationDocument(
            records,
            was_truncated=True,
        ),
        adapter=lambda record: candidate(
            GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
            str(record),
        ),
        pipeline_factory=lambda _: pipeline,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    google_run, mandiant_run = runs(fake_session)

    assert exit_code == 1
    assert google_run.status == "partial"
    assert mandiant_run.status == "partial"
    assert google_run.records_fetched == 100
    assert len(pipeline.persist_calls) == 100
    assert "google-100" not in [call.source_external_id for call in pipeline.persist_calls]
    assert "Capped: true" in stdout.getvalue()
    assert "controlled failure" in stderr.getvalue()


@pytest.mark.parametrize("value", [0, 101, True])
def test_invalid_direct_parameters_reject_before_factories(value: object) -> None:
    stderr = StringIO()

    exit_code = google_threat_publications_cli.run_ingestion(
        max_records=value,  # type: ignore[arg-type]
        clock=lambda: pytest.fail("clock must not run"),
        client_factory=lambda: pytest.fail("client must not be created"),
        session_factory=lambda: pytest.fail("session must not be created"),
        stderr=stderr,
    )

    assert exit_code == 2
    assert stderr.getvalue() == "Invalid manual Google Threat publication parameters.\n"


class BrokenTimezoneDatetime(datetime):
    def utcoffset(self):
        raise RuntimeError("private clock timezone detail")


def _raising_clock() -> datetime:
    raise RuntimeError("private clock failure")


@pytest.mark.parametrize(
    "clock",
    [
        _raising_clock,
        lambda: "private non-datetime result",
        lambda: datetime(2026, 7, 15, 8, 0),
        lambda: BrokenTimezoneDatetime(2026, 7, 15, 8, 0, tzinfo=UTC),
    ],
    ids=["raises", "non-datetime", "naive", "timezone-method-raises"],
)
def test_unsafe_clock_is_sanitized_before_session_or_client_creation(clock) -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = google_threat_publications_cli.run_ingestion(
        max_records=25,
        clock=clock,
        client_factory=lambda: pytest.fail("client must not be created"),
        session_factory=lambda: pytest.fail("session must not be created"),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "Manual Google Threat publication ingestion could not establish a safe "
        "observation time.\n"
    )


def test_fetch_failure_is_audited_for_both_real_sources() -> None:
    exit_code, stdout, stderr, session, client, _ = run_fake(
        client=FakeClient(error=GoogleThreatRssRedirectError("private redirect")),
    )

    assert exit_code == 1
    assert client.closed
    assert all(run.status == "failed" for run in runs(session))
    errors = [item for item in session.added if isinstance(item, IngestionError)]
    assert {error.error_type for error in errors} == {"google_threat_rss_fetch_rejected"}
    assert "private redirect" not in stdout
    assert "private redirect" not in stderr
    assert session.commits == 1


def test_database_error_rolls_back_entire_run_without_disclosure() -> None:
    secret = "postgresql://private:password@host/database"
    exit_code, stdout, stderr, session, _, _ = run_fake(
        pipeline_error=PublicationPersistenceError(secret),
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
    exit_code, _, stderr, session, _, _ = run_fake(session=session)

    assert exit_code == 1
    assert session.commits == 0
    assert session.rollbacks == 1
    assert "private" not in stderr


def test_cli_arguments_are_deterministic(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(google_threat_publications_cli, "run_ingestion", lambda **_: 0)

    assert google_threat_publications_cli.main(["--max-records", "25"]) == 0
    assert google_threat_publications_cli.main(["--max-records", "0"]) == 2
    assert "Invalid manual Google Threat publication arguments." in capsys.readouterr().err
