from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from io import StringIO
from uuid import UUID, uuid4

import pytest

from app.ingestion import rss_cli
from app.ingestion.collectors.rss_client import (
    CERT_EU_FEED_URL,
    RssFetchResult,
    RssRateLimitError,
    RssRedirectError,
    RssRequestError,
)
from app.ingestion.normalizers.rss import RssNormalizationError, normalize_rss_entry
from app.ingestion.services.rss_ingestion_service import (
    RssPersistenceError,
    RssPersistenceResult,
)
from app.models import IngestionError, IngestionRun, IngestionRunRecord, IntelligenceSource


NOW = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)
FEED = b"""<rss><channel><item>
<guid>CERT-EU-SA2026-001</guid>
<title>CERT-EU Security Advisory</title>
<link>https://cert.europa.eu/publications/security-advisories/2026-001</link>
<description>Safe advisory summary.</description>
</item></channel></rss>"""


class FakeSession:
    def __init__(self, *, fail_commit: bool = False):
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
            raise RssPersistenceError("postgresql://private:password@host/db")
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class FakeClient:
    def __init__(self, feed: bytes = FEED, error: Exception | None = None):
        self.feed = feed
        self.error = error
        self.closed = False
        self.fetches = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.closed = True

    def fetch_cert_eu_security_advisories(self) -> RssFetchResult:
        self.fetches += 1
        if self.error is not None:
            raise self.error
        return RssFetchResult(
            feed_bytes=self.feed,
            source_url=CERT_EU_FEED_URL,
            final_url=CERT_EU_FEED_URL,
            content_type="application/rss+xml",
            byte_count=len(self.feed),
        )


class FakeService:
    def __init__(
        self,
        session: FakeSession,
        outcomes: list[str] | None = None,
        error: Exception | None = None,
    ):
        self.session = session
        self.outcomes = list(outcomes or ["created"])
        self.error = error
        self.persist_calls: list[object] = []
        self.source = IntelligenceSource(
            slug="cert-eu-security-advisories",
            name="CERT-EU Security Advisories",
            source_type="rss",
            base_url=CERT_EU_FEED_URL,
            is_enabled=True,
            checkpoint_value="existing-checkpoint",
            last_successful_fetch_at=datetime(2026, 7, 9, 12, 0, tzinfo=UTC),
        )

    def ensure_source(self) -> IntelligenceSource:
        return self.source

    def persist(self, normalized: object, *, observed_at: datetime):
        del observed_at
        self.persist_calls.append(normalized)
        if self.error is not None:
            raise self.error
        outcome = self.outcomes.pop(0)
        source_external_id = getattr(normalized, "source_external_id")
        return RssPersistenceResult(source_external_id, outcome, None, None, 123)


class ServiceFactory:
    def __init__(self, outcomes: list[str] | None = None, error: Exception | None = None):
        self.outcomes = outcomes
        self.error = error
        self.service: FakeService | None = None

    def __call__(self, session: FakeSession) -> FakeService:
        self.service = FakeService(session, self.outcomes, self.error)
        return self.service


def run_fake(
    *,
    session: FakeSession | None = None,
    client: FakeClient | None = None,
    service_factory: ServiceFactory | None = None,
    feed_parser=None,
    entry_normalizer=normalize_rss_entry,
    max_records: int = 25,
):
    fake_session = session or FakeSession()
    fake_client = client or FakeClient()
    services = service_factory or ServiceFactory()
    stdout = StringIO()
    stderr = StringIO()
    exit_code = rss_cli.run_ingestion(
        max_records=max_records,
        clock=lambda: NOW,
        client_factory=lambda: fake_client,  # type: ignore[arg-type]
        session_factory=lambda: fake_session,  # type: ignore[arg-type]
        feed_parser=feed_parser or rss_cli.parse_rss_feed_entries,
        entry_normalizer=entry_normalizer,
        service_factory=services,  # type: ignore[arg-type]
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), fake_session, fake_client, services


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1", 0), ("100", 0), ("0", 2), ("101", 2), ("bad", 2)],
)
def test_cli_argument_bounds(monkeypatch, value: str, expected: int, capsys) -> None:
    monkeypatch.setattr(rss_cli, "run_ingestion", lambda **kwargs: 0)

    assert rss_cli.main(["--max-records", value]) == expected
    if expected == 2:
        assert "Invalid manual RSS ingestion arguments." in capsys.readouterr().err


def test_direct_validation_rejects_values_before_factories() -> None:
    stderr = StringIO()

    exit_code = rss_cli.run_ingestion(
        max_records=True,  # type: ignore[arg-type]
        clock=lambda: pytest.fail("clock must not run"),
        client_factory=lambda: pytest.fail("client must not be created"),
        session_factory=lambda: pytest.fail("session must not be created"),
        stderr=stderr,
    )

    assert exit_code == 2
    assert stderr.getvalue() == "Invalid manual RSS ingestion parameters.\n"


def test_successful_ingestion_creates_audit_and_commits() -> None:
    exit_code, stdout, stderr, session, client, _ = run_fake()

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert isinstance(run.public_id, UUID)
    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 1
    assert run.records_created == 1
    assert run.records_failed == 0
    assert run.checkpoint_after == "2026-07-10T12:00:00Z"
    assert run.source.checkpoint_value == "2026-07-10T12:00:00Z"
    assert run.source.last_successful_fetch_at == NOW
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closed
    assert client.closed
    assert "Created: 1" in stdout
    assert "Capped: false" in stdout
    assert stderr == ""


def test_empty_feed_succeeds_without_record_work() -> None:
    empty_feed = b"<rss><channel><title>CERT-EU</title></channel></rss>"

    exit_code, _, stderr, session, _, services = run_fake(client=FakeClient(empty_feed))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 0
    assert run.status == "succeeded"
    assert run.records_fetched == 0
    assert services.service.persist_calls == []
    assert stderr == ""


def test_exact_duplicate_advisory_is_processed_once() -> None:
    duplicate_feed = b"""<rss><channel>
<item><guid>CERT-EU-SA2026-001</guid><title>CERT-EU Security Advisory</title>
<link>https://cert.europa.eu/publications/security-advisories/2026-001</link>
<description>Safe advisory summary.</description></item>
<item><guid>CERT-EU-SA2026-001</guid><title>CERT-EU Security Advisory</title>
<link>https://cert.europa.eu/publications/security-advisories/2026-001</link>
<description>Safe advisory summary.</description></item>
</channel></rss>"""

    exit_code, _, _, session, _, services = run_fake(client=FakeClient(duplicate_feed))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 0
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert len(services.service.persist_calls) == 1


def test_conflicting_duplicate_advisory_fails_safely() -> None:
    conflicting = b"""<rss><channel>
<item><guid>CERT-EU-SA2026-001</guid><title>One</title>
<link>https://cert.europa.eu/publications/a</link></item>
<item><guid>CERT-EU-SA2026-001</guid><title>Two</title>
<link>https://cert.europa.eu/publications/b</link></item>
</channel></rss>"""

    exit_code, stdout, stderr, session, _, services = run_fake(client=FakeClient(conflicting))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    error = next(record for record in session.added if isinstance(record, IngestionError))
    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_created == 1
    assert run.records_failed == 1
    assert run.error_count == 1
    assert error.error_type == "rss_duplicate_conflict"
    assert len(services.service.persist_calls) == 1
    assert "https://cert.europa.eu/publications/b" not in stdout
    assert "https://cert.europa.eu/publications/b" not in stderr


@pytest.mark.parametrize("invalid_first", [False, True])
def test_entry_normalization_failure_is_isolated_and_commits_partial(
    invalid_first: bool,
) -> None:
    valid = b"""<item><guid>CERT-EU-SA2026-001</guid><title>Valid</title>
<link>https://cert.europa.eu/publications/a</link></item>"""
    invalid_url = "https://example.com/not-approved"
    invalid = f"""<item><guid>CERT-EU-SA2026-002</guid><title>Invalid</title>
<link>{invalid_url}</link></item>""".encode()
    entries = invalid + valid if invalid_first else valid + invalid
    feed = b"<rss><channel>" + entries + b"</channel></rss>"

    exit_code, stdout, stderr, session, _, services = run_fake(client=FakeClient(feed))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    failed_records = [
        record
        for record in session.added
        if isinstance(record, IngestionRunRecord) and record.action == "failed"
    ]
    errors = [record for record in session.added if isinstance(record, IngestionError)]
    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_failed == 1
    assert run.checkpoint_after is None
    assert run.source.checkpoint_value == "existing-checkpoint"
    assert run.source.last_successful_fetch_at == datetime(2026, 7, 9, 12, 0, tzinfo=UTC)
    assert len(services.service.persist_calls) == 1
    assert len(failed_records) == 1
    assert len(errors) == 1
    assert errors[0].error_type == "rss_normalization_error"
    assert invalid_url not in errors[0].safe_message
    assert invalid_url not in stdout
    assert invalid_url not in stderr
    assert session.commits == 1
    assert session.rollbacks == 0


def test_malformed_advisory_url_records_controlled_sanitized_outcome() -> None:
    malformed_url = "https://cert.europa.eu:bad/feed"
    feed = f"""<rss><channel><item>
<guid>CERT-EU-SA2026-001</guid><title>Invalid URL</title>
<link>{malformed_url}</link>
</item></channel></rss>""".encode()

    exit_code, stdout, stderr, session, _, services = run_fake(client=FakeClient(feed))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    error = next(record for record in session.added if isinstance(record, IngestionError))
    assert exit_code == 1
    assert run.status == "failed"
    assert run.records_fetched == 1
    assert run.records_failed == 1
    assert services.service.persist_calls == []
    assert error.error_type == "rss_normalization_error"
    assert malformed_url not in error.safe_message
    assert malformed_url not in stdout
    assert malformed_url not in stderr


def test_non_representable_entry_date_is_isolated_and_commits_partial() -> None:
    invalid_date = "0000-01-01T00:00:00Z"
    feed = f"""<rss><channel>
<item><guid>CERT-EU-SA2026-001</guid><title>Valid</title>
<link>https://cert.europa.eu/publications/a</link></item>
<item><guid>CERT-EU-SA2026-002</guid><title>Invalid Date</title>
<link>https://cert.europa.eu/publications/b</link>
<pubDate>{invalid_date}</pubDate></item>
</channel></rss>""".encode()

    exit_code, stdout, stderr, session, _, services = run_fake(client=FakeClient(feed))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    failed_records = [
        record
        for record in session.added
        if isinstance(record, IngestionRunRecord) and record.action == "failed"
    ]
    errors = [record for record in session.added if isinstance(record, IngestionError)]
    assert exit_code == 1
    assert run.status == "partial"
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_failed == 1
    assert len(services.service.persist_calls) == 1
    assert len(failed_records) == 1
    assert len(errors) == 1
    assert errors[0].error_type == "rss_normalization_error"
    assert run.checkpoint_after is None
    assert run.source.checkpoint_value == "existing-checkpoint"
    assert session.commits == 1
    assert session.rollbacks == 0
    assert invalid_date not in stdout
    assert invalid_date not in stderr
    assert invalid_date not in failed_records[0].safe_detail
    assert invalid_date not in errors[0].safe_message


def test_normalization_failure_is_sanitized() -> None:
    marker = "private-feed-fragment"

    def fail_parsing(value: bytes):
        assert marker.encode() in value
        raise RssNormalizationError(marker)

    exit_code, stdout, stderr, session, _, _ = run_fake(
        client=FakeClient(b"<rss>private-feed-fragment</rss>"),
        feed_parser=fail_parsing,
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    error = next(record for record in session.added if isinstance(record, IngestionError))
    assert exit_code == 1
    assert run.records_failed == 1
    assert error.error_type == "rss_normalization_error"
    assert marker not in stdout
    assert marker not in stderr
    assert marker not in error.safe_message


def test_persistence_failure_is_sanitized_and_committed_as_partial() -> None:
    marker = "postgresql://private:password@host/database"

    exit_code, stdout, stderr, session, _, _ = run_fake(
        service_factory=ServiceFactory(error=RssPersistenceError(marker)),
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    error = next(record for record in session.added if isinstance(record, IngestionError))
    assert exit_code == 1
    assert run.status == "failed"
    assert session.commits == 1
    assert marker not in stdout
    assert marker not in stderr
    assert error.error_type == "rss_persistence_error"


@pytest.mark.parametrize(
    ("error", "expected_type", "retryable"),
    [
        (RssRequestError("secret transport detail"), "rss_fetch_error", True),
        (RssRateLimitError("secret rate detail"), "rss_rate_limit", True),
        (RssRedirectError("secret redirect detail"), "rss_fetch_rejected", False),
    ],
)
def test_fetch_failures_are_retryable_or_rejected_safely(
    error: Exception,
    expected_type: str,
    retryable: bool,
) -> None:
    exit_code, stdout, stderr, session, client, _ = run_fake(client=FakeClient(error=error))

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    error_record = next(record for record in session.added if isinstance(record, IngestionError))
    assert exit_code == 1
    assert run.status == "failed"
    assert client.closed
    assert error_record.error_type == expected_type
    assert error_record.retryable is retryable
    assert "secret" not in stdout
    assert "secret" not in stderr


def test_partial_run_does_not_advance_checkpoint() -> None:
    exit_code, _, _, session, _, _ = run_fake(
        service_factory=ServiceFactory(["failed"]),
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 1
    assert run.checkpoint_after is None
    assert run.source.checkpoint_value == "existing-checkpoint"
    assert run.source.last_successful_fetch_at == datetime(2026, 7, 9, 12, 0, tzinfo=UTC)


def test_whole_run_database_failure_rolls_back_and_closes() -> None:
    session = FakeSession(fail_commit=True)

    exit_code, stdout, stderr, session, _, _ = run_fake(session=session)

    assert exit_code == 1
    assert stdout == ""
    assert "database operation" in stderr
    assert "private" not in stderr
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed


def test_max_records_cap_marks_run_partial_without_advancing_checkpoint() -> None:
    two_records = b"""<rss><channel>
<item><guid>CERT-EU-SA2026-001</guid><title>One</title>
<link>https://cert.europa.eu/publications/a</link></item>
<item><guid>CERT-EU-SA2026-002</guid><title>Two</title>
<link>https://cert.europa.eu/publications/b</link></item>
</channel></rss>"""

    exit_code, stdout, stderr, session, _, services = run_fake(
        client=FakeClient(two_records),
        service_factory=ServiceFactory(["created"]),
        max_records=1,
    )

    run = next(record for record in session.added if isinstance(record, IngestionRun))
    assert exit_code == 1
    assert run.status == "partial"
    assert run.checkpoint_after is None
    assert run.source.checkpoint_value == "existing-checkpoint"
    assert run.source.last_successful_fetch_at == datetime(2026, 7, 9, 12, 0, tzinfo=UTC)
    assert run.records_fetched == 2
    assert run.records_created == 1
    assert run.records_failed == 0
    assert "capped=true" in run.safe_summary
    assert "Capped: true" in stdout
    assert "Record cap reached" in stdout
    assert "controlled failure" in stderr
    assert session.commits == 1
    assert session.rollbacks == 0
    assert len(services.service.persist_calls) == 1
    assert session.added
    assert any(isinstance(record, IngestionRunRecord) for record in session.added)
