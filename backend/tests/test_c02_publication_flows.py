from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.orchestration.contracts import (
    ClassifiedFailure,
    QuotaObservation,
    ResultStatus,
    SOURCE_POLICIES,
    SourceAttemptIdentity,
    SourceExecutionContext,
)
from app.orchestration.source_handlers.publications import (
    CERT_EU_SOURCE_SLUG,
    GOOGLE_SOURCE_SLUG,
    MANDIANT_SOURCE_SLUG,
    PublicationSourceHandler,
)


SLOT = datetime(2026, 8, 3, 8, 17, tzinfo=UTC)


def google_item(author: str, slug: str) -> str:
    return f"""
    <item>
      <title>{author} report</title>
      <author>{author}</author>
      <link>https://cloud.google.com/blog/topics/threat-intelligence/{slug}/</link>
      <guid>{slug}</guid>
      <pubDate>Sun, 03 Aug 2026 07:00:00 GMT</pubDate>
      <description>Safe public summary.</description>
    </item>
    """


def malformed_google_item(author: str, slug: str) -> str:
    return f"""
    <item>
      <author>{author}</author>
      <link>https://cloud.google.com/blog/topics/threat-intelligence/{slug}/</link>
      <guid>{slug}</guid>
    </item>
    """


def shared_feed(*items: str) -> bytes:
    return ("<rss><channel>" + "".join(items) + "</channel></rss>").encode()


CERT_FEED = b"""<rss><channel><item>
<title>CERT-EU advisory</title>
<link>https://cert.europa.eu/publications/security-advisories/2026-001/</link>
<guid>2026-001</guid>
<pubDate>Sun, 03 Aug 2026 07:00:00 GMT</pubDate>
</item></channel></rss>"""


class Rows:
    def scalars(self):
        return self

    def all(self):
        return []


class FakeSession:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def begin(self):
        return nullcontext()

    def execute(self, statement):
        del statement
        return Rows()

    def add(self, record):
        del record

    def flush(self):
        return None


class FeedClient:
    def __init__(self, feed_bytes):
        self.feed_bytes = feed_bytes
        self.closed = False

    def fetch_publications(self):
        return SimpleNamespace(feed_bytes=self.feed_bytes)

    def fetch_cert_eu_security_advisories(self):
        return SimpleNamespace(feed_bytes=self.feed_bytes)

    def close(self):
        self.closed = True


def context(source_slug):
    policy = SOURCE_POLICIES[source_slug]
    return SourceExecutionContext(
        policy=policy,
        attempt=SourceAttemptIdentity(source_slug, 1, 5, 0, 1),
        scheduled_for=SLOT,
        deployment_ref="alpha-data-ingestion-cycle",
        progress=None,
        quota=QuotaObservation(policy.quota_policy_key),
    )


def persisted(outcome="created"):
    return SimpleNamespace(
        outcome=outcome,
        source_record=None,
        intelligence_item_id=9,
    )


def test_cert_eu_fetches_fixed_feed_and_uses_rss_service(monkeypatch) -> None:
    captured = []

    class Service:
        def __init__(self, session):
            del session

        def persist(self, record, *, observed_at):
            captured.append((record.canonical_url, observed_at))
            return persisted()

    monkeypatch.setattr(
        "app.orchestration.source_handlers.publications.RssIngestionService",
        Service,
    )
    client = FeedClient(CERT_FEED)
    result = PublicationSourceHandler(
        CERT_EU_SOURCE_SLUG,
        session_factory=FakeSession,
        cert_client_factory=lambda: client,
    ).execute(context(CERT_EU_SOURCE_SLUG))

    assert result.status is ResultStatus.SUCCESS
    assert result.counters.created == 1
    assert captured == [
        (
            "https://cert.europa.eu/publications/security-advisories/2026-001/",
            SLOT,
        )
    ]
    assert client.closed is True


@pytest.mark.parametrize(
    ("active_slug", "expected_author"),
    [
        (GOOGLE_SOURCE_SLUG, "Google Threat Intelligence Group"),
        (MANDIANT_SOURCE_SLUG, "Mandiant"),
    ],
)
def test_shared_feed_persists_only_active_source(
    monkeypatch,
    active_slug,
    expected_author,
) -> None:
    captured = []

    class Pipeline:
        def __init__(self, session):
            del session

        def persist(self, candidate, *, observed_at):
            del observed_at
            captured.append(candidate)
            return persisted()

    monkeypatch.setattr(
        "app.orchestration.source_handlers.publications.PublicationPipeline",
        Pipeline,
    )
    feed = shared_feed(
        google_item("Google Threat Intelligence Group", "google-report"),
        google_item("Mandiant", "mandiant-report"),
    )
    result = PublicationSourceHandler(
        active_slug,
        session_factory=FakeSession,
        google_client_factory=lambda: FeedClient(feed),
    ).execute(context(active_slug))

    assert result.status is ResultStatus.SUCCESS
    assert len(captured) == 1
    assert captured[0].source_slug == active_slug
    assert captured[0].safe_source_payload["authoritative_author"] == expected_author
    assert result.counters.failed == 0
    assert result.progress_proposal is not None
    assert result.progress_proposal.value == SLOT


@pytest.mark.parametrize("active_slug", [GOOGLE_SOURCE_SLUG, MANDIANT_SOURCE_SLUG])
def test_unassigned_entry_is_rejected_without_poisoning_active_source(
    monkeypatch,
    active_slug,
) -> None:
    captured = []

    class Pipeline:
        def __init__(self, session):
            del session

        def persist(self, candidate, *, observed_at):
            del observed_at
            captured.append(candidate)
            return persisted()

    monkeypatch.setattr(
        "app.orchestration.source_handlers.publications.PublicationPipeline",
        Pipeline,
    )
    feed = shared_feed(
        google_item("Unapproved Author", "unassigned"),
    )

    result = PublicationSourceHandler(
        active_slug,
        session_factory=FakeSession,
        google_client_factory=lambda: FeedClient(feed),
    ).execute(context(active_slug))

    assert result.status is ResultStatus.NO_CHANGE
    assert result.counters.fetched == 0
    assert result.counters.failed == 0
    assert captured == []
    assert result.progress_proposal is not None
    assert result.progress_proposal.value == SLOT


@pytest.mark.parametrize(
    ("owner_slug", "other_slug", "author"),
    [
        (
            GOOGLE_SOURCE_SLUG,
            MANDIANT_SOURCE_SLUG,
            "Google Threat Intelligence Group",
        ),
        (MANDIANT_SOURCE_SLUG, GOOGLE_SOURCE_SLUG, "Mandiant"),
    ],
)
def test_attributable_malformed_entry_fails_only_owning_source(
    monkeypatch,
    owner_slug,
    other_slug,
    author,
) -> None:
    class Pipeline:
        def __init__(self, session):
            del session

        def persist(self, candidate, *, observed_at):
            del candidate, observed_at
            return persisted()

    monkeypatch.setattr(
        "app.orchestration.source_handlers.publications.PublicationPipeline",
        Pipeline,
    )
    malformed = malformed_google_item(author, "malformed-owner-record")
    feed = shared_feed(google_item(author, "valid-owner-record"), malformed)

    owner_result = PublicationSourceHandler(
        owner_slug,
        session_factory=FakeSession,
        google_client_factory=lambda: FeedClient(feed),
    ).execute(context(owner_slug))
    other_result = PublicationSourceHandler(
        other_slug,
        session_factory=FakeSession,
        google_client_factory=lambda: FeedClient(feed),
    ).execute(context(other_slug))
    failed_result = PublicationSourceHandler(
        owner_slug,
        session_factory=FakeSession,
        google_client_factory=lambda: FeedClient(shared_feed(malformed)),
    ).execute(context(owner_slug))

    assert owner_result.status is ResultStatus.PARTIAL
    assert owner_result.counters.created == 1
    assert owner_result.counters.failed == 1
    assert owner_result.progress_proposal is None
    assert other_result.status is ResultStatus.NO_CHANGE
    assert other_result.counters.fetched == 0
    assert other_result.counters.failed == 0
    assert other_result.progress_proposal is not None
    assert other_result.progress_proposal.value == SLOT
    assert failed_result.status is ResultStatus.FAILED
    assert failed_result.counters.failed == 1
    assert failed_result.progress_proposal is None


def test_unchanged_publication_advances_scheduled_watermark(monkeypatch) -> None:
    class Pipeline:
        def __init__(self, session):
            del session

        def persist(self, candidate, *, observed_at):
            del candidate, observed_at
            return persisted("unchanged")

    monkeypatch.setattr(
        "app.orchestration.source_handlers.publications.PublicationPipeline",
        Pipeline,
    )
    feed = shared_feed(
        google_item("Google Threat Intelligence Group", "unchanged")
    )

    result = PublicationSourceHandler(
        GOOGLE_SOURCE_SLUG,
        session_factory=FakeSession,
        google_client_factory=lambda: FeedClient(feed),
    ).execute(context(GOOGLE_SOURCE_SLUG))

    assert result.status is ResultStatus.NO_CHANGE
    assert result.counters.fetched == 1
    assert result.counters.unchanged == 1
    assert result.progress_proposal.value == SLOT


def test_duplicate_valid_records_are_deduplicated_before_persistence(monkeypatch) -> None:
    captured = []

    class Pipeline:
        def __init__(self, session):
            del session

        def persist(self, candidate, *, observed_at):
            del observed_at
            captured.append(candidate)
            return persisted("unchanged")

    monkeypatch.setattr(
        "app.orchestration.source_handlers.publications.PublicationPipeline",
        Pipeline,
    )
    item = google_item("Google Threat Intelligence Group", "duplicate")
    feed = shared_feed(item, item)

    result = PublicationSourceHandler(
        GOOGLE_SOURCE_SLUG,
        session_factory=FakeSession,
        google_client_factory=lambda: FeedClient(feed),
    ).execute(context(GOOGLE_SOURCE_SLUG))

    assert result.status is ResultStatus.NO_CHANGE
    assert result.counters.fetched == 1
    assert result.counters.unchanged == 1
    assert len(captured) == 1
    assert result.progress_proposal is not None


def test_shared_feed_over_record_bound_fails_closed_before_persistence(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.orchestration.source_handlers.publications.PublicationPipeline",
        lambda session: pytest.fail("persistence must not start"),
    )
    feed = shared_feed(
        *(
            google_item("Google Threat Intelligence Group", f"report-{index}")
            for index in range(101)
        )
    )
    handler = PublicationSourceHandler(
        GOOGLE_SOURCE_SLUG,
        session_factory=FakeSession,
        google_client_factory=lambda: FeedClient(feed),
    )

    with pytest.raises(ClassifiedFailure):
        handler.execute(context(GOOGLE_SOURCE_SLUG))


def test_malformed_feed_fails_before_persistence(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.orchestration.source_handlers.publications.PublicationPipeline",
        lambda session: pytest.fail("persistence must not start"),
    )
    handler = PublicationSourceHandler(
        GOOGLE_SOURCE_SLUG,
        session_factory=FakeSession,
        google_client_factory=lambda: FeedClient(b"\xff\xfe\x00bad"),
    )

    with pytest.raises(ClassifiedFailure):
        handler.execute(context(GOOGLE_SOURCE_SLUG))
