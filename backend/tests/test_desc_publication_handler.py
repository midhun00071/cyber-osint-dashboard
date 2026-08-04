from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from types import SimpleNamespace

import pytest

from app.ingestion.collectors.desc_publications_client import (
    DescCollectionResult,
    DescPublicationSource,
    DescRejectionCategory,
)
from app.ingestion.publication_pipeline import PublicationCandidate
from app.orchestration.contracts import (
    ClassifiedFailure,
    EligibilityMode,
    ProgressKind,
    ProgressStorage,
    QuotaObservation,
    ReconciledCounters,
    ResultStatus,
    RetryPlan,
    SafeMetrics,
    SourceAttemptIdentity,
    SourceExecutionContext,
    SourceExecutionResult,
    SourcePolicy,
    SOURCE_POLICIES,
)
from app.orchestration.flows import DEFAULT_SOURCE_HANDLERS
from app.orchestration.source_handlers import desc_publications as module
from app.orchestration.source_handlers.desc_publications import (
    DESC_NEWS_SOURCE_SLUG,
    DESC_PUBLICATION_SOURCE_SLUGS,
    DESC_RESEARCH_SOURCE_SLUG,
    DescPublicationSourceHandler,
)


SLOT = datetime(2026, 8, 4, 8, 17, tzinfo=UTC)


def policy(slug: str) -> SourcePolicy:
    return SourcePolicy(
        source_slug=slug,
        eligibility_mode=EligibilityMode.APPROVAL_REQUIRED,
        source_concurrency_limit=1,
        retry_plan=RetryPlan(3, (30, 60)),
        stagger_seconds=0,
        quota_policy_key=f"{slug}.controlled",
        progress_storage=ProgressStorage.WATERMARK,
        progress_kind=ProgressKind.MODIFIED_SINCE,
        execution_timeout_seconds=900,
    )


def context(slug: str, *, run_id: int = 5) -> SourceExecutionContext:
    selected = policy(slug)
    return SourceExecutionContext(
        policy=selected,
        attempt=SourceAttemptIdentity(slug, 1, run_id, 0, 1),
        scheduled_for=SLOT,
        deployment_ref="desc-controlled-fixture",
        progress=None,
        quota=QuotaObservation(selected.quota_policy_key),
    )


def news_candidate() -> PublicationCandidate:
    return PublicationCandidate(
        source_slug=DESC_NEWS_SOURCE_SLUG,
        source_external_id="desc-news:safe-news",
        canonical_title="Safe DESC News",
        canonical_url="https://www.desc.gov.ae/safe-news/",
        summary="Safe listing summary.",
        source_published_at=SLOT,
        safe_source_payload={"category": "DESC News"},
    )


def research_candidate() -> PublicationCandidate:
    url = "https://dl.acm.org/doi/10.1145/123"
    return PublicationCandidate(
        source_slug=DESC_RESEARCH_SOURCE_SLUG,
        source_external_id="desc-published-research:"
        + sha256(url.encode("utf-8")).hexdigest(),
        canonical_title="Safe Research",
        canonical_url=url,
        summary="Journal statement. Publishers: DESC.",
        safe_source_payload={
            "publication_statement": "Journal statement.",
            "publishers": "DESC",
            "publication_host": "dl.acm.org",
            "category": "DESC Published Research",
        },
    )


class Rows:
    def scalars(self):
        return self

    def all(self):
        return []


class Transaction:
    def __init__(self, session: "FakeSession") -> None:
        self.session = session

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, traceback):
        del error, traceback
        if error_type is not None:
            self.session.rolled_back = True
        else:
            self.session.committed = True
        return False


class FakeSession:
    last: "FakeSession | None" = None

    def __init__(self):
        self.added: list[object] = []
        self.flushed = False
        self.committed = False
        self.rolled_back = False
        FakeSession.last = self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def begin(self):
        return Transaction(self)

    def execute(self, statement):
        del statement
        return Rows()

    def add(self, item):
        self.added.append(item)

    def flush(self):
        self.flushed = True


class Client:
    def __init__(self, result: DescCollectionResult):
        self.result = result
        self.closed = False
        self.fetches = 0

    def fetch(self):
        self.fetches += 1
        return self.result

    def close(self):
        self.closed = True


def collection(slug: str, *, rejected: int = 0) -> DescCollectionResult:
    source = DescPublicationSource.NEWS if slug == DESC_NEWS_SOURCE_SLUG else DescPublicationSource.PUBLISHED_RESEARCH
    candidate = news_candidate() if source is DescPublicationSource.NEWS else research_candidate()
    return DescCollectionResult(
        source=source,
        source_slug=slug,
        candidates=(candidate,),
        rejected_record_count=rejected,
        rejection_categories=((DescRejectionCategory.STRUCTURE,) if rejected else ()),
        fetched_listing_page_count=1,
        record_limit_exceeded=False,
    )


def forged_collection(**overrides: object) -> DescCollectionResult:
    values: dict[str, object] = {
        "source": DescPublicationSource.NEWS,
        "source_slug": DESC_NEWS_SOURCE_SLUG,
        "candidates": (news_candidate(),),
        "rejected_record_count": 0,
        "rejection_categories": (),
        "fetched_listing_page_count": 1,
        "record_limit_exceeded": False,
    }
    values.update(overrides)
    result = object.__new__(DescCollectionResult)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def persisted(outcome: str = "created"):
    return SimpleNamespace(outcome=outcome, source_record=None, intelligence_item_id=9)


def test_invalid_source_slug_is_rejected() -> None:
    with pytest.raises(ValueError):
        DescPublicationSourceHandler("ae-cert")


def test_context_source_mismatch_is_rejected_before_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: pytest.fail("approval must not run"))
    with pytest.raises(ClassifiedFailure) as exc_info:
        DescPublicationSourceHandler(
            DESC_NEWS_SOURCE_SLUG,
            session_factory=FakeSession,
        ).execute(context(DESC_RESEARCH_SOURCE_SLUG))
    assert exc_info.value.category.value == "invalid_source_policy"


def test_pending_approval_constructs_no_client_and_persists_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: False)
    constructed = []
    handler = DescPublicationSourceHandler(
        DESC_NEWS_SOURCE_SLUG,
        session_factory=FakeSession,
        client_factory=lambda selector: constructed.append(selector),  # type: ignore[arg-type,return-value]
    )
    with pytest.raises(ClassifiedFailure) as exc_info:
        handler.execute(context(DESC_NEWS_SOURCE_SLUG))
    assert exc_info.value.category.value == "approval_requirement"
    assert constructed == []


@pytest.mark.parametrize("slug", [DESC_NEWS_SOURCE_SLUG, DESC_RESEARCH_SOURCE_SLUG])
def test_approved_mocked_result_persists_and_proposes_progress(monkeypatch: pytest.MonkeyPatch, slug: str) -> None:
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda value: True)
    outcomes: list[PublicationCandidate] = []
    class Pipeline:
        def __init__(self, session):
            del session
        def persist(self, candidate, *, observed_at):
            assert observed_at == SLOT
            outcomes.append(candidate)
            return persisted()
    monkeypatch.setattr(module, "PublicationPipeline", Pipeline)
    client = Client(collection(slug))
    result = DescPublicationSourceHandler(
        slug, session_factory=FakeSession, client_factory=lambda selector: client
    ).execute(context(slug))

    assert result.status is ResultStatus.SUCCESS
    assert result.counters == ReconciledCounters(fetched=1, created=1)
    assert result.progress_proposal.value == SLOT
    assert outcomes[0].source_slug == slug
    assert client.fetches == 1 and client.closed is True
    assert FakeSession.last is not None and FakeSession.last.committed is True
    assert FakeSession.last.flushed is True


def test_rejected_records_produce_truthful_partial_without_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: True)
    class Pipeline:
        def __init__(self, session):
            del session
        def persist(self, candidate, *, observed_at):
            del candidate, observed_at
            return persisted()
    monkeypatch.setattr(module, "PublicationPipeline", Pipeline)
    result = DescPublicationSourceHandler(
        DESC_NEWS_SOURCE_SLUG,
        session_factory=FakeSession,
        client_factory=lambda selector: Client(collection(DESC_NEWS_SOURCE_SLUG, rejected=2)),
    ).execute(context(DESC_NEWS_SOURCE_SLUG))
    assert result.status is ResultStatus.PARTIAL
    assert result.counters.created == 1 and result.counters.failed == 2
    assert result.progress_proposal is None


def test_capped_collection_is_partial_and_never_proposes_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: True)
    class Pipeline:
        def __init__(self, session):
            del session
        def persist(self, candidate, *, observed_at):
            del candidate, observed_at
            return persisted()
    monkeypatch.setattr(module, "PublicationPipeline", Pipeline)
    capped = DescCollectionResult(
        source=DescPublicationSource.NEWS,
        source_slug=DESC_NEWS_SOURCE_SLUG,
        candidates=(news_candidate(),),
        rejected_record_count=1,
        rejection_categories=(DescRejectionCategory.RECORD_LIMIT,),
        fetched_listing_page_count=1,
        record_limit_exceeded=True,
    )
    result = DescPublicationSourceHandler(
        DESC_NEWS_SOURCE_SLUG,
        session_factory=FakeSession,
        client_factory=lambda selector: Client(capped),
    ).execute(context(DESC_NEWS_SOURCE_SLUG))
    assert result.status is ResultStatus.PARTIAL
    assert result.counters.created == 1 and result.counters.failed == 1
    assert result.progress_proposal is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"rejected_record_count": -5},
        {"rejected_record_count": True},
        {"rejected_record_count": "5"},
        {"rejected_record_count": 1, "record_limit_exceeded": True, "rejection_categories": ()},
        {"rejected_record_count": 1, "record_limit_exceeded": False, "rejection_categories": (DescRejectionCategory.RECORD_LIMIT,)},
        {"rejected_record_count": 0, "record_limit_exceeded": True, "rejection_categories": (DescRejectionCategory.RECORD_LIMIT,)},
        {"rejected_record_count": 1, "rejection_categories": ()},
        {"rejected_record_count": 0, "rejection_categories": (DescRejectionCategory.STRUCTURE,)},
        {"source_slug": DESC_RESEARCH_SOURCE_SLUG},
        {"candidates": [news_candidate()]},
        {"candidates": (news_candidate(), news_candidate())},
        {"candidates": tuple(replace(news_candidate(), source_external_id=f"desc-news:item-{index}") for index in range(51))},
        {"candidates": (replace(news_candidate(), source_slug=DESC_RESEARCH_SOURCE_SLUG),)},
        {"rejection_categories": [DescRejectionCategory.STRUCTURE]},
        {"rejected_record_count": 2, "rejection_categories": (DescRejectionCategory.STRUCTURE, DescRejectionCategory.STRUCTURE)},
        {"fetched_listing_page_count": 2},
        {"fetched_listing_page_count": True},
        {"record_limit_exceeded": 1},
    ],
)
def test_handler_rejects_forged_collection_before_persistence(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
) -> None:
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: True)
    monkeypatch.setattr(
        module,
        "PublicationPipeline",
        lambda session: pytest.fail("persistence must not start"),
    )
    client = Client(forged_collection(**overrides))
    with pytest.raises(ClassifiedFailure) as exc_info:
        DescPublicationSourceHandler(
            DESC_NEWS_SOURCE_SLUG,
            session_factory=FakeSession,
            client_factory=lambda selector: client,
        ).execute(context(DESC_NEWS_SOURCE_SLUG))
    assert exc_info.value.category.value == "contract_violation"
    assert "-5" not in str(exc_info.value)
    assert client.closed is True
    assert FakeSession.last is not None
    assert FakeSession.last.added == []
    assert FakeSession.last.flushed is False


@pytest.mark.parametrize(
    ("outcome", "status"),
    [("updated", ResultStatus.SUCCESS), ("unchanged", ResultStatus.NO_CHANGE)],
)
def test_updated_and_unchanged_counters_are_reconciled(
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
    status: ResultStatus,
) -> None:
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: True)
    class Pipeline:
        def __init__(self, session):
            del session
        def persist(self, candidate, *, observed_at):
            del candidate, observed_at
            return persisted(outcome)
    monkeypatch.setattr(module, "PublicationPipeline", Pipeline)
    result = DescPublicationSourceHandler(
        DESC_NEWS_SOURCE_SLUG,
        session_factory=FakeSession,
        client_factory=lambda selector: Client(collection(DESC_NEWS_SOURCE_SLUG)),
    ).execute(context(DESC_NEWS_SOURCE_SLUG))
    assert result.status is status
    assert getattr(result.counters, outcome) == 1
    assert result.progress_proposal is not None


def test_persistence_failure_rolls_back_and_does_not_return_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: True)
    class Pipeline:
        def __init__(self, session):
            del session
        def persist(self, candidate, *, observed_at):
            del candidate, observed_at
            raise RuntimeError("private failure")
    monkeypatch.setattr(module, "PublicationPipeline", Pipeline)
    with pytest.raises(ClassifiedFailure) as exc_info:
        DescPublicationSourceHandler(
            DESC_NEWS_SOURCE_SLUG,
            session_factory=FakeSession,
            client_factory=lambda selector: Client(collection(DESC_NEWS_SOURCE_SLUG)),
        ).execute(context(DESC_NEWS_SOURCE_SLUG))
    assert "private" not in str(exc_info.value)
    assert FakeSession.last is not None and FakeSession.last.rolled_back is True


def test_committed_execution_replay_precedes_approval_and_network(monkeypatch: pytest.MonkeyPatch) -> None:
    replay = SourceExecutionResult(
        source_slug=DESC_NEWS_SOURCE_SLUG,
        status=ResultStatus.NO_CHANGE,
        counters=ReconciledCounters(),
        metrics=SafeMetrics(),
    )
    monkeypatch.setattr(module, "load_execution_evidence", lambda factory, ctx: replay)
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: pytest.fail("approval must not be rechecked"))
    result = DescPublicationSourceHandler(
        DESC_NEWS_SOURCE_SLUG,
        session_factory=FakeSession,
        client_factory=lambda selector: pytest.fail("network must not be opened"),
    ).execute(context(DESC_NEWS_SOURCE_SLUG))
    assert result is replay


def test_desc_sources_are_not_automatically_bound_or_policy_enabled() -> None:
    assert DESC_PUBLICATION_SOURCE_SLUGS.isdisjoint(DEFAULT_SOURCE_HANDLERS)
    assert DESC_PUBLICATION_SOURCE_SLUGS.isdisjoint(SOURCE_POLICIES)
