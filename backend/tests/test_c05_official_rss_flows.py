from dataclasses import replace
from datetime import UTC, datetime
import inspect
from pathlib import Path
from types import MappingProxyType

import httpx
import pytest

from app.ingestion.adapters.official_rss_publications import (
    adapt_official_rss_feed,
    build_official_rss_cursor,
    parse_official_rss_cursor,
)
from app.ingestion.collectors.official_rss_client import (
    C05_OFFICIAL_RSS_POLICIES,
    C05_OFFICIAL_RSS_SOURCE_SLUGS,
    OfficialRssClient,
    OfficialRssSourcePolicy,
)
from app.ingestion.publication_pipeline import PublicationBatchResult
from app.ingestion.source_registry import (
    ImplementationStatus,
    get_source_definition,
)
from app.orchestration.contracts import (
    ClassifiedFailure,
    EligibilityMode,
    ProgressKind,
    ProgressSnapshot,
    ProgressStorage,
    QuotaObservation,
    RetryPlan,
    SourceAttemptIdentity,
    SourceExecutionContext,
    SourcePolicy,
)
from app.orchestration.flows import DEFAULT_SOURCE_HANDLERS
from app.orchestration.source_handlers import C02_BOUND_SOURCE_SLUGS
import app.orchestration.source_handlers.official_rss as official_rss_module
from app.orchestration.source_handlers.official_rss import (
    OfficialRssSourceHandler,
    build_c05_official_rss_handlers,
)


SLOT = datetime(2026, 8, 5, tzinfo=UTC)
FIXTURES = Path(__file__).parent / "fixtures" / "c05"


def context(source_slug, *, progress_value=None):
    policy = SourcePolicy(
        source_slug=source_slug,
        eligibility_mode=EligibilityMode.DISABLED,
        source_concurrency_limit=1,
        retry_plan=RetryPlan(1, ()),
        stagger_seconds=0,
        quota_policy_key=f"{source_slug}.quota",
        progress_storage=ProgressStorage.CHECKPOINT,
        progress_kind=ProgressKind.SOURCE_CURSOR,
        execution_timeout_seconds=30,
    )
    return SourceExecutionContext(
        policy=policy,
        attempt=SourceAttemptIdentity(source_slug, 1, 1, 0, 1),
        scheduled_for=SLOT,
        deployment_ref="alpha-data-ingestion-cycle",
        progress=(
            None
            if progress_value is None
            else ProgressSnapshot(
                storage=ProgressStorage.CHECKPOINT,
                kind=ProgressKind.SOURCE_CURSOR,
                name=ProgressKind.SOURCE_CURSOR.value,
                value=progress_value,
                version=1,
            )
        ),
        quota=QuotaObservation(policy.quota_policy_key),
    )


def test_all_official_rss_sources_are_implemented_but_disabled_and_need_no_auth():
    assert C05_OFFICIAL_RSS_SOURCE_SLUGS == {
        "cert-fr-security-alerts",
        "cert-fr-security-advisories",
        "uk-ncsc-threat-reports",
    }
    for source_slug in C05_OFFICIAL_RSS_SOURCE_SLUGS:
        source = get_source_definition(source_slug)
        assert source.implementation_status is ImplementationStatus.IMPLEMENTED
        assert source.enabled is False
        assert source.authentication_required is False
        assert source.base_url == C05_OFFICIAL_RSS_POLICIES[source_slug].feed_url


def test_inactive_builder_is_separate_from_production_handlers():
    copied = MappingProxyType(dict(C05_OFFICIAL_RSS_POLICIES))
    handlers = build_c05_official_rss_handlers(copied)
    assert frozenset(handlers) == C05_OFFICIAL_RSS_SOURCE_SLUGS
    assert C05_OFFICIAL_RSS_SOURCE_SLUGS.isdisjoint(
        frozenset(DEFAULT_SOURCE_HANDLERS)
    )
    assert frozenset(DEFAULT_SOURCE_HANDLERS) == C02_BOUND_SOURCE_SLUGS
    assert all(isinstance(value, OfficialRssSourceHandler) for value in handlers.values())
    assert isinstance(
        OfficialRssSourceHandler(
            "cert-fr-security-alerts",
            policy_registry=copied,
        ),
        OfficialRssSourceHandler,
    )
    with pytest.raises(TypeError):
        handlers["other"] = next(iter(handlers.values()))  # type: ignore[index]


@pytest.mark.parametrize("source_slug", sorted(C05_OFFICIAL_RSS_SOURCE_SLUGS))
def test_disabled_execution_guard_rejects_before_client_or_network(source_slug):
    client_called = False

    def forbidden_client(registry):
        nonlocal client_called
        client_called = True
        raise AssertionError("network client must not be constructed")

    handler = OfficialRssSourceHandler(
        source_slug,
        client_factory=forbidden_client,
    )
    with pytest.raises(ClassifiedFailure, match="source identity"):
        handler.execute(context(source_slug))
    assert client_called is False


def test_handler_uses_one_transaction_and_never_fetches_linked_content():
    source = inspect.getsource(OfficialRssSourceHandler.execute)
    assert "session.begin()" in source
    assert "PublicationPipeline" in source
    assert "document.records_rejected == 0" in source
    assert ".commit(" not in source
    assert ".rollback(" not in source
    lowered = source.lower()
    assert "article request" not in lowered
    assert "pdf" not in lowered
    assert "enclosure" not in lowered
    assert "attachment" not in lowered


class _Transaction:
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        self.events.append("transaction_enter")
        return self

    def __exit__(self, exc_type, exc, traceback):
        del exc, traceback
        self.events.append(
            "transaction_rollback" if exc_type is not None else "transaction_commit"
        )
        return False


class _Session:
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        self.events.append("session_enter")
        return self

    def __exit__(self, exc_type, exc, traceback):
        del exc_type, exc, traceback
        self.events.append("session_exit")
        return False

    def begin(self):
        return _Transaction(self.events)

    def flush(self):
        self.events.append("flush")


def _batch(*, total, created=0, updated=0, unchanged=0, skipped=0, failed=0):
    return PublicationBatchResult(
        total=total,
        created=created,
        updated=updated,
        unchanged=unchanged,
        skipped=skipped,
        failed=failed,
        results=(),
    )


def _execute_with_dependencies(
    monkeypatch,
    document,
    batch,
    *,
    progress_value=None,
    pipeline_error=None,
    evidence_error=None,
):
    events = []
    requests = []

    def transport(request):
        events.append("network")
        requests.append(request)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/rss+xml"},
            stream=httpx.ByteStream(b"<rss><channel/></rss>"),
            request=request,
        )

    class Pipeline:
        def __init__(self, session):
            assert isinstance(session, _Session)
            assert "transaction_enter" in events

        def process_candidates(self, candidates, *, observed_at):
            del candidates, observed_at
            events.append("publication_pipeline")
            if pipeline_error is not None:
                raise pipeline_error
            return batch

    def persist_outcomes(session, **kwargs):
        del session, kwargs
        events.append("outcome_evidence")

    def persist_execution(session, **kwargs):
        del session, kwargs
        events.append("execution_evidence")
        if evidence_error is not None:
            raise evidence_error

    monkeypatch.setattr(official_rss_module, "validate_handler_context", lambda *a, **k: None)
    monkeypatch.setattr(official_rss_module, "load_execution_evidence", lambda *a, **k: None)
    monkeypatch.setattr(official_rss_module, "adapt_official_rss_feed", lambda *a, **k: document)
    monkeypatch.setattr(official_rss_module, "PublicationPipeline", Pipeline)
    monkeypatch.setattr(official_rss_module, "persist_outcome_evidence", persist_outcomes)
    monkeypatch.setattr(official_rss_module, "persist_execution_evidence", persist_execution)

    handler = OfficialRssSourceHandler(
        "cert-fr-security-alerts",
        session_factory=lambda: _Session(events),
        client_factory=lambda registry: OfficialRssClient(
            policy_registry=registry,
            http_transport=httpx.MockTransport(transport),
        ),
    )
    result = handler.execute(
        context("cert-fr-security-alerts", progress_value=progress_value)
    )
    events.append("handler_return")
    return result, events, requests


def _alert_document():
    return adapt_official_rss_feed(
        "cert-fr-security-alerts",
        (FIXTURES / "cert-fr-alerts.xml").read_bytes(),
    )


def test_executable_success_orders_network_transaction_commit_and_cursor(monkeypatch):
    document = _alert_document()
    result, events, requests = _execute_with_dependencies(
        monkeypatch,
        document,
        _batch(total=1, unchanged=1),
    )

    assert len(requests) == 1
    assert str(requests[0].url) == C05_OFFICIAL_RSS_POLICIES[
        "cert-fr-security-alerts"
    ].feed_url
    assert events.index("network") < events.index("transaction_enter")
    assert events.index("transaction_enter") < events.index("publication_pipeline")
    assert events.index("publication_pipeline") < events.index("execution_evidence")
    assert events.index("transaction_commit") < events.index("handler_return")
    assert result.progress_proposal is not None


def test_same_hash_skips_pipeline_and_returns_no_change_without_progress(monkeypatch):
    document = _alert_document()
    previous = build_official_rss_cursor(document)
    result, events, requests = _execute_with_dependencies(
        monkeypatch,
        document,
        _batch(total=1, unchanged=1),
        progress_value=previous,
    )
    assert len(requests) == 1
    assert "publication_pipeline" not in events
    assert result.status.value == "no_change"
    assert result.progress_proposal is None
    assert events.index("transaction_commit") < events.index("handler_return")


def test_partial_feed_runs_pipeline_but_returns_no_progress(monkeypatch):
    body = (FIXTURES / "cert-fr-alerts.xml").read_bytes().replace(
        b"CERT-FR</author>",
        b"x" * 201 + b"</author>",
    )
    document = adapt_official_rss_feed("cert-fr-security-alerts", body)
    result, events, _ = _execute_with_dependencies(
        monkeypatch,
        document,
        _batch(total=0),
    )
    assert "publication_pipeline" in events
    assert result.status.value == "partial"
    assert result.progress_proposal is None


@pytest.mark.parametrize("failure_site", ("pipeline", "evidence"))
def test_pipeline_or_evidence_failure_rolls_back_without_result_or_progress(
    monkeypatch,
    failure_site,
):
    document = _alert_document()
    events = []
    original_transaction = _Transaction.__exit__

    def record_exit(self, exc_type, exc, traceback):
        outcome = original_transaction(self, exc_type, exc, traceback)
        events.extend(self.events)
        return outcome

    monkeypatch.setattr(_Transaction, "__exit__", record_exit)
    kwargs = {
        "pipeline_error": RuntimeError("synthetic pipeline failure")
        if failure_site == "pipeline"
        else None,
        "evidence_error": RuntimeError("synthetic evidence failure")
        if failure_site == "evidence"
        else None,
    }
    with pytest.raises(ClassifiedFailure):
        _execute_with_dependencies(
            monkeypatch,
            document,
            _batch(total=1, unchanged=1),
            **kwargs,
        )
    assert "transaction_rollback" in events
    assert "handler_return" not in events


@pytest.mark.parametrize(
    ("current_timestamp", "expected_timestamp"),
    (
        (None, datetime(2026, 8, 4, 12, tzinfo=UTC)),
        (datetime(2026, 8, 3, 12, tzinfo=UTC), datetime(2026, 8, 4, 12, tzinfo=UTC)),
        (datetime(2026, 8, 5, 12, tzinfo=UTC), datetime(2026, 8, 5, 12, tzinfo=UTC)),
    ),
)
def test_changed_feed_cursor_retains_or_advances_greatest_timestamp(
    monkeypatch,
    current_timestamp,
    expected_timestamp,
):
    previous_timestamp = datetime(2026, 8, 4, 12, tzinfo=UTC)
    base = _alert_document()
    previous_document = replace(
        base,
        canonical_metadata_hash="a" * 64,
        greatest_publication_timestamp=previous_timestamp,
    )
    current_document = replace(
        base,
        canonical_metadata_hash="b" * 64,
        greatest_publication_timestamp=current_timestamp,
    )
    result, events, _ = _execute_with_dependencies(
        monkeypatch,
        current_document,
        _batch(total=len(current_document.candidates), unchanged=len(current_document.candidates)),
        progress_value=build_official_rss_cursor(previous_document),
    )
    assert result.progress_proposal is not None
    current_hash, timestamp = parse_official_rss_cursor(
        result.progress_proposal.value
    )
    assert current_hash == "b" * 64
    assert timestamp == expected_timestamp
    assert events.index("transaction_commit") < events.index("handler_return")


def test_changed_empty_feed_with_both_timestamps_absent_uses_dash(monkeypatch):
    document = adapt_official_rss_feed(
        "cert-fr-security-alerts",
        b"<rss><channel/></rss>",
    )
    result, _, _ = _execute_with_dependencies(
        monkeypatch,
        document,
        _batch(total=0),
    )
    assert result.progress_proposal is not None
    assert result.progress_proposal.value.endswith(":-")


def test_handler_and_builder_reject_altered_endpoint_policy_before_client():
    policies = dict(C05_OFFICIAL_RSS_POLICIES)
    policies["cert-fr-security-alerts"] = replace(
        policies["cert-fr-security-alerts"],
        feed_url="https://substituted.invalid/alerte/feed/",
        feed_host="substituted.invalid",
    )
    altered = MappingProxyType(policies)
    client_called = False

    def forbidden_client(registry):
        nonlocal client_called
        client_called = True
        raise AssertionError("client must not be constructed")

    with pytest.raises(ValueError, match="handler policy registry"):
        OfficialRssSourceHandler(
            "cert-fr-security-alerts",
            policy_registry=altered,
            client_factory=forbidden_client,
        )
    with pytest.raises(ValueError, match="handler policy registry"):
        build_c05_official_rss_handlers(
            altered,
            client_factory=forbidden_client,
        )
    assert client_called is False


class _AlwaysEqualHandlerRssPolicy(OfficialRssSourcePolicy):
    def __eq__(self, other):
        del other
        return True


class _HandlerStringSubclass(str):
    pass


@pytest.mark.parametrize("kind", ("policy_subclass", "key_subclass"))
def test_handler_and_builder_reject_adversarial_policy_types_before_client(kind):
    policies = dict(C05_OFFICIAL_RSS_POLICIES)
    canonical = policies["cert-fr-security-alerts"]
    if kind == "policy_subclass":
        policies["cert-fr-security-alerts"] = _AlwaysEqualHandlerRssPolicy(
            source_slug=canonical.source_slug,
            feed_url="https://evil.example/feed",
            feed_host="evil.example",
            feed_path="/feed",
            canonical_hosts=canonical.canonical_hosts,
            canonical_kind=canonical.canonical_kind,
            source_language=canonical.source_language,
        )
    else:
        del policies["cert-fr-security-alerts"]
        policies[_HandlerStringSubclass("cert-fr-security-alerts")] = canonical
    registry = MappingProxyType(policies)
    client_called = False

    def forbidden_client(approved):
        nonlocal client_called
        client_called = True
        raise AssertionError("client must not be constructed")

    with pytest.raises(ValueError, match="handler policy registry"):
        OfficialRssSourceHandler(
            "cert-fr-security-alerts",
            policy_registry=registry,
            client_factory=forbidden_client,
        )
    with pytest.raises(ValueError, match="handler policy registry"):
        build_c05_official_rss_handlers(
            registry,
            client_factory=forbidden_client,
        )
    assert client_called is False
