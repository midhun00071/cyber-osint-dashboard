from dataclasses import fields, replace
from datetime import UTC, datetime
import logging
from pathlib import Path
from types import MappingProxyType

import httpx
import pytest

from app.ingestion.source_registry import get_source_definition
from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    ApprovedTaxiiCollectionPolicy,
    C05_IMPLEMENTED_TAXII_COLLECTION_POLICIES,
    MITRE_ATTACK_CUSTOM_PROPERTIES,
    MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
    MITRE_ATTACK_ENTERPRISE_TAXII_POLICY,
    PRODUCTION_TAXII_COLLECTION_POLICIES,
    build_taxii_policy_registry,
)
from app.ingestion.stix_taxii.stix_validation import StixValidationError
from app.ingestion.stix_taxii.import_service import StixImportResult
from app.ingestion.stix_taxii.taxii_client import (
    ACCEPT_HEADER,
    TaxiiCollectionClient,
    TaxiiConfigurationError,
    TaxiiHttpStatusError,
    TaxiiPaginationError,
    TaxiiRateLimitError,
)
from app.orchestration.flows import DEFAULT_SOURCE_HANDLERS
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
import app.orchestration.source_handlers.stix_taxii as stix_handler_module
from app.orchestration.source_handlers.stix_taxii import (
    MitreAttackSourceHandler,
    build_c05_mitre_attack_handlers,
)


FIXTURES = Path(__file__).parent / "fixtures" / "c05"
SLOT = datetime(2026, 8, 5, tzinfo=UTC)


def response(request, body, *, boundary=None, status=200):
    headers = {"Content-Type": ACCEPT_HEADER}
    if boundary is not None:
        headers["X-TAXII-Date-Added-Last"] = boundary
    return httpx.Response(
        status,
        headers=headers,
        stream=httpx.ByteStream(body),
        request=request,
    )


def test_fixed_mitre_policy_identity_limits_and_inactive_registration():
    source = get_source_definition("mitre-attack-enterprise")
    policy = MITRE_ATTACK_ENTERPRISE_TAXII_POLICY
    assert source.enabled is False
    assert source.authentication_required is False
    assert source.base_url == policy.objects_endpoint
    assert policy.api_root_url == "https://attack-taxii.mitre.org/api/v21"
    assert policy.collection_id == (
        "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
    )
    assert policy.collection_title == "Enterprise ATT&CK"
    assert policy.authentication_allowed is False
    assert policy.maximum_response_bytes == 8 * 1024 * 1024
    assert policy.maximum_total_response_bytes == 64 * 1024 * 1024
    assert policy.maximum_pages == policy.maximum_requests == 40
    assert policy.maximum_total_objects == 30_000
    assert policy.stix_policy.maximum_relationships == 20_000
    assert policy.stix_policy.maximum_json_depth == 24
    assert policy.stix_policy.maximum_json_nodes == 2_000_000
    assert policy.stix_policy.maximum_json_string_length == 50_000
    assert policy.stix_policy.maximum_aliases == 100
    assert policy.stix_policy.maximum_external_references == 25
    assert policy.stix_policy.allowed_custom_properties == MITRE_ATTACK_CUSTOM_PROPERTIES
    assert dict(PRODUCTION_TAXII_COLLECTION_POLICIES) == {}
    assert dict(DEFAULT_SOURCE_HANDLERS) == {}


def test_two_page_fixture_uses_fixed_filters_opaque_next_and_server_cursor():
    first = (FIXTURES / "mitre-enterprise-page-1.json").read_bytes()
    second = (FIXTURES / "mitre-enterprise-page-2.json").read_bytes()
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return response(
                request,
                first,
                boundary="2026-08-04T01:00:00Z",
            )
        return response(
            request,
            second,
            boundary="2026-08-04T02:00:00.123456Z",
        )

    client = TaxiiCollectionClient(
        policy_registry=MappingProxyType(
            dict(C05_IMPLEMENTED_TAXII_COLLECTION_POLICIES)
        ),
        http_transport=httpx.MockTransport(handler),
    )
    assert (
        client._policy_registry["mitre-attack-enterprise"]
        is MITRE_ATTACK_ENTERPRISE_TAXII_POLICY
    )
    result = client.collect("mitre-attack-enterprise")

    fixed = list(MITRE_ATTACK_ENTERPRISE_TAXII_POLICY.fixed_query_parameters)
    assert list(requests[0].url.params.multi_items()) == fixed
    assert list(requests[1].url.params.multi_items()) == fixed + [
        ("next", "c05-enterprise-page-2")
    ]
    assert all(request.method == "GET" for request in requests)
    assert all(request.url.host == "attack-taxii.mitre.org" for request in requests)
    assert all(request.headers["accept"] == ACCEPT_HEADER for request in requests)
    assert all("authorization" not in request.headers for request in requests)
    assert all("cookie" not in request.headers for request in requests)
    assert result.pages_collected == 2
    assert result.objects_received == result.objects_validated == 8
    assert result.greatest_server_date_added == "2026-08-04T02:00:00.123456Z"
    intrusion = next(
        item
        for item in result.validated_document.objects
        if item.stix_type == "intrusion-set"
    )
    assert intrusion.safe_payload["aliases"] == ("SEG", "Synthetic Group")
    attack_pattern = next(
        item
        for item in result.validated_document.objects
        if item.stix_type == "attack-pattern"
    )
    assert attack_pattern.safe_payload["external_references"] == (
        MappingProxyType({"source_name": "mitre-attack", "external_id": "T1234"}),
    )
    assert "url" not in str(attack_pattern.safe_payload)


def test_incremental_request_adds_exact_added_after_to_every_page():
    first = (FIXTURES / "mitre-enterprise-page-1.json").read_bytes()
    second = (FIXTURES / "mitre-enterprise-page-2.json").read_bytes()
    requests = []

    def handler(request):
        requests.append(request)
        body = first if len(requests) == 1 else second
        return response(request, body, boundary="2026-08-05T00:00:00Z")

    cursor = "2026-08-04T00:00:00.000000Z"
    TaxiiCollectionClient(
        policy_registry=C05_IMPLEMENTED_TAXII_COLLECTION_POLICIES,
        http_transport=httpx.MockTransport(handler),
    ).collect_incremental("mitre-attack-enterprise", added_after=cursor)
    fixed = list(MITRE_ATTACK_ENTERPRISE_TAXII_POLICY.fixed_query_parameters)
    assert list(requests[0].url.params.multi_items()) == fixed + [
        ("added_after", cursor)
    ]
    assert list(requests[1].url.params.multi_items()) == fixed + [
        ("added_after", cursor),
        ("next", "c05-enterprise-page-2"),
    ]


def test_authentication_is_prohibited_before_transport():
    called = False

    def handler(request):
        nonlocal called
        called = True
        return response(request, b"{}")

    client = TaxiiCollectionClient(
        policy_registry=C05_IMPLEMENTED_TAXII_COLLECTION_POLICIES,
        http_transport=httpx.MockTransport(handler),
        auth=httpx.BasicAuth("synthetic", "secret"),
    )
    with pytest.raises(TaxiiConfigurationError, match="prohibited"):
        client.collect("mitre-attack-enterprise")
    assert called is False


def test_429_and_later_page_failure_are_not_retried():
    calls = 0

    def limited(request):
        nonlocal calls
        calls += 1
        return response(request, b"{}", status=429)

    client = TaxiiCollectionClient(
        policy_registry=C05_IMPLEMENTED_TAXII_COLLECTION_POLICIES,
        http_transport=httpx.MockTransport(limited),
    )
    with pytest.raises(TaxiiRateLimitError):
        client.collect("mitre-attack-enterprise")
    assert calls == 1

    calls = 0
    first = (FIXTURES / "mitre-enterprise-page-1.json").read_bytes()

    def later_failure(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return response(request, first)
        return response(request, b"{}", status=503)

    client = TaxiiCollectionClient(
        policy_registry=C05_IMPLEMENTED_TAXII_COLLECTION_POLICIES,
        http_transport=httpx.MockTransport(later_failure),
    )
    with pytest.raises(TaxiiHttpStatusError):
        client.collect("mitre-attack-enterprise")
    assert calls == 2


def test_repeated_or_oversized_continuation_tokens_fail_closed():
    first = (FIXTURES / "mitre-enterprise-page-1.json").read_bytes()
    calls = 0

    def repeated(request):
        nonlocal calls
        calls += 1
        body = (
            first
            if calls == 1
            else first.replace(
                b"identity--11111111-1111-4111-8111-111111111111",
                b"identity--99999999-9999-4999-8999-999999999999",
            )
        )
        return response(request, body)

    with pytest.raises(TaxiiPaginationError, match="token"):
        TaxiiCollectionClient(
            policy_registry=C05_IMPLEMENTED_TAXII_COLLECTION_POLICIES,
            http_transport=httpx.MockTransport(repeated),
        ).collect("mitre-attack-enterprise")

    oversized = first.replace(
        b"c05-enterprise-page-2",
        b"x" * 1025,
    )
    with pytest.raises(TaxiiPaginationError):
        TaxiiCollectionClient(
            policy_registry=C05_IMPLEMENTED_TAXII_COLLECTION_POLICIES,
            http_transport=httpx.MockTransport(
                lambda request: response(request, oversized)
            ),
        ).collect("mitre-attack-enterprise")


def test_inactive_handler_builder_is_separate_and_immutable():
    handlers = build_c05_mitre_attack_handlers()
    assert tuple(handlers) == ("mitre-attack-enterprise",)
    assert isinstance(handlers["mitre-attack-enterprise"], MitreAttackSourceHandler)
    with pytest.raises(TypeError):
        handlers["other"] = handlers["mitre-attack-enterprise"]  # type: ignore[index]


@pytest.mark.parametrize(
    "altered",
    (
        replace(
            MITRE_ATTACK_ENTERPRISE_TAXII_POLICY,
            api_root_url="https://substituted.invalid/api/v21",
        ),
        replace(
            MITRE_ATTACK_ENTERPRISE_TAXII_POLICY,
            collection_id="substituted-collection",
        ),
        replace(
            MITRE_ATTACK_ENTERPRISE_TAXII_POLICY,
            fixed_query_parameters=(("limit", "999"),),
        ),
        replace(
            MITRE_ATTACK_ENTERPRISE_TAXII_POLICY,
            authentication_allowed=True,
        ),
        replace(
            MITRE_ATTACK_ENTERPRISE_TAXII_POLICY,
            maximum_requests=39,
        ),
        replace(
            MITRE_ATTACK_ENTERPRISE_TAXII_POLICY,
            stix_policy=replace(
                MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
                maximum_aliases=99,
            ),
        ),
    ),
)
def test_altered_same_slug_mitre_policy_fails_before_transport(altered, caplog):
    called = False

    def forbidden_transport(request):
        nonlocal called
        called = True
        raise AssertionError("transport must not run")

    registry = MappingProxyType({"mitre-attack-enterprise": altered})
    with pytest.raises(TaxiiConfigurationError) as caught:
        TaxiiCollectionClient(
            policy_registry=registry,
            http_transport=httpx.MockTransport(forbidden_transport),
        )
    assert called is False
    assert str(caught.value) == "The TAXII policy registry is invalid."
    assert "substituted.invalid" not in str(caught.value)
    assert "substituted.invalid" not in caplog.text

    with pytest.raises(ValueError, match="MITRE ATT&CK handler policy"):
        MitreAttackSourceHandler(
            "mitre-attack-enterprise",
            policy_registry=registry,
        )


def test_c05_builder_rejects_missing_or_additional_mitre_policy_entries():
    with pytest.raises(ValueError, match="C05 TAXII handler policy"):
        build_c05_mitre_attack_handlers(MappingProxyType({}))
    additional = MappingProxyType(
        {
            **dict(C05_IMPLEMENTED_TAXII_COLLECTION_POLICIES),
            "synthetic": MITRE_ATTACK_ENTERPRISE_TAXII_POLICY,
        }
    )
    with pytest.raises(ValueError, match="C05 TAXII handler policy"):
        build_c05_mitre_attack_handlers(additional)


def _context(*, progress_value=None):
    policy = SourcePolicy(
        source_slug="mitre-attack-enterprise",
        eligibility_mode=EligibilityMode.DISABLED,
        source_concurrency_limit=1,
        retry_plan=RetryPlan(1, ()),
        stagger_seconds=0,
        quota_policy_key="mitre-attack-enterprise.quota",
        progress_storage=ProgressStorage.CHECKPOINT,
        progress_kind=ProgressKind.SOURCE_CURSOR,
        execution_timeout_seconds=600,
    )
    return SourceExecutionContext(
        policy=policy,
        attempt=SourceAttemptIdentity("mitre-attack-enterprise", 1, 1, 0, 1),
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


class _MitreTransaction:
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


class _MitreSession:
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
        return _MitreTransaction(self.events)

    def flush(self):
        self.events.append("flush")


def _mitre_handler_dependencies(
    monkeypatch,
    *,
    boundary="2026-08-05T02:00:00.000000Z",
    import_error=None,
    evidence_error=None,
):
    events = []
    requests = []
    first = (FIXTURES / "mitre-enterprise-page-1.json").read_bytes()
    second = (FIXTURES / "mitre-enterprise-page-2.json").read_bytes()

    def transport(request):
        events.append("network")
        requests.append(request)
        body = first if len(requests) == 1 else second
        return response(request, body, boundary=boundary)

    class Importer:
        def __init__(self, session):
            assert isinstance(session, _MitreSession)
            assert "transaction_enter" in events

        def import_document(self, source_id, policy, document, *, observed_at):
            del source_id, policy, observed_at
            events.append("import")
            if import_error is not None:
                raise import_error
            return StixImportResult(
                status="processed",
                objects_received=document.objects_received,
                objects_validated=document.objects_validated,
            )

    def persist_outcomes(session, **kwargs):
        del session, kwargs
        events.append("outcome_evidence")

    def persist_execution(session, **kwargs):
        del session, kwargs
        events.append("execution_evidence")
        if evidence_error is not None:
            raise evidence_error

    monkeypatch.setattr(stix_handler_module, "validate_handler_context", lambda *a, **k: None)
    monkeypatch.setattr(stix_handler_module, "load_execution_evidence", lambda *a, **k: None)
    monkeypatch.setattr(stix_handler_module, "_source_id_for_slug", lambda *a, **k: 7)
    monkeypatch.setattr(stix_handler_module, "StixBundleImportService", Importer)
    monkeypatch.setattr(stix_handler_module, "persist_outcome_evidence", persist_outcomes)
    monkeypatch.setattr(stix_handler_module, "persist_execution_evidence", persist_execution)

    handler = MitreAttackSourceHandler(
        "mitre-attack-enterprise",
        policy_registry=C05_IMPLEMENTED_TAXII_COLLECTION_POLICIES,
        session_factory=lambda: _MitreSession(events),
        client_factory=lambda registry: TaxiiCollectionClient(
            policy_registry=registry,
            http_transport=httpx.MockTransport(transport),
        ),
    )
    return handler, events, requests


def test_executable_mitre_handler_returns_cursor_only_after_transaction_exit(
    monkeypatch,
):
    handler, events, requests = _mitre_handler_dependencies(monkeypatch)
    result = handler.execute(_context())
    events.append("handler_return")

    assert len(requests) == 2
    assert events.index("network") < events.index("transaction_enter")
    assert events.index("transaction_enter") < events.index("import")
    assert events.index("import") < events.index("execution_evidence")
    assert events.index("transaction_commit") < events.index("handler_return")
    assert result.progress_proposal is not None
    assert result.progress_proposal.value == "2026-08-05T02:00:00.000000Z"


def test_equal_mitre_cursor_returns_no_progress_proposal(monkeypatch):
    cursor = "2026-08-05T02:00:00.000000Z"
    handler, events, _ = _mitre_handler_dependencies(
        monkeypatch,
        boundary=cursor,
    )
    result = handler.execute(_context(progress_value=cursor))
    events.append("handler_return")
    assert result.progress_proposal is None
    assert events.index("transaction_commit") < events.index("handler_return")


@pytest.mark.parametrize("failure_site", ("import", "evidence"))
def test_mitre_import_or_evidence_failure_rolls_back_without_result_or_cursor(
    monkeypatch,
    failure_site,
):
    handler, events, _ = _mitre_handler_dependencies(
        monkeypatch,
        import_error=RuntimeError("synthetic import failure")
        if failure_site == "import"
        else None,
        evidence_error=RuntimeError("synthetic evidence failure")
        if failure_site == "evidence"
        else None,
    )
    with pytest.raises(ClassifiedFailure):
        handler.execute(_context())
    assert "transaction_rollback" in events
    assert "transaction_commit" not in events


def test_older_mitre_server_cursor_is_rejected_before_transaction(monkeypatch):
    handler, events, _ = _mitre_handler_dependencies(
        monkeypatch,
        boundary="2026-08-04T00:00:00.000000Z",
    )
    with pytest.raises(ClassifiedFailure):
        handler.execute(
            _context(progress_value="2026-08-05T00:00:00.000000Z")
        )
    assert "transaction_enter" not in events
    assert "transaction_commit" not in events


class _AlwaysEqualTaxiiPolicy(ApprovedTaxiiCollectionPolicy):
    def __eq__(self, other):
        del other
        return True


class _AlwaysEqualStixPolicy(ApprovedStixSourcePolicy):
    def __eq__(self, other):
        del other
        return True


class _MitreStringSubclass(str):
    pass


def _policy_values(policy):
    return {item.name: getattr(policy, item.name) for item in fields(type(policy))}


def _adversarial_mitre_registry(kind):
    canonical = MITRE_ATTACK_ENTERPRISE_TAXII_POLICY
    if kind == "taxii_subclass":
        values = _policy_values(canonical)
        values["api_root_url"] = "https://evil.example/api/v21"
        policy = _AlwaysEqualTaxiiPolicy(**values)
        key = "mitre-attack-enterprise"
    elif kind == "stix_subclass":
        stix_values = _policy_values(MITRE_ATTACK_ENTERPRISE_STIX_POLICY)
        stix_values["policy_base_url"] = "https://evil.example/objects"
        policy = replace(
            canonical,
            stix_policy=_AlwaysEqualStixPolicy(**stix_values),
        )
        key = "mitre-attack-enterprise"
    elif kind == "field_subclass":
        policy = replace(
            canonical,
            api_root_url=_MitreStringSubclass("https://evil.example/api/v21"),
        )
        key = "mitre-attack-enterprise"
    else:
        policy = canonical
        key = _MitreStringSubclass("mitre-attack-enterprise")
    return MappingProxyType({key: policy})


@pytest.mark.parametrize(
    "kind",
    ("taxii_subclass", "stix_subclass", "field_subclass", "key_subclass"),
)
def test_adversarial_mitre_equality_and_string_subclasses_fail_before_transport(
    kind,
    caplog,
):
    called = False

    def forbidden_transport(request):
        nonlocal called
        called = True
        raise AssertionError("transport must not run")

    registry = _adversarial_mitre_registry(kind)
    with caplog.at_level(logging.DEBUG), pytest.raises(
        TaxiiConfigurationError
    ) as caught:
        TaxiiCollectionClient(
            policy_registry=registry,
            http_transport=httpx.MockTransport(forbidden_transport),
        )
    assert called is False
    assert str(caught.value) == "The TAXII policy registry is invalid."
    assert "evil.example" not in str(caught.value)
    assert "evil.example" not in caplog.text

    with pytest.raises(ValueError):
        MitreAttackSourceHandler(
            "mitre-attack-enterprise",
            policy_registry=registry,
        )
    with pytest.raises(ValueError):
        build_c05_mitre_attack_handlers(registry)
