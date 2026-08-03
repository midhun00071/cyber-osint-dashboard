from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from hashlib import sha256
import json
from types import SimpleNamespace

from app.models import IngestionRunRecord
from app.orchestration.contracts import (
    ProgressSnapshot,
    ProgressStorage,
    ProgressKind,
    QuotaObservation,
    ResultStatus,
    SOURCE_POLICIES,
    SourceAttemptIdentity,
    SourceExecutionContext,
)
from app.orchestration.source_handlers.cisa_kev import CisaKevSourceHandler
from app.orchestration.source_handlers.cisa_kev import (
    LOCAL_IDENTIFIER_LOOKUP_BATCH_SIZE,
)


SLOT = datetime(2026, 8, 3, 8, 17, tzinfo=UTC)


def entry(cve_id: str = "CVE-2026-1001") -> dict[str, str]:
    return {
        "cveID": cve_id,
        "vendorProject": "Vendor",
        "product": "Product",
        "vulnerabilityName": "Example Vulnerability",
        "dateAdded": "2026-07-01",
        "shortDescription": "Safe description.",
        "requiredAction": "Apply updates.",
        "dueDate": "2026-08-01",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "Safe notes.",
    }


def catalog(*cve_ids: str) -> dict[str, object]:
    values = cve_ids or ("CVE-2026-1001",)
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.08.03",
        "dateReleased": "2026-08-03T08:00:00Z",
        "count": len(values),
        "vulnerabilities": [entry(cve_id) for cve_id in values],
    }


class Rows:
    def __init__(self, values=()):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values


class FakeSession:
    local_cves = frozenset({"CVE-2026-1001"})
    lookup_chunks = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def begin(self):
        return nullcontext()

    def execute(self, statement):
        expression = statement.column_descriptions[0]["expr"]
        if getattr(expression, "name", None) == "safe_detail":
            return Rows()
        if getattr(expression, "name", None) == "normalized_value":
            requested = next(
                tuple(criterion.right.value)
                for criterion in statement._where_criteria
                if getattr(criterion.operator, "__name__", "") == "in_op"
            )
            self.lookup_chunks.append(requested)
            return Rows(sorted(self.local_cves.intersection(requested)))
        raise AssertionError("Unexpected CISA handler query.")

    def add(self, record):
        del record

    def flush(self):
        return None


class FakeClient:
    def __init__(self, fetched_catalog=None):
        self.closed = False
        self.fetched_catalog = fetched_catalog or catalog()

    def fetch_catalog(self):
        return SimpleNamespace(catalog=self.fetched_catalog)

    def close(self):
        self.closed = True


def context(progress=None):
    policy = SOURCE_POLICIES["cisa-kev"]
    return SourceExecutionContext(
        policy=policy,
        attempt=SourceAttemptIdentity("cisa-kev", 1, 2, 0, 1),
        scheduled_for=SLOT,
        deployment_ref="alpha-data-ingestion-cycle",
        progress=progress,
        quota=QuotaObservation(policy.quota_policy_key),
    )


def install_services(monkeypatch, *, ingestion_outcome="updated", next_cursor=41):
    captured = {"enriched": []}

    class Ingestion:
        def __init__(self, session):
            del session

        def enrich(self, record, *, observed_at):
            del observed_at
            captured["enriched"].append(record.cve_id)
            return SimpleNamespace(
                outcome=ingestion_outcome,
                source_record=None,
                intelligence_item_id=10,
            )

    class Reconciliation:
        def __init__(self, session):
            del session

        def reconcile(self, cves, **kwargs):
            captured["cves"] = cves
            captured.update(kwargs)
            return SimpleNamespace(records=(), next_cursor=next_cursor)

    monkeypatch.setattr(
        "app.orchestration.source_handlers.cisa_kev.CisaKevIngestionService",
        Ingestion,
    )
    monkeypatch.setattr(
        "app.orchestration.source_handlers.cisa_kev.CisaKevReconciliationService",
        Reconciliation,
    )
    return captured


def test_catalogue_update_commits_hash_and_next_cursor(monkeypatch) -> None:
    FakeSession.local_cves = frozenset({"CVE-2026-1001"})
    captured = install_services(monkeypatch, next_cursor=41)
    client = FakeClient()
    handler = CisaKevSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: client,
    )

    result = handler.execute(context())

    assert result.status is ResultStatus.SUCCESS
    assert result.counters.updated == 1
    assert result.progress_proposal is not None
    assert result.progress_proposal.value.endswith(";cursor=41")
    assert result.progress_proposal.value.startswith("sha256=")
    assert captured["max_cves"] == 500
    assert captured["batch_size"] == 100
    assert captured["start_after_id"] == 0
    assert client.closed is True


def test_same_catalogue_hash_continues_local_cursor(monkeypatch) -> None:
    FakeSession.local_cves = frozenset({"CVE-2026-1001"})
    captured = install_services(monkeypatch, next_cursor=82)
    handler = CisaKevSourceHandler(
        session_factory=FakeSession,
        client_factory=FakeClient,
    )
    first = handler.execute(context())
    progress = ProgressSnapshot(
        storage=ProgressStorage.CHECKPOINT,
        kind=ProgressKind.CONTENT_HASH,
        name="content_hash",
        value=first.progress_proposal.value,
        version=3,
    )

    second = handler.execute(context(progress))

    assert captured["start_after_id"] == 82
    assert second.progress_proposal.expected_previous_version == 3
    assert second.progress_proposal.value.endswith(";cursor=82")


def test_real_invalid_local_target_is_controlled_failure_without_progress(monkeypatch) -> None:
    FakeSession.local_cves = frozenset({"CVE-2026-1001"})
    install_services(monkeypatch, ingestion_outcome="skipped")
    result = CisaKevSourceHandler(
        session_factory=FakeSession,
        client_factory=FakeClient,
    ).execute(context())

    assert result.status is ResultStatus.FAILED
    assert result.counters.skipped == 1
    assert result.progress_proposal is None


def test_changed_catalogue_hash_restarts_local_cursor(monkeypatch) -> None:
    FakeSession.local_cves = frozenset({"CVE-2026-1001"})
    captured = install_services(monkeypatch)
    progress = ProgressSnapshot(
        storage=ProgressStorage.CHECKPOINT,
        kind=ProgressKind.CONTENT_HASH,
        name="content_hash",
        value="sha256=" + "0" * 64 + ";cursor=99",
        version=1,
    )

    CisaKevSourceHandler(
        session_factory=FakeSession,
        client_factory=FakeClient,
    ).execute(context(progress))

    assert captured["start_after_id"] == 0


def test_catalogue_with_only_non_local_cves_is_no_change_with_progress(monkeypatch) -> None:
    FakeSession.local_cves = frozenset()
    captured = install_services(monkeypatch, next_cursor=17)
    fetched_catalog = catalog("CVE-2026-9001", "CVE-2026-9002")

    result = CisaKevSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient(fetched_catalog),
    ).execute(context())

    assert result.status is ResultStatus.NO_CHANGE
    assert result.counters.fetched == 0
    assert result.progress_proposal is not None
    assert result.progress_proposal.value.endswith(";cursor=17")
    assert captured["enriched"] == []
    assert captured["cves"] == frozenset({"CVE-2026-9001", "CVE-2026-9002"})


def test_local_identifier_lookup_uses_deterministic_bounded_chunks(monkeypatch) -> None:
    FakeSession.local_cves = frozenset()
    FakeSession.lookup_chunks = []
    install_services(monkeypatch)
    cve_ids = tuple(f"CVE-2026-{1000 + index}" for index in range(201))

    result = CisaKevSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient(catalog(*cve_ids)),
    ).execute(context())

    assert result.status is ResultStatus.NO_CHANGE
    assert [len(chunk) for chunk in FakeSession.lookup_chunks] == [100, 100, 1]
    assert all(
        len(chunk) <= LOCAL_IDENTIFIER_LOOKUP_BATCH_SIZE
        for chunk in FakeSession.lookup_chunks
    )
    assert tuple(value for chunk in FakeSession.lookup_chunks for value in chunk) == cve_ids


def test_mixed_catalogue_enriches_only_local_cve_without_partial_status(monkeypatch) -> None:
    FakeSession.local_cves = frozenset({"CVE-2026-1001"})
    captured = install_services(monkeypatch, next_cursor=23)

    result = CisaKevSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient(
            catalog("CVE-2026-1001", "CVE-2026-9001")
        ),
    ).execute(context())

    assert result.status is ResultStatus.SUCCESS
    assert result.counters.updated == 1
    assert result.counters.skipped == 0
    assert result.progress_proposal is not None
    assert captured["enriched"] == ["CVE-2026-1001"]


def test_catalogue_hash_includes_non_local_entries(monkeypatch) -> None:
    FakeSession.local_cves = frozenset({"CVE-2026-1001"})
    install_services(monkeypatch, next_cursor=31)
    fetched_catalog = catalog("CVE-2026-1001", "CVE-2026-9001")
    expected_hash = sha256(
        json.dumps(
            fetched_catalog,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    result = CisaKevSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient(fetched_catalog),
    ).execute(context())

    assert result.progress_proposal is not None
    assert result.progress_proposal.value == f"sha256={expected_hash};cursor=31"


def test_replay_and_reconstruction_are_network_free(monkeypatch) -> None:
    class EvidenceSession(FakeSession):
        records = []
        local_cves = frozenset()

        def add(self, record):
            if isinstance(record, IngestionRunRecord):
                self.records.append(record)

        def execute(self, statement):
            expression = statement.column_descriptions[0]["expr"]
            if getattr(expression, "name", None) == "safe_detail":
                return Rows([record.safe_detail for record in self.records])
            return super().execute(statement)

    EvidenceSession.records = []
    install_services(monkeypatch, next_cursor=43)
    execution_context = context()
    first = CisaKevSourceHandler(
        session_factory=EvidenceSession,
        client_factory=lambda: FakeClient(catalog("CVE-2026-9001")),
    ).execute(execution_context)

    def unexpected_client():
        raise AssertionError("replay and reconstruction must not create a client")

    replay_handler = CisaKevSourceHandler(
        session_factory=EvidenceSession,
        client_factory=unexpected_client,
    )
    replayed = replay_handler.execute(execution_context)
    reconstructed = replay_handler.reconstruct_progress(
        execution_context,
        first.counters,
    )

    assert replayed.progress_proposal == first.progress_proposal
    assert reconstructed == first.progress_proposal
