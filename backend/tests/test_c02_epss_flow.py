from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from types import SimpleNamespace

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import sessionmaker

from app.models import IngestionRunRecord
from app.orchestration.contracts import (
    QuotaObservation,
    ResultStatus,
    SOURCE_POLICIES,
    SourceAttemptIdentity,
    SourceExecutionContext,
)
from app.orchestration.source_handlers.epss import EpssSourceHandler


SLOT = datetime(2026, 8, 3, 8, 17, tzinfo=UTC)


def score(cve_id: str, *, date: str = "2026-08-03", epss: str = "0.1"):
    return {"cve": cve_id, "epss": epss, "percentile": "0.2", "date": date}


class Rows:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values


class FakeSession:
    candidates = ("CVE-2026-1001",)
    statements = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def begin(self):
        return nullcontext()

    def execute(self, statement):
        self.statements.append(str(statement))
        expression = statement.column_descriptions[0]["expr"]
        if getattr(expression, "name", None) == "safe_detail":
            return Rows([])
        return Rows(list(self.candidates))

    def add(self, record):
        del record

    def flush(self):
        return None


class EvidenceSession(FakeSession):
    records = []

    def add(self, record):
        if isinstance(record, IngestionRunRecord):
            self.records.append(record)

    def execute(self, statement):
        expression = statement.column_descriptions[0]["expr"]
        if getattr(expression, "name", None) == "safe_detail":
            return Rows(
                [
                    record.safe_detail
                    for record in self.records
                    if record.safe_detail.startswith("c02-evidence-v1:")
                ]
            )
        return super().execute(statement)


class FakeClient:
    def __init__(self, records_by_batch):
        self.records_by_batch = list(records_by_batch)
        self.requests = []
        self.closed = False

    def build_batches(self, cves, *, max_batch_size):
        return [tuple(cves[index : index + max_batch_size]) for index in range(0, len(cves), max_batch_size)]

    def fetch_batch(self, requested):
        self.requests.append(requested)
        return SimpleNamespace(
            requested_cves=requested,
            records=self.records_by_batch.pop(0),
        )

    def close(self):
        self.closed = True


def context():
    policy = SOURCE_POLICIES["first-epss"]
    return SourceExecutionContext(
        policy=policy,
        attempt=SourceAttemptIdentity("first-epss", 1, 4, 0, 1),
        scheduled_for=SLOT,
        deployment_ref="alpha-data-ingestion-cycle",
        progress=None,
        quota=QuotaObservation(policy.quota_policy_key),
    )


def install_service(monkeypatch, outcomes=("created",)):
    queued = list(outcomes)
    enriched = []

    class Service:
        def __init__(self, session):
            del session

        def enrich(self, record, *, observed_at):
            del observed_at
            enriched.append(record.cve_id)
            return SimpleNamespace(
                outcome=queued.pop(0),
                source_record=None,
                intelligence_item_id=7,
            )

    monkeypatch.setattr(
        "app.orchestration.source_handlers.epss.EpssEnrichmentService",
        Service,
    )
    return enriched


def test_valid_scores_commit_and_advance_scheduled_watermark(monkeypatch) -> None:
    FakeSession.candidates = ("CVE-2026-1001",)
    install_service(monkeypatch)
    client = FakeClient([[score("CVE-2026-1001")]])

    result = EpssSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: client,
    ).execute(context())

    assert result.status is ResultStatus.SUCCESS
    assert result.counters.created == 1
    assert result.progress_proposal.value == SLOT
    assert client.requests == [("CVE-2026-1001",)]
    assert client.closed is True


def test_all_requested_records_omitted_are_neutral_without_fabricated_scores(monkeypatch) -> None:
    FakeSession.candidates = ("CVE-2026-1001",)
    enriched = install_service(monkeypatch, outcomes=())

    result = EpssSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient([[]]),
    ).execute(context())

    assert result.status is ResultStatus.NO_CHANGE
    assert result.counters.fetched == 1
    assert result.counters.unchanged == 1
    assert result.counters.failed == 0
    assert result.counters.error_count == 0
    assert result.progress_proposal.value == SLOT
    assert enriched == []


def test_good_record_and_omission_commit_successfully_with_progress(monkeypatch) -> None:
    FakeSession.candidates = ("CVE-2026-1001", "CVE-2026-1002")
    install_service(monkeypatch)

    result = EpssSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient([[score("CVE-2026-1001")]]),
    ).execute(context())

    assert result.status is ResultStatus.SUCCESS
    assert result.counters.fetched == 2
    assert result.counters.created == 1
    assert result.counters.unchanged == 1
    assert result.counters.failed == 0
    assert result.counters.error_count == 0
    assert result.progress_proposal.value == SLOT


def test_malformed_returned_record_still_fails_without_progress(monkeypatch) -> None:
    FakeSession.candidates = ("CVE-2026-1001",)
    enriched = install_service(monkeypatch, outcomes=())

    result = EpssSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient(
            [[score("CVE-2026-1001", epss="not-a-score")]]
        ),
    ).execute(context())

    assert result.status is ResultStatus.FAILED
    assert result.counters.failed == 1
    assert result.counters.unchanged == 0
    assert result.progress_proposal is None
    assert enriched == []


def test_unexpected_returned_cve_is_explicit_failure(monkeypatch) -> None:
    FakeSession.candidates = ("CVE-2026-1001",)
    install_service(monkeypatch, outcomes=())

    result = EpssSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient([[score("CVE-2026-9999")]]),
    ).execute(context())

    assert result.status is ResultStatus.PARTIAL
    assert result.counters.failed == 1
    assert result.counters.unchanged == 1
    assert result.progress_proposal is None


def test_conflicting_duplicate_returned_record_still_fails(monkeypatch) -> None:
    FakeSession.candidates = ("CVE-2026-1001",)
    enriched = install_service(monkeypatch, outcomes=())

    result = EpssSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient(
            [[score("CVE-2026-1001"), score("CVE-2026-1001", epss="0.2")]]
        ),
    ).execute(context())

    assert result.status is ResultStatus.FAILED
    assert result.counters.failed == 1
    assert result.counters.unchanged == 0
    assert result.progress_proposal is None
    assert enriched == []


def test_future_dataset_date_is_rejected(monkeypatch) -> None:
    FakeSession.candidates = ("CVE-2026-1001",)
    install_service(monkeypatch, outcomes=())

    result = EpssSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient(
            [[score("CVE-2026-1001", date="2026-08-04")]]
        ),
    ).execute(context())

    assert result.status is ResultStatus.FAILED
    assert result.counters.failed == 1
    assert result.counters.unchanged == 0
    assert result.progress_proposal is None


def test_genuine_validation_failure_with_omission_prevents_progress(monkeypatch) -> None:
    FakeSession.candidates = ("CVE-2026-1001", "CVE-2026-1002")
    install_service(monkeypatch, outcomes=())

    result = EpssSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient(
            [[score("CVE-2026-1001", epss="not-a-score")]]
        ),
    ).execute(context())

    assert result.status is ResultStatus.PARTIAL
    assert result.counters.failed == 1
    assert result.counters.unchanged == 1
    assert result.progress_proposal is None


def test_omission_evidence_replays_and_reconstructs_progress_without_network(monkeypatch) -> None:
    EvidenceSession.records = []
    EvidenceSession.candidates = ("CVE-2026-1001", "CVE-2026-1002")
    install_service(monkeypatch)
    execution_context = context()
    first = EpssSourceHandler(
        session_factory=EvidenceSession,
        client_factory=lambda: FakeClient([[score("CVE-2026-1001")]]),
    ).execute(execution_context)

    def unexpected_client():
        raise AssertionError("replay and reconstruction must not create a client")

    replay_handler = EpssSourceHandler(
        session_factory=EvidenceSession,
        client_factory=unexpected_client,
    )
    replayed = replay_handler.execute(execution_context)
    reconstructed = replay_handler.reconstruct_progress(
        execution_context,
        first.counters,
    )
    omission_evidence = [
        record
        for record in EvidenceSession.records
        if "requested CVE omitted" in record.safe_detail
    ]

    assert replayed.status == first.status
    assert replayed.counters == first.counters
    assert replayed.metrics == first.metrics
    assert replayed.progress_proposal == first.progress_proposal
    assert reconstructed == first.progress_proposal
    assert len(omission_evidence) == 1
    assert omission_evidence[0].action == "unchanged"
    assert omission_evidence[0].source_record_id is None
    assert omission_evidence[0].intelligence_item_id is None


def test_candidate_query_orders_unseen_then_oldest_then_cve_identity(monkeypatch) -> None:
    FakeSession.candidates = ()
    FakeSession.statements = []
    install_service(monkeypatch, outcomes=())
    result = EpssSourceHandler(
        session_factory=FakeSession,
        client_factory=lambda: FakeClient([]),
    ).execute(context())

    candidate_statement = next(
        statement
        for statement in FakeSession.statements
        if "intelligence_item_identifiers.normalized_value" in statement
    )
    assert "NULLS FIRST" in candidate_statement
    assert (
        "source_records.source_external_id = "
        "intelligence_item_identifiers.normalized_value"
    ) in candidate_statement
    assert "normalized_value ASC" in candidate_statement
    assert result.status is ResultStatus.NO_CHANGE
    assert result.metrics.request_count == 0


def test_multi_cve_item_uses_each_identifiers_own_epss_date_for_fairness() -> None:
    metadata = MetaData()
    sources = Table(
        "intelligence_sources",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("slug", String, nullable=False),
    )
    items = Table(
        "intelligence_items",
        metadata,
        Column("id", Integer, primary_key=True),
    )
    identifiers = Table(
        "intelligence_item_identifiers",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("intelligence_item_id", Integer, nullable=False),
        Column("source_id", Integer, nullable=True),
        Column("namespace", String, nullable=False),
        Column("normalized_value", String, nullable=False),
    )
    vulnerabilities = Table(
        "vulnerabilities",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("intelligence_item_id", Integer, nullable=False),
    )
    source_records = Table(
        "source_records",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("source_id", Integer, nullable=False),
        Column("intelligence_item_id", Integer, nullable=True),
        Column("source_external_id", String, nullable=True),
        Column("source_modified_at", DateTime(timezone=True), nullable=True),
    )
    engine = create_engine("sqlite+pysqlite:///:memory:")
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(sources.insert(), [{"id": 1, "slug": "first-epss"}])
        connection.execute(items.insert(), [{"id": 10}, {"id": 20}])
        connection.execute(
            vulnerabilities.insert(),
            [
                {"id": 100, "intelligence_item_id": 10},
                {"id": 200, "intelligence_item_id": 20},
            ],
        )
        connection.execute(
            identifiers.insert(),
            [
                {
                    "id": 1,
                    "intelligence_item_id": 10,
                    "source_id": None,
                    "namespace": "cve",
                    "normalized_value": "CVE-2026-1001",
                },
                {
                    "id": 2,
                    "intelligence_item_id": 10,
                    "source_id": None,
                    "namespace": "cve",
                    "normalized_value": "CVE-2026-1002",
                },
                {
                    "id": 3,
                    "intelligence_item_id": 20,
                    "source_id": None,
                    "namespace": "cve",
                    "normalized_value": "CVE-2026-1003",
                },
            ],
        )
        connection.execute(
            source_records.insert(),
            [
                {
                    "id": 1,
                    "source_id": 1,
                    "intelligence_item_id": 10,
                    "source_external_id": "CVE-2026-1001",
                    "source_modified_at": datetime(2026, 8, 2, tzinfo=UTC),
                },
                {
                    "id": 2,
                    "source_id": 1,
                    "intelligence_item_id": 10,
                    "source_external_id": "CVE-2026-1002",
                    "source_modified_at": datetime(2026, 8, 1, tzinfo=UTC),
                },
            ],
        )

    session_factory = sessionmaker(bind=engine)
    try:
        candidates = EpssSourceHandler(
            session_factory=session_factory,
            client_factory=lambda: FakeClient([]),
        )._candidate_cves()
    finally:
        engine.dispose()

    assert candidates == (
        "CVE-2026-1003",
        "CVE-2026-1002",
        "CVE-2026-1001",
    )
