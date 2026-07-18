from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from io import StringIO
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion import censys_publications_live_cli
from app.ingestion.adapters.censys_publications import (
    CENSYS_ARC_RESEARCH_SLUG,
    CENSYS_RAPID_RESPONSE_SLUG,
)
from app.ingestion.collectors.censys_publications_client import (
    CensysCollectionResult,
    CensysDiscoveryCollectionError,
    CensysFailureReason,
    CensysPublicationSource,
)
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPersistenceResult,
)
from app.ingestion.services.censys_publications_ingestion_service import (
    CensysIngestionDatabaseError,
    CensysIngestionResult,
    CensysPublicationsIngestionService,
)
from app.models import IngestionRun, IntelligenceSource


NOW = datetime(2026, 7, 17, 9, 0, tzinfo=UTC)
RUN_ID = UUID("12345678-1234-5678-1234-567812345678")


def source_slug(source: CensysPublicationSource) -> str:
    if source is CensysPublicationSource.ARC:
        return CENSYS_ARC_RESEARCH_SLUG
    return CENSYS_RAPID_RESPONSE_SLUG


def candidate(source: CensysPublicationSource) -> PublicationCandidate:
    slug = source_slug(source)
    path = "blog" if source is CensysPublicationSource.ARC else "advisory"
    return PublicationCandidate(
        source_slug=slug,
        source_external_id=f"{slug}:safe-id",
        canonical_title="Private-looking title that must not be printed",
        canonical_url=f"https://censys.com/{path}/safe-id/",
    )


def collection(
    source: CensysPublicationSource = CensysPublicationSource.ARC,
    *,
    candidates: tuple[PublicationCandidate, ...] | None = None,
    failures: tuple[CensysFailureReason, ...] = (),
    capped: bool = False,
    override_slug: str | None = None,
) -> CensysCollectionResult:
    records = (candidate(source),) if candidates is None else candidates
    return CensysCollectionResult(
        source=source,
        source_slug=override_slug or source_slug(source),
        candidates=records,
        failure_count=len(failures),
        failure_reasons=failures,
        discovered_approved_link_count=len(records) + len(failures),
        capped=capped,
    )


class FakeCollector:
    def __init__(
        self,
        result: CensysCollectionResult | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.entered = False
        self.exited = False
        self.calls: list[tuple[CensysPublicationSource, int]] = []

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        del exc_type, exc, traceback
        self.exited = True

    def fetch_publications(
        self,
        source: CensysPublicationSource,
        max_records: int,
    ) -> CensysCollectionResult:
        self.calls.append((source, max_records))
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


class FakeSession:
    def __init__(self, *, close_error: Exception | None = None) -> None:
        self.close_error = close_error
        self.closed = False
        self.rollbacks = 0
        self.commits = 0
        self.added: list[object] = []
        self.nested_transactions = 0

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error

    def add(self, record: object) -> None:
        self.added.append(record)

    def flush(self) -> None:
        for record in self.added:
            if isinstance(record, IngestionRun) and record.id is None:
                record.id = 1
                record.public_id = RUN_ID

    def begin_nested(self):
        self.nested_transactions += 1
        return nullcontext()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


class CapturingService:
    def __init__(self, session: FakeSession, *, status: str = "succeeded") -> None:
        self.session = session
        self.status = status
        self.calls: list[dict[str, object]] = []

    def ingest(self, **kwargs: object) -> CensysIngestionResult:
        self.calls.append(kwargs)
        candidates = tuple(kwargs["candidates"])  # type: ignore[arg-type]
        failures = tuple(kwargs["failure_kinds"])  # type: ignore[arg-type]
        run = SimpleNamespace(
            public_id=RUN_ID,
            status=self.status,
            records_fetched=kwargs["records_fetched"],
            records_created=len(candidates) if self.status != "failed" else 0,
            records_updated=0,
            records_unchanged=0,
            records_skipped=0,
            records_failed=len(failures) if failures else int(self.status == "failed"),
        )
        return CensysIngestionResult(run=run)  # type: ignore[arg-type]


def run_main(
    argv: list[str],
    *,
    result: CensysCollectionResult | None = None,
    collector_error: Exception | None = None,
    status: str = "succeeded",
    session: FakeSession | None = None,
    service_error: Exception | None = None,
):
    active_session = session or FakeSession()
    collector = FakeCollector(result, error=collector_error)
    service = CapturingService(active_session, status=status)
    session_requests = 0

    def session_factory() -> FakeSession:
        nonlocal session_requests
        session_requests += 1
        return active_session

    def service_factory(created_session: FakeSession):
        assert created_session is active_session
        if service_error is not None:
            raise service_error
        return service

    stdout = StringIO()
    stderr = StringIO()
    exit_code = censys_publications_live_cli.main(
        argv,
        collector_factory=lambda: collector,  # type: ignore[arg-type]
        session_factory=session_factory,  # type: ignore[arg-type]
        service_factory=service_factory,  # type: ignore[arg-type]
        clock=lambda: NOW,
        stdout=stdout,
        stderr=stderr,
    )
    return SimpleNamespace(
        exit_code=exit_code,
        stdout=stdout.getvalue(),
        stderr=stderr.getvalue(),
        collector=collector,
        session=active_session,
        session_requests=session_requests,
        service=service,
    )


@pytest.mark.parametrize(
    ("selector", "source", "slug"),
    [
        ("arc", CensysPublicationSource.ARC, CENSYS_ARC_RESEARCH_SLUG),
        (
            "rapid-response",
            CensysPublicationSource.RAPID_RESPONSE,
            CENSYS_RAPID_RESPONSE_SLUG,
        ),
    ],
)
def test_valid_source_invocation_collects_before_session_and_persists(
    selector: str,
    source: CensysPublicationSource,
    slug: str,
) -> None:
    result = collection(source)
    observed_order: list[str] = []
    collector = FakeCollector(result)
    original_fetch = collector.fetch_publications

    def fetch(selected: CensysPublicationSource, max_records: int):
        observed_order.append("collection")
        return original_fetch(selected, max_records)

    collector.fetch_publications = fetch  # type: ignore[method-assign]
    session = FakeSession()
    service = CapturingService(session)
    stdout = StringIO()
    stderr = StringIO()

    exit_code = censys_publications_live_cli.main(
        ["--source", selector],
        collector_factory=lambda: collector,  # type: ignore[arg-type]
        session_factory=lambda: (  # type: ignore[arg-type]
            observed_order.append("session") or session
        ),
        service_factory=lambda _: service,  # type: ignore[arg-type]
        clock=lambda: NOW,
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert observed_order == ["collection", "session"]
    assert collector.calls == [(source, 5)]
    assert collector.entered is True and collector.exited is True
    assert service.calls[0]["source_slug"] == slug
    assert service.calls[0]["candidates"] == result.candidates
    assert session.closed is True
    assert f"Source: {slug}" in stdout.getvalue()
    assert stderr.getvalue() == ""


@pytest.mark.parametrize("maximum", [1, 20])
def test_explicit_boundary_max_records_reaches_collector(maximum: int) -> None:
    outcome = run_main(
        ["--source", "arc", "--max-records", str(maximum)],
        result=collection(),
    )

    assert outcome.exit_code == 0
    assert outcome.collector.calls == [(CensysPublicationSource.ARC, maximum)]


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--source", "unknown"],
        ["--source", "https://censys.com/"],
        ["--source", "arc", "--max-records", "0"],
        ["--source", "arc", "--max-records", "-1"],
        ["--source", "arc", "--max-records", "21"],
        ["--source", "arc", "--max-records", "true"],
        ["--source", "arc", "--max-records", "1.0"],
        ["--source", "arc", "positional"],
        ["--source", "arc", "--unknown"],
        ["--sou", "arc"],
        ["--source", "arc", "--max-r", "5"],
        ["--source", "arc", "--source", "arc"],
        ["--source", "arc", "--max-records", "5", "--max-records", "5"],
        ["--source", "arc", "--url", "https://censys.com/"],
        ["--source", "arc", "--host", "censys.com"],
    ],
)
def test_invalid_or_expansive_arguments_are_rejected_without_side_effects(
    argv: list[str],
) -> None:
    collector_created = False
    session_created = False
    stdout = StringIO()
    stderr = StringIO()

    def collector_factory():
        nonlocal collector_created
        collector_created = True
        raise AssertionError("collector must not be created")

    def session_factory():
        nonlocal session_created
        session_created = True
        raise AssertionError("session must not be created")

    exit_code = censys_publications_live_cli.main(
        argv,
        collector_factory=collector_factory,
        session_factory=session_factory,
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 2
    assert collector_created is False
    assert session_created is False
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "Invalid manual Censys live ingestion arguments.\n"


def test_discovery_failure_is_sanitized_and_prevents_session_creation() -> None:
    secret = "https://private.example/path token=secret"
    outcome = run_main(
        ["--source", "arc"],
        collector_error=CensysDiscoveryCollectionError(secret),
    )

    assert outcome.exit_code == 1
    assert outcome.session_requests == 0
    assert outcome.collector.exited is True
    assert outcome.stdout == ""
    assert outcome.stderr == "Censys live collection failed safely.\n"
    assert secret not in outcome.stderr


def test_invalid_collection_source_slug_prevents_session_creation() -> None:
    outcome = run_main(
        ["--source", "arc"],
        result=collection(override_slug=CENSYS_RAPID_RESPONSE_SLUG),
    )

    assert outcome.exit_code == 1
    assert outcome.session_requests == 0
    assert outcome.stderr == "Censys live collection failed safely.\n"


@pytest.mark.parametrize(
    ("status", "failures", "expected_exit"),
    [
        ("succeeded", (), 0),
        ("partial", (CensysFailureReason.TIMEOUT,), 1),
        (
            "failed",
            (CensysFailureReason.TIMEOUT, CensysFailureReason.HTTP_FAILURE),
            1,
        ),
    ],
)
def test_safe_success_partial_and_failed_output(
    status: str,
    failures: tuple[CensysFailureReason, ...],
    expected_exit: int,
) -> None:
    records = () if status == "failed" else (candidate(CensysPublicationSource.ARC),)
    outcome = run_main(
        ["--source", "arc"],
        result=collection(candidates=records, failures=failures),
        status=status,
    )

    assert outcome.exit_code == expected_exit
    assert f"Status: {status}" in outcome.stdout
    assert f"Fetched: {len(records) + len(failures)}" in outcome.stdout
    assert f"Failed: {len(failures)}" in outcome.stdout
    assert str(RUN_ID) in outcome.stdout
    combined = (outcome.stdout + outcome.stderr).lower()
    assert "https://" not in combined
    assert "private-looking title" not in combined
    if status == "succeeded":
        assert outcome.stderr == ""
    else:
        assert "controlled failure" in outcome.stderr


@pytest.mark.parametrize("capped", [False, True])
def test_capped_state_is_reported_without_database_schema_change(capped: bool) -> None:
    outcome = run_main(
        ["--source", "arc"],
        result=collection(capped=capped),
    )

    assert f"Capped: {str(capped).lower()}" in outcome.stdout


def test_database_failure_is_sanitized_and_session_closes() -> None:
    secret = "postgresql://private:password@host/database SELECT secret"
    outcome = run_main(
        ["--source", "arc"],
        result=collection(),
        service_error=CensysIngestionDatabaseError(secret),
    )

    assert outcome.exit_code == 1
    assert outcome.session.closed is True
    assert outcome.stdout == ""
    assert outcome.stderr == (
        "Manual Censys live ingestion failed during a database operation.\n"
    )
    assert secret not in outcome.stderr


def test_sqlalchemy_persistence_failure_rolls_back_and_closes_session() -> None:
    secret = "postgresql://private:password@host/database params=secret"
    result = collection()
    collector = FakeCollector(result)
    session = FakeSession()

    class FailingPipeline:
        def __init__(self, _: object) -> None:
            self.source = IntelligenceSource(
                slug=CENSYS_ARC_RESEARCH_SLUG,
                name="Censys ARC Research",
                source_type="json",
                base_url="https://censys.com/",
                is_enabled=True,
            )

        def ensure_source(self, source_slug_value: str) -> IntelligenceSource:
            assert source_slug_value == CENSYS_ARC_RESEARCH_SLUG
            return self.source

        def persist(self, record: PublicationCandidate, *, observed_at: datetime):
            del record, observed_at
            raise SQLAlchemyError(secret)

    stdout = StringIO()
    stderr = StringIO()

    exit_code = censys_publications_live_cli.main(
        ["--source", "arc"],
        collector_factory=lambda: collector,  # type: ignore[arg-type]
        session_factory=lambda: session,  # type: ignore[arg-type]
        service_factory=lambda created_session: CensysPublicationsIngestionService(
            created_session,  # type: ignore[arg-type]
            pipeline_factory=FailingPipeline,  # type: ignore[arg-type]
        ),
        clock=lambda: NOW,
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert session.commits == 0
    assert session.rollbacks == 1
    assert session.closed is True
    assert stdout.getvalue() == ""
    assert "database operation" in stderr.getvalue()
    assert secret not in stderr.getvalue()


def test_session_close_failure_is_sanitized() -> None:
    secret = "postgresql://private:password@host/database"
    outcome = run_main(
        ["--source", "arc"],
        result=collection(),
        session=FakeSession(close_error=RuntimeError(secret)),
    )

    assert outcome.exit_code == 1
    assert outcome.session.closed is True
    assert outcome.stdout == ""
    assert secret not in outcome.stderr
    assert "database operation" in outcome.stderr


class LifecycleCollector(FakeCollector):
    def __init__(
        self,
        result: CensysCollectionResult,
        *,
        enter_error=None,
        fetch_error=None,
        exit_error=None,
    ) -> None:
        super().__init__(result, error=fetch_error)
        self.enter_error = enter_error
        self.exit_error = exit_error

    def __enter__(self):
        if self.enter_error is not None:
            raise self.enter_error
        return super().__enter__()

    def __exit__(self, exc_type, exc, traceback) -> None:
        super().__exit__(exc_type, exc, traceback)
        if self.exit_error is not None:
            raise self.exit_error


@pytest.mark.parametrize("failure_point", ["factory", "enter", "fetch", "exit"])
def test_collector_lifecycle_memory_error_propagates_before_session(
    failure_point: str,
) -> None:
    memory_error = MemoryError(f"private collector {failure_point}")
    collector = LifecycleCollector(
        collection(),
        enter_error=memory_error if failure_point == "enter" else None,
        fetch_error=memory_error if failure_point == "fetch" else None,
        exit_error=memory_error if failure_point == "exit" else None,
    )
    session_requested = False

    def collector_factory():
        if failure_point == "factory":
            raise memory_error
        return collector

    def session_factory():
        nonlocal session_requested
        session_requested = True
        raise AssertionError("session must not be requested")

    with pytest.raises(MemoryError) as exc_info:
        censys_publications_live_cli.main(
            ["--source", "arc"],
            collector_factory=collector_factory,
            session_factory=session_factory,
            clock=lambda: NOW,
            stdout=StringIO(),
            stderr=StringIO(),
        )

    assert exc_info.value is memory_error
    assert session_requested is False


def test_collector_cleanup_does_not_replace_active_memory_error() -> None:
    memory_error = MemoryError("primary private memory marker")
    collector = LifecycleCollector(
        collection(),
        fetch_error=memory_error,
        exit_error=RuntimeError("secondary private cleanup marker"),
    )

    with pytest.raises(MemoryError) as exc_info:
        censys_publications_live_cli.main(
            ["--source", "arc"],
            collector_factory=lambda: collector,  # type: ignore[arg-type]
            session_factory=lambda: pytest.fail("session must not be requested"),
            stdout=StringIO(),
            stderr=StringIO(),
        )

    assert exc_info.value is memory_error


def test_ordinary_collector_runtime_error_remains_sanitized() -> None:
    secret = "private collector runtime https://private.example/"
    outcome = run_main(
        ["--source", "arc"],
        collector_error=RuntimeError(secret),
    )

    assert outcome.exit_code == 1
    assert outcome.session_requests == 0
    assert outcome.stdout == ""
    assert outcome.stderr == "Censys live collection failed safely.\n"
    assert secret not in outcome.stderr


@pytest.mark.parametrize(
    "failure_point",
    ["clock", "session_factory", "service_factory", "service_ingestion", "close"],
)
def test_live_post_collection_memory_error_propagates(
    failure_point: str,
) -> None:
    memory_error = MemoryError(f"private live {failure_point}")
    collector = LifecycleCollector(collection())
    session = FakeSession(
        close_error=memory_error if failure_point == "close" else None
    )

    def clock():
        if failure_point == "clock":
            raise memory_error
        return NOW

    def session_factory():
        if failure_point == "session_factory":
            raise memory_error
        return session

    class Service(CapturingService):
        def ingest(self, **kwargs: object) -> CensysIngestionResult:
            if failure_point == "service_ingestion":
                raise memory_error
            return super().ingest(**kwargs)

    def service_factory(created_session: FakeSession):
        if failure_point == "service_factory":
            raise memory_error
        return Service(created_session)

    with pytest.raises(MemoryError) as exc_info:
        censys_publications_live_cli.main(
            ["--source", "arc"],
            collector_factory=lambda: collector,  # type: ignore[arg-type]
            session_factory=session_factory,  # type: ignore[arg-type]
            service_factory=service_factory,  # type: ignore[arg-type]
            clock=clock,
            stdout=StringIO(),
            stderr=StringIO(),
        )

    assert exc_info.value is memory_error


def test_live_summary_memory_error_propagates_after_session_close() -> None:
    memory_error = MemoryError("private summary marker")
    session = FakeSession()

    class BrokenRun:
        @property
        def public_id(self):
            raise memory_error

    class Service:
        def ingest(self, **kwargs: object) -> CensysIngestionResult:
            del kwargs
            return CensysIngestionResult(run=BrokenRun())  # type: ignore[arg-type]

    with pytest.raises(MemoryError) as exc_info:
        censys_publications_live_cli.main(
            ["--source", "arc"],
            collector_factory=(  # type: ignore[arg-type]
                lambda: LifecycleCollector(collection())
            ),
            session_factory=lambda: session,  # type: ignore[arg-type]
            service_factory=lambda _: Service(),  # type: ignore[arg-type]
            clock=lambda: NOW,
            stdout=StringIO(),
            stderr=StringIO(),
        )

    assert exc_info.value is memory_error
    assert session.closed is True


def test_live_session_cleanup_does_not_replace_active_memory_error() -> None:
    primary_error = MemoryError("primary private service marker")
    session = FakeSession(
        close_error=RuntimeError("secondary private cleanup marker")
    )

    class Service:
        def ingest(self, **kwargs: object) -> CensysIngestionResult:
            del kwargs
            raise primary_error

    with pytest.raises(MemoryError) as exc_info:
        censys_publications_live_cli.main(
            ["--source", "arc"],
            collector_factory=(  # type: ignore[arg-type]
                lambda: LifecycleCollector(collection())
            ),
            session_factory=lambda: session,  # type: ignore[arg-type]
            service_factory=lambda _: Service(),  # type: ignore[arg-type]
            clock=lambda: NOW,
            stdout=StringIO(),
            stderr=StringIO(),
        )

    assert exc_info.value is primary_error
