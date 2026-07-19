from __future__ import annotations

from datetime import UTC, datetime
from io import StringIO
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.ingestion import anomali_publications_live_cli
from app.ingestion.adapters.anomali_publications import ANOMALI_SOURCE_SLUG
from app.ingestion.collectors.anomali_publications_client import (
    AnomaliCollectionResult,
    AnomaliDiscoveryCollectionError,
    AnomaliFailureReason,
    AnomaliHttpError,
    AnomaliRequestStateIsolationError,
    AnomaliTimeoutError,
    AnomaliTransportError,
)
from app.ingestion.publication_pipeline import PublicationCandidate
from app.ingestion.services.anomali_publications_ingestion_service import (
    AnomaliIngestionDatabaseError,
    AnomaliIngestionError,
    AnomaliIngestionResult,
)


NOW = datetime(2026, 7, 19, 9, 0, tzinfo=UTC)
RUN_ID = UUID("12345678-1234-5678-1234-567812345678")


def candidate(identifier: str = "safe-id") -> PublicationCandidate:
    return PublicationCandidate(
        source_slug=ANOMALI_SOURCE_SLUG,
        source_external_id=f"{ANOMALI_SOURCE_SLUG}:{identifier}",
        canonical_title="Private-looking title that must not be printed",
        canonical_url=f"https://www.anomali.com/blog/{identifier}",
        safe_source_payload={"authors": ("Private-looking author",)},
    )


def collection(
    *,
    candidates: tuple[PublicationCandidate, ...] | None = None,
    failures: tuple[AnomaliFailureReason, ...] = (),
    capped: bool = False,
    source_slug: str = ANOMALI_SOURCE_SLUG,
) -> AnomaliCollectionResult:
    records = (candidate(),) if candidates is None else candidates
    return AnomaliCollectionResult(
        source_slug=source_slug,
        candidates=records,
        failure_count=len(failures),
        failure_reasons=failures,
        discovered_approved_link_count=len(records) + len(failures),
        capped=capped,
    )


def persisted_result(
    *,
    capped: object = False,
    **run_overrides: object,
) -> AnomaliIngestionResult:
    values: dict[str, object] = {
        "public_id": RUN_ID,
        "status": "succeeded",
        "records_fetched": 1,
        "records_created": 1,
        "records_updated": 0,
        "records_unchanged": 0,
        "records_skipped": 0,
        "records_failed": 0,
    }
    values.update(run_overrides)
    return AnomaliIngestionResult(
        run=SimpleNamespace(**values),  # type: ignore[arg-type]
        capped=capped,  # type: ignore[arg-type]
    )


class FakeCollector:
    def __init__(
        self,
        result: AnomaliCollectionResult | None = None,
        *,
        error: BaseException | None = None,
        exit_error: BaseException | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.exit_error = exit_error
        self.entered = False
        self.exited = False
        self.calls: list[int] = []

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        del exc_type, exc, traceback
        self.exited = True
        if self.exit_error is not None:
            raise self.exit_error

    def fetch_publications(self, *, max_records: int) -> AnomaliCollectionResult:
        self.calls.append(max_records)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


class FakeSession:
    def __init__(self, *, close_error: BaseException | None = None) -> None:
        self.close_error = close_error
        self.closed = False
        self.close_attempts = 0
        self.rollbacks = 0

    def close(self) -> None:
        self.close_attempts += 1
        if self.close_error is not None:
            raise self.close_error
        self.closed = True

    def rollback(self) -> None:
        self.rollbacks += 1


class CapturingService:
    def __init__(
        self,
        *,
        status: str = "succeeded",
        error: BaseException | None = None,
        result: object | None = None,
    ) -> None:
        self.status = status
        self.error = error
        self.result = result
        self.calls: list[dict[str, object]] = []

    def ingest(self, **kwargs: object) -> AnomaliIngestionResult:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        if self.result is not None:
            return self.result  # type: ignore[return-value]
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
            records_failed=(
                len(failures) if failures else int(self.status == "failed")
            ),
        )
        return AnomaliIngestionResult(
            run=run,  # type: ignore[arg-type]
            capped=kwargs["capped"],  # type: ignore[arg-type]
        )


def run_main(
    argv: list[str],
    *,
    result: AnomaliCollectionResult | None = None,
    collector_error: BaseException | None = None,
    collector_exit_error: BaseException | None = None,
    status: str = "succeeded",
    service_error: BaseException | None = None,
    service_result: object | None = None,
    session: FakeSession | None = None,
    clock=lambda: NOW,
):
    active_session = session or FakeSession()
    collector = FakeCollector(
        result,
        error=collector_error,
        exit_error=collector_exit_error,
    )
    service = CapturingService(
        status=status,
        error=service_error,
        result=service_result,
    )
    order: list[str] = []

    original_fetch = collector.fetch_publications

    def observed_fetch(*, max_records: int):
        order.append("collection")
        return original_fetch(max_records=max_records)

    collector.fetch_publications = observed_fetch  # type: ignore[method-assign]

    def session_factory() -> FakeSession:
        order.append("session")
        return active_session

    stdout = StringIO()
    stderr = StringIO()
    exit_code = anomali_publications_live_cli.main(
        argv,
        collector_factory=lambda: collector,  # type: ignore[arg-type]
        session_factory=session_factory,  # type: ignore[arg-type]
        service_factory=lambda _: service,  # type: ignore[arg-type]
        clock=clock,
        stdout=stdout,
        stderr=stderr,
    )
    return SimpleNamespace(
        exit_code=exit_code,
        stdout=stdout.getvalue(),
        stderr=stderr.getvalue(),
        collector=collector,
        session=active_session,
        service=service,
        order=order,
    )


def test_default_collects_before_session_and_persists_owned_source() -> None:
    outcome = run_main([], result=collection())

    assert outcome.exit_code == 0
    assert outcome.order == ["collection", "session"]
    assert outcome.collector.calls == [5]
    assert outcome.collector.entered is True
    assert outcome.collector.exited is True
    assert outcome.session.closed is True
    assert outcome.service.calls[0]["source_slug"] == ANOMALI_SOURCE_SLUG
    assert outcome.service.calls[0]["records_fetched"] == 1
    assert outcome.service.calls[0]["capped"] is False


@pytest.mark.parametrize("maximum", [1, 20])
def test_boundary_max_records_reaches_collector(maximum: int) -> None:
    outcome = run_main(
        ["--max-records", str(maximum)],
        result=collection(candidates=()),
    )

    assert outcome.exit_code == 0
    assert outcome.collector.calls == [maximum]


@pytest.mark.parametrize(
    "argv",
    [
        ["--max-records", "0"],
        ["--max-records", "-1"],
        ["--max-records", "21"],
        ["--max-records", "1.0"],
        ["--max-records", "true"],
        ["--max-records", "01"],
        ["--max-records", "+1"],
        ["--max-records", "5", "--max-records", "6"],
        ["--source", "anomali"],
        ["--url", "https://private.example/"],
        ["positional"],
    ],
)
def test_invalid_cli_values_are_rejected_without_collection_or_session(
    argv: list[str],
) -> None:
    outcome = run_main(argv, result=collection())

    assert outcome.exit_code == 2
    assert outcome.order == []
    assert outcome.collector.entered is False
    assert outcome.session.close_attempts == 0
    assert outcome.stdout == ""
    assert outcome.stderr == "Invalid manual Anomali live ingestion arguments.\n"
    assert "private.example" not in outcome.stderr


@pytest.mark.parametrize("value", [True, False, "5", 5.0, 0, -1, 21])
def test_direct_run_rejects_non_strict_max_records(value: object) -> None:
    stdout = StringIO()
    stderr = StringIO()

    exit_code = anomali_publications_live_cli.run_live_ingestion(
        max_records=value,  # type: ignore[arg-type]
        collector_factory=lambda: pytest.fail("collector must not be created"),
        session_factory=lambda: pytest.fail("session must not be created"),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 2
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "Invalid manual Anomali live ingestion arguments.\n"


def test_success_summary_contains_only_allowlisted_operational_fields() -> None:
    outcome = run_main([], result=collection())

    assert outcome.exit_code == 0
    assert outcome.stderr == ""
    assert outcome.stdout == (
        "Manual Anomali live ingestion completed.\n"
        f"Source: {ANOMALI_SOURCE_SLUG}\n"
        f"Run ID: {RUN_ID}\n"
        "Status: succeeded\n"
        "Fetched: 1\n"
        "Created: 1\n"
        "Updated: 0\n"
        "Unchanged: 0\n"
        "Skipped: 0\n"
        "Failed: 0\n"
        "Capped: false\n"
    )
    assert "Private-looking" not in outcome.stdout
    assert "https://" not in outcome.stdout


def test_article_failure_and_capped_state_are_safe_partial_summary() -> None:
    outcome = run_main(
        ["--max-records", "2"],
        result=collection(
            failures=(AnomaliFailureReason.TIMEOUT,),
            capped=True,
        ),
        status="partial",
    )

    assert outcome.exit_code == 1
    assert "Status: partial" in outcome.stdout
    assert "Fetched: 2" in outcome.stdout
    assert "Failed: 1" in outcome.stdout
    assert "Capped: true" in outcome.stdout
    assert "controlled failure" in outcome.stderr
    assert outcome.service.calls[0]["capped"] is True
    failure_kinds = outcome.service.calls[0]["failure_kinds"]
    assert tuple(item.value for item in failure_kinds) == ("timeout",)  # type: ignore[union-attr]


def test_capped_true_with_fewer_records_than_requested_creates_no_session() -> None:
    outcome = run_main(
        [],
        result=collection(candidates=(candidate(),), capped=True),
    )

    assert outcome.exit_code == 1
    assert outcome.order == ["collection"]
    assert outcome.session.close_attempts == 0
    assert outcome.stdout == ""
    assert outcome.stderr == "Anomali live collection failed safely.\n"


@pytest.mark.parametrize(
    ("service_result", "secret"),
    [
        (persisted_result(public_id="SECRET-id"), "SECRET-id"),
        (
            persisted_result(public_id="bad-id\nINJECTED: https://private.example/"),
            "INJECTED",
        ),
        (persisted_result(status="SECRET-status"), "SECRET-status"),
        (persisted_result(records_created=True), "True"),
        (
            persisted_result(records_created=-1, records_unchanged=2),
            "-1",
        ),
        (persisted_result(records_created="SECRET-counter"), "SECRET-counter"),
        (persisted_result(records_created=0), "counter-total"),
        (
            persisted_result(records_fetched=2, records_created=2),
            "fetched-mismatch",
        ),
        (persisted_result(capped="SECRET-capped"), "SECRET-capped"),
        (persisted_result(capped=True), "capped-mismatch"),
        (
            AnomaliIngestionResult(
                run=SimpleNamespace(public_id=RUN_ID),  # type: ignore[arg-type]
                capped=False,
            ),
            "missing-attributes",
        ),
        (SimpleNamespace(run="SECRET object repr"), "SECRET object repr"),
    ],
    ids=[
        "public-id-string",
        "public-id-newline",
        "status",
        "bool-counter",
        "negative-counter",
        "string-counter",
        "counter-total",
        "fetched-count",
        "non-bool-capped",
        "capped-mismatch",
        "missing-run-attributes",
        "wrong-result-type",
    ],
)
def test_malformed_service_result_is_sanitized_before_output_and_closes_session(
    service_result: object,
    secret: str,
) -> None:
    outcome = run_main(
        [],
        result=collection(),
        service_result=service_result,
    )

    assert outcome.exit_code == 1
    assert outcome.session.closed is True
    assert outcome.session.close_attempts == 1
    assert outcome.stdout == ""
    assert outcome.stderr == "Manual Anomali live ingestion failed safely.\n"
    assert secret not in outcome.stdout + outcome.stderr
    assert "https://" not in outcome.stdout + outcome.stderr
    assert "Traceback" not in outcome.stdout + outcome.stderr


def test_malformed_result_with_close_failure_keeps_generic_ingestion_message() -> None:
    session = FakeSession(close_error=RuntimeError("SECRET close configuration"))

    outcome = run_main(
        [],
        result=collection(),
        service_result=persisted_result(status="SECRET malformed status"),
        session=session,
    )

    assert outcome.exit_code == 1
    assert session.close_attempts == 1
    assert outcome.stdout == ""
    assert outcome.stderr == "Manual Anomali live ingestion failed safely.\n"
    assert "SECRET" not in outcome.stderr


@pytest.mark.parametrize(
    ("status", "records", "failures", "maximum", "expected_exit"),
    [
        ("succeeded", (candidate(),), (), 5, 0),
        (
            "partial",
            (candidate(),),
            (AnomaliFailureReason.TIMEOUT,),
            2,
            1,
        ),
        ("failed", (), (AnomaliFailureReason.HTTP_FAILURE,), 1, 1),
    ],
)
def test_valid_completed_status_summaries_remain_stable(
    status: str,
    records: tuple[PublicationCandidate, ...],
    failures: tuple[AnomaliFailureReason, ...],
    maximum: int,
    expected_exit: int,
) -> None:
    outcome = run_main(
        ["--max-records", str(maximum)],
        result=collection(candidates=records, failures=failures),
        status=status,
    )

    assert outcome.exit_code == expected_exit
    assert f"Status: {status}\n" in outcome.stdout
    assert f"Fetched: {len(records) + len(failures)}\n" in outcome.stdout
    assert "Capped: false\n" in outcome.stdout
    if expected_exit == 0:
        assert outcome.stderr == ""
    else:
        assert outcome.stderr == (
            "Manual Anomali live ingestion completed with a controlled failure.\n"
        )


class SystemExceptionRun:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    @property
    def public_id(self):
        raise self.error


@pytest.mark.parametrize(
    "error",
    [MemoryError("memory"), KeyboardInterrupt(), SystemExit(3), GeneratorExit()],
)
def test_system_exception_during_result_field_access_propagates_after_close(
    error: BaseException,
) -> None:
    session = FakeSession()
    result = AnomaliIngestionResult(
        run=SystemExceptionRun(error),  # type: ignore[arg-type]
        capped=False,
    )

    with pytest.raises(type(error)) as exc_info:
        run_main(
            [],
            result=collection(),
            service_result=result,
            session=session,
        )

    assert exc_info.value is error
    assert session.close_attempts == 1
    assert session.closed is True


class SystemExceptionWriter:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def write(self, value: str) -> int:
        del value
        raise self.error


@pytest.mark.parametrize(
    "error",
    [MemoryError("memory"), KeyboardInterrupt(), SystemExit(4), GeneratorExit()],
)
def test_system_exception_during_valid_summary_printing_propagates_after_close(
    error: BaseException,
) -> None:
    session = FakeSession()
    collector = FakeCollector(collection())
    service = CapturingService()

    with pytest.raises(type(error)) as exc_info:
        anomali_publications_live_cli.main(
            [],
            collector_factory=lambda: collector,  # type: ignore[arg-type]
            session_factory=lambda: session,  # type: ignore[arg-type]
            service_factory=lambda _: service,  # type: ignore[arg-type]
            clock=lambda: NOW,
            stdout=SystemExceptionWriter(error),  # type: ignore[arg-type]
            stderr=StringIO(),
        )

    assert exc_info.value is error
    assert session.close_attempts == 1
    assert session.closed is True


@pytest.mark.parametrize(
    "error",
    [
        AnomaliDiscoveryCollectionError("SECRET discovery URL"),
        AnomaliRequestStateIsolationError("SECRET cookie isolation"),
        AnomaliTimeoutError("SECRET timeout response"),
        AnomaliTransportError("SECRET transport headers"),
        AnomaliHttpError("SECRET HTTP body"),
        RuntimeError("SECRET unexpected metadata"),
    ],
)
def test_collection_failures_are_sanitized_and_create_no_session(
    error: BaseException,
) -> None:
    outcome = run_main([], collector_error=error)

    assert outcome.exit_code == 1
    assert outcome.order == ["collection"]
    assert outcome.collector.exited is True
    assert outcome.session.close_attempts == 0
    assert outcome.stdout == ""
    assert outcome.stderr == "Anomali live collection failed safely.\n"
    assert "SECRET" not in outcome.stderr
    assert "Traceback" not in outcome.stderr


def test_collector_close_failure_before_session_is_sanitized() -> None:
    outcome = run_main(
        [],
        result=collection(),
        collector_exit_error=AnomaliTransportError("SECRET close cookie"),
    )

    assert outcome.exit_code == 1
    assert outcome.order == ["collection"]
    assert outcome.session.close_attempts == 0
    assert outcome.stderr == "Anomali live collection failed safely.\n"


@pytest.mark.parametrize(
    "malformed",
    [
        collection(source_slug="not-anomali"),
        AnomaliCollectionResult(
            source_slug=ANOMALI_SOURCE_SLUG,
            candidates=(candidate(),),
            failure_count=1,
            failure_reasons=(),
            discovered_approved_link_count=1,
            capped=False,
        ),
        AnomaliCollectionResult(
            source_slug=ANOMALI_SOURCE_SLUG,
            candidates=(candidate(),),
            failure_count=0,
            failure_reasons=(),
            discovered_approved_link_count=20,
            capped=True,
        ),
    ],
)
def test_invalid_collection_result_creates_no_session(
    malformed: AnomaliCollectionResult,
) -> None:
    outcome = run_main([], result=malformed)

    assert outcome.exit_code == 1
    assert outcome.order == ["collection"]
    assert outcome.session.close_attempts == 0
    assert outcome.stderr == "Anomali live collection failed safely.\n"


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            AnomaliIngestionDatabaseError("SECRET SQL database URL"),
            "Manual Anomali live ingestion failed during a database operation.\n",
        ),
        (
            SQLAlchemyError("SECRET SQL statement"),
            "Manual Anomali live ingestion failed during a database operation.\n",
        ),
        (
            AnomaliIngestionError("SECRET raw payload"),
            "Manual Anomali live ingestion failed safely.\n",
        ),
    ],
)
def test_database_and_ingestion_failures_are_sanitized_and_close_session(
    error: BaseException,
    expected: str,
) -> None:
    outcome = run_main([], result=collection(), service_error=error)

    assert outcome.exit_code == 1
    assert outcome.session.closed is True
    assert outcome.stdout == ""
    assert outcome.stderr == expected
    assert "SECRET" not in outcome.stderr
    assert "Traceback" not in outcome.stderr


def test_session_creation_failure_is_sanitized_without_cleanup_attempt() -> None:
    collector = FakeCollector(collection())
    stdout = StringIO()
    stderr = StringIO()

    exit_code = anomali_publications_live_cli.main(
        [],
        collector_factory=lambda: collector,  # type: ignore[arg-type]
        session_factory=lambda: (_ for _ in ()).throw(
            RuntimeError("SECRET postgresql://private/database")
        ),
        service_factory=lambda _: pytest.fail("service must not be created"),
        clock=lambda: NOW,
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 1
    assert collector.exited is True
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "Manual Anomali live ingestion failed during a database operation.\n"
    )
    assert "SECRET" not in stderr.getvalue()


def test_session_close_failure_is_sanitized_after_success() -> None:
    session = FakeSession(close_error=RuntimeError("SECRET database configuration"))

    outcome = run_main([], result=collection(), session=session)

    assert outcome.exit_code == 1
    assert session.close_attempts == 1
    assert outcome.stdout == ""
    assert outcome.stderr == (
        "Manual Anomali live ingestion failed during a database operation.\n"
    )
    assert "SECRET" not in outcome.stderr


@pytest.mark.parametrize(
    "error",
    [MemoryError("memory"), KeyboardInterrupt(), SystemExit(9), GeneratorExit()],
)
@pytest.mark.parametrize("stage", ["collector", "clock", "service"])
def test_system_exceptions_propagate_and_resources_close(
    error: BaseException,
    stage: str,
) -> None:
    result = collection()
    collector_error = error if stage == "collector" else None
    service_error = error if stage == "service" else None

    with pytest.raises(type(error)) as exc_info:
        outcome = run_main(
            [],
            result=result,
            collector_error=collector_error,
            service_error=service_error,
            clock=(lambda: (_ for _ in ()).throw(error)) if stage == "clock" else (lambda: NOW),
        )
        pytest.fail(f"unexpected result: {outcome}")

    assert exc_info.value is error


def test_collector_cleanup_does_not_replace_active_system_exception() -> None:
    primary = MemoryError("primary")
    secondary = RuntimeError("secondary SECRET close")
    collector = FakeCollector(error=primary, exit_error=secondary)

    with pytest.raises(MemoryError) as exc_info:
        anomali_publications_live_cli.main(
            [],
            collector_factory=lambda: collector,  # type: ignore[arg-type]
            session_factory=lambda: pytest.fail("session must not be created"),
            stdout=StringIO(),
            stderr=StringIO(),
        )

    assert exc_info.value is primary
    assert collector.exited is True


def test_active_service_system_exception_is_not_replaced_by_close_failure() -> None:
    primary = MemoryError("primary")
    session = FakeSession(close_error=MemoryError("secondary"))

    with pytest.raises(MemoryError) as exc_info:
        run_main(
            [],
            result=collection(),
            service_error=primary,
            session=session,
        )

    assert exc_info.value is primary
    assert session.close_attempts == 1


@pytest.mark.parametrize(
    "clock",
    [
        lambda: datetime(2026, 7, 19, 9, 0),
        lambda: "SECRET non-datetime",
        lambda: (_ for _ in ()).throw(RuntimeError("SECRET clock detail")),
    ],
)
def test_unsafe_clock_is_sanitized_before_session(clock) -> None:
    outcome = run_main([], result=collection(), clock=clock)

    assert outcome.exit_code == 1
    assert outcome.order == ["collection"]
    assert outcome.session.close_attempts == 0
    assert outcome.stderr == "Anomali live collection failed safely.\n"
    assert "SECRET" not in outcome.stderr


def test_all_valid_live_tests_remain_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def network_forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("Live requests are forbidden in this test.")

    monkeypatch.setattr(socket, "create_connection", network_forbidden)

    outcome = run_main([], result=collection())

    assert outcome.exit_code == 0
    assert outcome.collector.calls == [5]
