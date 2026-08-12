from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.bootstrap_data.service as bootstrap_service
from app.bootstrap_data.service import (
    ALLOWED_SOURCE_SLUGS,
    BootstrapDataError,
    PUBLICATION_COUNTS,
    _parse_snapshot_bytes,
    bootstrap_offline_intelligence,
    load_bootstrap_snapshot,
)
from app.ingestion.normalizers.nvd import NormalizedNvdCve
from app.ingestion.publication_pipeline import PublicationCandidate


SNAPSHOT_PATH = (
    Path(__file__).resolve().parents[1]
    / "app"
    / "bootstrap_data"
    / "snapshot.json"
)
SERVICE_PATH = SNAPSHOT_PATH.with_name("service.py")


def snapshot_document() -> dict[str, object]:
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def encoded(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


class CountSession:
    def __init__(self, counts: tuple[int, int, int, int]) -> None:
        self.counts = list(counts)

    def scalar(self, _statement):
        return self.counts.pop(0)


class RecordingNvdService:
    def __init__(self, outcomes: list[str] | None = None) -> None:
        self.calls: list[tuple[NormalizedNvdCve, object]] = []
        self.outcomes = list(outcomes or ["created"] * 100)

    def persist(self, normalized, *, observed_at):
        self.calls.append((normalized, observed_at))
        return SimpleNamespace(outcome=self.outcomes.pop(0))


class RecordingPublicationPipeline:
    def __init__(self, outcomes: list[str] | None = None) -> None:
        self.calls: list[tuple[PublicationCandidate, object]] = []
        self.outcomes = list(outcomes or ["created"] * 12)

    def persist(self, candidate, *, observed_at):
        self.calls.append((candidate, observed_at))
        return SimpleNamespace(outcome=self.outcomes.pop(0))


def install_recorders(
    monkeypatch,
    *,
    nvd_outcomes: list[str] | None = None,
    publication_outcomes: list[str] | None = None,
) -> tuple[RecordingNvdService, RecordingPublicationPipeline]:
    nvd = RecordingNvdService(nvd_outcomes)
    publications = RecordingPublicationPipeline(publication_outcomes)
    monkeypatch.setattr(bootstrap_service, "NvdIngestionService", lambda _session: nvd)
    monkeypatch.setattr(
        bootstrap_service,
        "PublicationPipeline",
        lambda _session: publications,
    )
    return nvd, publications


def test_valid_fixed_snapshot_contract_loads_successfully() -> None:
    snapshot = load_bootstrap_snapshot()

    assert snapshot.schema_version == 1
    assert snapshot.observation_timestamp.tzinfo is not None
    assert len(snapshot.nvd_records) == 100
    assert len(snapshot.publication_records) == 12


def test_snapshot_has_exact_counts_and_only_approved_source_identities() -> None:
    snapshot = load_bootstrap_snapshot()
    source_counts = {
        slug: sum(
            record.source_slug == slug for record in snapshot.publication_records
        )
        for slug in PUBLICATION_COUNTS
    }

    assert source_counts == PUBLICATION_COUNTS
    assert {record.source_slug for record in snapshot.nvd_records} == {"nvd"}
    assert {
        *(record.source_slug for record in snapshot.nvd_records),
        *(record.source_slug for record in snapshot.publication_records),
    } == ALLOWED_SOURCE_SLUGS


def test_malformed_json_fails_closed_with_sanitized_error() -> None:
    with pytest.raises(BootstrapDataError, match="failed validation") as exc_info:
        _parse_snapshot_bytes(b'{"schema_version":')

    assert "line" not in str(exc_info.value).lower()


def test_duplicate_json_keys_fail_closed() -> None:
    raw = b'{"schema_version":1,"schema_version":1}'

    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(raw)


def test_unsupported_schema_version_fails_closed() -> None:
    document = snapshot_document()
    document["schema_version"] = 2

    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(encoded(document))


@pytest.mark.parametrize("collection", ("nvd_records", "publication_records"))
def test_wrong_record_counts_fail_closed(collection: str) -> None:
    document = snapshot_document()
    document[collection].pop()  # type: ignore[union-attr]

    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(encoded(document))


def test_duplicate_cve_identity_fails_closed() -> None:
    document = snapshot_document()
    records = document["nvd_records"]
    records[1] = deepcopy(records[0])  # type: ignore[index]

    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(encoded(document))


def test_duplicate_publication_identity_fails_closed() -> None:
    document = snapshot_document()
    records = document["publication_records"]
    records[1] = deepcopy(records[0])  # type: ignore[index]

    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(encoded(document))


def test_over_64_kib_nvd_record_fails_closed() -> None:
    document = snapshot_document()
    first = document["nvd_records"][0]  # type: ignore[index]
    first["raw_payload"]["oversized"] = "x" * (64 * 1024)  # type: ignore[index]

    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(encoded(document))


@pytest.mark.parametrize(
    "field,container",
    (
        ("observation_timestamp", None),
        ("source_published_at", "publication_records"),
        ("source_modified_at", "publication_records"),
    ),
)
def test_invalid_or_naive_timestamp_fails_closed(field: str, container: str | None) -> None:
    document = snapshot_document()
    target = document if container is None else document[container][0]  # type: ignore[index]
    target[field] = "2026-08-12T10:17:00"  # type: ignore[index]

    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(encoded(document))


@pytest.mark.parametrize("collection", ("nvd_records", "publication_records"))
def test_unexpected_source_slug_fails_closed(collection: str) -> None:
    document = snapshot_document()
    document[collection][0]["source_slug"] = "unexpected-source"  # type: ignore[index]

    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(encoded(document))


@pytest.mark.parametrize(
    "field,value",
    (
        ("summary", "x" * 10_001),
        ("canonical_url", "https://cert.europa.eu/publications/security-advisories/2026-001/?utm_source=test"),
    ),
)
def test_publication_fields_must_already_be_bounded_and_canonical(
    field: str, value: str
) -> None:
    document = snapshot_document()
    document["publication_records"][0][field] = value  # type: ignore[index]

    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(encoded(document))


def test_nonstandard_json_constant_and_excessive_depth_fail_closed() -> None:
    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(b'{"value":NaN}')

    document = snapshot_document()
    nested: dict[str, object] = {}
    document["nvd_records"][0]["raw_payload"]["nested"] = nested  # type: ignore[index]
    for _ in range(35):
        child: dict[str, object] = {}
        nested["child"] = child
        nested = child
    with pytest.raises(BootstrapDataError, match="failed validation"):
        _parse_snapshot_bytes(encoded(document))


def test_empty_state_imports_through_normal_services_with_snapshot_observation(
    monkeypatch,
) -> None:
    nvd, publications = install_recorders(monkeypatch)

    result = bootstrap_offline_intelligence(CountSession((0, 0, 0, 0)))  # type: ignore[arg-type]

    assert result.attempted is True
    assert (result.created, result.updated, result.unchanged) == (112, 0, 0)
    assert len(nvd.calls) == 100
    assert len(publications.calls) == 12
    assert all(isinstance(call[0], NormalizedNvdCve) for call in nvd.calls)
    assert all(isinstance(call[0], PublicationCandidate) for call in publications.calls)
    observation_times = {call[1] for call in (*nvd.calls, *publications.calls)}
    assert observation_times == {load_bootstrap_snapshot().observation_timestamp}


def test_second_execution_and_existing_populated_state_create_no_duplicates(
    monkeypatch,
) -> None:
    nvd, publications = install_recorders(monkeypatch)

    first = bootstrap_offline_intelligence(CountSession((0, 0, 0, 0)))  # type: ignore[arg-type]
    second = bootstrap_offline_intelligence(CountSession((112, 112, 124, 100)))  # type: ignore[arg-type]

    assert first.created == 112
    assert second.attempted is False
    assert second.existing_state_rows == 448
    assert len(nvd.calls) == 100
    assert len(publications.calls) == 12


@pytest.mark.parametrize(
    "counts",
    (
        (1, 0, 0, 0),
        (0, 1, 0, 0),
        (0, 0, 1, 0),
        (0, 0, 0, 1),
        (5, 7, 0, 0),
    ),
)
def test_any_populated_or_partial_intelligence_state_is_untouched(
    monkeypatch, counts
) -> None:
    def forbidden_service(_session):
        raise AssertionError("persistence service must not be constructed")

    monkeypatch.setattr(bootstrap_service, "NvdIngestionService", forbidden_service)
    monkeypatch.setattr(bootstrap_service, "PublicationPipeline", forbidden_service)
    monkeypatch.setattr(
        bootstrap_service,
        "load_bootstrap_snapshot",
        lambda: (_ for _ in ()).throw(AssertionError("snapshot must not be loaded")),
    )

    result = bootstrap_offline_intelligence(CountSession(counts))  # type: ignore[arg-type]

    assert result.attempted is False
    assert result.existing_state_rows == sum(counts)


def test_failed_nvd_result_fails_the_bootstrap(monkeypatch) -> None:
    nvd, publications = install_recorders(
        monkeypatch,
        nvd_outcomes=["failed"],
    )

    with pytest.raises(BootstrapDataError, match="NVD bootstrap"):
        bootstrap_offline_intelligence(CountSession((0, 0, 0, 0)))  # type: ignore[arg-type]

    assert len(nvd.calls) == 1
    assert publications.calls == []


@pytest.mark.parametrize("outcome", ("failed", "skipped"))
def test_failed_or_skipped_publication_result_fails_the_bootstrap(
    monkeypatch, outcome: str
) -> None:
    nvd, publications = install_recorders(
        monkeypatch,
        publication_outcomes=[outcome],
    )

    with pytest.raises(BootstrapDataError, match="publication bootstrap"):
        bootstrap_offline_intelligence(CountSession((0, 0, 0, 0)))  # type: ignore[arg-type]

    assert len(nvd.calls) == 100
    assert len(publications.calls) == 1


def test_malformed_snapshot_starts_no_partial_persistence(monkeypatch) -> None:
    nvd, publications = install_recorders(monkeypatch)
    monkeypatch.setattr(
        bootstrap_service,
        "load_bootstrap_snapshot",
        lambda: (_ for _ in ()).throw(BootstrapDataError("safe failure")),
    )

    with pytest.raises(BootstrapDataError, match="safe failure"):
        bootstrap_offline_intelligence(CountSession((0, 0, 0, 0)))  # type: ignore[arg-type]

    assert nvd.calls == []
    assert publications.calls == []


def test_snapshot_loading_has_no_network_or_runtime_progress_capability() -> None:
    source = SERVICE_PATH.read_text(encoding="utf-8").lower()

    for forbidden in (
        "httpx",
        "requests",
        "urllib.request",
        "socket",
        "ingestioncycle",
        "ingestionrun",
        "sourcewatermark",
        "sourcecheckpoint",
    ):
        assert forbidden not in source
