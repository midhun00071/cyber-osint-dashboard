"""Validate and import the fixed bundled public-intelligence snapshot offline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ingestion.normalizers.nvd import NvdNormalizationError, normalize_nvd_cve
from app.ingestion.publication_pipeline import (
    PublicationCandidate,
    PublicationPipeline,
    PublicationPipelineError,
    normalize_publication_candidate,
)
from app.ingestion.services.nvd_ingestion_service import (
    NvdIngestionService,
    NvdPersistenceError,
)
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    SourceRecord,
    Vulnerability,
)


SNAPSHOT_PATH = Path(__file__).with_name("snapshot.json")
SNAPSHOT_SCHEMA_VERSION = 1
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_DEPTH = 32
MAX_NVD_PAYLOAD_BYTES = 64 * 1024
EXPECTED_NVD_RECORDS = 100
EXPECTED_PUBLICATION_RECORDS = 12
PUBLICATION_COUNTS = {
    "cert-eu-security-advisories": 4,
    "google-threat-intelligence-public-research": 4,
    "mandiant-public-threat-research": 4,
}
ALLOWED_SOURCE_SLUGS = frozenset(("nvd", *PUBLICATION_COUNTS))
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "observation_timestamp",
        "nvd_records",
        "publication_records",
    }
)
_NVD_FIELDS = frozenset({"source_slug", "cve_id", "raw_payload"})
_PUBLICATION_FIELDS = frozenset(
    {
        "source_slug",
        "source_external_id",
        "canonical_title",
        "canonical_url",
        "summary",
        "source_published_at",
        "source_modified_at",
        "safe_source_payload",
    }
)


class BootstrapDataError(RuntimeError):
    """The bundled snapshot could not be validated or persisted safely."""


class _SnapshotContractError(ValueError):
    """Internal detail for a rejected immutable snapshot contract."""


@dataclass(frozen=True, slots=True)
class NvdBootstrapRecord:
    source_slug: str
    cve_id: str
    canonical_payload: bytes


@dataclass(frozen=True, slots=True)
class PublicationBootstrapRecord:
    source_slug: str
    source_external_id: str
    canonical_title: str
    canonical_url: str
    summary: str | None
    source_published_at: datetime | None
    source_modified_at: datetime | None
    canonical_safe_payload: bytes


@dataclass(frozen=True, slots=True)
class BootstrapSnapshot:
    schema_version: int
    observation_timestamp: datetime
    nvd_records: tuple[NvdBootstrapRecord, ...]
    publication_records: tuple[PublicationBootstrapRecord, ...]


@dataclass(frozen=True, slots=True)
class BootstrapDataResult:
    attempted: bool
    created: int
    updated: int
    unchanged: int
    existing_state_rows: int


def load_bootstrap_snapshot() -> BootstrapSnapshot:
    """Load only the application-packaged snapshot from its fixed path."""

    try:
        raw_bytes = SNAPSHOT_PATH.read_bytes()
    except OSError as exc:
        raise BootstrapDataError(
            "The bundled bootstrap snapshot could not be loaded safely."
        ) from exc
    return _parse_snapshot_bytes(raw_bytes)


def bootstrap_offline_intelligence(session: Session) -> BootstrapDataResult:
    """Import the bundled snapshot only when all intelligence tables are empty."""

    existing_counts = tuple(
        int(session.scalar(select(func.count(model.id))) or 0)
        for model in (
            IntelligenceItem,
            SourceRecord,
            IntelligenceItemIdentifier,
            Vulnerability,
        )
    )
    existing_state_rows = sum(existing_counts)
    if existing_state_rows:
        return BootstrapDataResult(False, 0, 0, 0, existing_state_rows)

    snapshot = load_bootstrap_snapshot()
    outcomes: list[str] = []
    try:
        nvd_service = NvdIngestionService(session)
        for record in snapshot.nvd_records:
            raw_payload = json.loads(record.canonical_payload)
            normalized = normalize_nvd_cve(raw_payload)
            result = nvd_service.persist(
                normalized,
                observed_at=snapshot.observation_timestamp,
            )
            if result.outcome not in {"created", "updated", "unchanged"}:
                raise BootstrapDataError(
                    "Bundled NVD bootstrap intelligence could not be persisted safely."
                )
            outcomes.append(result.outcome)

        publication_pipeline = PublicationPipeline(session)
        for record in snapshot.publication_records:
            candidate = PublicationCandidate(
                source_slug=record.source_slug,
                source_external_id=record.source_external_id,
                canonical_title=record.canonical_title,
                canonical_url=record.canonical_url,
                summary=record.summary,
                source_published_at=record.source_published_at,
                source_modified_at=record.source_modified_at,
                safe_source_payload=json.loads(record.canonical_safe_payload),
            )
            result = publication_pipeline.persist(
                candidate,
                observed_at=snapshot.observation_timestamp,
            )
            if result.outcome not in {"created", "updated", "unchanged"}:
                raise BootstrapDataError(
                    "Bundled publication bootstrap intelligence could not be persisted safely."
                )
            outcomes.append(result.outcome)
    except BootstrapDataError:
        raise
    except (
        json.JSONDecodeError,
        NvdNormalizationError,
        NvdPersistenceError,
        PublicationPipelineError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise BootstrapDataError(
            "Bundled bootstrap intelligence could not be persisted safely."
        ) from exc

    return BootstrapDataResult(
        attempted=True,
        created=outcomes.count("created"),
        updated=outcomes.count("updated"),
        unchanged=outcomes.count("unchanged"),
        existing_state_rows=0,
    )


def _parse_snapshot_bytes(raw_bytes: bytes) -> BootstrapSnapshot:
    try:
        if not isinstance(raw_bytes, bytes) or not raw_bytes:
            raise _SnapshotContractError("empty snapshot")
        if len(raw_bytes) > MAX_SNAPSHOT_BYTES:
            raise _SnapshotContractError("snapshot size")
        text = raw_bytes.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
        )
        _validate_depth(document)
        root = _require_object(document)
        _require_exact_fields(root, _TOP_LEVEL_FIELDS)
        if type(root["schema_version"]) is not int:
            raise _SnapshotContractError("schema version type")
        if root["schema_version"] != SNAPSHOT_SCHEMA_VERSION:
            raise _SnapshotContractError("unsupported schema version")
        observation_timestamp = _parse_timestamp(
            root["observation_timestamp"], required=True
        )
        nvd_documents = _require_sequence(root["nvd_records"])
        publication_documents = _require_sequence(root["publication_records"])
        if len(nvd_documents) != EXPECTED_NVD_RECORDS:
            raise _SnapshotContractError("NVD record count")
        if len(publication_documents) != EXPECTED_PUBLICATION_RECORDS:
            raise _SnapshotContractError("publication record count")

        nvd_records = _validate_nvd_records(nvd_documents)
        publication_records = _validate_publication_records(publication_documents)
        return BootstrapSnapshot(
            schema_version=SNAPSHOT_SCHEMA_VERSION,
            observation_timestamp=observation_timestamp,
            nvd_records=nvd_records,
            publication_records=publication_records,
        )
    except BootstrapDataError:
        raise
    except (
        json.JSONDecodeError,
        _SnapshotContractError,
        NvdNormalizationError,
        PublicationPipelineError,
        KeyError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise BootstrapDataError(
            "The bundled bootstrap snapshot failed validation."
        ) from exc


def _validate_nvd_records(
    documents: Sequence[object],
) -> tuple[NvdBootstrapRecord, ...]:
    records: list[NvdBootstrapRecord] = []
    identities: set[str] = set()
    for value in documents:
        document = _require_object(value)
        _require_exact_fields(document, _NVD_FIELDS)
        source_slug = _require_string(document["source_slug"])
        cve_id = _require_string(document["cve_id"])
        if source_slug != "nvd" or source_slug not in ALLOWED_SOURCE_SLUGS:
            raise _SnapshotContractError("NVD source slug")
        if cve_id in identities:
            raise _SnapshotContractError("duplicate CVE identity")
        raw_payload = _require_object(document["raw_payload"])
        canonical_payload = _canonical_bytes(raw_payload)
        if len(canonical_payload) > MAX_NVD_PAYLOAD_BYTES:
            raise _SnapshotContractError("NVD payload size")
        normalized = normalize_nvd_cve(dict(raw_payload))
        if normalized.cve_id != cve_id:
            raise _SnapshotContractError("NVD identity mismatch")
        identities.add(cve_id)
        records.append(NvdBootstrapRecord(source_slug, cve_id, canonical_payload))
    return tuple(records)


def _validate_publication_records(
    documents: Sequence[object],
) -> tuple[PublicationBootstrapRecord, ...]:
    records: list[PublicationBootstrapRecord] = []
    identity_keys: set[tuple[str, str]] = set()
    url_keys: set[tuple[str, str]] = set()
    source_counts = {slug: 0 for slug in PUBLICATION_COUNTS}
    for value in documents:
        document = _require_object(value)
        _require_exact_fields(document, _PUBLICATION_FIELDS)
        source_slug = _require_string(document["source_slug"])
        if source_slug not in PUBLICATION_COUNTS:
            raise _SnapshotContractError("publication source slug")
        source_external_id = _require_string(document["source_external_id"])
        canonical_title = _require_string(document["canonical_title"])
        canonical_url = _require_string(document["canonical_url"])
        summary = _optional_string(document["summary"])
        source_published_at = _parse_timestamp(
            document["source_published_at"], required=False
        )
        source_modified_at = _parse_timestamp(
            document["source_modified_at"], required=False
        )
        safe_payload = _require_object(document["safe_source_payload"])
        canonical_safe_payload = _canonical_bytes(safe_payload)
        candidate = PublicationCandidate(
            source_slug=source_slug,
            source_external_id=source_external_id,
            canonical_title=canonical_title,
            canonical_url=canonical_url,
            summary=summary,
            source_published_at=source_published_at,
            source_modified_at=source_modified_at,
            safe_source_payload=safe_payload,
        )
        normalized = normalize_publication_candidate(candidate)
        if (
            normalized.source_external_id != source_external_id
            or normalized.canonical_title != canonical_title
            or normalized.canonical_url != canonical_url
            or normalized.summary != summary
            or normalized.source_published_at != source_published_at
            or normalized.source_modified_at != source_modified_at
            or normalized.raw_payload != safe_payload
        ):
            raise _SnapshotContractError("publication field normalization")
        identity_key = (source_slug, normalized.source_external_id)
        url_key = (source_slug, normalized.canonical_url_hash)
        if identity_key in identity_keys or url_key in url_keys:
            raise _SnapshotContractError("duplicate publication identity")
        identity_keys.add(identity_key)
        url_keys.add(url_key)
        source_counts[source_slug] += 1
        records.append(
            PublicationBootstrapRecord(
                source_slug=source_slug,
                source_external_id=source_external_id,
                canonical_title=canonical_title,
                canonical_url=canonical_url,
                summary=summary,
                source_published_at=source_published_at,
                source_modified_at=source_modified_at,
                canonical_safe_payload=canonical_safe_payload,
            )
        )
    if source_counts != PUBLICATION_COUNTS:
        raise _SnapshotContractError("publication source counts")
    return tuple(records)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _SnapshotContractError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonstandard_constant(_value: str) -> object:
    raise _SnapshotContractError("non-standard JSON constant")


def _validate_depth(value: object, depth: int = 1) -> None:
    if depth > MAX_SNAPSHOT_DEPTH:
        raise _SnapshotContractError("snapshot nesting depth")
    if isinstance(value, Mapping):
        for child in value.values():
            _validate_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_depth(child, depth + 1)


def _require_object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _SnapshotContractError("expected object")
    return value


def _require_sequence(value: object) -> list[object]:
    if not isinstance(value, list):
        raise _SnapshotContractError("expected array")
    return value


def _require_exact_fields(
    value: Mapping[str, object], expected: frozenset[str]
) -> None:
    if frozenset(value) != expected:
        raise _SnapshotContractError("unexpected snapshot fields")


def _require_string(value: object) -> str:
    if not isinstance(value, str):
        raise _SnapshotContractError("expected string")
    return value


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return _require_string(value)


def _parse_timestamp(value: object, *, required: bool) -> datetime | None:
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise _SnapshotContractError("timestamp type")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise _SnapshotContractError("timezone-aware timestamp")
        return parsed.astimezone(UTC)
    except _SnapshotContractError:
        raise
    except (TypeError, ValueError, OverflowError) as exc:
        raise _SnapshotContractError("invalid timestamp") from exc


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _SnapshotContractError("canonical JSON") from exc


__all__ = [
    "ALLOWED_SOURCE_SLUGS",
    "BootstrapDataError",
    "BootstrapDataResult",
    "BootstrapSnapshot",
    "EXPECTED_NVD_RECORDS",
    "EXPECTED_PUBLICATION_RECORDS",
    "PUBLICATION_COUNTS",
    "bootstrap_offline_intelligence",
    "load_bootstrap_snapshot",
]
