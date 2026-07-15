"""Common validation and persistence pipeline for public publication candidates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
import json
import math
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.source_registry import (
    AccessMethod,
    ContentFamily,
    ImplementationStatus,
    SourceDefinition,
    SourceRegistryError,
    get_source_definition,
    source_allows_publication_hostname,
)
from app.ingestion.services.article_identity_service import (
    ARTICLE_IDENTITY_CONFLICT_MESSAGE,
    ArticleIdentityConflictError,
    ArticleIdentityService,
)
from app.models import IntelligenceItem, IntelligenceSource, SourceRecord
from app.models.common import utc_now
from app.processing.uae_classification_service import UaeClassificationService


MAX_PUBLICATION_TITLE_LENGTH = 500
MAX_PUBLICATION_SUMMARY_LENGTH = 10_000
MAX_PUBLICATION_EXTERNAL_ID_LENGTH = 300
MAX_PUBLICATION_URL_LENGTH = 2048
MAX_SAFE_PAYLOAD_KEYS = 50
MAX_SAFE_PAYLOAD_SEQUENCE_ITEMS = 100
MAX_SAFE_PAYLOAD_BYTES = 8_192
PUBLICATION_DATA_CONFIDENCE = Decimal("0.900")
VALID_PUBLICATION_OUTCOMES = {"created", "updated", "unchanged", "skipped", "failed"}

PUBLICATION_ACCESS_METHODS = {
    AccessMethod.PUBLIC_FEED,
    AccessMethod.PUBLIC_PUBLICATION,
    AccessMethod.MANUAL_CATALOGUE,
}
PUBLICATION_CONTENT_FAMILIES = {
    ContentFamily.SECURITY_ADVISORY,
    ContentFamily.THREAT_RESEARCH,
    ContentFamily.EXPOSURE_RESEARCH,
    ContentFamily.PUBLIC_OSINT_ADVISORY,
}
TRACKING_PARAMS = {
    "gclid",
    "fbclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
    "campaign",
    "campaignid",
    "adgroupid",
    "creative",
}
CONTENT_FAMILY_ITEM_TYPES = {
    ContentFamily.SECURITY_ADVISORY: "security_advisory",
    ContentFamily.PUBLIC_OSINT_ADVISORY: "security_advisory",
    ContentFamily.THREAT_RESEARCH: "threat_report",
    ContentFamily.EXPOSURE_RESEARCH: "threat_report",
}
SENSITIVE_PAYLOAD_KEYS = {
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "password",
    "secret",
    "credentials",
    "requestheaders",
    "responseheaders",
    "sig",
    "signature",
    "clientsecret",
    "authtoken",
    "idtoken",
    "sessiontoken",
    "sastoken",
    "bearertoken",
    "xapikey",
    "secretkey",
    "token",
    "apitoken",
    "apitokenvalue",
    "oauthtoken",
    "oauth2token",
    "jwt",
    "jwttoken",
    "privatekey",
    "accesskey",
    "secretaccesskey",
    "awsaccesskeyid",
    "googleaccessid",
    "xamzcredential",
    "xamzsecuritytoken",
    "xgoogcredential",
    "xgoogsecuritytoken",
}
SENSITIVE_QUERY_KEYS = {
    "authorization",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "token",
    "password",
    "secret",
    "credentials",
    "signature",
    "xamzsignature",
    "xamzcredential",
    "xamzsecuritytoken",
    "xgoogsignature",
    "xgoogcredential",
    "xgoogsecuritytoken",
    "sig",
    "clientsecret",
    "authtoken",
    "idtoken",
    "sessiontoken",
    "sastoken",
    "bearertoken",
    "xapikey",
    "secretkey",
    "apitoken",
    "apitokenvalue",
    "oauthtoken",
    "oauth2token",
    "jwt",
    "jwttoken",
    "privatekey",
    "accesskey",
    "secretaccesskey",
    "awsaccesskeyid",
    "googleaccessid",
}


class PublicationPipelineError(RuntimeError):
    """A publication candidate could not be processed safely."""


class PublicationCandidateError(PublicationPipelineError, ValueError):
    """A publication candidate failed local validation."""


class PublicationSourceError(PublicationPipelineError):
    """A source registry rule rejected a publication candidate."""


class PublicationPersistenceError(PublicationPipelineError):
    """A database operation failed without exposing database details."""


@dataclass(frozen=True, slots=True)
class PublicationCandidate:
    """Already-fetched and already-parsed public publication data."""

    source_slug: str
    source_external_id: str
    canonical_title: str
    canonical_url: str
    summary: str | None = None
    source_published_at: datetime | None = None
    source_modified_at: datetime | None = None
    safe_source_payload: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "safe_source_payload",
            _snapshot_safe_payload(self.safe_source_payload),
        )


@dataclass(frozen=True, slots=True)
class NormalizedPublication:
    """Validated database-ready values for one public publication."""

    source: SourceDefinition
    source_external_id: str
    canonical_title: str
    normalized_title_hash: str
    summary: str | None
    canonical_url: str
    canonical_url_hash: str
    source_published_at: datetime | None
    source_modified_at: datetime | None
    content_hash: str
    raw_payload: dict[str, object]
    item_type: str


@dataclass(frozen=True)
class PublicationPersistenceResult:
    """Sanitized outcome for one normalized publication."""

    source_external_id: str
    outcome: str
    message: str | None = None
    source_record: SourceRecord | None = None
    intelligence_item_id: int | None = None

    def __post_init__(self) -> None:
        if self.outcome not in VALID_PUBLICATION_OUTCOMES:
            raise ValueError("Invalid publication persistence outcome.")


@dataclass(frozen=True)
class PublicationBatchResult:
    """Structured counters for a caller-controlled publication batch."""

    total: int
    created: int
    updated: int
    unchanged: int
    skipped: int
    failed: int
    results: tuple[PublicationPersistenceResult, ...]


class PublicationPipeline:
    """Validate and persist publication candidates without fetching or committing."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def ensure_source(self, source_slug: str) -> IntelligenceSource:
        """Create or validate a registry-approved publication source."""

        try:
            source_definition = require_publication_source(source_slug)
            source, failure = self._get_or_create_source(source_definition)
            if failure is not None:
                raise PublicationPersistenceError(failure)
            return source
        except SourceRegistryError as exc:
            raise PublicationSourceError("The publication source is not approved.") from exc
        except SQLAlchemyError as exc:
            raise PublicationPersistenceError(
                "Database error while preparing the approved publication source."
            ) from exc

    def persist(
        self,
        candidate: PublicationCandidate,
        *,
        observed_at: datetime | None = None,
    ) -> PublicationPersistenceResult:
        external_id = _safe_external_id_for_error(candidate)
        try:
            observation_time = _normalize_required_datetime(
                observed_at if observed_at is not None else utc_now(),
                "observation time",
            )
        except PublicationCandidateError:
            return _result(
                external_id,
                "failed",
                "The publication observation time must be timezone-aware.",
            )

        try:
            normalized = normalize_publication_candidate(candidate)
            source, source_failure = self._get_or_create_source(normalized.source)
            if source_failure is not None:
                return _result(normalized.source_external_id, "failed", source_failure)
            return self._persist_normalized(source, normalized, observation_time)
        except (PublicationCandidateError, PublicationSourceError) as exc:
            return _result(external_id, "failed", str(exc))
        except ArticleIdentityConflictError as exc:
            return _result(external_id, "failed", str(exc))
        except SQLAlchemyError as exc:
            raise PublicationPersistenceError(
                "Database error while persisting normalized publication data."
            ) from exc

    def process_candidates(
        self,
        candidates: Sequence[PublicationCandidate],
        *,
        observed_at: datetime | None = None,
    ) -> PublicationBatchResult:
        results = tuple(
            self.persist(candidate, observed_at=observed_at) for candidate in candidates
        )
        return PublicationBatchResult(
            total=len(results),
            created=sum(result.outcome == "created" for result in results),
            updated=sum(result.outcome == "updated" for result in results),
            unchanged=sum(result.outcome == "unchanged" for result in results),
            skipped=sum(result.outcome == "skipped" for result in results),
            failed=sum(result.outcome == "failed" for result in results),
            results=results,
        )

    def _persist_normalized(
        self,
        source: IntelligenceSource,
        normalized: NormalizedPublication,
        observed_at: datetime,
    ) -> PublicationPersistenceResult:
        identity_service = ArticleIdentityService(self._session)
        by_external_id = self._find_by_external_id(source, normalized.source_external_id)
        by_url_hash = self._find_by_url_hash(source, normalized.canonical_url_hash)
        if (
            by_external_id is not None
            and by_url_hash is not None
            and by_external_id is not by_url_hash
        ):
            return _result(
                normalized.source_external_id,
                "failed",
                "The publication external ID and URL hash refer to different source records.",
                source_record=by_external_id,
                intelligence_item_id=getattr(by_external_id.intelligence_item, "id", None),
            )

        source_record = by_external_id or by_url_hash
        if source_record is None:
            identity_resolution = identity_service.resolve_new_article(
                canonical_url_hash=normalized.canonical_url_hash,
                normalized_title_hash=normalized.normalized_title_hash,
                expected_item_type=normalized.item_type,
            )
            if identity_resolution.failed:
                return _result(
                    normalized.source_external_id,
                    "failed",
                    identity_resolution.failure_message,
                )
            source_record = self._create_records(
                source,
                normalized,
                observed_at,
                existing_item=identity_resolution.item,
                identity_service=identity_service,
            )
            self._session.flush()
            message = (
                _linked_existing_item_message(normalized.item_type)
                if identity_resolution.item is not None
                else None
            )
            return _result(
                normalized.source_external_id,
                "created",
                message,
                source_record=source_record,
                intelligence_item_id=getattr(source_record.intelligence_item, "id", None),
            )

        item = source_record.intelligence_item
        identity_failure = identity_service.validate_source_record_identity(
            item,
            canonical_url_hash=normalized.canonical_url_hash,
            normalized_title_hash=normalized.normalized_title_hash,
            expected_item_type=normalized.item_type,
        )
        if identity_failure is not None:
            return _result(
                normalized.source_external_id,
                "failed",
                identity_failure,
                source_record=source_record,
                intelligence_item_id=getattr(item, "id", None),
            )
        if item is None:
            return _result(
                normalized.source_external_id,
                "failed",
                ARTICLE_IDENTITY_CONFLICT_MESSAGE,
                source_record=source_record,
            )

        try:
            identity_plan = identity_service.prepare_identifier_update(
                item,
                canonical_url_hash=normalized.canonical_url_hash,
                normalized_title_hash=normalized.normalized_title_hash,
                expected_item_type=normalized.item_type,
            )
        except ArticleIdentityConflictError as exc:
            return _result(
                normalized.source_external_id,
                "failed",
                str(exc),
                source_record=source_record,
                intelligence_item_id=getattr(item, "id", None),
            )

        identity_service.apply_identifier_update(identity_plan)
        source_record.last_seen_at = observed_at
        source_record.payload_collected_at = observed_at
        source_record.last_processed_at = observed_at
        source_record.upstream_status = "present"
        source_record.processing_status = "processed"
        source_record.safe_error_summary = None
        item.last_seen_at = observed_at

        if source_record.content_hash == normalized.content_hash:
            self._session.flush()
            return _result(
                normalized.source_external_id,
                "unchanged",
                source_record=source_record,
                intelligence_item_id=getattr(item, "id", None),
            )

        self._apply_update(item, source_record, normalized)
        self._session.flush()
        return _result(
            normalized.source_external_id,
            "updated",
            source_record=source_record,
            intelligence_item_id=getattr(item, "id", None),
        )

    def _get_or_create_source(
        self,
        source_definition: SourceDefinition,
    ) -> tuple[IntelligenceSource, str | None]:
        source = self._session.execute(
            select(IntelligenceSource).where(IntelligenceSource.slug == source_definition.slug)
        ).scalar_one_or_none()
        expected_base_url = source_definition.base_url
        if source is None:
            source = IntelligenceSource(
                slug=source_definition.slug,
                name=source_definition.display_name,
                source_type=source_definition.source_type,
                base_url=expected_base_url,
                is_enabled=True,
                rate_limit_notes=source_definition.rate_limit_notes,
                checkpoint_value=None,
            )
            self._session.add(source)
            self._session.flush()
            return source, None

        expected = (
            source.name == source_definition.display_name
            and source.source_type == source_definition.source_type
            and source.base_url == expected_base_url
        )
        if not expected:
            return (
                source,
                "The existing publication source configuration conflicts with the approved source.",
            )
        return source, None

    def _find_by_external_id(
        self,
        source: IntelligenceSource,
        source_external_id: str,
    ) -> SourceRecord | None:
        return self._session.execute(
            select(SourceRecord)
            .where(SourceRecord.source_id == source.id)
            .where(SourceRecord.source_external_id == source_external_id)
        ).scalar_one_or_none()

    def _find_by_url_hash(
        self,
        source: IntelligenceSource,
        canonical_url_hash: str,
    ) -> SourceRecord | None:
        return self._session.execute(
            select(SourceRecord)
            .where(SourceRecord.source_id == source.id)
            .where(SourceRecord.canonical_url_hash == canonical_url_hash)
        ).scalar_one_or_none()

    def _create_records(
        self,
        source: IntelligenceSource,
        normalized: NormalizedPublication,
        observed_at: datetime,
        *,
        existing_item: IntelligenceItem | None,
        identity_service: ArticleIdentityService,
    ) -> SourceRecord:
        item = existing_item
        if item is None:
            item = IntelligenceItem(
                item_type=normalized.item_type,
                canonical_title=normalized.canonical_title,
                summary=normalized.summary,
                canonical_url=normalized.canonical_url,
                source_published_at=normalized.source_published_at,
                source_modified_at=normalized.source_modified_at,
                collected_at=observed_at,
                last_seen_at=observed_at,
                status="active",
                data_confidence=PUBLICATION_DATA_CONFIDENCE,
                geographic_scope="global",
                uae_relevance_status="unknown",
                uae_relevance_confidence=None,
                uae_relevance_reason=None,
                uae_relevance_method="unassigned",
                analyst_review_status="pending",
            )
            UaeClassificationService(self._session).classify_and_apply_if_allowed(item)
            self._session.add(item)
            identity_service.add_fingerprint_identifiers(
                item,
                canonical_url_hash=normalized.canonical_url_hash,
                normalized_title_hash=normalized.normalized_title_hash,
            )
        has_primary_reference = any(
            record.is_primary_reference for record in item.source_records
        )
        source_record = SourceRecord(
            source=source,
            intelligence_item=item,
            source_external_id=normalized.source_external_id,
            source_url=normalized.canonical_url,
            canonical_url_hash=normalized.canonical_url_hash,
            content_hash=normalized.content_hash,
            is_primary_reference=not has_primary_reference,
            raw_payload=normalized.raw_payload,
            payload_collected_at=observed_at,
            first_seen_at=observed_at,
            last_seen_at=observed_at,
            source_published_at=normalized.source_published_at,
            source_modified_at=normalized.source_modified_at,
            processing_status="processed",
            last_processed_at=observed_at,
            safe_error_summary=None,
            upstream_status="present",
        )
        self._session.add(source_record)
        return source_record

    def _apply_update(
        self,
        item: IntelligenceItem,
        source_record: SourceRecord,
        normalized: NormalizedPublication,
    ) -> None:
        item.canonical_title = normalized.canonical_title
        item.summary = normalized.summary
        item.canonical_url = normalized.canonical_url
        item.source_published_at = normalized.source_published_at
        item.source_modified_at = normalized.source_modified_at
        UaeClassificationService(self._session).classify_and_apply_if_allowed(item)

        source_record.source_external_id = normalized.source_external_id
        source_record.source_url = normalized.canonical_url
        source_record.canonical_url_hash = normalized.canonical_url_hash
        source_record.content_hash = normalized.content_hash
        source_record.raw_payload = normalized.raw_payload
        source_record.source_published_at = normalized.source_published_at
        source_record.source_modified_at = normalized.source_modified_at


def require_publication_source(source_slug: str) -> SourceDefinition:
    """Return a source definition only when it is approved for publications."""

    try:
        source = get_source_definition(source_slug)
    except SourceRegistryError as exc:
        raise PublicationSourceError("The publication source is not registered.") from exc
    if source.implementation_status is not ImplementationStatus.IMPLEMENTED:
        raise PublicationSourceError("The publication source is not implemented.")
    if source.enabled is not True:
        raise PublicationSourceError("The publication source is not enabled.")
    if source.access_method not in PUBLICATION_ACCESS_METHODS:
        raise PublicationSourceError("The source access method is not publication-compatible.")
    if source.content_family not in PUBLICATION_CONTENT_FAMILIES:
        raise PublicationSourceError("The source content family is not publication-compatible.")
    return source


def publication_item_type_for_content_family(content_family: ContentFamily) -> str:
    """Return the article item type owned by one publication content family."""

    try:
        return CONTENT_FAMILY_ITEM_TYPES[content_family]
    except KeyError as exc:
        raise PublicationSourceError(
            "The source content family is not publication-compatible."
        ) from exc


def normalize_publication_candidate(candidate: PublicationCandidate) -> NormalizedPublication:
    """Validate one already-parsed publication candidate."""

    source = require_publication_source(candidate.source_slug)
    item_type = publication_item_type_for_content_family(source.content_family)
    external_id = _required_text(
        candidate.source_external_id,
        "source_external_id",
        MAX_PUBLICATION_EXTERNAL_ID_LENGTH,
    )
    title = _required_text(
        candidate.canonical_title,
        "canonical_title",
        MAX_PUBLICATION_TITLE_LENGTH,
    )
    normalized_title_hash = normalized_publication_title_sha256(title)
    summary = _optional_text(candidate.summary, MAX_PUBLICATION_SUMMARY_LENGTH)
    canonical_url = canonicalize_publication_url(source.slug, candidate.canonical_url)
    canonical_url_hash = sha256(
        _safe_utf8_bytes(canonical_url, "The publication URL is invalid.")
    ).hexdigest()
    published_at = _normalize_optional_datetime(
        candidate.source_published_at,
        "source_published_at",
    )
    modified_at = _normalize_optional_datetime(
        candidate.source_modified_at,
        "source_modified_at",
    )
    raw_payload = _safe_payload(candidate.safe_source_payload)
    content_hash = publication_content_hash(
        source_external_id=external_id,
        canonical_title=title,
        summary=summary,
        canonical_url=canonical_url,
        source_published_at=published_at,
        source_modified_at=modified_at,
        raw_payload=raw_payload,
    )
    return NormalizedPublication(
        source=source,
        source_external_id=external_id,
        canonical_title=title,
        normalized_title_hash=normalized_title_hash,
        summary=summary,
        canonical_url=canonical_url,
        canonical_url_hash=canonical_url_hash,
        source_published_at=published_at,
        source_modified_at=modified_at,
        content_hash=content_hash,
        raw_payload=raw_payload,
        item_type=item_type,
    )


def canonicalize_publication_url(source_slug: str, value: object) -> str:
    """Canonicalize a publication URL using the exact source registry host allow-list."""

    require_publication_source(source_slug)
    if not isinstance(value, str):
        raise PublicationCandidateError("The publication URL is required.")
    raw_url = value.strip(" ")
    if not raw_url:
        raise PublicationCandidateError("The publication URL is required.")
    _validate_safe_text(raw_url, "The publication URL is invalid.")
    if len(raw_url) > MAX_PUBLICATION_URL_LENGTH:
        raise PublicationCandidateError("The publication URL exceeds the length limit.")
    try:
        parsed = urlparse(raw_url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        username = parsed.username
        password = parsed.password
        port = parsed.port
        host = (parsed.hostname or "").lower()
    except ValueError as exc:
        raise PublicationCandidateError("The publication URL is invalid.") from exc
    if scheme != "https":
        raise PublicationCandidateError("The publication URL must use HTTPS.")
    if "@" in netloc or username or password:
        raise PublicationCandidateError("The publication URL must not contain credentials.")
    if port not in (None, 443):
        raise PublicationCandidateError("The publication URL uses an unexpected port.")
    if not source_allows_publication_hostname(source_slug, host):
        raise PublicationCandidateError("The publication URL host is not approved.")
    if host.endswith("."):
        host = host[:-1]

    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_sensitive_query_key(key):
            raise PublicationCandidateError(
                "The publication URL contains unsupported query parameters."
            )
        if not _is_tracking_param(key):
            query.append((key, value))
    query.sort()
    canonical = urlunparse(
        (
            "https",
            host,
            parsed.path or "/",
            "",
            urlencode(query, doseq=True),
            "",
        )
    )
    if len(canonical) > MAX_PUBLICATION_URL_LENGTH:
        raise PublicationCandidateError("The publication URL exceeds the length limit.")
    return canonical


def normalized_publication_title_sha256(value: object) -> str:
    """Return a deterministic SHA-256 fingerprint for a publication title."""

    if not isinstance(value, str):
        raise PublicationCandidateError("The publication title must be a string.")
    _validate_safe_text(value, "The publication title is invalid.")
    try:
        normalized = unicodedata.normalize("NFKC", value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PublicationCandidateError("The publication title is invalid.") from exc
    _validate_safe_text(normalized, "The publication title is invalid.")
    normalized = re.sub(r"\s+", " ", normalized).strip().casefold()
    if not normalized:
        raise PublicationCandidateError("The publication title is required.")
    return sha256(
        _safe_utf8_bytes(normalized, "The publication title is invalid.")
    ).hexdigest()


def publication_content_hash(
    *,
    source_external_id: str,
    canonical_title: str,
    summary: str | None,
    canonical_url: str,
    source_published_at: datetime | None,
    source_modified_at: datetime | None,
    raw_payload: Mapping[str, object],
) -> str:
    """Hash source-owned publication fields using stable canonical JSON."""

    hash_payload = {
        "source_external_id": source_external_id,
        "canonical_title": canonical_title,
        "summary": summary,
        "canonical_url": canonical_url,
        "source_published_at": (
            source_published_at.isoformat() if source_published_at else None
        ),
        "source_modified_at": (
            source_modified_at.isoformat() if source_modified_at else None
        ),
        "raw_payload": dict(raw_payload),
    }
    return sha256(_canonical_bytes(hash_payload)).hexdigest()


def _required_text(value: object, field_name: str, maximum_length: int) -> str:
    if value is None:
        raise PublicationCandidateError(f"The publication {field_name} is required.")
    if not isinstance(value, str):
        raise PublicationCandidateError("The publication text field must be a string.")
    _validate_safe_text(value, "The publication text contains unsupported characters.")
    text = _normalize_text(value)
    if not text:
        raise PublicationCandidateError(f"The publication {field_name} is required.")
    if len(text) > maximum_length:
        raise PublicationCandidateError(
            f"The publication {field_name} exceeds the length limit."
        )
    return text


def _optional_text(value: object, maximum_length: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PublicationCandidateError("The publication text field must be a string.")
    _validate_safe_text(value, "The publication text contains unsupported characters.")
    text = _normalize_text(value)
    if not text:
        return None
    return text[:maximum_length]


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _normalize_optional_datetime(value: object, field_name: str) -> datetime | None:
    if value is None:
        return None
    return _normalize_required_datetime(value, field_name)


def _normalize_required_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise PublicationCandidateError(
            f"The publication {field_name} must be timezone-aware."
        )
    try:
        if value.tzinfo is None or value.utcoffset() is None:
            raise PublicationCandidateError(
                f"The publication {field_name} must be timezone-aware."
            )
        return value.astimezone(UTC)
    except PublicationCandidateError:
        raise
    except Exception as exc:
        raise PublicationCandidateError(
            f"The publication {field_name} must be timezone-aware."
        ) from exc


def _snapshot_safe_payload(
    value: Mapping[str, object] | None,
) -> MappingProxyType[str, object]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise PublicationCandidateError("The publication source payload must be an object.")
    if len(value) > MAX_SAFE_PAYLOAD_KEYS:
        raise PublicationCandidateError("The publication source payload is too large.")
    payload: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise PublicationCandidateError("The publication source payload has an invalid key.")
        _validate_safe_text(
            key,
            "The publication source payload contains unsafe text.",
        )
        if not key or len(key) > 100 or _is_sensitive_key(key):
            raise PublicationCandidateError("The publication source payload has an invalid key.")
        if isinstance(item, str):
            _validate_safe_text(
                item,
                "The publication source payload contains unsafe text.",
            )
            payload[key] = item[:MAX_PUBLICATION_SUMMARY_LENGTH]
            continue
        if isinstance(item, Sequence) and not isinstance(item, (bytes, bytearray, str)):
            if len(item) > MAX_SAFE_PAYLOAD_SEQUENCE_ITEMS:
                raise PublicationCandidateError("The publication source payload is too large.")
            values: list[str] = []
            for member in item:
                if not isinstance(member, str):
                    raise PublicationCandidateError(
                        "The publication source payload sequence is invalid."
                    )
                _validate_safe_text(
                    member,
                    "The publication source payload contains unsafe text.",
                )
                values.append(member[:MAX_PUBLICATION_SUMMARY_LENGTH])
            payload[key] = tuple(values)
            continue
        if isinstance(item, bool) or item is None:
            payload[key] = item
            continue
        if isinstance(item, int):
            payload[key] = item
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise PublicationCandidateError(
                    "The publication source payload contains unsafe data."
                )
            payload[key] = item
            continue
        raise PublicationCandidateError("The publication source payload contains unsafe data.")
    _check_safe_payload_size(payload)
    return MappingProxyType(payload)


def _safe_payload(value: Mapping[str, object] | None) -> dict[str, object]:
    snapshot = _snapshot_safe_payload(value)
    payload: dict[str, object] = {}
    for key, item in snapshot.items():
        payload[key] = list(item) if isinstance(item, tuple) else item
    _check_safe_payload_size(payload)
    return json.loads(_canonical_bytes(payload))


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    try:
        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PublicationCandidateError(
            "The publication candidate is not valid canonical JSON."
        ) from exc
    return _safe_utf8_bytes(
        serialized,
        "The publication candidate is not valid canonical JSON.",
    )


def _is_tracking_param(key: str) -> bool:
    lowered = key.lower()
    return lowered.startswith("utm_") or lowered in TRACKING_PARAMS


def _is_sensitive_key(key: str) -> bool:
    return _normalize_security_key(key) in SENSITIVE_PAYLOAD_KEYS


def _is_sensitive_query_key(key: str) -> bool:
    return _normalize_security_key(key) in SENSITIVE_QUERY_KEYS


def _normalize_security_key(key: str) -> str:
    normalized = unicodedata.normalize("NFKC", key).casefold()
    return "".join(character for character in normalized if character.isalnum())


def _validate_safe_text(value: str, error_message: str) -> None:
    if any(
        ord(character) < 0x20
        or ord(character) == 0x7F
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        raise PublicationCandidateError(error_message)


def _safe_utf8_bytes(value: object, error_message: str) -> bytes:
    if not isinstance(value, str):
        raise PublicationCandidateError(error_message)
    _validate_safe_text(value, error_message)
    try:
        return value.encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PublicationCandidateError(error_message) from exc


def _check_safe_payload_size(payload: Mapping[str, object]) -> None:
    if len(_canonical_bytes(payload)) > MAX_SAFE_PAYLOAD_BYTES:
        raise PublicationCandidateError("The publication source payload is too large.")


def _safe_external_id_for_error(candidate: PublicationCandidate) -> str:
    return safe_publication_external_id_for_error(candidate.source_external_id)


def safe_publication_external_id_for_error(value: object) -> str:
    """Return a bounded printable external ID suitable for sanitized results."""

    if isinstance(value, str):
        try:
            _validate_safe_text(value, "")
        except PublicationCandidateError:
            return "unknown"
        if value.strip() and value.isprintable():
            return value[:MAX_PUBLICATION_EXTERNAL_ID_LENGTH]
    return "unknown"


def _linked_existing_item_message(item_type: str) -> str:
    if item_type == "security_advisory":
        return "A new source record was linked to an existing advisory."
    return "A new source record was linked to an existing publication."


def _result(
    source_external_id: str,
    outcome: str,
    message: str | None = None,
    *,
    source_record: SourceRecord | None = None,
    intelligence_item_id: int | None = None,
) -> PublicationPersistenceResult:
    return PublicationPersistenceResult(
        source_external_id=source_external_id,
        outcome=outcome,
        message=message,
        source_record=source_record,
        intelligence_item_id=intelligence_item_id,
    )
