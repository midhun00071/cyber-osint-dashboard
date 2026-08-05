"""Caller-transaction-owned persistence for validated offline STIX documents."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
import re
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.stix_taxii.bounded_json import thaw_json
from app.ingestion.stix_taxii.object_mapping import (
    StagedStixObject,
    StixMappedObservable,
    canonical_safe_content_hash,
)
from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    validate_stix_source_policy,
)
from app.ingestion.stix_taxii.stix_validation import (
    ExistingStixReferenceUse,
    StixValidationError,
    ValidatedStixDocument,
    validate_canonical_safe_payload,
    validate_existing_safe_payload,
    validate_persistable_stix_document,
)
from app.ingestion.stix_taxii.threat_knowledge import (
    ThreatKnowledgeCounts,
    ThreatKnowledgeError,
    ThreatKnowledgeWriter,
    map_threat_entity,
)
from app.models import (
    Indicator,
    IndicatorProvenance,
    IntelligenceSource,
    SourceRecord,
)


class StixImportServiceError(RuntimeError):
    """Sanitized failure for an atomic offline STIX import."""


class StixImportPersistenceError(StixImportServiceError):
    """Sanitized transient failure from the database persistence boundary."""


@dataclass(frozen=True, slots=True)
class _StagedRecord:
    staged: StagedStixObject
    record: SourceRecord
    action: str
    previous_payload: Mapping[str, object] | None


@dataclass(frozen=True, slots=True)
class StixRecordOutcome:
    source_record_id: int
    stix_id: str
    action: str

    def __post_init__(self) -> None:
        if type(self.source_record_id) is not int or self.source_record_id < 1:
            raise ValueError("STIX record outcome identity is invalid.")
        if (
            not isinstance(self.stix_id, str)
            or len(self.stix_id) > 300
            or re.fullmatch(
                r"[a-z][a-z0-9-]{0,249}--[0-9a-f]{8}-[0-9a-f]{4}-"
                r"[45][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                self.stix_id,
            )
            is None
            or self.action not in {"created", "updated", "unchanged", "skipped"}
        ):
            raise ValueError("STIX record outcome is invalid.")


@dataclass(frozen=True, slots=True)
class StixImportResult:
    """Immutable safe counters for one validated document import."""

    status: str
    objects_received: int
    objects_validated: int
    objects_created: int = 0
    objects_updated: int = 0
    objects_unchanged: int = 0
    objects_stale: int = 0
    objects_rejected: int = 0
    relationships_validated: int = 0
    relationships_excluded: int = 0
    indicators_created: int = 0
    indicators_existing: int = 0
    provenances_created: int = 0
    provenances_updated: int = 0
    provenances_unchanged: int = 0
    false_positive_suppressed: int = 0
    revoked_indicators_suppressed: int = 0
    markings_validated: int = 0
    entities_created: int = 0
    entities_updated: int = 0
    entities_unchanged: int = 0
    aliases_created: int = 0
    aliases_updated: int = 0
    aliases_deleted: int = 0
    aliases_unchanged: int = 0
    threat_relationships_created: int = 0
    threat_relationships_updated: int = 0
    threat_relationships_unchanged: int = 0
    threat_objects_unmapped: int = 0
    threat_relationships_unmapped: int = 0
    record_outcomes: tuple[StixRecordOutcome, ...] = ()
    bounded: bool = True


@dataclass(slots=True)
class _Counts:
    objects_created: int = 0
    objects_updated: int = 0
    objects_unchanged: int = 0
    objects_stale: int = 0
    indicators_created: int = 0
    indicators_existing: int = 0
    provenances_created: int = 0
    provenances_updated: int = 0
    provenances_unchanged: int = 0
    false_positive_suppressed: int = 0
    revoked_indicators_suppressed: int = 0


class StixBundleImportService:
    """Persist one validated STIX document without commit or rollback ownership."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def import_document(
        self,
        source_id: int,
        policy: ApprovedStixSourcePolicy,
        document: ValidatedStixDocument,
        *,
        observed_at: datetime,
    ) -> StixImportResult:
        if type(source_id) is not int or source_id <= 0:
            raise ValueError("source_id must be a positive integer.")
        if not isinstance(document, ValidatedStixDocument):
            raise ValueError("A validated STIX document is required.")
        normalized_policy = validate_stix_source_policy(policy)
        observation_time = _aware_utc(observed_at)
        try:
            source = self._session.get(IntelligenceSource, source_id)
            self._validate_source(source, normalized_policy)
            assert source is not None
            canonical_document = self._validate_document(
                document,
                normalized_policy,
            )
            self._validate_external_references(
                source_id,
                canonical_document,
                normalized_policy,
            )

            counts = _Counts()
            threat_counts = ThreatKnowledgeCounts()
            threat_writer = ThreatKnowledgeWriter(
                self._session, source_id, source.slug, threat_counts
            )
            staged_records: dict[str, _StagedRecord] = {}
            outcomes: list[StixRecordOutcome] = []
            for staged in canonical_document.objects:
                record = self._find_source_record(source_id, staged.stix_id)
                staged_record = self._stage_object(
                    source,
                    record,
                    staged,
                    normalized_policy,
                    observation_time,
                )
                if staged_record.action == "stale":
                    counts.objects_stale += 1
                    outcomes.append(
                        StixRecordOutcome(
                            staged_record.record.id,
                            staged.stix_id,
                            "skipped",
                        )
                    )
                    continue
                if staged_record.action == "created":
                    counts.objects_created += 1
                elif staged_record.action == "updated":
                    counts.objects_updated += 1
                else:
                    counts.objects_unchanged += 1
                staged_records[staged.stix_id] = staged_record
                outcomes.append(
                    StixRecordOutcome(
                        staged_record.record.id,
                        staged.stix_id,
                        staged_record.action,
                    )
                )
                if (
                    staged.stix_type == "indicator"
                    and staged.safe_payload.get("revoked") is True
                ):
                    counts.revoked_indicators_suppressed += 1
                    continue
                for observable in staged.observables:
                    self._upsert_indicator(
                        source_id,
                        staged_record.record,
                        observable,
                        observation_time,
                        counts,
                    )

            for staged_record in staged_records.values():
                if staged_record.staged.stix_type in {
                    "threat-actor",
                    "intrusion-set",
                    "campaign",
                    "malware",
                    "attack-pattern",
                }:
                    threat_writer.upsert_entity(
                        staged_record.record,
                        staged_record.staged.safe_payload,
                        staged_record.action,
                        previous_payload=staged_record.previous_payload,
                    )

            for staged_record in staged_records.values():
                staged = staged_record.staged
                if staged.stix_type != "relationship":
                    continue
                source_payload, source_record, source_previous_payload = self._relationship_endpoint(
                    source_id, staged.safe_payload["source_ref"], staged_records, normalized_policy
                )
                target_payload, target_record, target_previous_payload = self._relationship_endpoint(
                    source_id, staged.safe_payload["target_ref"], staged_records, normalized_policy
                )
                source_value = map_threat_entity(source_payload)
                target_value = map_threat_entity(target_payload)
                if source_value is None or target_value is None:
                    if threat_writer.find_relationship(staged.stix_id) is not None:
                        raise ThreatKnowledgeError(
                            "Threat relationship mapping identity cannot be removed."
                        )
                    threat_counts.threat_relationships_unmapped += 1
                    continue
                source_entity = threat_writer.find_entity(source_value.stix_id)
                if source_entity is None:
                    source_entity = threat_writer.upsert_entity(
                        source_record,
                        source_payload,
                        "unchanged",
                        previous_payload=source_previous_payload,
                    )
                target_entity = threat_writer.find_entity(target_value.stix_id)
                if target_entity is None:
                    target_entity = threat_writer.upsert_entity(
                        target_record,
                        target_payload,
                        "unchanged",
                        previous_payload=target_previous_payload,
                    )
                if source_entity is None or target_entity is None:
                    raise ThreatKnowledgeError("Threat relationship endpoint materialization failed.")
                threat_writer.upsert_relationship(
                    staged_record.record,
                    staged.safe_payload,
                    source_entity,
                    target_entity,
                    staged_record.action,
                    previous_payload=staged_record.previous_payload,
                )

            return StixImportResult(
                status="processed",
                objects_received=canonical_document.objects_received,
                objects_validated=canonical_document.objects_validated,
                objects_created=counts.objects_created,
                objects_updated=counts.objects_updated,
                objects_unchanged=counts.objects_unchanged,
                objects_stale=counts.objects_stale,
                relationships_validated=canonical_document.relationships_validated,
                relationships_excluded=canonical_document.relationships_excluded,
                indicators_created=counts.indicators_created,
                indicators_existing=counts.indicators_existing,
                provenances_created=counts.provenances_created,
                provenances_updated=counts.provenances_updated,
                provenances_unchanged=counts.provenances_unchanged,
                false_positive_suppressed=counts.false_positive_suppressed,
                revoked_indicators_suppressed=(
                    counts.revoked_indicators_suppressed
                ),
                markings_validated=canonical_document.markings_validated,
                entities_created=threat_counts.entities_created,
                entities_updated=threat_counts.entities_updated,
                entities_unchanged=threat_counts.entities_unchanged,
                aliases_created=threat_counts.aliases_created,
                aliases_updated=threat_counts.aliases_updated,
                aliases_deleted=threat_counts.aliases_deleted,
                aliases_unchanged=threat_counts.aliases_unchanged,
                threat_relationships_created=threat_counts.relationships_created,
                threat_relationships_updated=threat_counts.relationships_updated,
                threat_relationships_unchanged=threat_counts.relationships_unchanged,
                threat_objects_unmapped=threat_counts.threat_objects_unmapped,
                threat_relationships_unmapped=threat_counts.threat_relationships_unmapped,
                record_outcomes=tuple(outcomes),
            )
        except StixImportServiceError:
            raise
        except ThreatKnowledgeError as exc:
            raise StixImportServiceError("Validated STIX threat knowledge conflicts.") from exc
        except SQLAlchemyError as exc:
            raise StixImportPersistenceError(
                "Database error while importing validated STIX metadata."
            ) from exc

    @staticmethod
    def _validate_document(
        document: ValidatedStixDocument,
        policy: ApprovedStixSourcePolicy,
    ) -> ValidatedStixDocument:
        try:
            return validate_persistable_stix_document(document, policy)
        except (StixValidationError, TypeError, ValueError) as exc:
            raise StixImportServiceError(
                "Validated STIX document is invalid for persistence."
            ) from exc

    @staticmethod
    def _validate_source(
        source: IntelligenceSource | None,
        policy: ApprovedStixSourcePolicy,
    ) -> None:
        if source is None:
            raise StixImportServiceError("Approved STIX source does not exist.")
        if (
            source.slug != policy.source_slug
            or source.is_enabled is not policy.expected_source_enabled
            or source.source_type != "json"
            or not isinstance(source.base_url, str)
            or source.base_url.rstrip("/") != policy.policy_base_url.rstrip("/")
        ):
            raise StixImportServiceError("Approved STIX source identity does not match.")

    def _validate_external_references(
        self,
        source_id: int,
        document: ValidatedStixDocument,
        policy: ApprovedStixSourcePolicy,
    ) -> None:
        document_ids = {item.stix_id for item in document.objects}
        for item in document.objects:
            references: list[tuple[str, ExistingStixReferenceUse]] = [
                (reference, ExistingStixReferenceUse.OBJECT_MARKING)
                for reference in item.safe_payload.get("object_marking_refs", ())
            ]
            if item.stix_type == "relationship":
                references.extend(
                    (
                        (
                            item.safe_payload["source_ref"],
                            ExistingStixReferenceUse.RELATIONSHIP_TARGET,
                        ),
                        (
                            item.safe_payload["target_ref"],
                            ExistingStixReferenceUse.RELATIONSHIP_TARGET,
                        ),
                    )
                )
            for reference, expected_use in references:
                if reference in document_ids:
                    continue
                record = self._find_source_record(source_id, reference)
                self._validate_reference_record(
                    record,
                    source_id,
                    reference,
                    policy,
                    expected_use,
                )

    @staticmethod
    def _validate_reference_record(
        record: SourceRecord | None,
        source_id: int,
        expected_stix_id: str,
        policy: ApprovedStixSourcePolicy,
        expected_use: ExistingStixReferenceUse,
    ) -> None:
        try:
            expected_source_url = policy.object_url(expected_stix_id)
            expected_url_hash = _canonical_url_hash(policy, expected_source_url)
            if (
                record is None
                or record.source_id != source_id
                or record.source_external_id != expected_stix_id
                or record.intelligence_item_id is not None
                or record.is_primary_reference is not False
                or record.source_url != expected_source_url
                or record.canonical_url_hash != expected_url_hash
                or record.processing_status != "processed"
                or record.upstream_status != "present"
                or record.safe_error_summary is not None
                or not isinstance(record.raw_payload, dict)
                or not isinstance(record.content_hash, str)
                or _IDENTITY_HASH_RE.fullmatch(record.content_hash) is None
            ):
                raise StixValidationError("Existing STIX reference record is invalid.")
            validate_existing_safe_payload(
                expected_stix_id,
                record.raw_payload,
                policy,
                expected_use,
            )
            if canonical_safe_content_hash(record.raw_payload) != record.content_hash:
                raise StixValidationError("Existing STIX reference record is invalid.")
            _validate_record_audit_metadata(record, record.raw_payload)
        except (StixValidationError, TypeError, ValueError) as exc:
            raise StixImportServiceError(
                "Existing STIX reference record is invalid."
            ) from exc

    @staticmethod
    def _validate_current_record(
        record: SourceRecord,
        source_id: int,
        staged: StagedStixObject,
        policy: ApprovedStixSourcePolicy,
        source_url: str,
        canonical_url_hash: str,
    ) -> Mapping[str, object]:
        try:
            if (
                record.source_id != source_id
                or record.source_external_id != staged.stix_id
                or record.intelligence_item_id is not None
                or record.is_primary_reference is not False
                or record.source_url != source_url
                or record.canonical_url_hash != canonical_url_hash
                or record.processing_status != "processed"
                or record.upstream_status != "present"
                or record.safe_error_summary is not None
                or not isinstance(record.raw_payload, dict)
                or not isinstance(record.content_hash, str)
                or _IDENTITY_HASH_RE.fullmatch(record.content_hash) is None
            ):
                raise StixValidationError("Existing STIX source record is invalid.")
            safe_payload = validate_canonical_safe_payload(
                staged.stix_id,
                record.raw_payload,
                policy,
                expected_stix_type=staged.stix_type,
            )
            if canonical_safe_content_hash(record.raw_payload) != record.content_hash:
                raise StixValidationError("Existing STIX source record is invalid.")
            _validate_record_audit_metadata(record, safe_payload)
            return safe_payload
        except (StixValidationError, TypeError, ValueError) as exc:
            raise StixImportServiceError(
                "Existing STIX source record is invalid."
            ) from exc

    def _find_source_record(
        self,
        source_id: int,
        external_id: str,
    ) -> SourceRecord | None:
        statement = select(SourceRecord).where(
            SourceRecord.source_id == source_id,
            SourceRecord.source_external_id == external_id,
        )
        return self._session.execute(statement).scalar_one_or_none()

    def _relationship_endpoint(
        self,
        source_id: int,
        stix_id: object,
        staged_records: Mapping[str, _StagedRecord],
        policy: ApprovedStixSourcePolicy,
    ) -> tuple[
        Mapping[str, object],
        SourceRecord,
        Mapping[str, object] | None,
    ]:
        if not isinstance(stix_id, str):
            raise StixImportServiceError("STIX relationship endpoint is invalid.")
        staged_entry = staged_records.get(stix_id)
        if staged_entry is not None:
            return (
                staged_entry.staged.safe_payload,
                staged_entry.record,
                staged_entry.previous_payload,
            )
        record = self._find_source_record(source_id, stix_id)
        self._validate_reference_record(
            record, source_id, stix_id, policy, ExistingStixReferenceUse.RELATIONSHIP_TARGET
        )
        assert record is not None and isinstance(record.raw_payload, dict)
        try:
            payload = validate_canonical_safe_payload(
                stix_id,
                record.raw_payload,
                policy,
                expected_stix_type=stix_id.split("--", 1)[0],
            )
        except (StixValidationError, TypeError, ValueError) as exc:
            raise StixImportServiceError("Existing STIX relationship endpoint is invalid.") from exc
        return payload, record, payload

    def _stage_object(
        self,
        source: IntelligenceSource,
        record: SourceRecord | None,
        staged: StagedStixObject,
        policy: ApprovedStixSourcePolicy,
        observed_at: datetime,
    ) -> _StagedRecord:
        source_url = policy.object_url(staged.stix_id)
        canonical_url_hash = _canonical_url_hash(policy, source_url)
        payload = thaw_json(staged.safe_payload)
        assert isinstance(payload, dict)
        if record is None:
            record = SourceRecord(
                source_id=source.id,
                intelligence_item_id=None,
                source_external_id=staged.stix_id,
                source_url=source_url,
                canonical_url_hash=canonical_url_hash,
                content_hash=staged.content_hash,
                is_primary_reference=False,
                raw_payload=payload,
                payload_collected_at=observed_at,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                source_published_at=staged.created,
                source_modified_at=staged.modified,
                processing_status="processed",
                last_processed_at=observed_at,
                safe_error_summary=None,
                upstream_status="present",
            )
            self._session.add(record)
            self._session.flush()
            return _StagedRecord(staged, record, "created", None)

        existing_payload = self._validate_current_record(
            record,
            source.id,
            staged,
            policy,
            source_url,
            canonical_url_hash,
        )
        comparison = _compare_existing_version(record, staged, existing_payload)
        if comparison == "stale":
            return _StagedRecord(staged, record, "stale", existing_payload)
        record.last_seen_at = max(_aware_utc(record.last_seen_at), observed_at)
        record.last_processed_at = observed_at
        if comparison == "unchanged":
            return _StagedRecord(staged, record, "unchanged", existing_payload)
        record.source_url = source_url
        record.canonical_url_hash = canonical_url_hash
        record.content_hash = staged.content_hash
        record.raw_payload = payload
        record.payload_collected_at = observed_at
        record.source_published_at = staged.created
        record.source_modified_at = staged.modified
        record.processing_status = "processed"
        record.upstream_status = "present"
        record.safe_error_summary = None
        return _StagedRecord(staged, record, "updated", existing_payload)

    def _upsert_indicator(
        self,
        source_id: int,
        record: SourceRecord,
        observable: StixMappedObservable,
        fallback_observed_at: datetime,
        counts: _Counts,
    ) -> None:
        normalized = observable.normalized
        statement = select(Indicator).where(
            Indicator.identity_sha256 == normalized.identity_sha256
        )
        indicator = self._session.execute(statement).scalar_one_or_none()
        observed_at = observable.observed_at or fallback_observed_at
        if indicator is None:
            indicator = Indicator(
                observable_type=normalized.observable_type,
                normalized_value=normalized.normalized_value,
                hash_algorithm=normalized.hash_algorithm,
                identity_sha256=normalized.identity_sha256,
                status="active",
                confidence=observable.confidence,
                context_summary=None,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                revoked_at=None,
                expires_at=None,
            )
            self._session.add(indicator)
            self._session.flush()
            counts.indicators_created += 1
        else:
            counts.indicators_existing += 1
            if indicator.status == "false_positive":
                counts.false_positive_suppressed += 1
                return
            _update_indicator(indicator, observed_at, observable.confidence)

        statement = select(IndicatorProvenance).where(
            IndicatorProvenance.indicator_id == indicator.id,
            IndicatorProvenance.source_id == source_id,
            IndicatorProvenance.source_record_id == record.id,
        )
        provenance = self._session.execute(statement).scalar_one_or_none()
        if provenance is None:
            self._session.add(
                IndicatorProvenance(
                    indicator_id=indicator.id,
                    source_id=source_id,
                    source_record_id=record.id,
                    confidence=observable.confidence,
                    context_summary=observable.context_summary[:1000],
                    first_observed_at=observed_at,
                    last_observed_at=observed_at,
                )
            )
            counts.provenances_created += 1
        elif _update_provenance(provenance, observed_at, observable.confidence):
            counts.provenances_updated += 1
        else:
            counts.provenances_unchanged += 1


def _compare_existing_version(
    record: SourceRecord,
    staged: StagedStixObject,
    existing_payload: Mapping[str, object],
) -> str:
    if staged.modified is None:
        if existing_payload == staged.safe_payload:
            return "unchanged"
        raise StixImportServiceError("Non-versioned STIX object content conflicts.")
    existing_modified = record.source_modified_at
    if existing_modified is None:
        raise StixImportServiceError("Existing STIX version metadata is inconsistent.")
    existing_modified = _aware_utc(existing_modified)
    payload = existing_payload
    if (
        payload.get("type") != staged.stix_type
        or payload.get("id") != staged.stix_id
        or payload.get("spec_version") != "2.1"
    ):
        raise StixImportServiceError("Existing STIX version metadata is inconsistent.")
    stored_created = _stored_safe_timestamp(payload.get("created"))
    stored_modified = _stored_safe_timestamp(payload.get("modified"))
    if (
        stored_modified != existing_modified
    ):
        raise StixImportServiceError("Existing STIX version metadata is inconsistent.")
    if (
        stored_created != staged.created
        or payload.get("created_by_ref")
        != staged.safe_payload.get("created_by_ref")
    ):
        raise StixImportServiceError("STIX object version changed invariant metadata.")
    stored_revoked = payload.get("revoked", False)
    if type(stored_revoked) is not bool:
        raise StixImportServiceError("Existing STIX version metadata is inconsistent.")
    if staged.modified < existing_modified:
        return "stale"
    if staged.modified == existing_modified:
        if payload == staged.safe_payload:
            return "unchanged"
        raise StixImportServiceError("STIX object version content conflicts.")
    if stored_revoked:
        raise StixImportServiceError("A revoked STIX object cannot have a newer version.")
    if _mapped_identity_set(payload) != _mapped_identity_set(staged.safe_payload):
        raise StixImportServiceError("STIX object version changed mapped identity.")
    return "updated"


def _validate_record_audit_metadata(
    record: SourceRecord,
    safe_payload: Mapping[str, object],
) -> None:
    expected_created = _canonical_payload_timestamp(safe_payload.get("created"))
    expected_modified = _canonical_payload_timestamp(safe_payload.get("modified"))
    _require_matching_record_timestamp(record.source_published_at, expected_created)
    _require_matching_record_timestamp(record.source_modified_at, expected_modified)

    _required_record_timestamp(record.payload_collected_at)
    first_seen = _required_record_timestamp(record.first_seen_at)
    last_seen = _required_record_timestamp(record.last_seen_at)
    _required_record_timestamp(record.last_processed_at)
    if first_seen > last_seen:
        raise StixValidationError("Existing STIX record audit metadata is invalid.")


def _canonical_payload_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StixValidationError("Existing STIX record audit metadata is invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StixValidationError(
            "Existing STIX record audit metadata is invalid."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StixValidationError("Existing STIX record audit metadata is invalid.")
    normalized = parsed.astimezone(UTC)
    canonical = normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value != canonical:
        raise StixValidationError("Existing STIX record audit metadata is invalid.")
    return normalized


def _required_record_timestamp(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise StixValidationError("Existing STIX record audit metadata is invalid.")
    return value.astimezone(UTC)


def _require_matching_record_timestamp(
    value: object,
    expected: datetime | None,
) -> None:
    if expected is None:
        if value is not None:
            raise StixValidationError("Existing STIX record audit metadata is invalid.")
        return
    if _required_record_timestamp(value) != expected:
        raise StixValidationError("Existing STIX record audit metadata is invalid.")


def _canonical_url_hash(
    policy: ApprovedStixSourcePolicy,
    source_url: str,
) -> str:
    return sha256(
        f"{policy.source_slug}\0{source_url}".encode("utf-8")
    ).hexdigest()


_IDENTITY_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _mapped_identity_set(
    payload: Mapping[str, object],
) -> tuple[tuple[str, str | None, str], ...]:
    has_value = "mapped_observables" in payload
    value = payload.get("mapped_observables", ())
    if not isinstance(value, (tuple, list)):
        raise StixImportServiceError("Existing STIX mapped identity is inconsistent.")
    if payload.get("type") == "indicator" and (not has_value or not value):
        raise StixImportServiceError("Existing STIX mapped identity is inconsistent.")
    identities: list[tuple[str, str | None, str]] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "observable_type",
            "hash_algorithm",
            "identity_sha256",
        }:
            raise StixImportServiceError("Existing STIX mapped identity is inconsistent.")
        observable_type = item.get("observable_type")
        hash_algorithm = item.get("hash_algorithm")
        identity = item.get("identity_sha256")
        if (
            not isinstance(observable_type, str)
            or (hash_algorithm is not None and not isinstance(hash_algorithm, str))
            or not isinstance(identity, str)
            or _IDENTITY_HASH_RE.fullmatch(identity) is None
        ):
            raise StixImportServiceError("Existing STIX mapped identity is inconsistent.")
        identities.append((observable_type, hash_algorithm, identity))
    ordered = tuple(sorted(identities, key=lambda item: (item[0], item[1] or "", item[2])))
    if len(ordered) != len(set(ordered)):
        raise StixImportServiceError("Existing STIX mapped identity is inconsistent.")
    return ordered


def _stored_safe_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise StixImportServiceError("Existing STIX version metadata is inconsistent.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StixImportServiceError(
            "Existing STIX version metadata is inconsistent."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StixImportServiceError("Existing STIX version metadata is inconsistent.")
    normalized = parsed.astimezone(UTC)
    canonical = normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value != canonical:
        raise StixImportServiceError("Existing STIX version metadata is inconsistent.")
    return normalized


def _update_indicator(
    indicator: Indicator,
    observed_at: datetime,
    confidence: Decimal | None,
) -> None:
    if indicator.first_seen_at is None or observed_at < indicator.first_seen_at:
        indicator.first_seen_at = observed_at
    if indicator.last_seen_at is None or observed_at > indicator.last_seen_at:
        indicator.last_seen_at = observed_at
    if confidence is not None and (
        indicator.confidence is None or confidence > indicator.confidence
    ):
        indicator.confidence = confidence


def _update_provenance(
    provenance: IndicatorProvenance,
    observed_at: datetime,
    confidence: Decimal | None,
) -> bool:
    changed = False
    if provenance.first_observed_at is None or observed_at < provenance.first_observed_at:
        provenance.first_observed_at = observed_at
        changed = True
    if provenance.last_observed_at is None or observed_at > provenance.last_observed_at:
        provenance.last_observed_at = observed_at
        changed = True
    if confidence is not None and (
        provenance.confidence is None or confidence > provenance.confidence
    ):
        provenance.confidence = confidence
        changed = True
    return changed


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("STIX observation timestamp must be timezone-aware.")
    return value.astimezone(UTC)
