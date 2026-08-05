from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import builtins
from hashlib import sha256
import json
import socket
from copy import deepcopy

import httpx
import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.indicators.value_normalization import normalize_observable
from app.ingestion.stix_taxii.bounded_json import (
    StixDocumentFormat,
    parse_stix_json_bytes,
    thaw_json,
)
from app.ingestion.stix_taxii.import_service import (
    StixBundleImportService,
    StixImportPersistenceError,
    StixImportServiceError,
)
from app.ingestion.stix_taxii.object_mapping import canonical_safe_content_hash
from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
    StixInputTransport,
    validate_stix_source_policy,
)
from app.ingestion.stix_taxii.threat_knowledge import map_threat_entity
from app.ingestion.stix_taxii.stix_validation import (
    ValidatedStixDocument,
    validate_stix_document,
)
from app.models import (
    Indicator,
    IndicatorProvenance,
    IntelligenceItemIndicator,
    IntelligenceSource,
    SourceRecord,
    ThreatEntity,
    ThreatEntityAlias,
    ThreatRelationship,
)


OBSERVED = datetime(2026, 7, 10, 12, tzinfo=UTC)
CREATED = "2026-07-01T10:00:00Z"
MODIFIED = "2026-07-01T11:00:00Z"
INDICATOR_ID = "indicator--22222222-2222-4222-8222-222222222222"
IP_ID = "ipv4-addr--88888888-8888-4888-8888-888888888888"
IDENTITY_ID = "identity--11111111-1111-4111-8111-111111111111"
OTHER_IDENTITY_ID = "identity--12121212-1212-4121-8121-121212121212"
MALWARE_ID = "malware--66666666-6666-4666-8666-666666666666"
RELATIONSHIP_ID = "relationship--33333333-3333-4333-8333-333333333333"
TLP_WHITE_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

    def scalars(self):
        return self

    def __iter__(self):
        if self._value is None:
            return iter(())
        if isinstance(self._value, list):
            return iter(self._value)
        return iter((self._value,))


class FakeSession:
    def __init__(self, source, *, records=(), indicators=(), provenances=(), entities=(), aliases=(), threat_relationships=()):
        self.source = source
        self.records = list(records)
        self.indicators = list(indicators)
        self.provenances = list(provenances)
        self.entities = list(entities)
        self.aliases = list(aliases)
        self.threat_relationships = list(threat_relationships)
        self.publication_relationships = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.execute_calls = 0
        self.execute_error = None
        self._snapshot = deepcopy((
            list(self.records),
            list(self.indicators),
            list(self.provenances),
            list(self.entities),
            list(self.aliases),
            list(self.threat_relationships),
        ))

    def get(self, model, identity):
        assert model is IntelligenceSource
        return self.source if self.source.id == identity else None

    def execute(self, statement):
        self.execute_calls += 1
        if self.execute_error is not None:
            raise self.execute_error
        entity = statement.column_descriptions[0]["entity"]
        collection = {
            SourceRecord: self.records,
            Indicator: self.indicators,
            IndicatorProvenance: self.provenances,
            ThreatEntity: self.entities,
            ThreatEntityAlias: self.aliases,
            ThreatRelationship: self.threat_relationships,
        }[entity]
        criteria = {
            criterion.left.name: criterion.right.value
            for criterion in statement._where_criteria
        }
        matches = [
            row
            for row in collection
            if all(getattr(row, name) == value for name, value in criteria.items())
        ]
        if entity is ThreatEntityAlias:
            return _ScalarResult(matches)
        assert len(matches) <= 1
        return _ScalarResult(matches[0] if matches else None)

    def add(self, value):
        if isinstance(value, SourceRecord):
            self.records.append(value)
        elif isinstance(value, Indicator):
            self.indicators.append(value)
        elif isinstance(value, IndicatorProvenance):
            self.provenances.append(value)
        elif isinstance(value, IntelligenceItemIndicator):
            self.publication_relationships.append(value)
        elif isinstance(value, ThreatEntity):
            self.entities.append(value)
        elif isinstance(value, ThreatEntityAlias):
            self.aliases.append(value)
        elif isinstance(value, ThreatRelationship):
            self.threat_relationships.append(value)
        else:
            raise AssertionError(f"unexpected add type: {type(value).__name__}")

    def flush(self):
        self.flush_calls += 1
        attached_aliases = {
            alias
            for entity in self.entities
            for alias in entity.aliases
        }
        self.aliases = [alias for alias in self.aliases if alias in attached_aliases]
        for collection in (self.records, self.indicators, self.provenances, self.entities, self.aliases, self.threat_relationships):
            for index, value in enumerate(collection, start=1):
                if value.id is None:
                    value.id = index

    def commit(self):
        self.commit_calls += 1

    def rollback(self):
        self.rollback_calls += 1

    def begin_caller_transaction(self):
        self._snapshot = deepcopy(
            (
                self.records,
                self.indicators,
                self.provenances,
                self.entities,
                self.aliases,
                self.threat_relationships,
            )
        )

    def caller_rollback(self):
        self.records, self.indicators, self.provenances, self.entities, self.aliases, self.threat_relationships = (
            list(items) for items in deepcopy(self._snapshot)
        )


def policy(**changes):
    base = ApprovedStixSourcePolicy(
        source_slug="synthetic-stix",
        allowed_transport=StixInputTransport.LOCAL_BUNDLE,
        policy_base_url="https://stix.example/objects",
        allowed_tlp_levels=frozenset({"white"}),
    )
    return validate_stix_source_policy(replace(base, **changes))


def source(**changes):
    values = {
        "id": 7,
        "name": "Synthetic STIX",
        "slug": "synthetic-stix",
        "source_type": "json",
        "base_url": "https://stix.example/objects",
        "is_enabled": True,
    }
    values.update(changes)
    return IntelligenceSource(**values)


def safe_reference_payload(stix_id, stix_type, **changes):
    payload = {"type": stix_type, "id": stix_id, "spec_version": "2.1"}
    if stix_type == "marking-definition":
        payload.update(
            created="2017-01-20T00:00:00.000000Z",
            marking_type="tlp",
            marking_level="white",
        )
    elif stix_type in {
        "identity",
        "indicator",
        "relationship",
        "attack-pattern",
        "campaign",
        "malware",
        "threat-actor",
    }:
        payload.update(
            created="2026-07-01T10:00:00.000000Z",
            modified="2026-07-01T11:00:00.000000Z",
        )
        if stix_type == "identity":
            payload.update(name="Existing identity", identity_class="organization")
        elif stix_type in {"attack-pattern", "campaign", "malware", "threat-actor"}:
            payload["name"] = f"Existing {stix_type}"
    payload.update(changes)
    return payload


def reference_record(stix_id, stix_type, *, record_id, source_id=7, **changes):
    payload = safe_reference_payload(stix_id, stix_type)
    source_url = f"https://stix.example/objects/{stix_id}"
    created = payload.get("created")
    modified = payload.get("modified")
    values = {
        "id": record_id,
        "source_id": source_id,
        "intelligence_item_id": None,
        "source_external_id": stix_id,
        "source_url": source_url,
        "canonical_url_hash": sha256(
            f"synthetic-stix\0{source_url}".encode("utf-8")
        ).hexdigest(),
        "content_hash": canonical_safe_content_hash(payload),
        "is_primary_reference": False,
        "raw_payload": payload,
        "payload_collected_at": OBSERVED,
        "first_seen_at": OBSERVED,
        "last_seen_at": OBSERVED,
        "source_published_at": (
            datetime.fromisoformat(created.replace("Z", "+00:00"))
            if isinstance(created, str)
            else None
        ),
        "source_modified_at": (
            datetime.fromisoformat(modified.replace("Z", "+00:00"))
            if isinstance(modified, str)
            else None
        ),
        "processing_status": "processed",
        "last_processed_at": OBSERVED,
        "safe_error_summary": None,
        "upstream_status": "present",
    }
    values.update(changes)
    return SourceRecord(**values)


def current_record(staged, **changes):
    payload = thaw_json(staged.safe_payload)
    source_url = f"https://stix.example/objects/{staged.stix_id}"
    values = {
        "id": 1,
        "source_id": 7,
        "intelligence_item_id": None,
        "source_external_id": staged.stix_id,
        "source_url": source_url,
        "canonical_url_hash": sha256(
            f"synthetic-stix\0{source_url}".encode("utf-8")
        ).hexdigest(),
        "content_hash": canonical_safe_content_hash(payload),
        "is_primary_reference": False,
        "raw_payload": payload,
        "payload_collected_at": OBSERVED,
        "first_seen_at": OBSERVED,
        "last_seen_at": OBSERVED,
        "source_published_at": staged.created,
        "source_modified_at": staged.modified,
        "processing_status": "processed",
        "last_processed_at": OBSERVED,
        "safe_error_summary": None,
        "upstream_status": "present",
    }
    values.update(changes)
    return SourceRecord(**values)


def record_state(record):
    return {
        column.name: deepcopy(getattr(record, column.name))
        for column in SourceRecord.__table__.columns
    }


def assert_current_record_rejection(session, approved, document, record):
    before = record_state(record)
    with pytest.raises(StixImportServiceError) as caught:
        StixBundleImportService(session).import_document(
            7,
            approved,
            document,
            observed_at=OBSERVED + timedelta(hours=1),
        )
    assert str(caught.value) == "Existing STIX source record is invalid."
    assert record_state(record) == before
    assert session.records == [record]
    assert session.indicators == []
    assert session.provenances == []
    assert session.flush_calls == 0
    assert_caller_owns_transaction(session)


def assert_fabricated_document_rejection(
    approved,
    document,
    *,
    expected_record_queries=0,
):
    session = FakeSession(source())

    with pytest.raises(StixImportServiceError) as caught:
        StixBundleImportService(session).import_document(
            7,
            approved,
            document,
            observed_at=OBSERVED,
        )

    assert str(caught.value) in {
        "Validated STIX document is invalid for persistence.",
        "Existing STIX reference record is invalid.",
    }
    assert "8.8.8.8" not in str(caught.value)
    assert "password" not in str(caught.value)
    assert session.execute_calls == expected_record_queries
    assert session.records == []
    assert session.indicators == []
    assert session.provenances == []
    assert session.flush_calls == 0
    assert_caller_owns_transaction(session)


def assert_external_record_rejection(session, approved, document):
    before = [record_state(record) for record in session.records]

    with pytest.raises(StixImportServiceError) as caught:
        StixBundleImportService(session).import_document(
            7,
            approved,
            document,
            observed_at=OBSERVED,
        )

    assert str(caught.value) == "Existing STIX reference record is invalid."
    assert [record_state(record) for record in session.records] == before
    assert session.indicators == []
    assert session.provenances == []
    assert session.flush_calls == 0
    assert_caller_owns_transaction(session)


def indicator_object(
    *,
    created=CREATED,
    modified=MODIFIED,
    confidence=80,
    value="8.8.8.8",
    created_by_ref=None,
    revoked=False,
    pattern_spaces=True,
):
    equals = " = " if pattern_spaces else "="
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": INDICATOR_ID,
        "created": created,
        "modified": modified,
        "pattern": f"[ipv4-addr:value{equals}'{value}']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": CREATED,
        "confidence": confidence,
        **({"created_by_ref": created_by_ref} if created_by_ref else {}),
        **({"revoked": True} if revoked else {}),
    }


def identity_object(*, modified=MODIFIED, name="Synthetic identity", **changes):
    value = {
        "type": "identity",
        "spec_version": "2.1",
        "id": IDENTITY_ID,
        "created": CREATED,
        "modified": modified,
        "name": name,
        "identity_class": "organization",
    }
    value.update(changes)
    return value


def validated(objects, *, existing=None):
    approved = policy()
    data = json.dumps({"type": "bundle", "objects": objects}).encode()
    document = parse_stix_json_bytes(
        data,
        approved,
        StixDocumentFormat.STIX_BUNDLE,
    )
    return approved, validate_stix_document(
        document,
        approved,
        existing_objects=existing,
    )


def assert_caller_owns_transaction(session):
    assert session.commit_calls == 0
    assert session.rollback_calls == 0


def test_first_import_stages_safe_record_indicator_and_exact_provenance():
    approved, document = validated([indicator_object()])
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        document,
        observed_at=OBSERVED,
    )

    assert result.status == "processed"
    assert (result.objects_received, result.objects_validated) == (1, 1)
    assert (result.objects_created, result.indicators_created) == (1, 1)
    assert result.provenances_created == 1
    assert result.bounded is True
    with pytest.raises(FrozenInstanceError):
        result.status = "changed"  # type: ignore[misc]
    record = session.records[0]
    assert record.source_external_id == INDICATOR_ID
    assert record.source_url == f"https://stix.example/objects/{INDICATOR_ID}"
    assert record.intelligence_item_id is None
    assert record.is_primary_reference is False
    assert record.processing_status == "processed"
    assert record.upstream_status == "present"
    assert record.safe_error_summary is None
    assert record.raw_payload == thaw_json(document.objects[0].safe_payload)
    assert session.indicators[0].confidence == Decimal("0.800")
    provenance = session.provenances[0]
    assert (provenance.source_id, provenance.source_record_id) == (7, record.id)
    assert session.publication_relationships == []
    assert_caller_owns_transaction(session)


def test_repeat_import_reuses_indicator_provenance_and_record_idempotently():
    approved, document = validated([indicator_object()])
    session = FakeSession(source())
    service = StixBundleImportService(session)

    first = service.import_document(7, approved, document, observed_at=OBSERVED)
    second = service.import_document(7, approved, document, observed_at=OBSERVED)

    assert first.objects_created == 1
    assert second.objects_unchanged == 1
    assert second.indicators_existing == 1
    assert second.provenances_unchanged == 1
    assert (len(session.records), len(session.indicators), len(session.provenances)) == (
        1,
        1,
        1,
    )
    assert session.flush_calls == 2
    assert_caller_owns_transaction(session)


@pytest.mark.parametrize("reverse_order", [False, True])
def test_multi_version_identity_persists_only_latest_with_verified_counters(
    reverse_order,
):
    older = identity_object(name="Older identity")
    latest = identity_object(
        modified="2026-07-02T11:00:00Z",
        name="Latest identity",
    )
    objects = [latest, older] if reverse_order else [older, latest]
    approved, document = validated(objects)
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        document,
        observed_at=OBSERVED,
    )

    assert (result.objects_received, result.objects_validated) == (2, 2)
    assert result.objects_created == 1
    assert len(document.validated_versions) == 2
    assert len(session.records) == 1
    assert session.records[0].raw_payload["name"] == "Latest identity"
    assert session.indicators == session.provenances == []
    assert_caller_owns_transaction(session)


def test_multi_version_indicator_reconstructs_one_indicator_and_provenance():
    approved, document = validated(
        [
            indicator_object(confidence=20),
            indicator_object(
                modified="2026-07-02T11:00:00Z",
                confidence=90,
                pattern_spaces=False,
            ),
        ]
    )
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        document,
        observed_at=OBSERVED,
    )

    assert (result.objects_received, result.objects_validated) == (2, 2)
    assert result.objects_created == 1
    assert result.indicators_created == result.provenances_created == 1
    assert len(session.records) == len(session.indicators) == len(session.provenances) == 1
    assert session.records[0].source_modified_at == datetime(
        2026, 7, 2, 11, tzinfo=UTC
    )
    assert session.indicators[0].confidence == Decimal("0.900")
    assert_caller_owns_transaction(session)


def test_multi_version_relationship_counts_all_versions_and_stages_latest_only():
    identity = identity_object()
    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": MALWARE_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "name": "Synthetic malware",
        "is_family": False,
    }
    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": RELATIONSHIP_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "relationship_type": "uses",
        "source_ref": IDENTITY_ID,
        "target_ref": MALWARE_ID,
    }
    latest_relationship = {
        **relationship,
        "modified": "2026-07-02T11:00:00Z",
    }
    approved, document = validated(
        [identity, relationship, malware, latest_relationship]
    )
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        document,
        observed_at=OBSERVED,
    )

    assert (result.objects_received, result.objects_validated) == (4, 4)
    assert result.relationships_validated == 2
    assert result.objects_created == 3
    assert len(session.records) == 3
    relationship_record = next(
        record
        for record in session.records
        if record.source_external_id == RELATIONSHIP_ID
    )
    assert relationship_record.source_modified_at == datetime(
        2026, 7, 2, 11, tzinfo=UTC
    )
    assert_caller_owns_transaction(session)


def test_multiple_ids_with_one_version_lineage_create_one_record_per_id():
    approved, document = validated(
        [
            identity_object(name="Older identity"),
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": MALWARE_ID,
                "created": CREATED,
                "modified": MODIFIED,
                "name": "Synthetic malware",
                "is_family": False,
            },
            identity_object(
                modified="2026-07-02T11:00:00Z",
                name="Latest identity",
            ),
        ]
    )
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        document,
        observed_at=OBSERVED,
    )

    assert (result.objects_received, result.objects_validated) == (3, 3)
    assert result.objects_created == 2
    assert len(session.records) == 2
    assert {
        record.source_external_id for record in session.records
    } == {IDENTITY_ID, MALWARE_ID}
    assert_caller_owns_transaction(session)


def test_latest_revoked_indicator_version_is_staged_once_without_automation():
    approved, document = validated(
        [
            indicator_object(),
            indicator_object(
                modified="2026-07-02T11:00:00Z",
                revoked=True,
            ),
        ]
    )
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        document,
        observed_at=OBSERVED,
    )

    assert (result.objects_received, result.objects_validated) == (2, 2)
    assert result.objects_created == 1
    assert result.revoked_indicators_suppressed == 1
    assert len(session.records) == 1
    assert session.records[0].raw_payload["revoked"] is True
    assert session.indicators == session.provenances == []
    assert_caller_owns_transaction(session)


def test_newer_version_updates_record_and_existing_indicator_without_status_change():
    approved, first = validated([indicator_object(confidence=20)])
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, first, observed_at=OBSERVED)
    session.indicators[0].status = "archived"
    _, newer = validated(
        [indicator_object(modified="2026-07-02T11:00:00Z", confidence=90)]
    )

    result = service.import_document(
        7,
        approved,
        newer,
        observed_at=datetime(2026, 7, 11, tzinfo=UTC),
    )

    assert result.objects_updated == 1
    assert result.indicators_existing == 1
    assert result.provenances_updated == 1
    assert session.indicators[0].status == "archived"
    assert session.indicators[0].confidence == Decimal("0.900")


def test_identity_changing_version_is_rejected_before_any_mutation():
    approved, first = validated([indicator_object()])
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, first, observed_at=OBSERVED)
    before_record = deepcopy(session.records[0].raw_payload)
    before_hash = session.records[0].content_hash
    before_record_state = (
        session.records[0].source_modified_at,
        session.records[0].last_seen_at,
        session.records[0].last_processed_at,
    )
    before_indicator = (
        session.indicators[0].status,
        session.indicators[0].confidence,
        session.indicators[0].first_seen_at,
        session.indicators[0].last_seen_at,
    )
    before_provenance = (
        session.provenances[0].confidence,
        session.provenances[0].first_observed_at,
        session.provenances[0].last_observed_at,
    )
    _, changed = validated(
        [indicator_object(modified="2026-07-02T11:00:00Z", value="1.1.1.1")]
    )

    with pytest.raises(StixImportServiceError, match="changed mapped identity"):
        service.import_document(7, approved, changed, observed_at=OBSERVED)

    assert session.records[0].raw_payload == before_record
    assert session.records[0].content_hash == before_hash
    assert (
        session.records[0].source_modified_at,
        session.records[0].last_seen_at,
        session.records[0].last_processed_at,
    ) == before_record_state
    assert (
        session.indicators[0].status,
        session.indicators[0].confidence,
        session.indicators[0].first_seen_at,
        session.indicators[0].last_seen_at,
    ) == before_indicator
    assert (
        session.provenances[0].confidence,
        session.provenances[0].first_observed_at,
        session.provenances[0].last_observed_at,
    ) == before_provenance
    assert (len(session.indicators), len(session.provenances)) == (1, 1)
    assert_caller_owns_transaction(session)


def test_pattern_syntax_change_with_same_normalized_identity_updates_safely():
    approved, first = validated([indicator_object()])
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, first, observed_at=OBSERVED)
    _, changed = validated(
        [indicator_object(modified="2026-07-02T11:00:00Z", pattern_spaces=False)]
    )

    result = service.import_document(7, approved, changed, observed_at=OBSERVED)

    assert result.objects_updated == 1
    assert result.indicators_existing == 1
    assert len(session.indicators) == len(session.provenances) == 1


def test_marking_only_version_update_preserves_mapped_identity():
    approved, first = validated([indicator_object()])
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, first, observed_at=OBSERVED)
    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": TLP_WHITE_ID,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "white"},
    }
    updated_indicator = indicator_object(modified="2026-07-02T11:00:00Z")
    updated_indicator["object_marking_refs"] = [TLP_WHITE_ID]
    _, updated = validated([marking, updated_indicator])

    result = service.import_document(7, approved, updated, observed_at=OBSERVED)

    assert result.objects_updated == 1
    assert result.objects_created == 1
    assert session.records[0].raw_payload["object_marking_refs"] == [TLP_WHITE_ID]
    assert len(session.indicators) == len(session.provenances) == 1


def test_first_import_of_revoked_indicator_stages_only_source_record():
    approved, document = validated([indicator_object(revoked=True)])
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(
        7, approved, document, observed_at=OBSERVED
    )

    assert result.objects_created == 1
    assert result.revoked_indicators_suppressed == 1
    assert session.records[0].raw_payload["revoked"] is True
    assert session.indicators == session.provenances == []
    assert_caller_owns_transaction(session)


@pytest.mark.parametrize(
    "status",
    ["active", "archived", "inactive", "revoked", "false_positive"],
)
def test_revoked_incoming_indicator_never_mutates_existing_local_lifecycle(status):
    approved, first = validated([indicator_object(confidence=20)])
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, first, observed_at=OBSERVED)
    local = session.indicators[0]
    local.status = status
    local.revoked_at = OBSERVED if status == "revoked" else None
    before_indicator = (
        local.status,
        local.revoked_at,
        local.confidence,
        local.first_seen_at,
        local.last_seen_at,
    )
    provenance = session.provenances[0]
    before_provenance = (
        provenance.confidence,
        provenance.first_observed_at,
        provenance.last_observed_at,
    )
    _, revoked = validated(
        [
            indicator_object(
                modified="2026-07-02T11:00:00Z",
                confidence=100,
                revoked=True,
            )
        ]
    )

    result = service.import_document(7, approved, revoked, observed_at=OBSERVED)

    assert result.objects_updated == 1
    assert result.revoked_indicators_suppressed == 1
    assert (
        local.status,
        local.revoked_at,
        local.confidence,
        local.first_seen_at,
        local.last_seen_at,
    ) == before_indicator
    assert (
        provenance.confidence,
        provenance.first_observed_at,
        provenance.last_observed_at,
    ) == before_provenance
    assert (len(session.indicators), len(session.provenances)) == (1, 1)
    assert_caller_owns_transaction(session)


@pytest.mark.parametrize(
    "change",
    [
        {"created": "2026-06-30T10:00:00Z"},
        {"created_by_ref": OTHER_IDENTITY_ID},
    ],
)
def test_stored_version_rejects_changed_created_or_creator(change):
    approved, first = validated(
        [indicator_object(created_by_ref=IDENTITY_ID)]
    )
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, first, observed_at=OBSERVED)
    incoming_values = {
        "modified": "2026-07-02T11:00:00Z",
        "created_by_ref": IDENTITY_ID,
        **change,
    }
    incoming = indicator_object(**incoming_values)
    _, newer = validated([incoming])

    with pytest.raises(StixImportServiceError, match="invariant metadata"):
        service.import_document(7, approved, newer, observed_at=OBSERVED)

    assert session.records[0].raw_payload == thaw_json(first.objects[0].safe_payload)
    assert (len(session.indicators), len(session.provenances)) == (1, 1)


def test_no_version_may_follow_a_stored_revoked_version():
    approved, revoked = validated([indicator_object(revoked=True)])
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, revoked, observed_at=OBSERVED)
    _, newer = validated(
        [indicator_object(modified="2026-07-02T11:00:00Z", revoked=True)]
    )

    with pytest.raises(StixImportServiceError, match="cannot have a newer version"):
        service.import_document(7, approved, newer, observed_at=OBSERVED)

    assert session.records[0].raw_payload["modified"] == (
        "2026-07-01T11:00:00.000000Z"
    )
    assert session.indicators == session.provenances == []
    assert_caller_owns_transaction(session)


def test_malformed_existing_safe_version_metadata_fails_consistently():
    approved, first = validated([indicator_object()])
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, first, observed_at=OBSERVED)
    session.records[0].raw_payload.pop("created")
    _, newer = validated(
        [indicator_object(modified="2026-07-02T11:00:00Z")]
    )

    with pytest.raises(StixImportServiceError, match="source record is invalid"):
        service.import_document(7, approved, newer, observed_at=OBSERVED)


def test_stale_version_does_not_overwrite_newer_record_or_touch_indicator():
    approved, newer = validated(
        [indicator_object(modified="2026-07-03T11:00:00Z", confidence=90)]
    )
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, newer, observed_at=OBSERVED)
    content_hash = session.records[0].content_hash
    _, stale = validated([indicator_object(modified=MODIFIED, confidence=20)])

    result = service.import_document(7, approved, stale, observed_at=OBSERVED)

    assert result.objects_stale == 1
    assert result.indicators_existing == 0
    assert session.records[0].content_hash == content_hash
    assert session.indicators[0].confidence == Decimal("0.900")


def test_same_version_content_conflict_and_nonversioned_conflicts_are_rejected():
    approved, first = validated([indicator_object(confidence=20)])
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, first, observed_at=OBSERVED)
    _, conflict = validated([indicator_object(confidence=90)])

    with pytest.raises(StixImportServiceError, match="version content conflicts"):
        service.import_document(7, approved, conflict, observed_at=OBSERVED)

    direct = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": IP_ID,
        "value": "8.8.8.8",
    }
    approved, first_direct = validated([direct])
    direct_session = FakeSession(source())
    direct_service = StixBundleImportService(direct_session)
    direct_service.import_document(7, approved, first_direct, observed_at=OBSERVED)
    _, direct_conflict = validated([{**direct, "value": "1.1.1.1"}])
    with pytest.raises(StixImportServiceError, match="Non-versioned"):
        direct_service.import_document(
            7, approved, direct_conflict, observed_at=OBSERVED
        )


def test_nonversioned_marking_conflict_is_rejected():
    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": TLP_WHITE_ID,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "white"},
    }
    approved, document = validated([marking])
    session = FakeSession(source())
    service = StixBundleImportService(session)
    service.import_document(7, approved, document, observed_at=OBSERVED)
    session.records[0].content_hash = "0" * 64

    with pytest.raises(StixImportServiceError, match="source record is invalid"):
        service.import_document(7, approved, document, observed_at=OBSERVED)


def test_false_positive_suppresses_indicator_and_provenance_automation():
    approved, document = validated([indicator_object()])
    normalized = normalize_observable("ipv4", "8.8.8.8")
    existing = Indicator(
        id=5,
        observable_type="ipv4",
        normalized_value="8.8.8.8",
        identity_sha256=normalized.identity_sha256,
        status="false_positive",
        confidence=Decimal("0.100"),
        first_seen_at=OBSERVED,
        last_seen_at=OBSERVED,
    )
    session = FakeSession(source(), indicators=[existing])

    result = StixBundleImportService(session).import_document(
        7, approved, document, observed_at=OBSERVED
    )

    assert result.false_positive_suppressed == 1
    assert result.provenances_created == 0
    assert session.provenances == []
    assert existing.confidence == Decimal("0.100")


@pytest.mark.parametrize(
    "source_change",
    [
        {"slug": "other-source"},
        {"is_enabled": False},
        {"source_type": "rss"},
        {"base_url": "https://alias.example/objects"},
    ],
)
def test_source_identity_mismatch_fails_before_any_persistence(source_change):
    approved, document = validated([indicator_object()])
    session = FakeSession(source(**source_change))

    with pytest.raises(StixImportServiceError, match="identity does not match"):
        StixBundleImportService(session).import_document(
            7, approved, document, observed_at=OBSERVED
        )

    assert session.records == session.indicators == session.provenances == []
    assert session.flush_calls == 0
    assert_caller_owns_transaction(session)


def test_missing_source_and_strict_call_arguments_fail_safely():
    approved, document = validated([indicator_object()])
    session = FakeSession(source(id=8))
    service = StixBundleImportService(session)
    with pytest.raises(StixImportServiceError, match="does not exist"):
        service.import_document(7, approved, document, observed_at=OBSERVED)
    for source_id in (0, -1, True, "7"):
        with pytest.raises(ValueError, match="positive integer"):
            service.import_document(
                source_id, approved, document, observed_at=OBSERVED  # type: ignore[arg-type]
            )
    with pytest.raises(ValueError, match="timezone-aware"):
        service.import_document(
            8, approved, document, observed_at=datetime(2026, 7, 10)
        )


def test_database_failure_is_sanitized_and_persistence_specific_without_transaction_ownership():
    approved, document = validated([indicator_object()])
    session = FakeSession(source())
    session.execute_error = SQLAlchemyError(
        "secret SQL with submitted observable 8.8.8.8"
    )

    with pytest.raises(StixImportPersistenceError) as caught:
        StixBundleImportService(session).import_document(
            7, approved, document, observed_at=OBSERVED
        )

    assert str(caught.value) == (
        "Database error while importing validated STIX metadata."
    )
    assert "8.8.8.8" not in str(caught.value)
    assert_caller_owns_transaction(session)


@pytest.mark.parametrize("unexpected_key", ["password", "command_line"])
def test_fabricated_document_rejects_correctly_hashed_unexpected_payload_key(
    unexpected_key,
):
    approved, document = validated([indicator_object()])
    staged = document.objects[0]
    payload = thaw_json(staged.safe_payload)
    payload[unexpected_key] = "must-not-persist"
    forged = replace(
        staged,
        safe_payload=payload,
        content_hash=canonical_safe_content_hash(payload),
    )

    assert_fabricated_document_rejection(
        approved,
        replace(document, objects=(forged,)),
    )


def test_fabricated_document_rejects_forged_content_hash():
    approved, document = validated([indicator_object()])
    forged = replace(document.objects[0], content_hash="f" * 64)

    assert_fabricated_document_rejection(
        approved,
        replace(document, objects=(forged,)),
    )


def test_fabricated_document_rejects_injected_direct_observable():
    direct = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": IP_ID,
        "value": "8.8.8.8",
    }
    approved, document = validated([direct])
    _, different = validated([{**direct, "value": "1.1.1.1"}])
    forged = replace(
        document.objects[0],
        observables=different.objects[0].observables,
    )

    assert_fabricated_document_rejection(
        approved,
        replace(document, objects=(forged,)),
    )


def test_fabricated_indicator_rejects_mismatched_mapped_identity():
    approved, document = validated([indicator_object()])
    staged = document.objects[0]
    payload = thaw_json(staged.safe_payload)
    different = normalize_observable("ipv4", "1.1.1.1")
    payload["mapped_observables"] = [
        {
            "observable_type": "ipv4",
            "hash_algorithm": None,
            "identity_sha256": different.identity_sha256,
        }
    ]
    forged = replace(
        staged,
        safe_payload=payload,
        content_hash=canonical_safe_content_hash(payload),
    )

    assert_fabricated_document_rejection(
        approved,
        replace(document, objects=(forged,)),
    )


def test_mutable_safe_payload_changed_after_document_construction_is_rejected():
    approved, document = validated([indicator_object()])
    staged = document.objects[0]
    mutable_payload = thaw_json(staged.safe_payload)
    forged = replace(staged, safe_payload=mutable_payload)
    fabricated = replace(document, objects=(forged,))
    mutable_payload["password"] = "changed-after-construction"

    assert_fabricated_document_rejection(approved, fabricated)


def test_valid_mutable_payload_is_copied_before_persistence():
    approved, document = validated([indicator_object()])
    staged = document.objects[0]
    mutable_payload = thaw_json(staged.safe_payload)
    caller_document = replace(
        document,
        objects=(replace(staged, safe_payload=mutable_payload),),
    )
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        caller_document,
        observed_at=OBSERVED,
    )
    mutable_payload["password"] = "changed-after-import"

    assert result.objects_created == 1
    assert "password" not in session.records[0].raw_payload
    assert session.records[0].raw_payload == thaw_json(staged.safe_payload)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda staged: replace(staged, stix_type="identity"),
        lambda staged: replace(staged, stix_id=OTHER_IDENTITY_ID),
        lambda staged: replace(staged, created=OBSERVED),
        lambda staged: replace(staged, modified=OBSERVED),
    ],
)
def test_fabricated_document_rejects_staged_identity_and_timestamp_mismatches(
    mutation,
):
    approved, document = validated([indicator_object()])
    forged = mutation(document.objects[0])

    assert_fabricated_document_rejection(
        approved,
        replace(document, objects=(forged,)),
    )


def test_fabricated_document_rejects_duplicate_stix_ids():
    approved, document = validated([indicator_object()])
    staged = document.objects[0]
    fabricated = ValidatedStixDocument(
        objects=(staged, staged),
        validated_versions=(staged, staged),
        objects_received=2,
        objects_validated=2,
        relationships_validated=0,
        markings_validated=0,
    )

    assert_fabricated_document_rejection(approved, fabricated)


def test_fabricated_version_lineage_cannot_omit_an_inspected_version():
    approved, document = validated(
        [
            identity_object(name="Older identity"),
            identity_object(
                modified="2026-07-02T11:00:00Z",
                name="Latest identity",
            ),
        ]
    )
    fabricated = replace(
        document,
        validated_versions=(document.validated_versions[-1],),
    )

    assert_fabricated_document_rejection(approved, fabricated)


def test_fabricated_lineage_rejects_duplicate_nonversioned_sco():
    direct = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": IP_ID,
        "value": "8.8.8.8",
    }
    approved, document = validated([direct])
    staged = document.objects[0]
    fabricated = replace(
        document,
        validated_versions=(staged, staged),
        objects_received=2,
        objects_validated=2,
    )

    assert_fabricated_document_rejection(approved, fabricated)


def test_fabricated_latest_tuple_must_be_derived_from_version_lineage():
    approved, document = validated(
        [
            identity_object(name="Older identity"),
            identity_object(
                modified="2026-07-02T11:00:00Z",
                name="Latest identity",
            ),
        ]
    )
    fabricated = replace(
        document,
        objects=(document.validated_versions[0],),
    )

    assert_fabricated_document_rejection(approved, fabricated)


@pytest.mark.parametrize(
    "forgery",
    ["hash", "payload", "observable", "id", "created", "modified"],
)
def test_fabricated_version_lineage_entry_is_fully_revalidated(forgery):
    approved, document = validated(
        [
            identity_object(name="Older identity"),
            identity_object(
                modified="2026-07-02T11:00:00Z",
                name="Latest identity",
            ),
        ]
    )
    staged = document.validated_versions[0]
    if forgery == "hash":
        forged = replace(staged, content_hash="f" * 64)
    elif forgery == "payload":
        payload = thaw_json(staged.safe_payload)
        payload["password"] = "must-not-persist"
        forged = replace(
            staged,
            safe_payload=payload,
            content_hash=canonical_safe_content_hash(payload),
        )
    elif forgery == "observable":
        _, indicator_document = validated([indicator_object()])
        forged = replace(
            staged,
            observables=indicator_document.objects[0].observables,
        )
    elif forgery == "id":
        forged = replace(staged, stix_id=OTHER_IDENTITY_ID)
    elif forgery == "created":
        forged = replace(staged, created=OBSERVED)
    else:
        forged = replace(staged, modified=OBSERVED)
    versions = list(document.validated_versions)
    versions[0] = forged

    assert_fabricated_document_rejection(
        approved,
        replace(document, validated_versions=tuple(versions)),
    )


@pytest.mark.parametrize(
    "invariant",
    ["duplicate_modified", "changed_created", "changed_creator", "revoked_then_newer"],
)
def test_fabricated_version_lineage_reruns_cross_version_invariants(invariant):
    approved, document = validated(
        [
            identity_object(name="Older identity"),
            identity_object(
                modified="2026-07-02T11:00:00Z",
                name="Latest identity",
            ),
        ]
    )
    versions = list(document.validated_versions)
    target_index = 0 if invariant in {"duplicate_modified", "revoked_then_newer"} else 1
    staged = versions[target_index]
    payload = thaw_json(staged.safe_payload)
    if invariant == "duplicate_modified":
        payload["modified"] = "2026-07-02T11:00:00.000000Z"
    elif invariant == "changed_created":
        payload["created"] = "2026-06-30T10:00:00.000000Z"
    elif invariant == "changed_creator":
        payload["created_by_ref"] = OTHER_IDENTITY_ID
    else:
        payload["revoked"] = True
    created = datetime.fromisoformat(payload["created"].replace("Z", "+00:00"))
    modified = datetime.fromisoformat(payload["modified"].replace("Z", "+00:00"))
    versions[target_index] = replace(
        staged,
        safe_payload=payload,
        content_hash=canonical_safe_content_hash(payload),
        created=created,
        modified=modified,
    )

    assert_fabricated_document_rejection(
        approved,
        replace(document, validated_versions=tuple(versions)),
    )


@pytest.mark.parametrize(
    "counter_change",
    [
        {"objects_received": 2},
        {"objects_validated": 2},
        {"relationships_validated": 1},
        {"markings_validated": 1},
    ],
)
def test_fabricated_document_rejects_object_relationship_and_marking_counters(
    counter_change,
):
    approved, document = validated([indicator_object()])

    assert_fabricated_document_rejection(
        approved,
        replace(document, **counter_change),
    )


def test_fabricated_document_rejects_relationship_before_referenced_objects():
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": IDENTITY_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "name": "Synthetic identity",
        "identity_class": "organization",
    }
    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": MALWARE_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "name": "Synthetic malware",
        "is_family": False,
    }
    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": RELATIONSHIP_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "relationship_type": "uses",
        "source_ref": IDENTITY_ID,
        "target_ref": MALWARE_ID,
    }
    approved, document = validated([identity, malware, relationship])
    by_type = {item.stix_type: item for item in document.objects}
    fabricated = replace(
        document,
        objects=(
            by_type["relationship"],
            by_type["identity"],
            by_type["malware"],
        ),
    )

    assert_fabricated_document_rejection(approved, fabricated)


def test_fabricated_unresolved_relationship_is_rejected_without_persistence():
    approved, document = relationship_with_existing_document()

    assert_fabricated_document_rejection(
        approved,
        document,
        expected_record_queries=1,
    )


def test_fabricated_unapproved_marking_reference_is_rejected_without_persistence():
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": IDENTITY_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "name": "Marked identity",
        "identity_class": "organization",
        "object_marking_refs": [TLP_WHITE_ID],
    }
    marking_payload = safe_reference_payload(TLP_WHITE_ID, "marking-definition")
    approved, document = validated(
        [identity],
        existing={TLP_WHITE_ID: marking_payload},
    )

    assert_fabricated_document_rejection(
        approved,
        document,
        expected_record_queries=1,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("processing_status", "failed"),
        ("upstream_status", "missing"),
        ("safe_error_summary", "safe failure"),
    ],
)
def test_current_indicator_record_status_must_be_processed_present_and_error_free(
    field, value
):
    approved, document = validated([indicator_object()])
    record = current_record(document.objects[0])
    setattr(record, field, value)
    session = FakeSession(source(), records=[record])

    assert_current_record_rejection(session, approved, document, record)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("intelligence_item_id", 42),
        ("is_primary_reference", True),
        ("source_published_at", OBSERVED),
        ("source_modified_at", OBSERVED),
        ("last_processed_at", None),
        ("payload_collected_at", datetime(2026, 7, 10, 12)),
        ("first_seen_at", datetime(2026, 7, 10, 12)),
        ("last_seen_at", datetime(2026, 7, 10, 12)),
        ("last_processed_at", datetime(2026, 7, 10, 12)),
    ],
)
def test_current_record_rejects_ownership_and_audit_metadata_mismatches(
    field,
    value,
):
    approved, document = validated([indicator_object()])
    record = current_record(document.objects[0])
    setattr(record, field, value)
    session = FakeSession(source(), records=[record])

    assert_current_record_rejection(session, approved, document, record)


def test_current_record_rejects_first_seen_after_last_seen():
    approved, document = validated([indicator_object()])
    record = current_record(
        document.objects[0],
        first_seen_at=OBSERVED + timedelta(hours=1),
        last_seen_at=OBSERVED,
    )
    session = FakeSession(source(), records=[record])

    assert_current_record_rejection(session, approved, document, record)


@pytest.mark.parametrize("field", ["source_published_at", "source_modified_at"])
def test_nonversioned_current_sco_rejects_source_version_timestamps(field):
    direct = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": IP_ID,
        "value": "8.8.8.8",
    }
    approved, document = validated([direct])
    record = current_record(document.objects[0])
    setattr(record, field, OBSERVED)
    session = FakeSession(source(), records=[record])

    assert_current_record_rejection(session, approved, document, record)


@pytest.mark.parametrize("changed_field", ["pattern", "mapped_observables"])
def test_current_indicator_rejects_incoming_hash_over_mismatched_raw_payload(
    changed_field,
):
    approved, document = validated([indicator_object()])
    record = current_record(document.objects[0])
    if changed_field == "pattern":
        record.raw_payload["pattern"] = "[ipv4-addr:value = '1.1.1.1']"
    else:
        different = normalize_observable("ipv4", "1.1.1.1")
        record.raw_payload["mapped_observables"] = [
            {
                "observable_type": "ipv4",
                "hash_algorithm": None,
                "identity_sha256": different.identity_sha256,
            }
        ]
    record.content_hash = document.objects[0].content_hash
    session = FakeSession(source(), records=[record])

    assert_current_record_rejection(session, approved, document, record)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda record: setattr(record, "raw_payload", None),
        lambda record: (
            setattr(record, "raw_payload", {"type": "ipv4-addr"}),
            setattr(
                record,
                "content_hash",
                canonical_safe_content_hash({"type": "ipv4-addr"}),
            ),
        ),
        lambda record: setattr(record, "content_hash", "0" * 64),
        lambda record: setattr(
            record,
            "source_url",
            "https://stix.example/objects/ipv4-addr--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        ),
        lambda record: setattr(record, "canonical_url_hash", "0" * 64),
    ],
)
def test_current_sco_requires_complete_payload_hash_and_canonical_source_identity(
    mutation,
):
    direct = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": IP_ID,
        "value": "8.8.8.8",
    }
    approved, document = validated([direct])
    record = current_record(document.objects[0])
    mutation(record)
    session = FakeSession(source(), records=[record])

    assert_current_record_rejection(session, approved, document, record)


@pytest.mark.parametrize("newer", [False, True])
def test_current_indicator_extra_key_cannot_authorize_unchanged_or_update(newer):
    approved, old_document = validated([indicator_object()])
    record = current_record(old_document.objects[0])
    record.raw_payload["password"] = "must-not-authorize"
    record.content_hash = canonical_safe_content_hash(record.raw_payload)
    document = old_document
    if newer:
        _, document = validated(
            [indicator_object(modified="2026-07-02T11:00:00Z")]
        )
    session = FakeSession(source(), records=[record])

    assert_current_record_rejection(session, approved, document, record)


def test_relationship_requires_same_source_existing_record_at_persistence_boundary():
    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": RELATIONSHIP_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "relationship_type": "uses",
        "source_ref": IDENTITY_ID,
        "target_ref": MALWARE_ID,
    }
    existing = {
        IDENTITY_ID: safe_reference_payload(IDENTITY_ID, "identity"),
        MALWARE_ID: safe_reference_payload(MALWARE_ID, "malware"),
    }
    approved, document = validated([relationship], existing=existing)
    session = FakeSession(source())

    with pytest.raises(StixImportServiceError, match="reference record is invalid"):
        StixBundleImportService(session).import_document(
            7, approved, document, observed_at=OBSERVED
        )

    other_source_records = [
        reference_record(
            stix_id,
            stix_type,
            record_id=index,
            source_id=8,
        )
        for index, (stix_id, stix_type) in enumerate(
            ((IDENTITY_ID, "identity"), (MALWARE_ID, "malware")), start=1
        )
    ]
    session = FakeSession(source(), records=other_source_records)
    with pytest.raises(StixImportServiceError, match="reference record is invalid"):
        StixBundleImportService(session).import_document(
            7, approved, document, observed_at=OBSERVED
        )


def relationship_with_existing_document():
    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": RELATIONSHIP_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "relationship_type": "uses",
        "source_ref": IDENTITY_ID,
        "target_ref": MALWARE_ID,
    }
    existing = {
        IDENTITY_ID: safe_reference_payload(IDENTITY_ID, "identity"),
        MALWARE_ID: safe_reference_payload(MALWARE_ID, "malware"),
    }
    return validated([relationship], existing=existing)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("intelligence_item_id", 42),
        ("is_primary_reference", True),
        ("source_published_at", OBSERVED),
        ("source_modified_at", OBSERVED),
        ("last_processed_at", None),
        ("payload_collected_at", datetime(2026, 7, 10, 12)),
        ("first_seen_at", datetime(2026, 7, 10, 12)),
        ("last_seen_at", datetime(2026, 7, 10, 12)),
        ("last_processed_at", datetime(2026, 7, 10, 12)),
    ],
)
def test_external_reference_rejects_ownership_and_audit_metadata_mismatches(
    field,
    value,
):
    approved, document = relationship_with_existing_document()
    records = [
        reference_record(IDENTITY_ID, "identity", record_id=1),
        reference_record(MALWARE_ID, "malware", record_id=2),
    ]
    setattr(records[0], field, value)
    session = FakeSession(source(), records=records)

    assert_external_record_rejection(session, approved, document)


def test_external_reference_rejects_first_seen_after_last_seen():
    approved, document = relationship_with_existing_document()
    records = [
        reference_record(
            IDENTITY_ID,
            "identity",
            record_id=1,
            first_seen_at=OBSERVED + timedelta(hours=1),
            last_seen_at=OBSERVED,
        ),
        reference_record(MALWARE_ID, "malware", record_id=2),
    ]
    session = FakeSession(source(), records=records)

    assert_external_record_rejection(session, approved, document)


@pytest.mark.parametrize("field", ["source_published_at", "source_modified_at"])
def test_external_nonversioned_sco_rejects_source_version_timestamps(field):
    direct = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": IP_ID,
        "value": "8.8.8.8",
    }
    _, direct_document = validated([direct])
    ip_payload = thaw_json(direct_document.objects[0].safe_payload)
    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": RELATIONSHIP_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "relationship_type": "related-to",
        "source_ref": IDENTITY_ID,
        "target_ref": IP_ID,
    }
    approved, document = validated(
        [relationship],
        existing={
            IDENTITY_ID: safe_reference_payload(IDENTITY_ID, "identity"),
            IP_ID: ip_payload,
        },
    )
    records = [
        reference_record(IDENTITY_ID, "identity", record_id=1),
        reference_record(
            IP_ID,
            "ipv4-addr",
            record_id=2,
            raw_payload=ip_payload,
            content_hash=canonical_safe_content_hash(ip_payload),
        ),
    ]
    setattr(records[1], field, OBSERVED)
    session = FakeSession(source(), records=records)

    assert_external_record_rejection(session, approved, document)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda record: setattr(record, "processing_status", "failed"),
        lambda record: setattr(record, "processing_status", "pending"),
        lambda record: setattr(record, "source_id", 8),
        lambda record: setattr(record, "source_external_id", OTHER_IDENTITY_ID),
        lambda record: setattr(record, "upstream_status", "missing"),
        lambda record: setattr(record, "upstream_status", "unavailable"),
        lambda record: setattr(record, "safe_error_summary", "safe failure"),
        lambda record: setattr(record, "raw_payload", None),
        lambda record: setattr(record, "raw_payload", []),
        lambda record: setattr(
            record,
            "raw_payload",
            safe_reference_payload(MALWARE_ID, "url"),
        ),
        lambda record: setattr(
            record,
            "raw_payload",
            safe_reference_payload(OTHER_IDENTITY_ID, "identity"),
        ),
        lambda record: record.raw_payload.update(spec_version="2.0"),
        lambda record: setattr(record, "content_hash", None),
        lambda record: setattr(record, "content_hash", "not-a-hash"),
        lambda record: setattr(record, "content_hash", "0" * 64),
    ],
)
def test_invalid_existing_reference_record_never_authorizes_persistence(mutation):
    approved, document = relationship_with_existing_document()
    records = [
        reference_record(IDENTITY_ID, "identity", record_id=1),
        reference_record(MALWARE_ID, "malware", record_id=2),
    ]
    mutation(records[1])
    session = FakeSession(source(), records=records)

    with pytest.raises(StixImportServiceError) as caught:
        StixBundleImportService(session).import_document(
            7, approved, document, observed_at=OBSERVED
        )

    assert str(caught.value) == "Existing STIX reference record is invalid."
    assert MALWARE_ID not in str(caught.value)
    assert len(session.records) == 2
    assert session.flush_calls == 0
    assert session.indicators == session.provenances == []
    assert_caller_owns_transaction(session)


def test_correctly_hashed_extra_key_cannot_authorize_relationship_reference():
    approved, document = relationship_with_existing_document()
    records = [
        reference_record(IDENTITY_ID, "identity", record_id=1),
        reference_record(MALWARE_ID, "malware", record_id=2),
    ]
    records[1].raw_payload["command_line"] = "must-not-authorize"
    records[1].content_hash = canonical_safe_content_hash(records[1].raw_payload)
    session = FakeSession(source(), records=records)

    with pytest.raises(StixImportServiceError, match="reference record is invalid"):
        StixBundleImportService(session).import_document(
            7, approved, document, observed_at=OBSERVED
        )

    assert len(session.records) == 2
    assert session.indicators == session.provenances == []
    assert session.flush_calls == 0
    assert_caller_owns_transaction(session)


def test_previously_accepted_failed_mismatched_records_are_rejected_atomically():
    approved, document = relationship_with_existing_document()
    source_record = reference_record(
        IDENTITY_ID,
        "identity",
        record_id=1,
        processing_status="failed",
        upstream_status="missing",
    )
    source_record.raw_payload = safe_reference_payload(IDENTITY_ID, "url")
    target_record = reference_record(
        MALWARE_ID,
        "malware",
        record_id=2,
        processing_status="failed",
        upstream_status="missing",
        raw_payload=None,
    )
    session = FakeSession(source(), records=[source_record, target_record])

    with pytest.raises(StixImportServiceError):
        StixBundleImportService(session).import_document(
            7, approved, document, observed_at=OBSERVED
        )

    assert len(session.records) == 2
    assert session.flush_calls == 0
    assert_caller_owns_transaction(session)


def test_canonical_processed_present_content_verified_records_resolve_successfully():
    approved, document = relationship_with_existing_document()
    records = [
        reference_record(IDENTITY_ID, "identity", record_id=1),
        reference_record(MALWARE_ID, "malware", record_id=2),
    ]
    session = FakeSession(source(), records=records)

    result = StixBundleImportService(session).import_document(
        7, approved, document, observed_at=OBSERVED
    )

    assert result.objects_created == 1
    assert len(session.records) == 3
    assert session.flush_calls == 1
    assert_caller_owns_transaction(session)


def test_canonical_existing_marking_record_resolves_successfully():
    marking_payload = safe_reference_payload(
        TLP_WHITE_ID,
        "marking-definition",
        marking_type="tlp",
        marking_level="white",
    )
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": IDENTITY_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "name": "Marked identity",
        "identity_class": "organization",
        "object_marking_refs": [TLP_WHITE_ID],
    }
    approved, document = validated(
        [identity], existing={TLP_WHITE_ID: marking_payload}
    )
    marking_record = reference_record(
        TLP_WHITE_ID,
        "marking-definition",
        record_id=1,
        raw_payload=marking_payload,
        content_hash=canonical_safe_content_hash(marking_payload),
    )
    session = FakeSession(source(), records=[marking_record])

    result = StixBundleImportService(session).import_document(
        7, approved, document, observed_at=OBSERVED
    )

    assert result.objects_created == 1
    assert len(session.records) == 2


def test_invalid_existing_marking_record_cannot_authorize_marked_object():
    marking_payload = safe_reference_payload(
        TLP_WHITE_ID,
        "marking-definition",
        marking_type="tlp",
        marking_level="white",
    )
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": IDENTITY_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "name": "Marked identity",
        "identity_class": "organization",
        "object_marking_refs": [TLP_WHITE_ID],
    }
    approved, document = validated(
        [identity], existing={TLP_WHITE_ID: marking_payload}
    )
    marking_record = reference_record(
        TLP_WHITE_ID,
        "marking-definition",
        record_id=1,
        raw_payload=marking_payload,
        content_hash=canonical_safe_content_hash(marking_payload),
        processing_status="failed",
    )
    session = FakeSession(source(), records=[marking_record])

    with pytest.raises(StixImportServiceError):
        StixBundleImportService(session).import_document(
            7, approved, document, observed_at=OBSERVED
        )

    assert len(session.records) == 1
    assert session.flush_calls == 0
    assert_caller_owns_transaction(session)


def test_correctly_hashed_extra_key_cannot_authorize_existing_marking():
    marking_payload = safe_reference_payload(TLP_WHITE_ID, "marking-definition")
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": IDENTITY_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "name": "Marked identity",
        "identity_class": "organization",
        "object_marking_refs": [TLP_WHITE_ID],
    }
    approved, document = validated(
        [identity], existing={TLP_WHITE_ID: marking_payload}
    )
    marking_payload["secret"] = "must-not-authorize"
    marking_record = reference_record(
        TLP_WHITE_ID,
        "marking-definition",
        record_id=1,
        raw_payload=marking_payload,
        content_hash=canonical_safe_content_hash(marking_payload),
    )
    session = FakeSession(source(), records=[marking_record])

    with pytest.raises(StixImportServiceError, match="reference record is invalid"):
        StixBundleImportService(session).import_document(
            7, approved, document, observed_at=OBSERVED
        )

    assert session.records == [marking_record]
    assert session.indicators == session.provenances == []
    assert session.flush_calls == 0
    assert_caller_owns_transaction(session)


def test_caller_rollback_removes_atomic_object_indicator_provenance_and_relationship():
    actor = _threat_object(
        "threat-actor",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "Synthetic actor",
        aliases=["Synthetic alias"],
    )
    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": MALWARE_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "name": "Synthetic Malware Metadata",
        "is_family": False,
    }
    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": RELATIONSHIP_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "relationship_type": "uses",
        "source_ref": actor["id"],
        "target_ref": MALWARE_ID,
    }
    approved, document = validated(
        [actor, malware, indicator_object(), relationship]
    )
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(
        7, approved, document, observed_at=OBSERVED
    )
    assert result.objects_created == 4
    assert (len(session.records), len(session.indicators), len(session.provenances)) == (
        4,
        1,
        1,
    )
    assert (
        len(session.entities),
        len(session.aliases),
        len(session.threat_relationships),
    ) == (2, 1, 1)
    assert_caller_owns_transaction(session)

    session.caller_rollback()
    assert (
        session.records
        == session.indicators
        == session.provenances
        == session.entities
        == session.aliases
        == session.threat_relationships
        == []
    )


def test_import_path_performs_no_network_access(monkeypatch):
    approved, document = validated([indicator_object()])
    session = FakeSession(source())

    def blocked(*args, **kwargs):
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(httpx, "Client", blocked)
    monkeypatch.setattr(httpx, "AsyncClient", blocked)
    monkeypatch.setattr(builtins, "open", blocked)

    result = StixBundleImportService(session).import_document(
        7, approved, document, observed_at=OBSERVED
    )

    assert result.objects_created == 1


def _threat_object(stix_type, suffix, name, **changes):
    value = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": f"{stix_type}--{suffix}",
        "created": CREATED,
        "modified": MODIFIED,
        "name": name,
    }
    value.update(changes)
    return value


def test_c03a_persists_all_four_entity_types_aliases_and_exact_provenance():
    actor = _threat_object("threat-actor", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Shared Name", aliases=["  Alpha  Team ", "ALPHA TEAM"])
    campaign = _threat_object("campaign", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Shared Name")
    malware = _threat_object("malware", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "Synthetic family", is_family=True)
    technique = _threat_object("attack-pattern", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "Synthetic technique", external_references=[{"source_name": "mitre-attack", "external_id": "T1059.001"}])
    approved, document = validated([actor, campaign, malware, technique])
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(7, approved, document, observed_at=OBSERVED)

    assert result.entities_created == 4
    assert {item.entity_type for item in session.entities} == {"threat_actor", "campaign", "malware_family", "attack_technique"}
    assert len({item.identity_sha256 for item in session.entities}) == 4
    assert len(session.aliases) == 1
    assert session.aliases[0].normalized_value == "alpha team"
    assert all(item.source_id == 7 and item.source_record_id in {record.id for record in session.records} for item in session.entities)
    assert next(item for item in session.entities if item.entity_type == "attack_technique").attack_id == "T1059.001"
    assert_caller_owns_transaction(session)


def test_c03a_non_attack_pattern_is_source_record_only():
    item = _threat_object("attack-pattern", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "Unmapped pattern", external_references=[{"source_name": "example", "external_id": "X100"}])
    approved, document = validated([item])
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(7, approved, document, observed_at=OBSERVED)

    assert result.objects_created == 1
    assert result.threat_objects_unmapped == 1
    assert session.entities == []


def test_c03a_approved_relationship_is_idempotent_and_reconciles_newer_aliases():
    actor = _threat_object("threat-actor", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Actor", aliases=["Old Alias"])
    malware = _threat_object("malware", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "Family", is_family=True)
    relationship = {"type": "relationship", "spec_version": "2.1", "id": "relationship--ffffffff-ffff-4fff-8fff-ffffffffffff", "created": CREATED, "modified": MODIFIED, "relationship_type": "uses", "source_ref": actor["id"], "target_ref": malware["id"]}
    approved, document = validated([actor, malware, relationship])
    session = FakeSession(source())
    first = StixBundleImportService(session).import_document(7, approved, document, observed_at=OBSERVED)
    assert first.threat_relationships_created == 1
    assert len(session.threat_relationships) == 1

    second = StixBundleImportService(session).import_document(7, approved, document, observed_at=OBSERVED + timedelta(minutes=1))
    assert second.entities_unchanged == 2
    assert second.threat_relationships_unchanged == 1
    assert len(session.entities) == 2 and len(session.threat_relationships) == 1

    newer_actor = {**actor, "modified": "2026-07-02T11:00:00Z", "aliases": ["New Alias"]}
    _, newer_document = validated([newer_actor])
    newer = StixBundleImportService(session).import_document(7, approved, newer_document, observed_at=OBSERVED + timedelta(days=1))
    assert newer.entities_updated == 1
    assert newer.aliases_created == newer.aliases_deleted == 1
    actor_entity = next(item for item in session.entities if item.entity_type == "threat_actor")
    assert [item.normalized_value for item in actor_entity.aliases] == ["new alias"]
    assert_caller_owns_transaction(session)


def test_c03a_rejects_unsupported_normalized_relationship_combination_atomically():
    actor_a = _threat_object("threat-actor", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Actor A")
    actor_b = _threat_object("threat-actor", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Actor B")
    relationship = {"type": "relationship", "spec_version": "2.1", "id": "relationship--ffffffff-ffff-4fff-8fff-ffffffffffff", "created": CREATED, "modified": MODIFIED, "relationship_type": "uses", "source_ref": actor_a["id"], "target_ref": actor_b["id"]}
    approved, document = validated([actor_a, actor_b, relationship])
    session = FakeSession(source())

    with pytest.raises(StixImportServiceError, match="threat knowledge conflicts"):
        StixBundleImportService(session).import_document(7, approved, document, observed_at=OBSERVED)
    assert_caller_owns_transaction(session)


def test_c03a_newer_attack_pattern_cannot_remove_attack_identity():
    technique = _threat_object("attack-pattern", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "Technique", external_references=[{"source_name": "mitre-attack", "external_id": "T1059"}])
    approved, document = validated([technique])
    session = FakeSession(source())
    StixBundleImportService(session).import_document(7, approved, document, observed_at=OBSERVED)
    newer = {**technique, "modified": "2026-07-02T11:00:00Z", "external_references": [{"source_name": "example", "external_id": "X100"}]}
    _, newer_document = validated([newer])

    with pytest.raises(StixImportServiceError, match="threat knowledge conflicts"):
        StixBundleImportService(session).import_document(7, approved, newer_document, observed_at=OBSERVED + timedelta(days=1))
    assert len(session.entities) == 1
    assert session.entities[0].attack_id == "T1059"
    assert_caller_owns_transaction(session)


def _c03a_graph():
    actor = _threat_object(
        "threat-actor",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "Actor",
        aliases=["Old Alias"],
        confidence=50,
    )
    malware = _threat_object(
        "malware",
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "Family",
        is_family=True,
        confidence=40,
    )
    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--ffffffff-ffff-4fff-8fff-ffffffffffff",
        "created": CREATED,
        "modified": MODIFIED,
        "relationship_type": "uses",
        "source_ref": actor["id"],
        "target_ref": malware["id"],
        "confidence": 50,
        "start_time": "2026-07-01T10:30:00Z",
        "stop_time": "2026-07-01T10:45:00Z",
    }
    return actor, malware, relationship


def _import_c03a_graph():
    actor, malware, relationship = _c03a_graph()
    approved, document = validated([actor, malware, relationship])
    session = FakeSession(source())
    StixBundleImportService(session).import_document(
        7,
        approved,
        document,
        observed_at=OBSERVED,
    )
    return approved, session, actor, malware, relationship


@pytest.mark.parametrize(
    "mutation",
    [
        lambda entity: setattr(entity, "name", "Corrupted name"),
        lambda entity: setattr(entity, "confidence", Decimal("0.100")),
        lambda entity: setattr(entity, "revoked", True),
        lambda entity: setattr(
            entity,
            "stix_modified_at",
            datetime(2026, 7, 4, 11, tzinfo=UTC),
        ),
    ],
)
def test_c03a_newer_entity_fails_closed_when_previous_normalized_state_conflicts(
    mutation,
):
    approved, session, actor, _, _ = _import_c03a_graph()
    entity = next(item for item in session.entities if item.stix_id == actor["id"])
    mutation(entity)
    corrupted = (
        entity.name,
        entity.confidence,
        entity.stix_modified_at,
        entity.revoked,
    )
    newer_actor = {
        **actor,
        "name": "Legitimate newer actor",
        "modified": "2026-07-02T11:00:00Z",
        "confidence": 75,
    }
    _, newer_document = validated([newer_actor])

    with pytest.raises(StixImportServiceError) as caught:
        StixBundleImportService(session).import_document(
            7,
            approved,
            newer_document,
            observed_at=OBSERVED + timedelta(days=1),
        )

    assert str(caught.value) == "Validated STIX threat knowledge conflicts."
    assert (
        entity.name,
        entity.confidence,
        entity.stix_modified_at,
        entity.revoked,
    ) == corrupted
    assert_caller_owns_transaction(session)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda alias: setattr(alias, "display_value", "Corrupted display"),
        lambda alias: setattr(alias, "normalized_value", "corrupted identity"),
    ],
)
def test_c03a_newer_entity_rejects_previous_alias_display_or_set_conflict(mutation):
    approved, session, actor, _, _ = _import_c03a_graph()
    mutation(session.aliases[0])
    newer_actor = {
        **actor,
        "modified": "2026-07-02T11:00:00Z",
        "aliases": ["New Alias"],
    }
    _, newer_document = validated([newer_actor])

    with pytest.raises(StixImportServiceError) as caught:
        StixBundleImportService(session).import_document(
            7,
            approved,
            newer_document,
            observed_at=OBSERVED + timedelta(days=1),
        )

    assert str(caught.value) == "Validated STIX threat knowledge conflicts."
    assert [item.normalized_value for item in session.entities[0].aliases] != [
        "new alias"
    ]
    assert_caller_owns_transaction(session)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("confidence", Decimal("0.900")),
        ("stix_created_at", datetime(2026, 6, 30, 10, tzinfo=UTC)),
        ("stix_modified_at", datetime(2026, 7, 4, 11, tzinfo=UTC)),
        ("start_time", datetime(2026, 7, 1, 10, 31, tzinfo=UTC)),
        ("stop_time", datetime(2026, 7, 1, 10, 46, tzinfo=UTC)),
        ("revoked", True),
        ("relationship_type", "attributed-to"),
        ("source_entity_id", 2),
        ("target_entity_id", 1),
    ],
)
def test_c03a_newer_relationship_rejects_previous_normalized_state_conflict(
    field,
    value,
):
    approved, session, actor, malware, relationship = _import_c03a_graph()
    stored = session.threat_relationships[0]
    setattr(stored, field, value)
    newer_relationship = {
        **relationship,
        "modified": "2026-07-02T11:00:00Z",
        "confidence": 75,
        "stop_time": "2026-07-02T10:45:00Z",
    }
    _, newer_document = validated(
        [newer_relationship],
        existing={
            actor["id"]: session.records[0].raw_payload,
            malware["id"]: session.records[1].raw_payload,
        },
    )

    with pytest.raises(StixImportServiceError) as caught:
        StixBundleImportService(session).import_document(
            7,
            approved,
            newer_document,
            observed_at=OBSERVED + timedelta(days=1),
        )

    assert str(caught.value) == "Validated STIX threat knowledge conflicts."
    assert_caller_owns_transaction(session)


def test_c03a_synchronized_entity_aliases_and_relationship_accept_newer_versions():
    approved, session, actor, malware, relationship = _import_c03a_graph()
    newer_actor = {
        **actor,
        "name": "Updated actor",
        "modified": "2026-07-02T11:00:00Z",
        "aliases": ["New Alias"],
        "confidence": 75,
    }
    newer_relationship = {
        **relationship,
        "modified": "2026-07-02T11:00:00Z",
        "confidence": 75,
        "stop_time": "2026-07-02T10:45:00Z",
    }
    _, newer_document = validated([newer_actor, malware, newer_relationship])

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        newer_document,
        observed_at=OBSERVED + timedelta(days=1),
    )

    assert result.entities_updated == 1
    assert result.threat_relationships_updated == 1
    assert result.aliases_created == result.aliases_deleted == 1
    assert [item.normalized_value for item in session.entities[0].aliases] == [
        "new alias"
    ]
    assert session.threat_relationships[0].confidence == Decimal("0.750")
    assert_caller_owns_transaction(session)


def test_c03a_newer_relationship_cannot_remove_normalized_mapping_identity():
    approved, session, actor, _, relationship = _import_c03a_graph()
    relationship_record = next(
        item
        for item in session.records
        if item.source_external_id == relationship["id"]
    )
    previous_record_state = record_state(relationship_record)
    stored_relationship = session.threat_relationships[0]
    previous_relationship_state = (
        stored_relationship.source_id,
        stored_relationship.source_record_id,
        stored_relationship.source_entity_id,
        stored_relationship.target_entity_id,
        stored_relationship.relationship_type,
        stored_relationship.stix_id,
        stored_relationship.identity_sha256,
        stored_relationship.confidence,
        stored_relationship.stix_created_at,
        stored_relationship.stix_modified_at,
        stored_relationship.start_time,
        stored_relationship.stop_time,
        stored_relationship.revoked,
    )
    previous_record_count = len(session.records)
    previous_entity_count = len(session.entities)
    session.begin_caller_transaction()

    outside_endpoint = identity_object(
        modified="2026-07-02T11:00:00Z",
        name="Outside reduced domain",
    )
    newer_relationship = {
        **relationship,
        "modified": "2026-07-02T11:00:00Z",
        "target_ref": outside_endpoint["id"],
    }
    _, newer_document = validated(
        [outside_endpoint, newer_relationship],
        existing={actor["id"]: session.records[0].raw_payload},
    )

    with pytest.raises(StixImportServiceError) as caught:
        StixBundleImportService(session).import_document(
            7,
            approved,
            newer_document,
            observed_at=OBSERVED + timedelta(days=1),
        )

    assert str(caught.value) == "Validated STIX threat knowledge conflicts."
    assert isinstance(caught.value.__cause__, ValueError)
    assert str(caught.value.__cause__) == (
        "Threat relationship mapping identity cannot be removed."
    )
    assert relationship["id"] not in str(caught.value)
    assert outside_endpoint["id"] not in str(caught.value)
    assert len(session.entities) == previous_entity_count
    assert len(session.threat_relationships) == 1
    assert (
        stored_relationship.source_id,
        stored_relationship.source_record_id,
        stored_relationship.source_entity_id,
        stored_relationship.target_entity_id,
        stored_relationship.relationship_type,
        stored_relationship.stix_id,
        stored_relationship.identity_sha256,
        stored_relationship.confidence,
        stored_relationship.stix_created_at,
        stored_relationship.stix_modified_at,
        stored_relationship.start_time,
        stored_relationship.stop_time,
        stored_relationship.revoked,
    ) == previous_relationship_state
    assert len(session.records) == previous_record_count + 1
    assert record_state(relationship_record) != previous_record_state
    assert_caller_owns_transaction(session)

    session.caller_rollback()

    restored_record = next(
        item
        for item in session.records
        if item.source_external_id == relationship["id"]
    )
    restored_relationship = session.threat_relationships[0]
    assert len(session.records) == previous_record_count
    assert record_state(restored_record) == previous_record_state
    assert len(session.entities) == previous_entity_count
    assert (
        restored_relationship.source_id,
        restored_relationship.source_record_id,
        restored_relationship.source_entity_id,
        restored_relationship.target_entity_id,
        restored_relationship.relationship_type,
        restored_relationship.stix_id,
        restored_relationship.identity_sha256,
        restored_relationship.confidence,
        restored_relationship.stix_created_at,
        restored_relationship.stix_modified_at,
        restored_relationship.start_time,
        restored_relationship.stop_time,
        restored_relationship.revoked,
    ) == previous_relationship_state


def test_c03a_pre_c03_source_record_materializes_missing_normalized_entity():
    actor, _, _ = _c03a_graph()
    approved, document = validated([actor])
    record = current_record(document.objects[0])
    session = FakeSession(source(), records=[record])

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        document,
        observed_at=OBSERVED + timedelta(minutes=1),
    )

    assert result.objects_unchanged == 1
    assert result.entities_created == 1
    assert len(session.entities) == len(session.aliases) == 1
    assert session.entities[0].source_record_id == record.id
    assert_caller_owns_transaction(session)


def test_c03a_relationship_materializes_missing_same_source_normalized_endpoints():
    actor, malware, relationship = _c03a_graph()
    _, endpoint_document = validated([actor, malware])
    endpoint_payloads = {
        item.stix_id: thaw_json(item.safe_payload)
        for item in endpoint_document.objects
    }
    approved, relationship_document = validated(
        [relationship],
        existing=endpoint_payloads,
    )
    records = [
        current_record(endpoint_document.objects[0], id=1),
        current_record(endpoint_document.objects[1], id=2),
    ]
    session = FakeSession(source(), records=records)

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        relationship_document,
        observed_at=OBSERVED + timedelta(minutes=1),
    )

    assert result.entities_created == 2
    assert result.threat_relationships_created == 1
    assert {item.stix_id for item in session.entities} == {
        actor["id"],
        malware["id"],
    }
    assert_caller_owns_transaction(session)


def test_c03a_one_sided_and_outside_domain_relationships_remain_source_record_only():
    actor, _, _ = _c03a_graph()
    identity_a = identity_object()
    identity_b = {
        **identity_object(name="Other identity"),
        "id": OTHER_IDENTITY_ID,
    }
    one_sided = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": RELATIONSHIP_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "relationship_type": "related-to",
        "source_ref": actor["id"],
        "target_ref": identity_a["id"],
    }
    outside_domain = {
        **one_sided,
        "id": "relationship--34343434-3434-4434-8434-343434343434",
        "source_ref": identity_a["id"],
        "target_ref": identity_b["id"],
    }
    approved, document = validated(
        [actor, identity_a, identity_b, one_sided, outside_domain]
    )
    session = FakeSession(source())

    result = StixBundleImportService(session).import_document(
        7,
        approved,
        document,
        observed_at=OBSERVED,
    )

    assert result.threat_relationships_unmapped == 2
    assert len(session.records) == 5
    assert len(session.entities) == 1
    assert session.threat_relationships == []
    assert_caller_owns_transaction(session)


def test_c05_intrusion_set_maps_to_existing_threat_actor_lifecycle():
    raw = json.dumps(
        {
            "objects": [
                {
                    "type": "intrusion-set",
                    "spec_version": "2.1",
                    "id": "intrusion-set--dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                    "created": CREATED,
                    "modified": MODIFIED,
                    "name": "Synthetic Enterprise Group",
                    "x_mitre_domains": ["enterprise-attack"],
                    "x_mitre_deprecated": True,
                }
            ],
        }
    ).encode()
    bounded = parse_stix_json_bytes(
        raw,
        MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
        StixDocumentFormat.TAXII_ENVELOPE,
    )
    document = validate_stix_document(
        bounded,
        MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
    )
    value = map_threat_entity(document.objects[0].safe_payload)
    assert value is not None
    assert value.entity_type == "threat_actor"
    assert value.revoked is True
    assert document.objects[0].safe_payload["source_revoked"] is False
    assert document.objects[0].safe_payload["x_mitre_deprecated"] is True


MITRE_INTRUSION_ID = "intrusion-set--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
MITRE_MALWARE_ID = "malware--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
MITRE_RELATIONSHIP_ID = "relationship--cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _mitre_objects():
    intrusion = {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": MITRE_INTRUSION_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "name": "Synthetic Enterprise Group",
        "x_mitre_domains": ["enterprise-attack"],
    }
    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": MITRE_MALWARE_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "name": "Synthetic Enterprise Malware",
        "is_family": True,
        "x_mitre_domains": ["enterprise-attack"],
    }
    relationship = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": MITRE_RELATIONSHIP_ID,
        "created": CREATED,
        "modified": MODIFIED,
        "relationship_type": "uses",
        "source_ref": MITRE_INTRUSION_ID,
        "target_ref": MITRE_MALWARE_ID,
        "x_mitre_domains": ["enterprise-attack"],
    }
    return intrusion, malware, relationship


def _mitre_validated(objects, *, allow_unresolved=False):
    bounded = parse_stix_json_bytes(
        json.dumps({"objects": objects}).encode(),
        MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
        StixDocumentFormat.TAXII_ENVELOPE,
    )
    return validate_stix_document(
        bounded,
        MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
        allow_unresolved_relationships=allow_unresolved,
    )


def _mitre_source():
    return IntelligenceSource(
        id=17,
        name="MITRE ATT&CK Enterprise",
        slug="mitre-attack-enterprise",
        source_type="json",
        base_url=MITRE_ATTACK_ENTERPRISE_STIX_POLICY.policy_base_url + "/",
        is_enabled=False,
    )


def _mitre_record(staged, record_id):
    payload = thaw_json(staged.safe_payload)
    source_url = MITRE_ATTACK_ENTERPRISE_STIX_POLICY.object_url(staged.stix_id)
    return SourceRecord(
        id=record_id,
        source_id=17,
        intelligence_item_id=None,
        source_external_id=staged.stix_id,
        source_url=source_url,
        canonical_url_hash=sha256(
            f"mitre-attack-enterprise\0{source_url}".encode("utf-8")
        ).hexdigest(),
        content_hash=canonical_safe_content_hash(payload),
        is_primary_reference=False,
        raw_payload=payload,
        payload_collected_at=OBSERVED,
        first_seen_at=OBSERVED,
        last_seen_at=OBSERVED,
        source_published_at=staged.created,
        source_modified_at=staged.modified,
        processing_status="processed",
        last_processed_at=OBSERVED,
        safe_error_summary=None,
        upstream_status="present",
    )


def _mitre_incremental_setup():
    intrusion, malware, relationship = _mitre_objects()
    endpoints = _mitre_validated([intrusion, malware])
    relationship_only = _mitre_validated(
        [relationship],
        allow_unresolved=True,
    )
    records = [
        _mitre_record(endpoints.objects[0], 1),
        _mitre_record(endpoints.objects[1], 2),
    ]
    return relationship_only, records


def test_c05_relationship_only_increment_resolves_revalidated_same_source_endpoints_idempotently():
    document, records = _mitre_incremental_setup()
    session = FakeSession(_mitre_source(), records=records)
    service = StixBundleImportService(session)

    first = service.import_document(
        17,
        MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
        document,
        observed_at=OBSERVED,
    )
    second = service.import_document(
        17,
        MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
        document,
        observed_at=OBSERVED + timedelta(minutes=1),
    )

    assert first.objects_created == 1
    assert first.entities_created == 2
    assert first.threat_relationships_created == 1
    assert second.objects_unchanged == 1
    assert second.entities_unchanged == 0
    assert second.threat_relationships_unchanged == 1
    assert len(session.records) == 3
    assert len(session.entities) == 2
    assert len(session.threat_relationships) == 1
    assert session.execute_calls >= 6
    assert_caller_owns_transaction(session)


@pytest.mark.parametrize(
    "corruption",
    (
        "missing",
        "conflicting",
        "malformed_payload",
        "hash_inconsistent",
        "corrupt_status",
    ),
)
def test_c05_relationship_only_increment_fails_closed_for_invalid_stored_endpoint(
    corruption,
):
    document, records = _mitre_incremental_setup()
    if corruption == "missing":
        records.pop()
    elif corruption == "conflicting":
        records[1].canonical_url_hash = "0" * 64
    elif corruption == "malformed_payload":
        records[1].raw_payload = {
            "type": "malware",
            "id": MITRE_MALWARE_ID,
            "spec_version": "2.1",
        }
        records[1].content_hash = canonical_safe_content_hash(
            records[1].raw_payload
        )
    elif corruption == "hash_inconsistent":
        records[1].content_hash = "0" * 64
    elif corruption == "corrupt_status":
        records[1].processing_status = "failed"
    session = FakeSession(_mitre_source(), records=records)
    before = [record_state(record) for record in session.records]
    session.begin_caller_transaction()

    with pytest.raises(StixImportServiceError) as caught:
        StixBundleImportService(session).import_document(
            17,
            MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
            document,
            observed_at=OBSERVED + timedelta(minutes=1),
        )

    assert str(caught.value) == "Existing STIX reference record is invalid."
    assert "malware--" not in str(caught.value)
    session.caller_rollback()
    assert [record_state(record) for record in session.records] == before
    assert session.entities == []
    assert session.threat_relationships == []
    assert_caller_owns_transaction(session)
