"""Fail-closed mapping and persistence for the reduced STIX threat domain."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
import re
import unicodedata
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import SourceRecord, ThreatEntity, ThreatEntityAlias, ThreatRelationship


ENTITY_TYPE_BY_STIX = {
    "threat-actor": "threat_actor",
    "intrusion-set": "threat_actor",
    "campaign": "campaign",
    "malware": "malware_family",
    "attack-pattern": "attack_technique",
}
APPROVED_RELATIONSHIPS = frozenset(
    {
        ("threat_actor", "uses", "malware_family"),
        ("threat_actor", "uses", "attack_technique"),
        ("campaign", "uses", "malware_family"),
        ("campaign", "uses", "attack_technique"),
        ("malware_family", "uses", "attack_technique"),
        ("campaign", "attributed-to", "threat_actor"),
    }
)
_ATTACK_ID_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")


class ThreatKnowledgeError(ValueError):
    """A safe threat mapping or persistence invariant failed."""


@dataclass(frozen=True, slots=True)
class ThreatEntityValue:
    entity_type: str
    stix_id: str
    name: str
    attack_id: str | None
    confidence: Decimal | None
    created: datetime
    modified: datetime
    revoked: bool
    aliases: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class ThreatRelationshipValue:
    relationship_type: str
    stix_id: str
    source_ref: str
    target_ref: str
    confidence: Decimal | None
    created: datetime
    modified: datetime
    start: datetime | None
    stop: datetime | None
    revoked: bool


@dataclass(slots=True)
class ThreatKnowledgeCounts:
    entities_created: int = 0
    entities_updated: int = 0
    entities_unchanged: int = 0
    aliases_created: int = 0
    aliases_updated: int = 0
    aliases_deleted: int = 0
    aliases_unchanged: int = 0
    relationships_created: int = 0
    relationships_updated: int = 0
    relationships_unchanged: int = 0
    threat_objects_unmapped: int = 0
    threat_relationships_unmapped: int = 0


def source_stix_identity(source_slug: str, stix_id: str) -> str:
    """Hash only the approved source identity and canonical STIX identity."""

    return sha256(f"{source_slug}\x00{stix_id}".encode("utf-8")).hexdigest()


def normalize_alias(value: str) -> tuple[str, str]:
    """Return bounded display text and its deterministic case-insensitive identity."""

    if not isinstance(value, str):
        raise ThreatKnowledgeError("Threat alias is invalid.")
    display = " ".join(unicodedata.normalize("NFC", value).split())
    normalized = " ".join(unicodedata.normalize("NFKC", value).split()).casefold()
    if not display or not normalized or len(display) > 500 or len(normalized) > 500:
        raise ThreatKnowledgeError("Threat alias is invalid.")
    return display, normalized


def map_threat_entity(payload: Mapping[str, object]) -> ThreatEntityValue | None:
    stix_type = payload.get("type")
    entity_type = ENTITY_TYPE_BY_STIX.get(stix_type) if isinstance(stix_type, str) else None
    if entity_type is None:
        return None
    stix_id = payload.get("id")
    name = payload.get("name")
    if not isinstance(stix_id, str) or not isinstance(name, str):
        raise ThreatKnowledgeError("Threat entity metadata is invalid.")
    canonical_name = " ".join(unicodedata.normalize("NFC", name).split())
    if not canonical_name or len(canonical_name) > 500:
        raise ThreatKnowledgeError("Threat entity name is invalid.")
    attack_id = _attack_id(payload) if stix_type == "attack-pattern" else None
    if stix_type == "attack-pattern" and attack_id is None:
        return None
    aliases_by_identity: dict[str, str] = {}
    raw_aliases = payload.get("aliases", ())
    if not isinstance(raw_aliases, (list, tuple)):
        raise ThreatKnowledgeError("Threat aliases are invalid.")
    for raw_alias in raw_aliases:
        display, normalized = normalize_alias(raw_alias)  # type: ignore[arg-type]
        current_display = aliases_by_identity.get(normalized)
        aliases_by_identity[normalized] = (
            display if current_display is None else min(current_display, display)
        )
    confidence_value = payload.get("confidence")
    if confidence_value is not None and (type(confidence_value) is not int or not 0 <= confidence_value <= 100):
        raise ThreatKnowledgeError("Threat confidence is invalid.")
    confidence = None if confidence_value is None else Decimal(confidence_value).scaleb(-2).quantize(Decimal("0.001"))
    created = _timestamp(payload.get("created"))
    modified = _timestamp(payload.get("modified"))
    if modified < created:
        raise ThreatKnowledgeError("Threat entity timestamps are invalid.")
    revoked = payload.get("revoked", False)
    if type(revoked) is not bool:
        raise ThreatKnowledgeError("Threat revocation state is invalid.")
    return ThreatEntityValue(
        entity_type=entity_type,
        stix_id=stix_id,
        name=canonical_name,
        attack_id=attack_id,
        confidence=confidence,
        created=created,
        modified=modified,
        revoked=revoked,
        aliases=tuple((display, identity) for identity, display in sorted(aliases_by_identity.items())),
    )


def map_threat_relationship(
    payload: Mapping[str, object],
) -> ThreatRelationshipValue:
    relationship_type = payload.get("relationship_type")
    stix_id = payload.get("id")
    source_ref = payload.get("source_ref")
    target_ref = payload.get("target_ref")
    if not all(
        isinstance(value, str)
        for value in (relationship_type, stix_id, source_ref, target_ref)
    ):
        raise ThreatKnowledgeError("Threat relationship metadata is invalid.")
    created = _timestamp(payload.get("created"))
    modified = _timestamp(payload.get("modified"))
    start = _optional_timestamp(payload.get("start_time"))
    stop = _optional_timestamp(payload.get("stop_time"))
    if modified < created or start is not None and stop is not None and stop < start:
        raise ThreatKnowledgeError("Threat relationship timestamps are invalid.")
    confidence_value = payload.get("confidence")
    if confidence_value is not None and (
        type(confidence_value) is not int or not 0 <= confidence_value <= 100
    ):
        raise ThreatKnowledgeError("Threat relationship confidence is invalid.")
    confidence = (
        None
        if confidence_value is None
        else Decimal(confidence_value).scaleb(-2).quantize(Decimal("0.001"))
    )
    revoked = payload.get("revoked", False)
    if type(revoked) is not bool:
        raise ThreatKnowledgeError("Threat relationship revocation state is invalid.")
    assert isinstance(relationship_type, str)
    assert isinstance(stix_id, str)
    assert isinstance(source_ref, str)
    assert isinstance(target_ref, str)
    return ThreatRelationshipValue(
        relationship_type=relationship_type,
        stix_id=stix_id,
        source_ref=source_ref,
        target_ref=target_ref,
        confidence=confidence,
        created=created,
        modified=modified,
        start=start,
        stop=stop,
        revoked=revoked,
    )


class ThreatKnowledgeWriter:
    """Persist reduced knowledge inside the caller-owned SQLAlchemy transaction."""

    def __init__(self, session: Session, source_id: int, source_slug: str, counts: ThreatKnowledgeCounts) -> None:
        self.session = session
        self.source_id = source_id
        self.source_slug = source_slug
        self.counts = counts

    def upsert_entity(
        self,
        record: SourceRecord,
        payload: Mapping[str, object],
        action: str,
        *,
        previous_payload: Mapping[str, object] | None = None,
    ) -> ThreatEntity | None:
        if action not in {"created", "updated", "unchanged"}:
            raise ThreatKnowledgeError("Threat entity persistence action is invalid.")
        value = map_threat_entity(payload)
        if value is None:
            if payload.get("type") in ENTITY_TYPE_BY_STIX:
                self.counts.threat_objects_unmapped += 1
                stix_id = payload.get("id")
                if isinstance(stix_id, str) and self.find_entity(stix_id) is not None:
                    raise ThreatKnowledgeError(
                        "Threat entity mapping identity cannot be removed."
                    )
            return None
        if (
            record.source_id != self.source_id
            or record.source_external_id != value.stix_id
        ):
            raise ThreatKnowledgeError("Threat entity SourceRecord provenance conflicts.")
        entity = self.session.execute(select(ThreatEntity).where(ThreatEntity.source_id == self.source_id, ThreatEntity.stix_id == value.stix_id)).scalar_one_or_none()
        identity = source_stix_identity(self.source_slug, value.stix_id)
        created_entity = entity is None
        if entity is None:
            entity = ThreatEntity(source_id=self.source_id, source_record_id=record.id, entity_type=value.entity_type, stix_id=value.stix_id, identity_sha256=identity, name=value.name, attack_id=value.attack_id, confidence=value.confidence, stix_created_at=value.created, stix_modified_at=value.modified, revoked=value.revoked)
            self.session.add(entity)
            self.session.flush()
            self.counts.entities_created += 1
        else:
            if previous_payload is None:
                raise ThreatKnowledgeError(
                    "Existing threat entity has no validated previous state."
                )
            self._assert_previous_entity_state(entity, record, previous_payload)
            if (entity.source_record_id != record.id or entity.entity_type != value.entity_type or entity.identity_sha256 != identity or entity.attack_id != value.attack_id or _utc(entity.stix_created_at) != value.created):
                raise ThreatKnowledgeError("Threat entity identity or provenance conflicts.")
            current = (entity.name, entity.confidence, _utc(entity.stix_modified_at), entity.revoked)
            desired = (value.name, value.confidence, value.modified, value.revoked)
            if action == "unchanged" and current != desired:
                raise ThreatKnowledgeError("Unchanged threat entity state conflicts.")
            if action == "updated":
                if entity.revoked and not value.revoked:
                    raise ThreatKnowledgeError("A revoked threat entity cannot be reactivated.")
                entity.name, entity.confidence, entity.stix_modified_at, entity.revoked = desired
                self.counts.entities_updated += 1
            else:
                self.counts.entities_unchanged += 1
        self._reconcile_aliases(entity, value.aliases, allow_change=action != "unchanged" or created_entity)
        return entity

    def upsert_relationship(
        self,
        record: SourceRecord,
        payload: Mapping[str, object],
        source_entity: ThreatEntity,
        target_entity: ThreatEntity,
        action: str,
        *,
        previous_payload: Mapping[str, object] | None = None,
    ) -> ThreatRelationship:
        if action not in {"created", "updated", "unchanged"}:
            raise ThreatKnowledgeError("Threat relationship persistence action is invalid.")
        value = map_threat_relationship(payload)
        combination = (
            source_entity.entity_type,
            value.relationship_type,
            target_entity.entity_type,
        )
        if (
            record.source_id != self.source_id
            or record.source_external_id != value.stix_id
            or source_entity.source_id != self.source_id
            or target_entity.source_id != self.source_id
            or value.source_ref != source_entity.stix_id
            or value.target_ref != target_entity.stix_id
        ):
            raise ThreatKnowledgeError("Threat relationship provenance conflicts.")
        if combination not in APPROVED_RELATIONSHIPS:
            raise ThreatKnowledgeError("Threat relationship combination is not approved.")
        if source_entity.id == target_entity.id:
            raise ThreatKnowledgeError("Threat relationship self-reference is not approved.")
        relationship = self.session.execute(select(ThreatRelationship).where(ThreatRelationship.source_id == self.source_id, ThreatRelationship.stix_id == value.stix_id)).scalar_one_or_none()
        identity = source_stix_identity(self.source_slug, value.stix_id)
        values = (source_entity.id, target_entity.id, value.relationship_type, value.confidence, value.modified, value.start, value.stop, value.revoked)
        if relationship is None:
            relationship = ThreatRelationship(source_id=self.source_id, source_record_id=record.id, source_entity_id=source_entity.id, target_entity_id=target_entity.id, relationship_type=value.relationship_type, stix_id=value.stix_id, identity_sha256=identity, confidence=value.confidence, stix_created_at=value.created, stix_modified_at=value.modified, start_time=value.start, stop_time=value.stop, revoked=value.revoked)
            self.session.add(relationship)
            self.counts.relationships_created += 1
        else:
            if previous_payload is None:
                raise ThreatKnowledgeError(
                    "Existing threat relationship has no validated previous state."
                )
            self._assert_previous_relationship_state(
                relationship,
                record,
                previous_payload,
            )
            if relationship.source_record_id != record.id or relationship.identity_sha256 != identity or _utc(relationship.stix_created_at) != value.created or (relationship.source_entity_id, relationship.target_entity_id, relationship.relationship_type) != values[:3]:
                raise ThreatKnowledgeError("Threat relationship identity or provenance conflicts.")
            current = (relationship.source_entity_id, relationship.target_entity_id, relationship.relationship_type, relationship.confidence, _utc(relationship.stix_modified_at), _optional_utc(relationship.start_time), _optional_utc(relationship.stop_time), relationship.revoked)
            desired = values
            if action == "unchanged" and current != desired:
                raise ThreatKnowledgeError("Unchanged threat relationship state conflicts.")
            if action == "updated":
                if relationship.revoked and value.revoked is not True:
                    raise ThreatKnowledgeError("A revoked threat relationship cannot be reactivated.")
                relationship.confidence, relationship.stix_modified_at, relationship.start_time, relationship.stop_time, relationship.revoked = value.confidence, value.modified, value.start, value.stop, value.revoked
                self.counts.relationships_updated += 1
            else:
                self.counts.relationships_unchanged += 1
        return relationship

    def find_entity(self, stix_id: str) -> ThreatEntity | None:
        return self.session.execute(select(ThreatEntity).where(ThreatEntity.source_id == self.source_id, ThreatEntity.stix_id == stix_id)).scalar_one_or_none()

    def find_relationship(self, stix_id: str) -> ThreatRelationship | None:
        return self.session.execute(
            select(ThreatRelationship).where(
                ThreatRelationship.source_id == self.source_id,
                ThreatRelationship.stix_id == stix_id,
            )
        ).scalar_one_or_none()

    def _assert_previous_entity_state(
        self,
        entity: ThreatEntity,
        record: SourceRecord,
        previous_payload: Mapping[str, object],
    ) -> None:
        previous = map_threat_entity(previous_payload)
        if previous is None:
            raise ThreatKnowledgeError("Previous threat entity state is invalid.")
        current = (
            entity.source_id,
            entity.source_record_id,
            entity.entity_type,
            entity.stix_id,
            entity.identity_sha256,
            entity.name,
            entity.attack_id,
            entity.confidence,
            _utc(entity.stix_created_at),
            _utc(entity.stix_modified_at),
            entity.revoked,
        )
        expected = (
            self.source_id,
            record.id,
            previous.entity_type,
            previous.stix_id,
            source_stix_identity(self.source_slug, previous.stix_id),
            previous.name,
            previous.attack_id,
            previous.confidence,
            previous.created,
            previous.modified,
            previous.revoked,
        )
        if current != expected:
            raise ThreatKnowledgeError(
                "Normalized threat entity conflicts with its previous source state."
            )
        aliases = list(
            self.session.execute(
                select(ThreatEntityAlias).where(
                    ThreatEntityAlias.threat_entity_id == entity.id
                )
            ).scalars()
        )
        current_aliases: list[tuple[str, str]] = []
        for alias in aliases:
            if (
                alias.threat_entity_id != entity.id
                or alias.source_id != self.source_id
                or alias.source_record_id != record.id
            ):
                raise ThreatKnowledgeError(
                    "Normalized threat aliases conflict with their previous source state."
                )
            current_aliases.append((alias.display_value, alias.normalized_value))
        current_aliases.sort(key=lambda item: item[1])
        if tuple(current_aliases) != previous.aliases:
            raise ThreatKnowledgeError(
                "Normalized threat aliases conflict with their previous source state."
            )

    def _assert_previous_relationship_state(
        self,
        relationship: ThreatRelationship,
        record: SourceRecord,
        previous_payload: Mapping[str, object],
    ) -> None:
        previous = map_threat_relationship(previous_payload)
        source_entity = self.session.execute(
            select(ThreatEntity).where(
                ThreatEntity.id == relationship.source_entity_id
            )
        ).scalar_one_or_none()
        target_entity = self.session.execute(
            select(ThreatEntity).where(
                ThreatEntity.id == relationship.target_entity_id
            )
        ).scalar_one_or_none()
        if source_entity is None or target_entity is None:
            raise ThreatKnowledgeError(
                "Normalized threat relationship endpoints are invalid."
            )
        current = (
            relationship.source_id,
            relationship.source_record_id,
            relationship.stix_id,
            relationship.identity_sha256,
            relationship.relationship_type,
            source_entity.source_id,
            source_entity.stix_id,
            target_entity.source_id,
            target_entity.stix_id,
            relationship.confidence,
            _utc(relationship.stix_created_at),
            _utc(relationship.stix_modified_at),
            _optional_utc(relationship.start_time),
            _optional_utc(relationship.stop_time),
            relationship.revoked,
        )
        expected = (
            self.source_id,
            record.id,
            previous.stix_id,
            source_stix_identity(self.source_slug, previous.stix_id),
            previous.relationship_type,
            self.source_id,
            previous.source_ref,
            self.source_id,
            previous.target_ref,
            previous.confidence,
            previous.created,
            previous.modified,
            previous.start,
            previous.stop,
            previous.revoked,
        )
        if current != expected:
            raise ThreatKnowledgeError(
                "Normalized threat relationship conflicts with its previous source state."
            )

    def _reconcile_aliases(self, entity: ThreatEntity, desired_values: tuple[tuple[str, str], ...], *, allow_change: bool) -> None:
        existing = {item.normalized_value: item for item in self.session.execute(select(ThreatEntityAlias).where(ThreatEntityAlias.threat_entity_id == entity.id)).scalars()}
        desired = {identity: display for display, identity in desired_values}
        if not allow_change and ({key: item.display_value for key, item in existing.items()} != desired):
            raise ThreatKnowledgeError("Unchanged threat aliases conflict.")
        for identity, display in desired.items():
            alias = existing.pop(identity, None)
            if alias is None:
                self.session.add(ThreatEntityAlias(entity=entity, threat_entity_id=entity.id, source_id=entity.source_id, source_record_id=entity.source_record_id, display_value=display, normalized_value=identity))
                self.counts.aliases_created += 1
            elif alias.display_value != display:
                alias.display_value = display
                self.counts.aliases_updated += 1
            else:
                self.counts.aliases_unchanged += 1
        for alias in existing.values():
            entity.aliases.remove(alias)
            self.counts.aliases_deleted += 1


def _attack_id(payload: Mapping[str, object]) -> str | None:
    references = payload.get("external_references", ())
    if not isinstance(references, (list, tuple)):
        raise ThreatKnowledgeError("ATT&CK references are invalid.")
    mitre_references = [
        reference
        for reference in references
        if isinstance(reference, Mapping)
        and reference.get("source_name") == "mitre-attack"
    ]
    if len(mitre_references) > 1:
        raise ThreatKnowledgeError("Conflicting MITRE ATT&CK identifiers are not approved.")
    if not mitre_references:
        return None
    external_id = mitre_references[0].get("external_id")
    return (
        external_id
        if isinstance(external_id, str) and _ATTACK_ID_RE.fullmatch(external_id)
        else None
    )


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ThreatKnowledgeError("Required STIX timestamp is invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ThreatKnowledgeError("Required STIX timestamp is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ThreatKnowledgeError("Required STIX timestamp is invalid.")
    return parsed.astimezone(UTC)


def _optional_timestamp(value: object) -> datetime | None:
    return None if value is None else _timestamp(value)


def _utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ThreatKnowledgeError("Stored threat timestamp is invalid.")
    return value.astimezone(UTC)


def _optional_utc(value: datetime | None) -> datetime | None:
    return None if value is None else _utc(value)


__all__ = ["APPROVED_RELATIONSHIPS", "ENTITY_TYPE_BY_STIX", "ThreatEntityValue", "ThreatKnowledgeCounts", "ThreatKnowledgeError", "ThreatKnowledgeWriter", "map_threat_entity", "normalize_alias", "source_stix_identity"]
