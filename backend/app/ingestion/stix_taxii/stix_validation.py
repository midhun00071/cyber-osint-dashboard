"""Whole-document STIX 2.1 validation and safe staging."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
import re
from types import MappingProxyType
from typing import Mapping
import unicodedata
from urllib.parse import urlsplit
from uuid import UUID

from stix2 import parse as parse_stix
from stix2patterns.validator import run_validator

from app.indicators.value_normalization import IndicatorValueError, normalize_observable
from app.ingestion.stix_taxii.bounded_json import BoundedStixDocument, thaw_json
from app.ingestion.stix_taxii.object_mapping import (
    StagedStixObject,
    StixMappedObservable,
    StixObjectMappingError,
    canonical_safe_content_hash,
    direct_observables,
    freeze_mapping,
    indicator_pattern_observable,
    safe_payload_observables,
)
from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    validate_stix_source_policy,
)


_ID_RE = re.compile(r"^(?P<type>[a-z0-9-]+)--(?P<uuid>[0-9a-fA-F-]{36})$")
_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_SOURCE_NAME_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_EXTERNAL_ID_RE = re.compile(r"^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$")
_STANDARD_TLP = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "white",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}
_VERSIONED_TYPES = frozenset(
    {
        "identity",
        "indicator",
        "relationship",
        "attack-pattern",
        "campaign",
        "malware",
        "intrusion-set",
        "threat-actor",
    }
)
_BASE_SAFE_KEYS = frozenset({"type", "id", "spec_version"})
_VERSIONED_SAFE_KEYS = frozenset(
    {
        "created",
        "modified",
        "revoked",
        "source_revoked",
        "x_mitre_deprecated",
        "confidence",
        "created_by_ref",
        "object_marking_refs",
        "labels",
        "external_references",
    }
)
_SAFE_KEYS_BY_TYPE = {
    "marking-definition": _BASE_SAFE_KEYS
    | {"created", "created_by_ref", "marking_type", "marking_level", "statement"},
    "identity": _BASE_SAFE_KEYS
    | _VERSIONED_SAFE_KEYS
    | {"name", "identity_class", "sectors"},
    "indicator": _BASE_SAFE_KEYS
    | _VERSIONED_SAFE_KEYS
    | {
        "name",
        "pattern",
        "pattern_type",
        "pattern_version",
        "indicator_types",
        "valid_from",
        "valid_until",
        "kill_chain_phases",
        "mapped_observables",
    },
    "relationship": _BASE_SAFE_KEYS
    | _VERSIONED_SAFE_KEYS
    | {"relationship_type", "source_ref", "target_ref", "start_time", "stop_time"},
    "attack-pattern": _BASE_SAFE_KEYS | _VERSIONED_SAFE_KEYS | {"name", "aliases"},
    "campaign": _BASE_SAFE_KEYS | _VERSIONED_SAFE_KEYS | {"name", "aliases"},
    "malware": _BASE_SAFE_KEYS | _VERSIONED_SAFE_KEYS | {"name", "aliases"},
    "intrusion-set": _BASE_SAFE_KEYS | _VERSIONED_SAFE_KEYS | {"name", "aliases"},
    "threat-actor": _BASE_SAFE_KEYS | _VERSIONED_SAFE_KEYS | {"name", "aliases"},
    "ipv4-addr": _BASE_SAFE_KEYS | {"object_marking_refs", "observable", "mapped_observables"},
    "ipv6-addr": _BASE_SAFE_KEYS | {"object_marking_refs", "observable", "mapped_observables"},
    "domain-name": _BASE_SAFE_KEYS | {"object_marking_refs", "observable", "mapped_observables"},
    "url": _BASE_SAFE_KEYS | {"object_marking_refs", "observable", "mapped_observables"},
    "file": _BASE_SAFE_KEYS | {"object_marking_refs", "hashes", "mapped_observables"},
}
_REQUIRED_SAFE_KEYS_BY_TYPE = {
    "marking-definition": _BASE_SAFE_KEYS | {"created", "marking_type"},
    "identity": _BASE_SAFE_KEYS | {"created", "modified", "name", "identity_class"},
    "indicator": _BASE_SAFE_KEYS
    | {"created", "modified", "pattern", "pattern_type", "pattern_version", "valid_from", "mapped_observables"},
    "relationship": _BASE_SAFE_KEYS
    | {"created", "modified", "relationship_type", "source_ref", "target_ref"},
    "attack-pattern": _BASE_SAFE_KEYS | {"created", "modified", "name"},
    "campaign": _BASE_SAFE_KEYS | {"created", "modified", "name"},
    "malware": _BASE_SAFE_KEYS | {"created", "modified", "name"},
    "intrusion-set": _BASE_SAFE_KEYS | {"created", "modified", "name"},
    "threat-actor": _BASE_SAFE_KEYS | {"created", "modified", "name"},
    "ipv4-addr": _BASE_SAFE_KEYS | {"observable", "mapped_observables"},
    "ipv6-addr": _BASE_SAFE_KEYS | {"observable", "mapped_observables"},
    "domain-name": _BASE_SAFE_KEYS | {"observable", "mapped_observables"},
    "url": _BASE_SAFE_KEYS | {"observable", "mapped_observables"},
    "file": _BASE_SAFE_KEYS | {"hashes", "mapped_observables"},
}


class StixValidationError(ValueError):
    """A STIX document failed sanitized whole-document validation."""


class ExistingStixReferenceUse(str, Enum):
    """Approved use of an existing bounded safe STIX payload."""

    RELATIONSHIP_TARGET = "relationship_target"
    OBJECT_MARKING = "object_marking"


@dataclass(frozen=True, slots=True)
class ValidatedStixDocument:
    """Latest safe version of every validated object plus bounded counters."""

    objects: tuple[StagedStixObject, ...]
    validated_versions: tuple[StagedStixObject, ...]
    objects_received: int
    objects_validated: int
    relationships_validated: int
    markings_validated: int
    relationships_excluded: int = 0


def validate_existing_safe_payload(
    expected_stix_id: str,
    payload: object,
    policy: ApprovedStixSourcePolicy,
    expected_use: ExistingStixReferenceUse,
) -> Mapping[str, object]:
    """Revalidate and minimize an untrusted existing P9-10 safe payload."""

    safe_payload = validate_canonical_safe_payload(
        expected_stix_id,
        payload,
        policy,
    )
    stix_type = safe_payload["type"]
    assert isinstance(stix_type, str)
    try:
        use = (
            expected_use
            if isinstance(expected_use, ExistingStixReferenceUse)
            else ExistingStixReferenceUse(expected_use)
        )
    except (TypeError, ValueError) as exc:
        raise StixValidationError("Existing STIX reference use is invalid.") from exc

    safe: dict[str, object] = {
        "type": stix_type,
        "id": expected_stix_id,
        "spec_version": "2.1",
    }
    if use is ExistingStixReferenceUse.RELATIONSHIP_TARGET:
        if stix_type in {"marking-definition", "relationship"}:
            raise StixValidationError("Existing STIX relationship target is invalid.")
    else:
        if stix_type != "marking-definition":
            raise StixValidationError("Existing STIX marking is invalid.")
        marking_type = safe_payload.get("marking_type")
        if marking_type == "tlp":
            level = _bounded_text(safe_payload.get("marking_level"), 20, "marking level")
            expected_level = _STANDARD_TLP.get(expected_stix_id)
            if expected_level != level or level not in policy.allowed_tlp_levels:
                raise StixValidationError("Existing STIX TLP marking is not approved.")
            safe.update(marking_type="tlp", marking_level=level)
        elif marking_type == "statement":
            if not policy.allow_statement_markings:
                raise StixValidationError("Existing STIX statement marking is disabled.")
            statement = _bounded_text(safe_payload.get("statement"), 1000, "statement")
            if not statement.strip() or statement != " ".join(statement.split()):
                raise StixValidationError("Existing STIX statement marking is invalid.")
            safe.update(marking_type="statement", statement=statement)
        else:
            raise StixValidationError("Existing STIX marking is invalid.")
    return MappingProxyType(safe)


def validate_canonical_safe_payload(
    expected_stix_id: str,
    payload: object,
    policy: ApprovedStixSourcePolicy,
    *,
    expected_stix_type: str | None = None,
) -> Mapping[str, object]:
    """Validate the exact complete schema emitted by the P9-10 safe mapper."""

    if not isinstance(payload, Mapping):
        raise StixValidationError("Existing STIX safe payload is invalid.")
    _validate_safe_payload_tree(payload, policy)
    stix_type = payload.get("type")
    if (
        not isinstance(stix_type, str)
        or stix_type not in policy.allowed_stix_types
        or expected_stix_type is not None
        and stix_type != expected_stix_type
        or payload.get("id") != expected_stix_id
        or payload.get("spec_version") != "2.1"
    ):
        raise StixValidationError("Existing STIX safe payload is invalid.")
    _validate_stix_id(expected_stix_id, stix_type)
    allowed = _SAFE_KEYS_BY_TYPE[stix_type]
    required = _REQUIRED_SAFE_KEYS_BY_TYPE[stix_type]
    if set(payload) - allowed or not required.issubset(payload):
        raise StixValidationError("Existing STIX safe payload schema is invalid.")
    _validate_safe_payload_fields(payload, stix_type, policy)
    frozen = freeze_mapping(thaw_json(payload))
    return frozen


def validate_persistable_stix_document(
    document: ValidatedStixDocument,
    policy: ApprovedStixSourcePolicy,
) -> ValidatedStixDocument:
    """Rebuild a caller-supplied validation result for safe persistence."""

    if not isinstance(document, ValidatedStixDocument):
        raise StixValidationError("Validated STIX document is invalid.")
    approved = validate_stix_source_policy(policy)
    if not isinstance(document.objects, tuple) or not isinstance(
        document.validated_versions, tuple
    ):
        raise StixValidationError("Validated STIX document is invalid.")
    if len(document.validated_versions) > approved.maximum_objects:
        raise StixValidationError("Validated STIX document exceeds policy.")
    for count in (
        document.objects_received,
        document.objects_validated,
        document.relationships_validated,
        document.markings_validated,
        document.relationships_excluded,
    ):
        if type(count) is not int or count < 0:
            raise StixValidationError("Validated STIX document counters are invalid.")

    revalidated_versions = [
        _canonicalize_persistable_staged(staged, approved)
        for staged in document.validated_versions
    ]
    latest = _latest_strict_versions(revalidated_versions)
    canonical_versions = _canonical_version_lineage(revalidated_versions)
    actual_count = len(canonical_versions)
    relationship_count = sum(
        item.stix_type == "relationship" for item in canonical_versions
    )
    marking_count = sum(
        item.stix_type == "marking-definition" for item in canonical_versions
    )
    if (
        document.objects_received != actual_count + document.relationships_excluded
        or document.objects_validated != actual_count
        or document.relationships_validated != relationship_count
        or document.markings_validated != marking_count
        or relationship_count > approved.maximum_relationships
    ):
        raise StixValidationError("Validated STIX document counters are invalid.")

    canonical_objects = tuple(
        [item for item in latest if item.stix_type != "relationship"]
        + [item for item in latest if item.stix_type == "relationship"]
    )
    supplied_objects = tuple(
        _canonicalize_persistable_staged(staged, approved)
        for staged in document.objects
    )
    if supplied_objects != canonical_objects:
        raise StixValidationError("Validated STIX latest objects are invalid.")

    by_id = {item.stix_id: item for item in canonical_objects}
    for item in canonical_objects:
        for reference in item.safe_payload.get("object_marking_refs", ()):
            target = by_id.get(reference)
            if target is not None:
                validate_existing_safe_payload(
                    reference,
                    target.safe_payload,
                    approved,
                    ExistingStixReferenceUse.OBJECT_MARKING,
                )
        if item.stix_type != "relationship":
            continue
        relationship_type = item.safe_payload["relationship_type"]
        source_ref = item.safe_payload["source_ref"]
        target_ref = item.safe_payload["target_ref"]
        if relationship_type not in approved.allowed_relationship_types:
            raise StixValidationError("Validated STIX relationship is not approved.")
        if source_ref == target_ref and relationship_type != "related-to":
            raise StixValidationError("Validated STIX relationship is not approved.")
        for reference in (source_ref, target_ref):
            target = by_id.get(reference)
            if target is not None:
                validate_existing_safe_payload(
                    reference,
                    target.safe_payload,
                    approved,
                    ExistingStixReferenceUse.RELATIONSHIP_TARGET,
                )

    return ValidatedStixDocument(
        objects=canonical_objects,
        validated_versions=canonical_versions,
        objects_received=actual_count,
        objects_validated=actual_count,
        relationships_validated=relationship_count,
        markings_validated=marking_count,
        relationships_excluded=document.relationships_excluded,
    )


def _canonicalize_persistable_staged(
    staged: object,
    policy: ApprovedStixSourcePolicy,
) -> StagedStixObject:
    if type(staged) is not StagedStixObject:
        raise StixValidationError("Validated STIX staged object is invalid.")
    canonical_payload = validate_canonical_safe_payload(
        staged.stix_id,
        staged.safe_payload,
        policy,
        expected_stix_type=staged.stix_type,
    )
    stix_id = canonical_payload["id"]
    stix_type = canonical_payload["type"]
    if not isinstance(stix_id, str) or not isinstance(stix_type, str):
        raise StixValidationError("Validated STIX staged identity is invalid.")
    if staged.stix_id != stix_id or staged.stix_type != stix_type:
        raise StixValidationError("Validated STIX staged identity is invalid.")
    content_hash = canonical_safe_content_hash(canonical_payload)
    if staged.content_hash != content_hash:
        raise StixValidationError("Validated STIX content hash is invalid.")
    created = _canonical_staged_timestamp(canonical_payload.get("created"), "created")
    modified = _canonical_staged_timestamp(
        canonical_payload.get("modified"), "modified"
    )
    if not _staged_timestamp_matches(
        staged.created, created
    ) or not _staged_timestamp_matches(staged.modified, modified):
        raise StixValidationError("Validated STIX staged timestamp is invalid.")
    try:
        observables = safe_payload_observables(canonical_payload)
    except (StixObjectMappingError, TypeError, ValueError) as exc:
        raise StixValidationError(
            "Validated STIX mapped observables are invalid."
        ) from exc
    if (
        not isinstance(staged.observables, tuple)
        or any(type(item) is not StixMappedObservable for item in staged.observables)
        or staged.observables != observables
    ):
        raise StixValidationError("Validated STIX mapped observables are invalid.")
    return StagedStixObject(
        stix_type=stix_type,
        stix_id=stix_id,
        created=created,
        modified=modified,
        safe_payload=canonical_payload,
        content_hash=content_hash,
        observables=observables,
    )


def _canonical_staged_timestamp(value: object, field_name: str) -> datetime | None:
    parsed = _optional_timestamp(value, field_name)
    if parsed is not None and value != _timestamp_text(parsed):
        raise StixValidationError("Validated STIX staged timestamp is invalid.")
    return parsed


def _staged_timestamp_matches(
    supplied: object,
    canonical: datetime | None,
) -> bool:
    if canonical is None:
        return supplied is None
    return (
        isinstance(supplied, datetime)
        and supplied.tzinfo is UTC
        and supplied == canonical
    )


def validate_stix_document(
    document: BoundedStixDocument,
    policy: ApprovedStixSourcePolicy,
    *,
    existing_objects: Mapping[str, Mapping[str, object]] | None = None,
    allow_unresolved_relationships: bool = False,
) -> ValidatedStixDocument:
    """Validate all objects and reject the complete document on any unsafe item."""

    if not isinstance(document, BoundedStixDocument):
        raise StixValidationError("A bounded STIX document is required.")
    approved = validate_stix_source_policy(policy)
    if type(allow_unresolved_relationships) is not bool:
        raise StixValidationError("STIX relationship-resolution policy is invalid.")
    if len(document.objects) > approved.maximum_objects:
        raise StixValidationError("STIX object count exceeds policy.")
    existing = existing_objects or MappingProxyType({})
    staged_versions: list[StagedStixObject] = []
    try:
        for item in document.objects:
            staged_versions.append(_validate_and_stage_object(item, approved))
    except (StixObjectMappingError, TypeError, ValueError) as exc:
        if isinstance(exc, StixValidationError):
            raise
        raise StixValidationError("STIX object validation failed.") from exc

    relationships_excluded = 0
    accepted_versions: list[StagedStixObject] = []
    for item in staged_versions:
        if (
            item.stix_type == "relationship"
            and approved.allowed_custom_properties
            and not _supported_relationship_combination(item.safe_payload)
        ):
            relationships_excluded += 1
            continue
        accepted_versions.append(item)
    staged_versions = accepted_versions
    relationship_count = sum(
        item.stix_type == "relationship" for item in staged_versions
    )
    if relationship_count > approved.maximum_relationships:
        raise StixValidationError("STIX relationship count exceeds policy.")
    latest = _latest_strict_versions(staged_versions)
    validated_versions = _canonical_version_lineage(staged_versions)
    by_id = {item.stix_id: item for item in latest}
    _validate_marking_references(
        latest,
        by_id,
        existing,
        approved,
        allow_unresolved=allow_unresolved_relationships,
    )
    _validate_relationships(
        latest,
        by_id,
        existing,
        approved,
        allow_unresolved=allow_unresolved_relationships,
    )
    ordered = tuple(
        [item for item in latest if item.stix_type != "relationship"]
        + [item for item in latest if item.stix_type == "relationship"]
    )
    return ValidatedStixDocument(
        objects=ordered,
        validated_versions=validated_versions,
        objects_received=len(document.objects),
        objects_validated=len(staged_versions),
        relationships_validated=relationship_count,
        markings_validated=sum(
            item.stix_type == "marking-definition" for item in staged_versions
        ),
        relationships_excluded=relationships_excluded,
    )


def _validate_and_stage_object(
    obj: Mapping[str, object],
    policy: ApprovedStixSourcePolicy,
) -> StagedStixObject:
    stix_type = obj.get("type")
    stix_id = obj.get("id")
    if not isinstance(stix_type, str) or stix_type not in policy.allowed_stix_types:
        raise StixValidationError("STIX object type is not approved.")
    _validate_stix_id(stix_id, stix_type)
    assert isinstance(stix_id, str)
    if obj.get("spec_version") != "2.1":
        raise StixValidationError("Only STIX 2.1 objects are supported.")
    if "extensions" in obj or "granular_markings" in obj:
        raise StixValidationError("STIX extensions or granular markings are unsupported.")
    _reject_control_strings(obj)
    custom_values = _validate_source_custom_properties(obj, policy)
    standards_object = thaw_json(obj)
    for custom_name in custom_values:
        standards_object.pop(custom_name, None)
    try:
        parse_stix(standards_object, allow_custom=False, version="2.1")
    except Exception as exc:
        raise StixValidationError("STIX standards validation failed.") from exc

    created = _optional_timestamp(obj.get("created"), "created")
    modified = _optional_timestamp(obj.get("modified"), "modified")
    if stix_type in _VERSIONED_TYPES and (created is None or modified is None):
        raise StixValidationError("Versioned STIX object timestamps are required.")
    if created is not None and modified is not None and modified < created:
        raise StixValidationError("STIX modified timestamp precedes created timestamp.")
    valid_from = _optional_timestamp(obj.get("valid_from"), "valid_from")
    valid_until = _optional_timestamp(obj.get("valid_until"), "valid_until")
    if valid_from is not None and valid_until is not None and valid_until < valid_from:
        raise StixValidationError("STIX validity timestamp order is invalid.")
    for name in ("start_time", "stop_time"):
        _optional_timestamp(obj.get(name), name)
    if obj.get("start_time") is not None and obj.get("stop_time") is not None:
        if _optional_timestamp(obj["stop_time"], "stop_time") < _optional_timestamp(
            obj["start_time"], "start_time"
        ):
            raise StixValidationError("STIX relationship timestamp order is invalid.")
    source_revoked = obj.get("revoked")
    if source_revoked is not None and type(source_revoked) is not bool:
        raise StixValidationError("STIX revoked value must be a boolean.")
    deprecated = custom_values.get("x_mitre_deprecated")
    inactive = source_revoked is True or deprecated is True
    confidence_value = obj.get("confidence")
    if confidence_value is not None and (
        type(confidence_value) is not int or not 0 <= confidence_value <= 100
    ):
        raise StixValidationError("STIX confidence is invalid.")
    confidence = (
        None
        if confidence_value is None
        else Decimal(confidence_value).scaleb(-2).quantize(Decimal("0.001"))
    )
    marking_refs = _bounded_string_list(
        obj.get("object_marking_refs", ()),
        policy.maximum_marking_refs,
        "object marking references",
    )
    labels = _bounded_string_list(
        obj.get("labels", ()),
        policy.maximum_aliases,
        "labels",
    )
    aliases = _bounded_string_list(
        obj.get("aliases", ()),
        policy.maximum_aliases,
        "aliases",
    )
    mitre_aliases = custom_values.get("x_mitre_aliases", ())
    if not isinstance(mitre_aliases, tuple):
        raise StixValidationError("ATT&CK alias metadata is invalid.")
    aliases = tuple(dict.fromkeys((*aliases, *mitre_aliases)))
    if len(aliases) > policy.maximum_aliases:
        raise StixValidationError("STIX aliases are invalid.")
    external_references = _safe_external_references(obj, policy)

    safe: dict[str, object] = {
        "type": stix_type,
        "id": stix_id,
        "spec_version": "2.1",
    }
    _put_timestamp(safe, "created", created)
    _put_timestamp(safe, "modified", modified)
    if policy.allowed_custom_properties and (
        source_revoked is not None or deprecated is not None
    ):
        safe["revoked"] = inactive
        safe["source_revoked"] = source_revoked is True
        safe["x_mitre_deprecated"] = deprecated is True
    elif source_revoked is not None:
        safe["revoked"] = source_revoked
    if confidence_value is not None:
        safe["confidence"] = confidence_value
    for name in ("created_by_ref", "name"):
        value = obj.get(name)
        if value is not None:
            safe[name] = _bounded_text(value, 1000, name)
    if marking_refs:
        safe["object_marking_refs"] = list(marking_refs)
    if labels:
        safe["labels"] = list(labels)
    if aliases:
        safe["aliases"] = list(aliases)
    if external_references:
        safe["external_references"] = external_references

    _map_object_specific(
        obj,
        safe,
        policy,
        valid_from=valid_from,
        valid_until=valid_until,
    )
    observation_time = valid_from or modified or created
    observables = direct_observables(
        obj,
        confidence=confidence,
        observed_at=observation_time,
    )
    if stix_type == "indicator":
        pattern = obj.get("pattern")
        if obj.get("pattern_type") != "stix" or obj.get("pattern_version") != "2.1":
            raise StixValidationError("STIX Indicator pattern metadata is invalid.")
        if not isinstance(pattern, str) or run_validator(pattern, "2.1"):
            raise StixValidationError("STIX Indicator pattern is invalid.")
        observables = (
            indicator_pattern_observable(
                obj,
                confidence=confidence,
                observed_at=observation_time,
            ),
        )
    if observables:
        safe["mapped_observables"] = [
            {
                "observable_type": observable.normalized.observable_type,
                "hash_algorithm": observable.normalized.hash_algorithm,
                "identity_sha256": observable.normalized.identity_sha256,
            }
            for observable in sorted(
                observables,
                key=lambda item: (
                    item.normalized.observable_type,
                    item.normalized.hash_algorithm or "",
                    item.normalized.identity_sha256,
                ),
            )
        ]
    frozen = freeze_mapping(safe)
    return StagedStixObject(
        stix_type=stix_type,
        stix_id=stix_id,
        created=created,
        modified=modified,
        safe_payload=frozen,
        content_hash=canonical_safe_content_hash(frozen),
        observables=observables,
    )


def _map_object_specific(
    obj: Mapping[str, object],
    safe: dict[str, object],
    policy: ApprovedStixSourcePolicy,
    *,
    valid_from: datetime | None,
    valid_until: datetime | None,
) -> None:
    stix_type = obj["type"]
    if stix_type == "marking-definition":
        _map_marking_definition(obj, safe, policy)
    elif stix_type == "identity":
        safe["identity_class"] = _bounded_text(obj.get("identity_class"), 100, "identity class")
        sectors = _bounded_string_list(
            obj.get("sectors", ()), policy.maximum_aliases, "sectors"
        )
        if sectors:
            safe["sectors"] = list(sectors)
    elif stix_type == "indicator":
        safe["pattern"] = _bounded_text(obj.get("pattern"), 4096, "pattern")
        safe["pattern_type"] = _bounded_text(obj.get("pattern_type"), 40, "pattern type")
        safe["pattern_version"] = _bounded_text(
            obj.get("pattern_version"), 20, "pattern version"
        )
        indicator_types = _bounded_string_list(
            obj.get("indicator_types", ()), policy.maximum_aliases, "indicator types"
        )
        if indicator_types:
            safe["indicator_types"] = list(indicator_types)
        _put_timestamp(safe, "valid_from", valid_from)
        _put_timestamp(safe, "valid_until", valid_until)
        phases = obj.get("kill_chain_phases", ())
        if (
            not isinstance(phases, (tuple, list))
            or len(phases) > policy.maximum_aliases
        ):
            raise StixValidationError("STIX kill-chain phases are invalid.")
        mapped_phases = []
        for phase in phases:
            if not isinstance(phase, Mapping):
                raise StixValidationError("STIX kill-chain phase is invalid.")
            chain = _bounded_text(phase.get("kill_chain_name"), 100, "kill chain")
            name = _bounded_text(phase.get("phase_name"), 100, "kill-chain phase")
            identity = f"{chain}:{name}".lower()
            if identity not in policy.allowed_kill_chain_phases:
                raise StixValidationError("STIX kill-chain phase is not approved.")
            mapped_phases.append({"kill_chain_name": chain, "phase_name": name})
        if mapped_phases:
            safe["kill_chain_phases"] = mapped_phases
    elif stix_type == "relationship":
        for name in ("relationship_type", "source_ref", "target_ref"):
            safe[name] = _bounded_text(obj.get(name), 300, name)
        if safe["relationship_type"] not in policy.allowed_relationship_types:
            raise StixValidationError("STIX relationship type is not approved.")
        _put_timestamp(
            safe, "start_time", _optional_timestamp(obj.get("start_time"), "start_time")
        )
        _put_timestamp(
            safe, "stop_time", _optional_timestamp(obj.get("stop_time"), "stop_time")
        )
    elif stix_type in {"ipv4-addr", "ipv6-addr", "domain-name", "url"}:
        observables = direct_observables(obj, confidence=None, observed_at=None)
        safe["observable"] = _safe_observable_fields(observables[0].normalized)
    elif stix_type == "file":
        observables = direct_observables(obj, confidence=None, observed_at=None)
        safe["hashes"] = {
            observable.normalized.hash_algorithm: observable.normalized.normalized_value
            for observable in observables
        }


def _map_marking_definition(
    obj: Mapping[str, object],
    safe: dict[str, object],
    policy: ApprovedStixSourcePolicy,
) -> None:
    stix_id = obj["id"]
    definition_type = obj.get("definition_type")
    definition = obj.get("definition")
    if not isinstance(definition, Mapping):
        raise StixValidationError("STIX marking definition is invalid.")
    if definition_type == "tlp":
        level = definition.get("tlp")
        expected = _STANDARD_TLP.get(stix_id)
        if level != expected or level not in policy.allowed_tlp_levels:
            raise StixValidationError("STIX TLP marking is not approved.")
        safe["marking_type"] = "tlp"
        safe["marking_level"] = level
    elif definition_type == "statement":
        if not policy.allow_statement_markings:
            raise StixValidationError("STIX statement markings are disabled.")
        statement = _bounded_text(definition.get("statement"), 1000, "statement")
        safe["marking_type"] = "statement"
        safe["statement"] = " ".join(statement.split())
    else:
        raise StixValidationError("STIX marking definition type is unsupported.")


def _latest_strict_versions(
    objects: list[StagedStixObject],
) -> list[StagedStixObject]:
    grouped: dict[str, list[StagedStixObject]] = {}
    order: list[str] = []
    for item in objects:
        if item.stix_id not in grouped:
            grouped[item.stix_id] = []
            order.append(item.stix_id)
        grouped[item.stix_id].append(item)
    latest: list[StagedStixObject] = []
    for stix_id in order:
        versions = grouped[stix_id]
        if len(versions) == 1:
            latest.append(versions[0])
            continue
        if any(item.modified is None for item in versions):
            raise StixValidationError("Duplicate non-versioned STIX object identifier.")
        sorted_versions = sorted(versions, key=lambda item: item.modified)
        timestamps = [item.modified for item in sorted_versions]
        if len(timestamps) != len(set(timestamps)):
            raise StixValidationError("Conflicting duplicate STIX object version.")
        if len({item.stix_type for item in versions}) != 1:
            raise StixValidationError("STIX object versions have inconsistent types.")
        if len({item.created for item in versions}) != 1:
            raise StixValidationError("STIX object versions changed created timestamp.")
        if len(
            {item.safe_payload.get("created_by_ref") for item in versions}
        ) != 1:
            raise StixValidationError("STIX object versions changed creator identity.")
        revoked_indexes = [
            index
            for index, item in enumerate(sorted_versions)
            if item.safe_payload.get("revoked") is True
        ]
        if revoked_indexes and revoked_indexes != [len(sorted_versions) - 1]:
            raise StixValidationError("STIX revocation must be the terminal version.")
        latest.append(sorted_versions[-1])
    return latest


def _canonical_version_lineage(
    objects: list[StagedStixObject],
) -> tuple[StagedStixObject, ...]:
    grouped: dict[str, list[StagedStixObject]] = {}
    order: list[str] = []
    for item in objects:
        if item.stix_id not in grouped:
            grouped[item.stix_id] = []
            order.append(item.stix_id)
        grouped[item.stix_id].append(item)
    lineage: list[StagedStixObject] = []
    for stix_id in order:
        versions = grouped[stix_id]
        if len(versions) == 1:
            lineage.extend(versions)
        else:
            lineage.extend(sorted(versions, key=lambda item: item.modified))
    return tuple(lineage)


def _validate_marking_references(
    objects: list[StagedStixObject],
    by_id: Mapping[str, StagedStixObject],
    existing: Mapping[str, Mapping[str, object]],
    policy: ApprovedStixSourcePolicy,
    *,
    allow_unresolved: bool,
) -> None:
    for item in objects:
        refs = item.safe_payload.get("object_marking_refs", ())
        for reference in refs:
            target = by_id.get(reference)
            payload = target.safe_payload if target is not None else existing.get(reference)
            if payload is None:
                if allow_unresolved:
                    continue
                raise StixValidationError("STIX marking reference is unresolved.")
            validate_existing_safe_payload(
                reference,
                payload,
                policy,
                ExistingStixReferenceUse.OBJECT_MARKING,
            )


def _validate_relationships(
    objects: list[StagedStixObject],
    by_id: Mapping[str, StagedStixObject],
    existing: Mapping[str, Mapping[str, object]],
    policy: ApprovedStixSourcePolicy,
    *,
    allow_unresolved: bool,
) -> None:
    for item in objects:
        if item.stix_type != "relationship":
            continue
        payload = item.safe_payload
        relationship_type = payload["relationship_type"]
        source_ref = payload["source_ref"]
        target_ref = payload["target_ref"]
        if relationship_type not in policy.allowed_relationship_types:
            raise StixValidationError("STIX relationship type is not approved.")
        if source_ref == target_ref and relationship_type != "related-to":
            raise StixValidationError("STIX relationship self-reference is not approved.")
        for reference in (source_ref, target_ref):
            target = by_id.get(reference)
            target_payload = target.safe_payload if target is not None else existing.get(reference)
            if target_payload is None:
                if allow_unresolved:
                    continue
                raise StixValidationError("STIX relationship reference is unresolved.")
            validate_existing_safe_payload(
                reference,
                target_payload,
                policy,
                ExistingStixReferenceUse.RELATIONSHIP_TARGET,
            )


def _supported_relationship_combination(payload: Mapping[str, object]) -> bool:
    if payload.get("type") != "relationship":
        return True
    relationship_type = payload.get("relationship_type")
    source_ref = payload.get("source_ref")
    target_ref = payload.get("target_ref")
    if not all(
        isinstance(value, str)
        for value in (relationship_type, source_ref, target_ref)
    ):
        raise StixValidationError("STIX relationship metadata is invalid.")
    assert isinstance(relationship_type, str)
    assert isinstance(source_ref, str)
    assert isinstance(target_ref, str)
    source_type = source_ref.split("--", 1)[0]
    target_type = target_ref.split("--", 1)[0]
    entity_types = {"attack-pattern", "campaign", "intrusion-set", "malware"}
    if source_type not in entity_types or target_type not in entity_types:
        return False
    approved = {
        ("intrusion-set", "uses", "malware"),
        ("intrusion-set", "uses", "attack-pattern"),
        ("campaign", "uses", "malware"),
        ("campaign", "uses", "attack-pattern"),
        ("malware", "uses", "attack-pattern"),
        ("campaign", "attributed-to", "intrusion-set"),
    }
    return (source_type, relationship_type, target_type) in approved


def _validate_stix_id(value: object, expected_type: str) -> None:
    if not isinstance(value, str) or len(value) > 300:
        raise StixValidationError("STIX object identifier is invalid.")
    match = _ID_RE.fullmatch(value)
    if match is None or match.group("type") != expected_type:
        raise StixValidationError("STIX object identifier does not match its type.")
    try:
        identifier = UUID(match.group("uuid"))
    except ValueError as exc:
        raise StixValidationError("STIX object identifier is malformed.") from exc
    if identifier.version not in {4, 5}:
        raise StixValidationError("STIX object identifier UUID version is unsupported.")


def _optional_timestamp(value: object, field_name: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise StixValidationError(f"STIX {field_name} timestamp is invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StixValidationError(f"STIX {field_name} timestamp is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StixValidationError(f"STIX {field_name} timestamp must be aware.")
    return parsed.astimezone(UTC)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _put_timestamp(target: dict[str, object], name: str, value: datetime | None) -> None:
    if value is not None:
        target[name] = _timestamp_text(value)


def _bounded_text(value: object, maximum: int, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise StixValidationError(f"STIX {field_name} text is invalid.")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise StixValidationError(f"STIX {field_name} text contains controls.")
    return value


def _bounded_string_list(value: object, maximum: int, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or len(value) > maximum:
        raise StixValidationError(f"STIX {field_name} are invalid.")
    return tuple(_bounded_text(item, 500, field_name) for item in value)


def _safe_external_references(
    obj: Mapping[str, object],
    policy: ApprovedStixSourcePolicy,
) -> list[dict[str, str]]:
    references = obj.get("external_references", ())
    if not isinstance(references, (tuple, list)) or len(references) > policy.maximum_external_references:
        raise StixValidationError("STIX external references are invalid.")
    safe: list[dict[str, str]] = []
    mitre_policy = bool(policy.allowed_custom_properties)
    for reference in references:
        allowed_fields = (
            {"source_name", "external_id", "url", "description"}
            if mitre_policy
            else {"source_name", "external_id"}
        )
        if (
            not isinstance(reference, Mapping)
            or not {"source_name"}.issubset(reference)
            or set(reference) - allowed_fields
            or "external_id" in reference
            and reference["external_id"] is None
        ):
            raise StixValidationError("STIX external reference contains unsafe fields.")
        source_name = _bounded_text(reference.get("source_name"), 200, "external source")
        if _SOURCE_NAME_RE.fullmatch(source_name) is None:
            raise StixValidationError("STIX external source identifier is invalid.")
        mapped = {"source_name": source_name}
        if reference.get("external_id") is not None:
            external_id = _bounded_text(
                reference["external_id"], 200, "external identifier"
            )
            if _EXTERNAL_ID_RE.fullmatch(external_id) is None:
                raise StixValidationError("STIX external identifier is invalid.")
            mapped["external_id"] = external_id
        if "url" in reference:
            _validate_discarded_external_url(reference["url"])
        if "description" in reference:
            _bounded_text(reference["description"], 5000, "external description")
        safe.append(mapped)
    return safe


def _validate_discarded_external_url(value: object) -> None:
    text = _bounded_text(value, 2048, "external URL")
    if not text.isascii():
        raise StixValidationError("STIX external URL is invalid.")
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError:
        raise StixValidationError("STIX external URL is invalid.") from None
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or port not in {None, 80, 443}
        or parsed.fragment
    ):
        raise StixValidationError("STIX external URL is invalid.")


def _validate_source_custom_properties(
    obj: Mapping[str, object],
    policy: ApprovedStixSourcePolicy,
) -> Mapping[str, object]:
    custom_names = {key for key in obj if key.startswith("x_")}
    if custom_names - policy.allowed_custom_properties:
        raise StixValidationError("STIX custom property is not approved.")
    if not custom_names:
        return MappingProxyType({})
    list_fields = {
        "x_mitre_aliases",
        "x_mitre_contributors",
        "x_mitre_data_sources",
        "x_mitre_defense_bypassed",
        "x_mitre_domains",
        "x_mitre_effective_permissions",
        "x_mitre_impact_type",
        "x_mitre_permissions_required",
        "x_mitre_platforms",
        "x_mitre_system_requirements",
    }
    text_limits = {
        "x_mitre_attack_spec_version": 100,
        "x_mitre_detection": 50_000,
        "x_mitre_first_seen_citation": 5_000,
        "x_mitre_last_seen_citation": 5_000,
        "x_mitre_version": 100,
    }
    boolean_fields = {
        "x_mitre_deprecated",
        "x_mitre_is_subtechnique",
        "x_mitre_network_requirements",
        "x_mitre_remote_support",
    }
    validated: dict[str, object] = {}
    for name in sorted(custom_names):
        value = obj[name]
        if name in list_fields:
            items = _bounded_string_list(
                value,
                policy.maximum_aliases,
                name,
            )
            validated[name] = items
        elif name in text_limits:
            validated[name] = _bounded_text(value, text_limits[name], name)
        elif name in boolean_fields:
            if type(value) is not bool:
                raise StixValidationError("ATT&CK custom property is invalid.")
            validated[name] = value
        else:
            raise StixValidationError("STIX custom property is not approved.")
    domains = validated.get("x_mitre_domains")
    if domains is not None and (
        not isinstance(domains, tuple) or "enterprise-attack" not in domains
    ):
        raise StixValidationError("ATT&CK object is outside the Enterprise domain.")
    return MappingProxyType(validated)


def _reject_control_strings(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, (tuple, list)):
            stack.extend(current)
        elif isinstance(current, str) and any(
            unicodedata.category(character) == "Cc" for character in current
        ):
            raise StixValidationError("STIX text contains unsupported controls.")


def _validate_safe_payload_tree(
    value: object,
    policy: ApprovedStixSourcePolicy,
) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > policy.maximum_json_nodes or depth > policy.maximum_json_depth:
            raise StixValidationError("Existing STIX safe payload exceeds policy.")
        if isinstance(current, Mapping):
            if len(current) > policy.maximum_json_nodes:
                raise StixValidationError("Existing STIX safe payload exceeds policy.")
            for key, item in current.items():
                if (
                    not isinstance(key, str)
                    or len(key) > policy.maximum_json_string_length
                    or any(unicodedata.category(character) == "Cc" for character in key)
                ):
                    raise StixValidationError("Existing STIX safe payload is invalid.")
                stack.append((item, depth + 1))
        elif isinstance(current, (tuple, list)):
            if len(current) > policy.maximum_json_nodes:
                raise StixValidationError("Existing STIX safe payload exceeds policy.")
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            if (
                len(current) > policy.maximum_json_string_length
                or any(unicodedata.category(character) == "Cc" for character in current)
            ):
                raise StixValidationError("Existing STIX safe payload is invalid.")
        elif type(current) is int:
            if not -(2**63) <= current <= 2**63 - 1:
                raise StixValidationError("Existing STIX safe payload is invalid.")
        elif current is not None and type(current) is not bool:
            raise StixValidationError("Existing STIX safe payload is invalid.")


def _validate_safe_payload_fields(
    payload: Mapping[str, object],
    stix_type: str,
    policy: ApprovedStixSourcePolicy,
) -> None:
    timestamps: dict[str, datetime] = {}
    for name in ("created", "modified", "valid_from", "valid_until", "start_time", "stop_time"):
        if name in payload:
            value = payload[name]
            parsed = _optional_timestamp(value, name)
            if parsed is None or value != _timestamp_text(parsed):
                raise StixValidationError("Existing STIX timestamp is not canonical.")
            timestamps[name] = parsed
    for earlier, later in (
        ("created", "modified"),
        ("valid_from", "valid_until"),
        ("start_time", "stop_time"),
    ):
        if earlier in timestamps and later in timestamps and timestamps[later] < timestamps[earlier]:
            raise StixValidationError("Existing STIX timestamp order is invalid.")
    if "created_by_ref" in payload:
        _validate_stix_id(payload["created_by_ref"], "identity")
    if "revoked" in payload and type(payload["revoked"]) is not bool:
        raise StixValidationError("Existing STIX revoked value is invalid.")
    for name in ("source_revoked", "x_mitre_deprecated"):
        if name in payload and type(payload[name]) is not bool:
            raise StixValidationError("Existing ATT&CK lifecycle value is invalid.")
    if "source_revoked" in payload or "x_mitre_deprecated" in payload:
        if not policy.allowed_custom_properties or payload.get("revoked") is not (
            payload.get("source_revoked", False)
            or payload.get("x_mitre_deprecated", False)
        ):
            raise StixValidationError("Existing ATT&CK lifecycle value is invalid.")
    if "confidence" in payload and (
        type(payload["confidence"]) is not int
        or not 0 <= payload["confidence"] <= 100
    ):
        raise StixValidationError("Existing STIX confidence is invalid.")
    text_limits = {
        "name": 1000,
        "identity_class": 100,
        "pattern": 4096,
        "pattern_type": 40,
        "pattern_version": 20,
        "relationship_type": 300,
        "source_ref": 300,
        "target_ref": 300,
    }
    for name, maximum in text_limits.items():
        if name in payload:
            _bounded_text(payload[name], maximum, name)
    for name in ("labels", "aliases", "sectors", "indicator_types"):
        if name in payload:
            if not _bounded_string_list(payload[name], policy.maximum_aliases, name):
                raise StixValidationError("Existing STIX safe payload is not canonical.")
    if "object_marking_refs" in payload:
        refs = _bounded_string_list(
            payload["object_marking_refs"],
            policy.maximum_marking_refs,
            "object marking references",
        )
        if not refs:
            raise StixValidationError("Existing STIX safe payload is not canonical.")
        for reference in refs:
            _validate_stix_id(reference, "marking-definition")
    if "external_references" in payload:
        if not _safe_external_references(payload, policy):
            raise StixValidationError("Existing STIX safe payload is not canonical.")
    if "kill_chain_phases" in payload:
        phases = payload["kill_chain_phases"]
        if (
            not isinstance(phases, (tuple, list))
            or not phases
            or len(phases) > policy.maximum_aliases
        ):
            raise StixValidationError("Existing STIX kill-chain phases are invalid.")
        for phase in phases:
            if not isinstance(phase, Mapping) or set(phase) != {
                "kill_chain_name",
                "phase_name",
            }:
                raise StixValidationError("Existing STIX kill-chain phase is invalid.")
            chain = _bounded_text(phase["kill_chain_name"], 100, "kill chain")
            name = _bounded_text(phase["phase_name"], 100, "kill-chain phase")
            if f"{chain}:{name}".lower() not in policy.allowed_kill_chain_phases:
                raise StixValidationError("Existing STIX kill-chain phase is not approved.")

    mapped = _validated_mapped_identities(payload.get("mapped_observables"))
    if stix_type in {"ipv4-addr", "ipv6-addr", "domain-name", "url"}:
        observable = payload["observable"]
        if not isinstance(observable, Mapping) or set(observable) != {
            "observable_type",
            "normalized_value",
            "hash_algorithm",
        }:
            raise StixValidationError("Existing STIX observable mapping is invalid.")
        expected_type = {
            "ipv4-addr": "ipv4",
            "ipv6-addr": "ipv6",
            "domain-name": "domain",
            "url": "url",
        }[stix_type]
        if observable.get("observable_type") != expected_type or observable.get("hash_algorithm") is not None:
            raise StixValidationError("Existing STIX observable mapping is invalid.")
        normalized = _renormalize_safe_observable(
            expected_type,
            observable.get("normalized_value"),
            None,
        )
        if normalized.normalized_value != observable.get("normalized_value"):
            raise StixValidationError("Existing STIX observable mapping is not canonical.")
        if mapped != ((expected_type, None, normalized.identity_sha256),):
            raise StixValidationError("Existing STIX mapped identity is inconsistent.")
    elif stix_type == "file":
        hashes = payload["hashes"]
        if not isinstance(hashes, Mapping) or not hashes or set(hashes) - {
            "md5",
            "sha1",
            "sha256",
            "sha512",
        }:
            raise StixValidationError("Existing STIX file hashes are invalid.")
        expected = []
        for algorithm in sorted(hashes):
            normalized = _renormalize_safe_observable(
                "file_hash",
                hashes[algorithm],
                algorithm,
            )
            if normalized.normalized_value != hashes[algorithm]:
                raise StixValidationError("Existing STIX file hash is not canonical.")
            expected.append(("file_hash", algorithm, normalized.identity_sha256))
        if mapped != tuple(sorted(expected)):
            raise StixValidationError("Existing STIX mapped identity is inconsistent.")
    elif stix_type == "indicator":
        if payload["pattern_type"] != "stix" or payload["pattern_version"] != "2.1":
            raise StixValidationError("Existing STIX Indicator metadata is invalid.")
        confidence_value = payload.get("confidence")
        confidence = (
            None
            if confidence_value is None
            else Decimal(confidence_value).scaleb(-2).quantize(Decimal("0.001"))
        )
        try:
            expected_observable = indicator_pattern_observable(
                payload,
                confidence=confidence,
                observed_at=timestamps["valid_from"],
            )
        except (StixObjectMappingError, KeyError, TypeError, ValueError) as exc:
            raise StixValidationError(
                "Existing STIX Indicator mapping is invalid."
            ) from exc
        expected_mapped = (
            (
                expected_observable.normalized.observable_type,
                expected_observable.normalized.hash_algorithm,
                expected_observable.normalized.identity_sha256,
            ),
        )
        if mapped != expected_mapped:
            raise StixValidationError("Existing STIX mapped identity is inconsistent.")
    elif mapped:
        raise StixValidationError("Existing STIX mapped identity is unexpected.")

    if stix_type == "marking-definition":
        marking_type = payload["marking_type"]
        if marking_type == "tlp":
            if set(payload) != _BASE_SAFE_KEYS | {
                "created",
                "marking_type",
                "marking_level",
            }:
                raise StixValidationError("Existing STIX marking schema is invalid.")
            expected = _STANDARD_TLP.get(payload["id"])
            if (
                payload["created"] != "2017-01-20T00:00:00.000000Z"
                or payload["marking_level"] != expected
                or expected not in policy.allowed_tlp_levels
            ):
                raise StixValidationError("Existing STIX TLP marking is not approved.")
        elif marking_type == "statement":
            if (
                payload["id"] in _STANDARD_TLP
                or "statement" not in payload
                or "marking_level" in payload
            ):
                raise StixValidationError("Existing STIX marking schema is invalid.")
            statement = _bounded_text(payload["statement"], 1000, "statement")
            if (
                not policy.allow_statement_markings
                or not statement.strip()
                or statement != " ".join(statement.split())
            ):
                raise StixValidationError("Existing STIX statement marking is invalid.")
        else:
            raise StixValidationError("Existing STIX marking schema is invalid.")
    if stix_type == "relationship":
        if payload["relationship_type"] not in policy.allowed_relationship_types:
            raise StixValidationError("Existing STIX relationship type is invalid.")
        for name in ("source_ref", "target_ref"):
            _validate_supported_reference_id(payload[name], policy)


def _validated_mapped_identities(
    value: object,
) -> tuple[tuple[str, str | None, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, (tuple, list)) or not value:
        raise StixValidationError("Existing STIX mapped identity is invalid.")
    identities = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "observable_type",
            "hash_algorithm",
            "identity_sha256",
        }:
            raise StixValidationError("Existing STIX mapped identity is invalid.")
        observable_type = item.get("observable_type")
        hash_algorithm = item.get("hash_algorithm")
        identity = item.get("identity_sha256")
        if (
            observable_type not in {"ipv4", "ipv6", "domain", "url", "file_hash"}
            or hash_algorithm not in {None, "md5", "sha1", "sha256", "sha512"}
            or observable_type == "file_hash" and hash_algorithm is None
            or observable_type != "file_hash" and hash_algorithm is not None
            or not isinstance(identity, str)
            or re.fullmatch(r"[0-9a-f]{64}", identity) is None
        ):
            raise StixValidationError("Existing STIX mapped identity is invalid.")
        identities.append((observable_type, hash_algorithm, identity))
    original = tuple(identities)
    ordered = tuple(sorted(original, key=lambda item: (item[0], item[1] or "", item[2])))
    if original != ordered or len(ordered) != len(set(ordered)):
        raise StixValidationError("Existing STIX mapped identity is invalid.")
    return ordered


def _renormalize_safe_observable(
    observable_type: str,
    value: object,
    hash_algorithm: str | None,
):
    if not isinstance(value, str):
        raise StixValidationError("Existing STIX observable mapping is invalid.")
    try:
        return normalize_observable(
            observable_type,
            value,
            hash_algorithm=hash_algorithm,
        )
    except IndicatorValueError as exc:
        raise StixValidationError("Existing STIX observable mapping is invalid.") from exc


def _validate_supported_reference_id(
    value: object,
    policy: ApprovedStixSourcePolicy,
) -> None:
    if not isinstance(value, str):
        raise StixValidationError("Existing STIX reference identifier is invalid.")
    match = _ID_RE.fullmatch(value)
    if match is None or match.group("type") not in policy.allowed_stix_types:
        raise StixValidationError("Existing STIX reference identifier is invalid.")
    _validate_stix_id(value, match.group("type"))


def _safe_observable_fields(normalized) -> dict[str, object]:
    return {
        "observable_type": normalized.observable_type,
        "normalized_value": normalized.normalized_value,
        "hash_algorithm": normalized.hash_algorithm,
    }
