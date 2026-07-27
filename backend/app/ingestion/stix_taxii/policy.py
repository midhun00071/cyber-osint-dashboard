"""Immutable allow-list policy for offline STIX/TAXII processing."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import ipaddress
import idna
import re
from types import MappingProxyType
import unicodedata
from urllib.parse import quote, urlsplit, urlunsplit


SUPPORTED_STIX_TYPES = frozenset(
    {
        "marking-definition",
        "identity",
        "indicator",
        "relationship",
        "attack-pattern",
        "campaign",
        "malware",
        "threat-actor",
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "url",
        "file",
    }
)
SUPPORTED_RELATIONSHIP_TYPES = frozenset(
    {"indicates", "uses", "attributed-to", "targets", "related-to"}
)
SUPPORTED_TLP_LEVELS = frozenset({"white", "green", "amber", "red"})
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
_MAX_POLICY_BASE_URL_LENGTH = 1700
_STIX_ID_RE = re.compile(
    r"^[a-z][a-z0-9-]{0,249}--"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[45][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class StixPolicyError(ValueError):
    """A policy definition or lookup failed safe validation."""


class UnknownStixSourceError(StixPolicyError):
    """A source has no approved production STIX policy."""


class StixInputTransport(str, Enum):
    """Offline input forms supported by this implementation unit."""

    LOCAL_BUNDLE = "local_bundle"
    TAXII_ENVELOPE_FIXTURE = "taxii_envelope_fixture"


@dataclass(frozen=True, slots=True)
class ApprovedStixSourcePolicy:
    """Developer-controlled limits and semantic allow-lists for one source."""

    source_slug: str
    allowed_transport: StixInputTransport
    policy_base_url: str
    allowed_stix_types: frozenset[str] = SUPPORTED_STIX_TYPES
    allowed_relationship_types: frozenset[str] = SUPPORTED_RELATIONSHIP_TYPES
    allowed_tlp_levels: frozenset[str] = frozenset()
    allowed_kill_chain_phases: frozenset[str] = frozenset()
    allow_statement_markings: bool = False
    maximum_file_bytes: int = 2 * 1024 * 1024
    maximum_json_depth: int = 16
    maximum_json_nodes: int = 10_000
    maximum_json_string_length: int = 10_000
    maximum_objects: int = 500
    maximum_relationships: int = 200
    maximum_marking_refs: int = 20
    maximum_external_references: int = 20
    maximum_aliases: int = 50

    def object_url(self, stix_id: str) -> str:
        """Build a fixed-policy object identity without performing a request."""

        if not isinstance(stix_id, str) or _STIX_ID_RE.fullmatch(stix_id) is None:
            raise StixPolicyError("STIX object identity is invalid.")
        encoded = quote(stix_id, safe="")
        return f"{self.policy_base_url.rstrip('/')}/{encoded}"


def validate_stix_source_policy(
    policy: ApprovedStixSourcePolicy,
) -> ApprovedStixSourcePolicy:
    """Normalize and validate a frozen source policy."""

    if not isinstance(policy, ApprovedStixSourcePolicy):
        raise StixPolicyError("STIX source policy is invalid.")
    if not isinstance(policy.source_slug, str) or _SLUG_RE.fullmatch(
        policy.source_slug
    ) is None:
        raise StixPolicyError("STIX source slug is not canonical.")
    try:
        transport = (
            policy.allowed_transport
            if isinstance(policy.allowed_transport, StixInputTransport)
            else StixInputTransport(policy.allowed_transport)
        )
    except (TypeError, ValueError) as exc:
        raise StixPolicyError("STIX transport is not supported.") from exc

    stix_types = _validated_allow_list(
        policy.allowed_stix_types,
        SUPPORTED_STIX_TYPES,
        "STIX object type",
        require_values=True,
    )
    relationship_types = _validated_allow_list(
        policy.allowed_relationship_types,
        SUPPORTED_RELATIONSHIP_TYPES,
        "STIX relationship type",
        require_values=False,
    )
    tlp_levels = _validated_allow_list(
        policy.allowed_tlp_levels,
        SUPPORTED_TLP_LEVELS,
        "TLP level",
        require_values=False,
    )
    kill_chain_phases = _validated_bounded_strings(
        policy.allowed_kill_chain_phases,
        "kill-chain phase",
    )
    if type(policy.allow_statement_markings) is not bool:
        raise StixPolicyError("Statement-marking policy must be a boolean.")
    limits = (
        policy.maximum_file_bytes,
        policy.maximum_json_depth,
        policy.maximum_json_nodes,
        policy.maximum_json_string_length,
        policy.maximum_objects,
        policy.maximum_relationships,
        policy.maximum_marking_refs,
        policy.maximum_external_references,
        policy.maximum_aliases,
    )
    if any(type(limit) is not int or limit <= 0 for limit in limits):
        raise StixPolicyError("STIX policy limits must be positive integers.")
    if policy.maximum_objects > policy.maximum_json_nodes:
        raise StixPolicyError("STIX object limit exceeds the JSON node limit.")
    base_url = _normalize_policy_base_url(policy.policy_base_url)
    return replace(
        policy,
        allowed_transport=transport,
        policy_base_url=base_url,
        allowed_stix_types=stix_types,
        allowed_relationship_types=relationship_types,
        allowed_tlp_levels=tlp_levels,
        allowed_kill_chain_phases=kill_chain_phases,
    )


def build_stix_policy_registry(
    policies: tuple[ApprovedStixSourcePolicy, ...],
) -> MappingProxyType[str, ApprovedStixSourcePolicy]:
    """Validate policies and return an immutable exact-slug registry."""

    registry: dict[str, ApprovedStixSourcePolicy] = {}
    for policy in policies:
        normalized = validate_stix_source_policy(policy)
        if normalized.source_slug in registry:
            raise StixPolicyError("Duplicate STIX source policy.")
        registry[normalized.source_slug] = normalized
    return MappingProxyType(registry)


def get_production_stix_policy(source_slug: str) -> ApprovedStixSourcePolicy:
    """Return one production policy; the registry is intentionally empty."""

    if not isinstance(source_slug, str) or _SLUG_RE.fullmatch(source_slug) is None:
        raise UnknownStixSourceError("STIX source is not approved.")
    try:
        return PRODUCTION_STIX_SOURCE_POLICIES[source_slug]
    except KeyError as exc:
        raise UnknownStixSourceError("STIX source is not approved.") from exc


def _validated_allow_list(
    values: object,
    supported: frozenset[str],
    label: str,
    *,
    require_values: bool,
) -> frozenset[str]:
    if not isinstance(values, (set, frozenset, tuple, list)):
        raise StixPolicyError(f"{label} allow-list is invalid.")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or value != value.strip().lower():
            raise StixPolicyError(f"{label} is not canonical.")
        if value not in supported:
            raise StixPolicyError(f"{label} is not supported.")
        normalized.append(value)
    if require_values and not normalized:
        raise StixPolicyError(f"{label} allow-list must not be empty.")
    if len(normalized) != len(set(normalized)):
        raise StixPolicyError(f"Duplicate {label} entry.")
    return frozenset(normalized)


def _normalize_policy_base_url(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > _MAX_POLICY_BASE_URL_LENGTH
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        raise StixPolicyError("STIX policy base URL is invalid.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise StixPolicyError("STIX policy base URL is invalid.") from exc
    submitted_hostname = parsed.hostname or ""
    try:
        hostname = idna.encode(
            submitted_hostname,
            uts46=True,
            std3_rules=True,
            transitional=False,
        ).decode("ascii")
    except idna.IDNAError as exc:
        raise StixPolicyError("STIX policy base URL is invalid.") from exc
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        is_ip_literal = False
    else:
        is_ip_literal = True
    if (
        parsed.scheme != "https"
        or not hostname
        or submitted_hostname != hostname
        or _HOST_RE.fullmatch(hostname) is None
        or is_ip_literal
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or parsed.netloc not in {hostname, f"{hostname}:443"}
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
        or "\\" in parsed.path
        or "//" in parsed.path
    ):
        raise StixPolicyError("STIX policy base URL is invalid.")
    segments = parsed.path.split("/")[1:] if parsed.path.startswith("/") else []
    if parsed.path and (
        not parsed.path.startswith("/")
        or any(
            not segment or _PATH_SEGMENT_RE.fullmatch(segment) is None
            for segment in segments[:-1] if parsed.path.endswith("/")
        )
        or any(
            segment in {"", ".", ".."}
            or _PATH_SEGMENT_RE.fullmatch(segment) is None
            for segment in (segments[:-1] if parsed.path.endswith("/") else segments)
        )
    ):
        raise StixPolicyError("STIX policy base URL is invalid.")
    netloc = hostname
    path = parsed.path.rstrip("/")
    return urlunsplit(("https", netloc, path, "", ""))


def _validated_bounded_strings(values: object, label: str) -> frozenset[str]:
    if not isinstance(values, (set, frozenset, tuple, list)):
        raise StixPolicyError(f"{label} allow-list is invalid.")
    normalized: list[str] = []
    for value in values:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip().lower()
            or len(value) > 200
        ):
            raise StixPolicyError(f"{label} is not canonical.")
        normalized.append(value)
    if len(normalized) != len(set(normalized)):
        raise StixPolicyError(f"Duplicate {label} entry.")
    return frozenset(normalized)


PRODUCTION_STIX_SOURCE_POLICIES = build_stix_policy_registry(())
