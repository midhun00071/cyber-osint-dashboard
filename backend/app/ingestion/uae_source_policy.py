"""Immutable evidence and approval boundaries for assessed UAE public sources.

This module is governance metadata only.  It performs deterministic local URL
classification and deliberately contains no network, DNS, socket, or download
functionality.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ipaddress
import re
from types import MappingProxyType
from urllib.parse import SplitResult, urlsplit


MAX_UAE_URL_CHARS = 2048
MAX_UAE_PATH_SEGMENT_CHARS = 160


class UaeSourcePolicyError(ValueError):
    """A UAE source policy definition or lookup is invalid."""


class UnknownUaeSourcePolicyError(UaeSourcePolicyError):
    """A requested UAE source policy is not registered."""


class AutomationApprovalState(str, Enum):
    """Developer-controlled network-automation approval state."""

    PENDING = "pending"


class AssessedUrlKind(str, Enum):
    """Evidence-derived role of a safe URL identity."""

    LISTING = "listing"
    CANONICAL_METADATA_LINK = "canonical_metadata_link"


@dataclass(frozen=True, slots=True)
class UaeSourcePolicy:
    """Immutable evidence boundary kept separate from access approval."""

    source_slug: str
    vendor: str
    assessed_host: str
    assessed_listing_paths: tuple[str, ...]
    canonical_metadata_path_pattern: str | None
    automated_access_approved: bool
    automation_approval_state: AutomationApprovalState
    proposed_minimum_cadence_hours: int | None


@dataclass(frozen=True, slots=True)
class UaeUrlAssessment:
    """Local assessment result that never authorizes a network request."""

    source_slug: str
    matches_assessed_boundary: bool
    assessed_url_kind: AssessedUrlKind | None
    assessed_request_target: bool
    automated_access_approved: bool
    automation_approval_state: AutomationApprovalState


_SAFE_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SAFE_HOST_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$",
    flags=re.ASCII,
)
_CSC_CANONICAL_METADATA_PATH_PATTERN = r"/en/w/[a-z0-9]+(?:-[a-z0-9]+)*"


def get_uae_source_policy(source_slug: str) -> UaeSourcePolicy:
    """Return one immutable policy by its exact canonical source slug."""

    if not isinstance(source_slug, str) or not _SAFE_SLUG_PATTERN.fullmatch(
        source_slug
    ):
        raise UnknownUaeSourcePolicyError("Unknown UAE source policy.")
    try:
        return UAE_SOURCE_POLICIES[source_slug]
    except KeyError as exc:
        raise UnknownUaeSourcePolicyError("Unknown UAE source policy.") from exc


def list_uae_source_policies() -> tuple[UaeSourcePolicy, ...]:
    """Return policies in deterministic canonical-slug order."""

    return tuple(UAE_SOURCE_POLICIES.values())


def classify_assessed_uae_url(
    source_slug: str,
    url: str,
) -> AssessedUrlKind | None:
    """Classify a URL against evidence without granting network approval."""

    policy = get_uae_source_policy(source_slug)
    parsed = _parse_safe_exact_https_url(url, expected_host=policy.assessed_host)
    if parsed is None:
        return None
    if parsed.path in policy.assessed_listing_paths:
        return AssessedUrlKind.LISTING
    if policy.canonical_metadata_path_pattern is not None and re.fullmatch(
        policy.canonical_metadata_path_pattern,
        parsed.path,
        flags=re.ASCII,
    ):
        return AssessedUrlKind.CANONICAL_METADATA_LINK
    return None


def assess_uae_source_url(source_slug: str, url: str) -> UaeUrlAssessment:
    """Return evidence and approval decisions as explicitly separate fields."""

    policy = get_uae_source_policy(source_slug)
    kind = classify_assessed_uae_url(source_slug, url)
    return UaeUrlAssessment(
        source_slug=policy.source_slug,
        matches_assessed_boundary=kind is not None,
        assessed_url_kind=kind,
        assessed_request_target=kind is AssessedUrlKind.LISTING,
        automated_access_approved=policy.automated_access_approved,
        automation_approval_state=policy.automation_approval_state,
    )


def url_matches_assessed_uae_boundary(source_slug: str, url: str) -> bool:
    """Return whether a URL is an assessed listing or canonical metadata link."""

    return classify_assessed_uae_url(source_slug, url) is not None


def automated_uae_access_is_approved(source_slug: str) -> bool:
    """Return the separate automation decision; all current decisions are false."""

    return get_uae_source_policy(source_slug).automated_access_approved


def _parse_safe_exact_https_url(
    url: object,
    *,
    expected_host: str,
) -> SplitResult | None:
    if (
        not isinstance(url, str)
        or not url
        or url != url.strip()
        or len(url) > MAX_UAE_URL_CHARS
        or not url.isascii()
        or "\\" in url
        or "%" in url
        or "@" in url
        or "?" in url
        or "#" in url
        or "\ufffd" in url
        or any(ord(character) < 32 or ord(character) == 127 for character in url)
    ):
        return None

    try:
        parsed = urlsplit(url)
        host = parsed.hostname
    except (TypeError, ValueError):
        return None

    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.netloc != expected_host
        or host is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not _SAFE_HOST_PATTERN.fullmatch(host)
        or host != expected_host
    ):
        return None

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return None

    path = parsed.path
    if not path.startswith("/") or "//" in path:
        return None
    segments = path[1:].split("/")
    if segments and segments[-1] == "":
        segments = segments[:-1]
    if (
        not segments
        or any(not segment for segment in segments)
        or any(segment in {".", ".."} for segment in segments)
        or any(len(segment) > MAX_UAE_PATH_SEGMENT_CHARS for segment in segments)
    ):
        return None
    return parsed


def _build_policy_registry(
    policies: tuple[UaeSourcePolicy, ...],
) -> MappingProxyType[str, UaeSourcePolicy]:
    built: dict[str, UaeSourcePolicy] = {}
    for policy in policies:
        if policy.source_slug in built:
            raise UaeSourcePolicyError("Duplicate UAE source policy.")
        if not _SAFE_SLUG_PATTERN.fullmatch(policy.source_slug):
            raise UaeSourcePolicyError("UAE source policy slug is invalid.")
        if policy.automated_access_approved is not False:
            raise UaeSourcePolicyError("UAE automated access is not approved.")
        if policy.automation_approval_state is not AutomationApprovalState.PENDING:
            raise UaeSourcePolicyError("UAE automation approval must remain pending.")
        built[policy.source_slug] = policy
    return MappingProxyType(dict(sorted(built.items())))


UAE_SOURCE_POLICIES = _build_policy_registry(
    (
        UaeSourcePolicy(
            source_slug="ae-cert",
            vendor="TDRA / aeCERT",
            assessed_host="tdra.gov.ae",
            assessed_listing_paths=(),
            canonical_metadata_path_pattern=None,
            automated_access_approved=False,
            automation_approval_state=AutomationApprovalState.PENDING,
            proposed_minimum_cadence_hours=None,
        ),
        UaeSourcePolicy(
            source_slug="uae-cyber-security-council",
            vendor="UAE Cyber Security Council",
            assessed_host="csc.gov.ae",
            assessed_listing_paths=(
                "/en/stay-alert",
                "/en/all-threats",
                "/en/all-updates",
            ),
            canonical_metadata_path_pattern=_CSC_CANONICAL_METADATA_PATH_PATTERN,
            automated_access_approved=False,
            automation_approval_state=AutomationApprovalState.PENDING,
            proposed_minimum_cadence_hours=6,
        ),
        UaeSourcePolicy(
            source_slug="uae-cyber-security-council-nibras",
            vendor="UAE Cyber Security Council",
            assessed_host="csc.gov.ae",
            assessed_listing_paths=(),
            canonical_metadata_path_pattern=None,
            automated_access_approved=False,
            automation_approval_state=AutomationApprovalState.PENDING,
            proposed_minimum_cadence_hours=None,
        ),
        UaeSourcePolicy(
            source_slug="desc-news",
            vendor="Dubai Electronic Security Center (DESC)",
            assessed_host="www.desc.gov.ae",
            assessed_listing_paths=("/media-hub/news/",),
            canonical_metadata_path_pattern=None,
            automated_access_approved=False,
            automation_approval_state=AutomationApprovalState.PENDING,
            proposed_minimum_cadence_hours=12,
        ),
        UaeSourcePolicy(
            source_slug="desc-published-research",
            vendor="Dubai Electronic Security Center (DESC)",
            assessed_host="www.desc.gov.ae",
            assessed_listing_paths=("/research-innovation/published-research/",),
            canonical_metadata_path_pattern=None,
            automated_access_approved=False,
            automation_approval_state=AutomationApprovalState.PENDING,
            proposed_minimum_cadence_hours=6,
        ),
    )
)


__all__ = [
    "AssessedUrlKind",
    "AutomationApprovalState",
    "MAX_UAE_PATH_SEGMENT_CHARS",
    "MAX_UAE_URL_CHARS",
    "UAE_SOURCE_POLICIES",
    "UaeSourcePolicy",
    "UaeSourcePolicyError",
    "UaeUrlAssessment",
    "UnknownUaeSourcePolicyError",
    "assess_uae_source_url",
    "automated_uae_access_is_approved",
    "classify_assessed_uae_url",
    "get_uae_source_policy",
    "list_uae_source_policies",
    "url_matches_assessed_uae_boundary",
]
