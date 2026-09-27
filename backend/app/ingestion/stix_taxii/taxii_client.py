"""Fixed-policy synchronous TAXII 2.1 collection client."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
import logging
import math
import threading
from types import MappingProxyType
from typing import Callable, Mapping
import time

import httpx

from app.ingestion.stix_taxii.bounded_json import (
    BoundedStixDocument,
    StixBoundedJsonError,
    StixDocumentFormat,
    StixTaxiiPaginationJsonError,
    parse_stix_json_bytes,
    thaw_json,
    validate_bounded_json_tree,
)
from app.ingestion.stix_taxii.policy import (
    ApprovedStixSourcePolicy,
    ApprovedTaxiiCollectionPolicy,
    MITRE_ATTACK_ENTERPRISE_STIX_POLICY,
    MITRE_ATTACK_ENTERPRISE_TAXII_POLICY,
    PRODUCTION_TAXII_COLLECTION_POLICIES,
    StixPolicyError,
    UnknownStixSourceError,
    validate_taxii_collection_policy,
)
from app.ingestion.stix_taxii.stix_validation import (
    StixValidationError,
    ValidatedStixDocument,
    validate_stix_document,
)


USER_AGENT = "Cyber-Sentinel-OSINT/0.1 TAXII-2.1-Client"
ACCEPT_HEADER = "application/taxii+json;version=2.1"
ACCEPT_ENCODING_HEADER = "identity"
_REDIRECT_STATUS_CODES = frozenset({300, 301, 302, 303, 304, 305, 306, 307, 308})
_HTTP_LOGGER_NAMES = (
    "httpx",
    "httpcore",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
)
MITRE_ATTACK_ENTERPRISE_SOURCE_SLUG = "mitre-attack-enterprise"


class TaxiiClientError(Exception):
    """Base class for sanitized fixed-policy TAXII failures."""


class TaxiiConfigurationError(TaxiiClientError, ValueError):
    """The controlled client or approved policy could not be configured."""


class TaxiiTransportError(TaxiiClientError):
    """The request failed at the HTTP transport boundary."""


class TaxiiTimeoutError(TaxiiTransportError):
    """A request or the total collection deadline expired."""


class TaxiiRateLimitError(TaxiiClientError):
    """The approved TAXII service returned HTTP 429."""


class TaxiiHttpStatusError(TaxiiClientError):
    """The approved TAXII service returned an unsuccessful status."""


class TaxiiRedirectError(TaxiiClientError):
    """A redirect response or changed response URL was rejected."""


class TaxiiContentTypeError(TaxiiClientError):
    """The response did not use the exact TAXII 2.1 JSON media type."""


class TaxiiContentEncodingError(TaxiiClientError):
    """The response used a content encoding outside the fixed safe policy."""


class TaxiiRequestPolicyError(TaxiiClientError):
    """The authenticated request failed the pre-transport policy guard."""


class TaxiiResponseTooLargeError(TaxiiClientError):
    """A response or the collection exceeded its byte policy."""


class TaxiiPaginationError(TaxiiClientError):
    """A pagination invariant failed closed."""


class TaxiiEnvelopeError(TaxiiClientError):
    """A TAXII response envelope failed bounded parsing."""


class TaxiiStixValidationError(TaxiiClientError):
    """The complete collected STIX document failed semantic validation."""


@dataclass(frozen=True, slots=True)
class TaxiiCollectionResult:
    """Immutable safe counters and validated output for one collection run."""

    pages_collected: int
    response_bytes_collected: int
    objects_received: int
    objects_validated: int
    pagination_complete: bool
    validated_document: ValidatedStixDocument
    greatest_server_date_added: str | None = None


class _CollectionThreadLogFilter(logging.Filter):
    """Reject HTTP transport records created or handled by this collection thread."""

    __slots__ = ("_thread_id",)

    def __init__(self) -> None:
        super().__init__()
        self._thread_id = threading.get_ident()

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            return (
                threading.get_ident() != self._thread_id
                and getattr(record, "thread", None) != self._thread_id
            )
        except Exception:
            return False


class _ScopedHttpLoggingIsolation:
    """Temporarily isolate third-party HTTP logs for one collection thread."""

    __slots__ = ("_filter", "_loggers")

    def __init__(self) -> None:
        self._filter = _CollectionThreadLogFilter()
        self._loggers: list[logging.Logger] = []

    def __enter__(self) -> None:
        try:
            for name in _HTTP_LOGGER_NAMES:
                logger = logging.getLogger(name)
                self._loggers.append(logger)
                logger.addFilter(self._filter)
        except Exception:
            self._remove_filters()
            raise TaxiiConfigurationError(
                "TAXII HTTP logging could not be isolated safely."
            ) from None

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        del exc_type, exc, traceback
        if not self._remove_filters():
            raise TaxiiTransportError(
                "TAXII HTTP logging isolation could not be released safely."
            ) from None
        return False

    def _remove_filters(self) -> bool:
        clean = True
        for logger in reversed(self._loggers):
            try:
                logger.removeFilter(self._filter)
            except Exception:
                clean = False
            if any(item is self._filter for item in logger.filters):
                clean = False
                try:
                    logger.filters[:] = [
                        item for item in logger.filters if item is not self._filter
                    ]
                except Exception:
                    pass
            if any(item is self._filter for item in logger.filters):
                clean = False
        self._loggers.clear()
        return clean


class _PreTransportRequestGuard:
    """Validate the authenticated request immediately before transport."""

    __slots__ = (
        "_auth_enabled",
        "_expected_timeout",
        "_expected_url",
        "_policy",
        "_ready",
    )

    def __init__(
        self,
        policy: ApprovedTaxiiCollectionPolicy,
        *,
        auth_enabled: bool,
    ) -> None:
        self._policy = policy
        self._auth_enabled = auth_enabled
        self._expected_url: httpx.URL | None = None
        self._expected_timeout: dict[str, float] | None = None
        self._ready = False

    def arm(
        self,
        *,
        params: tuple[tuple[str, str], ...],
        timeout: httpx.Timeout,
    ) -> None:
        if self._ready:
            raise TaxiiRequestPolicyError(
                "A TAXII request failed pre-transport policy validation."
            )
        self._expected_url = httpx.URL(self._policy.objects_endpoint, params=params)
        self._expected_timeout = timeout.as_dict()
        self._ready = True

    def __call__(self, request: httpx.Request) -> None:
        try:
            self._validate(request)
        except TaxiiRequestPolicyError:
            raise
        except Exception:
            raise TaxiiRequestPolicyError(
                "A TAXII request failed pre-transport policy validation."
            ) from None
        self._ready = False

    def _validate(self, request: httpx.Request) -> None:
        expected_url = self._expected_url
        expected_timeout = self._expected_timeout
        if not self._ready or expected_url is None or expected_timeout is None:
            raise TaxiiRequestPolicyError(
                "A TAXII request failed pre-transport policy validation."
            )
        if request.method != "GET" or request.url != expected_url:
            raise TaxiiRequestPolicyError(
                "A TAXII request failed pre-transport policy validation."
            )
        expected_query = list(expected_url.params.multi_items())
        if list(request.url.params.multi_items()) != expected_query:
            raise TaxiiRequestPolicyError(
                "A TAXII request failed pre-transport policy validation."
            )
        expected_headers = {
            "host": expected_url.host,
            "accept": ACCEPT_HEADER,
            "user-agent": USER_AGENT,
            "accept-encoding": ACCEPT_ENCODING_HEADER,
        }
        header_pairs = request.headers.multi_items()
        if self._auth_enabled:
            authorization = request.headers.get("authorization")
            if (
                not isinstance(authorization, str)
                or not authorization.startswith("Basic ")
                or len(authorization) <= len("Basic ")
                or not authorization.isascii()
                or any(character.isspace() for character in authorization[6:])
            ):
                raise TaxiiRequestPolicyError(
                    "A TAXII request failed pre-transport policy validation."
                )
            expected_headers["authorization"] = authorization
        if (
            len(header_pairs) != len(expected_headers)
            or {name for name, _ in header_pairs} != set(expected_headers)
            or any(value != expected_headers[name] for name, value in header_pairs)
        ):
            raise TaxiiRequestPolicyError(
                "A TAXII request failed pre-transport policy validation."
            )
        if set(request.extensions) != {"timeout"}:
            raise TaxiiRequestPolicyError(
                "A TAXII request failed pre-transport policy validation."
            )
        actual_timeout = request.extensions.get("timeout")
        if (
            not isinstance(actual_timeout, dict)
            or set(actual_timeout) != {"connect", "read", "write", "pool"}
            or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) <= 0
                or float(value) != expected_timeout[name]
                for name, value in actual_timeout.items()
            )
        ):
            raise TaxiiRequestPolicyError(
                "A TAXII request failed pre-transport policy validation."
            )


def _exact_canonical_field(value: object, canonical: object) -> bool:
    if type(value) is not type(canonical):
        return False
    if type(canonical) is tuple:
        return len(value) == len(canonical) and all(
            _exact_canonical_field(item, expected)
            for item, expected in zip(value, canonical, strict=True)
        )
    if type(canonical) is frozenset:
        return all(type(item) is str for item in value) and value == canonical
    return value == canonical


def _stix_policy_signature(policy: ApprovedStixSourcePolicy) -> tuple[object, ...]:
    return (
        policy.source_slug,
        policy.allowed_transport,
        policy.policy_base_url,
        policy.allowed_stix_types,
        policy.allowed_relationship_types,
        policy.allowed_tlp_levels,
        policy.allowed_kill_chain_phases,
        policy.allowed_custom_properties,
        policy.allow_statement_markings,
        policy.expected_source_enabled,
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


def _taxii_policy_signature(
    policy: ApprovedTaxiiCollectionPolicy,
) -> tuple[object, ...]:
    return (
        policy.api_root_url,
        policy.collection_id,
        policy.collection_title,
        policy.fixed_query_parameters,
        policy.authentication_allowed,
        policy.allow_incremental_relationship_references,
        policy.maximum_response_bytes,
        policy.maximum_total_response_bytes,
        policy.maximum_pages,
        policy.maximum_requests,
        policy.maximum_total_objects,
        policy.maximum_pagination_token_length,
        policy.connect_timeout_seconds,
        policy.read_timeout_seconds,
        policy.write_timeout_seconds,
        policy.pool_timeout_seconds,
        policy.total_collection_deadline_seconds,
    )


def validate_mitre_attack_policy_entry(
    source_slug: object,
    policy: object,
) -> ApprovedTaxiiCollectionPolicy:
    """Return the trusted MITRE policy after exact-type canonical validation."""

    if (
        type(source_slug) is not str
        or source_slug != MITRE_ATTACK_ENTERPRISE_SOURCE_SLUG
        or type(policy) is not ApprovedTaxiiCollectionPolicy
        or type(policy.stix_policy) is not ApprovedStixSourcePolicy
    ):
        raise TaxiiConfigurationError("The MITRE ATT&CK TAXII policy is invalid.")
    canonical = MITRE_ATTACK_ENTERPRISE_TAXII_POLICY
    canonical_stix = MITRE_ATTACK_ENTERPRISE_STIX_POLICY
    if not _exact_canonical_field(
        _stix_policy_signature(policy.stix_policy),
        _stix_policy_signature(canonical_stix),
    ) or not _exact_canonical_field(
        _taxii_policy_signature(policy),
        _taxii_policy_signature(canonical),
    ):
        raise TaxiiConfigurationError("The MITRE ATT&CK TAXII policy is invalid.")
    if policy.stix_policy != canonical_stix or policy != canonical:
        raise TaxiiConfigurationError("The MITRE ATT&CK TAXII policy is invalid.")
    return canonical


def validate_c05_mitre_policy_registry(
    policy_registry: object,
) -> MappingProxyType[str, ApprovedTaxiiCollectionPolicy]:
    """Validate and snapshot the exact one-entry inactive C05 registry."""

    if not isinstance(policy_registry, MappingProxyType) or len(policy_registry) != 1:
        raise TaxiiConfigurationError("The MITRE ATT&CK TAXII policy is invalid.")
    source_slug, policy = next(iter(policy_registry.items()))
    canonical = validate_mitre_attack_policy_entry(source_slug, policy)
    return MappingProxyType({MITRE_ATTACK_ENTERPRISE_SOURCE_SLUG: canonical})


def _declares_mitre_policy(source_slug: object, policy: object) -> bool:
    if isinstance(source_slug, str) and str.__eq__(
        source_slug, MITRE_ATTACK_ENTERPRISE_SOURCE_SLUG
    ) is True:
        return True
    if not isinstance(policy, ApprovedTaxiiCollectionPolicy):
        return False
    stix_policy = policy.stix_policy
    return (
        isinstance(stix_policy, ApprovedStixSourcePolicy)
        and isinstance(stix_policy.source_slug, str)
        and str.__eq__(
            stix_policy.source_slug,
            MITRE_ATTACK_ENTERPRISE_SOURCE_SLUG,
        )
        is True
    )


class TaxiiCollectionClient:
    """Collect one source selected only through an immutable policy registry."""

    def __init__(
        self,
        *,
        policy_registry: Mapping[str, ApprovedTaxiiCollectionPolicy] = (
            PRODUCTION_TAXII_COLLECTION_POLICIES
        ),
        http_transport: httpx.BaseTransport | None = None,
        auth: httpx.BasicAuth | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(policy_registry, MappingProxyType):
            raise TaxiiConfigurationError("The TAXII policy registry is invalid.")
        normalized: dict[str, ApprovedTaxiiCollectionPolicy] = {}
        try:
            for source_slug, policy in policy_registry.items():
                approved = (
                    validate_mitre_attack_policy_entry(source_slug, policy)
                    if _declares_mitre_policy(source_slug, policy)
                    else validate_taxii_collection_policy(policy)
                )
                if source_slug != approved.source_slug:
                    raise StixPolicyError("TAXII registry identity is invalid.")
                normalized[source_slug] = approved
        except (StixPolicyError, TypeError, ValueError):
            raise TaxiiConfigurationError(
                "The TAXII policy registry is invalid."
            ) from None
        if http_transport is not None and not isinstance(
            http_transport, httpx.BaseTransport
        ):
            raise TaxiiConfigurationError("The TAXII HTTP transport is invalid.")
        if auth is not None and type(auth) is not httpx.BasicAuth:
            raise TaxiiConfigurationError("The TAXII authentication type is invalid.")
        if not callable(monotonic_clock):
            raise TaxiiConfigurationError("The TAXII monotonic clock is invalid.")
        self._policy_registry = MappingProxyType(normalized)
        self._http_transport = http_transport
        self._auth = auth
        self._clock = monotonic_clock
        self._last_clock: float | None = None

    def collect(
        self,
        source_slug: str,
    ) -> TaxiiCollectionResult:
        """Collect an initial or non-incremental exact approved source."""

        return self.collect_incremental(source_slug, added_after=None)

    def collect_incremental(
        self,
        source_slug: str,
        *,
        added_after: str | None = None,
    ) -> TaxiiCollectionResult:
        """Collect and validate one exact approved source without discovery."""

        policy = self._policy_for_source(source_slug)
        if self._auth is not None and not policy.authentication_allowed:
            raise TaxiiConfigurationError(
                "Authentication is prohibited for this TAXII source."
            )
        canonical_added_after = (
            None
            if added_after is None
            else canonical_taxii_timestamp(added_after)
        )
        started = self._read_clock()
        deadline = started + policy.total_collection_deadline_seconds
        request_guard = _PreTransportRequestGuard(
            policy,
            auth_enabled=self._auth is not None,
        )
        try:
            with _ScopedHttpLoggingIsolation():
                with httpx.Client(
                    auth=self._auth,
                    timeout=_request_timeout(
                        policy,
                        policy.total_collection_deadline_seconds,
                    ),
                    follow_redirects=False,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": ACCEPT_HEADER,
                        "Accept-Encoding": ACCEPT_ENCODING_HEADER,
                    },
                    event_hooks={"request": [request_guard]},
                    transport=self._http_transport,
                    trust_env=False,
                ) as client:
                    client.headers.pop("Connection", None)
                    return self._collect_with_client(
                        client,
                        policy,
                        deadline,
                        request_guard,
                        added_after=canonical_added_after,
                    )
        except (TaxiiClientError, UnknownStixSourceError):
            raise
        except httpx.TimeoutException:
            raise TaxiiTimeoutError("A TAXII collection request timed out.") from None
        except httpx.TransportError:
            raise TaxiiTransportError(
                "A TAXII collection request failed during transport."
            ) from None
        except Exception:
            raise TaxiiTransportError(
                "A TAXII collection request failed during transport."
            ) from None

    def _policy_for_source(self, source_slug: str) -> ApprovedTaxiiCollectionPolicy:
        if not isinstance(source_slug, str):
            raise UnknownStixSourceError("TAXII source is not approved.")
        try:
            return self._policy_registry[source_slug]
        except KeyError:
            raise UnknownStixSourceError("TAXII source is not approved.") from None

    def _collect_with_client(
        self,
        client: httpx.Client,
        policy: ApprovedTaxiiCollectionPolicy,
        deadline: float,
        request_guard: _PreTransportRequestGuard,
        *,
        added_after: str | None,
    ) -> TaxiiCollectionResult:
        pages: list[BoundedStixDocument] = []
        total_bytes = 0
        total_objects = 0
        next_token: str | None = None
        seen_tokens: set[str] = set()
        seen_response_hashes: set[str] = set()
        seen_page_hashes: set[str] = set()
        seen_object_hashes: set[str] = set()
        greatest_server_date_added: str | None = None
        request_count = 0

        while True:
            if len(pages) >= policy.maximum_pages:
                raise TaxiiPaginationError("TAXII pagination exceeded the page limit.")
            if request_count >= policy.maximum_requests:
                raise TaxiiPaginationError("TAXII pagination exceeded the request limit.")
            remaining = self._remaining(deadline)
            params = list(policy.fixed_query_parameters)
            if added_after is not None:
                params.append(("added_after", added_after))
            if next_token is not None:
                params.append(("next", next_token))
            body, server_date_added = self._request_page(
                client,
                policy,
                params=tuple(params),
                remaining=remaining,
                deadline=deadline,
                total_bytes=total_bytes,
                request_guard=request_guard,
            )
            request_count += 1
            if server_date_added is not None:
                if added_after is not None and server_date_added < added_after:
                    raise TaxiiEnvelopeError(
                        "The TAXII server date-added boundary regressed."
                    )
                if (
                    greatest_server_date_added is None
                    or server_date_added > greatest_server_date_added
                ):
                    greatest_server_date_added = server_date_added
            total_bytes += len(body)
            response_identity = sha256(body).hexdigest()
            if response_identity in seen_response_hashes:
                raise TaxiiPaginationError("TAXII pagination repeated a page.")
            seen_response_hashes.add(response_identity)
            try:
                page = parse_stix_json_bytes(
                    body,
                    policy.stix_policy,
                    StixDocumentFormat.TAXII_ENVELOPE,
                )
            except StixTaxiiPaginationJsonError:
                raise TaxiiPaginationError(
                    "TAXII pagination metadata is invalid."
                ) from None
            except StixBoundedJsonError:
                raise TaxiiEnvelopeError(
                    "A TAXII response envelope failed bounded validation."
                ) from None
            page_identity = _page_object_identity(page)
            if page_identity in seen_page_hashes:
                raise TaxiiPaginationError("TAXII pagination repeated a page.")
            seen_page_hashes.add(page_identity)
            if not page.objects and (page.more is True or pages):
                raise TaxiiPaginationError("TAXII pagination made no progress.")
            object_hashes = {_object_identity(item) for item in page.objects}
            if pages and object_hashes and object_hashes <= seen_object_hashes:
                raise TaxiiPaginationError("TAXII pagination made no progress.")
            seen_object_hashes.update(object_hashes)
            total_objects += len(page.objects)
            if total_objects > policy.maximum_total_objects:
                raise TaxiiPaginationError("TAXII pagination exceeded the object limit.")
            pages.append(page)

            if page.more is True:
                token = page.next_token
                if not _safe_next_token(token, policy.maximum_pagination_token_length):
                    raise TaxiiPaginationError("TAXII pagination metadata is invalid.")
                assert token is not None
                if token in seen_tokens:
                    raise TaxiiPaginationError("TAXII pagination repeated a token.")
                seen_tokens.add(token)
                next_token = token
                self._remaining(deadline)
                continue
            if page.next_token is not None:
                raise TaxiiPaginationError("TAXII pagination metadata is invalid.")
            break

        combined = BoundedStixDocument(
            document_format=StixDocumentFormat.TAXII_ENVELOPE,
            objects=tuple(item for page in pages for item in page.objects),
            more=False,
            next_token=None,
        )
        try:
            validate_bounded_json_tree(
                {"objects": combined.objects},
                policy.stix_policy,
            )
        except StixBoundedJsonError:
            raise TaxiiEnvelopeError(
                "The collected TAXII document exceeded aggregate JSON limits."
            ) from None
        try:
            validated = validate_stix_document(
                combined,
                policy.stix_policy,
                allow_unresolved_relationships=(
                    policy.allow_incremental_relationship_references
                ),
            )
        except StixValidationError:
            raise TaxiiStixValidationError(
                "The collected STIX document failed semantic validation."
            ) from None
        self._remaining(deadline)
        return TaxiiCollectionResult(
            pages_collected=len(pages),
            response_bytes_collected=total_bytes,
            objects_received=total_objects,
            objects_validated=validated.objects_validated,
            pagination_complete=True,
            validated_document=validated,
            greatest_server_date_added=greatest_server_date_added,
        )

    def _request_page(
        self,
        client: httpx.Client,
        policy: ApprovedTaxiiCollectionPolicy,
        *,
        params: tuple[tuple[str, str], ...],
        remaining: float,
        deadline: float,
        total_bytes: int,
        request_guard: _PreTransportRequestGuard,
    ) -> tuple[bytes, str | None]:
        timeout = _request_timeout(policy, remaining)
        request_guard.arm(params=params, timeout=timeout)
        try:
            with client.stream(
                "GET",
                policy.objects_endpoint,
                params=params,
                follow_redirects=False,
                timeout=timeout,
            ) as response:
                self._remaining(deadline)
                _validate_response_url(response.url, policy, params)
                if response.status_code in _REDIRECT_STATUS_CODES:
                    raise TaxiiRedirectError("A TAXII redirect response was rejected.")
                if response.status_code == 429:
                    raise TaxiiRateLimitError("The TAXII service rate limited the request.")
                if response.status_code != 200:
                    raise TaxiiHttpStatusError(
                        "The TAXII service returned an unsuccessful response."
                    )
                if not _is_identity_content_encoding(
                    response.headers.get("content-encoding")
                ):
                    raise TaxiiContentEncodingError(
                        "A TAXII response used an invalid content encoding."
                    )
                if not _is_taxii_21_content_type(response.headers.get("content-type")):
                    raise TaxiiContentTypeError(
                        "A TAXII response used an invalid content type."
                    )
                content_length = _content_length(response.headers.get("content-length"))
                remaining_total = policy.maximum_total_response_bytes - total_bytes
                if content_length is not None and (
                    content_length > policy.maximum_response_bytes
                    or content_length > remaining_total
                ):
                    raise TaxiiResponseTooLargeError(
                        "A TAXII response exceeded the allowed size."
                    )
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_raw():
                    self._remaining(deadline)
                    size += len(chunk)
                    if (
                        size > policy.maximum_response_bytes
                        or size > remaining_total
                    ):
                        raise TaxiiResponseTooLargeError(
                            "A TAXII response exceeded the allowed size."
                        )
                    chunks.append(chunk)
                    self._remaining(deadline)
                self._remaining(deadline)
                boundary = _taxii_date_added_boundary(response.headers)
                return b"".join(chunks), boundary
        except TaxiiClientError:
            raise
        except httpx.TimeoutException:
            raise TaxiiTimeoutError("A TAXII collection request timed out.") from None
        except httpx.TransportError:
            raise TaxiiTransportError(
                "A TAXII collection request failed during transport."
            ) from None
        except Exception:
            raise TaxiiTransportError(
                "A TAXII collection request failed during transport."
            ) from None
        finally:
            try:
                client.cookies.clear()
            except Exception:
                raise TaxiiTransportError(
                    "TAXII request state could not be isolated safely."
                ) from None

    def _read_clock(self) -> float:
        try:
            value = self._clock()
        except Exception:
            raise TaxiiTimeoutError(
                "The TAXII collection deadline could not be enforced."
            ) from None
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or self._last_clock is not None
            and float(value) < self._last_clock
        ):
            raise TaxiiTimeoutError("The TAXII collection deadline could not be enforced.")
        self._last_clock = float(value)
        return self._last_clock

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._read_clock()
        if not math.isfinite(remaining) or remaining <= 0:
            raise TaxiiTimeoutError("The TAXII collection exceeded its total deadline.")
        return remaining


def collect_production_taxii_collection(
    source_slug: str,
    *,
    auth: httpx.BasicAuth | None = None,
) -> TaxiiCollectionResult:
    """Collect one production source through the intentionally closed registry."""

    return TaxiiCollectionClient(auth=auth).collect(source_slug)


def _request_timeout(
    policy: ApprovedTaxiiCollectionPolicy,
    remaining: float,
) -> httpx.Timeout:
    return httpx.Timeout(
        min(policy.read_timeout_seconds, remaining),
        connect=min(policy.connect_timeout_seconds, remaining),
        read=min(policy.read_timeout_seconds, remaining),
        write=min(policy.write_timeout_seconds, remaining),
        pool=min(policy.pool_timeout_seconds, remaining),
    )


def _is_taxii_21_content_type(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or any(ord(character) < 0x20 and character != "\t" for character in value)
        or "\x7f" in value
    ):
        return False
    parts = value.split(";")
    if parts[0].strip().lower() != "application/taxii+json" or len(parts) != 2:
        return False
    parameter = parts[1]
    if parameter.count("=") != 1:
        return False
    name, parameter_value = (part.strip() for part in parameter.split("=", 1))
    if name.lower() != "version":
        return False
    if parameter_value.startswith('"') or parameter_value.endswith('"'):
        if len(parameter_value) < 2 or not (
            parameter_value.startswith('"') and parameter_value.endswith('"')
        ):
            return False
        parameter_value = parameter_value[1:-1]
    return parameter_value == "2.1"


def _is_identity_content_encoding(value: object) -> bool:
    if value is None:
        return True
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or any(ord(character) < 0x20 and character != "\t" for character in value)
        or "\x7f" in value
        or "," in value
        or ";" in value
    ):
        return False
    return value.strip().lower() == "identity"


def _content_length(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise TaxiiTransportError("TAXII response metadata was invalid.")
    try:
        return int(value)
    except ValueError:
        raise TaxiiTransportError("TAXII response metadata was invalid.") from None


def _safe_next_token(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and value.isascii()
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _validate_response_url(
    url: httpx.URL,
    policy: ApprovedTaxiiCollectionPolicy,
    params: tuple[tuple[str, str], ...],
) -> None:
    expected = httpx.URL(policy.objects_endpoint, params=params)
    if url != expected:
        raise TaxiiRedirectError("A TAXII response URL failed validation.")


def canonical_taxii_timestamp(value: object) -> str:
    """Return a canonical UTC RFC 3339 cursor value or fail safely."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > 100
        or value != value.strip()
        or not value.isascii()
    ):
        raise TaxiiEnvelopeError("A TAXII server date-added value was invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise TaxiiEnvelopeError(
            "A TAXII server date-added value was invalid."
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TaxiiEnvelopeError("A TAXII server date-added value was invalid.")
    utc_value = parsed.astimezone(UTC)
    return utc_value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _taxii_date_added_boundary(headers: httpx.Headers) -> str | None:
    values = headers.get_list("x-taxii-date-added-last")
    if not values:
        return None
    if len(values) != 1 or "," in values[0]:
        raise TaxiiEnvelopeError(
            "TAXII server date-added response metadata was invalid."
        )
    return canonical_taxii_timestamp(values[0])


def _page_object_identity(page: BoundedStixDocument) -> str:
    objects = [thaw_json(item) for item in page.objects]
    encoded = json.dumps(
        objects,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _object_identity(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        thaw_json(value),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest()
