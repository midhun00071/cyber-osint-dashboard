"""Strict, source-neutral contracts for the C01 Prefect orchestration core."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
import re
from types import MappingProxyType
from typing import Mapping, Protocol, runtime_checkable

from app.ingestion.source_registry import (
    AccessMethod,
    ProgressContract,
    get_source_definition,
    list_enabled_implemented_sources,
)


MAX_COUNTER = 2_147_483_647
MAX_ATTEMPTS = 10
MAX_RETRY_DELAY_SECONDS = 3_600
MAX_STAGGER_SECONDS = 300
MAX_EXECUTION_SECONDS = 3_600
MAX_DIAGNOSTIC_LENGTH = 500
MAX_PROGRESS_VALUE_LENGTH = 500
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_SAFE_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_UNSAFE_DIAGNOSTIC = re.compile(
    r"(?:authorization|cookie|set-cookie|password|passwd|api[_-]?key|"
    r"access[_-]?token|bearer\s+|basic\s+|traceback|stack\s+trace|"
    r"(?:select\b.{0,200}\bfrom\b)|(?:insert\s+into\b)|"
    r"(?:update\s+\S+\s+set\b)|(?:delete\s+from\b)|"
    r"(?:alter\s+table\b)|(?:drop\s+(?:table|database)\b))",
    re.IGNORECASE,
)


class ContractValidationError(ValueError):
    """A typed orchestration contract failed closed validation."""


class ResultStatus(str, Enum):
    """Exact operational result vocabulary shared with persistence."""

    SUCCESS = "success"
    NO_CHANGE = "no_change"
    SKIPPED = "skipped"
    DEFERRED_QUOTA = "deferred_quota"
    APPROVAL_PENDING = "approval_pending"
    DISABLED = "disabled"
    CREDENTIALS_MISSING = "credentials_missing"
    LICENCE_REQUIRED = "licence_required"
    RATE_LIMITED = "rate_limited"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CycleStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EligibilityMode(str, Enum):
    SCHEDULED = "scheduled"
    MANUAL_ONLY = "manual_only"
    APPROVAL_REQUIRED = "approval_required"
    DISABLED = "disabled"
    CREDENTIALS_REQUIRED = "credentials_required"
    LICENCE_REQUIRED = "licence_required"


class FailureCategory(str, Enum):
    APPROVED_TIMEOUT = "approved_timeout"
    TEMPORARY_CONNECTION = "temporary_connection"
    PROVIDER_RATE_LIMIT = "provider_rate_limit"
    RETRYABLE_SERVER_RESPONSE = "retryable_server_response"
    PERSISTENCE_CONTENTION = "persistence_contention"
    VALIDATION_FAILURE = "validation_failure"
    UNSUPPORTED_CONTENT = "unsupported_content"
    INVALID_SOURCE_POLICY = "invalid_source_policy"
    MISSING_CREDENTIAL = "missing_credential"
    MISSING_LICENCE = "missing_licence"
    APPROVAL_REQUIREMENT = "approval_requirement"
    UNSAFE_INPUT = "unsafe_input"
    PERMANENT_PROVIDER_REJECTION = "permanent_provider_rejection"
    CONTRACT_VIOLATION = "contract_violation"


_TRANSIENT_FAILURES = frozenset(
    {
        FailureCategory.APPROVED_TIMEOUT,
        FailureCategory.TEMPORARY_CONNECTION,
        FailureCategory.PROVIDER_RATE_LIMIT,
        FailureCategory.RETRYABLE_SERVER_RESPONSE,
        FailureCategory.PERSISTENCE_CONTENTION,
    }
)


class ProgressKind(str, Enum):
    ETAG = "etag"
    LAST_MODIFIED = "last_modified"
    MODIFIED_SINCE = "modified_since"
    SOURCE_CURSOR = "source_cursor"
    PAGINATION_TOKEN = "pagination_token"
    CONTENT_HASH = "content_hash"


class ProgressStorage(str, Enum):
    NONE = "none"
    CHECKPOINT = "checkpoint"
    WATERMARK = "watermark"


class RateState(str, Enum):
    AVAILABLE = "available"
    LIMITED = "limited"
    BACKOFF = "backoff"
    QUOTA_UNAVAILABLE = "quota_unavailable"
    UNKNOWN = "unknown"


def _utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ContractValidationError(f"{field_name} must be timezone-aware.")
    try:
        if value.utcoffset() is None:
            raise ContractValidationError(f"{field_name} must be timezone-aware.")
    except (OverflowError, ValueError) as exc:
        raise ContractValidationError(f"{field_name} is invalid.") from exc
    return value.astimezone(UTC)


def _safe_name(value: str, field_name: str) -> str:
    if not isinstance(value, str) or _SAFE_NAME.fullmatch(value) is None:
        raise ContractValidationError(f"{field_name} is not a safe name.")
    return value


def _safe_slug(value: str) -> str:
    if not isinstance(value, str) or _SAFE_SLUG.fullmatch(value) is None:
        raise ContractValidationError("The source slug is not canonical.")
    try:
        definition = get_source_definition(value)
    except ValueError as exc:
        raise ContractValidationError("The source slug is not registered.") from exc
    return definition.slug


def sanitize_diagnostic(value: str | None) -> str | None:
    """Accept only bounded operational prose, never arbitrary diagnostics."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise ContractValidationError("The diagnostic message is invalid.")
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_DIAGNOSTIC_LENGTH:
        raise ContractValidationError("The diagnostic message is invalid.")
    if any(not character.isprintable() for character in normalized):
        raise ContractValidationError("The diagnostic message is invalid.")
    if _UNSAFE_DIAGNOSTIC.search(normalized) is not None:
        raise ContractValidationError("The diagnostic message is invalid.")
    if "://" in normalized:
        raise ContractValidationError("The diagnostic message is invalid.")
    return normalized


@dataclass(frozen=True, slots=True)
class ReconciledCounters:
    fetched: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped: int = 0
    failed: int = 0
    error_count: int = 0

    def __post_init__(self) -> None:
        values = (
            self.fetched,
            self.created,
            self.updated,
            self.unchanged,
            self.skipped,
            self.failed,
            self.error_count,
        )
        if any(type(value) is not int for value in values):
            raise ContractValidationError("Counters must be integers.")
        if any(value < 0 or value > MAX_COUNTER for value in values):
            raise ContractValidationError("Counters are outside the supported range.")
        if self.fetched != sum(values[1:6]):
            raise ContractValidationError("Counters do not reconcile.")
        if self.error_count < self.failed:
            raise ContractValidationError("Error counters do not reconcile.")


@dataclass(frozen=True, slots=True)
class SafeMetrics:
    duration_ms: int = 0
    request_count: int = 0
    page_count: int = 0

    def __post_init__(self) -> None:
        values = (self.duration_ms, self.request_count, self.page_count)
        if any(type(value) is not int for value in values):
            raise ContractValidationError("Metrics must be integers.")
        if not 0 <= self.duration_ms <= 86_400_000:
            raise ContractValidationError("The duration metric is out of bounds.")
        if not 0 <= self.request_count <= 10_000:
            raise ContractValidationError("The request metric is out of bounds.")
        if not 0 <= self.page_count <= 10_000:
            raise ContractValidationError("The page metric is out of bounds.")


@dataclass(frozen=True, slots=True)
class FailureClassification:
    category: FailureCategory
    transient: bool
    safe_message: str

    def __post_init__(self) -> None:
        if not isinstance(self.category, FailureCategory):
            raise ContractValidationError("The failure category is invalid.")
        if type(self.transient) is not bool:
            raise ContractValidationError("The failure classification is invalid.")
        if self.transient != (self.category in _TRANSIENT_FAILURES):
            raise ContractValidationError("The failure classification is inconsistent.")
        object.__setattr__(self, "safe_message", sanitize_diagnostic(self.safe_message))


class ClassifiedFailure(RuntimeError):
    """A handler-safe failure signal carrying no provider diagnostics."""

    def __init__(self, category: FailureCategory, safe_message: str) -> None:
        self.category = category
        self.safe_message = sanitize_diagnostic(safe_message)
        super().__init__(self.safe_message)


def classify_failure(error: BaseException) -> FailureClassification:
    """Classify only explicit allow-listed signals; unknown failures are permanent."""

    if isinstance(error, ClassifiedFailure):
        category = error.category
        message = error.safe_message or "The source execution failed safely."
    elif isinstance(error, TimeoutError):
        category = FailureCategory.APPROVED_TIMEOUT
        message = "The approved source operation timed out."
    elif isinstance(error, ConnectionError):
        category = FailureCategory.TEMPORARY_CONNECTION
        message = "The approved source connection failed temporarily."
    elif isinstance(error, ContractValidationError):
        category = FailureCategory.VALIDATION_FAILURE
        message = "The source result failed contract validation."
    else:
        category = FailureCategory.CONTRACT_VIOLATION
        message = "The source handler failed without an approved classification."
    return FailureClassification(
        category=category,
        transient=category in _TRANSIENT_FAILURES,
        safe_message=message,
    )


@dataclass(frozen=True, slots=True)
class RetryPlan:
    maximum_attempts: int
    delays_seconds: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.maximum_attempts) is not int or not 1 <= self.maximum_attempts <= MAX_ATTEMPTS:
            raise ContractValidationError("The maximum attempt count is invalid.")
        if len(self.delays_seconds) != self.maximum_attempts - 1:
            raise ContractValidationError("The retry delay count is invalid.")
        previous = 0
        for delay in self.delays_seconds:
            if type(delay) is not int or not 1 <= delay <= MAX_RETRY_DELAY_SECONDS:
                raise ContractValidationError("A retry delay is outside the supported range.")
            if delay < previous:
                raise ContractValidationError("Retry delays must be non-decreasing.")
            previous = delay


@dataclass(frozen=True, slots=True)
class SourcePolicy:
    source_slug: str
    eligibility_mode: EligibilityMode
    source_concurrency_limit: int
    retry_plan: RetryPlan
    stagger_seconds: int
    quota_policy_key: str
    progress_storage: ProgressStorage
    progress_kind: ProgressKind | None
    execution_timeout_seconds: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_slug", _safe_slug(self.source_slug))
        if not isinstance(self.eligibility_mode, EligibilityMode):
            raise ContractValidationError("The eligibility mode is invalid.")
        if self.source_concurrency_limit != 1:
            raise ContractValidationError("Source concurrency must be one.")
        if not isinstance(self.retry_plan, RetryPlan):
            raise ContractValidationError("The retry plan is invalid.")
        if type(self.stagger_seconds) is not int or not 0 <= self.stagger_seconds <= MAX_STAGGER_SECONDS:
            raise ContractValidationError("The stagger delay is invalid.")
        object.__setattr__(
            self,
            "quota_policy_key",
            _safe_name(self.quota_policy_key, "quota_policy_key"),
        )
        if not isinstance(self.progress_storage, ProgressStorage):
            raise ContractValidationError("The progress storage is invalid.")
        if self.progress_storage is ProgressStorage.NONE:
            if self.progress_kind is not None:
                raise ContractValidationError("A no-progress policy cannot name progress.")
        elif not isinstance(self.progress_kind, ProgressKind):
            raise ContractValidationError("The progress kind is invalid.")
        if type(self.execution_timeout_seconds) is not int or not 1 <= self.execution_timeout_seconds <= MAX_EXECUTION_SECONDS:
            raise ContractValidationError("The execution timeout is invalid.")


@dataclass(frozen=True, slots=True)
class SourceEligibility:
    source_slug: str
    request_allowed: bool
    status: ResultStatus | None
    safe_message: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_slug", _safe_slug(self.source_slug))
        if type(self.request_allowed) is not bool:
            raise ContractValidationError("Eligibility must be explicit.")
        if self.request_allowed != (self.status is None):
            raise ContractValidationError("Eligibility status is inconsistent.")
        object.__setattr__(self, "safe_message", sanitize_diagnostic(self.safe_message))


@dataclass(frozen=True, slots=True)
class QuotaObservation:
    policy_key: str
    state: RateState = RateState.UNKNOWN
    state_version: int | None = None
    remaining: int | None = None
    backoff_until: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy_key", _safe_name(self.policy_key, "policy_key"))
        if not isinstance(self.state, RateState):
            raise ContractValidationError("The quota state is invalid.")
        if self.state_version is not None and (
            type(self.state_version) is not int or self.state_version < 1
        ):
            raise ContractValidationError("The quota state version is invalid.")
        if self.remaining is not None and (
            type(self.remaining) is not int or not 0 <= self.remaining <= MAX_COUNTER
        ):
            raise ContractValidationError("The quota remainder is invalid.")
        if self.backoff_until is not None:
            object.__setattr__(self, "backoff_until", _utc(self.backoff_until, "backoff_until"))


def _progress_value(kind: ProgressKind, value: str | datetime) -> str | datetime:
    if kind is ProgressKind.MODIFIED_SINCE:
        if not isinstance(value, datetime):
            raise ContractValidationError("Time progress requires a timestamp.")
        return _utc(value, "progress_value")
    if not isinstance(value, str) or not value or len(value) > MAX_PROGRESS_VALUE_LENGTH:
        raise ContractValidationError("The opaque progress value is invalid.")
    if any(not character.isprintable() for character in value):
        raise ContractValidationError("The opaque progress value is invalid.")
    lowered = value.casefold()
    if any(token in lowered for token in ("authorization", "cookie", "password", "api_key", "access_token")):
        raise ContractValidationError("The opaque progress value is invalid.")
    return value


@dataclass(frozen=True, slots=True)
class ProgressSnapshot:
    storage: ProgressStorage
    kind: ProgressKind
    name: str
    value: str | datetime
    version: int

    def __post_init__(self) -> None:
        if self.storage is ProgressStorage.NONE:
            raise ContractValidationError("A progress snapshot requires storage.")
        if not isinstance(self.kind, ProgressKind):
            raise ContractValidationError("The progress kind is invalid.")
        object.__setattr__(self, "name", _safe_name(self.name, "progress_name"))
        object.__setattr__(self, "value", _progress_value(self.kind, self.value))
        if type(self.version) is not int or self.version < 1:
            raise ContractValidationError("The progress version is invalid.")


@dataclass(frozen=True, slots=True)
class ProgressProposal:
    storage: ProgressStorage
    kind: ProgressKind
    name: str
    value: str | datetime
    expected_previous_version: int

    def __post_init__(self) -> None:
        if self.storage is ProgressStorage.NONE:
            raise ContractValidationError("A progress proposal requires storage.")
        if not isinstance(self.kind, ProgressKind):
            raise ContractValidationError("The progress kind is invalid.")
        object.__setattr__(self, "name", _safe_name(self.name, "progress_name"))
        object.__setattr__(self, "value", _progress_value(self.kind, self.value))
        if type(self.expected_previous_version) is not int or self.expected_previous_version < 0:
            raise ContractValidationError("The expected progress version is invalid.")


@dataclass(frozen=True, slots=True)
class CycleHandle:
    cycle_id: int
    idempotency_key: str
    scheduled_for: datetime

    def __post_init__(self) -> None:
        if type(self.cycle_id) is not int or self.cycle_id < 1:
            raise ContractValidationError("The cycle identity is invalid.")
        if not isinstance(self.idempotency_key, str) or not self.idempotency_key:
            raise ContractValidationError("The cycle key is invalid.")
        object.__setattr__(self, "scheduled_for", _utc(self.scheduled_for, "scheduled_for"))


@dataclass(frozen=True, slots=True)
class SourceAttemptIdentity:
    source_slug: str
    cycle_id: int
    run_id: int
    attempt_number: int
    state_version: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_slug", _safe_slug(self.source_slug))
        if any(type(value) is not int or value < 1 for value in (self.cycle_id, self.run_id, self.state_version)):
            raise ContractValidationError("The source attempt identity is invalid.")
        if type(self.attempt_number) is not int or not 0 <= self.attempt_number < MAX_ATTEMPTS:
            raise ContractValidationError("The source attempt number is invalid.")


@dataclass(frozen=True, slots=True)
class RunHandle:
    identity: SourceAttemptIdentity
    status: str
    counters: ReconciledCounters = field(default_factory=ReconciledCounters)

    def __post_init__(self) -> None:
        if not isinstance(self.identity, SourceAttemptIdentity):
            raise ContractValidationError("The run identity is invalid.")
        if self.status not in {"running", "checkpoint_pending", *(status.value for status in ResultStatus)}:
            raise ContractValidationError("The run status is invalid.")
        if not isinstance(self.counters, ReconciledCounters):
            raise ContractValidationError("The run counters are invalid.")


@dataclass(frozen=True, slots=True)
class SourceExecutionContext:
    policy: SourcePolicy
    attempt: SourceAttemptIdentity
    scheduled_for: datetime
    deployment_ref: str
    progress: ProgressSnapshot | None
    quota: QuotaObservation

    def __post_init__(self) -> None:
        if not isinstance(self.policy, SourcePolicy) or not isinstance(self.attempt, SourceAttemptIdentity):
            raise ContractValidationError("The source execution context is invalid.")
        if self.policy.source_slug != self.attempt.source_slug:
            raise ContractValidationError("The execution source identity conflicts.")
        object.__setattr__(self, "scheduled_for", _utc(self.scheduled_for, "scheduled_for"))
        object.__setattr__(self, "deployment_ref", _safe_name(self.deployment_ref, "deployment_ref"))
        if not isinstance(self.quota, QuotaObservation):
            raise ContractValidationError("The quota observation is invalid.")


@dataclass(frozen=True, slots=True)
class SourceExecutionResult:
    source_slug: str
    status: ResultStatus
    counters: ReconciledCounters = field(default_factory=ReconciledCounters)
    metrics: SafeMetrics = field(default_factory=SafeMetrics)
    safe_message: str = "Source evaluation completed."
    progress_proposal: ProgressProposal | None = None
    failure: FailureClassification | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_slug", _safe_slug(self.source_slug))
        if not isinstance(self.status, ResultStatus):
            raise ContractValidationError("The source result status is invalid.")
        if not isinstance(self.counters, ReconciledCounters) or not isinstance(self.metrics, SafeMetrics):
            raise ContractValidationError("The source result evidence is invalid.")
        object.__setattr__(self, "safe_message", sanitize_diagnostic(self.safe_message))
        if self.progress_proposal is not None and self.status not in {
            ResultStatus.SUCCESS,
            ResultStatus.NO_CHANGE,
        }:
            raise ContractValidationError("Non-success results cannot advance progress.")
        if self.failure is not None and self.status not in {ResultStatus.FAILED, ResultStatus.PARTIAL}:
            raise ContractValidationError("Failure evidence conflicts with the result status.")
        if self.status in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE} and self.failure is not None:
            raise ContractValidationError("A successful result cannot carry failure evidence.")


@dataclass(frozen=True, slots=True)
class CycleEvidence:
    """Latest-attempt operational evidence for one parent cycle."""

    cycle_id: int
    sources_expected: int
    sources_started: int
    sources_completed: int
    sources_successful: int
    sources_non_successful: int
    source_results: tuple[SourceExecutionResult, ...]
    incomplete_source_slugs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        values = (
            self.sources_expected,
            self.sources_started,
            self.sources_completed,
            self.sources_successful,
            self.sources_non_successful,
        )
        if type(self.cycle_id) is not int or self.cycle_id < 1:
            raise ContractValidationError("The cycle evidence identity is invalid.")
        if any(type(value) is not int or not 0 <= value <= 10_000 for value in values):
            raise ContractValidationError("The cycle evidence counters are invalid.")
        if not (
            self.sources_completed <= self.sources_started <= self.sources_expected
            and self.sources_successful + self.sources_non_successful
            == self.sources_completed
            and len(self.source_results) == self.sources_completed
            and len(self.incomplete_source_slugs)
            == self.sources_started - self.sources_completed
        ):
            raise ContractValidationError("The cycle evidence counters do not reconcile.")
        successful = sum(
            result.status in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}
            for result in self.source_results
        )
        if successful != self.sources_successful:
            raise ContractValidationError("The cycle evidence outcomes do not reconcile.")
        incomplete = tuple(_safe_slug(slug) for slug in self.incomplete_source_slugs)
        object.__setattr__(self, "incomplete_source_slugs", incomplete)
        slugs = tuple(result.source_slug for result in self.source_results) + incomplete
        if len(slugs) != len(set(slugs)):
            raise ContractValidationError("The cycle evidence contains duplicate sources.")


@dataclass(frozen=True, slots=True)
class CycleResult:
    cycle_id: int
    status: CycleStatus
    sources_expected: int
    sources_started: int
    sources_completed: int
    sources_successful: int
    sources_non_successful: int
    source_results: tuple[SourceExecutionResult, ...]

    def __post_init__(self) -> None:
        values = (
            self.sources_expected,
            self.sources_started,
            self.sources_completed,
            self.sources_successful,
            self.sources_non_successful,
        )
        if type(self.cycle_id) is not int or self.cycle_id < 1:
            raise ContractValidationError("The cycle identity is invalid.")
        if any(type(value) is not int or value < 0 for value in values):
            raise ContractValidationError("The cycle counters are invalid.")
        if not (
            self.sources_completed <= self.sources_started <= self.sources_expected
            and self.sources_successful + self.sources_non_successful == self.sources_completed
            and len(self.source_results) == self.sources_completed
        ):
            raise ContractValidationError("The cycle counters do not reconcile.")
        successful = sum(
            result.status in {ResultStatus.SUCCESS, ResultStatus.NO_CHANGE}
            for result in self.source_results
        )
        if successful != self.sources_successful:
            raise ContractValidationError("The cycle results do not reconcile.")
        derived_status = (
            CycleStatus.CANCELLED
            if any(result.status is ResultStatus.CANCELLED for result in self.source_results)
            else CycleStatus.SUCCESS
            if self.sources_completed == self.sources_expected
            and self.sources_successful == self.sources_expected
            else CycleStatus.PARTIAL
            if self.sources_successful
            else CycleStatus.FAILED
        )
        if self.status is not derived_status:
            raise ContractValidationError("The cycle status conflicts with source evidence.")


@dataclass(frozen=True, slots=True)
class DeploymentSpecification:
    flow_name: str
    deployment_name: str
    work_pool_name: str
    cron: str
    timezone: str
    concurrency_limit: int
    paused: bool
    deployment_ref: str

    def __post_init__(self) -> None:
        for name in (self.flow_name, self.deployment_name, self.work_pool_name, self.deployment_ref):
            if not isinstance(name, str) or not name or len(name) > 80:
                raise ContractValidationError("A deployment identity is invalid.")
        if self.concurrency_limit != 1 or type(self.paused) is not bool:
            raise ContractValidationError("The deployment concurrency contract is invalid.")
        if self.cron != "17 */2 * * *" or self.timezone != "Asia/Dubai":
            raise ContractValidationError("The deployment schedule contract is invalid.")


@runtime_checkable
class SourceHandler(Protocol):
    """C02 binding contract; handlers own durable source-data transactions."""

    def execute(self, context: SourceExecutionContext) -> SourceExecutionResult: ...

    def reconstruct_progress(
        self,
        context: SourceExecutionContext,
        committed_counters: ReconciledCounters,
    ) -> ProgressProposal: ...


@runtime_checkable
class PersistenceAdapter(Protocol):
    """Transaction-owning boundary used by flow code."""

    def acquire_scheduled_cycle(self, scheduled_for: datetime, sources_expected: int) -> CycleHandle: ...
    def acquire_source_run(self, cycle_id: int, source_slug: str) -> RunHandle: ...
    def acquire_retry(self, prior_run_id: int) -> RunHandle: ...
    def read_progress(self, policy: SourcePolicy) -> ProgressSnapshot | None: ...
    def read_quota(self, policy: SourcePolicy) -> QuotaObservation: ...
    def record_result(self, run: RunHandle, result: SourceExecutionResult) -> RunHandle: ...
    def advance_progress(self, run: RunHandle, proposal: ProgressProposal) -> RunHandle: ...
    def abandon_pending_progress(
        self,
        run: RunHandle,
        status: ResultStatus,
        safe_message: str,
    ) -> RunHandle: ...
    def read_cycle_evidence(self, cycle_id: int) -> CycleEvidence: ...
    def finalize_cycle(self, result: CycleResult, safe_summary: str) -> None: ...


def eligibility_for_policy(policy: SourcePolicy, *, handler_bound: bool) -> SourceEligibility:
    if policy.eligibility_mode is EligibilityMode.MANUAL_ONLY:
        return SourceEligibility(policy.source_slug, False, ResultStatus.APPROVAL_PENDING, "The source remains manual-only pending approval.")
    if policy.eligibility_mode is EligibilityMode.APPROVAL_REQUIRED:
        return SourceEligibility(policy.source_slug, False, ResultStatus.APPROVAL_PENDING, "Scheduled source access requires approval.")
    if policy.eligibility_mode is EligibilityMode.DISABLED:
        return SourceEligibility(policy.source_slug, False, ResultStatus.DISABLED, "Scheduled source access is disabled.")
    if policy.eligibility_mode is EligibilityMode.CREDENTIALS_REQUIRED:
        return SourceEligibility(policy.source_slug, False, ResultStatus.CREDENTIALS_MISSING, "Scheduled source credentials are not configured.")
    if policy.eligibility_mode is EligibilityMode.LICENCE_REQUIRED:
        return SourceEligibility(policy.source_slug, False, ResultStatus.LICENCE_REQUIRED, "Scheduled source access requires a licence.")
    if not handler_bound:
        return SourceEligibility(policy.source_slug, False, ResultStatus.FAILED, "The scheduled source handler is not bound.")
    return SourceEligibility(policy.source_slug, True, None, "The source is eligible for scheduled execution.")


def _policy_for(source, index: int) -> SourcePolicy:
    manual_only = source.access_method is AccessMethod.MANUAL_CATALOGUE
    storage = {
        ProgressContract.NONE: ProgressStorage.NONE,
        ProgressContract.CHECKPOINT: ProgressStorage.CHECKPOINT,
        ProgressContract.WATERMARK: ProgressStorage.WATERMARK,
    }[source.progress_contract]
    if storage is ProgressStorage.CHECKPOINT:
        kind = ProgressKind.CONTENT_HASH if source.slug == "cisa-kev" else ProgressKind.SOURCE_CURSOR
    elif storage is ProgressStorage.WATERMARK:
        kind = ProgressKind.MODIFIED_SINCE
    else:
        kind = None
    return SourcePolicy(
        source_slug=source.slug,
        eligibility_mode=EligibilityMode.MANUAL_ONLY if manual_only else EligibilityMode.SCHEDULED,
        source_concurrency_limit=1,
        retry_plan=RetryPlan(maximum_attempts=3, delays_seconds=(30, 60)),
        stagger_seconds=min(index * 5, MAX_STAGGER_SECONDS),
        quota_policy_key=f"{source.slug}.scheduled",
        progress_storage=storage,
        progress_kind=kind,
        execution_timeout_seconds=900,
    )


def build_source_policies(policies: tuple[SourcePolicy, ...]) -> Mapping[str, SourcePolicy]:
    enabled = {source.slug for source in list_enabled_implemented_sources()}
    built: dict[str, SourcePolicy] = {}
    for policy in policies:
        if not isinstance(policy, SourcePolicy):
            raise ContractValidationError("A source policy is invalid.")
        if policy.source_slug in built:
            raise ContractValidationError("A source policy slug is duplicated.")
        built[policy.source_slug] = policy
    if set(built) != enabled:
        raise ContractValidationError("Enabled implemented sources require exactly one policy.")
    return MappingProxyType(dict(sorted(built.items())))


SOURCE_POLICIES = build_source_policies(
    tuple(
        _policy_for(source, index)
        for index, source in enumerate(list_enabled_implemented_sources())
    )
)


def list_source_policies() -> tuple[SourcePolicy, ...]:
    return tuple(SOURCE_POLICIES.values())


__all__ = [
    "ClassifiedFailure",
    "ContractValidationError",
    "CycleEvidence",
    "CycleHandle",
    "CycleResult",
    "CycleStatus",
    "DeploymentSpecification",
    "EligibilityMode",
    "FailureCategory",
    "FailureClassification",
    "PersistenceAdapter",
    "ProgressKind",
    "ProgressProposal",
    "ProgressSnapshot",
    "ProgressStorage",
    "QuotaObservation",
    "RateState",
    "ReconciledCounters",
    "ResultStatus",
    "RetryPlan",
    "RunHandle",
    "SafeMetrics",
    "SOURCE_POLICIES",
    "SourceAttemptIdentity",
    "SourceEligibility",
    "SourceExecutionContext",
    "SourceExecutionResult",
    "SourceHandler",
    "SourcePolicy",
    "build_source_policies",
    "classify_failure",
    "eligibility_for_policy",
    "list_source_policies",
    "sanitize_diagnostic",
]
