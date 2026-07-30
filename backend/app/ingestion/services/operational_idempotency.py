"""Deterministic, non-secret identities for B1-04 operational persistence."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import re


class OperationalIdentityValidationError(ValueError):
    """A deterministic identity input is invalid."""


_VERSION = "b104-v1"
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_SAFE_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SAFE_ACTION = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_LOCK_NAMESPACES = frozenset(
    {"cycle-idempotency", "source-no-overlap", "progress-identity", "rate-state-identity"}
)
_MAX_MANUAL_KEY_BYTES = 512


def _canonical_digest(namespace: str, fields: dict[str, object]) -> str:
    payload = json.dumps(
        {"namespace": f"{_VERSION}:{namespace}", **fields},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _database_key(prefix: str, namespace: str, fields: dict[str, object]) -> str:
    return f"{prefix}{_canonical_digest(namespace, fields)}"


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise OperationalIdentityValidationError("A timezone-aware timestamp is required.")
    try:
        offset = value.utcoffset()
    except Exception as exc:
        raise OperationalIdentityValidationError(
            "A timezone-aware timestamp is required."
        ) from exc
    if value.tzinfo is None or offset is None:
        raise OperationalIdentityValidationError("A timezone-aware timestamp is required.")
    return value.astimezone(UTC)


def _safe_reference(value: object) -> str:
    if not isinstance(value, str) or _SAFE_REFERENCE.fullmatch(value) is None:
        raise OperationalIdentityValidationError("A safe deployment reference is required.")
    return value


def _source_slug(value: object) -> str:
    if not isinstance(value, str) or len(value) > 80 or _SAFE_SLUG.fullmatch(value) is None:
        raise OperationalIdentityValidationError("A safe source slug is required.")
    return value


def _action(value: object) -> str:
    if not isinstance(value, str) or _SAFE_ACTION.fullmatch(value) is None:
        raise OperationalIdentityValidationError("A safe action name is required.")
    return value


def _manual_key(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise OperationalIdentityValidationError("A manual request key is required.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise OperationalIdentityValidationError("A manual request key is invalid.") from exc
    if len(encoded) > _MAX_MANUAL_KEY_BYTES or any(
        char == "\x00" or ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise OperationalIdentityValidationError("A manual request key is invalid.")
    return value


def _attempt(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 10:
        raise OperationalIdentityValidationError("An attempt number from 0 through 10 is required.")
    return value


def build_scheduled_cycle_key(deployment_ref: str, scheduled_for: datetime) -> str:
    """Build a stable scheduled-cycle database key."""

    deployment = _safe_reference(deployment_ref)
    slot = _aware_utc(scheduled_for).isoformat(timespec="microseconds")
    return _database_key("b104cs-", "scheduled-cycle", {"deployment": deployment, "slot": slot})


def build_manual_cycle_key(manual_request_key: str) -> str:
    """Build a stable manual-cycle key without retaining the opaque input."""

    request_key = _manual_key(manual_request_key)
    return _database_key("b104cm-", "manual-cycle", {"request_sha256": hashlib.sha256(request_key.encode("utf-8")).hexdigest()})


def build_source_attempt_run_key(cycle_key: str, source_slug: str, attempt_number: int) -> str:
    """Build the source/cycle/attempt identity used by operational runs."""

    if not isinstance(cycle_key, str) or not re.fullmatch(r"b104c[sm]-[0-9a-f]{64}", cycle_key):
        raise OperationalIdentityValidationError("A valid cycle identity is required.")
    return _database_key(
        "b104r-",
        "source-attempt",
        {"cycle_sha256": hashlib.sha256(cycle_key.encode("ascii")).hexdigest(), "source": _source_slug(source_slug), "attempt": _attempt(attempt_number)},
    )


def build_audit_event_key(action: str, target_key: str) -> str:
    """Build a B1-04 audit-event identity from allow-listed safe inputs."""

    safe_action = _action(action)
    if not isinstance(target_key, str) or re.fullmatch(r"b104[a-z]*-[0-9a-f]{64}", target_key) is None:
        raise OperationalIdentityValidationError("A valid audit target identity is required.")
    return _database_key("b104a-", "audit-event", {"action": safe_action, "target_sha256": hashlib.sha256(target_key.encode("ascii")).hexdigest()})


def build_advisory_lock_key(namespace: str, identity: str) -> int:
    """Build a deterministic signed PostgreSQL advisory-lock bigint."""

    if namespace not in _LOCK_NAMESPACES:
        raise OperationalIdentityValidationError("An approved lock namespace is required.")
    if not isinstance(identity, str) or not identity or len(identity) > 500:
        raise OperationalIdentityValidationError("A bounded lock identity is required.")
    digest = bytes.fromhex(_canonical_digest(f"lock:{namespace}", {"identity": identity}))
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


# Concise aliases retained as a public convenience for service callers.
scheduled_cycle_key = build_scheduled_cycle_key
manual_cycle_key = build_manual_cycle_key
source_attempt_run_key = build_source_attempt_run_key
audit_event_key = build_audit_event_key
advisory_lock_key = build_advisory_lock_key


__all__ = [
    "OperationalIdentityValidationError",
    "advisory_lock_key",
    "audit_event_key",
    "build_advisory_lock_key",
    "build_audit_event_key",
    "build_manual_cycle_key",
    "build_scheduled_cycle_key",
    "build_source_attempt_run_key",
    "manual_cycle_key",
    "scheduled_cycle_key",
    "source_attempt_run_key",
]
