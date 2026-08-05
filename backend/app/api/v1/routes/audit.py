"""Administrator-only bounded security audit search."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.api.v1.query_validation import validate_query_parameters
from app.api.v1.schemas.audit import AuditEventListResponse, AuditEventResponse
from app.db.session import get_db_session
from app.security.contracts import AuthenticatedPrincipal
from app.security.dependencies import prevent_auth_caching, require_audit_read
from app.services.audit_query_service import AuditQueryError, AuditQueryFilters, AuditQueryService
from app.services.security_audit_service import SecurityAuditAction


router = APIRouter(prefix="/audit/events", tags=["security-audit"])
validate_audit_query = validate_query_parameters({"limit", "offset", "action", "outcome", "correlation_id", "occurred_from", "occurred_to"})
_AUDIT_OUTCOMES = frozenset({"success", "denied", "failed", "no_change"})


class AuditQueryValidationError(ValueError):
    """Expected safe rejection of administrator-supplied audit filters."""


def _bounded_integer(value: str, *, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or len(value) > len(str(maximum))
    ):
        raise AuditQueryValidationError("Invalid audit query.")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise AuditQueryValidationError("Invalid audit query.")
    return parsed


def _optional_action(value: str | None) -> SecurityAuditAction | None:
    if value is None:
        return None
    try:
        return SecurityAuditAction(value)
    except ValueError:
        raise AuditQueryValidationError("Invalid audit query.") from None


def _optional_outcome(value: str | None) -> str | None:
    if value is None:
        return None
    if value not in _AUDIT_OUTCOMES:
        raise AuditQueryValidationError("Invalid audit query.")
    return value


def _optional_uuid(value: str | None) -> UUID | None:
    if value is None:
        return None
    try:
        return UUID(value)
    except (ValueError, AttributeError):
        raise AuditQueryValidationError("Invalid audit query.") from None


def _optional_utc_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise AuditQueryValidationError("Invalid audit query.") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise AuditQueryValidationError("Invalid audit query.")
    return parsed.astimezone(UTC)


def _audit_filters(
    *,
    limit: str,
    offset: str,
    action: str | None,
    outcome: str | None,
    correlation_id: str | None,
    occurred_from: str | None,
    occurred_to: str | None,
) -> AuditQueryFilters:
    parsed_from = _optional_utc_timestamp(occurred_from)
    parsed_to = _optional_utc_timestamp(occurred_to)
    if parsed_from is not None and parsed_to is not None:
        if parsed_to <= parsed_from or parsed_to - parsed_from > timedelta(days=366):
            raise AuditQueryValidationError("Invalid audit query.")
    return AuditQueryFilters(
        limit=_bounded_integer(limit, minimum=1, maximum=100),
        offset=_bounded_integer(offset, minimum=0, maximum=100000),
        action=_optional_action(action),
        outcome=_optional_outcome(outcome),
        correlation_id=_optional_uuid(correlation_id),
        occurred_from=parsed_from,
        occurred_to=parsed_to,
    )


@router.get("", response_model=AuditEventListResponse, dependencies=[Depends(validate_audit_query)])
def list_audit_events(response: Response, limit: str = Query("50"), offset: str = Query("0"), action: str | None = Query(None), outcome: str | None = Query(None), correlation_id: str | None = Query(None), occurred_from: str | None = Query(None), occurred_to: str | None = Query(None), _principal: AuthenticatedPrincipal = Depends(require_audit_read), db_session: Session = Depends(get_db_session)) -> AuditEventListResponse:
    prevent_auth_caching(response)
    try:
        filters = _audit_filters(limit=limit, offset=offset, action=action, outcome=outcome, correlation_id=correlation_id, occurred_from=occurred_from, occurred_to=occurred_to)
        items, total = AuditQueryService(db_session).list_events(filters)
    except AuditQueryValidationError:
        raise HTTPException(status_code=400, detail="Invalid audit query.", headers={"Cache-Control": "no-store"}) from None
    except AuditQueryError:
        raise HTTPException(status_code=500, detail="An unexpected server error occurred.", headers={"Cache-Control": "no-store"}) from None
    return AuditEventListResponse(items=[AuditEventResponse.model_validate(item) for item in items], total=total, limit=filters.limit, offset=filters.offset)
