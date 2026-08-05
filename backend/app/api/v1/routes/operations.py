"""Authenticated, bounded source and ingestion operations API."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.query_validation import validate_query_parameters
from app.api.v1.schemas.operations import (
    CycleListResponse,
    OperationAcceptanceResponse,
    OperationsSummaryResponse,
    RunEventListResponse,
    RunListResponse,
    RunResponse,
    SourceListResponse,
    SourceResponse,
    SourceTransitionResponse,
    StrictOperationRequest,
)
from app.db.session import get_db_session
from app.security.contracts import AuthenticatedPrincipal
from app.security.dependencies import (
    prevent_auth_caching,
    require_csrf_json,
    require_ingestion_pause,
    require_ingestion_read,
    require_ingestion_retry,
    require_ingestion_run,
    require_source_manage,
    require_source_read,
)
from app.services.operations_query_service import (
    OperationsNotFoundError,
    OperationsQueryError,
    OperationsQueryInputError,
    OperationsQueryService,
)
from app.services.operator_control_service import OperatorControlError, OperatorControlService
from app.services.security_audit_service import SecurityAuditError


router = APIRouter(tags=["source-operations"])
_SOURCE_SLUG = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"
_IDEMPOTENCY_KEY = r"^[A-Za-z0-9._:-]{16,128}$"
validate_source_list_query = validate_query_parameters({"limit", "offset", "operator_state", "effective_state"})
validate_run_list_query = validate_query_parameters({"limit", "offset", "source_slug", "status", "trigger_type", "retryable", "from", "to"})
validate_cycle_list_query = validate_query_parameters({"limit", "offset", "status", "trigger_type", "from", "to"})
validate_event_list_query = validate_query_parameters({"limit", "offset"})
validate_no_query_parameters = validate_query_parameters(set())


def _query_error(exc: Exception) -> HTTPException:
    if isinstance(exc, OperationsNotFoundError):
        return _error(404, "not_found", "The requested operational resource was not found.")
    if isinstance(exc, OperationsQueryInputError):
        return _error(400, "invalid_query", "The operations query is invalid.")
    return _error(500, "operations_unavailable", "Operational data could not be loaded safely.")


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
        headers={"Cache-Control": "no-store"},
    )


def _control_failure(
    exc: OperatorControlError,
    *,
    db_session: Session,
    principal: AuthenticatedPrincipal,
    request_id: str,
) -> HTTPException:
    db_session.rollback()
    try:
        OperatorControlService(db_session).audit_denial(
            exc, actor=principal, correlation_id=request_id
        )
        db_session.commit()
    except (SecurityAuditError, SQLAlchemyError, ValueError):
        db_session.rollback()
        return _error(500, "audit_unavailable", "The operation could not be audited safely.")
    return _error(exc.status_code, exc.code, exc.public_message)


def _commit(db_session: Session) -> None:
    try:
        db_session.commit()
    except SQLAlchemyError:
        db_session.rollback()
        raise _error(500, "operation_unavailable", "The operation could not be committed safely.") from None


@router.get("/sources", response_model=SourceListResponse, dependencies=[Depends(validate_source_list_query)])
def list_sources(
    response: Response,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
    operator_state: str | None = Query(None),
    effective_state: str | None = Query(None),
    principal: AuthenticatedPrincipal = Depends(require_source_read),
    db_session: Session = Depends(get_db_session),
) -> SourceListResponse:
    prevent_auth_caching(response)
    try:
        items, total = OperationsQueryService(db_session).list_sources(
            permissions=principal.permissions, limit=limit, offset=offset,
            operator_state=operator_state, effective_state=effective_state,
        )
    except (OperationsQueryError, OperationsQueryInputError) as exc:
        raise _query_error(exc) from None
    return SourceListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/sources/{source_slug}", response_model=SourceResponse, dependencies=[Depends(validate_no_query_parameters)])
def get_source(
    source_slug: Annotated[str, Path(pattern=_SOURCE_SLUG, max_length=80)],
    response: Response,
    principal: AuthenticatedPrincipal = Depends(require_source_read),
    db_session: Session = Depends(get_db_session),
) -> SourceResponse:
    prevent_auth_caching(response)
    try:
        return SourceResponse.model_validate(
            OperationsQueryService(db_session).get_source(source_slug, permissions=principal.permissions)
        )
    except (OperationsNotFoundError, OperationsQueryError) as exc:
        raise _query_error(exc) from None


@router.get("/ingestion/operations/summary", response_model=OperationsSummaryResponse, dependencies=[Depends(validate_no_query_parameters)])
def operations_summary(
    response: Response,
    _principal: AuthenticatedPrincipal = Depends(require_ingestion_read),
    db_session: Session = Depends(get_db_session),
) -> OperationsSummaryResponse:
    prevent_auth_caching(response)
    try:
        return OperationsSummaryResponse.model_validate(
            OperationsQueryService(db_session).operations_summary()
        )
    except OperationsQueryError as exc:
        raise _query_error(exc) from None


@router.get("/ingestion/cycles", response_model=CycleListResponse, dependencies=[Depends(validate_cycle_list_query)])
def list_cycles(
    response: Response,
    limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0, le=100000),
    status_filter: str | None = Query(None, alias="status"),
    trigger_type: str | None = Query(None),
    occurred_from: datetime | None = Query(None, alias="from"),
    occurred_to: datetime | None = Query(None, alias="to"),
    _principal: AuthenticatedPrincipal = Depends(require_ingestion_read),
    db_session: Session = Depends(get_db_session),
) -> CycleListResponse:
    prevent_auth_caching(response)
    try:
        items, total = OperationsQueryService(db_session).list_cycles(
            limit=limit, offset=offset, status=status_filter, trigger_type=trigger_type,
            occurred_from=occurred_from, occurred_to=occurred_to,
        )
    except (OperationsQueryError, OperationsQueryInputError) as exc:
        raise _query_error(exc) from None
    return CycleListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/ingestion/runs", response_model=RunListResponse, dependencies=[Depends(validate_run_list_query)])
def list_runs(
    response: Response,
    limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0, le=100000),
    source_slug: str | None = Query(None, pattern=_SOURCE_SLUG, max_length=80),
    status_filter: str | None = Query(None, alias="status"),
    trigger_type: str | None = Query(None), retryable: bool | None = Query(None),
    occurred_from: datetime | None = Query(None, alias="from"),
    occurred_to: datetime | None = Query(None, alias="to"),
    _principal: AuthenticatedPrincipal = Depends(require_ingestion_read),
    db_session: Session = Depends(get_db_session),
) -> RunListResponse:
    prevent_auth_caching(response)
    try:
        items, total = OperationsQueryService(db_session).list_runs(
            limit=limit, offset=offset, source_slug=source_slug, status=status_filter,
            trigger_type=trigger_type, retryable=retryable,
            occurred_from=occurred_from, occurred_to=occurred_to,
        )
    except (OperationsQueryError, OperationsQueryInputError) as exc:
        raise _query_error(exc) from None
    return RunListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/ingestion/runs/{run_public_id}", response_model=RunResponse, dependencies=[Depends(validate_no_query_parameters)])
def get_run(
    run_public_id: UUID, response: Response,
    _principal: AuthenticatedPrincipal = Depends(require_ingestion_read),
    db_session: Session = Depends(get_db_session),
) -> RunResponse:
    prevent_auth_caching(response)
    try:
        return RunResponse.model_validate(OperationsQueryService(db_session).get_run(run_public_id))
    except (OperationsNotFoundError, OperationsQueryError) as exc:
        raise _query_error(exc) from None


@router.get("/ingestion/runs/{run_public_id}/events", response_model=RunEventListResponse, dependencies=[Depends(validate_event_list_query)])
def list_run_events(
    run_public_id: UUID, response: Response,
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=100000),
    _principal: AuthenticatedPrincipal = Depends(require_ingestion_read),
    db_session: Session = Depends(get_db_session),
) -> RunEventListResponse:
    prevent_auth_caching(response)
    try:
        items, total = OperationsQueryService(db_session).list_run_events(
            run_public_id, limit=limit, offset=offset
        )
    except (OperationsNotFoundError, OperationsQueryError, OperationsQueryInputError) as exc:
        raise _query_error(exc) from None
    return RunEventListResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("/sources/{source_slug}/runs", response_model=OperationAcceptanceResponse, status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(validate_no_query_parameters), Depends(require_ingestion_run)])
def request_manual_run(
    source_slug: Annotated[str, Path(pattern=_SOURCE_SLUG, max_length=80)],
    _payload: StrictOperationRequest,
    request: Request,
    response: Response,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=128, pattern=_IDEMPOTENCY_KEY)],
    principal: AuthenticatedPrincipal = Depends(require_csrf_json),
    db_session: Session = Depends(get_db_session),
) -> OperationAcceptanceResponse:
    prevent_auth_caching(response)
    try:
        result = OperatorControlService(db_session).request_manual_run(
            source_slug=source_slug, idempotency_key=idempotency_key, actor=principal,
            correlation_id=request.state.request_id,
        )
        _commit(db_session)
    except OperatorControlError as exc:
        raise _control_failure(exc, db_session=db_session, principal=principal, request_id=request.state.request_id) from None
    if result.replayed:
        response.status_code = status.HTTP_200_OK
    return OperationAcceptanceResponse.model_validate(result)


@router.post("/ingestion/runs/{run_public_id}/retry", response_model=OperationAcceptanceResponse, status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(validate_no_query_parameters), Depends(require_ingestion_retry)])
def request_retry(
    run_public_id: UUID, _payload: StrictOperationRequest, request: Request, response: Response,
    principal: AuthenticatedPrincipal = Depends(require_csrf_json),
    db_session: Session = Depends(get_db_session),
) -> OperationAcceptanceResponse:
    prevent_auth_caching(response)
    try:
        result = OperatorControlService(db_session).request_retry(
            run_public_id=run_public_id, actor=principal, correlation_id=request.state.request_id
        )
        _commit(db_session)
    except OperatorControlError as exc:
        raise _control_failure(exc, db_session=db_session, principal=principal, request_id=request.state.request_id) from None
    if result.replayed:
        response.status_code = status.HTTP_200_OK
    return OperationAcceptanceResponse.model_validate(result)


def _transition(
    source_slug: str, operation: str, request: Request, response: Response,
    principal: AuthenticatedPrincipal, db_session: Session,
) -> SourceTransitionResponse:
    prevent_auth_caching(response)
    try:
        result = OperatorControlService(db_session).transition_source(
            source_slug=source_slug, operation=operation, actor=principal,
            correlation_id=request.state.request_id,
        )
        _commit(db_session)
    except OperatorControlError as exc:
        raise _control_failure(exc, db_session=db_session, principal=principal, request_id=request.state.request_id) from None
    return SourceTransitionResponse.model_validate(result)


def _transition_route(operation: str, permission_dependency):
    def endpoint(
        source_slug: Annotated[str, Path(pattern=_SOURCE_SLUG, max_length=80)],
        _payload: StrictOperationRequest, request: Request, response: Response,
        _authorized: AuthenticatedPrincipal = Depends(permission_dependency),
        principal: AuthenticatedPrincipal = Depends(require_csrf_json),
        db_session: Session = Depends(get_db_session),
    ) -> SourceTransitionResponse:
        return _transition(source_slug, operation, request, response, principal, db_session)
    return endpoint


router.post("/sources/{source_slug}/pause", response_model=SourceTransitionResponse, dependencies=[Depends(validate_no_query_parameters)])(_transition_route("pause", require_ingestion_pause))
router.post("/sources/{source_slug}/resume", response_model=SourceTransitionResponse, dependencies=[Depends(validate_no_query_parameters)])(_transition_route("resume", require_ingestion_pause))
router.post("/sources/{source_slug}/disable", response_model=SourceTransitionResponse, dependencies=[Depends(validate_no_query_parameters)])(_transition_route("disable", require_ingestion_pause))
router.post("/sources/{source_slug}/enable", response_model=SourceTransitionResponse, dependencies=[Depends(validate_no_query_parameters)])(_transition_route("enable", require_source_manage))
