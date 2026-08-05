"""Administrator-only explicit local user lifecycle routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.query_validation import validate_query_parameters
from app.api.v1.schemas.admin_users import AdminUserListResponse, AdminUserResponse, CreateAdminUserRequest, UserExpiryRequest, UserRoleRequest, UserStatusRequest
from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.security.contracts import AuthenticatedPrincipal
from app.security.dependencies import prevent_auth_caching, require_csrf, require_csrf_json, require_user_manage, require_user_read
from app.services.user_admin_service import AdministratorSafetyError, UserAdminService, UserAdminServiceError, UserConflictError, UserInputError, UserNotFoundError


router = APIRouter(prefix="/admin/users", tags=["administrator-users"])
validate_list_query = validate_query_parameters({"limit", "offset"})
validate_no_query_parameters = validate_query_parameters(set())


def _commit_or_500(db_session: Session) -> None:
    try:
        db_session.commit()
    except SQLAlchemyError:
        db_session.rollback()
        raise HTTPException(status_code=500, detail="An unexpected server error occurred.") from None


def _service_error(exc: Exception) -> HTTPException:
    if isinstance(exc, UserNotFoundError):
        return HTTPException(status_code=404, detail="The requested user was not found.")
    if isinstance(exc, UserConflictError):
        return HTTPException(status_code=409, detail="The user could not be created.")
    if isinstance(exc, AdministratorSafetyError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, UserInputError):
        return HTTPException(status_code=400, detail="Invalid request.")
    return HTTPException(status_code=500, detail="An unexpected server error occurred.")


@router.get("", response_model=AdminUserListResponse, dependencies=[Depends(validate_list_query)])
def list_users(response: Response, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0, le=100000), _principal: AuthenticatedPrincipal = Depends(require_user_read), db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> AdminUserListResponse:
    prevent_auth_caching(response)
    try:
        items, total = UserAdminService(db_session, settings).list_users(limit=limit, offset=offset)
    except (UserAdminServiceError, SQLAlchemyError) as exc:
        raise _service_error(exc) from None
    return AdminUserListResponse(items=[AdminUserResponse.model_validate(item) for item in items], total=total, limit=limit, offset=offset)


@router.get("/{user_public_id}", response_model=AdminUserResponse, dependencies=[Depends(validate_no_query_parameters)])
def get_user(user_public_id: UUID, response: Response, _principal: AuthenticatedPrincipal = Depends(require_user_read), db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> AdminUserResponse:
    prevent_auth_caching(response)
    try:
        return AdminUserResponse.model_validate(UserAdminService(db_session, settings).get_user(user_public_id))
    except (UserNotFoundError, UserAdminServiceError, SQLAlchemyError) as exc:
        raise _service_error(exc) from None


@router.post("", response_model=AdminUserResponse, status_code=201, dependencies=[Depends(validate_no_query_parameters), Depends(require_user_manage)])
def create_user(payload: CreateAdminUserRequest, request: Request, response: Response, principal: AuthenticatedPrincipal = Depends(require_csrf_json), db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> AdminUserResponse:
    prevent_auth_caching(response)
    try:
        record = UserAdminService(db_session, settings).create_user(actor=principal, username=payload.username, display_name=payload.display_name, password=payload.password.get_secret_value(), role=payload.role, account_expires_at=payload.account_expires_at, correlation_id=request.state.request_id)
        _commit_or_500(db_session)
        return AdminUserResponse.model_validate(record)
    except (UserConflictError, AdministratorSafetyError, UserNotFoundError, UserAdminServiceError, SQLAlchemyError) as exc:
        db_session.rollback()
        raise _service_error(exc) from None


def _update_user(operation, db_session: Session):
    try:
        record = operation()
        _commit_or_500(db_session)
        return AdminUserResponse.model_validate(record)
    except (UserNotFoundError, AdministratorSafetyError, UserConflictError, UserAdminServiceError, SQLAlchemyError) as exc:
        db_session.rollback()
        raise _service_error(exc) from None


@router.patch("/{user_public_id}/status", response_model=AdminUserResponse, dependencies=[Depends(validate_no_query_parameters), Depends(require_user_manage)])
def change_status(user_public_id: UUID, payload: UserStatusRequest, request: Request, response: Response, principal: AuthenticatedPrincipal = Depends(require_csrf_json), db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> AdminUserResponse:
    prevent_auth_caching(response)
    service = UserAdminService(db_session, settings)
    return _update_user(lambda: service.change_status(actor=principal, public_id=user_public_id, status_value=payload.status, correlation_id=request.state.request_id), db_session)


@router.patch("/{user_public_id}/role", response_model=AdminUserResponse, dependencies=[Depends(validate_no_query_parameters), Depends(require_user_manage)])
def change_role(user_public_id: UUID, payload: UserRoleRequest, request: Request, response: Response, principal: AuthenticatedPrincipal = Depends(require_csrf_json), db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> AdminUserResponse:
    prevent_auth_caching(response)
    service = UserAdminService(db_session, settings)
    return _update_user(lambda: service.change_role(actor=principal, public_id=user_public_id, role_value=payload.role, correlation_id=request.state.request_id), db_session)


@router.patch("/{user_public_id}/expiry", response_model=AdminUserResponse, dependencies=[Depends(validate_no_query_parameters), Depends(require_user_manage)])
def change_expiry(user_public_id: UUID, payload: UserExpiryRequest, request: Request, response: Response, principal: AuthenticatedPrincipal = Depends(require_csrf_json), db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> AdminUserResponse:
    prevent_auth_caching(response)
    service = UserAdminService(db_session, settings)
    return _update_user(lambda: service.change_expiry(actor=principal, public_id=user_public_id, account_expires_at=payload.account_expires_at, correlation_id=request.state.request_id), db_session)


@router.post("/{user_public_id}/sessions/revoke", status_code=204, dependencies=[Depends(validate_no_query_parameters), Depends(require_user_manage)])
def revoke_sessions(user_public_id: UUID, request: Request, response: Response, principal: AuthenticatedPrincipal = Depends(require_csrf), db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> Response:
    prevent_auth_caching(response)
    try:
        UserAdminService(db_session, settings).revoke_sessions(actor=principal, public_id=user_public_id, correlation_id=request.state.request_id)
        _commit_or_500(db_session)
    except (UserNotFoundError, AdministratorSafetyError, UserAdminServiceError, SQLAlchemyError) as exc:
        db_session.rollback()
        raise _service_error(exc) from None
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
