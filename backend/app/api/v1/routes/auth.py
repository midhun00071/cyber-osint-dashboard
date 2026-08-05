"""Opaque-cookie authentication and authenticated self-service routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.query_validation import validate_query_parameters
from app.api.v1.schemas.auth import ChangePasswordRequest, LoginRequest, PrincipalResponse
from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.security.contracts import AuthenticatedPrincipal
from app.security.dependencies import prevent_auth_caching, require_authenticated_principal, require_csrf, require_csrf_json, require_login_request_security
from app.security.sessions import clear_auth_cookies, set_auth_cookies
from app.services.authentication_service import AuthenticationService, AuthenticationServiceError, INVALID_CREDENTIALS_DETAIL, InvalidCredentialsError, PasswordChangeError


router = APIRouter(prefix="/auth", tags=["authentication"])
validate_no_query_parameters = validate_query_parameters(set())


def _principal_response(principal: AuthenticatedPrincipal) -> PrincipalResponse:
    return PrincipalResponse(public_id=principal.user_public_id, display_name=principal.display_name, role=principal.role, permissions=sorted(permission.value for permission in principal.permissions), account_expires_at=principal.account_expires_at)


@router.post("/login", response_model=PrincipalResponse, dependencies=[Depends(validate_no_query_parameters), Depends(require_login_request_security)])
def login(payload: LoginRequest, request: Request, response: Response, db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> PrincipalResponse:
    prevent_auth_caching(response)
    service = AuthenticationService(db_session, settings)
    try:
        principal, issued = service.login(username=payload.username, password=payload.password.get_secret_value(), correlation_id=request.state.request_id)
    except InvalidCredentialsError:
        try:
            db_session.commit()
        except SQLAlchemyError:
            db_session.rollback()
            raise HTTPException(status_code=500, detail="Authentication could not be completed.") from None
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS_DETAIL) from None
    except AuthenticationServiceError:
        db_session.rollback()
        raise HTTPException(status_code=500, detail="Authentication could not be completed.") from None
    try:
        db_session.commit()
    except SQLAlchemyError:
        db_session.rollback()
        raise HTTPException(status_code=500, detail="Authentication could not be completed.") from None
    set_auth_cookies(response, issued, settings)
    return _principal_response(principal)


@router.get("/me", response_model=PrincipalResponse, dependencies=[Depends(validate_no_query_parameters)])
def me(response: Response, principal: AuthenticatedPrincipal = Depends(require_authenticated_principal)) -> PrincipalResponse:
    prevent_auth_caching(response)
    return _principal_response(principal)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(validate_no_query_parameters)])
def logout(request: Request, response: Response, principal: AuthenticatedPrincipal = Depends(require_csrf), db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> Response:
    prevent_auth_caching(response)
    try:
        AuthenticationService(db_session, settings).logout(principal, correlation_id=request.state.request_id)
        db_session.commit()
    except (AuthenticationServiceError, SQLAlchemyError):
        db_session.rollback()
        raise HTTPException(status_code=500, detail="Logout could not be completed.") from None
    clear_auth_cookies(response, settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post("/refresh", response_model=PrincipalResponse, dependencies=[Depends(validate_no_query_parameters)])
def refresh(request: Request, response: Response, principal: AuthenticatedPrincipal = Depends(require_csrf), db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> PrincipalResponse:
    prevent_auth_caching(response)
    try:
        issued = AuthenticationService(db_session, settings).refresh(principal, correlation_id=request.state.request_id)
        db_session.commit()
    except (AuthenticationServiceError, SQLAlchemyError, ValueError):
        db_session.rollback()
        raise HTTPException(status_code=401, detail="Authentication required.") from None
    set_auth_cookies(response, issued, settings)
    return _principal_response(principal)


@router.post("/change-password", response_model=PrincipalResponse, dependencies=[Depends(validate_no_query_parameters)])
def change_password(payload: ChangePasswordRequest, request: Request, response: Response, principal: AuthenticatedPrincipal = Depends(require_csrf_json), db_session: Session = Depends(get_db_session), settings: Settings = Depends(get_settings)) -> PrincipalResponse:
    prevent_auth_caching(response)
    try:
        issued = AuthenticationService(db_session, settings).change_password(principal, current_password=payload.current_password.get_secret_value(), new_password=payload.new_password.get_secret_value(), correlation_id=request.state.request_id)
        db_session.commit()
    except PasswordChangeError:
        db_session.rollback()
        raise HTTPException(status_code=400, detail="The password could not be changed.") from None
    except (SQLAlchemyError, ValueError, RuntimeError):
        db_session.rollback()
        raise HTTPException(status_code=500, detail="The password could not be changed.") from None
    set_auth_cookies(response, issued, settings)
    return _principal_response(principal)
