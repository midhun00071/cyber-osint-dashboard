"""Authorized bounded report catalog and export routes."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import Response as BinaryResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.query_validation import validate_query_parameters
from app.api.v1.schemas.reports import (
    ReportCatalogItem,
    ReportCatalogResponse,
    ReportExportRequest,
    ReportFormat,
    ReportType,
)
from app.db.session import get_db_session
from app.security.contracts import AuthenticatedPrincipal
from app.security.dependencies import (
    prevent_auth_caching,
    require_csrf_json,
    require_report_export,
    require_report_read,
)
from app.services.report_service import (
    MAX_REPORT_BYTES,
    MAX_REPORT_CELL_CHARACTERS,
    MAX_REPORT_ROWS,
    ReportGenerationError,
    ReportService,
    ReportSizeLimitError,
)
from app.services.security_audit_service import (
    SecurityAuditAction,
    SecurityAuditError,
    SecurityAuditService,
)


router = APIRouter(prefix="/reports", tags=["reports"])
validate_no_query_parameters = validate_query_parameters(set())


@router.get(
    "/catalog",
    response_model=ReportCatalogResponse,
    dependencies=[Depends(validate_no_query_parameters), Depends(require_report_read)],
)
def report_catalog(response: Response) -> ReportCatalogResponse:
    prevent_auth_caching(response)
    return ReportCatalogResponse(
        reports=[
            ReportCatalogItem(
                report_type=ReportType.UAE_INTELLIGENCE,
                label="UAE Intelligence",
                formats=[ReportFormat.CSV, ReportFormat.PDF],
            ),
            ReportCatalogItem(
                report_type=ReportType.SOURCE_OPERATIONS,
                label="Source Operations",
                formats=[ReportFormat.CSV, ReportFormat.PDF],
            ),
        ],
        maximum_rows=MAX_REPORT_ROWS,
        maximum_bytes=MAX_REPORT_BYTES,
        maximum_cell_characters=MAX_REPORT_CELL_CHARACTERS,
    )


@router.post(
    "/export",
    dependencies=[
        Depends(validate_no_query_parameters),
        Depends(require_report_export),
    ],
)
def export_report(
    payload: ReportExportRequest,
    request: Request,
    principal: AuthenticatedPrincipal = Depends(require_csrf_json),
    db_session: Session = Depends(get_db_session),
) -> BinaryResponse:
    try:
        generated = ReportService(db_session).generate(
            report_type=payload.report_type,
            report_format=payload.format,
            limit=payload.limit,
            permissions=principal.permissions,
        )
        SecurityAuditService(db_session).append(
            action=SecurityAuditAction.REPORT_EXPORT_REQUESTED,
            actor_type="user",
            actor_ref=str(principal.user_public_id),
            target_type="system",
            target_ref=f"report:{payload.report_type.value}",
            outcome="success",
            correlation_id=request.state.request_id,
            safe_detail={"operation": payload.format.value},
        )
        db_session.commit()
    except ReportSizeLimitError:
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="The report exceeds the configured output limit.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except (ReportGenerationError, SecurityAuditError, SQLAlchemyError, ValueError):
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The report could not be generated safely.",
            headers={"Cache-Control": "no-store"},
        ) from None
    return BinaryResponse(
        content=generated.content,
        media_type=generated.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{generated.filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
