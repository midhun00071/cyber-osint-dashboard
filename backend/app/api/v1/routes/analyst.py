"""Authenticated and bounded C08 analyst read routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.v1.query_validation import (
    ITEM_TYPE_VALUES,
    MAX_PAGINATION_OFFSET,
    MAX_SEARCH_LENGTH,
    CanonicalPublicUUID,
    normalize_enum_filter,
    normalize_search_text,
    normalize_slug_filter,
    validate_query_parameters,
)
from app.api.v1.schemas.analyst import (
    IndicatorDetailResponse,
    IndicatorListResponse,
    ItemProvenanceResponse,
    ThreatEntityDetailResponse,
    ThreatEntityListResponse,
    UaeIntelligenceListResponse,
)
from app.db.session import get_db_session
from app.models.indicator import INDICATOR_STATUS_VALUES, OBSERVABLE_TYPE_VALUES
from app.models.threat_entity import THREAT_ENTITY_TYPE_VALUES
from app.security.dependencies import (
    prevent_auth_caching,
    require_analysis_use,
    require_content_read,
)
from app.security.rate_limit import require_read_rate_limit
from app.services.analyst_query_service import (
    AnalystNotFoundError,
    AnalystQueryError,
    AnalystQueryService,
    IndicatorFilters,
    ThreatEntityFilters,
    UaeIntelligenceFilters,
)


router = APIRouter(prefix="/analysis", tags=["analysis"])
_RELEVANCE_FILTER_VALUES = ("direct", "potential", "global", "no_evidence")

validate_threat_list_query = validate_query_parameters(
    {"limit", "offset", "q", "entity_type", "source_slug", "revoked"}
)
validate_indicator_list_query = validate_query_parameters(
    {"limit", "offset", "q", "observable_type", "status"}
)
validate_uae_list_query = validate_query_parameters(
    {"limit", "offset", "q", "relevance", "item_type", "source_slug"}
)
validate_no_query_parameters = validate_query_parameters(set())

threat_rate_limit = require_read_rate_limit("analysis.threat_entities")
indicator_rate_limit = require_read_rate_limit("analysis.indicators")
provenance_rate_limit = require_read_rate_limit("analysis.provenance")
uae_rate_limit = require_read_rate_limit("analysis.uae")


def _not_found(message: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message)


def _unavailable(message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=message,
    )


@router.get(
    "/threat-entities",
    response_model=ThreatEntityListResponse,
    dependencies=[
        Depends(validate_threat_list_query),
        Depends(require_content_read),
        Depends(threat_rate_limit),
    ],
)
def list_threat_entities(
    response: Response,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=MAX_PAGINATION_OFFSET),
    q: str | None = Query(default=None, min_length=1, max_length=MAX_SEARCH_LENGTH),
    entity_type: str | None = Query(default=None, min_length=1, max_length=40),
    source_slug: str | None = Query(default=None, min_length=1, max_length=80),
    revoked: bool | None = Query(default=False),
    db_session: Session = Depends(get_db_session),
) -> ThreatEntityListResponse:
    prevent_auth_caching(response)
    filters = ThreatEntityFilters(
        q=normalize_search_text(q),
        entity_type=normalize_enum_filter(
            entity_type,
            allowed_values=THREAT_ENTITY_TYPE_VALUES,
            field_name="entity_type",
        ),
        source_slug=normalize_slug_filter(source_slug, field_name="source_slug"),
        revoked=revoked,
        limit=limit,
        offset=offset,
    )
    try:
        return AnalystQueryService(db_session).list_threat_entities(filters)
    except AnalystQueryError as exc:
        raise _unavailable("Unable to load threat metadata.") from exc


@router.get(
    "/threat-entities/{public_id}",
    response_model=ThreatEntityDetailResponse,
    dependencies=[
        Depends(validate_no_query_parameters),
        Depends(require_content_read),
        Depends(threat_rate_limit),
    ],
)
def get_threat_entity(
    public_id: CanonicalPublicUUID,
    response: Response,
    db_session: Session = Depends(get_db_session),
) -> ThreatEntityDetailResponse:
    prevent_auth_caching(response)
    try:
        return AnalystQueryService(db_session).get_threat_entity(public_id)
    except AnalystNotFoundError as exc:
        raise _not_found("The requested threat metadata was not found.") from exc
    except AnalystQueryError as exc:
        raise _unavailable("Unable to load threat metadata.") from exc


@router.get(
    "/indicators",
    response_model=IndicatorListResponse,
    dependencies=[
        Depends(validate_indicator_list_query),
        Depends(require_analysis_use),
        Depends(indicator_rate_limit),
    ],
)
def list_indicators(
    response: Response,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=MAX_PAGINATION_OFFSET),
    q: str | None = Query(default=None, min_length=1, max_length=MAX_SEARCH_LENGTH),
    observable_type: str | None = Query(default=None, min_length=1, max_length=20),
    indicator_status: str | None = Query(
        default="active",
        alias="status",
        min_length=1,
        max_length=40,
    ),
    db_session: Session = Depends(get_db_session),
) -> IndicatorListResponse:
    prevent_auth_caching(response)
    filters = IndicatorFilters(
        q=normalize_search_text(q),
        observable_type=normalize_enum_filter(
            observable_type,
            allowed_values=OBSERVABLE_TYPE_VALUES,
            field_name="observable_type",
        ),
        status=normalize_enum_filter(
            indicator_status,
            allowed_values=INDICATOR_STATUS_VALUES,
            field_name="status",
        ),
        limit=limit,
        offset=offset,
    )
    try:
        return AnalystQueryService(db_session).list_indicators(filters)
    except AnalystQueryError as exc:
        raise _unavailable("Unable to load indicators.") from exc


@router.get(
    "/indicators/{public_id}",
    response_model=IndicatorDetailResponse,
    dependencies=[
        Depends(validate_no_query_parameters),
        Depends(require_analysis_use),
        Depends(indicator_rate_limit),
    ],
)
def get_indicator(
    public_id: CanonicalPublicUUID,
    response: Response,
    db_session: Session = Depends(get_db_session),
) -> IndicatorDetailResponse:
    prevent_auth_caching(response)
    try:
        return AnalystQueryService(db_session).get_indicator(public_id)
    except AnalystNotFoundError as exc:
        raise _not_found("The requested indicator was not found.") from exc
    except AnalystQueryError as exc:
        raise _unavailable("Unable to load indicator.") from exc


@router.get(
    "/items/{public_id}/provenance",
    response_model=ItemProvenanceResponse,
    dependencies=[
        Depends(validate_no_query_parameters),
        Depends(require_content_read),
        Depends(provenance_rate_limit),
    ],
)
def get_item_provenance(
    public_id: CanonicalPublicUUID,
    response: Response,
    db_session: Session = Depends(get_db_session),
) -> ItemProvenanceResponse:
    prevent_auth_caching(response)
    try:
        return AnalystQueryService(db_session).get_item_provenance(public_id)
    except AnalystNotFoundError as exc:
        raise _not_found("The requested intelligence item was not found.") from exc
    except AnalystQueryError as exc:
        raise _unavailable("Unable to load item provenance.") from exc


@router.get(
    "/uae-intelligence",
    response_model=UaeIntelligenceListResponse,
    dependencies=[
        Depends(validate_uae_list_query),
        Depends(require_content_read),
        Depends(uae_rate_limit),
    ],
)
def list_uae_intelligence(
    response: Response,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=MAX_PAGINATION_OFFSET),
    q: str | None = Query(default=None, min_length=1, max_length=MAX_SEARCH_LENGTH),
    relevance: str | None = Query(default=None, min_length=1, max_length=20),
    item_type: str | None = Query(default=None, min_length=1, max_length=40),
    source_slug: str | None = Query(default=None, min_length=1, max_length=80),
    db_session: Session = Depends(get_db_session),
) -> UaeIntelligenceListResponse:
    prevent_auth_caching(response)
    filters = UaeIntelligenceFilters(
        q=normalize_search_text(q),
        relevance=normalize_enum_filter(
            relevance,
            allowed_values=_RELEVANCE_FILTER_VALUES,
            field_name="relevance",
        ),
        item_type=normalize_enum_filter(
            item_type,
            allowed_values=ITEM_TYPE_VALUES,
            field_name="item_type",
        ),
        source_slug=normalize_slug_filter(source_slug, field_name="source_slug"),
        limit=limit,
        offset=offset,
    )
    try:
        return AnalystQueryService(db_session).list_uae_intelligence(filters)
    except AnalystQueryError as exc:
        raise _unavailable("Unable to load UAE intelligence.") from exc
