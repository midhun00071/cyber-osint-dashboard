from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.routes import analyst
from app.api.v1.schemas.analyst import (
    IndicatorDetailResponse,
    IndicatorListResponse,
    ItemProvenanceResponse,
    ThreatEntityDetailResponse,
    ThreatEntityListResponse,
    UaeIntelligenceListResponse,
)
from app.db.session import get_db_session
from app.main import app
from app.security.dependencies import require_analysis_use, require_content_read
from app.security.rate_limit import ReadRateLimiter, require_read_rate_limit
from app.services.analyst_query_service import (
    AnalystNotFoundError,
    AnalystQueryService,
)


NOW = datetime(2026, 8, 8, tzinfo=UTC)
THREAT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_THREAT_ID = UUID("22222222-2222-4222-8222-222222222222")
RELATIONSHIP_ID = UUID("33333333-3333-4333-8333-333333333333")
INDICATOR_ID = UUID("44444444-4444-4444-8444-444444444444")
PROVENANCE_ID = UUID("55555555-5555-4555-8555-555555555555")
ITEM_ID = UUID("66666666-6666-4666-8666-666666666666")
RUN_ID = UUID("77777777-7777-4777-8777-777777777777")


class FailingSession:
    def execute(self, _statement):
        raise SQLAlchemyError("postgresql://private-user:private-password@db/private")


def threat_summary() -> dict:
    return {
        "public_id": THREAT_ID,
        "entity_type": "campaign",
        "name": "Synthetic defensive campaign",
        "attack_id": "C0001",
        "aliases": ["Example alias"],
        "confidence": 0.8,
        "source_slug": "mitre-attack",
        "source_name": "MITRE ATT&CK",
        "source_url": "https://attack.mitre.org/campaigns/C0001/",
        "content_sha256": "a" * 64,
        "stix_created_at": NOW,
        "stix_modified_at": NOW,
        "revoked": False,
    }


def indicator_summary() -> dict:
    return {
        "public_id": INDICATOR_ID,
        "observable_type": "domain",
        "normalized_value": "example.test",
        "hash_algorithm": None,
        "status": "active",
        "confidence": 0.75,
        "context_summary": "Synthetic defensive fixture.",
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "expires_at": None,
        "provenance_count": 1,
        "publication_count": 1,
    }


def enable_all_analyst_reads() -> None:
    app.dependency_overrides[get_db_session] = lambda: object()
    app.dependency_overrides[require_content_read] = lambda: None
    app.dependency_overrides[require_analysis_use] = lambda: None
    app.dependency_overrides[analyst.threat_rate_limit] = lambda: None
    app.dependency_overrides[analyst.indicator_rate_limit] = lambda: None
    app.dependency_overrides[analyst.provenance_rate_limit] = lambda: None
    app.dependency_overrides[analyst.uae_rate_limit] = lambda: None


def assert_safe_public_payload(value: object) -> None:
    forbidden = {
        "id",
        "raw_payload",
        "headers",
        "cookies",
        "authorization",
        "password",
        "secret",
        "sql",
        "stack_trace",
    }
    if isinstance(value, dict):
        assert not (set(value) & forbidden)
        for nested in value.values():
            assert_safe_public_payload(nested)
    elif isinstance(value, list):
        for nested in value:
            assert_safe_public_payload(nested)


def test_c08_openapi_has_strict_analyst_route_inventory() -> None:
    paths = app.openapi()["paths"]
    expected = {
        "/api/v1/analysis/threat-entities",
        "/api/v1/analysis/threat-entities/{public_id}",
        "/api/v1/analysis/indicators",
        "/api/v1/analysis/indicators/{public_id}",
        "/api/v1/analysis/items/{public_id}/provenance",
        "/api/v1/analysis/uae-intelligence",
    }
    assert expected <= set(paths)
    for path in expected:
        assert paths[path]["get"]["responses"]["200"]["content"]["application/json"]


def test_positive_analyst_lists_details_pagination_and_safe_public_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, tuple[int, int]] = {}
    threat = threat_summary()
    threat_detail = ThreatEntityDetailResponse.model_validate(
        {
            **threat,
            "relationships": [
                {
                    "public_id": RELATIONSHIP_ID,
                    "direction": "outgoing",
                    "relationship_type": "uses",
                    "other_entity_public_id": OTHER_THREAT_ID,
                    "other_entity_type": "malware_family",
                    "other_entity_name": "Synthetic malware family",
                    "confidence": 0.7,
                    "stix_modified_at": NOW,
                    "revoked": False,
                }
            ],
        }
    )
    indicator = indicator_summary()
    indicator_detail = IndicatorDetailResponse.model_validate(
        {
            **indicator,
            "provenances": [
                {
                    "public_id": PROVENANCE_ID,
                    "source_slug": "fixture-source",
                    "source_name": "Fixture Source",
                    "source_url": "https://example.test/evidence",
                    "confidence": 0.8,
                    "context_summary": "Bounded provenance.",
                    "first_observed_at": NOW,
                    "last_observed_at": NOW,
                }
            ],
            "publications": [
                {
                    "item_public_id": ITEM_ID,
                    "title": "Synthetic publication",
                    "item_type": "security_advisory",
                    "relationship_type": "mentioned",
                    "confidence": 0.8,
                    "context_summary": "Mentioned in normalized text.",
                    "first_observed_at": NOW,
                    "last_observed_at": NOW,
                }
            ],
        }
    )
    provenance = ItemProvenanceResponse.model_validate(
        {
            "item_public_id": ITEM_ID,
            "sources": [
                {
                    "source_slug": "fixture-source",
                    "source_name": "Fixture Source",
                    "source_url": "https://example.test/publication",
                    "content_sha256": "b" * 64,
                    "published_at": NOW,
                    "modified_at": NOW,
                    "collected_at": NOW,
                    "first_seen_at": NOW,
                    "last_seen_at": NOW,
                    "import_runs": [
                        {
                            "public_id": RUN_ID,
                            "action": "created",
                            "status": "success",
                            "started_at": NOW,
                            "completed_at": NOW,
                            "processed_at": NOW,
                        }
                    ],
                }
            ],
            "classification_tags": [
                {
                    "kind": "emirate",
                    "slug": "uae-emirate-dubai",
                    "label": "Dubai",
                    "confidence": 0.7,
                    "evidence": "Controlled emirate metadata.",
                }
            ],
            "indicators": [
                {
                    "public_id": INDICATOR_ID,
                    "observable_type": "domain",
                    "normalized_value": "example.test",
                    "hash_algorithm": None,
                    "status": "active",
                    "confidence": 0.8,
                    "context_summary": "Mentioned in normalized text.",
                    "first_observed_at": NOW,
                    "last_observed_at": NOW,
                }
            ],
        }
    )
    uae = UaeIntelligenceListResponse.model_validate(
        {
            "items": [
                {
                    "public_id": ITEM_ID,
                    "title": "Dubai defensive notice",
                    "summary": "Synthetic defensive fixture.",
                    "item_type": "security_advisory",
                    "cve_id": None,
                    "severity": None,
                    "source_slug": "ae-cert",
                    "source_name": "TDRA / aeCERT",
                    "source_url": "https://tdra.gov.ae/example",
                    "published_at": NOW,
                    "modified_at": NOW,
                    "collected_at": NOW,
                    "last_seen_at": NOW,
                    "geographic_scope": "uae",
                    "relevance_status": "possible",
                    "relevance_label": "Potential UAE relevance",
                    "relevance_confidence": 0.55,
                    "relevance_reason": "No attribution asserted.",
                    "relevance_method": "automatic",
                    "classification_tags": [],
                }
            ],
            "total": 3,
            "limit": 1,
            "offset": 2,
        }
    )

    def list_threats(_self, filters):
        observed["threat"] = (filters.limit, filters.offset)
        return ThreatEntityListResponse(
            items=[threat], total=3, limit=filters.limit, offset=filters.offset
        )

    def list_indicators(_self, filters):
        observed["indicator"] = (filters.limit, filters.offset)
        return IndicatorListResponse(
            items=[indicator], total=3, limit=filters.limit, offset=filters.offset
        )

    monkeypatch.setattr(AnalystQueryService, "list_threat_entities", list_threats)
    monkeypatch.setattr(AnalystQueryService, "get_threat_entity", lambda *_: threat_detail)
    monkeypatch.setattr(AnalystQueryService, "list_indicators", list_indicators)
    monkeypatch.setattr(AnalystQueryService, "get_indicator", lambda *_: indicator_detail)
    monkeypatch.setattr(AnalystQueryService, "get_item_provenance", lambda *_: provenance)
    monkeypatch.setattr(AnalystQueryService, "list_uae_intelligence", lambda *_: uae)
    enable_all_analyst_reads()
    try:
        with TestClient(app) as client:
            responses = [
                client.get("/api/v1/analysis/threat-entities?limit=1&offset=2"),
                client.get(f"/api/v1/analysis/threat-entities/{THREAT_ID}"),
                client.get("/api/v1/analysis/indicators?q=example&limit=1&offset=2"),
                client.get(f"/api/v1/analysis/indicators/{INDICATOR_ID}"),
                client.get(f"/api/v1/analysis/items/{ITEM_ID}/provenance"),
                client.get("/api/v1/analysis/uae-intelligence?limit=1&offset=2"),
            ]
    finally:
        app.dependency_overrides.clear()

    assert all(response.status_code == 200 for response in responses)
    assert observed == {"threat": (1, 2), "indicator": (1, 2)}
    assert responses[0].json()["items"][0]["aliases"] == ["Example alias"]
    assert responses[1].json()["relationships"][0]["other_entity_public_id"] == str(OTHER_THREAT_ID)
    assert responses[3].json()["provenances"][0]["public_id"] == str(PROVENANCE_ID)
    assert responses[3].json()["publications"][0]["item_public_id"] == str(ITEM_ID)
    assert responses[4].json()["item_public_id"] == str(ITEM_ID)
    assert responses[5].json()["total"] == 3
    for response in responses:
        assert_safe_public_payload(response.json())
        lowered = response.text.lower()
        assert "raw_payload" not in lowered
        assert "postgresql" not in lowered
        assert "cookie" not in lowered


def test_analyst_lists_reject_unknown_repeated_and_invalid_inputs() -> None:
    app.dependency_overrides[get_db_session] = lambda: object()
    app.dependency_overrides[require_content_read] = lambda: None
    app.dependency_overrides[analyst.threat_rate_limit] = lambda: None
    try:
        with TestClient(app) as client:
            assert client.get("/api/v1/analysis/threat-entities?extra=1").status_code == 422
            assert client.get("/api/v1/analysis/threat-entities?limit=1&limit=2").status_code == 422
            assert client.get("/api/v1/analysis/threat-entities?limit=101").status_code == 422
            assert client.get("/api/v1/analysis/threat-entities?entity_type=credential").status_code == 422
            response = client.get("/api/v1/analysis/threat-entities/not-a-uuid")
            assert response.status_code == 422
            assert "postgresql" not in response.text.lower()
    finally:
        app.dependency_overrides.clear()


def test_indicator_routes_require_analysis_permission_directly() -> None:
    app.dependency_overrides[get_db_session] = lambda: FailingSession()
    app.dependency_overrides[analyst.indicator_rate_limit] = lambda: None
    try:
        with TestClient(app) as client:
            assert client.get("/api/v1/analysis/indicators?q=example").status_code == 401
        app.dependency_overrides[require_analysis_use] = lambda: None
        with TestClient(app) as client:
            # Authorization succeeds; the fake database then fails safely.
            response = client.get("/api/v1/analysis/indicators?q=example")
            assert response.status_code == 500
            assert response.json() == {"detail": "Unable to load indicators."}
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/analysis/threat-entities",
        f"/api/v1/analysis/threat-entities/{THREAT_ID}",
        f"/api/v1/analysis/items/{ITEM_ID}/provenance",
        "/api/v1/analysis/uae-intelligence",
    ],
)
def test_content_analyst_routes_enforce_permission_directly(path: str) -> None:
    with TestClient(app) as client:
        response = client.get(path)
    assert response.status_code == 401
    assert "postgresql" not in response.text.lower()


def test_analyst_safe_404_and_429_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        AnalystQueryService,
        "get_threat_entity",
        lambda *_: (_ for _ in ()).throw(AnalystNotFoundError("private-canary")),
    )
    app.dependency_overrides[get_db_session] = lambda: object()
    app.dependency_overrides[require_content_read] = lambda: None
    app.dependency_overrides[analyst.threat_rate_limit] = lambda: None
    try:
        with TestClient(app) as client:
            not_found = client.get(
                f"/api/v1/analysis/threat-entities/{THREAT_ID}"
            )
        assert not_found.status_code == 404
        assert not_found.json() == {
            "detail": "The requested threat metadata was not found."
        }
        assert "private-canary" not in not_found.text

        def throttled() -> None:
            raise HTTPException(
                status_code=429,
                detail="Request rate limit exceeded.",
                headers={"Retry-After": "60"},
            )

        app.dependency_overrides[analyst.uae_rate_limit] = throttled
        with TestClient(app) as client:
            limited = client.get("/api/v1/analysis/uae-intelligence")
        assert limited.status_code == 429
        assert limited.json() == {"detail": "Request rate limit exceeded."}
        assert limited.headers["Retry-After"] == "60"
        assert "postgresql" not in limited.text.lower()
    finally:
        app.dependency_overrides.clear()


def test_read_rate_limiter_is_scoped_bounded_and_expires() -> None:
    now = [100.0]
    limiter = ReadRateLimiter(clock=lambda: now[0], max_keys=2)
    assert limiter.allow(session_key="one", scope="analysis.indicators", limit=2, window_seconds=60)
    assert limiter.allow(session_key="one", scope="analysis.indicators", limit=2, window_seconds=60)
    assert not limiter.allow(session_key="one", scope="analysis.indicators", limit=2, window_seconds=60)
    assert limiter.allow(session_key="one", scope="analysis.uae", limit=2, window_seconds=60)
    assert not limiter.allow(session_key="two", scope="analysis.uae", limit=2, window_seconds=60)
    now[0] = 161.0
    assert limiter.allow(session_key="two", scope="analysis.uae", limit=2, window_seconds=60)


def test_invalid_rate_limit_configuration_fails_closed() -> None:
    limiter = ReadRateLimiter(clock=lambda: 1.0)
    assert not limiter.allow(session_key="", scope="analysis.uae", limit=1, window_seconds=60)
    assert not limiter.allow(session_key="one", scope="bad scope", limit=1, window_seconds=60)
    try:
        require_read_rate_limit("bad scope")
    except ValueError as exc:
        assert str(exc) == "Read rate-limit configuration is invalid."
    else:
        raise AssertionError("Invalid rate-limit scope must be rejected.")
