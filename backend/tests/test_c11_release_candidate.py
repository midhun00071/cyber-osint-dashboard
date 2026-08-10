from pathlib import Path

from app.main import app
from app.orchestration.deployments import (
    CRON,
    DEPLOYMENT_CONCURRENCY,
    DEPLOYMENT_NAME,
    TIMEZONE,
    deployment_specification,
)
from app.orchestration.flows import DEFAULT_SOURCE_HANDLERS
from app.orchestration.source_handlers import C02_BOUND_SOURCE_SLUGS
from app.ingestion.source_registry import get_source_definition


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_DISABLED_SOURCES = {
    "mitre-attack-enterprise",
    "cert-fr-security-alerts",
    "cert-fr-security-advisories",
    "uk-ncsc-threat-reports",
}
EXPECTED_RELEASE_READ_PATHS = {
    "/api/v1/dashboard/summary",
    "/api/v1/articles",
    "/api/v1/intelligence/items",
    "/api/v1/analysis/uae-intelligence",
    "/api/v1/analysis/indicators",
    "/api/v1/ingestion/operations/summary",
    "/api/v1/sources",
    "/api/v1/ingestion/runs",
    "/api/v1/reports/catalog",
    "/api/v1/system/health",
    "/api/v1/audit/events",
}


def test_release_api_inventory_and_bounds_remain_present() -> None:
    paths = app.openapi()["paths"]
    assert EXPECTED_RELEASE_READ_PATHS <= set(paths)
    for path in EXPECTED_RELEASE_READ_PATHS:
        assert "get" in paths[path]

    assert paths["/api/v1/articles"]["get"]["parameters"][0]["schema"]["maximum"] == 100
    assert paths["/api/v1/intelligence/items"]["get"]["parameters"][0]["schema"]["maximum"] == 100
    assert paths["/api/v1/analysis/uae-intelligence"]["get"]["parameters"][0]["schema"]["maximum"] == 100
    assert paths["/api/v1/analysis/indicators"]["get"]["parameters"][0]["schema"]["maximum"] == 100


def test_post_c11_source_bindings_are_exact_and_frozen_sources_disabled() -> None:
    assert frozenset(DEFAULT_SOURCE_HANDLERS) == C02_BOUND_SOURCE_SLUGS
    for slug in EXPECTED_DISABLED_SOURCES:
        definition = get_source_definition(slug)
        assert definition.enabled is False


def test_two_hour_parent_schedule_is_single_paused_by_default_contract() -> None:
    specification = deployment_specification()
    assert DEPLOYMENT_NAME == "alpha-data-ingestion-cycle"
    assert CRON == "17 */2 * * *"
    assert TIMEZONE == "Asia/Dubai"
    assert DEPLOYMENT_CONCURRENCY == 1
    assert specification.cron == CRON
    assert specification.timezone == TIMEZONE
    assert specification.concurrency_limit == DEPLOYMENT_CONCURRENCY
    assert specification.paused is True


def test_committed_migration_set_has_expected_release_head_file() -> None:
    versions = REPOSITORY_ROOT / "backend" / "alembic" / "versions"
    migration_names = {path.name for path in versions.glob("*.py")}
    assert "c07a01b02c03_add_source_operator_state.py" in migration_names
    assert len(migration_names) == 8
