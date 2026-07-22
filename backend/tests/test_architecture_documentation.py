from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse

import yaml

from app.main import app


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ARCHITECTURE_PATH = PROJECT_ROOT / "docs" / "architecture.md"
PRODUCTION_COMPOSE_PATH = PROJECT_ROOT / "compose.prod.yml"
RUN_SCRIPT_PATH = PROJECT_ROOT / "run.ps1"
FRONTEND_API_CLIENT_PATH = PROJECT_ROOT / "frontend" / "src" / "services" / "apiClient.ts"
FRONTEND_CLIENT_COMPONENT_PATHS = (
    PROJECT_ROOT / "frontend" / "src" / "components" / "HealthStatusCard.tsx",
    PROJECT_ROOT / "frontend" / "src" / "app" / "articles" / "[publicId]" / "page.tsx",
    PROJECT_ROOT
    / "frontend"
    / "src"
    / "app"
    / "vulnerabilities"
    / "[publicId]"
    / "page.tsx",
)


def architecture_text() -> str:
    return ARCHITECTURE_PATH.read_text(encoding="utf-8")


def normalized_architecture() -> str:
    return " ".join(architecture_text().split())


def test_architecture_exists_and_identifies_current_defensive_system() -> None:
    assert ARCHITECTURE_PATH.is_file()
    document = normalized_architecture().lower()

    for phrase in (
        "alpha data / cyber osint dashboard",
        "implemented technical design",
        "defensive public cybersecurity intelligence",
        "external osint is untrusted data",
        "not an aspirational design",
    ):
        assert phrase in document

    assert "phase 1 setup only" not in document
    assert "application will follow" not in document


def test_context_and_component_boundaries_are_traceable() -> None:
    document = normalized_architecture()

    for phrase in (
        "Approved public intelligence sources",
        "Explicit manual collector/CLI execution",
        "Backend ingestion, validation, and normalization",
        "SQLAlchemy ORM-managed persistence",
        "Allow-listed read-only response schemas",
        "FastAPI query endpoints",
        "Next.js frontend",
        "no direct frontend-to-source or frontend-to-PostgreSQL connection",
    ):
        assert phrase in document

    for component in (
        "Source registry",
        "Collectors",
        "Adapters and normalizers",
        "Ingestion services and CLIs",
        "Common publication pipeline",
        "PostgreSQL and SQLAlchemy",
        "FastAPI",
        "Next.js",
    ):
        assert component in document


def test_manual_ingestion_and_publication_transaction_ownership_are_accurate() -> None:
    document = normalized_architecture()

    for phrase in (
        "Ingestion is manual-only",
        "does not fetch upstream content",
        "does not commit transactions",
        "Transaction ownership is workflow-specific",
        "Censys local/live and live Anomali",
        "reviewed local-file Anomali CLI owns its own transaction",
        "no ingestion job, scheduler, recurring background worker",
        "frontend ingestion trigger",
        "public ingestion API",
    ):
        assert phrase in document

    assert "Each CLI owns commit/rollback" not in document


def test_vulnerability_publication_and_audit_flows_are_documented() -> None:
    document = normalized_architecture()

    for phrase in (
        "Operator runs NVD CLI",
        "optional later operator-run FIRST EPSS enrichment",
        "optional later operator-run CISA KEV enrichment",
        "skips unknown KEV-only entries",
        "source-specific collector or bounded file adapter",
        "PublicationCandidate",
        "article identity and deduplication",
        "IngestionRun status and bounded counters",
        "IngestionRunRecord outcomes",
        "sanitized IngestionError evidence",
    ):
        assert phrase in document


def test_documented_read_only_routes_come_from_current_fastapi_application() -> None:
    document = normalized_architecture()
    implemented_get_routes: set[str] = set()
    for route in app.routes:
        included_router = getattr(route, "original_router", None)
        if included_router is not None:
            prefix = getattr(getattr(route, "include_context", None), "prefix", "")
            implemented_get_routes.update(
                f"{prefix}{included_route.path}"
                for included_route in included_router.routes
                if "GET" in getattr(included_route, "methods", set())
            )
            continue

        path = getattr(route, "path", None)
        if (
            isinstance(path, str)
            and "GET" in getattr(route, "methods", set())
            and path not in {"/docs", "/docs/oauth2-redirect", "/openapi.json", "/redoc"}
        ):
            implemented_get_routes.add(path)

    assert implemented_get_routes == {
        "/",
        "/api/health",
        "/api/version",
        "/api/v1/articles",
        "/api/v1/articles/{public_id}",
        "/api/v1/dashboard/summary",
        "/api/v1/intelligence/items",
        "/api/v1/intelligence/items/{item_public_id}",
    }
    for route in implemented_get_routes:
        assert f"`GET {route}`" in document

    for phrase in (
        "Unknown or repeated query parameters are rejected",
        "Pydantic response fields",
        "no write, ingestion, administration, login, authentication, or authorization endpoint",
        "unauthenticated read-only interface",
    ):
        assert phrase in document


def test_frontend_data_rendering_and_link_boundaries_are_documented() -> None:
    document = normalized_architecture()

    for phrase in (
        "Next.js App Router",
        "`/articles/[publicId]`",
        "`/vulnerabilities/[publicId]`",
        "loading, success, not-found, and sanitized error states",
        "validate every JSON response shape",
        "`NEXT_PUBLIC_API_BASE_URL`",
        "`dangerouslySetInnerHTML` is not used",
        "`rel=\"noopener noreferrer\"`",
        "No authentication session or login state exists",
    ):
        assert phrase in document


def test_browser_api_data_path_is_distinct_from_compose_network_topology() -> None:
    document = normalized_architecture()
    api_client = FRONTEND_API_CLIENT_PATH.read_text(encoding="utf-8")

    assert "process.env.NEXT_PUBLIC_API_BASE_URL" in api_client
    assert all(
        path.read_text(encoding="utf-8").startswith('"use client";')
        for path in FRONTEND_CLIENT_COMPONENT_PATHS
    )

    for phrase in (
        "Dashboard and detail API calls originate in the browser",
        "public `NEXT_PUBLIC_API_BASE_URL` value is embedded in the frontend browser assets at build time",
        "frontend container does not proxy the current API requests",
        "browser has no direct access to PostgreSQL or external intelligence sources",
        "backend remains the only application component that accesses PostgreSQL",
        "container-topology property, not the current client-side API request path",
        "external browser cannot automatically resolve the Docker service hostname `backend`",
        "production CORS must allow the actual browser frontend origin",
        "repository does not implement it",
    ):
        assert phrase in document

    assert "frontend :3000 -- application network --> backend :8000" not in document


def test_development_runner_architecture_matches_implemented_commands() -> None:
    document = architecture_text()
    runner = RUN_SCRIPT_PATH.read_text(encoding="utf-8")
    implemented_commands = set(re.findall(r'^\s*"([a-z]+)"\s*\{', runner, re.MULTILINE))
    documented_commands = set(re.findall(r"\| `\.\\run\.cmd ([a-z]+)` \|", document))

    assert documented_commands == implemented_commands == {
        "setup",
        "install",
        "test",
        "docker",
        "dev",
        "full",
        "help",
    }
    assert r"`.\run.cmd test`" in document
    assert r"`\.\run.cmd test`" not in document

    normalized = normalized_architecture()
    for phrase in (
        "PostgreSQL in Docker while backend and frontend development servers run on the Windows host",
        "exact, case-insensitive hostname `db` to `localhost`",
        "parent environment is restored in `finally`",
        "credential-bearing URL must not be printed",
        "database container remains running",
        "not production controls",
    ):
        assert phrase in normalized


def test_production_architecture_matches_compose_service_and_network_contracts() -> None:
    compose = yaml.safe_load(PRODUCTION_COMPOSE_PATH.read_text(encoding="utf-8"))
    document = normalized_architecture()

    assert set(compose["services"]) == {"db", "backend", "frontend", "migrate"}
    assert compose["services"]["migrate"]["profiles"] == ["migration"]
    assert "ports" not in compose["services"]["db"]
    assert compose["networks"]["database"]["internal"] is True
    assert compose["services"]["frontend"]["networks"] == ["application"]
    assert compose["services"]["backend"]["networks"] == [
        "application",
        "database",
    ]
    assert compose["services"]["db"]["networks"] == ["database"]

    for phrase in (
        "lists `db`, `backend`, and `frontend`",
        "`migrate` service appears only when the `migration` profile is enabled",
        "database has no production host port by default",
        "internal database network",
        "dedicated non-root users (`appuser` and `nextjs`)",
        "`no-new-privileges`",
        "drop all Linux capabilities",
        "three 10 MiB files",
        "No development reload server",
    ):
        assert phrase in document


def test_database_migrations_role_and_persistence_limitations_are_honest() -> None:
    document = normalized_architecture()

    for phrase in (
        "Alembic owns schema migration",
        "application startup does not run migrations",
        "persistent storage across container recreation",
        "It is not a backup",
        "`docker compose down -v` deletes the persistent PostgreSQL volume",
        "creates a privileged PostgreSQL role",
        "reuse that privileged role",
        "No separate restricted application database role is provisioned",
        "must not be described as least privilege",
    ):
        assert phrase in document


def test_trust_security_logging_and_error_boundaries_are_documented() -> None:
    document = normalized_architecture()

    for phrase in (
        "exact environment-driven allow-list",
        "`X-Content-Type-Options: nosniff`",
        "`X-Frame-Options: DENY`",
        "`Referrer-Policy: no-referrer`",
        "server-generated `X-Request-ID`",
        "Uvicorn access logging is disabled",
        "Raw source payloads and internal exception details",
        "React escapes text",
        "No user authentication, authorization",
        "centralized log aggregation, monitoring, alerting",
    ):
        assert phrase in document


def test_absent_production_and_collection_capabilities_are_explicit() -> None:
    document = normalized_architecture().lower()

    for phrase in (
        "tls termination",
        "reverse proxy",
        "automated postgresql backups",
        "validated disaster recovery",
        "centralized logging",
        "production monitoring",
        "ci/cd deployment",
        "kubernetes",
        "automated secret rotation",
        "zero-downtime deployment",
        "production load testing",
        "validated public-internet deployment",
        "arbitrary url ingestion",
        "active scanning/probing",
        "active ioc validation",
        "malware retrieval",
        "exploit execution",
    ):
        assert phrase in document


def test_architecture_has_no_private_path_or_secret_and_all_links_resolve() -> None:
    document = architecture_text()
    prohibited_patterns = (
        r"(?i)[a-z]:\\users\\[^\\\s]+",
        r"(?i)\bbearer\s+[a-z0-9._~-]{16,}",
        r"(?i)\bauthorization\s*:\s*\S+",
        r"[a-z][a-z0-9+.-]*://[^\s/:@<>]+:[^\s/@<>]+@",
        r"(?im)^\s*(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S+",
    )
    assert not any(re.search(pattern, document) for pattern in prohibited_patterns)

    links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", document)
    assert links
    for target in links:
        parsed = urlparse(target)
        if parsed.scheme or target.startswith("#"):
            continue
        assert parsed.path
        assert (ARCHITECTURE_PATH.parent / parsed.path).resolve().is_file()
