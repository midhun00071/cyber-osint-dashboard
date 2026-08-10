from pathlib import Path
import re


REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT_GUIDE = REPO_ROOT / "docs" / "production-docker-deployment.md"
ENVIRONMENT_GUIDE = REPO_ROOT / "docs" / "environment-and-secrets.md"
README = REPO_ROOT / "README.md"


def normalized_guide() -> str:
    guide = re.sub(
        r"(?m)^>\s?",
        "",
        DEPLOYMENT_GUIDE.read_text(encoding="utf-8").lower(),
    )
    return re.sub(
        r"\s+",
        " ",
        guide,
    )


def test_canonical_deployment_guide_exists_and_is_linked() -> None:
    assert DEPLOYMENT_GUIDE.is_file()
    assert ENVIRONMENT_GUIDE.is_file()
    assert "(docs/production-docker-deployment.md)" in README.read_text(
        encoding="utf-8"
    )


def test_guide_identifies_production_entry_point_and_environment_reference() -> None:
    guide = normalized_guide()

    assert "`compose.prod.yml`" in guide
    assert "(environment-and-secrets.md)" in guide
    assert "local development" in guide
    assert "local production-style validation" in guide
    assert "real production deployment" in guide
    assert "destructive maintenance" in guide
    assert "do not use `.\\run.cmd dev`" in guide


def test_architecture_matches_current_services_networks_and_persistence() -> None:
    guide = normalized_guide()

    for service in ("`db`", "`backend`", "`frontend`", "`migrate`"):
        assert service in guide
    for required_phrase in (
        "`migration` profile",
        "`application` network",
        "internal `database` network",
        "frontend cannot join the database network",
        "postgresql is not published to the host",
        "named `postgres_data` volume",
    ):
        assert required_phrase in guide


def test_security_model_records_implemented_controls_and_database_limitation() -> None:
    guide = normalized_guide()

    for required_phrase in (
        "dedicated non-root users",
        "non-privileged",
        "`no-new-privileges`",
        "drop all linux capabilities",
        "no application source, docker socket, environment file, or host directory",
        "no reload server",
        "exact https cors origins",
        "normal startup does not run alembic migrations",
        "startup path performs no ingestion",
        "superuser privileges",
        "backend and migration access",
        "does not provision a separate restricted application role",
        "non-superuser application role",
        "future, separately reviewed work",
    ):
        assert required_phrase in guide

    assert "least-privilege application role" not in guide


def test_prerequisites_and_preflight_checks_are_safe_and_reviewable() -> None:
    guide = normalized_guide()

    for required_term in (
        "docker engine",
        "docker compose v2 plugin",
        "docker desktop",
        "git and powershell",
        "git status --short",
        "git rev-parse head",
        "docker version",
        "docker compose version",
        "config --quiet",
        "config --services",
        "get-nettcpconnection",
    ):
        assert required_term in guide
    assert "do not replace them with unrestricted `docker compose config`" in guide


def test_runtime_and_migration_profile_validation_are_distinct() -> None:
    raw_guide = DEPLOYMENT_GUIDE.read_text(encoding="utf-8").lower()
    commands = re.sub(r"`\r?\n\s*", " ", raw_guide)
    commands = re.sub(r"\s+", " ", commands)
    guide = normalized_guide()

    normal_prefix = "docker compose -f $composefile --env-file $prodenv"
    assert f"{normal_prefix} config --quiet" in commands
    assert f"{normal_prefix} config --services" in commands
    assert f"{normal_prefix} --profile migration config --quiet" in commands
    assert f"{normal_prefix} --profile migration config --services" in commands

    for required_phrase in (
        "normal runtime validation excludes profiled services",
        "expected service set is `db`, `backend`, and `frontend`",
        "with the `migration` profile enabled, the service set additionally includes `migrate`",
        "`migrate` is intentionally excluded from normal runtime configuration and normal startup",
        "appears only when the `migration` profile is enabled or when the `migrate` service is explicitly targeted",
        "this preserves manual-only migration behavior",
        "absence from the normal runtime service list is expected, not a deployment failure",
    ):
        assert required_phrase in guide


def test_environment_and_image_build_procedures_preserve_secret_boundaries() -> None:
    guide = normalized_guide()

    for variable in (
        "`postgres_db`",
        "`postgres_user`",
        "`postgres_password`",
        "`backend_cors_allowed_origins`",
        "`next_public_api_base_url`",
    ):
        assert variable in guide
    for required_phrase in (
        "public configuration, not a secret",
        "changing it requires a frontend rebuild",
        "build --no-cache backend frontend",
        "never supply passwords, tokens, keys, database urls, or other secrets as build arguments",
        "image tags and ids",
        "`app_env=production`",
        "`debug=false`",
        "`enable_admin_ingestion=false`",
    ):
        assert required_phrase in guide


def test_manual_migration_workflow_includes_revision_verification() -> None:
    guide = normalized_guide()

    for required_phrase in (
        "migrations do not run automatically during normal startup",
        "--profile migration run --rm migrate",
        "alembic -c /app/alembic.ini heads",
        "alembic upgrade head",
        "alembic -c /app/alembic.ini current",
        "both must agree at the expected head",
        "do not generate a migration during deployment",
        "does not run ingestion",
    ):
        assert required_phrase in guide


def test_startup_health_and_cors_checks_cover_real_public_routes() -> None:
    guide = normalized_guide()

    for required_phrase in (
        "up -d db backend frontend",
        "docker compose -f $composefile --env-file $prodenv ps",
        "/api/health",
        "/api/version",
        "/api/v1/dashboard/summary",
        "/api/v1/articles",
        "/api/v1/intelligence/items",
        "frontend root",
        "http `200`",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "wildcard production cors is prohibited",
        "unapproved cors origin",
    ):
        assert required_phrase in guide


def test_logging_restart_and_troubleshooting_cover_required_failures() -> None:
    guide = normalized_guide()

    for required_phrase in (
        "logs --tail 200 backend frontend db",
        "bounded",
        "restart backend",
        "restart frontend",
        "restart loop requires investigation",
        "missing required environment value",
        "wrong backend",
        "cors mismatch",
        "postgresql is unhealthy",
        "backend cannot resolve the database",
        "migration not applied",
        "port conflict",
        "production build fails",
        "database volume permission or corruption indicators",
        "docker desktop is running",
    ):
        assert required_phrase in guide


def test_update_and_rollback_require_evidence_and_schema_compatibility() -> None:
    guide = normalized_guide()

    for required_phrase in (
        "update and redeployment workflow",
        "review the approved release notes",
        "record their tags and ids",
        "does not provide zero-downtime deployment",
        "recorded prior git commit",
        "schema-compatibility decision",
        "stop frontend backend",
        "application rollback does not automatically reverse database migrations",
        "alembic downgrade must not be run casually",
        "separately validated recovery plan",
    ):
        assert required_phrase in guide


def test_shutdown_backup_and_destructive_boundaries_are_explicit() -> None:
    guide = normalized_guide()

    for required_phrase in (
        "`stop` stops services but retains their containers, networks, and volume state",
        "`down` removes the compose service containers and networks but retains named volumes",
        "`docker compose down -v` deletes",
        "it is not routine cleanup",
        "c09 package implements age-encrypted postgresql and prefect backup/restore",
        "off-host destination and owner",
        "measure recovery objectives",
        "`postgres_data` volume is not a backup",
        "restore has been tested",
    ):
        assert required_phrase in guide


def test_deployment_evidence_and_known_limitations_are_complete() -> None:
    guide = normalized_guide()

    for required_phrase in (
        "deployment evidence checklist",
        "deployed git commit",
        "image tags and immutable ids",
        "alembic migration revision",
        "validation timestamp and operator",
        "rollback reference",
        "tls termination",
        "caddy reverse proxy is included",
        "encrypted database and prefect backup/restore tooling is included",
        "prometheus and alertmanager are integrated privately",
        "no centralized logging platform",
        "no ci/cd deployment workflow",
        "no orchestration platform",
        "automated secret rotation",
        "no separate restricted postgresql application role",
        "test-only dependencies are confined",
        "no public internet deployment has been validated",
    ):
        assert required_phrase in guide


def test_guide_does_not_embed_credentials_or_recommend_weakened_controls() -> None:
    raw_guide = DEPLOYMENT_GUIDE.read_text(encoding="utf-8")
    guide = re.sub(r"\s+", " ", raw_guide.lower())
    private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"

    prohibited_patterns = (
        re.escape(private_key_marker),
        r"(?i)\bbearer\s+[a-z0-9._~-]{16,}",
        r"(?i)\bauthorization\s*:\s*\S+",
        r"(?i)\bsession(?:id)?\s*=\s*[^\s#]+",
        r"[a-z][a-z0-9+.-]*://[^\s/:@<>]+:[^\s/@<>]+@",
        r"(?im)^\s*(?:postgres_)?password\s*=\s*\S+",
        r"(?im)^\s*backend_cors_allowed_origins\s*=\s*\*\s*$",
    )

    assert not any(re.search(pattern, raw_guide) for pattern in prohibited_patterns)
    assert "do not publish postgresql" in guide
    assert "mount the docker socket" in guide
    assert "enable privileged containers" in guide
    assert "/var/run/docker.sock" not in raw_guide
    assert "privileged: true" not in guide
