from pathlib import Path
import re


REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"
OPERATOR_GUIDE = REPO_ROOT / "docs" / "operator-guide.md"
DEPLOYMENT_NOTES = REPO_ROOT / "docs" / "deployment-notes.md"


def readme_text() -> str:
    return README.read_text(encoding="utf-8")


def normalized_readme() -> str:
    return re.sub(r"\s+", " ", readme_text()).lower()


def assert_in_order(document: str, phrases: tuple[str, ...]) -> None:
    cursor = -1
    for phrase in phrases:
        next_cursor = document.find(phrase, cursor + 1)
        assert next_cursor > cursor, f"Missing or out-of-order README phrase: {phrase}"
        cursor = next_cursor


def test_readme_leads_with_project_overview_and_fresh_laptop_setup() -> None:
    readme = normalized_readme()

    assert README.is_file()
    assert "# alpha data / cyber osint dashboard" in readme
    assert "full-stack defensive cybersecurity osint platform" in readme
    assert "mentor-accessible external staging host" in readme
    assert_in_order(
        readme,
        (
            "# alpha data / cyber osint dashboard",
            "## start here — fresh laptop setup",
            "### 1. install the required tools",
            "### 2. clone the authoritative repository and select `main`",
            "### 3. create the local environment files safely",
            "### 4. start and initialize the complete application",
            "### 5. verify successful startup",
            "### 6. create the first application administrator",
            "### 7. sign in and make the first review",
            "### 8. verify prefect without starting ingestion",
            "### 9. stop and restart safely",
        ),
    )


def test_readme_fresh_setup_is_executable_and_complete() -> None:
    raw = readme_text()
    readme = normalized_readme()

    for command in (
        'git clone "https://github.com/midhun00071/cyber-osint-dashboard.git"',
        "git switch main",
        "git pull --ff-only origin main",
        ".\\run.cmd setup",
        ".\\run.cmd",
        "docker compose ps",
        "http://localhost:8000/api/health",
        "http://localhost:3000/",
        "docker compose exec backend python -m app.security.bootstrap_admin_cli",
        "docker compose exec -t prefect-worker python -m app.orchestration.deployments --verify-registration",
        "docker compose down",
    ):
        assert command in readme

    for phrase in (
        "docker compose v2",
        "does **not** require python or node.js on the host",
        "creates only missing files and never overwrites",
        "no user",
        "there is no default password",
        "public self-registration does not exist",
        "a newly created deployment is deliberately **paused**",
        "does **not** launch a manual flow",
        "does not contact an external intelligence source",
        "data-destruction warning",
    ):
        assert phrase in readme

    assert "prefect deployment schedule resume" in raw
    assert "APPROVED_REPOSITORY_URL" not in raw
    assert "`git branch --show-current` must print `main`" in raw


def test_readme_enforces_future_proof_main_handover_policy() -> None:
    raw = readme_text()
    readme = normalized_readme()

    for phrase in (
        "## final release and handover state",
        "**12 august 2026**",
        "`main` the authoritative mentor, operator, and future-development branch",
        "authoritative handover branch | `main`",
        "mentor/developer working branch | `main`",
        "historical release-preparation branch | `dev`",
        "preparation and validation context only, not a mentor checkout instruction",
        "this document does not invent or predeclare it",
        "mentor-accessible external staging | not claimed",
        "8e584852-6ffc-4806-9cc9-22b758767bf3",
        "`paused=false`, `ready`, one active schedule",
    ):
        assert phrase in readme

    for stale_phrase in (
        "current implementation branch",
        "main_promotion=pending",
        "promotion to `main` | **pending**",
        "git switch dev",
        "checkout dev",
        "authoritative handover branch | `dev`",
    ):
        assert stale_phrase not in readme

    assert raw.count("https://github.com/midhun00071/cyber-osint-dashboard.git") >= 1


def test_readme_explains_environment_and_secret_boundaries() -> None:
    raw = readme_text()
    readme = normalized_readme()

    for path in (
        ".env.example",
        "backend/.env.example",
        "frontend/.env.example",
        ".env.production.example",
        "scripts/setup-dev.ps1",
        "backend/app/core/config.py",
        "backend/app/db/session.py",
        "frontend/src/config/publicEnvironment.ts",
        "docker-compose.yml",
        "compose.prod.yml",
    ):
        assert path in raw

    for phrase in (
        "source code / example templates",
        "real environment values / credentials",
        "never committed",
        "process environment variables before `backend/.env`",
        "secretstr",
        "must never be placed in `next_public_*`",
        "staging and production add stricter rules",
        "database password must come from a readable protected secret file",
        "never print resolved compose configuration",
    ):
        assert phrase in readme


def test_readme_explains_architecture_and_major_modules() -> None:
    raw = readme_text()
    readme = normalized_readme()

    assert_in_order(
        readme,
        (
            "approved public source or reviewed local catalogue",
            "fixed source collector/client",
            "source-specific adapter or normalizer",
            "ingestion/publication service",
            "sqlalchemy transaction and postgresql",
            "query service",
            "allow-listed fastapi schema",
            "validated frontend api client",
            "authenticated dashboard page",
        ),
    )

    for path in (
        "backend/app/main.py",
        "backend/app/api/v1/routes/",
        "backend/app/api/v1/schemas/",
        "backend/app/services/",
        "backend/app/security/",
        "backend/app/ingestion/source_registry.py",
        "backend/app/ingestion/collectors/",
        "backend/app/ingestion/normalizers/",
        "backend/app/ingestion/adapters/",
        "backend/app/orchestration/flows.py",
        "backend/app/orchestration/deployments.py",
        "backend/app/runtime_bootstrap.py",
        "backend/app/models/",
        "backend/alembic/versions/",
        "frontend/src/app/",
        "frontend/src/services/",
    ):
        assert path in raw


def test_readme_explains_ingestion_integrity_and_safety() -> None:
    readme = normalized_readme()

    for heading in (
        "### 1. source registry and policy",
        "### 2. collection/client layer",
        "### 3. adapter and normalizer layer",
        "### 4. persistence, identity, and deduplication",
        "### 5. operational state and progress",
        "### 6. failure, retry, and source isolation",
        "### 7. example scheduled lifecycle",
    ):
        assert heading in readme

    for slug in (
        "nvd",
        "first-epss",
        "cisa-kev",
        "cert-eu-security-advisories",
        "google-threat-intelligence-public-research",
        "mandiant-public-threat-research",
    ):
        assert f"`{slug}`" in readme

    for manual_slug in (
        "anomali-cyber-watch",
        "censys-arc-research",
        "censys-rapid-response-advisories",
        "ibm-x-force-public-osint-advisories",
        "ibm-x-force-public-research",
    ):
        assert f"`{manual_slug}`" in readme

    for phrase in (
        "checkpoint/watermark progress advances safely",
        "progress never advances merely because a request returned",
        "one source failure does not stop unrelated sources",
        "not an arbitrary url",
        "do not scan targets",
        "download malware",
        "execute exploits",
        "fake success",
        "registered does not mean scheduled",
    ):
        assert phrase in readme


def test_readme_records_final_runtime_and_bootstrap_proof() -> None:
    readme = normalized_readme()

    for phrase in (
        "expected sources = **6**",
        "started = **6**",
        "completed = **6**",
        "successful = **6**",
        "non-successful = **0**",
        "manual-only recurring rows = **0**",
        "parent status = `success`",
        "100 nvd vulnerabilities",
        "4 cert-eu advisories",
        "4 google threat intelligence publications",
        "4 mandiant publications",
        "a second startup imports 0 duplicates",
    ):
        assert phrase in readme


def test_readme_explains_fresh_bootstrap_without_fabricating_history() -> None:
    readme = normalized_readme()

    for phrase in (
        "exactly **112** records",
        "**100** nvd vulnerabilities",
        "**4** cert-eu security advisories",
        "**4** google threat intelligence",
        "**4** mandiant",
        "runs only when all core intelligence tables are genuinely empty",
        "creates no default user",
        "no `ingestioncycle`",
        "no `ingestionrun`",
        "no checkpoint",
        "no watermark",
        "no fabricated collection history",
        "application initialization",
        "live/scheduled ingestion",
    ):
        assert phrase in readme


def test_readme_explains_prefect_database_authentication_and_ui() -> None:
    readme = normalized_readme()

    for phrase in (
        "a **flow** is python code",
        "a **deployment** is the registered runnable configuration",
        "a **work pool** is the queueing boundary",
        "a **worker** polls that pool",
        "every two hours at minute 17 in dubai time",
        "`cancel_new`",
        "postgresql is alpha data's system of record",
        "alembic migrations are the ordered, committed history",
        "create a **new** alembic migration; never edit a committed migration",
        "exactly one linear head",
        "least privilege",
        "argon2id",
        "opaque session",
        "backend is authoritative",
        "**overview**",
        "**threat feed**",
        "**vulnerabilities**",
        "**uae intelligence**",
        "**ioc search**",
        "**sources**",
        "**ingestion operations**",
        "**run history**",
        "**reports**",
        "**system health**",
        "**audit log**",
        "**methodology**",
        "**user access**",
    ):
        assert phrase in readme


def test_readme_contains_complete_new_source_extension_runbook() -> None:
    raw = readme_text()
    readme = normalized_readme()

    assert_in_order(
        readme,
        (
            "## adding a new ingestion source",
            "### 1. approve and freeze the source policy",
            "### 2. register identity without implying scheduling",
            "### 3. configure credentials and limits safely",
            "### 4. implement the fixed-policy client",
            "### 5. normalize into canonical data",
            "### 6. reuse the canonical database model",
            "### 7. persist idempotently through the service layer",
            "### 8. define incremental progress safely",
            "### 9. bind the handler and prefect flow",
            "### 10. decide scheduled versus manual explicitly",
            "### 11. preserve the deployment model",
            "### 12. validate offline before any live request",
            "### 13. gate and record live validation",
            "### 14. update the operator and product documentation",
            "### 15. source completion checklist",
        ),
    )

    for phrase in (
        "never accept a runtime-supplied api root",
        "registered does not mean scheduled",
        "a new source does **not** automatically justify a new table",
        "never advance progress",
        "one source exception must remain isolated",
        "never auto-enable a commercial source",
        "do not add a second scheduler",
        "an http 200 alone is never evidence",
        "manual-only sources stayed outside the recurring cycle",
    ):
        assert phrase in readme

    assert raw.count("- [ ]") >= 25


def test_readme_includes_validation_troubleshooting_limitations_and_references() -> None:
    raw = readme_text()
    readme = normalized_readme()

    for phrase in (
        "## testing and validation",
        ".\\run.cmd test",
        "**5,225 passed, 258 skipped, 56 failed, 12 warnings**",
        "54 failures",
        "powershell 7",
        "test_reviewed_sql_hashes_match_final_files",
        "test_previous_migration_files_are_byte_for_byte_unchanged",
        "38 files and 237 tests",
        "exactly one linear head",
        "not a newly demonstrated release regression",
        "## troubleshooting",
        "docker or compose is unavailable",
        "missing or invalid environment values",
        "a port is occupied",
        "database or migration validation fails",
        "first administrator or login fails",
        "prefect is unavailable, paused, or not scheduling",
        "tests stop at the powershell/checkout boundary",
        "## known limitations",
        "no mentor-accessible external staging environment",
        "off-cron parent run is not the normal validation method",
    ):
        assert phrase in readme

    for relative_path in (
        "docs/operator-guide.md",
        "docs/environment-and-secrets.md",
        "docs/data-sources.md",
        "docs/architecture.md",
        "docs/security-notes.md",
        "docs/testing-plan.md",
        "docs/manual-test-cases.md",
        "docs/production-docker-deployment.md",
        "docs/c09-recovery-runbook.md",
        "docs/deployment-notes.md",
        "docs/final-mentor-report.md",
        "docs/final-architecture-package.md",
        "backend/README.md",
        "frontend/README.md",
    ):
        assert f"({relative_path})" in raw


def test_documentation_hierarchy_keeps_readme_primary() -> None:
    readme = normalized_readme()
    operator = re.sub(
        r"\s+", " ", OPERATOR_GUIDE.read_text(encoding="utf-8")
    ).lower()
    deployment = re.sub(
        r"\s+", " ", DEPLOYMENT_NOTES.read_text(encoding="utf-8")
    ).lower()

    assert "primary, self-contained entry point" in readme
    assert "readme.md" in operator
    assert "primary self-contained" in operator
    assert "detailed specialist operational runbook" in operator
    assert "work from a verified `main` checkout" in operator
    assert "primary self-contained" in deployment
    assert "specialist operational detail" in deployment
    assert "single canonical operational runbook" not in operator
    assert "single canonical operational runbook" not in deployment
    assert "work from a verified `dev` checkout" not in operator


def test_readme_preserves_defensive_boundary_and_contains_no_obvious_secret() -> None:
    raw = readme_text()
    readme = normalized_readme()

    for phrase in (
        "defensive, ethical, authorized, educational, or lab-safe",
        "must not be used for exploit execution",
        "unauthorized scanning or probing",
        "malware retrieval/delivery",
        "external osint is untrusted data",
        "registry inclusion does not grant collection authorization",
        "licensing permission",
        "storage rights",
        "redistribution rights",
    ):
        assert phrase in readme

    private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
    prohibited_patterns = (
        re.escape(private_key_marker),
        r"(?i)[a-z]:\\users\\[^\\\s]+",
        r"(?i)\bbearer\s+[a-z0-9._~-]{16,}",
        r"(?i)\bauthorization\s*:\s*\S+",
        r"[a-z][a-z0-9+.-]*://[^\s/:@<>]+:[^\s/@<>]+@",
        r"(?im)^\s*(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S+",
    )

    assert not any(re.search(pattern, raw) for pattern in prohibited_patterns)
