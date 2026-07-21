from pathlib import Path
import re
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENT_DOCUMENTATION = REPO_ROOT / "docs" / "environment-and-secrets.md"
README = REPO_ROOT / "README.md"
PRODUCTION_DOCUMENTATION = (
    REPO_ROOT / "docs" / "production-docker-deployment.md"
)
PRODUCTION_COMPOSE = REPO_ROOT / "compose.prod.yml"
GITIGNORE = REPO_ROOT / ".gitignore"
EXAMPLE_FILES = (
    REPO_ROOT / ".env.example",
    REPO_ROOT / ".env.production.example",
    REPO_ROOT / "backend" / ".env.example",
    REPO_ROOT / "frontend" / ".env.example",
)


def parse_active_assignments(path: Path) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        assignments[name.strip()] = value.strip()
    return assignments


def test_canonical_environment_documentation_exists_and_is_linked() -> None:
    assert ENVIRONMENT_DOCUMENTATION.is_file()
    assert "(docs/environment-and-secrets.md)" in README.read_text(encoding="utf-8")
    assert "(environment-and-secrets.md)" in PRODUCTION_DOCUMENTATION.read_text(
        encoding="utf-8"
    )


def test_verified_operator_variables_are_covered_by_canonical_document() -> None:
    documentation = ENVIRONMENT_DOCUMENTATION.read_text(encoding="utf-8")
    example_text = "\n".join(
        path.read_text(encoding="utf-8") for path in EXAMPLE_FILES
    )
    source_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            *EXAMPLE_FILES,
            REPO_ROOT / "backend" / "app" / "core" / "config.py",
            PRODUCTION_COMPOSE,
            REPO_ROOT / "docker-compose.yml",
            REPO_ROOT / "frontend" / "src" / "services" / "apiClient.ts",
        )
    )
    variable_patterns = (
        r'alias\s*=\s*["\']([A-Z][A-Z0-9_]*)["\']',
        r"\$\{([A-Z][A-Z0-9_]*)[:}]",
        r"process\.env\.([A-Z][A-Z0-9_]*)",
    )
    variables = {
        match.group(1)
        for pattern in variable_patterns
        for match in re.finditer(pattern, source_text)
    }
    variables.update(
        match.group(1)
        for match in re.finditer(
            r"(?m)^#?\s*([A-Z][A-Z0-9_]*)\s*=",
            example_text,
        )
    )

    assert variables
    assert all(f"`{variable}`" in documentation for variable in variables)


def test_example_files_use_only_safe_secret_placeholders() -> None:
    for example_file in EXAMPLE_FILES:
        assignments = parse_active_assignments(example_file)
        for name, value in assignments.items():
            if name.endswith("PASSWORD"):
                assert value == "" or value.startswith("replace_with_")
            if name.endswith("API_KEY"):
                assert value == "" or value.startswith("replace_with_")


def test_examples_contain_no_credential_or_private_key_patterns() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in EXAMPLE_FILES)
    prohibited_patterns = (
        r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----",
        r"(?i)\bbearer\s+[A-Za-z0-9._~-]+",
        r"(?i)\bauthorization\s*:",
        r"(?i)\bsession(?:id)?\s*=\s*[^\s#]+",
        r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@",
    )
    assert not any(re.search(pattern, combined) for pattern in prohibited_patterns)


def test_examples_keep_production_security_defaults_safe() -> None:
    for example_file in EXAMPLE_FILES:
        assignments = parse_active_assignments(example_file)
        cors_value = assignments.get("BACKEND_CORS_ALLOWED_ORIGINS")
        if cors_value is not None:
            assert "*" not in cors_value
        assert assignments.get("DEBUG", "false").lower() != "true"
        assert assignments.get("ENABLE_ADMIN_INGESTION", "false").lower() != "true"


def test_public_frontend_variable_is_explicitly_non_secret_and_build_time() -> None:
    documentation = ENVIRONMENT_DOCUMENTATION.read_text(encoding="utf-8").lower()
    deployment_documentation = PRODUCTION_DOCUMENTATION.read_text(
        encoding="utf-8"
    ).lower()

    assert "`next_public_api_base_url`" in documentation
    assert "public configuration" in documentation
    assert "browser-delivered" in documentation
    assert "must never contain a secret" in documentation
    assert "rebuild" in documentation
    assert "never a secret" in deployment_documentation


def test_canonical_document_prohibits_secret_leakage_channels() -> None:
    documentation = re.sub(
        r"\s+",
        " ",
        ENVIRONMENT_DOCUMENTATION.read_text(encoding="utf-8").lower(),
    )

    for required_phrase in (
        "commit a real `.env`",
        "docker build arguments",
        "authorization headers",
        "session cookies",
        "review zip",
        "task sheets",
        "daily reports",
        "screenshots",
        "chat",
        "frontend bundle",
    ):
        assert required_phrase in documentation


def test_canonical_document_includes_complete_rotation_sequence_and_limitation() -> None:
    raw_documentation = ENVIRONMENT_DOCUMENTATION.read_text(encoding="utf-8").lower()
    documentation = re.sub(r"\s+", " ", raw_documentation)

    for step in range(1, 8):
        assert re.search(rf"(?m)^{step}\. ", raw_documentation)
    for required_term in (
        "generate",
        "secret store",
        "restart or redeploy",
        "verify service health",
        "revoke",
        "review sanitized logs",
        "does not automate postgresql role-password rotation",
        "privileged initialization role",
        "database-administration password change",
        "service restart or redeployment",
        "health verification",
        "old-credential revocation",
        "do not delete the database volume",
    ):
        assert required_term in documentation


def test_current_postgres_role_privileges_and_future_boundary_are_documented() -> None:
    documentation = re.sub(
        r"\s+",
        " ",
        ENVIRONMENT_DOCUMENTATION.read_text(encoding="utf-8").lower(),
    )
    deployment_documentation = re.sub(
        r"\s+",
        " ",
        PRODUCTION_DOCUMENTATION.read_text(encoding="utf-8").lower(),
    )

    for required_phrase in (
        "official postgresql image",
        "superuser privileges",
        "backend and migration",
        "does not provision a separate restricted application role",
        "non-superuser application role",
        "separately reviewed database and deployment change",
        "outside p7-02",
        "does not implement or automate that change",
    ):
        assert required_phrase in documentation

    for required_phrase in (
        "official postgresql image",
        "superuser privileges",
        "backend and migration access",
        "does not provision a separate restricted application role",
        "non-superuser application role",
        "future, separately reviewed work",
        "not implemented or automated by p7-02",
    ):
        assert required_phrase in deployment_documentation

    assert "least-privilege application role" not in documentation


def test_gitignore_blocks_real_environment_files_and_allows_templates() -> None:
    assert GITIGNORE.is_file()

    ignored_real_files = (
        ".env",
        "backend/.env",
        "frontend/.env.local",
        ".env.production",
        "backend/.env.production",
        "frontend/.env.production.local",
    )
    for path in ignored_real_files:
        completed = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", "--", path],
            cwd=REPO_ROOT,
            check=False,
        )
        assert completed.returncode == 0, f"Expected {path} to be ignored."

    for example_file in EXAMPLE_FILES:
        relative_path = example_file.relative_to(REPO_ROOT).as_posix()
        completed = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", "--", relative_path],
            cwd=REPO_ROOT,
            check=False,
        )
        assert completed.returncode == 1, f"Expected {relative_path} to be trackable."


def test_production_compose_still_requires_sensitive_values() -> None:
    compose_text = PRODUCTION_COMPOSE.read_text(encoding="utf-8")

    for variable in (
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "BACKEND_CORS_ALLOWED_ORIGINS",
        "NEXT_PUBLIC_API_BASE_URL",
    ):
        assert f"${{{variable}:?" in compose_text

    lowered = compose_text.lower()
    assert "change_me" not in lowered
    assert "password123" not in lowered
