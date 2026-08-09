"""C10 static controls for production dependency and container provenance."""

from __future__ import annotations

from pathlib import Path
import re


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PINNED_IMAGE = re.compile(r"^FROM\s+[^\s]+@sha256:[0-9a-f]{64}(?:\s+AS\s+\w+)?$", re.MULTILINE | re.IGNORECASE)


def test_every_production_dockerfile_base_is_digest_pinned() -> None:
    dockerfiles = (
        REPOSITORY_ROOT / "backend" / "Dockerfile.prod",
        REPOSITORY_ROOT / "frontend" / "Dockerfile.prod",
        REPOSITORY_ROOT / "database" / "Dockerfile.prod",
        REPOSITORY_ROOT / "prefect" / "Dockerfile",
        REPOSITORY_ROOT / "ops" / "caddy" / "Dockerfile",
        REPOSITORY_ROOT / "ops" / "backup" / "Dockerfile.validation",
    )
    for dockerfile in dockerfiles:
        from_lines = [line for line in dockerfile.read_text(encoding="utf-8").splitlines() if line.startswith("FROM ")]
        assert from_lines
        assert all(PINNED_IMAGE.fullmatch(line) for line in from_lines), dockerfile


def test_direct_production_python_requirements_are_exactly_pinned() -> None:
    lines = (REPOSITORY_ROOT / "backend" / "requirements.prod.txt").read_text(encoding="utf-8").splitlines()
    requirements = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    assert requirements
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^\s]+", item) for item in requirements)


def test_edge_uses_deterministic_caddy_inputs_without_repository_time_upgrade() -> None:
    dockerfile = (REPOSITORY_ROOT / "ops" / "caddy" / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.startswith(
        "FROM caddy:2.11.4-alpine@sha256:"
        "5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"
    )
    normalized = re.sub(r"\\\s*\n", " ", dockerfile.lower())
    assert not re.search(r"\bapk\s+upgrade\b", normalized)
    assert ":latest" not in normalized
    assert "c-ares=1.34.8-r0" in normalized
    assert "curl=8.20.0-r0" in normalized
    assert "libcurl=8.20.0-r0" in normalized

    for arguments in re.findall(r"\bapk\s+add\b([^;&\n]*)", normalized):
        packages = [token for token in arguments.split() if not token.startswith("-")]
        assert packages
        assert all("=" in package for package in packages)


def test_tracked_environment_templates_do_not_contain_secret_values() -> None:
    templates = (
        REPOSITORY_ROOT / ".env.example",
        REPOSITORY_ROOT / ".env.production.example",
        REPOSITORY_ROOT / "backend" / ".env.example",
        REPOSITORY_ROOT / "frontend" / ".env.example",
    )
    secret_name = re.compile(r"(?:PASSWORD|TOKEN|API_KEY|DATABASE_URL|PRIVATE_KEY)$")
    for template in templates:
        for line in template.read_text(encoding="utf-8").splitlines():
            if not line or line.lstrip().startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", maxsplit=1)
            if secret_name.search(name):
                assert (
                    value == ""
                    or "${" in value
                    or "replace" in value.lower()
                    or "example" in value.lower()
                    or "change-me" in value.lower()
                )
