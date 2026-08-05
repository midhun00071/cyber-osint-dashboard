from pathlib import Path
import re


REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"
RUN_SCRIPT = REPO_ROOT / "run.ps1"


def readme_text() -> str:
    return README.read_text(encoding="utf-8")


def normalized_readme() -> str:
    return re.sub(r"\s+", " ", readme_text()).lower()


def test_readme_exists_and_identifies_the_project_and_handover_audience() -> None:
    assert README.is_file()
    readme = normalized_readme()

    assert "# alpha data / cyber osint dashboard" in readme
    assert "full-stack defensive cybersecurity osint dashboard" in readme
    assert "mentor and senior-reviewer handover" in readme
    assert "not a claim of a complete, public-internet-ready production platform" in readme


def test_readme_preserves_defensive_and_untrusted_content_boundaries() -> None:
    readme = normalized_readme()

    for required_phrase in (
        "defensive, ethical, authorized, educational, or lab-safe",
        "must not be used for exploit execution",
        "unauthorized scanning or probing",
        "malware retrieval",
        "external osint content is untrusted data",
        "fixed, developer-controlled sources",
        "source-registry entry does not grant collection authorization",
        "licensing",
        "storage rights",
        "redistribution rights",
    ):
        assert required_phrase in readme


def test_readme_states_manual_only_ingestion_without_stale_scheduler_claims() -> None:
    raw_readme = readme_text()
    readme = normalized_readme()

    for required_phrase in (
        "ingestion remains manual-only",
        "no active scheduler",
        "startup ingestion",
        "recurring background ingestion",
        "public ingestion api",
        "frontend ingestion trigger",
        "no command below runs on fastapi startup",
    ):
        assert required_phrase in readme

    for stale_claim in (
        "Automated open-source intelligence ingestion",
        "Background scheduling: APScheduler for MVP",
        "in the MVP ingestion and backend foundation stage",
    ):
        assert stale_claim not in raw_readme

    for c01_phrase in (
        "prefect is pinned exactly to 3.8.1",
        "`17 */2 * * *` in `asia/dubai` with parent concurrency one",
        "registration is explicit and paused by default",
        "c01 did not activate a schedule or execute a source workflow",
        "production binding registry is intentionally empty",
        "activation fails closed while scheduled-eligible handlers are missing",
        "compose does not register or execute the deployment",
    ):
        assert c01_phrase in readme


def test_readme_documents_curated_nvd_as_bounded_manual_sample() -> None:
    readme = normalized_readme()

    for required_phrase in (
        "manual curated multi-year nvd dataset",
        "representative sample rather than a complete nvd mirror",
        "10 critical, 5 high, 3 medium, and 2 low",
        "app.ingestion.nvd_curated_cli --plan",
        "capped or incomplete",
        "unrelated cves are never deleted",
        "first epss and cisa kev commands separately",
        "stops its decoded streaming read immediately above 20 mib",
        "retains at most 10 critical, 5 high, 3 medium, and 2 low",
        "valid unselected observations as skipped",
        "does not prove a not-listed kev result for every local cve",
        "app.ingestion.cisa_kev_reconcile_cli",
        "validates every declared catalog entry",
        "controlled `partial` result",
        "`unknown_remaining` count includes only selected rows",
        "formal `ingestionrun` counters describe local rows",
        "catalog raw-record and unique-cve counts remain separate",
        "checked time after complete validation immediately before local reconciliation",
        "lowest local vulnerability ids",
        "future cursor/resume enhancement",
        "exactly one outcome per unique vulnerability row",
        "ambiguous identity never selects a cve based on identifier query order",
        "catalog-version evidence is restricted to a non-empty, bounded ascii token",
        "this product uses data from the nvd api but is not endorsed or certified by the nvd",
    ):
        assert required_phrase in readme


def test_documented_runner_commands_match_the_runner_switch() -> None:
    readme = readme_text()
    runner = RUN_SCRIPT.read_text(encoding="utf-8")
    runner_section = readme.split("### Runner commands", 1)[1].split("## ", 1)[0]

    documented_commands = set(
        re.findall(r"\| `\.\\run\.cmd ([a-z]+)` \|", runner_section)
    )
    implemented_commands = set(re.findall(r'(?m)^\s*"([a-z]+)"\s*\{', runner))

    assert documented_commands == implemented_commands == {
        "setup",
        "install",
        "test",
        "docker",
        "dev",
        "full",
        "help",
    }


def test_local_development_and_production_instructions_are_separate() -> None:
    raw_readme = readme_text()
    readme = normalized_readme()

    assert raw_readme.index("## Local development") < raw_readme.index(
        "## Production-oriented deployment"
    )
    for required_phrase in (
        "development and local validation commands, not production deployment commands",
        "do not use `.\\run.cmd dev`",
        "do not use `.\\run.cmd dev`, `.\\run.cmd docker`, `docker-compose.yml`",
        "standalone [`compose.prod.yml`](compose.prod.yml)",
        "hardened production-oriented baseline",
        "not a complete or validated public-internet production platform",
    ):
        assert required_phrase in readme


def test_readme_links_the_canonical_handover_documents() -> None:
    raw_readme = readme_text()

    for relative_path in (
        "docs/architecture.md",
        "docs/data-sources.md",
        "docs/source-assessment-matrix.md",
        "docs/source-integration-policy.md",
        "docs/security-notes.md",
        "docs/testing-plan.md",
        "docs/manual-test-cases.md",
        "docs/environment-and-secrets.md",
        "docs/production-docker-deployment.md",
        "docs/b2-01-prefect-platform.md",
        "docs/c01-prefect-orchestration-core.md",
        "docs/deployment-build-validation.md",
    ):
        assert f"({relative_path})" in raw_readme


def test_readme_records_current_database_and_persistence_limitations() -> None:
    readme = normalized_readme()

    for required_phrase in (
        "operator-selected bootstrap identity for initialization and administration",
        "normal runtime does not reuse it",
        "separate non-superuser migration identity",
        "separate least-privilege runtime application identity",
        "three login passwords through separate secret files",
        "publishes no postgresql host port",
        "named `postgres_data` volume is persistent storage, not a backup",
        "automated backup and tested recovery are not implemented",
        "destructive retention remains disabled until its safety and recovery evidence exists",
        "`docker compose down -v` deletes the persistent postgresql volume",
        "it is not routine cleanup",
        "explicit authorization",
    ):
        assert required_phrase in readme

    assert "reuses that privileged role for backend and migration access" not in readme
    assert "no separate restricted application role is provisioned" not in readme


def test_readme_represents_production_limitations_honestly() -> None:
    readme = normalized_readme()

    for required_phrase in (
        "tls termination",
        "reverse proxy",
        "load balancer",
        "automated postgresql backups",
        "representative restore testing",
        "validated disaster recovery",
        "centralized logging",
        "production monitoring",
        "alerting",
        "ci/cd deployment",
        "kubernetes or another orchestration platform",
        "zero-downtime deployment",
        "automated secret rotation",
        "production load",
        "public-internet deployment have not been validated",
    ):
        assert required_phrase in readme


def test_readme_contains_no_developer_path_or_obvious_secret_assignment() -> None:
    readme = readme_text()
    private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
    prohibited_patterns = (
        re.escape(private_key_marker),
        r"(?i)[a-z]:\\users\\[^\\\s]+",
        r"(?i)\bbearer\s+[a-z0-9._~-]{16,}",
        r"(?i)\bauthorization\s*:\s*\S+",
        r"[a-z][a-z0-9+.-]*://[^\s/:@<>]+:[^\s/@<>]+@",
        r"(?im)^\s*(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S+",
    )

    assert not any(re.search(pattern, readme) for pattern in prohibited_patterns)


def test_readme_does_not_describe_unfinished_p8_tasks_as_complete() -> None:
    readme = readme_text()

    assert not re.search(
        r"(?is)\bP8-0[2-6]\b.{0,80}\b(?:complete|completed|implemented|passed)\b",
        readme,
    )


def test_readme_documents_c05_disabled_fixture_only_contract() -> None:
    document = readme_text()
    assert "C05 official public sources" in document
    assert "MITRE ATT&CK Enterprise TAXII/STIX 2.1" in document
    assert "CERT-FR alerts" in document
    assert "UK NCSC Threat Reports" in document
    assert "implemented but disabled" in document
    assert "made no live request" in document
    assert "No database migration was added" in document
    assert "c05-official-public-sources.md" in document


def test_readme_documents_current_c06_authentication_and_pending_frontend() -> None:
    readme = normalized_readme()
    for phrase in (
        "opaque database-backed browser sessions",
        "sha-256 session-token and csrf-token hashes",
        "passwords use argon2id",
        "content routes require `content.read`",
        "user-management and audit-search routes are administrator-only",
        "hiding a frontend button is not authorization",
        "frontend login and protected-navigation integration remain pending",
        "no real account has been provisioned",
        "apr-13 remains pending",
        "manual bootstrap cli has not been executed",
        "sso is absent and remains approval-gated",
        "`get`, `post`, `patch`, and `options`",
        "`content-type` and `x-csrf-token`",
        "`authorization`",
    ):
        assert phrase in readme
    for obsolete in (
        "credentials are disabled",
        "method policy allows only `get`",
        "current application does not use browser cookies",
    ):
        assert obsolete not in readme
