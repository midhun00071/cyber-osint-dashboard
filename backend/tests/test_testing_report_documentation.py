from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = PROJECT_ROOT / "docs" / "testing-report.md"
MANUAL_TEST_PATH = PROJECT_ROOT / "docs" / "manual-test-cases.md"
DEPLOYMENT_EVIDENCE_PATH = PROJECT_ROOT / "docs" / "deployment-build-validation.md"
RUN_SCRIPT_PATH = PROJECT_ROOT / "run.ps1"


def report_text() -> str:
    return REPORT_PATH.read_text(encoding="utf-8")


def normalized_report() -> str:
    return " ".join(report_text().split())


def test_report_exists_and_identifies_p8_04_review_purpose() -> None:
    assert REPORT_PATH.is_file()
    document = normalized_report()

    for phrase in (
        "P8-04 Testing Report",
        "mentor, senior cybersecurity reviewer",
        "what has been demonstrated and what still requires validation",
        "Validated evidence snapshot ready for mentor review",
    ):
        assert phrase in document

    assert "pending independent file-level review" not in document


def test_evidence_date_and_parent_checkpoint_are_explicit() -> None:
    document = normalized_report()

    assert "22 July 2026" in document
    assert "ef1307a29969c47c2289862a3ed9bd02ebbd5bc3" in document
    assert "clean pushed parent checkpoint" in document
    assert "validation performed on the two-file P8-04 working tree" in document
    assert "eventual P8-04 commit is intentionally not self-referenced" in document
    assert "trace the final commit through Git history" in document
    assert "no p8-04 commit exists before independent review" not in document.lower()


def test_current_historical_manual_and_unvalidated_evidence_are_distinct() -> None:
    document = normalized_report()

    for phrase in (
        "Current evidence",
        "Historical automated evidence",
        "Historical deployment-build evidence",
        "Available procedures or unvalidated areas",
        "A documented procedure is not an executed test",
        "A historical result is not presented as if it were rerun during P8-04",
    ):
        assert phrase in document


def test_dated_automated_snapshot_has_exact_current_results() -> None:
    document = normalized_report()

    for phrase in (
        "dated snapshot from 22 July 2026",
        "134 passed, 1 warning in 8.91 seconds",
        "5 skipped in 0.84 seconds",
        "2,747 passed, 5 skipped, 1 warning",
        "9 test files passed; 66 tests passed in 7.96 seconds",
        "Frontend TypeScript check | Passed",
        "Frontend production build | Passed",
        "exited with code 0",
        "increased from the 2,735-test parent baseline only by the 12 new P8-04 documentation tests",
    ):
        assert phrase in document

    assert "5 skipped tests passed" not in document
    assert "0 skipped" not in document
    assert "0 warning" not in document


def test_backend_and_database_coverage_is_summarized_without_overclaiming() -> None:
    document = normalized_report()

    for phrase in (
        "Health and version response shape",
        "Article APIs",
        "Intelligence APIs",
        "Pydantic allow-listed fields",
        "Database configuration",
        "Models and constraints",
        "Alembic",
        "Source registry",
        "NVD collection/normalization/persistence",
        "FIRST EPSS enrichment",
        "CISA KEV enrichment",
        "CERT-EU RSS ingestion",
        "Censys, Anomali, IBM X-Force, Google Threat Intelligence/Mandiant",
        "identity, deduplication",
        "does not claim complete path, branch, mutation, fuzz, load, penetration, or live-provider coverage",
    ):
        assert phrase in document


def test_frontend_and_security_coverage_is_precise() -> None:
    document = normalized_report()

    for phrase in (
        "Vitest, jsdom, React Testing Library",
        "loading, success, empty, not-found, and sanitized error states",
        "runtime validation of backend JSON response shapes",
        "React plain-text handling",
        "`rel=\"noopener noreferrer\"`",
        "absence of `dangerouslySetInnerHTML`",
        "Exact environment-driven origins",
        "no wildcard",
        "Server-generated request IDs",
        "secrets, authorization/cookie values, database URLs, raw SQL, stack traces, raw payloads",
        "not an independent penetration test",
    ):
        assert phrase in document


def test_ingestion_strategy_is_offline_bounded_and_manual_only() -> None:
    document = normalized_report()

    for phrase in (
        "deterministic offline evidence",
        "synthetic fixtures and reviewed local-input shapes",
        "mocked HTTP clients",
        "bounded response/file sizes and record counts",
        "no unrestricted live-source request",
        "active IOC validation",
        "malware retrieval",
        "exploit execution",
        "Ingestion remains manual-only",
        "no startup ingestion, scheduler, recurring background worker, public ingestion API, or frontend ingestion trigger",
    ):
        assert phrase in document

    assert "arbitrary URL ingestion is tested live" not in document


def test_manual_and_historical_deployment_evidence_remain_separate() -> None:
    document = normalized_report()
    manual_document = MANUAL_TEST_PATH.read_text(encoding="utf-8")
    deployment_document = DEPLOYMENT_EVIDENCE_PATH.read_text(encoding="utf-8")

    assert manual_document.count("**Status:** Not Run") == 46
    assert "All 46 formal cases remain **Not Run**" in document
    assert "P6-05 did not record those actions as executed P6-04 case IDs" in document
    assert "does not mark any manual case passed" in document
    assert "all manual tests passed" not in document.lower()

    for evidence in (
        "build --no-cache",
        "f8d739439ed0 (head)",
        "restart recovery",
        "docker compose stop",
    ):
        assert evidence in deployment_document

    for phrase in (
        "Historical P6-05 execution",
        "isolated no-cache backend and frontend image builds",
        "restart recovery in 6.4 seconds",
        "not a P8-04 rerun",
        "not a P8-04 rerun, public production certification",
    ):
        assert phrase in document


def test_warning_and_five_skip_reasons_are_not_reported_as_passes() -> None:
    document = normalized_report()

    for phrase in (
        "one pre-existing, non-blocking `StarletteDeprecationWarning`",
        "P8-04 did not introduce the warning",
        "technical debt to track",
        "Censys local publication adapter | 3",
        "Anomali local publication adapter | 1",
        "IBM X-Force local publication adapter | 1",
        "Symlink creation unavailable: OSError",
        "These five cases did not pass",
        "skipped because the current Windows process lacks the symlink-creation capability",
    ):
        assert phrase in document


def test_readiness_and_limitations_are_honest() -> None:
    document = normalized_report()

    for phrase in (
        "Controlled local demonstration | Ready",
        "Manual operational checklist | Available; not executed",
        "Public production deployment | Not validated",
        "Security certification | Not performed",
        "not certified or fully validated for unrestricted public production deployment",
        "TLS termination",
        "automated PostgreSQL backups",
        "centralized logging",
        "CI/CD deployment",
        "zero-downtime deployment",
        "production load/endurance/capacity testing",
        "formal penetration testing",
        "browser compatibility matrix",
        "visual-regression suite",
        "full accessibility/WCAG certification",
        "authentication, authorization",
        "privileged and reused by the backend and migration service",
        "persistent volume is not a backup",
        "`docker compose down -v` destroys",
    ):
        assert phrase in document


def test_reproduction_commands_and_traceability_are_present() -> None:
    document = normalized_report()
    runner = RUN_SCRIPT_PATH.read_text(encoding="utf-8")

    assert '"test" {' in runner
    assert r"`.\run.cmd test`" in document
    assert r"`\.\run.cmd test`" not in document

    for phrase in (
        "`3dfae978`",
        "`6135783`",
        "`553ab41`",
        "`589df1d`",
        "`e986a81`",
        "`6f7c958`",
        "`6e64169`",
        "`5c0c864`",
        "`446fd53`",
        "`26959f3`",
        "`ea5d0fd`",
        "`d3dee0a`",
        "`46c252e`",
        "`ef1307a`",
        "P8-04 evidence snapshot",
        "final task commit traceable through Git history",
        "Dated consolidated testing evidence for mentor review",
        "committed report and focused test retain consistent UTF-8 and repository line-ending conventions",
        "tests/test_testing_report_documentation.py",
        "npm run test:run",
        "npm run type-check",
        "npm run build",
    ):
        assert phrase in document

    for stale_phrase in (
        "no candidate commit",
        "pending review",
        "before approving staging",
    ):
        assert stale_phrase not in document.lower()


def test_report_has_no_private_path_or_secret_and_relative_links_resolve() -> None:
    document = report_text()
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
        assert (REPORT_PATH.parent / parsed.path).resolve().is_file()
