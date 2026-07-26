from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse

from app.ingestion.source_registry import list_enabled_implemented_sources


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_SOURCES_PATH = PROJECT_ROOT / "docs" / "data-sources.md"


def document_text() -> str:
    return DATA_SOURCES_PATH.read_text(encoding="utf-8")


def normalized_document() -> str:
    return " ".join(document_text().split())


def test_document_exists_and_traces_every_enabled_implemented_source() -> None:
    assert DATA_SOURCES_PATH.is_file()
    document = normalized_document()

    for source in list_enabled_implemented_sources():
        assert f"`{source.slug}`" in document
        assert source.display_name in document
        assert source.vendor in document
        assert f"`{source.content_family.value}`" in document
        assert f"`{source.source_type}`" in document
        assert f"`{source.access_method.value}`" in document
        assert f"`{source.base_url}`" in document
        for host in source.allowed_hosts:
            assert f"`{host}`" in document


def test_registry_status_and_manual_only_boundaries_are_explicit() -> None:
    document = normalized_document().lower()

    for phrase in (
        "registry inclusion",
        "does not grant collection authorization",
        "licensing permission",
        "all ingestion and enrichment is manual-only",
        "no active scheduler",
        "startup ingestion",
        "recurring background ingestion",
        "frontend ingestion trigger",
        "public ingestion api",
        "no standard refresh interval is implemented",
    ):
        assert phrase in document


def test_all_operator_entry_points_and_fixed_source_boundaries_are_documented() -> None:
    document = normalized_document()

    for module in (
        "app.ingestion.nvd_cli",
        "app.ingestion.nvd_curated_cli",
        "app.ingestion.epss_cli",
        "app.ingestion.cisa_kev_cli",
        "app.ingestion.cisa_kev_reconcile_cli",
        "app.ingestion.rss_cli",
        "app.ingestion.censys_publications_live_cli",
        "app.ingestion.censys_publications_cli",
        "app.ingestion.google_threat_publications_cli",
        "app.ingestion.anomali_publications_live_cli",
        "app.ingestion.anomali_publications_cli",
        "app.ingestion.ibm_x_force_publications_cli",
    ):
        assert f"-m {module}" in document

    assert "fixed endpoints" in document
    assert "no arbitrary URL input is available" in document
    assert "do not accept operator-supplied network URLs" in document
    assert "reviewed local-file fallback" in document


def test_vulnerability_and_enrichment_roles_and_fields_are_traceable() -> None:
    document = normalized_document()

    for phrase in (
        "uppercase CVE identifier",
        "CVSS score, vector, and version",
        "affected-product configuration",
        "does not mirror, NVD",
        "10 Critical, 5 High, 3 Medium, and 2 Low",
        "CISA KEV metadata first",
        "unselected records are not deleted",
        "incrementally reads decoded body bytes",
        "Default retained full-candidate limits per year",
        "valid unselected candidates as skipped",
        "does not prove a `not_listed` result",
        "Only the separate reconciliation workflow assigns `not_listed`",
        "`--max-cves` limit (1–500) applies to local rows",
        "controlled partial result",
        "`unknown_remaining` counts only selected rows",
        "Formal `IngestionRun` counters describe local rows",
        "Catalog raw-record and unique-CVE counts",
        "lowest local vulnerability IDs",
        "future cursor/resume enhancement",
        "one outcome per unique vulnerability row",
        "ambiguous identity never selects a CVE based on identifier query order",
        "Catalog version evidence is restricted to a non-empty, bounded ASCII token",
        "This product uses data from the NVD API but is not endorsed or certified by the NVD",
        "FIRST EPSS enriches existing local CVE vulnerability records",
        "EPSS probability",
        "percentile",
        "CISA KEV enriches existing local CVE vulnerability records",
        "known ransomware-campaign-use boolean",
        "Unknown KEV-only CVEs are skipped",
        "CERT-EU publication URL",
        "does not fetch article bodies",
    ):
        assert phrase in document


def test_publication_families_and_shared_feed_ownership_remain_separate() -> None:
    document = normalized_document()

    for slug in (
        "censys-arc-research",
        "censys-rapid-response-advisories",
        "anomali-cyber-watch",
        "ibm-x-force-public-research",
        "ibm-x-force-public-osint-advisories",
        "google-threat-intelligence-public-research",
        "mandiant-public-threat-research",
    ):
        assert f"### `{slug}`" in document

    assert "Google Threat Intelligence Group" in document
    assert "`Mandiant` maps to `mandiant-public-threat-research`" in document
    assert "Ownership is never inferred from titles" in document
    assert "`threat_report` items" in document
    assert "`security_advisory` items" in document


def test_normalization_identity_audit_and_security_exclusions_are_documented() -> None:
    document = normalized_document().lower()

    for phrase in (
        "canonical url",
        "normalized-title sha-256",
        "content hash",
        "sanitized audit",
        "source links",
        "raw payloads are not exposed through public apis",
        "active scanning",
        "target probing",
        "exploit execution",
        "credential collection",
        "malware retrieval",
        "file submission",
        "attachments",
        "headers and cookies",
    ):
        assert phrase in document


def test_transaction_and_audit_ownership_is_documented_per_workflow() -> None:
    document = normalized_document()

    assert "commit/rollback ownership are workflow-specific" in document
    assert "Transaction ownership is workflow-specific" in document
    assert "source-specific ingestion service owns commit/rollback" in document
    assert "`PublicationPipeline` itself does not commit" in document
    assert "Censys and live Anomali workflows delegate it" in document
    assert "Each CLI owns commit/rollback" not in document
    assert (
        "Caller-owned CLIs create sanitized audit records and control the transaction"
        not in document
    )


def test_assessed_sources_are_separated_from_implemented_support() -> None:
    document = normalized_document()

    assert "## Planned and assessed sources" in document
    assert "Assessment is not implementation" in document
    assert "Only the eleven registry identities" in document
    assert "No other Censys data" in document
    assert "Recorded Future source" in document
    assert "Scheduling remains out of scope" in document


def test_document_has_no_private_path_or_obvious_secret_and_links_resolve() -> None:
    document = document_text()
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
        path_text = parsed.path
        assert path_text
        assert (DATA_SOURCES_PATH.parent / path_text).resolve().is_file()
