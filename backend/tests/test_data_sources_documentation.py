from __future__ import annotations

import csv
from pathlib import Path
import re
from urllib.parse import urlparse

from app.ingestion.source_registry import list_enabled_implemented_sources


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_SOURCES_PATH = PROJECT_ROOT / "docs" / "data-sources.md"
UAE_GOVERNANCE_PATH = PROJECT_ROOT / "docs" / "uae-source-governance.md"
SOURCE_INTEGRATION_POLICY_PATH = PROJECT_ROOT / "docs" / "source-integration-policy.md"
SOURCE_ASSESSMENT_MATRIX_PATH = PROJECT_ROOT / "docs" / "source-assessment-matrix.md"
APPROVAL_REGISTER_PATH = PROJECT_ROOT / "docs" / "b0-05-approval-register.csv"


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


def test_b1_04_progress_contract_mapping_is_exactly_documented() -> None:
    document = normalized_document()
    assert "### B1-04 progress contracts" in document
    expected = {
        "watermark": {
            "nvd", "first-epss", "cert-eu-security-advisories",
            "google-threat-intelligence-public-research",
            "mandiant-public-threat-research",
        },
        "checkpoint": {"cisa-kev"},
        "none": {
            "censys-arc-research", "censys-rapid-response-advisories",
            "anomali-cyber-watch", "ibm-x-force-public-research",
            "ibm-x-force-public-osint-advisories",
        },
    }
    for contract, slugs in expected.items():
        mapping_row = next(
            line for line in document_text().splitlines()
            if line.startswith(f"| `{contract}` |")
        )
        assert {f"`{slug}`" for slug in slugs} <= set(
            re.findall(r"`[^`]+`", mapping_row)
        )
    assert "Runtime callers cannot select or override it" in document
    assert "must not run concurrently with new operational writers" in document


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


def test_c02_flow_ready_sources_are_documented_without_activation_claims() -> None:
    document = normalized_document()

    for phrase in (
        "six reviewed, flow-ready handler implementations",
        "not bound to the immutable production `DEFAULT_SOURCE_HANDLERS` mapping",
        "Operational collection therefore remains manual-only",
        "Anomali, both Censys identities, and both IBM identities remain manual-only",
        "unavailable as scheduled success paths",
        "start-after cursor continuation and one wrap-around",
    ):
        assert phrase in document


def test_c03a_taxii_eligibility_is_documented_without_activation() -> None:
    document = normalized_document()
    for phrase in (
        "C03A STIX/TAXII eligibility",
        "immutable test/later-staging TAXII handler builder",
        "PRODUCTION_STIX_SOURCE_POLICIES",
        "PRODUCTION_TAXII_COLLECTION_POLICIES",
        "DEFAULT_SOURCE_HANDLERS",
        "No live TAXII request was performed",
    ):
        assert phrase in document


def test_c04a_uae_governance_documents_exact_disabled_boundaries() -> None:
    assert UAE_GOVERNANCE_PATH.is_file()
    governance = " ".join(
        UAE_GOVERNANCE_PATH.read_text(encoding="utf-8").split()
    )

    for phrase in (
        "C04A / B5-01",
        "37a8906e0f65f2391fbbbe42c2980bdbb6c945e3",
        "4 August 2026",
        "`ae-cert`",
        "`uae-cyber-security-council`",
        "`uae-cyber-security-council-nibras`",
        "`desc-news`",
        "`desc-published-research`",
        "`tdra.gov.ae`",
        "`csc.gov.ae`",
        "`www.desc.gov.ae`",
        "`https://csc.gov.ae/en/stay-alert`",
        "`https://csc.gov.ae/en/all-threats`",
        "`https://csc.gov.ae/en/all-updates`",
        "`https://www.desc.gov.ae/media-hub/news/`",
        "`https://www.desc.gov.ae/research-innovation/published-research/`",
        "automated_access_approved: false",
        "All five sources",
        "approval state `pending`",
        "No live source request was made",
        "This does not complete B5-03",
    ):
        assert phrase in governance

    for bundle, digest in (
        (
            "c04-source-discovery-20260804-104617.zip",
            "8993FBE95288EBF8019942CFCA8D474E72D05D9D61AF0B5C1229BE34EA7EAA9B",
        ),
        (
            "c04-source-discovery-pass2-20260804-105156.zip",
            "3FBCD687DA0D6B9A599C8C3E2C7E4E0A976550F6371370E2498876C31174B9F3",
        ),
        (
            "c04-source-discovery-pass3-20260804-105959.zip",
            "69CAE79E9D10E9CA54A2683ACF51E13CBAE8AB5FFC1FF5B59E21958BFD9C3BFB",
        ),
    ):
        assert bundle in governance
        assert digest in governance

    assert not re.search(r"(?i)[a-z]:\\users\\[^\\\s]+", governance)


def test_c04a_policy_matrix_and_data_sources_consistently_deny_activation() -> None:
    documents = (
        normalized_document(),
        " ".join(SOURCE_INTEGRATION_POLICY_PATH.read_text(encoding="utf-8").split()),
        " ".join(SOURCE_ASSESSMENT_MATRIX_PATH.read_text(encoding="utf-8").split()),
    )

    for document in documents:
        for slug in (
            "ae-cert",
            "uae-cyber-security-council",
            "uae-cyber-security-council-nibras",
            "desc-news",
            "desc-published-research",
        ):
            assert f"`{slug}`" in document
        assert "all UAE collectors remain disabled" in document

    data_sources = documents[0]
    assert "`planned`, `enabled: false`" in data_sources
    assert "`uae-cert` is not a network source" in data_sources
    assert "does not automatically make it classification-trusted" in data_sources
    assert "APR-05 remains `Need Approval`" in data_sources
    assert "decision date remain `Pending`" in data_sources


def test_apr_05_remains_pending_with_exact_evidence_references() -> None:
    with APPROVAL_REGISTER_PATH.open(encoding="utf-8", newline="") as handle:
        rows = {row["Approval ID"]: row for row in csv.DictReader(handle)}

    apr_05 = rows["APR-05"]
    assert apr_05["Current Status"] == "Need Approval"
    assert apr_05["Decision"] == "Pending"
    assert apr_05["Decision Date"] == "Pending"
    assert apr_05["Review or Expiry Date"] == "Pending"
    assert "all uae collectors remain disabled" in (
        apr_05["What Remains Disabled"].casefold()
    )
    assert "must not be interpreted as legal approval" in apr_05["Notes"]

    evidence = apr_05["Evidence Reference"]
    for expected in (
        "c04-source-discovery-20260804-104617.zip",
        "8993FBE95288EBF8019942CFCA8D474E72D05D9D61AF0B5C1229BE34EA7EAA9B",
        "c04-source-discovery-pass2-20260804-105156.zip",
        "3FBCD687DA0D6B9A599C8C3E2C7E4E0A976550F6371370E2498876C31174B9F3",
        "c04-source-discovery-pass3-20260804-105959.zip",
        "69CAE79E9D10E9CA54A2683ACF51E13CBAE8AB5FFC1FF5B59E21958BFD9C3BFB",
    ):
        assert expected in evidence
    assert not re.search(r"(?i)[a-z]:\\users\\", evidence)
