from __future__ import annotations

from pathlib import Path

from app.ingestion.collectors.anomali_publications_client import DISCOVERY_URL
from app.ingestion.source_registry import (
    AccessMethod,
    ImplementationStatus,
    get_source_definition,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
README_PATH = PROJECT_ROOT / "README.md"
BACKEND_README_PATH = PROJECT_ROOT / "backend" / "README.md"
ARCHITECTURE_PATH = PROJECT_ROOT / "docs" / "architecture.md"
DATA_SOURCES_PATH = PROJECT_ROOT / "docs" / "data-sources.md"
SOURCE_ASSESSMENT_PATH = PROJECT_ROOT / "docs" / "source-assessment-matrix.md"
ANOMALI_DOCUMENTS = (
    BACKEND_README_PATH,
    ARCHITECTURE_PATH,
    DATA_SOURCES_PATH,
    SOURCE_ASSESSMENT_PATH,
)


def normalized_document(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_canonical_source_references_document_both_manual_anomali_commands() -> None:
    for path in (BACKEND_README_PATH, DATA_SOURCES_PATH):
        document = normalized_document(path)

        assert "-m app.ingestion.anomali_publications_live_cli" in document
        assert "--max-records 5" in document
        assert "-m app.ingestion.anomali_publications_cli" in document
        assert "--file C:\\path\\to\\anomali-cyber-watch.json" in document
        assert "1 through 20" in document


def test_canonical_source_references_document_closed_manual_only_live_boundary() -> None:
    for path in (BACKEND_README_PATH, DATA_SOURCES_PATH):
        document = normalized_document(path)

        assert "manually triggered only" in document or "manual-only" in document
        assert DISCOVERY_URL in document
        assert "no arbitrary URL" in document
        assert "www.anomali.com" in document
        assert "/blog/anomali-cyber-watch-" in document
        assert "Redirects" in document
        assert "not automatically retried" in document or "no automatic retries" in document
        assert "at least ten seconds apart" in document
        assert "response sizes" in document


def test_canonical_source_references_document_live_metadata_and_persistence_boundaries() -> None:
    for path in (BACKEND_README_PATH, DATA_SOURCES_PATH):
        document = normalized_document(path)

        assert "metadata only" in document or "metadata-only" in document
        assert "does not parse article-body prose" in document
        assert "selected title, summary, author, and category" in document
        assert "IOC-like URLs" in document
        assert "IP addresses" in document
        assert "domains" in document
        assert "hashes" in document
        assert "internationalized domains" in document
        assert "common defanged forms" in document
        assert "rejected before adapter invocation" in document
        assert "before a database session is opened" in document
        assert "atomic and safely audited" in document
        assert "raw HTTP" in document or "Raw HTTP" in document
        assert "database errors" in document


def test_documents_distinguish_reviewed_catalogue_from_live_screening() -> None:
    for path in ANOMALI_DOCUMENTS:
        document = normalized_document(path)
        anomali_section = document[document.find("Anomali") :]

        assert "reviewed" in anomali_section
        assert "operator-prepared" in anomali_section
        assert "publication metadata only" in anomali_section
        assert "not a comprehensive automatic IOC detector" in anomali_section
        assert "exclude article-body text" in anomali_section
        assert "IOCs and observables" in anomali_section
        assert "raw HTML" in anomali_section
        assert "HTTP headers and cookies" in anomali_section
        assert "attachments" in anomali_section
        assert "malware samples" in anomali_section


def test_documents_cover_live_ioc_like_metadata_rejection() -> None:
    for path in ANOMALI_DOCUMENTS:
        document = normalized_document(path)
        anomali_section = document[document.find("Anomali") :]

        assert "does not parse article-body prose" in anomali_section
        assert "selected title, summary, author, and category" in anomali_section
        assert "IOC-like URLs" in anomali_section
        assert "IP addresses" in anomali_section
        assert "domains" in anomali_section
        assert "hashes" in anomali_section
        assert "internationalized domains" in anomali_section
        assert "common defanged forms" in anomali_section
        assert "before adapter invocation" in anomali_section


def test_canonical_source_references_document_manual_trigger_exclusions_and_fallback() -> None:
    for path in (BACKEND_README_PATH, DATA_SOURCES_PATH):
        document = normalized_document(path)

        assert "scheduler" in document
        assert "startup ingestion" in document
        assert "background ingestion" in document or "background job" in document
        assert "API" in document
        assert "frontend trigger" in document
        assert "reviewed local JSON fallback" in document
        assert "currently operational method" in document


def test_documents_record_controlled_http_200_limitation_without_false_success() -> None:
    for path in ANOMALI_DOCUMENTS:
        document = normalized_document(path)
        anomali_section = document[document.find("Anomali") :]

        assert "19 July 2026" in anomali_section
        assert "The request was not rejected with HTTP 403; the observed response status was HTTP 200." in anomali_section
        assert "returned HTML" in anomali_section
        assert "no deterministic main-content region" in anomali_section or (
            "no deterministic main region" in anomali_section
        )
        assert "no approved Cyber Watch article links" in anomali_section or (
            "no approved links" in anomali_section
        )
        assert "before an article request was issued" in anomali_section
        assert "no live records were persisted" in anomali_section or (
            "no ingestion run or live persistence" in anomali_section
        )
        assert "server-rendered HTML" not in anomali_section
        assert "upstream access block" not in anomali_section
        assert "returned HTTP 403" not in anomali_section
        assert "live ingestion succeeded" not in anomali_section
        assert "live ingestion persisted records" not in anomali_section


def test_documents_preserve_verified_safe_five_record_local_import() -> None:
    for path in ANOMALI_DOCUMENTS:
        document = normalized_document(path)
        anomali_section = document[document.find("Anomali") :]

        assert "five-record catalogue was reviewed and contained safe metadata" in anomali_section
        assert "5 records" in anomali_section or "five-record" in anomali_section


def test_stale_no_anomali_collector_wording_is_absent() -> None:
    stale_phrases = (
        "There is no Anomali HTTP collector",
        "The application performs no Anomali network requests",
        "Manual local-file metadata import only",
        "No live Anomali or IBM collection is implemented",
        "does not approve live Anomali collection",
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in ANOMALI_DOCUMENTS)

    assert all(phrase not in combined for phrase in stale_phrases)


def test_anomali_registry_matches_fixed_live_and_fallback_definition() -> None:
    source = get_source_definition("anomali-cyber-watch")
    notes = source.rate_limit_notes or ""

    assert source.access_method is AccessMethod.MANUAL_CATALOGUE
    assert source.allowed_hosts == ("www.anomali.com",)
    assert source.base_url == DISCOVERY_URL == "https://www.anomali.com/blog"
    assert source.authentication_required is False
    assert source.implementation_status is ImplementationStatus.IMPLEMENTED
    assert source.enabled is True
    assert "Manual-only live publication-metadata collection" in notes
    assert "one fixed public discovery page" in notes
    assert "at least ten seconds between request starts" in notes
    assert "maximum of 20 records" in notes
    assert "local-file JSON fallback remains supported" in notes
    assert "HTTP 200" in notes
    assert "failed safely before database-session creation" in notes


def test_ibm_remains_documented_as_local_only_not_live_ingestion() -> None:
    readme = normalized_document(DATA_SOURCES_PATH)
    assessment = normalized_document(SOURCE_ASSESSMENT_PATH)

    assert "manual-only importer" in readme
    assert "The application performs no IBM request" in readme
    assert "P9-07 performs no network requests" in assessment
    assert "P9-07 IBM X-Force local publication-metadata families" in assessment


def test_root_readme_routes_source_detail_without_duplicate_commands() -> None:
    readme = normalized_document(README_PATH)
    assert "[Data sources](docs/data-sources.md)" in readme
    assert "app.ingestion.anomali_publications_live_cli" not in readme
    assert "app.ingestion.ibm_x_force_publications_cli" not in readme
