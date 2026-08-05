import csv
from pathlib import Path

from app.ingestion.source_registry import list_source_definitions


ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"


def text(path):
    return path.read_text(encoding="utf-8")


def test_registry_preserves_public_censys_and_contains_no_paid_source_identity():
    sources = {source.slug: source for source in list_source_definitions()}
    assert "censys-arc-research" in sources
    assert "censys-rapid-response-advisories" in sources
    assert sources["censys-arc-research"].authentication_required is False
    assert sources["censys-rapid-response-advisories"].authentication_required is False
    assert all(
        token not in slug
        for slug in sources
        for token in (
            "censys-platform",
            "censys-search",
            "virustotal",
            "recorded-future",
        )
    )


def test_commercial_approval_rows_are_explicitly_retired_not_pending():
    with (DOCS / "b0-05-approval-register.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        rows = {row["Approval ID"]: row for row in csv.DictReader(handle)}
    for approval_id in ("APR-01", "APR-02", "APR-03", "APR-04"):
        row = rows[approval_id]
        assert row["Current Status"] == "Retired"
        assert row["Decision"] == "Superseded by C05"
        assert "not pending" in row["Notes"].lower()
        assert "Need Approval" not in " ".join(row.values())
        assert "Pending" not in " ".join(row.values())


def test_legacy_commercial_task_mappings_are_retired():
    with (DOCS / "b0-04-p9-phase-b-mapping.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        rows = {row["Mapping ID"]: row for row in csv.DictReader(handle)}
    for mapping_id in ("MAP-0002", "MAP-0003"):
        row = rows[mapping_id]
        assert row["Authoritative Status"] == "Retired mapping"
        assert row["Decision"] == "Retired"
        assert row["Phase B Replacement"] == "None"
        assert "not pending" in row["Notes"].lower()


def test_historical_documents_carry_unambiguous_c05_supersession_notices():
    paths = (
        "source-assessment-matrix.md",
        "source-integration-policy.md",
        "b0-03-production-mvp-scope.md",
        "b0-04-p9-phase-b-reassignment.md",
        "b0-05-mentor-approval-pack.md",
        "b0-06-architecture-decisions.md",
    )
    for name in paths:
        document = text(DOCS / name)
        assert "C05 supersession" in document
        assert "retired" in document.lower()
        assert "historical" in document.lower()


def test_current_c05_contract_distinguishes_public_censys_from_paid_work():
    document = text(DOCS / "c05-official-public-sources.md")
    normalized = " ".join(document.split())
    assert "paid and commercial source implementation work is retired" in document.lower()
    assert "censys-arc-research" in document
    assert "censys-rapid-response-advisories" in document
    assert "do not use or represent the Censys Platform API" in document
    for phrase in (
        "VirusTotal premium/business",
        "Recorded Future integration",
        "commercial free-tier workaround",
        "paid credential request",
        "paid-subscription mock",
        "fabricated commercial-source result",
    ):
        assert phrase in normalized


def test_registry_and_current_documentation_agree_on_c05_disabled_sources():
    source_slugs = {
        "mitre-attack-enterprise",
        "cert-fr-security-alerts",
        "cert-fr-security-advisories",
        "uk-ncsc-threat-reports",
    }
    sources = {source.slug: source for source in list_source_definitions()}
    documents = "\n".join(
        text(path)
        for path in (
            ROOT / "README.md",
            DOCS / "data-sources.md",
            DOCS / "c05-official-public-sources.md",
        )
    )
    for slug in source_slugs:
        assert sources[slug].enabled is False
        assert sources[slug].authentication_required is False
        assert slug in documents
    assert "implemented but disabled" in documents.lower()
    assert "no live request" in documents.lower()
