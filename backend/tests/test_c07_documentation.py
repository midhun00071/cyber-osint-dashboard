"""Current-state documentation assertions for the C07 operations boundary."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
C07_DOCUMENT = ROOT / "docs" / "c07-authenticated-operations-experience.md"


def test_c07_contract_documents_routes_permissions_and_safe_evidence() -> None:
    text = C07_DOCUMENT.read_text(encoding="utf-8")
    for phrase in (
        "GET` | `/sources`",
        "GET` | `/ingestion/operations/summary`",
        "GET` | `/ingestion/cycles`",
        "GET` | `/ingestion/runs`",
        "POST` | `/sources/{source_slug}/runs`",
        "POST` | `/ingestion/runs/{run_public_id}/retry`",
        "Administrator-only enable",
        "Idempotency-Key",
        "deterministic retry identity",
        "SHA-256 fingerprint",
        "Raw idempotency keys",
        "caller-owned transaction",
    ):
        assert phrase in text


def test_c07_contract_documents_frontend_and_inactive_execution_boundary() -> None:
    text = " ".join(C07_DOCUMENT.read_text(encoding="utf-8").split())
    for phrase in (
        "bootstrapping",
        "session-expired",
        "access-denied",
        "15 seconds",
        "one request at a time",
        "DEFAULT_SOURCE_HANDLERS` mapping is empty",
        "mitre-attack-enterprise",
        "cert-fr-security-alerts",
        "cert-fr-security-advisories",
        "uk-ncsc-threat-reports",
        "adds no model or migration",
        "Acceptance means committed durable evidence",
    ):
        assert phrase in text


def test_authorized_current_documents_link_to_the_c07_contract() -> None:
    expected_link = "c07-authenticated-operations-experience.md"
    for path in (
        ROOT / "backend" / "README.md",
        ROOT / "frontend" / "README.md",
        ROOT / "docs" / "api-contract.md",
        ROOT / "docs" / "architecture.md",
        ROOT / "docs" / "security-notes.md",
    ):
        assert expected_link in path.read_text(encoding="utf-8"), path
