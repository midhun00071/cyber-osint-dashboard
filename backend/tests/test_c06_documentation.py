from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CURRENT_DOCUMENTS = (
    ROOT / "README.md",
    ROOT / "docs" / "security-notes.md",
    ROOT / "docs" / "c06-identity-auth-rbac-audit.md",
    ROOT / "docs" / "b0-06-production-architecture.md",
    ROOT / "docs" / "b0-06-threat-model.md",
    ROOT / "docs" / "production-docker-deployment.md",
)


def test_c06_documentation_records_security_and_frontend_boundaries() -> None:
    text = (ROOT / "docs" / "c06-identity-auth-rbac-audit.md").read_text(encoding="utf-8")
    for phrase in ("Argon2id", "opaque", "SameSite=Strict", "X-CSRF-Token", "frontend", "SSO", "bootstrap", "f4a1c2d3e5b6"):
        assert phrase in text
    for phrase in (
        "Naturally expired accounts cannot regain access through an old session",
        "Extending or removing an already-reached account expiry",
        "revokes every unrevoked historical session",
    ):
        assert phrase in " ".join(text.split())


def _current_state_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    for historical_marker in (
        "## Historical B0 planning baseline",
        "## Historical B0 threat baseline",
    ):
        if historical_marker in text:
            return text.split(historical_marker, 1)[0]
    return text


def test_current_documents_state_the_authoritative_c06_contract() -> None:
    combined = "\n".join(_current_state_text(path) for path in CURRENT_DOCUMENTS)
    for phrase in (
        "opaque database-backed browser sessions",
        "SHA-256",
        "Argon2id",
        "GET`, `POST`, `PATCH`, and `OPTIONS",
        "Content-Type",
        "X-CSRF-Token",
        "Authorization",
        "content.read",
        "Administrator-only",
        "backend authorization is authoritative",
        "Frontend login",
        "protected-navigation",
        "No real account",
        "APR-13",
        "bootstrap",
        "SSO",
        "disabled and unscheduled",
    ):
        assert phrase.casefold() in combined.casefold()


def test_current_sections_do_not_repeat_obsolete_active_state_claims() -> None:
    obsolete = (
        "credentials are disabled",
        "method policy allows only `GET`",
        "current application does not use browser cookies",
        "authentication is absent",
        "RBAC is absent",
        "no session/account code exists",
    )
    for path in CURRENT_DOCUMENTS:
        current = _current_state_text(path)
        for phrase in obsolete:
            assert phrase.casefold() not in current.casefold(), (path, phrase)


def test_pre_c06_b0_material_is_explicitly_historical() -> None:
    architecture = (ROOT / "docs" / "b0-06-production-architecture.md").read_text(encoding="utf-8")
    threat_model = (ROOT / "docs" / "b0-06-threat-model.md").read_text(encoding="utf-8")
    assert "Historical B0 planning baseline" in architecture
    assert "superseded by the current-state reconciliation" in " ".join(architecture.split())
    assert "Historical B0 threat baseline" in threat_model
    assert "superseded by the current-state reconciliation" in " ".join(threat_model.split())
