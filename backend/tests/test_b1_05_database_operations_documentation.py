from pathlib import Path
import re


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_DOCUMENT = REPO_ROOT / "docs" / "b1-05-database-operations-controls.md"


def normalized_document() -> str:
    return re.sub(r"\s+", " ", CONTROL_DOCUMENT.read_text(encoding="utf-8").lower())


def test_b1_05_status_and_approval_dependencies_are_explicit() -> None:
    document = normalized_document()

    for phrase in (
        "roles have been provisioned",
        "no approved final retention period",
        "destructive retention is disabled",
        "apr-09",
        "apr-10",
        "apr-11",
        "need approval",
    ):
        assert phrase in document


def test_backup_and_recovery_boundaries_make_no_success_claim() -> None:
    document = normalized_document()

    for phrase in (
        "has not executed a production backup",
        "no restore has been proven",
        "b9-05 owns",
        "b9-06 owns",
        "no recoverability",
        "no staging or production database was changed",
    ):
        assert phrase in document
    assert "no recoverability, disaster-recovery readiness, rpo, or rto is claimed" in document


def test_role_pool_index_and_retention_controls_are_documented() -> None:
    document = normalized_document()

    for phrase in (
        "runtime application",
        "migration identity",
        "read-only",
        "logical backup",
        "retention planning",
        "no ownership, ddl, schema creation",
        "pool size plus overflow cannot exceed 30",
        "explain (format json)",
        "(source_id, started_at desc, id desc)",
        "(started_at desc, id desc)",
        'policy_state="approval_required"',
        "unknown or inconsistent state is protected by default",
        "pairwise distinct",
        "permits no membership at a managed role boundary",
        "grant nothing automatically",
        "without planner override settings",
        "every migration that introduces a new runtime-accessible object requires an explicit allow-list review and provisioning update",
    ):
        assert phrase in document


def test_document_never_contains_secret_or_backup_execution_examples() -> None:
    raw = CONTROL_DOCUMENT.read_text(encoding="utf-8")

    assert not re.search(r"postgres(?:ql)?://", raw, re.IGNORECASE)
    assert not re.search(r"(?i)(?:password|token|secret)\s*=\s*\S+", raw)
    assert "pg_dump " not in raw.lower()
    assert "docker compose exec" not in raw.lower()
