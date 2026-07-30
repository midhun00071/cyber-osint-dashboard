from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONTRACT = PROJECT_ROOT / "docs" / "b1-04-operational-persistence-contracts.md"


def normalized() -> str:
    return " ".join(CONTRACT.read_text(encoding="utf-8").split())


def test_contract_documents_scope_transactions_and_locking() -> None:
    document = normalized()
    assert "59b6ce8f67cbf16ecd9924e65e70d9130c509227" in document
    for phrase in (
        "caller-owned transaction", "never begins, commits, rolls back or closes",
        "PostgreSQL-only", "pg_try_advisory_xact_lock", "SELECT ... FOR UPDATE",
        "no public generic event append or arbitrary status setter",
    ):
        assert phrase in document


def test_contract_lists_api_and_lock_namespaces() -> None:
    document = normalized()
    for method in (
        "acquire_cycle", "acquire_source_run", "acquire_retry",
        "record_persistence_commit", "complete_non_request",
        "complete_partial_or_failure", "abandon_pending_progress",
        "advance_checkpoint", "advance_watermark", "update_rate_limit_state",
    ):
        assert f"`{method}`" in document
    for value in (
        "`b104cs-`", "`b104cm-`", "`b104r-`", "`b104a-`",
        "`cycle-idempotency`", "`source-no-overlap`",
        "`progress-identity`", "`rate-state-identity`",
    ):
        assert value in document


def test_contract_preserves_commit_order_and_deferred_ownership() -> None:
    document = normalized()
    for phrase in (
        "persistence transaction commits", "Only after that caller commit",
        "Rollback removes the new progress row and events",
        "Watermarks must be timezone-aware", "strictly increase",
        "B2-05 owns integration", "final non-null/status enforcement migration remains deferred",
        "APR-10 remains pending",
    ):
        assert phrase in document


def test_contract_documents_hardened_commit_and_value_validation() -> None:
    document = normalized()
    for phrase in (
        "ingestion_run_events.xmin",
        "pg_visible_in_snapshot(xmin::text::xid8, pg_current_snapshot())",
        "committed before the current statement snapshot",
        "same transaction therefore fails closed",
        "new caller-owned transaction after the persistence transaction commits",
        "Watermark values are required and never default",
        "whitespace-only checkpoint values are rejected",
        "ordinary opaque non-secret values are preserved exactly",
        "credential-bearing URLs",
        "Authorization values",
        "private-key blocks",
        "traceback/stack-trace text",
        "obvious raw SQL",
        "Unsafe summaries fail validation rather than being redacted",
    ):
        assert phrase in document
