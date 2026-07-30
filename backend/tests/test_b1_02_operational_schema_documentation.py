import re
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPOSITORY_ROOT / "docs" / "b1-02-operational-ingestion-audit-schema.md"
MIGRATION_PATH = (
    REPOSITORY_ROOT / "docs" / "b1-02-operational-schema-migration-plan.md"
)

REQUIRED_SCHEMA_SECTIONS = {
    "purpose and scope",
    "current-state inventory",
    "current-to-target mapping",
    "design principles",
    "complete target table inventory",
    "detailed data dictionary",
    "mermaid erd",
    "lifecycle and state definitions",
    "keys, foreign keys and deletion rules",
    "named uniqueness and check constraints",
    "query-driven index plan",
    "transaction boundaries",
    "checkpoint-after-commit contract",
    "retry and idempotency behavior",
    "rate-limit and quota state",
    "quarantine safety",
    "audit-event safety",
    "credential-reference safety",
    "retention and archival",
    "task ownership and deferred implementation",
    "threat and acceptance traceability",
    "explicit limitations",
}

REQUIRED_ENTITIES = {
    "intelligence_sources",
    "ingestion_cycles",
    "ingestion_runs",
    "ingestion_run_events",
    "source_checkpoints",
    "source_watermarks",
    "source_rate_limit_states",
    "ingestion_errors",
    "quarantined_records",
    "audit_events",
    "source_credential_references",
}

SCOPE_UNIQUE_INDEXES = {
    "uq_source_checkpoints_source_identity_version",
    "uq_source_checkpoints_partition_identity_version",
    "uq_source_watermarks_source_identity_version",
    "uq_source_watermarks_partition_identity_version",
}

CORRELATION_OBJECTS = {
    "uq_ingestion_runs_id_source_id",
    "uq_ingestion_runs_id_cycle_id",
    "uq_ingestion_run_events_id_run_id",
    "uq_source_checkpoints_id_source_id",
    "fk_source_checkpoints_advanced_run_source",
    "fk_source_checkpoints_previous_source",
    "uq_source_watermarks_id_source_id",
    "fk_source_watermarks_advanced_run_source",
    "fk_source_watermarks_previous_source",
    "fk_source_rate_limit_states_run_source",
    "fk_quarantined_records_run_source",
    "fk_quarantined_records_event_run",
    "fk_audit_events_run_cycle",
    "ck_audit_events_run_cycle_consistency",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _headings(document: str) -> set[str]:
    return {
        re.sub(r"^\d+\.\s*", "", match.group(1).strip()).casefold()
        for match in re.finditer(r"^##\s+(.+?)\s*$", document, re.MULTILINE)
    }


def _section(document: str, title: str) -> str:
    match = re.search(
        rf"^##\s+\d+\.\s+{re.escape(title)}\s*$\n(.*?)(?=^##\s+|\Z)",
        document,
        re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    assert match is not None, f"Missing section: {title}"
    return match.group(1).casefold()


def test_both_b1_02_documents_exist_and_have_required_sections() -> None:
    assert SCHEMA_PATH.is_file()
    assert MIGRATION_PATH.is_file()

    schema = _read(SCHEMA_PATH)
    migration = _read(MIGRATION_PATH)

    assert REQUIRED_SCHEMA_SECTIONS <= _headings(schema)
    assert {
        "baseline migration inventory",
        "immutable migration-history rule",
        "additive migration sequence",
        "new-table ordering",
        "existing-table extension ordering",
        "constraint and index ordering",
        "nullable first-stage columns",
        "deterministic backfills",
        "validation queries",
        "upgrade verification",
        "downgrade expectations",
        "rollback and partial-deployment handling",
        "model registration",
        "test requirements for b1-03",
        "deployment sequencing",
        "known windows crlf raw-byte limitation",
    } <= _headings(migration)


def test_schema_covers_required_entities_and_maps_existing_foundations() -> None:
    schema = _read(SCHEMA_PATH).casefold()

    missing_entities = REQUIRED_ENTITIES - {
        entity for entity in REQUIRED_ENTITIES if entity in schema
    }
    assert not missing_entities, f"Missing required entities: {sorted(missing_entities)}"
    for existing, role in (
        ("intelligence_sources", "source-registry foundation"),
        ("ingestion_runs", "source-run foundation"),
        ("ingestion_errors", "sanitized-failure foundation"),
    ):
        assert existing in schema
        assert role in schema
    assert "do not create `source_runs`" in schema
    assert "do not create `failures`" in schema
    assert "no current table is replaced by a duplicate" in schema


def test_erd_contains_core_operational_relationships() -> None:
    schema = _read(SCHEMA_PATH)
    erd = re.search(r"```mermaid\s+(.*?)```", schema, re.DOTALL)

    assert erd is not None
    diagram = erd.group(1)
    for relationship in (
        "INTELLIGENCE_SOURCES ||--o{ INGESTION_RUNS",
        "INGESTION_CYCLES ||--o{ INGESTION_RUNS",
        "INGESTION_RUNS ||--o{ INGESTION_RUN_EVENTS",
        "INGESTION_RUNS ||--o{ INGESTION_ERRORS",
        "INGESTION_RUNS ||--o{ SOURCE_CHECKPOINTS",
        "INGESTION_RUNS ||--o{ SOURCE_WATERMARKS",
        "INGESTION_RUNS ||--o{ QUARANTINED_RECORDS",
        "INTELLIGENCE_SOURCES ||--o{ SOURCE_RATE_LIMIT_STATES",
        "INTELLIGENCE_SOURCES ||--o{ SOURCE_CREDENTIAL_REFERENCES",
    ):
        assert relationship in diagram


def test_migration_plan_preserves_baseline_and_declares_history_immutable() -> None:
    migration = _read(MIGRATION_PATH).casefold()

    for revision in ("f8d739439ed0", "a6c9d4e2f107", "c4e8b2a91d30"):
        assert revision in migration
    assert "all three committed migration files are immutable" in migration
    assert "must not edit" in migration
    assert "single linear head" in migration
    assert "does not implement" in migration or "no alembic revision" in migration


def test_checkpoint_transaction_and_task_ownership_are_explicit() -> None:
    combined = f"{_read(SCHEMA_PATH)}\n{_read(MIGRATION_PATH)}".casefold()

    assert "no checkpoint or watermark advances before successful committed persistence" in combined
    for boundary in (
        "cycle creation",
        "source-run acquisition",
        "record persistence",
        "counters and final status",
        "event insertion",
        "checkpoint/watermark advancement",
        "quarantine insertion",
        "audit insertion",
    ):
        assert boundary in combined
    for owner in ("b1-03", "b1-04", "b2-05", "later api/ui tasks"):
        assert owner in combined


def test_checkpoint_pending_prevents_terminal_success_before_advancement() -> None:
    schema = _read(SCHEMA_PATH)
    migration = _read(MIGRATION_PATH)
    lifecycle = _section(schema, "Lifecycle and state definitions")
    transactions = _section(schema, "Transaction boundaries")
    checkpoint = _section(schema, "Checkpoint-after-commit contract")
    rollout = _section(migration, "Rollback and partial-deployment handling")

    assert "`checkpoint_pending` is nonterminal" in lifecycle
    for status in ("success", "no_change"):
        assert status in lifecycle
        assert status in transactions
        assert status in checkpoint
    assert "running -> checkpoint_pending" in lifecycle
    assert "must not set `success`" in transactions
    assert "all atomically" in transactions
    assert "run remains `checkpoint_pending`" in checkpoint
    assert "system never reports success" in checkpoint
    assert re.search(r"never\s+commits terminal success first", rollout)
    assert "progress_contract=none" in lifecycle


def test_progress_identity_uses_scope_specific_postgresql_uniqueness() -> None:
    schema = _read(SCHEMA_PATH).casefold()
    migration = _read(MIGRATION_PATH).casefold()

    for index_name in SCOPE_UNIQUE_INDEXES:
        assert index_name in schema
        assert index_name in migration
    assert "postgresql ordinary unique constraints treat nulls as distinct" in schema
    assert "single identity constraint containing nullable `partition_key` is prohibited" in migration
    assert re.search(
        r"duplicate\s+source-scope\s+and\s+partition-scope",
        migration,
    )
    assert "char_length(btrim(partition_key)) between 1 and 160" in schema


def test_legacy_import_backfill_preserves_historical_truth() -> None:
    schema = _read(SCHEMA_PATH).casefold()
    backfill = _section(_read(MIGRATION_PATH), "Deterministic backfills")
    extensions = _section(_read(MIGRATION_PATH), "Existing-table extension ordering")

    for document in (schema, backfill, extensions):
        assert "legacy_import" in document
    assert "runtime cycle creation" in extensions
    assert re.search(
        r"preserve the existing\s+`ingestion_runs\.trigger_type` unchanged",
        extensions,
    )
    assert "do not invent `scheduled_for`" in extensions
    assert "retry ancestry" in extensions
    for counter in (
        "sources_expected=1",
        "sources_started=1",
        "sources_completed=0",
        "sources_completed=1",
        "sources_successful=1",
        "sources_non_successful=0",
    ):
        assert counter in extensions
    assert "does not claim to reconstruct historical parent grouping" in extensions


def test_named_objects_enforce_source_run_cycle_event_correlation() -> None:
    schema = _read(SCHEMA_PATH).casefold()
    migration = _read(MIGRATION_PATH).casefold()

    for object_name in CORRELATION_OBJECTS:
        assert object_name in schema
        assert object_name in migration
    assert re.search(r"cross-source correlation\s+impossible", schema)
    assert "event belongs to that run" in schema
    assert "unrelated cycle" in schema


def test_row_local_counter_time_quarantine_and_credential_checks_are_exact() -> None:
    schema = _read(SCHEMA_PATH).casefold()
    migration_tests = _section(_read(MIGRATION_PATH), "Test requirements for B1-03")

    for relationship in (
        "sources_started <= sources_expected",
        "sources_completed <= sources_started",
        "sources_successful + sources_non_successful = sources_completed",
    ):
        assert relationship in schema
    assert re.search(
        r"null `completed_at` for `running` and\s+`checkpoint_pending`",
        schema,
    )
    assert "non-null `completed_at >= started_at`" in schema
    assert "octet_length(coalesce(safe_excerpt, ''))" in schema
    assert "octet_length(coalesce(safe_metadata, ''))" in schema
    assert "stored_byte_count <= 4096" in schema
    assert "ck_source_credential_references_configured_shape" in schema
    assert "exact credential-reference configured-shape cases" in migration_tests


def test_event_vocabulary_and_integrity_manifest_are_test_owned() -> None:
    schema = _read(SCHEMA_PATH).casefold()
    migration = _read(MIGRATION_PATH).casefold()
    migration_tests = _section(_read(MIGRATION_PATH), "Test requirements for B1-03")

    for event_type in (
        "`acquired`",
        "`started`",
        "`persistence_committed`",
        "`checkpoint_advanced`",
        "`completed`",
        "`skipped`",
        "`deferred`",
        "`partial`",
        "`failed`",
        "`cancelled`",
    ):
        assert event_type in schema
    assert "parameterized exact-name assertion" in migration_tests
    assert "complete section 7 integrity-object manifest" in migration_tests
    schema_objects = set(re.findall(r"`((?:ck|uq|fk)_[a-z0-9_]+)`", schema))
    migration_objects = set(
        re.findall(r"`((?:ck|uq|fk)_[a-z0-9_]+)`", migration)
    )
    assert schema_objects <= migration_objects


def test_task_ownership_is_exact() -> None:
    ownership = _section(
        _read(SCHEMA_PATH),
        "Task ownership and deferred implementation",
    )

    assert re.search(r"\*\*b1-03\*\* owns sqlalchemy models", ownership)
    assert re.search(r"\*\*b1-04\*\* owns transaction, lock", ownership)
    assert re.search(
        r"\*\*b2-05\*\* owns checkpoint and watermark advancement",
        ownership,
    )
    assert "b1-02 implements none of those responsibilities" in ownership


def test_credential_references_are_non_secret_and_apr_10_remains_pending() -> None:
    combined = f"{_read(SCHEMA_PATH)}\n{_read(MIGRATION_PATH)}".casefold()

    assert "provider-neutral" in combined
    assert "apr-10 remains pending" in combined
    assert "no credential values" in combined
    assert "no credential provider is approved" in combined
    assert re.search(
        r"no secret-management provider or\s+delivery mechanism is approved",
        combined,
    )


def test_documents_make_no_model_or_migration_implementation_claim() -> None:
    schema = _read(SCHEMA_PATH).casefold()
    migration = _read(MIGRATION_PATH).casefold()

    assert "design artifact only" in schema
    assert "does not implement sqlalchemy models" in schema
    assert "creates no alembic revision" in migration
    assert "not a migration implementation" in migration


def test_documents_contain_no_real_looking_secrets_or_credential_urls() -> None:
    combined = f"{_read(SCHEMA_PATH)}\n{_read(MIGRATION_PATH)}"

    forbidden_patterns = {
        "private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "credential database url": (
            r"postgres(?:ql)?(?:\+\w+)?://[^\s/:@]+:[^\s/@]+@[^\s]+"
        ),
        "bearer token": r"(?i)bearer\s+[a-z0-9._~+/=-]{20,}",
        "jwt": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "generic assigned secret": (
            r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)"
            r"\s*[:=]\s*['\"]?[a-z0-9_./+=-]{12,}"
        ),
    }
    for label, pattern in forbidden_patterns.items():
        assert re.search(pattern, combined) is None, label
