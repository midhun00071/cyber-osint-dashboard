"""Static and query-construction controls for the B1-06 database audit."""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import subprocess

import pytest
from sqlalchemy.dialects import postgresql

from app.db.base import Base
from app.services.article_query_service import ArticleQueryFilters, ArticleQueryService


BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = BACKEND_ROOT.parent
AUDIT_ROOTS = (BACKEND_ROOT / "app", BACKEND_ROOT / "alembic")
MODEL_NAMES = frozenset(
    {
        "AuditEvent",
        "AuthIdentity",
        "AuthLocalCredential",
        "AuthLoginThrottle",
        "AuthSession",
        "AuthUser",
        "AuthUserRole",
        "Indicator",
        "IndicatorProvenance",
        "IngestionCycle",
        "IngestionError",
        "IngestionRun",
        "IngestionRunEvent",
        "IngestionRunRecord",
        "IntelligenceItem",
        "IntelligenceItemIdentifier",
        "IntelligenceItemIndicator",
        "IntelligenceItemTag",
        "IntelligenceSource",
        "QuarantinedRecord",
        "SourceCheckpoint",
        "SourceCredentialReference",
        "SourceRateLimitState",
        "SourceRecord",
        "SourceWatermark",
        "Tag",
        "ThreatEntity",
        "ThreatEntityAlias",
        "ThreatRelationship",
        "Vulnerability",
    }
)


@dataclass(frozen=True)
class StaticSqlAllowance:
    path: str
    call: str
    fragment: str
    reason: str


def _allow(path: str, call: str, fragments: tuple[str, ...], reason: str):
    return tuple(StaticSqlAllowance(path, call, fragment, reason) for fragment in fragments)


STATIC_SQL_ALLOWLIST = (
    *_allow(
        "app/models/audit_event.py",
        "text",
        ("occurred_at DESC", "id DESC", "correlation_id IS NOT NULL"),
        "Fixed model index ordering and predicate.",
    ),
    *_allow(
        "app/models/indicator_provenance.py",
        "text",
        ("source_record_id IS NOT NULL", "source_record_id IS NULL"),
        "Fixed partial-index predicates.",
    ),
    *_allow(
        "app/models/ingestion_run_record.py",
        "text",
        ("source_record_id IS NOT NULL",),
        "Fixed partial-index predicate.",
    ),
    *_allow(
        "app/models/intelligence_item_identifier.py",
        "text",
        ("source_id IS NULL", "source_id IS NOT NULL", "is_primary IS TRUE"),
        "Fixed uniqueness predicates.",
    ),
    *_allow(
        "app/models/source_checkpoint.py",
        "text",
        (
            "scope_kind = 'source' AND partition_key IS NULL",
            "scope_kind = 'partition' AND partition_key IS NOT NULL",
        ),
        "Fixed source and partition index predicates.",
    ),
    *_allow(
        "app/models/source_watermark.py",
        "text",
        (
            "scope_kind = 'source' AND partition_key IS NULL",
            "scope_kind = 'partition' AND partition_key IS NOT NULL",
        ),
        "Fixed source and partition index predicates.",
    ),
    *_allow(
        "app/models/source_rate_limit_state.py",
        "text",
        ("state <> 'available'",),
        "Fixed state index predicate.",
    ),
    *_allow(
        "app/models/source_record.py",
        "text",
        (
            "source_external_id IS NOT NULL",
            "canonical_url_hash IS NOT NULL",
            "is_primary_reference IS TRUE AND intelligence_item_id IS NOT NULL",
        ),
        "Fixed provenance uniqueness predicates.",
    ),
    *_allow(
        "app/ingestion/services/operational_persistence_service.py",
        "literal_column",
        ("ingestion_run_events.xmin::text::xid8",),
        "Fixed PostgreSQL row-version expression; no input reaches the fragment.",
    ),
    *_allow(
        "alembic/versions/a6c9d4e2f107_add_indicator_ioc_models.py",
        "literal_column",
        ("last_seen_at DESC",),
        "Fixed migration index ordering.",
    ),
    *_allow(
        "alembic/versions/a6c9d4e2f107_add_indicator_ioc_models.py",
        "text",
        ("source_record_id IS NOT NULL", "source_record_id IS NULL"),
        "Fixed migration predicates.",
    ),
    *_allow(
        "alembic/versions/b103a71d2e4f_add_operational_ingestion_audit_schema.py",
        "literal_column",
        ("started_at DESC", "id DESC", "occurred_at DESC"),
        "Fixed migration index ordering.",
    ),
    *_allow(
        "alembic/versions/b103a71d2e4f_add_operational_ingestion_audit_schema.py",
        "text",
        (
            "scope_kind = 'source' AND partition_key IS NULL",
            "scope_kind = 'partition' AND partition_key IS NOT NULL",
            "state <> 'available'",
            "correlation_id IS NOT NULL",
        ),
        "Fixed migration predicates.",
    ),
    *_allow(
        "alembic/versions/d7a9e51c2f40_add_b1_05_query_indexes.py",
        "literal_column",
        ("started_at DESC", "id DESC"),
        "Fixed migration index ordering.",
    ),
    *_allow(
        "alembic/versions/f8d739439ed0_create_initial_schema.py",
        "literal_column",
        ("source_published_at DESC", "started_at DESC", "occurred_at DESC"),
        "Fixed initial-schema index ordering.",
    ),
    *_allow(
        "alembic/versions/f8d739439ed0_create_initial_schema.py",
        "text",
        (
            "source_external_id IS NOT NULL",
            "is_primary_reference IS TRUE AND intelligence_item_id IS NOT NULL",
            "canonical_url_hash IS NOT NULL",
            "source_record_id IS NOT NULL",
            "source_id IS NULL",
            "is_primary IS TRUE",
            "source_id IS NOT NULL",
        ),
        "Fixed initial-schema predicates.",
    ),
)
STATIC_SQL_KEYS = frozenset(
    (entry.path, entry.call, entry.fragment) for entry in STATIC_SQL_ALLOWLIST
)
SAFE_DYNAMIC_ATTRIBUTE_CALLS = frozenset(
    {
        (
            "app/core/logging_config.py",
            "getattr(handler, APPLICATION_HANDLER_MARKER, False)",
        ),
        (
            "app/core/logging_config.py",
            "setattr(handler, APPLICATION_HANDLER_MARKER, True)",
        ),
        (
            "app/dev_data/seed_service.py",
            "getattr(record, field_name)",
        ),
        (
            "app/ingestion/anomali_publications_live_cli.py",
            "setattr(namespace, self.dest, values)",
        ),
        (
            "app/ingestion/censys_publications_live_cli.py",
            "setattr(namespace, self.dest, values)",
        ),
    }
)
INJECTION_PAYLOADS = (
    "' OR 1=1 --",
    "%'; DROP TABLE intelligence_items; --",
    "UNION SELECT",
    "%",
    "_",
    "\\",
    "--",
    "/*",
    "*/",
    "1; SELECT pg_sleep(10)",
)


def _production_files() -> list[Path]:
    return sorted(path for root in AUDIT_ROOTS for path in root.rglob("*.py"))


def _relative(path: Path) -> str:
    return path.relative_to(BACKEND_ROOT).as_posix()


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _unsafe_sql_expression(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


def test_text_and_literal_column_calls_are_constant_and_exactly_allowlisted() -> None:
    observed: set[tuple[str, str, str]] = set()
    failures: list[str] = []
    for path in _production_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) not in {
                "text",
                "literal_column",
            }:
                continue
            if (
                len(node.args) != 1
                or not isinstance(node.args[0], ast.Constant)
                or not isinstance(node.args[0].value, str)
            ):
                failures.append(f"{_relative(path)}:{node.lineno}: nonconstant SQL")
                continue
            observed.add((_relative(path), _call_name(node), node.args[0].value))
    assert not failures, failures
    assert observed == STATIC_SQL_KEYS
    assert all(entry.reason for entry in STATIC_SQL_ALLOWLIST)


def test_no_exec_driver_sql_or_raw_string_orm_execute_in_production() -> None:
    failures: list[str] = []
    for path in _production_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name == "exec_driver_sql":
                failures.append(f"{_relative(path)}:{node.lineno}: exec_driver_sql")
            if (
                name == "execute"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                failures.append(f"{_relative(path)}:{node.lineno}: raw execute string")
    assert not failures, failures


def test_no_formatted_or_concatenated_sql_reaches_a_database_sink() -> None:
    failures: list[str] = []
    for path in _production_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        unsafe_names = {
            target.id
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (
                node.targets
                if isinstance(node, ast.Assign)
                else (node.target,)
            )
            if isinstance(target, ast.Name)
            and node.value is not None
            and _unsafe_sql_expression(node.value)
        }
        for node in ast.walk(tree):
            if (
                not isinstance(node, ast.Call)
                or _call_name(node)
                not in {"execute", "exec_driver_sql", "text", "literal_column"}
                or not node.args
            ):
                continue
            argument = node.args[0]
            if _unsafe_sql_expression(argument) or (
                isinstance(argument, ast.Name) and argument.id in unsafe_names
            ):
                failures.append(
                    f"{_relative(path)}:{node.lineno}: unsafe SQL construction"
                )
    assert not failures, failures


def test_no_model_mapping_expansion_or_unreviewed_dynamic_attributes() -> None:
    failures: list[str] = []
    observed_dynamic: set[tuple[str, str]] = set()
    for path in _production_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in MODEL_NAMES
                and any(keyword.arg is None for keyword in node.keywords)
            ):
                failures.append(
                    f"{_relative(path)}:{node.lineno}: **mapping into {node.func.id}"
                )
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in {"getattr", "setattr"}
                and len(node.args) >= 2
                and not isinstance(node.args[1], ast.Constant)
            ):
                observed_dynamic.add((_relative(path), ast.unparse(node)))
    assert not failures, failures
    assert observed_dynamic == SAFE_DYNAMIC_ATTRIBUTE_CALLS


def test_orm_updates_and_deletes_are_bounded_and_api_has_no_mutation_routes() -> None:
    mutation_routes: list[str] = []
    unsafe_writes: list[str] = []
    for path in _production_files():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name in {"post", "put", "patch", "delete"} and isinstance(
                node.func, ast.Attribute
            ):
                    mutation_routes.append(f"{_relative(path)}:{name}")
            orm_write = (
                isinstance(node.func, ast.Name) and name in {"update", "delete"}
            ) or (
                isinstance(node.func, ast.Attribute)
                and name in {"update", "delete"}
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in {"sa", "sqlalchemy"}
            )
            if orm_write:
                current: ast.AST | None = node
                bounded = False
                for _ in range(6):
                    current = parents.get(current) if current is not None else None
                    if (
                        isinstance(current, ast.Call)
                        and isinstance(current.func, ast.Attribute)
                        and current.func.attr == "where"
                    ):
                        bounded = True
                        break
                if not bounded:
                    unsafe_writes.append(f"{_relative(path)}:{node.lineno}:{name}")
    assert Counter(mutation_routes) == Counter(
        {
            "app/api/v1/routes/auth.py:post": 4,
            "app/api/v1/routes/admin_users.py:post": 2,
            "app/api/v1/routes/admin_users.py:patch": 3,
        }
    )
    assert not unsafe_writes, unsafe_writes


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_article_search_payloads_are_bound_and_wildcards_are_literal(payload: str) -> None:
    statement = ArticleQueryService._filtered_statement(
        object.__new__(ArticleQueryService),
        ArticleQueryFilters(q=payload),
    )
    compiled = statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    if payload not in {"%", "_", "\\", "--", "/*", "*/"}:
        assert payload not in sql
    assert "DROP TABLE" not in sql
    assert "UNION SELECT" not in sql
    assert "pg_sleep" not in sql
    values = tuple(compiled.params.values())
    assert len(values) >= 3
    expected = f"%{ArticleQueryService._escape_like(payload)}%"
    assert values.count(expected) == 2
    assert "ESCAPE '\\\\'" in sql


def test_schema_and_migrations_remain_exactly_at_the_frozen_boundary() -> None:
    import app.models  # noqa: F401

    assert len(Base.metadata.tables) == 30
    versions = BACKEND_ROOT / "alembic" / "versions"
    revision_pairs: dict[str, str | None] = {}
    for path in sorted(versions.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        assignments: dict[str, str | None] = {}
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in {"revision", "down_revision"}
            ):
                assignments[node.targets[0].id] = ast.literal_eval(node.value)
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id in {"revision", "down_revision"}
                and node.value is not None
            ):
                assignments[node.target.id] = ast.literal_eval(node.value)
        revision_pairs[assignments["revision"]] = assignments["down_revision"]
        # Git's comparison intentionally honors the repository's accepted
        # Windows CRLF normalization for predecessor migrations.
        comparison = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", str(path)],
            cwd=REPOSITORY_ROOT,
            check=False,
        )
        assert comparison.returncode == 0
    assert len(revision_pairs) == 8
    head = next(revision for revision in revision_pairs if revision not in revision_pairs.values())
    assert head == "c07a01b02c03"
    assert revision_pairs[head] == "f4a1c2d3e5b6"
    assert revision_pairs["f4a1c2d3e5b6"] == "e91f4c2a7b60"
    traversed: list[str] = []
    revision: str | None = head
    while revision is not None:
        traversed.append(revision)
        revision = revision_pairs[revision]
    assert len(traversed) == 8
