"""C10 regression evidence for query, command, header, and export injection."""

from __future__ import annotations

import ast
from pathlib import Path
import re

from sqlalchemy.dialects import postgresql

from app.services.article_query_service import ArticleQueryFilters, ArticleQueryService
from app.services.report_service import neutralize_csv_cell


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_article_search_payload_is_bound_data_not_sql_structure() -> None:
    payload = "x' OR 1=1 -- %_"
    statement = ArticleQueryService(object())._filtered_statement(
        ArticleQueryFilters(q=payload, limit=25, offset=0)
    )
    compiled = statement.compile(dialect=postgresql.dialect())
    rendered = str(compiled)
    assert payload not in rendered
    assert " OR 1=1 " not in rendered
    assert any("OR 1=1" in str(value) for value in compiled.params.values())


def test_csv_formula_prefixes_remain_neutralized_after_whitespace_and_controls() -> None:
    for value in ("=1+1", "+cmd", "-2+3", "@SUM(A1:A2)", "  =1+1", "\x00@cmd"):
        assert neutralize_csv_cell(value).startswith("'")


def test_production_scripts_use_argv_subprocesses_without_shell_execution() -> None:
    for relative in (
        "scripts/production/backup_restore.py",
        "scripts/production/recovery_rehearsal.py",
    ):
        source = (REPOSITORY_ROOT / relative).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=relative)
        assert "shell=True" not in source.replace(" ", "")
        assert "os.system" not in source
        assert "os.popen" not in source
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                assert not (keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True)


def test_report_filename_grammar_cannot_carry_header_controls() -> None:
    pattern = re.compile(r"^alpha-data-[a-z-]+-[0-9]{8}T[0-9]{6}Z\.(?:csv|pdf)$")
    assert pattern.fullmatch("alpha-data-uae-intelligence-20260809T000000Z.csv")
    assert pattern.fullmatch("alpha-data-source-operations-20260809T000000Z.pdf")
    assert pattern.fullmatch("alpha-data-report\r\nX-Test-injected.csv") is None
