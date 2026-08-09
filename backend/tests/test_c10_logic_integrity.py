"""C10 regressions for truthful runtime and closed production defaults."""

from __future__ import annotations

import ast
from pathlib import Path

from app.orchestration.flows import DEFAULT_SOURCE_HANDLERS


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_default_source_handlers_remain_closed() -> None:
    assert len(DEFAULT_SOURCE_HANDLERS) == 0


def test_runtime_modules_do_not_import_test_packages() -> None:
    for path in sorted((REPOSITORY_ROOT / "backend" / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(not alias.name.startswith("tests") for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("tests")


def test_production_code_has_no_unconditional_skip_or_xfail_markers() -> None:
    for root in (REPOSITORY_ROOT / "backend" / "app", REPOSITORY_ROOT / "scripts"):
        for path in root.rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            assert "pytest.skip" not in source
            assert "pytest.xfail" not in source
